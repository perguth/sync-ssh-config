/* global AbortController */
import b4a from 'b4a'
import * as child from 'child_process'
import crypto from 'crypto'
import * as fs from 'fs'
import Hyperswarm from 'hyperswarm'
import DHT from '@hyperswarm/dht'
import sodium from 'sodium-universal'
import { fileURLToPath } from 'url'
import { dirname } from 'path'

class SyncSshConfig {
  constructor () {
    const dir = dirname(fileURLToPath(import.meta.url))
    console.log(
      'Starting `sync-ssh-config` version',
      child.execSync(`cd ${dir} && git rev-parse --short HEAD`).toString().replace('\n', '')
    )

    this.sockets = new Set()
    this.mtime = null
    this.yggSelf = null
    this.abortController = null
    this.path = {
      ssh: '',
      swarm: '/etc/opt/sync-ssh-config/swarm.json'
    }
    this.conf = {
      ssh: '',
      swarm: {
        userName: '',
        sharedSecret: null,
        topic: null,
        previousSharedSecret: null,
        sharedKeyPair: null,
        remotePublicKeys: [],
        keyPair: {}
      }
    }
  }

  saveSwarmConf () {
    fs.writeFileSync(this.path.swarm, JSON.stringify(
      this.conf.swarm, null, 2
    ))
  }

  prepare () {
    try {
      this.conf.swarm = JSON.parse(
        fs.readFileSync(this.path.swarm, 'utf8')
      )
    } catch (_) {
      try {
        const folderPath = /^(.*\/)/g.exec(this.path.swarm)[0]
        fs.mkdirSync(folderPath)
      } catch (_) {}
      this.saveSwarmConf()
      child.execSync(`chmod o-r ${this.path.swarm}`)
    }

    if (!Object.keys(this.conf.swarm.keyPair).length) {
      const keyPair = DHT.keyPair()
      this.conf.swarm.keyPair = {
        publicKey: keyPair.publicKey.toString('hex'),
        secretKey: keyPair.secretKey.toString('hex')
      }
      this.saveSwarmConf()
    }

    if (
      !this.conf.swarm.sharedSecret
    ) {
      const sharedSecret = b4a.allocUnsafe(32)
      sodium.randombytes_buf(sharedSecret)
      this.conf.swarm.sharedSecret = sharedSecret.toString('hex')
      this.saveSwarmConf()
    }

    if (
      this.conf.swarm.sharedSecret !== this.conf.swarm.previousSharedSecret
    ) {
      const accessKeyPair = (DHT.keyPair(
        Buffer.from(sha256(this.conf.swarm.sharedSecret), 'hex')
      ))
      this.conf.swarm.sharedKeyPair = {
        publicKey: accessKeyPair.publicKey.toString('hex'),
        secretKey: accessKeyPair.secretKey.toString('hex')
      }
      const topic = b4a.allocUnsafe(32)
      sodium.crypto_generichash(topic,
        Buffer.from(sha256(this.conf.swarm.sharedSecret), 'hex')
      )
      this.conf.swarm.topic = topic.toString('hex')
      this.saveSwarmConf()
    }

    if (!this.conf.swarm.userName) {
      console.error(`\`userName\` not configured in \`${this.path.swarm}\``)
      process.exit(1)
    }

    if (!this.path.ssh) {
      if (this.conf.swarm.userName === 'root') {
        this.path.ssh = `/${this.conf.swarm.userName}/.ssh/config`
      } else {
        this.path.ssh = `/home/${this.conf.swarm.userName}/.ssh/config`
      }
    }
    try {
      this.conf.ssh = fs.readFileSync(this.path.ssh, 'utf8')
    } catch (_) {
      const folderPath = /^(.*\/)/g.exec(this.path.swarm)[0]
      fs.mkdirSync(folderPath, { mode: 0o700, recursive: true })
      fs.writeFileSync(this.path.ssh, '', { mode: 0o644, flag: 'a' })
      console.log(`Created config file \`${this.path.ssh}\``)
      const date = new Date(0)
      fs.utimesSync(this.path.ssh, date, date)
    }

    if (this.conf.swarm.sharedSecret !== this.conf.swarm.previousSharedSecret) {
      console.log('`sharedSecret` changed. Deprecating config.')
      this.conf.swarm.previousSharedSecret = this.conf.swarm.sharedSecret
      this.saveSwarmConf()
      const date = new Date(0)
      fs.utimesSync(this.path.ssh, date, date)
    }
  }

  async start () {
    this.prepare()

    this.mtime = fs.statSync(this.path.ssh).mtime

    const swarm = new Hyperswarm({
      keyPair: {
        publicKey: Buffer.from(this.conf.swarm.keyPair.publicKey, 'hex'),
        secretKey: Buffer.from(this.conf.swarm.keyPair.secretKey, 'hex')
      }
    })
    process.once('SIGINT', () => swarm.destroy())

    swarm.on('connection', (socket, peerInfo) => {
      const peerPublicKey = peerInfo.publicKey.toString('hex')

      this.sockets.add(socket)
      const handleClose = _ => {
        if (!this.sockets.has(socket)) {
          return
        }
        console.log(
          '(Previous) connection to peer closed:',
          peerPublicKey
        )
        this.sockets.delete(socket)
      }
      socket.on('close', handleClose)
      socket.on('error', handleClose)

      socket.on('data', data => {
        const isMember = this.conf.swarm.remotePublicKeys.includes(peerPublicKey)
        if (isMember) {
          return
        }

        try {
          data = JSON.parse(data.toString())
        } catch (err) {
          console.error('Received broken JSON from peer:', peerPublicKey, err)
          socket.destroy()
          return
        }

        if (data.hello) {
          data.hello = Buffer.from(data.hello)
          if (!sodium.crypto_sign_open(
            b4a.allocUnsafe(data.hello.length - sodium.crypto_sign_BYTES),
            data.hello,
            Buffer.from(this.conf.swarm.sharedKeyPair.publicKey, 'hex')
          )) {
            console.warn('Could not authenticate peer:', peerPublicKey)
            socket.destroy()
            return
          }
          if (!isMember) {
            this.conf.swarm.remotePublicKeys.push(peerPublicKey)
            this.saveSwarmConf()
          }

          console.log('Added new group member:', peerPublicKey)

          this.sync(socket, peerPublicKey)
        }
      })

      const isMember = this.conf.swarm.remotePublicKeys.includes(peerPublicKey)
      if (!isMember) {
        const randomBuffer = b4a.allocUnsafe(32)
        sodium.randombytes_buf(randomBuffer)
        const signedMessage = b4a.allocUnsafe(32 + sodium.crypto_sign_BYTES)
        sodium.crypto_sign(
          signedMessage,
          randomBuffer,
          Buffer.from(this.conf.swarm.sharedKeyPair.secretKey, 'hex')
        )
        socket.write(JSON.stringify({ hello: signedMessage }))
        return
      }

      this.sync(socket, peerPublicKey)
    })

    console.log('Common group topic:', this.conf.swarm.topic)
    console.log('Own ID:', this.conf.swarm.keyPair.publicKey)
    swarm.join(Buffer.from(this.conf.swarm.topic, 'hex'))

    this.watch()
  }

  sync (socket, peerPublicKey) {
    console.log('Connected to peer:', peerPublicKey)

    socket.on('data', data => {
      try {
        data = JSON.parse(data.toString())
      } catch (err) {
        console.error('Received broken JSON from peer:', peerPublicKey, err)
        socket.destroy()
        return
      }

      if (data.mtime) {
        data.mtime = new Date(data.mtime)
        if (this.mtime <= data.mtime) {
          console.log('No updates available for:', peerPublicKey)
          return
        }
        this.sendConfig(socket)
        return
      }

      if (data.ssh) {
        data.ssh.mtime = new Date(data.ssh.mtime)
        if (this.mtime >= data.ssh.mtime) {
          console.log('Discarding config from peer (already up to date):', peerPublicKey)
          return
        }
        console.log('Got newer configuration from peer:', peerPublicKey)
        this.conf.ssh = data.ssh.conf
        this.mtime = data.ssh.mtime
        this.updateSshConfig()
      }
    })

    socket.write(JSON.stringify({ mtime: this.mtime }))
  }

  watch () {
    let debounce
    this.abortController = new AbortController()
    fs.watch(this.path.ssh, { signal: this.abortController.signal }, _ => {
      const mtime = fs.statSync(this.path.ssh).mtime
      if (+debounce === +mtime) {
        return
      }
      console.log(`Detected file changes in \`${this.path.ssh}\``)
      debounce = mtime
      this.mtime = mtime
      this.conf.ssh = fs.readFileSync(this.path.ssh, 'utf8')
      for (const socket of this.sockets) {
        this.sendConfig(socket)
      }
    })
  }

  unWatch () {
    this.abortController.abort()
  }

  sendConfig (socket) {
    socket.write(JSON.stringify({
      ssh: {
        conf: this.conf.ssh,
        mtime: this.mtime.toJSON()
      }
    }))
    console.log('Sent config to peer:', socket.remotePublicKey.toString('hex'))
  }

  updateSshConfig () {
    this.unWatch()
    fs.writeFileSync(this.path.ssh, this.conf.ssh)
    fs.utimesSync(this.path.ssh, this.mtime, this.mtime)
    this.watch()
    console.log(`Updated \`${this.path.ssh}\``)
  }
}

export const ssc = new SyncSshConfig()

ssc.start()

function sha256 (inp) {
  return crypto.createHash('sha256').update(inp).digest('hex')
}
