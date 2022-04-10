// express is a node.js framework
import express from 'express'
// cors allows us to relax the security applied to an API
import cors from 'cors'
import { PrismaClient } from '@prisma/client'
// jsonwebtoken is used to generate tokens for each sign-in 
// it gets a 'secret' from .env file
import jwt from 'jsonwebtoken'
// bcrypt is used to create a hash instead of storing a password
import bcrypt from 'bcryptjs'

//function to create the token
function createToken(id: number) {
    //@ts-ignore
    const token = jwt.sign({ id: id }, process.env.MY_SECRET, {
        expiresIn: '3days'
    })
    return token
}

async function getUserFromToken(token: string) {
    //@ts-ignore
    const data = jwt.verify(token, process.env.MY_SECRET)
    const user = await prisma.user.findUnique({
        //@ts-ignore
        where: { id: data.id },
        select: {
            id: true,
            email: true,
            username: true,
            profilePic: true,
            favoriteGenres: true,
            favoriteArtists: true,
            favoriteSongs: true,
            playlists: { include: { playlistSongs: true } },
            comments: true
        }
    })
    return user
}

const prisma = new PrismaClient()
const PORT = 3001

const app = express()
app.use(cors())
app.use(express.json())

// signs up a user
app.post('/sign-up', async (req, res) => {
    // takes username, email and password from the body of the request
    // (these three are sent from the frontend using the form)
    const { username, email, password } = req.body

    try {
        //generate a hash from their password
        const hash = bcrypt.hashSync(password, 8)
        const user = await prisma.user.create({
            //store the hash instead of the password the user enters
            data: { username, email, password: hash, profilePic: `https://avatars.dicebear.com/api/avataaars/${username}.svg` },
            select: {
                id: true,
                email: true,
                username: true,
                profilePic: true,
                favoriteGenres: true,
                favoriteArtists: true,
                favoriteSongs: true,
                playlists: { include: { playlistSongs: true } },
                comments: true

            }
        })
        // send back the user object and the created token
        res.send({ user, token: createToken(user.id) })
    } catch (err) {
        res.status(400).send({
            error: "The e-mail or username you're trying to use already exists"
        })
    }
})

// signs in a user
app.post('/sign-in', async (req, res) => {
    // takes email and password from body of request
    const { email, password } = req.body

    try {
        const user = await prisma.user.findUnique({
            where: { email },
            select: {
                id: true,
                email: true,
                username: true,
                password: true,
                profilePic: true,
                favoriteGenres: true,
                favoriteArtists: true,
                favoriteSongs: true,
                playlists: { include: { playlistSongs: true } },
                comments: true

            }
        })
        //compares the password from the form with the hash password its stored in the database
        //@ts-ignore
        const passwordMatches = bcrypt.compareSync(password, user.password)

        if (user && passwordMatches) {
            res.send({ user, token: createToken(user.id) })
        } else {
            throw Error('Email/password invalid')
        }
    } catch (err) {
        //@ts-ignore
        res.status(400).send({ error: err.message })
    }
})

//checks if there is a token still available
//if there is, it signs us in directly
app.get('/validate', async (req, res) => {
    const token = req.headers.authorization || ''

    try {
        const user = await getUserFromToken(token)
        res.send(user)
    } catch (err) {
        //@ts-ignore
        res.status(400).send({ error: err.message })
    }
})

app.listen(PORT, () => console.log(`Server up: http:\\localhost:${PORT}`))