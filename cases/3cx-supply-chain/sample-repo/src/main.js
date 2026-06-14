import axios from 'axios'
import codec from 'x-trader-codec'

export async function checkUpdate() {
    return axios.get('https://cdn-update.example.invalid/manifest.json')
}

export async function desktopAppEntry() {
    const updateManifest = await checkUpdate()
    return {
        simulated: true,
        codecLoaded: Boolean(codec),
        client: Boolean(axios),
        updateManifest: Boolean(updateManifest),
    }
}

desktopAppEntry()