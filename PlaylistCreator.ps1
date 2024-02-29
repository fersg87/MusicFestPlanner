Get-SpotifyArtistTopTracks -accessToken $token -artistList $artists
# $topTracks
function Get-SpotifyArtistTopTracks {
    param (
        [Parameter(Mandatory)]
        [string]$accessToken,

        [Parameter(Mandatory)]
        [string[]]$artistList,

        [Parameter(Mandatory)]
        [int]$topN
    )

    $headers = @{
        Authorization = "Bearer $accessToken"
    }

    $artistTopTracks = @{}
    $trackUris = @()

    foreach ($artistName in $artistList) {
        # Search for the artist to get the artist's Spotify ID
        $searchResponse = Invoke-RestMethod -Uri "https://api.spotify.com/v1/search?q=$artistName&type=artist&limit=1" -Method Get -Headers $headers
        $artistId = $searchResponse.artists.items[0].id

        if ($artistId) {
            # Get the top tracks for the artist
            $topTracksResponse = Invoke-RestMethod -Uri "https://api.spotify.com/v1/artists/$artistId/top-tracks?market=US" -Method Get -Headers $headers
            $topTrackIds = $topTracksResponse.tracks[0..($topN-1)].uri
            $trackUris += $topTrackIds
            $artistTopTracks[$artistName] = $topTrackIds
        }
    }

    return $artistTopTracks, $trackUris
}

function Get-SpotifyAuthorizationUrl {
    param (
        [Parameter(Mandatory)]
        [string]$clientId,

        [Parameter(Mandatory)]
        [string]$redirectUri,

        [string]$scope = "user-library-read"
    )

    $authUrl = "https://accounts.spotify.com/authorize"
    $responseType = "code"

    # The scope parameter is optional but recommended
    $scope = [System.Web.HttpUtility]::UrlEncode($scope)

    # Construct the full URL
    $fullUrl = "$authUrl`?client_id=$clientId&response_type=$responseType&redirect_uri=$redirectUri&scope=$scope"

    return $fullUrl
}

function Get-SpotifyAccessToken {
    param (
        [Parameter(Mandatory)]
        [string]$clientId,

        [Parameter(Mandatory)]
        [string]$clientSecret,

        [Parameter(Mandatory)]
        [string]$code,

        [Parameter(Mandatory)]
        [string]$redirectUri
    )

    $tokenUrl = "https://accounts.spotify.com/api/token"
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($clientId):$($clientSecret)"))

    $body = @{
        grant_type    = "authorization_code"
        code          = $code
        redirect_uri  = $redirectUri
    }

    $headers = @{
        'Authorization' = "Basic $encodedCredentials"
        'Content-Type'  = "application/x-www-form-urlencoded"
    }

    $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Headers $headers -Body $body
    return $response.access_token, $response.refresh_token, $response.expires_in
}

function Get-ClientCredentialsAccessToken {
    param (
        [Parameter(Mandatory)]
        [string]$clientId,

        [Parameter(Mandatory)]
        [string]$clientSecret
    )

    # Base64 encode the client ID and client secret
    $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($clientID):$($clientSecret)"))

    # Spotify accounts service URL for token
    $tokenUrl = "https://accounts.spotify.com/api/token"

    # Set the body for the token request
    $body = @{
        grant_type = "client_credentials"
    }

    # Get the OAuth token
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -Headers @{ Authorization = "Basic $encoded" } -ContentType 'application/x-www-form-urlencoded'
    $token = $tokenResponse.access_token

    return $token
}

function Get-SpotifyAccessTokenWithRefreshToken {
    param (
        [Parameter(Mandatory)]
        [string]$clientId,

        [Parameter(Mandatory)]
        [string]$clientSecret,

        [Parameter(Mandatory)]
        [string]$refreshToken
    )

    $tokenUrl = "https://accounts.spotify.com/api/token"
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($clientID):$($clientSecret)"))

    $body = @{
        grant_type    = "refresh_token"
        refresh_token = $refreshToken
    }

    $headers = @{
        'Authorization' = "Basic $encodedCredentials"
        'Content-Type'  = "application/x-www-form-urlencoded"
    }

    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Headers $headers -Body $body
        Write-Output "Access Token: $($response.access_token)"
        return $response.access_token, $response.expires_in
    }
    catch {
        Write-Error "Failed to refresh access token: $_"
    }
}

function Ensure-SpotifyPlaylistExists {
    param (
        [Parameter(Mandatory)]
        [string]$accessToken,

        [Parameter(Mandatory)]
        [string]$userId,

        [Parameter(Mandatory)]
        [string]$playlistName
    )

    $headers = @{
        'Authorization' = "Bearer $accessToken"
        'Content-Type'  = "application/json"
    }

    # Check if the playlist exists
    $playlists = Invoke-RestMethod -Uri "https://api.spotify.com/v1/users/$userId/playlists?limit=50" -Method Get -Headers $headers
    $existingPlaylist = $playlists.items | Where-Object { $_.name -eq $playlistName }

    if ($existingPlaylist) {
        #Write-Output "Playlist already exists with ID: $($existingPlaylist.id)"
        return $existingPlaylist.id
    } else {
        # Create a new playlist
        $body = @{
            name        = $playlistName
            description = "Created with PowerShell"
            public      = $true
        } | ConvertTo-Json

        $playlist = Invoke-RestMethod -Uri "https://api.spotify.com/v1/users/$userId/playlists" -Method Post -Headers $headers -Body $body
        #Write-Output "Created new playlist with ID: $($playlist.id)"
        return $playlist.id 
    }
}

function Add-TracksToSpotifyPlaylist {
    param (
        [Parameter(Mandatory)]
        [string]$accessToken,

        [Parameter(Mandatory)]
        [string]$playlistId,

        [Parameter(Mandatory)]
        [string[]]$trackUris
    )

    $headers = @{
        'Authorization' = "Bearer $accessToken"
        'Content-Type'  = "application/json"
    }

    # Retrieve current tracks in the playlist to avoid adding duplicates
    $currentTracks = Invoke-RestMethod -Uri "https://api.spotify.com/v1/playlists/$playlistId/tracks" -Method Get -Headers $headers
    $existingUris = $currentTracks.items.track.uri

    $newTracks = $trackUris | Where-Object { $_ -notin $existingUris }

    if ($newTracks) {
        foreach ($trackUri in $newTracks) {
            $body = @{
                uris = @($trackUri)
            } | ConvertTo-Json

            $response = Invoke-RestMethod -Uri "https://api.spotify.com/v1/playlists/$playlistId/tracks" -Method Post -Headers $headers -Body $body
            Write-Output "Added track $trackUri to playlist $playlistId"
        }
    }
    else {
        Write-Output "No new tracks to add."
    }
}


#=====================================
# Step 1: Your spotify credentials
#
# 1. Update the clientId and clientSecret to match your spotify app
# 2. Update the redirectUri to match your Spotify App
# 3. Update the scopes you'll need when running APIs on behalf of a user
#=====================================
$clientID = ''
$clientSecret = ''
$redirectUri = 'http://localhost:8100'
$scopes = 'playlist-modify-private playlist-modify-public user-library-read'

#=====================================
# Step 2: Client credential token
#
# 1. Generate a client credential token
# 2. This token is used for non-user APIs such as search
#=====================================
$clientCredentialToken = Get-ClientCredentialsAccessToken -clientId $clientID -clientSecret $clientSecret

#=====================================
# Step 3: Authorization URL
#
# 1. Uncomment this section
# 2. Run this section to copy the authorization URL to clipboard
# 3. Comment section
#=====================================
#$authUrl = Get-SpotifyAuthorizationUrl -clientId $clientID -redirectUri $redirectUri -scope $scopes
#Set-Clipboard -Value $authUrl

#=====================================
# Step 4: Authorization code
#
# 1. Open a browser and navigate to the authorization URL in your clipboard, it will open Spotify's website
# 2. Login to Spotify and authorize
# 3. You'll be redirected to http://localhost:8100
# 4. Copy the value of 'code' in the redirected URI e.g. http://localhost:8100/?code=<value>
# 5. Update the authorization code below
#=====================================
$code = ''

#=====================================
# Step 5: User access token
#
# 1. Run the following section to get the access token, refresh token and expiry
# 2. This token is used for user APIs such as playlist creation
#=====================================
#$userToken, $refreshToken, $expiryInMs = Get-SpotifyAccessToken -clientId $clientID -clientSecret $clientSecret -redirectUri http://localhost:8100 -code $code
#$userToken, $expiresIn = Get-SpotifyAccessTokenWithRefreshToken -clientId $clientID -clientSecret $clientSecret -refreshToken $refreshToken

#=====================================
# Step 6: Playlist creation
#
# 1. Go to Spotify, your profile, click on "...", then copy link to profile
# 2. Navigate to the URL in your browser
# 3. Copy your user id in the URL, this is the format: https://open.spotify.com/user/<userId>?si=...
# 4. Update the userId below
# 5. Update playlist name
# 6. Run this section to create playlist if it doesn't exist
#=====================================
$userId = '121594582'
$playlistName = 'Besame Mucho Austin 2024 Petit'
$playlistId = Ensure-SpotifyPlaylistExists -accessToken $userToken -userId $userId -playlistName $playlistName

#=====================================
# Step 7: Artists' top songs
#
# 1. Update the list of artists
# 2. Update the number of top songs to retrieve per artist
# 3. Run this section to retrieve a list of topN songs per artist
#
# Artists are found by doing a search query by artist name and selecting the top result.
# If the artist you're looking for doesn't exist or the name collides with other more popular artists
# you might end up with songs of artists you're not looking for. You should do some validation after creating your playlist 
# to ensure you get the right songs.
#=====================================
$topN = 1
$artists = @(
    "Los Askis",
    "Los Hermanos Mendoza",
    "Los Wercos",
    "Grupo G",
    "Grupo Soñador",
    "Los Yaguaru",
    "Los 2 de la S",
    "Jumbo",
    "Oro Solido",
    "Caballo Dorado",
    "Banda Arkangel R-15",
    "Metal",
    "Amistades Peligrosas",
    "Los Terricolas",
    "Los Freddy's",
    "Los Ángeles de Charly",
    "Ximena Sariñana",
    "Amistades Peligrosas",
    "Los Viejones de Linares",
    "Aaron y Su Grupo Ilusion",
    "Su Majestad Mi Banda El Mexicano",
    "Kinky",
    "Suenatron",
    "Los Socios del Ritmo",
    "Cuisillos",
    "Grupo Kual?",
    "Mar",
    "Eliseo Robles",
    "Banda Machos",
    "El Gran Silencio",
    "Elena Rose",
    "Los Cadetes de Linares",
    "Banda El Limón",
    "La Unión",
    "Aleks Syntek",
    "Pesado",
    "La Séptima Banda",
    "Duncan Dhu",
    "Kumbia Kings",
    "Lorenzo de Monteclaro",
    "Los Sebastianes",
    "Moenia",
    "Elvis Crespo",
    "Grupo Cañaveral",
    "Bobby Pulido",
    "Elefante",
    "Fey",
    "Liberación",
    "Lalo Mora",
    "La Dinastía de Tuzantla",
    "Mago de Oz",
    "Grupo Legítimo",
    "Banda Los Recoditos",
    "Los Enanitos Verdes",
    "Marisela",
    "Alicia Villarreal",
    "La Adictiva",
    "La Ley",
    "Sin Bandera",
    "Los Rieleros del Norte",
    "Los Invasores de Nuevo León",
    "Molotov",
    "Danna Paola",
    "El Tri",
    "Los Cardenales de Nuevo León",
    "Panteón Rococó",
    "Belanova",
    "Ramón Ayala",
    "Duelo",
    "Hombres G",
    "Alejandra Guzmán",
    "Bronco",
    "Banda El Recodo",
    "Café Tacvba",
    "Gloria Trevi",
    "Grupo Frontera",
    "Los Tucanes de Tijuana",
    "Caifanes",
    "Ha*Ash",
    "Los Tigres del Norte",
    "Banda MS",
    "Juanes",
    "Reik",
    "Inspector",
    "Los Ángeles Negros"
)
$topTracksByArtistMap, $topTracksList = Get-SpotifyArtistTopTracks -accessToken $clientCredentialToken -artistList $artists -topN $topN

#=====================================
# Step 7: Adding top songs to playlist
#
# 1. Run the following section to add every top song to your playlist
#=====================================
Add-TracksToSpotifyPlaylist -accessToken $userToken -playlistId $playlistId -trackUris $topTracksList