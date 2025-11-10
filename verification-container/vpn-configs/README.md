# VPN Configuration

## Setup Instructions

1. **Get Surfshark VPN configs**:
   - Log in to your Surfshark account
   - Go to Manual Setup → OpenVPN
   - Download `.ovpn` config files for desired locations

2. **Place config files**:
   ```bash
   # Example locations matching setup-namespaces.sh
   us-nyc.ovpn      # US New York
   us-lax.ovpn      # US Los Angeles
   uk-lon.ovpn      # UK London
   de-fra.ovpn      # Germany Frankfurt
   jp-tok.ovpn      # Japan Tokyo
   au-syd.ovpn      # Australia Sydney
   ca-tor.ovpn      # Canada Toronto
   nl-ams.ovpn      # Netherlands Amsterdam
   sg-sin.ovpn      # Singapore
   br-sao.ovpn      # Brazil Sao Paulo
   ```

3. **Create credentials file**:
   ```bash
   cp credentials.example credentials.txt
   # Edit credentials.txt with your Surfshark username/password
   ```

4. **File format for credentials.txt**:
   ```
   your_username
   your_password
   ```

## Security Notes

- The `credentials.txt` file is in `.gitignore` and will NOT be committed
- Keep your VPN credentials secure
- `.ovpn` files are also gitignored for security

## Alternative VPN Providers

If using a different VPN provider (not Surfshark):

1. Get OpenVPN config files from your provider
2. Name them according to the locations in `setup-namespaces.sh`
3. Update the `VPN_LOCATIONS` array in `setup-namespaces.sh` if needed
