export const repo = 'https://github.com/Kajahkura/RSAT_Project';
export const workspaceVersion = '2.2.0';
export const releaseTag = 'v2.2.0';
export const platforms:Record<string,{name:string;file:string;command:string;checksums:string;prepare:string;checksumCommand:string;terminal:string}> = {
  Windows:{name:'Windows · x86_64',file:'RSAT_Windows_x86_64.exe',command:'.\\RSAT_Windows_x86_64.exe',checksums:'RSAT-windows-2022-SHA256SUMS.txt',prepare:'',checksumCommand:'Get-FileHash .\\RSAT_Windows_x86_64.exe -Algorithm SHA256',terminal:'Open PowerShell in the folder containing the downloaded executable.'},
  Linux:{name:'Linux · x86_64',file:'RSAT_Linux_x86_64',command:'./RSAT_Linux_x86_64',checksums:'RSAT-ubuntu-22.04-SHA256SUMS.txt',prepare:'chmod +x ./RSAT_Linux_x86_64',checksumCommand:'sha256sum ./RSAT_Linux_x86_64',terminal:'Open a terminal in the download folder. The portable build requires glibc 2.35 or newer; other systems can install from source.'},
  macOS:{name:'macOS · Apple Silicon',file:'RSAT_macOS_arm64',command:'./RSAT_macOS_arm64',checksums:'RSAT-macos-15-SHA256SUMS.txt',prepare:'chmod +x ./RSAT_macOS_arm64',checksumCommand:'shasum -a 256 ./RSAT_macOS_arm64',terminal:'Open Terminal in the download folder. Choose Apple Silicon for an M-series chip in About This Mac.'},
  macOSIntel:{name:'macOS · Intel',file:'RSAT_macOS_x86_64',command:'./RSAT_macOS_x86_64',checksums:'RSAT-macos-15-intel-SHA256SUMS.txt',prepare:'chmod +x ./RSAT_macOS_x86_64',checksumCommand:'shasum -a 256 ./RSAT_macOS_x86_64',terminal:'Open Terminal in the download folder. Choose Intel when About This Mac identifies an Intel processor.'},
};
export function releaseFile(name:string):string { return repo + '/releases/download/' + releaseTag + '/' + name; }
