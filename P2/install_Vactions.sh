sudo apt install pipx
pipx install --force conan
pipx ensurepath
sudo apt-get update && sudo apt-get install -y \
       build-essential autoconf automake libtool m4
conan profile detect
gcc --version
sudo apt install libc6-dev
conan install . --output-folder=build --build=missing
sudo chmod +x build
pwd
ls
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
