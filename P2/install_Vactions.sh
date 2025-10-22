sudo apt install pipx
pipx install --force conan
pipx ensurepath
conan profile detect
mkdir build
conan install . --output-folder=build --build=missing
sudo chmod +x build
pwd
ls
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
