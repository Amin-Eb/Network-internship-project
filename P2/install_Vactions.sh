sudo apt install pipx
pipx install --force conan
pipx ensurepath
conan profile detect
conan install . --output-folder=build --build=missing -s compiler.cppstd=20
sudo chmod +x build
pwd
ls
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
