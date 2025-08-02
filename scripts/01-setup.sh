#!/bin/bash

# Check if the conda is installed or not

echo "Starting the setup script for Python SAST tools..."
echo "=============================================================="
echo "Step 01 Checking if Conda is installed..."
echo "=============================================================="
if ! command -v conda &> /dev/null; then
    echo "Conda is not installed. Please install Anaconda or Miniconda first."
    exit 1
fi
echo ""
echo "Conda is installed. Proceeding with the setup..."

# Create a new conda environment
echo ""
echo "Checking for existing conda environment..."
ENV_NAME="python_sast"



if conda info --envs | grep -q "$ENV_NAME"; then
    echo "Environment '$ENV_NAME' already exists."
else
    echo "Creating a new conda environment named '$ENV_NAME'..."
    # Accept conda ToS for required channels
    echo "Accepting Conda Terms of Service for required channels..."
    conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main
    conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r
    conda create -n "$ENV_NAME" python=3.10 -y
fi


echo "Activating the conda environment '$ENV_NAME'..."
# Make sure conda is initialized for the shell
source "$(conda info --base)/etc/profile.d/conda.sh"
conda activate "$ENV_NAME"
echo ""

# Check if the codeql is installed or not
echo "=============================================================="
echo "Step 02 Checking if CodeQL CLI is installed..."
echo "=============================================================="
if ! command -v codeql &> /dev/null; then
    # Option 1: Install CodeQL CLI by now
    echo "Do you want to install CodeQL CLI now? (y/n)"
    read -r install_codeql

    if [[ "$install_codeql" == "y" ]]; then
        # Install CodeQL CLI
        echo "Installing CodeQL CLI..."
        echo "Downloading CodeQL Bundle from GitHub..."
        wget https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.22.2/codeql-bundle-linux64.tar.gz
        if [[ $? -ne 0 ]]; then
            echo "Failed to download CodeQL Bundle. Please check your internet connection."
            exit 1
        fi
        echo "Extracting CodeQL Bundle..."
        tar -xzf codeql-bundle-linux64.tar.gz
        if [[ $? -ne 0 ]]; then
            echo "Failed to extract CodeQL Bundle. Please check the downloaded file."
            exit 1
        fi
        echo "CodeQL CLI installed successfully."
        echo "You can now run 'codeql' command."
        rm codeql-bundle-linux64.tar.gz
    else
        # Option 2: Quit setup and ask the user to install CodeQL CLI manually
        echo "Please install CodeQL CLI manually from https://github.com/github/codeql-cli-binaries/releases"
        exit 1
    fi
fi
echo "CodeQL CLI is installed and available in the PATH."
echo ""

# Resolving CodeQL Language Support
echo "=============================================================="
echo "Step 03 Checking for CodeQL language support..."
echo "=============================================================="
if ! codeql resolve languages &> /dev/null; then
    echo "CodeQL language support for Python is not installed. Installing now..."
    codeql resolve languages
    if [[ $? -ne 0 ]]; then
        echo "Failed to install CodeQL language support. Please check your CodeQL installation."
        exit 1
    fi
    echo "CodeQL language support installed successfully."
else
    echo "CodeQL language support is already installed."
fi
echo ""

# Check GPU availability
echo "=============================================================="
echo "Step 04 Checking for GPU availability..."
echo "=============================================================="
if command -v nvidia-smi &> /dev/null; then
    echo "NVIDIA GPU detected."
    # if pytorch with cuda is not available
    if ! conda list | grep -q "pytorch" && ! conda list | grep -q "cudatoolkit"; then
        echo "Do you want to install PyTorch with CUDA support? (y/n)"
        read -r install_pytorch_cuda
        if [[ "$install_pytorch_cuda" == "y" ]]; then
            echo "Installing PyTorch with CUDA support..."
            conda install pytorch torchvision torchaudio cudatoolkit=11.3 -c pytorch-nightly -c pytorch -c nvidia -y
            if [[ $? -ne 0 ]]; then
                echo "Failed to install PyTorch with CUDA support. Please check your conda configuration."
                exit 1
            fi
            echo "PyTorch with CUDA support installed successfully."
        else
            echo "Skipping PyTorch with CUDA support installation."
        fi
    fi
    echo "PyTorch with CUDA support is already installed."

else
    echo "No NVIDIA GPU detected. Installing PyTorch without CUDA support..."
    conda install pytorch torchvision torchaudio cpuonly -c pytorch -y
    if [[ $? -ne 0 ]]; then
        echo "Failed to install PyTorch without CUDA support. Please check your conda configuration."
        exit 1
    fi
    echo "PyTorch without CUDA support installed successfully."
fi
echo ""


# Checking OPENAI API Key
echo "=============================================================="
echo "Step 05 Checking for LLM API Keys..."
echo "=============================================================="

echo "Checking for OPENAI API Key..."
if [[ -z "$OPENAI_API_KEY" ]]; then
    echo "OPENAI_API_KEY is not set. Please set it in your environment variables."
    echo "You can set it by running: export OPENAI_API_KEY='your_openai_api_key'"
    exit 1
else
    echo "OPENAI_API_KEY is set."
fi

# Checking ANTHROPIC API Key
echo "Checking for ANTHROPIC API Key..."
if [[ -z "$ANTHROPIC_API_KEY" ]]; then
    echo "ANTHROPIC_API_KEY is not set. Please set it in your environment variables."
    echo "You can set it by running: export ANTHROPIC_API_KEY='your_anthropic_api_key'"
    exit 1
else
    echo "ANTHROPIC_API_KEY is set."
fi

# Checking Hunggingface Cache Directory
echo "Checking for Huggingface cache directory..."
if [[ -z "$HF_HOME" ]]; then
    echo "HF_HOME is not set. Setting it to default: ~/.cache/huggingface"
    export HF_HOME="$HOME/.cache/huggingface"
    echo "You can set it permanently by adding 'export HF_HOME=\"$HF_HOME\"' to your ~/.bashrc or ~/.zshrc file."
else
    echo "HF_HOME is set to: $HF_HOME"
fi
echo ""

# Final Message Setup Report
echo "=============================================================="
echo "Setup completed successfully!"
echo "=============================================================="
echo "You can now use the Python SAST tools in the '$ENV_NAME' conda environment."
echo "To activate the environment, run: conda activate $ENV_NAME"
echo "To deactivate the environment, run: conda deactivate"
echo "For more information, please refer to the README.md file."
echo "You can now start using the Python SAST tools."
echo "=============================================================="