#!/bin/bash
# ==============================================================================
# Explainable Adaptive IDS - 1-Click macOS Launcher
# Double-click this file in Finder to launch the desktop application!
# ==============================================================================

# Ensure script runs from the repository root
cd "$(dirname "$0")"

clear
echo "=================================================================="
echo "  🛡️  Explainable Adaptive Intrusion Detection System (IDS)"
echo "  Academic Master of Engineering Research Prototype"
echo "=================================================================="
echo ""

# Check for Python 3
if command -v python3 &> /dev/null; then
    PY_CMD="python3"
elif command -v python &> /dev/null; then
    PY_CMD="python"
else
    echo "❌ Error: Python 3 was not found on your Mac."
    echo "You can download the standalone pre-packaged Mac application from GitHub:"
    echo "https://github.com/yudhaxibe-hue/IDS/releases/latest"
    echo ""
    open "https://github.com/yudhaxibe-hue/IDS/releases/latest"
    read -p "Press Enter to exit..."
    exit 1
fi

# Create virtual environment if missing
if [ ! -d "venv" ]; then
    echo "📦 Initializing local environment (one-time setup, please wait)..."
    $PY_CMD -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install -r requirements.txt
    echo "✅ Setup completed successfully!"
    echo ""
fi

# Ensure baseline model is trained
if [ ! -f "models/trained/baseline_model.joblib" ]; then
    echo "🧠 Verifying baseline ML model..."
    ./venv/bin/python3 -m models.training.trainer
    echo "✅ Baseline Random Forest model ready!"
    echo ""
fi

echo "🚀 Launching Explainable Adaptive IDS..."
echo "The application window will open automatically..."
echo ""

LAUNCH_ARG=""
if [ "$1" == "--browser" ]; then
    LAUNCH_ARG="--browser"
fi

./venv/bin/python3 -m app.launcher $LAUNCH_ARG
