#!/bin/bash

echo "=================================================="
echo "🚀 DNS Cache Poisoning Lab - Quick Start"
echo "=================================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

echo "✅ Docker is running"
echo ""

# Build and start containers
echo "📦 Building and starting containers..."
docker-compose down 2>/dev/null
docker-compose up -d --build

echo ""
echo "⏳ Waiting for containers to be ready..."
sleep 5

# Check container status
echo ""
echo "📊 Container Status:"
docker-compose ps

echo ""
echo "=================================================="
echo "✅ Lab Infrastructure is Ready!"
echo "=================================================="
echo ""
echo "🌐 Access Points:"
echo "  • Real Website:    http://localhost:8080"
echo "  • Fake Website:    http://localhost:8081"
echo "  • Frontend UI:     http://localhost:3000 (start separately)"
echo "  • Backend API:     http://localhost:5001 (start separately)"
echo ""
echo "📝 Next Steps:"
echo "  1. Start the backend API:"
echo "     cd attacker && python3 poison.py"
echo ""
echo "  2. Start the frontend UI:"
echo "     cd frontend && npm install && npm run dev"
echo ""
echo "  3. Open http://localhost:3000 in your browser"
echo ""
echo "🎯 Try it out:"
echo "  • Visit http://localhost:8080 to see the REAL website"
echo "  • Visit http://localhost:8081 to see the FAKE website"
echo "  • Use the UI to perform DNS poisoning attack"
echo ""
echo "🛑 To stop:"
echo "  docker-compose down"
echo ""
echo "=================================================="
