# Use lightweight official Node image
FROM node:20-alpine

# Create app directory inside container
WORKDIR /app

# Copy package files first (better caching)
COPY package*.json ./

# Install only production dependencies
RUN npm install --omit=dev

# Copy the rest of the app
COPY . .

# Expose port (informational)
EXPOSE 3000

# Start the app
CMD ["node", "index.js"]