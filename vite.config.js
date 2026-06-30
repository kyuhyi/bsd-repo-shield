import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// 정적 호스팅(Vercel/Netlify/GitHub Pages)에 그대로 배포 가능.
export default defineConfig({
  plugins: [react()],
  base: './',
})
