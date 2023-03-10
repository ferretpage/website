module.exports = {
  content: ["./views/*.ejs", "./views/**/*.ejs", "./views/*/*.ejs", "./views/*/*/*.ejs", "./views/*/*/*/*.ejs", "./meta/*.ejs", "./views/discord/*/*/*.ejs", "./views/discord/*/*.ejs", "./views/discord/*.ejs", "./views/account/*/*.ejs", "./views/exif/*.ejs"],
  darkMode: 'class', // or 'media' or 'class'
  theme: {
    extend: {
      colors: {
        blue: {
          150: '#111111'
        },
        'ayyblue-black': {
          DEFAULT: '#111111',
          '50': '#848484',
          '100': '#777777',
          '200': '#5E5E5E',
          '300': '#444444',
          '400': '#2B2B2B',
          '500': '#111111',
          '600': '#212529',
          '700': '#000000',
          '800': '#000000',
          '900': '#000000'
        },
        'ayyblue-white': {
          DEFAULT: '#FFFFFF',
          '50': '#eaeaea',
          '100': '#CCCCCC',
          '200': '#B5B5B5',
          '300': '#A6A6A6',
          '400': '#878787',
          '500': '#666666',
          '600': '#474747',
          '700': '#2E2E2E',
          '800': '#1F1F1F',
          '900': '#0F0F0F'
        },
        'ayyblue-blue': {
          DEFAULT: '#5050E4',
          '50': '#FFFFFF',
          '100': '#FFFFFF',
          '200': '#D5D5F8',
          '300': '#A8A8F2',
          '400': '#7C7CEB',
          '500': '#5050E4',
          '600': '#2424DD',
          '700': '#1C1CB2',
          '800': '#151586',
          '900': '#0E0E5A'
        },
        'meowmail-main': {
          DEFAULT: '#FFFFF',
          '50': '#F3E9DC',
          '100': '#F3E9DC',
          '200': '#F3E9DC',
          '300': '#F3E9DC',
          '400': '#F3E9DC',
          '500': '#191923',
          '600': '#191923',
          '700': '#191923',
          '800': '#191923',
          '900': '#191923'
        },
      }
    },
  },
  plugins: [],
}