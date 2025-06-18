# c-dockersec

Documentation site built with Nextra and Next.js.

## Quick Start

### Development

Start the development server:

```bash
docker-compose up
```

The site will be available at `http://localhost:3000`.

### Production

Build and run the production version:

```bash
docker-compose --profile production up --build
```

Access via nginx at `http://localhost:8080`.

## Project Structure

```
c-dockersec/
├── pages/           # Documentation pages (MDX files)
│   ├── docs/        # Main documentation
│   ├── api/         # API documentation
│   └── index.mdx    # Home page
├── components/      # Custom React components
├── public/          # Static assets
├── theme.config.tsx # Nextra theme configuration
├── next.config.js   # Next.js configuration
└── docker-compose.yml
```

## Writing Documentation

- Create new MDX files in the `pages/` directory
- Use `_meta.json` files to control navigation
- Add custom components in the `components/` directory

## Deployment

### Docker
```bash
docker build -t c-dockersec .
docker run -p 3000:3000 c-dockersec
```

### Vercel
```bash
npx vercel --prod
```

## Resources

- [Nextra Documentation](https://nextra.site)
- [Next.js Documentation](https://nextjs.org/docs)
- [MDX Documentation](https://mdxjs.com)
