# Document Anonymizer

A powerful Streamlit application for protecting PII, technical data, and business information in documents before cloud processing.

## Features

- **Auto-Detection**: Emails, phone numbers, SSNs, credit cards, addresses, names, IPs, URLs, companies, account IDs, ZIP codes, dates
- **Custom Token Types**: Define your own categories for specialized data
- **Word-Level Selection**: Choose specific words within detected matches
- **Smart Learning**: Whitelist and blacklist management for improved accuracy
- **Context Generation**: Creates AI-friendly context paragraphs explaining tokens
- **Reversible Process**: Complete de-anonymization with mapping files

## Installation

1. Clone this repository:
```bash
git clone https://github.com/YOUR_USERNAME/document-anonymizer.git
cd document-anonymizer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
streamlit run app.py
```

## Usage

### Step 1: Anonymize Documents
1. Upload a text file or paste content
2. Review detected sensitive items
3. Select words and adjust categories
4. Download anonymized content with context

### Step 2: Cloud Processing
- Process anonymized content with AI services
- Semantic tokens preserve context while protecting data

### Step 3: De-anonymize Results
- Upload processed results and mapping file
- Restore original content completely

## Token Categories

### Auto-Detected
- **EML**: Email addresses
- **PHN**: Phone numbers
- **SSN**: Social Security numbers
- **CRD**: Credit card numbers
- **ADR**: Street addresses
- **PER**: Person names
- **IPV**: IP addresses
- **URL**: Website URLs
- **COM**: Company names
- **ACC**: Account identifiers
- **ZIP**: ZIP codes
- **DTE**: Dates

### Custom Types
Define your own categories with custom prefixes for specialized data protection.

## Security Features

- **Session-based processing**: Each session gets unique tokens
- **Persistent learning**: Whitelist/blacklist management
- **No data persistence**: Content is not stored on servers
- **Reversible anonymization**: Complete data recovery possible

## Use Cases

- **Legal Document Review**: Protect client information
- **Healthcare Data**: Anonymize patient records
- **Business Intelligence**: Secure proprietary information
- **AI Training**: Prepare datasets safely
- **Compliance**: Meet privacy regulations

## Contributing

This project is maintained on a best-effort basis during free time. While I'm not actively supporting it, contributions are welcome:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

**Note**: Response times may vary as this is maintained as a side project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support & Maintenance

**Important**: This project is maintained during free time and is not actively supported. 

- Issues and pull requests are welcome but may not receive immediate responses
- For urgent needs, consider forking and maintaining your own version
- Community contributions and discussions are encouraged

If you encounter issues or have suggestions, please open an issue on GitHub with the understanding that response times may vary.
