# Contributing to Cylvarkana-Django
We’re flattered that you may want to contribute to **Cylvarkana-Django**! Whether you’re here to report issues, suggest improvements, or submit code, your input is vital. To ensure a smooth process, please follow the guidelines outlined below.

## 📝 Code of Conduct
By participating in this project, you agree to adhere to our [Code of Conduct](https://github.com/Cylvarkana/.github/blob/main/docs/CODE_OF_CONDUCT.md). We are committed to fostering a welcoming and inclusive community.

## 🛠️ How to Contribute
### 1. Reporting Issues
If you encounter a bug, performance issue, or security vulnerability, we encourage you to report it. 

**Steps to report:**
- Search the [issue tracker](https://github.com/Cylvarkana/Cylvarkana-Django/issues) to see if the issue has already been reported.
- If not, create a new issue, and provide as much detail as possible (e.g., steps to reproduce, expected behavior, logs, etc.).

### 2. Feature Requests and Suggestions
We welcome ideas for improving the project! If you have a feature request or general suggestion:
- First, open an issue to discuss your idea.
- We value feedback, so feel free to engage in conversations regarding any proposed features.

### 3. Submitting Pull Requests
#### **Fork and Clone the Repository**
1. **Fork the repository**:
   Click the **Fork** button at the top-right corner of the project page on GitHub.
   
2. **Clone your fork**:
   ```bash
   git clone https://github.com/your-username/chromatophore.git
   cd chromatophore

#### **Create a Branch**
Create a new branch for your changes:
```bash
git checkout -b feature/your-feature-name
```

#### **Make Your Changes**
Ensure your changes adhere to the project's coding style and pass existing tests. Consider adding new tests for any added functionality. Please make sure your code is well-documented.

#### **Commit Your Changes**
Use clear and descriptive commit messages:
```bash
git commit -m "Add detailed description of your changes"
```

#### **Push Your Branch**
Push the changes to your forked repository:
```bash
git push origin feature/your-feature-name
```

#### **Create a Pull Request**
Once your code is ready for review:
1. Navigate to your fork on GitHub.
2. Open a pull request (PR) to the `main` branch of the original repository.
3. Ensure you describe your changes and link any related issue(s).

The project maintainers will review your PR and provide feedback as necessary.

## 💡 Development Setup

For contributors who want to make more significant changes or run the project locally, follow the steps below:

### Prerequisites

- **Python 3.10+**
- **Docker**
- **Docker Compose**

### Installation

1. **Create a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. **Install dependencies** (for each app or use the setup.py utility):
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the development server**:
   ```bash
   docker-compose up
   ```
Now, you can access the project locally at http://localhost:8000.

## ✅ Contribution Guidelines
To ensure consistency and code quality, please follow these rules:

- Coding Style: Follow PEP 8 for Python code, and ensure other code adheres to relevant conventions.
- Tests: Run existing tests and add new ones for any added features.
- Commit Messages: Use clear and meaningful commit messages.
- Pull Requests: Make sure your pull request addresses one issue at a time.

## 🧪 Testing
Before submitting a pull request, ensure that all tests pass. To run the tests:

```bash
python manage.py test
```
Add tests for any new functionality where appropriate. We aim for high test coverage, so please prioritize creating meaningful tests. Please document thoroughly what testing was completed in your pull request.

## 🤝 Join the Discussion
We encourage active participation and collaboration. Join the conversation on our [Discord](https://discord.gg/D59w9g6Ptr) and engage with the community. Feel free to ask questions or seek guidance on ongoing development tasks.

## 📄 License
By contributing to Cylvarkana-Django, you agree that your contributions will be licensed under the [Creative Commons Attribution-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-sa/4.0/).

Thank you for contributing! 🌟