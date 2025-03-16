let currentEditingId = null; // Track the ID of the password being edited
let currentViewId = null; // Track the ID of the password being viewed individually

// Function to open individual view modal for entering the encryption password
function openViewPasswordModal(id) {
    currentViewId = id; // Set the current viewing ID
    document.getElementById('view-password-modal').style.display = 'flex'; // Show the view modal
}

// Function to close individual view modal
function closeViewPasswordModal() {
    document.getElementById('view-password-modal').style.display = 'none'; // Hide the view modal
}

// Function to confirm and display individual password
function confirmViewPassword() {
    const encryptionPassword = document.getElementById('encryption-password').value;

    if (!encryptionPassword) {
        alert("Encryption Password is required.");
        return;
    }

    const formData = new FormData();
    formData.append('encryption_password', encryptionPassword);

    fetch(`/decrypt_password/${currentViewId}`, {
        method: 'POST',
        body: formData,
    })
    .then(response => response.json())
    .then(data => {
        if (data.decrypted_password) {
            // Update the password in the page with decrypted password
            document.querySelector(`#password-${currentViewId} .encrypted-password`).innerText = `Password: ${data.decrypted_password}`;
            closeViewPasswordModal();
        } else {
            alert(data.error || "Error fetching password.");
        }
    })
    .catch(() => alert("Error fetching password."));
}






// Function to close "View All" modal
function closeViewAllModal() {
    document.getElementById('view-all-modal').style.display = 'none'; // Hide the view-all modal
}

// Function to open "View All" modal
function openViewAllModal() {
    document.getElementById('view-all-modal').style.display = 'flex'; // Show the view-all modal
}

// Function to confirm and display all passwords

function confirmViewAllPasswords() {
    const encryptionPassword = document.getElementById('encryption-password-all').value;  // Corrected ID

    if (!encryptionPassword) {
        alert("Encryption Password is required.");
        return;
    }

    const formData = new FormData();
    formData.append('encryption_password', encryptionPassword);

    fetch('/decrypt_all_passwords', {
        method: 'POST',
        body: formData,
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            data.passwords.forEach(password => {
                const passwordElement = document.querySelector(`#password-${password.id} .encrypted-password`);
                if (passwordElement) {
                    passwordElement.innerText = `Password: ${password.decrypted_password}`;
                }
            });
            closeViewAllModal();
        } else {
            alert(data.error || "Error decrypting all passwords.");
        }
    })
    .catch(() => alert("Error decrypting all passwords."));
}


// Existing functions remain the same

function hidePassword(id) {
    document.querySelector(`#password-${id} .encrypted-password`).innerText = 'Password: **********';
}

function openEditModal(id, website, encrypted) {
    currentEditingId = id;
    document.getElementById('edit-website').value = website;
    document.getElementById('edit-password').value = '';
    document.getElementById('edit-modal').style.display = 'flex';
}

function hideModal() {
    document.getElementById('edit-modal').style.display = 'none';
}

function updatePassword() {
    const website = document.getElementById('edit-website').value;
    const password = document.getElementById('edit-password').value;
    const secretPassword = prompt("Enter your Secret Password:");

    if (!secretPassword) {
        alert("Secret Password is required.");
        return;
    }

    fetch(`/edit_password/${currentEditingId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ website, password, secret_password: secretPassword }),
    })
    .then(response => {
        if (response.ok) {
            return response.json();
        } else {
            throw new Error("Error updating password.");
        }
    })
    .then(data => {
        alert("Password updated successfully!");
        document.querySelector(`#password-${currentEditingId} .website-name`).innerText = `Website: ${website}`;
        hideModal();
    })
    .catch(error => {
        alert(error.message);
    });
}

function hideAllPasswords() {
    const passwordElements = document.querySelectorAll('.encrypted-password');
    passwordElements.forEach((element) => {
        element.innerText = 'Password: **********';
    });
}

function openDeleteAllModal() {
    document.getElementById('delete-all-modal').style.display = 'flex';
}

function closeDeleteAllModal() {
    document.getElementById('delete-all-modal').style.display = 'none';
}

function confirmDeleteAllAction() {
    const secretPassword = document.getElementById('delete-all-password').value;

    if (!secretPassword) {
        alert("Secret Password is required.");
        return;
    }

    // Confirm deletion action
    if (confirm("Are you sure you want to delete all saved passwords? This action cannot be undone.")) {
        fetch('/delete_all_passwords', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ secret_password: secretPassword })
        })
        .then(response => {
            if (!response.ok) {
                // Handle errors based on the status code
                if (response.status === 401) {
                    alert("User not logged in. Please log in again.");
                    window.location.href = '/login';  // Redirect to login
                } else if (response.status === 403) {
                    alert("Incorrect Secret Password.");
                } else {
                    alert("An error occurred. Please try again.");
                }
                throw new Error("Request failed");
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                alert("All passwords deleted successfully!");
                closeDeleteAllModal();
                document.querySelectorAll('.password-row').forEach(row => row.remove()); // Remove all password rows from the DOM
            }
        })
        .catch(error => console.error("Error:", error));
    } else {
        closeDeleteAllModal();  // Close the modal if user cancels
    }
}



function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const icon = input.nextElementSibling.querySelector('i');
    if (input.type === "password") {
        input.type = "text";
        icon.classList.replace('fa-eye', 'fa-eye-slash');
    } else {
        input.type = "password";
        icon.classList.replace('fa-eye-slash', 'fa-eye');
    }
}

// JavaScript to hide header on scroll
let lastScrollTop = 0; // Initial scroll position
const header = document.querySelector('.head'); // Get the header element

window.addEventListener('scroll', function() {
    let currentScroll = window.pageYOffset || document.documentElement.scrollTop; // Get current scroll position

    if (currentScroll > lastScrollTop) {
        // Scrolling down, hide the header
        header.style.top = '-80px'; // Adjust this value depending on your header height
    } else {
        // Scrolling up, show the header
        header.style.top = '0';
    }

    lastScrollTop = currentScroll <= 0 ? 0 : currentScroll; // Prevent negative scroll position
});



