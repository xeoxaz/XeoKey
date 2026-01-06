// Dropdown menu functionality
function initAll() {
  // Attach event listeners to all dropdown buttons
  const dropdownButtons = document.querySelectorAll('.dropdown button');

  dropdownButtons.forEach(button => {
    button.addEventListener('click', function(event) {
      event.stopPropagation();
      toggleDropdown(this);
    });
  });

  // Close dropdowns when clicking outside
  document.addEventListener('click', function(event) {
    if (!event.target.closest('.dropdown')) {
      document.querySelectorAll('.dropdown').forEach(d => d.classList.remove('active'));
    }
  });

  // Password strength checker for register page
  initPasswordStrengthChecker();
  initPasswordMatchChecker();
  initRegisterFormValidation();

  // Live TOTP updater and copy buttons
  initTotpLive();
}

// Initialize when DOM is ready - use multiple strategies
function tryInit() {
  // Check if elements exist
  const menuToggle = document.querySelector('.menu-toggle');
  if (menuToggle || document.body) {
    initAll();
  } else {
    // Retry after a short delay
    setTimeout(tryInit, 50);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', tryInit);
} else {
  // DOM is already loaded, but wait a tick to ensure everything is ready
  setTimeout(tryInit, 0);
}

// Side drawer code removed - using bottom navigation instead

function toggleDropdown(button) {
  const dropdown = button.closest('.dropdown');
  const isActive = dropdown.classList.contains('active');

  // Close all dropdowns
  document.querySelectorAll('.dropdown').forEach(d => d.classList.remove('active'));

  // Open clicked dropdown if it wasn't active
  if (!isActive) {
    dropdown.classList.add('active');
  }
}

// Password strength checker
function checkPasswordStrength(password) {
  let strength = 0;

  if (password.length >= 6) strength++;
  if (password.length >= 8) strength++;
  if (password.length >= 12) strength++;
  if (/[a-z]/.test(password)) strength++;
  if (/[A-Z]/.test(password)) strength++;
  if (/[0-9]/.test(password)) strength++;
  if (/[^a-zA-Z0-9]/.test(password)) strength++;

  const strengthBar = document.getElementById('passwordStrengthBar');
  const strengthText = document.getElementById('passwordStrengthText');

  if (!strengthBar || !strengthText) return { strength: 0, valid: false };

  if (password.length === 0) {
    strengthBar.style.width = '0%';
    strengthBar.style.backgroundColor = '#4d4d4d';
    strengthText.textContent = '';
    return { strength: 0, valid: false };
  }

  let percentage = 0;
  let color = '#d4a5a5'; // Weak - red
  let text = 'Weak';
  let valid = false;

  if (strength <= 2) {
    percentage = 33;
    color = '#d4a5a5';
    text = 'Weak';
  } else if (strength <= 4) {
    percentage = 66;
    color = '#d4a5a5';
    text = 'Fair';
  } else if (strength <= 5) {
    percentage = 80;
    color = '#9db4d4';
    text = 'Good';
  } else {
    percentage = 100;
    color = '#7fb069';
    text = 'Strong';
    valid = true;
  }

  strengthBar.style.width = percentage + '%';
  strengthBar.style.backgroundColor = color;
  strengthText.textContent = text;
  strengthText.style.color = color;

  return { strength, valid: valid || password.length >= 6 };
}

// Password match checker
function checkPasswordMatch() {
  const passwordInput = document.getElementById('password');
  const confirmPasswordInput = document.getElementById('confirmPassword');
  const matchDiv = document.getElementById('passwordMatch');

  if (!passwordInput || !confirmPasswordInput || !matchDiv) return false;

  const password = passwordInput.value;
  const confirmPassword = confirmPasswordInput.value;

  if (confirmPassword.length === 0) {
    matchDiv.textContent = '';
    return false;
  }

  if (password === confirmPassword) {
    matchDiv.textContent = '✓ Passwords match';
    matchDiv.style.color = '#7fb069';
    return true;
  } else {
    matchDiv.textContent = '✗ Passwords do not match';
    matchDiv.style.color = '#d4a5a5';
    return false;
  }
}

// Initialize password strength checker (uses event delegation for dynamic content)
function initPasswordStrengthChecker() {
  // Use event delegation to work with dynamically loaded content
  document.addEventListener('input', function(event) {
    const passwordInput = event.target;
    if (passwordInput && passwordInput.id === 'password') {
      checkPasswordStrength(passwordInput.value);
      // Only check password match if confirmPassword field exists (register form)
      const confirmPasswordInput = document.getElementById('confirmPassword');
      if (confirmPasswordInput) {
        checkPasswordMatch();
      }
    }
  });
}

// Initialize password match checker
function initPasswordMatchChecker() {
  const confirmPasswordInput = document.getElementById('confirmPassword');
  if (confirmPasswordInput) {
    confirmPasswordInput.addEventListener('input', checkPasswordMatch);
  }
}

// Initialize register form validation
function initRegisterFormValidation() {
  const form = document.getElementById('registerForm');
  if (form) {
    form.addEventListener('submit', function(e) {
      const passwordInput = document.getElementById('password');
      const confirmPasswordInput = document.getElementById('confirmPassword');

      if (!passwordInput || !confirmPasswordInput) return;

      const password = passwordInput.value;
      const confirmPassword = confirmPasswordInput.value;
      const strength = checkPasswordStrength(password);

      if (password !== confirmPassword) {
        e.preventDefault();
        alert('Passwords do not match!');
        return false;
      }

      if (!strength.valid) {
        e.preventDefault();
        alert('Password is too weak. Please choose a stronger password.');
        return false;
      }
    });
  }
}

// Copy to clipboard functionality (browser-compatible)
function copyToClipboard(text) {
  // Modern Clipboard API (preferred)
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text).then(() => {
      return true;
    }).catch(() => {
      // Fallback to legacy method if Clipboard API fails
      return fallbackCopyToClipboard(text);
    });
  }

  // Fallback for older browsers
  return fallbackCopyToClipboard(text);
}

// Fallback copy method for older browsers
function fallbackCopyToClipboard(text) {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.left = '-999999px';
  textArea.style.top = '-999999px';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();

  try {
    const successful = document.execCommand('copy');
    document.body.removeChild(textArea);
    return successful;
  } catch (err) {
    document.body.removeChild(textArea);
    return false;
  }
}

// Initialize copy password button using event delegation
// This works even when content is loaded dynamically
document.addEventListener('click', async function(event) {
  const copyBtn = event.target.closest('#copyPasswordBtn');
  if (!copyBtn) return;

  event.preventDefault();
  event.stopPropagation();

  const statusDiv = document.getElementById('copyStatus');
  const password = copyBtn.getAttribute('data-password');

  if (!password) {
    if (statusDiv) {
      statusDiv.textContent = 'Error: Password not available';
      statusDiv.style.color = '#d4a5a5';
      statusDiv.style.display = 'block';
      setTimeout(() => {
        if (statusDiv) statusDiv.style.display = 'none';
      }, 3000);
    }
    return;
  }

  const success = await copyToClipboard(password);

  if (success) {
    // Track the copy event
    const entryId = copyBtn.getAttribute('data-entry-id');
    if (entryId) {
      // Call API to track copy (don't wait for response)
      fetch(`/passwords/${entryId}/copy`, {
        method: 'POST',
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          // Update the copy count display if it exists
          const copyCountElement = document.querySelector('[data-copy-count]');
          if (copyCountElement) {
            copyCountElement.textContent = data.copyCount || 0;
          }
          // Also update the parent element that shows "📋 Copies: X"
          const copyCountParent = document.querySelector('#copyCount');
          if (copyCountParent) {
            copyCountParent.textContent = data.copyCount || 0;
          }
        }
      })
      .catch(error => {
        console.warn('Failed to track copy:', error);
      });
    }

    if (statusDiv) {
      statusDiv.textContent = '✓ Password copied to clipboard!';
      statusDiv.style.color = '#7fb069';
      statusDiv.style.display = 'block';
    }

    // Update button text temporarily
    const originalText = copyBtn.textContent;
    copyBtn.textContent = 'Copied!';
    copyBtn.style.background = '#7fb069';

    setTimeout(() => {
      if (statusDiv) statusDiv.style.display = 'none';
      copyBtn.textContent = originalText;
      copyBtn.style.background = '#3d3d3d';
    }, 2000);
  } else {
    if (statusDiv) {
      statusDiv.textContent = '✗ Failed to copy. Please try again.';
      statusDiv.style.color = '#d4a5a5';
      statusDiv.style.display = 'block';
      setTimeout(() => {
        if (statusDiv) statusDiv.style.display = 'none';
      }, 3000);
    }
  }
});

// TOTP live update (auto-refresh codes and countdown bar)
function initTotpLive() {
  const items = document.querySelectorAll('.totp-item[data-type="TOTP"]');
  if (items.length === 0) return;

  function updateOne(item) {
    const entryId = item.getAttribute('data-entry-id');
    const period = parseInt(item.getAttribute('data-period') || '30', 10);
    const codeEl = document.getElementById('totpCode-' + entryId);
    const timerEl = item.querySelector('.totp-timer');
    const barEl = item.querySelector('.totp-timer-bar');
    const textEl = item.querySelector('.totp-timer-text');
    const copyBtn = item.querySelector('.copy-totp');

    if (!codeEl || !timerEl || !barEl) return;

    const now = Date.now();
    const step = Math.floor(now / 1000 / period);
    const nextBoundary = (step + 1) * period * 1000;
    const remainingMs = Math.max(0, nextBoundary - now);
    const remainingSec = Math.ceil(remainingMs / 1000);
    const remainingPct = Math.max(0, Math.min(100, (remainingMs / 1000) / period * 100));
    barEl.style.width = remainingPct + '%';
    if (textEl) textEl.textContent = remainingSec + 's';

    // When hit boundary, fetch new code
    if (remainingMs < 250) {
      fetch('/totp/code?id=' + encodeURIComponent(entryId))
        .then(r => r.ok ? r.json() : Promise.reject())
        .then(data => {
          if (data && data.code) {
            codeEl.textContent = data.code;
            if (copyBtn) copyBtn.setAttribute('data-code', data.code);
          }
        })
        .catch(() => {});
    }
  }

  function tick() {
    items.forEach(item => updateOne(item));
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// Copy TOTP codes
document.addEventListener('click', async function(event) {
  const btn = event.target.closest('.copy-totp');
  if (!btn) return;
  event.preventDefault();
  const code = btn.getAttribute('data-code') || '';
  if (!code) return;
  const ok = await copyToClipboard(code);
  const orig = btn.textContent;
  btn.textContent = ok ? 'Copied!' : 'Copy';
  setTimeout(() => (btn.textContent = orig), 1200);
});

// Confirm destructive actions (delete links + delete forms)
document.addEventListener('click', function(event) {
  const link = event.target.closest('a');
  if (!link) return;

  const href = link.getAttribute('href') || '';
  // Only intercept obvious delete links; never block logout
  const isDelete = href.includes('/delete');
  const isLogout = href.includes('/logout');
  if (!isDelete || isLogout) return;

  const msg = link.getAttribute('data-confirm') || 'Are you sure you want to delete this? This cannot be undone.';
  if (!window.confirm(msg)) {
    event.preventDefault();
    event.stopPropagation();
  }
});

document.addEventListener('submit', function(event) {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;

  const action = form.getAttribute('action') || '';
  const isDelete = action.includes('/delete');
  if (!isDelete) return;

  const msg = form.getAttribute('data-confirm') || 'Are you sure you want to delete this? This cannot be undone.';
  if (!window.confirm(msg)) {
    event.preventDefault();
    event.stopPropagation();
  }
}, true);

// Generate a strong password that works on any site
function generateStrongPassword() {
  // Use safe characters that work on most sites
  // Avoid: < > & " ' / \ ` | and other problematic characters
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  // Use safer symbols that work on most sites
  const safeSymbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

  const allChars = lowercase + uppercase + numbers + safeSymbols;
  let password = '';

  // Ensure at least one of each type
  password += lowercase[Math.floor(Math.random() * lowercase.length)];
  password += uppercase[Math.floor(Math.random() * uppercase.length)];
  password += numbers[Math.floor(Math.random() * numbers.length)];
  password += safeSymbols[Math.floor(Math.random() * safeSymbols.length)];

  // Fill the rest randomly (total length 16-20 characters)
  const length = 16 + Math.floor(Math.random() * 5);
  for (let i = password.length; i < length; i++) {
    password += allChars[Math.floor(Math.random() * allChars.length)];
  }

  // Shuffle the password
  return password.split('').sort(() => Math.random() - 0.5).join('');
}

// Initialize password generator button
document.addEventListener('click', async function(event) {
  const generateBtn = event.target.closest('#generatePasswordBtn');
  if (!generateBtn) return;

  event.preventDefault();
  event.stopPropagation();

  const passwordInput = document.getElementById('password');
  if (passwordInput) {
    const generatedPassword = generateStrongPassword();
    passwordInput.value = generatedPassword;
    passwordInput.type = 'text'; // Show the generated password

    // Update strength indicator immediately
    checkPasswordStrength(generatedPassword);

    // Also trigger input event for any other listeners
    passwordInput.dispatchEvent(new Event('input', { bubbles: true }));

    // Copy to clipboard
    const copied = await copyToClipboard(generatedPassword);

    // Change button text temporarily
    const originalText = generateBtn.textContent;
    if (copied) {
      generateBtn.textContent = 'Copied!';
      generateBtn.style.background = '#7fb069';
    } else {
      generateBtn.textContent = 'Generated';
      generateBtn.style.background = '#9db4d4';
    }

    setTimeout(() => {
      generateBtn.textContent = originalText;
      generateBtn.style.background = '#3d3d3d';
    }, 2000);
  }
});

// Make password entry cards clickable
document.addEventListener('click', function(event) {
  const passwordEntry = event.target.closest('.password-entry');
  if (passwordEntry) {
    const passwordId = passwordEntry.getAttribute('data-password-id');
    if (passwordId) {
      window.location.href = `/passwords/${passwordId}`;
    }
  }
});

// Password search functionality
function initPasswordSearch() {
  const searchInput = document.getElementById('passwordSearch');
  if (!searchInput) return;

  searchInput.addEventListener('input', function() {
    const searchTerm = this.value.toLowerCase().trim();
    const passwordEntries = document.querySelectorAll('.password-entry');
    const noResultsMessage = document.getElementById('noResultsMessage');
    let visibleCount = 0;

    passwordEntries.forEach(entry => {
      const website = entry.getAttribute('data-website') || '';
      const username = entry.getAttribute('data-username') || '';
      const email = entry.getAttribute('data-email') || '';
      const notes = entry.getAttribute('data-notes') || '';

      const searchableText = `${website} ${username} ${email} ${notes}`;

      if (searchTerm === '' || searchableText.includes(searchTerm)) {
        entry.style.display = 'block';
        visibleCount++;
      } else {
        entry.style.display = 'none';
      }
    });

    // Show/hide "no results" message
    if (noResultsMessage) {
      if (visibleCount === 0 && searchTerm !== '') {
        noResultsMessage.style.display = 'block';
      } else {
        noResultsMessage.style.display = 'none';
      }
    }
  });
}

// Initialize password search on page load
document.addEventListener('DOMContentLoaded', function() {
  initPasswordSearch();
});

// Also initialize when content is dynamically loaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initPasswordSearch);
} else {
  // DOM already loaded, initialize immediately
  initPasswordSearch();
}

// Handle delete password form submission with confirmation
document.addEventListener('submit', function(event) {
  const form = event.target;
  if (form && form.id === 'deletePasswordForm') {
    const confirmed = confirm('Are you sure you want to delete this password? This action cannot be undone.');

    if (!confirmed) {
      event.preventDefault();
      return false;
    }
    // If confirmed, allow form to submit naturally
  }
});

// Entry editing functionality - use event delegation for dynamic content
// Store original values globally so they persist
let originalEntryValues = null;

// Initialize entry editing when DOM is ready or immediately if already loaded
function initEntryEditing() {
  // Try to get elements
  const editPasswordInput = document.getElementById('editPasswordInput');
  const editWebsiteInput = document.getElementById('editWebsiteInput');
  const editUsernameInput = document.getElementById('editUsernameInput');
  const editEmailInput = document.getElementById('editEmailInput');
  const editNotesInput = document.getElementById('editNotesInput');

  // Only initialize if we're on a password details page
  if (!editPasswordInput && !editWebsiteInput) {
    return; // Not on password details page
  }

  console.log('Initializing entry editing:', {
    hasEditBtn: !!document.getElementById('editEntryBtn'),
    hasEditForm: !!document.getElementById('editEntryForm'),
    hasViewMode: !!document.getElementById('entryViewMode'),
    hasEditMode: !!document.getElementById('entryEditMode'),
    hasWebsiteInput: !!editWebsiteInput,
    hasPasswordInput: !!editPasswordInput
  });

  // Store original values
  // For password field, we need to read it immediately as browsers may clear it when hidden
  let passwordValue = '';
  if (editPasswordInput) {
    // Password fields may not expose their value for security, so try attribute first
    if (editPasswordInput.hasAttribute('value')) {
      passwordValue = editPasswordInput.getAttribute('value') || '';
    }
    // If still empty, try to get value from the input field
    if (!passwordValue) {
      passwordValue = editPasswordInput.value || '';
    }
    console.log('Password value read:', passwordValue ? '[REDACTED]' : 'EMPTY', 'from attribute:', editPasswordInput.hasAttribute('value'));
  }

  originalEntryValues = {
    website: editWebsiteInput ? editWebsiteInput.value : '',
    username: editUsernameInput ? editUsernameInput.value : '',
    email: editEmailInput ? editEmailInput.value : '',
    password: passwordValue,
    notes: editNotesInput ? editNotesInput.value : ''
  };

  console.log('Stored original values:', {
    website: originalEntryValues.website,
    username: originalEntryValues.username,
    email: originalEntryValues.email,
    password: originalEntryValues.password ? '[REDACTED]' : 'EMPTY',
    notes: originalEntryValues.notes
  });

  // Update password strength indicator immediately if we have a password value
  // This ensures the strength is correct even when the form is hidden
  if (passwordValue && passwordValue.length > 0) {
    // Use a small delay to ensure DOM elements are ready
    setTimeout(() => {
      isUpdatingPasswordStrength = true;
      updateEditPasswordStrength(passwordValue);
      console.log('Password strength updated on page load');
      setTimeout(() => {
        isUpdatingPasswordStrength = false;
      }, 100);
    }, 100);
  } else {
    console.warn('No password value found to calculate strength on page load');
  }
}

// Initialize on DOMContentLoaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function() {
    initEntryEditing();
    // Also update strength after a short delay to ensure everything is ready
    if (originalEntryValues && originalEntryValues.password) {
      setTimeout(() => {
        updateEditPasswordStrength(originalEntryValues.password);
      }, 200);
    }
  });
} else {
  // DOM already loaded, initialize immediately
  initEntryEditing();
  // Also update strength after a short delay
  if (originalEntryValues && originalEntryValues.password) {
    setTimeout(() => {
      updateEditPasswordStrength(originalEntryValues.password);
    }, 200);
  }
}

// Use event delegation for edit button (works even if element is created dynamically)
document.addEventListener('click', function(event) {
  const editBtn = event.target.closest('#editEntryBtn');
  if (!editBtn) return;

  event.preventDefault();
  event.stopPropagation();

  const viewMode = document.getElementById('entryViewMode');
  const editMode = document.getElementById('entryEditMode');
  const editPasswordInput = document.getElementById('editPasswordInput');
  const editWebsiteInput = document.getElementById('editWebsiteInput');
  const toggleVisibilityBtn = document.getElementById('togglePasswordVisibility');

  if (!viewMode || !editMode) return;

  // Ensure password value is set (browsers may clear password fields when hidden)
  if (editPasswordInput && originalEntryValues && originalEntryValues.password) {
    // Set flag to prevent input event from interfering
    isUpdatingPasswordStrength = true;
    editPasswordInput.value = originalEntryValues.password;
    editPasswordInput.type = 'password'; // Ensure password is hidden initially
    console.log('Password value restored when entering edit mode:', editPasswordInput.value ? '[REDACTED]' : 'EMPTY', 'length:', originalEntryValues.password.length);

    // Update password strength after a short delay to ensure DOM is ready
    // Use the stored password value directly
    setTimeout(() => {
      updateEditPasswordStrength(originalEntryValues.password);
      isUpdatingPasswordStrength = false;
    }, 50);
  } else {
    console.warn('Could not restore password value - editPasswordInput:', !!editPasswordInput, 'originalEntryValues:', !!originalEntryValues);
  }

  // Update CSRF token before showing edit mode
  // Fetch a fresh token from the server
  const csrfInput = editMode.querySelector('input[name="csrfToken"]');
  if (csrfInput) {
    // Get fresh token by making a request to get the current page (which will have a fresh token)
    // Or we can just reload the token from a meta tag if available
    // For now, we'll fetch the page to get a fresh token
    fetch(window.location.href, {
      method: 'GET',
      credentials: 'include'
    })
    .then(response => response.text())
    .then(html => {
      // Extract CSRF token from the HTML
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');
      const freshTokenInput = doc.querySelector('input[name="csrfToken"]');
      if (freshTokenInput && freshTokenInput.value) {
        csrfInput.value = freshTokenInput.value;
        console.log('CSRF token updated');
      }
    })
    .catch(error => {
      console.warn('Could not update CSRF token:', error);
      // Continue anyway - the server will handle it
    });
  }

  viewMode.style.display = 'none';
  editMode.style.display = 'block';
  if (editWebsiteInput) {
    editWebsiteInput.focus();
    editWebsiteInput.select();
  }
  if (toggleVisibilityBtn) {
    toggleVisibilityBtn.textContent = 'Show';
  }
  // Password strength is already updated above when restoring the password value
  // But ensure it's set correctly after edit mode is fully visible
  if (originalEntryValues && originalEntryValues.password) {
    // Use a longer delay to ensure the DOM is fully updated and visible
    setTimeout(() => {
      isUpdatingPasswordStrength = true;
      const passwordToUse = originalEntryValues.password;
      console.log('Updating strength with password from originalEntryValues, length:', passwordToUse.length);
      updateEditPasswordStrength(passwordToUse);
      setTimeout(() => {
        isUpdatingPasswordStrength = false;
      }, 50);
    }, 150);
  }
});

// Use event delegation for cancel button
document.addEventListener('click', function(event) {
  const cancelBtn = event.target.closest('#cancelEditEntryBtn');
  if (!cancelBtn) return;

  event.preventDefault();
  event.stopPropagation();

  const viewMode = document.getElementById('entryViewMode');
  const editMode = document.getElementById('entryEditMode');
  const editWebsiteInput = document.getElementById('editWebsiteInput');
  const editUsernameInput = document.getElementById('editUsernameInput');
  const editEmailInput = document.getElementById('editEmailInput');
  const editPasswordInput = document.getElementById('editPasswordInput');
  const editNotesInput = document.getElementById('editNotesInput');
  const toggleVisibilityBtn = document.getElementById('togglePasswordVisibility');

  if (!viewMode || !editMode || !originalEntryValues) return;

  // Restore original values
  if (editWebsiteInput) editWebsiteInput.value = originalEntryValues.website;
  if (editUsernameInput) editUsernameInput.value = originalEntryValues.username;
  if (editEmailInput) editEmailInput.value = originalEntryValues.email;
  if (editPasswordInput) {
    editPasswordInput.value = originalEntryValues.password;
    editPasswordInput.type = 'password';
  }
  if (editNotesInput) editNotesInput.value = originalEntryValues.notes;
  if (toggleVisibilityBtn) toggleVisibilityBtn.textContent = 'Show';

  // Reset password strength display
  updateEditPasswordStrength(originalEntryValues.password);

  // Switch back to view mode
  editMode.style.display = 'none';
  viewMode.style.display = 'block';
});

// Use event delegation for toggle password visibility
document.addEventListener('click', function(event) {
  const toggleBtn = event.target.closest('#togglePasswordVisibility');
  if (!toggleBtn) return;

  event.preventDefault();
  event.stopPropagation();

  const editPasswordInput = document.getElementById('editPasswordInput');
  if (!editPasswordInput) return;

  if (editPasswordInput.type === 'password') {
    editPasswordInput.type = 'text';
    toggleBtn.textContent = 'Hide';
  } else {
    editPasswordInput.type = 'password';
    toggleBtn.textContent = 'Show';
  }
});

// Real-time password strength checking while editing (use event delegation)
// Use a flag to prevent the input event from overriding our manual strength updates
let isUpdatingPasswordStrength = false;

document.addEventListener('input', function(event) {
  if (event.target && event.target.id === 'editPasswordInput') {
    // Skip if we're in the middle of programmatically updating the password
    if (isUpdatingPasswordStrength) {
      return;
    }

    const passwordValue = event.target.value;
    // If the input is empty but we have the original password value, use that instead
    // This handles cases where browsers clear password fields but we still have the value stored
    if (!passwordValue && originalEntryValues && originalEntryValues.password) {
      updateEditPasswordStrength(originalEntryValues.password);
    } else if (passwordValue) {
      updateEditPasswordStrength(passwordValue);
    }
  }
});

// Handle form submission (use event delegation)
document.addEventListener('submit', function(event) {
  const editForm = event.target;
  if (!editForm || editForm.id !== 'editEntryForm') return;

  console.log('Form submit event triggered');

  const editWebsiteInput = document.getElementById('editWebsiteInput');
  const editPasswordInput = document.getElementById('editPasswordInput');
  const statusDiv = document.getElementById('editEntryStatus');

  let website = editWebsiteInput ? editWebsiteInput.value.trim() : '';
  let password = editPasswordInput ? editPasswordInput.value.trim() : '';

  // If password is empty but we have the original value, restore it
  // This handles cases where browsers clear password fields for security
  if (!password && originalEntryValues && originalEntryValues.password && editPasswordInput) {
    console.log('Password field appears empty, restoring from original value');
    editPasswordInput.value = originalEntryValues.password;
    password = originalEntryValues.password;
  }

  console.log('Form values before validation:', {
    website,
    password: password ? '[REDACTED]' : 'EMPTY',
    passwordLength: password ? password.length : 0,
    hasWebsiteInput: !!editWebsiteInput,
    hasPasswordInput: !!editPasswordInput,
    originalPasswordExists: !!(originalEntryValues && originalEntryValues.password)
  });

  if (!website) {
    event.preventDefault();
    console.log('Validation failed: Website is required');
    if (statusDiv) {
      statusDiv.textContent = '✗ Website is required';
      statusDiv.style.color = '#d4a5a5';
      statusDiv.style.display = 'block';
      setTimeout(() => {
        statusDiv.style.display = 'none';
      }, 3000);
    }
    if (editWebsiteInput) editWebsiteInput.focus();
    return false;
  }

  if (!password) {
    event.preventDefault();
    console.log('Validation failed: Password is required');
    if (statusDiv) {
      statusDiv.textContent = '✗ Password is required';
      statusDiv.style.color = '#d4a5a5';
      statusDiv.style.display = 'block';
      setTimeout(() => {
        statusDiv.style.display = 'none';
      }, 3000);
    }
    if (editPasswordInput) editPasswordInput.focus();
    return false;
  }

  console.log('Form validation passed, allowing submission');
  // Allow form to submit naturally - don't prevent default
});

// Update password strength indicator in edit mode
function updateEditPasswordStrength(password) {
  const strengthBar = document.getElementById('editPasswordStrengthBar');
  const strengthText = document.getElementById('editPasswordStrengthText');

  console.log('updateEditPasswordStrength called with password length:', password ? password.length : 0, 'hasBar:', !!strengthBar, 'hasText:', !!strengthText, 'password:', password ? password.substring(0, 3) + '...' : 'EMPTY');

  if (!strengthBar || !strengthText) {
    console.warn('Password strength elements not found!');
    return;
  }

  // If password is empty or undefined, try to get it from the input field
  if (!password || password.length === 0) {
    const input = document.getElementById('editPasswordInput');
    if (input && input.value) {
      password = input.value;
      console.log('Got password from input field, length:', password.length);
    } else if (originalEntryValues && originalEntryValues.password) {
      password = originalEntryValues.password;
      console.log('Got password from originalEntryValues, length:', password.length);
    } else {
      console.warn('No password value available for strength calculation');
      return;
    }
  }

  // Calculate strength directly (don't use checkPasswordStrength as it looks for wrong DOM elements)
  let strength = 0;
  if (password.length >= 6) strength++;
  if (password.length >= 8) strength++;
  if (password.length >= 12) strength++;
  if (/[a-z]/.test(password)) strength++;
  if (/[A-Z]/.test(password)) strength++;
  if (/[0-9]/.test(password)) strength++;
  if (/[^a-zA-Z0-9]/.test(password)) strength++;

  console.log('Password strength calculation result:', { strength, passwordLength: password.length });

  let percentage = 0;
  let color = '#4d4d4d';
  let text = 'Unknown';

  if (password.length === 0) {
    percentage = 0;
    color = '#4d4d4d';
    text = '';
  } else if (strength <= 2) {
    percentage = 33;
    color = '#d4a5a5';
    text = 'Weak';
  } else if (strength <= 4) {
    percentage = 66;
    color = '#d4a5a5';
    text = 'Fair';
  } else if (strength <= 5) {
    percentage = 80;
    color = '#9db4d4';
    text = 'Good';
  } else {
    percentage = 100;
    color = '#7fb069';
    text = 'Strong';
  }

  strengthBar.style.width = percentage + '%';
  strengthBar.style.backgroundColor = color;
  strengthText.textContent = text;
  strengthText.style.color = color;
}


