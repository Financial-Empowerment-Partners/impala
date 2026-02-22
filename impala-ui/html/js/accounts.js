/**
 * Accounts page module — search, create, and update Stellar/Payala accounts.
 *
 * Search by stellar_account_id, create new linked accounts, or edit existing
 * ones. The Edit button and create/update forms respect the manage_accounts
 * permission. Validates Stellar IDs and phone numbers before submission.
 */
(function () {
    Router.init();

    var searchBtn = document.getElementById('search-btn');
    var searchInput = document.getElementById('search-account-id');
    var resultDiv = document.getElementById('search-result');
    var createForm = document.getElementById('create-form');
    var updateCard = document.getElementById('update-card');
    var updateForm = document.getElementById('update-form');

    searchBtn.addEventListener('click', doSearch);
    searchInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') doSearch();
    });

    function doSearch() {
        var id = searchInput.value.trim();
        if (!id) {
            Router.showToast('Please enter an account ID to search', 'warning');
            return;
        }

        var check = Validate.stellarId(id);
        if (!check.valid) {
            Router.showToast(check.message, 'warning');
            return;
        }

        API.setButtonLoading(searchBtn, true);
        resultDiv.innerHTML = '<div class="spinner"></div> Searching...';

        API.get('/account?stellar_account_id=' + encodeURIComponent(id))
            .then(function (data) {
                showResult(data);
            })
            .catch(function (err) {
                resultDiv.innerHTML = '<div class="callout warning">' + escapeHtml(err.message) + '</div>';
            })
            .then(function () {
                API.setButtonLoading(searchBtn, false);
            });
    }

    function showResult(data) {
        var html = '<table><thead><tr>' +
            '<th>Stellar ID</th><th>Payala ID</th><th>Display Name</th><th>Phone</th><th>Created</th>' +
            '</tr></thead><tbody>';

        var row = data;
        if (Array.isArray(data)) {
            if (data.length === 0) {
                resultDiv.innerHTML = '<div class="callout primary">No account found.</div>';
                return;
            }
            row = data[0];
        }

        html += '<tr>' +
            '<td>' + escapeHtml(row.stellar_account_id || '') + '</td>' +
            '<td>' + escapeHtml(row.payala_account_id || '') + '</td>' +
            '<td>' + escapeHtml(row.display_name || '') + '</td>' +
            '<td>' + escapeHtml(row.phone || '') + '</td>' +
            '<td>' + escapeHtml(row.created_at || '') + '</td>' +
            '</tr></tbody></table>';

        if (Roles.currentUserHasPermission('manage_accounts')) {
            html += '<button class="button small" id="edit-result-btn">Edit</button>';
        }

        resultDiv.innerHTML = html;

        var editBtn = document.getElementById('edit-result-btn');
        if (editBtn) {
            editBtn.addEventListener('click', function () {
                populateUpdate(row);
            });
        }
    }

    function populateUpdate(row) {
        document.getElementById('update-stellar-id').value = row.stellar_account_id || '';
        document.getElementById('update-payala-id').value = row.payala_account_id || '';
        document.getElementById('update-display-name').value = row.display_name || '';
        document.getElementById('update-phone').value = row.phone || '';
        updateCard.classList.remove('hidden');
        updateCard.scrollIntoView({ behavior: 'smooth' });
    }

    createForm.addEventListener('submit', function (e) {
        e.preventDefault();

        var stellarId = document.getElementById('create-stellar-id').value.trim();
        var phone = document.getElementById('create-phone').value.trim();

        // Validate required fields
        var error = Validate.firstError([
            Validate.stellarId(stellarId)
        ]);
        if (error) {
            Router.showToast(error, 'warning');
            return;
        }

        // Validate phone if provided
        if (phone) {
            var phoneCheck = Validate.phone(phone);
            if (!phoneCheck.valid) {
                Router.showToast(phoneCheck.message, 'warning');
                return;
            }
        }

        var body = {
            stellar_account_id: stellarId,
            payala_account_id: document.getElementById('create-payala-id').value.trim() || undefined,
            display_name: document.getElementById('create-display-name').value.trim() || undefined,
            phone: phone || undefined
        };

        var submitBtn = createForm.querySelector('button[type="submit"]');
        API.setButtonLoading(submitBtn, true);

        API.post('/account', body)
            .then(function () {
                Router.showToast('Account created', 'success');
                createForm.reset();
            })
            .catch(function (err) {
                Router.showToast('Error: ' + err.message, 'alert');
            })
            .then(function () {
                API.setButtonLoading(submitBtn, false);
            });
    });

    updateForm.addEventListener('submit', function (e) {
        e.preventDefault();

        var phone = document.getElementById('update-phone').value.trim();

        // Validate phone if provided
        if (phone) {
            var phoneCheck = Validate.phone(phone);
            if (!phoneCheck.valid) {
                Router.showToast(phoneCheck.message, 'warning');
                return;
            }
        }

        var body = {
            stellar_account_id: document.getElementById('update-stellar-id').value.trim(),
            payala_account_id: document.getElementById('update-payala-id').value.trim() || undefined,
            display_name: document.getElementById('update-display-name').value.trim() || undefined,
            phone: phone || undefined
        };

        var submitBtn = updateForm.querySelector('button[type="submit"]');
        API.setButtonLoading(submitBtn, true);

        API.put('/account', body)
            .then(function () {
                Router.showToast('Account updated', 'success');
                updateCard.classList.add('hidden');
            })
            .catch(function (err) {
                Router.showToast('Error: ' + err.message, 'alert');
            })
            .then(function () {
                API.setButtonLoading(submitBtn, false);
            });
    });

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }
})();
