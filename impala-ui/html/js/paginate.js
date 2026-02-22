/**
 * Client-side pagination module for table data.
 *
 * Provides data slicing and UI control rendering with prev/next navigation.
 *
 * @module Paginate
 */
var Paginate = (function () {
    /**
     * Paginate an array of data items.
     * @param {Array} data - The full data array.
     * @param {number} page - Current page number (1-based).
     * @param {number} pageSize - Number of items per page.
     * @returns {{items: Array, page: number, pageSize: number, totalPages: number, totalItems: number}}
     */
    function paginate(data, page, pageSize) {
        var totalItems = data.length;
        var totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
        page = Math.max(1, Math.min(page, totalPages));
        var start = (page - 1) * pageSize;
        var items = data.slice(start, start + pageSize);

        return {
            items: items,
            page: page,
            pageSize: pageSize,
            totalPages: totalPages,
            totalItems: totalItems
        };
    }

    /**
     * Render pagination controls (prev/next buttons + page indicator) into a container.
     * @param {{page: number, totalPages: number, totalItems: number}} info - Pagination info from paginate().
     * @param {string} containerId - DOM element ID to render controls into.
     * @param {function} onPageChange - Callback invoked with the new page number.
     */
    function renderControls(info, containerId, onPageChange) {
        var container = document.getElementById(containerId);
        if (!container) return;

        if (info.totalPages <= 1) {
            container.innerHTML = '';
            return;
        }

        var html = '<div class="pagination-controls" style="display:flex;align-items:center;justify-content:center;gap:1rem;margin-top:0.75rem;">';
        html += '<button class="button small secondary paginate-prev"' +
            (info.page <= 1 ? ' disabled' : '') +
            ' aria-label="Previous page">Prev</button>';
        html += '<span>Page ' + info.page + ' of ' + info.totalPages +
            ' (' + info.totalItems + ' items)</span>';
        html += '<button class="button small secondary paginate-next"' +
            (info.page >= info.totalPages ? ' disabled' : '') +
            ' aria-label="Next page">Next</button>';
        html += '</div>';

        container.innerHTML = html;

        var prevBtn = container.querySelector('.paginate-prev');
        var nextBtn = container.querySelector('.paginate-next');

        if (prevBtn) {
            prevBtn.addEventListener('click', function () {
                if (info.page > 1) onPageChange(info.page - 1);
            });
        }
        if (nextBtn) {
            nextBtn.addEventListener('click', function () {
                if (info.page < info.totalPages) onPageChange(info.page + 1);
            });
        }
    }

    return {
        paginate: paginate,
        renderControls: renderControls
    };
})();
