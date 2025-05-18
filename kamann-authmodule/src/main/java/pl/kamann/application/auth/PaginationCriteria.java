package pl.kamann.application.auth;

class PaginationCriteria {
    private int page;
    private int size;
    private String sortBy;
    private String direction;

    public PaginationCriteria() {
        this.page = 0;
        this.size = 10;
        this.sortBy = "id";
        this.direction = "asc";
    }

    public PaginationCriteria(int page, int size, String sortBy, String direction) {
        this.page = Math.max(page, 0);
        this.size = Math.max(size, 1);
        this.sortBy = sortBy;
        this.direction = direction;
    }

    public int getPage() {
        return page;
    }

    public int getSize() {
        return size;
    }

    public String getSortBy() {
        return sortBy;
    }

    public String getDirection() {
        return direction;
    }

    public void setPage(int page) {
        this.page = Math.max(page, 0);
    }

    public void setSize(int size) {
        this.size = Math.max(size, 1);
    }

    public void setSortBy(String sortBy) {
        this.sortBy = sortBy;
    }

    public void setDirection(String direction) {
        this.direction = direction;
    }
}