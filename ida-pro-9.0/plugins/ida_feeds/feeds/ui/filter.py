from PyQt5.QtCore import QSortFilterProxyModel, QRegularExpression
from PyQt5.QtCore import Qt


class CustomFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.filter_matches = False
        self.filter_dir = ''
        self.setSortRole(Qt.DisplayRole)
        self.setFilterCaseSensitivity(Qt.CaseInsensitive)

    def applyFilters(self, filter_pattern, filter_dir, filter_matches):
        self.filter_matches = filter_matches
        self.filter_dir = filter_dir
        self.setFilterRegularExpression(QRegularExpression(filter_pattern))

    def filterAcceptsRow(self, source_row, source_parent):
        model = self.sourceModel()
        regex = self.filterRegularExpression()

        # Check if the regex is valid
        if not regex.isValid():
            print(f'invalid regex {regex}')
            return True  # Show all rows if the regex is invalid

        # Don't filter children of group items
        if source_parent.isValid():
            return True

        # Filter no matches
        if self.filter_matches is True:
            index = model.index(source_row, 2)
            data = model.data(index, Qt.UserRole)
            if data < 1:
                return False

        if not self.dir_matches(model, source_row):
            return False

        # Check if the regex pattern is empty
        if regex.pattern() == "":
            return True  # Show all rows if no pattern is set

        return self.row_matches(model, source_row, regex)

    def dir_matches(self, model, row):
        index = model.index(row, 0)
        data = model.data(index, Qt.UserRole)
        if data is not None:
            if self.filter_dir in data:
                return True
        return False

    def row_matches(self, model, row, regex):
        for column in range(0, 2):
            index = model.index(row, column)
            data = model.data(index, Qt.DisplayRole)
            if data is not None:
                data_str = str(data)
                if regex.match(data_str).hasMatch():
                    return True
        return False

    def lessThan(self, left, right):
        col = left.column()
        if col in [2, 3, 4]:
            ldata = self.sourceModel().data(left, Qt.UserRole)
            rdata = self.sourceModel().data(right, Qt.UserRole)
            # Convert data to float for numeric comparison
            lvalue = float(ldata) if ldata else 0
            rvalue = float(rdata) if rdata else 0
            return lvalue < rvalue

        # Fallback to default sorting behavior
        return super(CustomFilterProxyModel, self).lessThan(left, right)
