find tests/data -type f | while read -r file; do
    echo "\n${file##*/}"
	find tests -type f -name '*.py' -exec grep -H ${file##*/} {} \;
done
