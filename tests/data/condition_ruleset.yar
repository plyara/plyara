rule image_filetype {
    condition:
        (
            uint32be(0x00) == 0x89504E47 or // PNG
            uint16be(0x00) == 0xFFD8 or // JPEG
            uint32be(0x00) == 0x47494638 // GIF
        )
        and
        (
            $eval or 1 of ($key*)
        )
        and
        (
            @a[1] or !a[1]
        )
        and
        not filename matches /[0-9a-zA-Z]{30,}/ 
}
