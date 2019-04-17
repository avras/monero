This directory has two scripts which were used to measure the time taken to check whether some key images have appeared on the blockchain.

  - `keyimage_file_generator.py`

      Running `python keyimage_file_generator.py <anon_set_size> <image_file>` will create a file called `image_file` containing `anon_set_size` random key images (essentially random 64-digit hex strings).

      For example, `python keyimage_file_generator.py 1000 images.json`.



  - `spent_status_checker.py`

    Running `python spent_status_checker.py <image_file>` will do the following:

      + Load all the key images from `image_file`
      + Do a batch query on `http://127.0.0.1:18081/is_key_image_spent`
      + Check if all the key images are unspent.

    For example, `python spent_status_checker.py image.json`.
