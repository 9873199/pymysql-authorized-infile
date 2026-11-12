.. _examples:

========
Examples
========

.. _CRUD:

CRUD
----

The following examples make use of a simple table

.. code:: sql

   CREATE TABLE `users` (
       `id` int(11) NOT NULL AUTO_INCREMENT,
       `email` varchar(255) COLLATE utf8_bin NOT NULL,
       `password` varchar(255) COLLATE utf8_bin NOT NULL,
       PRIMARY KEY (`id`)
   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
   AUTO_INCREMENT=1 ;


.. code:: python

    import pymysql.cursors

    # Connect to the database
    connection = pymysql.connect(host='localhost',
                                 user='user',
                                 password='passwd',
                                 database='db',
                                 charset='utf8mb4',
                                 cursorclass=pymysql.cursors.DictCursor)

    with connection:
        with connection.cursor() as cursor:
            # Create a new record
            sql = "INSERT INTO `users` (`email`, `password`) VALUES (%s, %s)"
            cursor.execute(sql, ('webmaster@python.org', 'very-secret'))

        # connection is not autocommit by default. So you must commit to save
        # your changes.
        connection.commit()

        with connection.cursor() as cursor:
            # Read a single record
            sql = "SELECT `id`, `password` FROM `users` WHERE `email`=%s"
            cursor.execute(sql, ('webmaster@python.org',))
            result = cursor.fetchone()
            print(result)


This example will print:

.. code:: python

    {'id': 1, 'password': 'very-secret'}


LOAD DATA LOCAL INFILE with per-command stream grants
-----------------------------------------------------

A malicious or compromised server can answer any query with a 0xfb
``LOAD LOCAL`` packet and choose an arbitrary path on your disk (the
classic `LOAD DATA LOCAL INFILE attack
<https://dev.mysql.com/doc/refman/en/load-data.html>`_).  The boolean
``local_infile`` connection option keeps its legacy behavior of opening
whatever path the server names; for connections to servers that are not
fully trusted, ``Cursor.execute()`` accepts a ``local_infile_streams``
keyword that authorizes exactly the bytes you intend to hand over for
this one command.

The argument is a mapping of the **raw protocol filename bytes** the
server may send to an already open, readable binary stream:

.. code:: python

    import io
    import pymysql.cursors

    connection = pymysql.connect(
        host='localhost',
        user='user',
        password='passwd',
        local_infile=True,  # required so the server may send 0xfb packets
    )

    payload = b"1,alpha\n2,beta\n"
    with connection.cursor() as cursor:
        # The SQL text may name anything; the grant keys are what matter.
        cursor.execute(
            "LOAD DATA LOCAL INFILE 'whatever' INTO TABLE t FIELDS TERMINATED BY ','",
            local_infile_streams={b"approved.csv": io.BytesIO(payload)},
        )

The mapping is valid only for this command's result set lifecycle.
The name sent by the server is matched byte-for-byte against the grant
keys — it is never decoded, normalized or looked up on disk, and no
server-provided name ever reaches :func:`open`.  Each stream is consumed
at most once; an unknown name, a repeated request for a consumed stream,
or a stream that raises while being read closes the connection so the
next query cannot consume leftover packets.  Streams remain owned by the
caller and are never closed by the driver.

Without ``local_infile_streams``, the legacy ``local_infile=True``
behavior is unchanged.
