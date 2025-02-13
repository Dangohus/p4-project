SELECT
  UNIX_TIMESTAMP() as time,
  AVG(hop_latency)/1000 AS value,
  switch_id
FROM (
  SELECT
      id,
      hop_latency,
      switch_id,
      inserted_at
  FROM
    demo_data
  WHERE
    switch_id = 1
  ORDER BY
    id
  DESC LIMIT 2)
demo_data
GROUP BY switch_id;


SELECT
	AVG(value) as value,
    UNIX_TIMESTAMP()
FROM
	(SELECT
		hop_latency/1000 AS value,
		switch_id,
		mon_id,
        id
	FROM demo_data
    WHERE mon_id IN
	(
		SELECT
			mon_id
		FROM
			flows
		WHERE id = (
			SELECT MAX(id) FROM flows
		)
	)
	AND switch_id = 1
    ORDER BY id DESC LIMIT 2
) t
