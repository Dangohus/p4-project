SELECT
  UNIX_TIMESTAMP(inserted_at) as time,
  hop_latency/1000 AS hop_latency
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
    inserted_at)
demo_data
WHERE $__timeFilter(inserted_at);

SELECT
  UNIX_TIMESTAMP(inserted_at) as time,
  hop_latency/1000 AS hop_latency
FROM (
  SELECT
      id,
      hop_latency,
      switch_id,
      inserted_at
  FROM
    demo_data
  WHERE
    switch_id = 2
  ORDER BY
    inserted_at)
demo_data
WHERE $__timeFilter(inserted_at);
