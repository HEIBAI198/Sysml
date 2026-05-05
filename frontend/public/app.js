(() => {
  const key = 'sysml_shadcn_cache_bust'
  const current = new URL(window.location.href)
  if (current.searchParams.get(key) === '1') {
    window.location.reload()
    return
  }
  current.searchParams.set(key, '1')
  window.location.replace(current.toString())
})()
