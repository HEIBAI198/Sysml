import { type ReactNode } from 'react'
import { Link, useLocation, useNavigate } from '@tanstack/react-router'
import { ChevronRight } from 'lucide-react'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  useSidebar,
} from '@/components/ui/sidebar'
import { Badge } from '../ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu'
import {
  type NavCollapsible,
  type NavItem,
  type NavLink,
  type NavGroup as NavGroupProps,
} from './types'

export function NavGroup({ title, items }: NavGroupProps) {
  const { state, isMobile } = useSidebar()
  const href = useLocation({ select: (location) => location.href })
  const navigate = useNavigate()
  return (
    <SidebarGroup>
      <SidebarGroupLabel>{title}</SidebarGroupLabel>
      <SidebarMenu>
        {items.map((item) => {
          const key = `${item.title}-${item.url}`

          if (!item.items)
            return <SidebarMenuLink key={key} item={item} href={href} navigate={navigate} />

          if (state === 'collapsed' && !isMobile)
            return (
              <SidebarMenuCollapsedDropdown key={key} item={item} href={href} navigate={navigate} />
            )

          return <SidebarMenuCollapsible key={key} item={item} href={href} navigate={navigate} />
        })}
      </SidebarMenu>
    </SidebarGroup>
  )
}

function NavBadge({ children }: { children: ReactNode }) {
  return <Badge className='rounded-full px-1 py-0 text-xs'>{children}</Badge>
}

function SidebarMenuLink({
  item,
  href,
  navigate,
}: {
  item: NavLink
  href: string
  navigate: ReturnType<typeof useNavigate>
}) {
  const { setOpenMobile } = useSidebar()
  const workbenchHash = getWorkbenchHash(item.url)
  const projectImportHash = getProjectImportHash(item.url)

  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        asChild
        isActive={checkIsActive(href, item)}
        tooltip={item.title}
      >
        {workbenchHash ? (
          <a
            href={`/${workbenchHash}`}
            onClick={(event) => {
              event.preventDefault()
              openWorkbenchSection(workbenchHash)
              setOpenMobile(false)
            }}
          >
            {item.icon && <item.icon />}
            <span>{item.title}</span>
            {item.badge && <NavBadge>{item.badge}</NavBadge>}
          </a>
        ) : projectImportHash ? (
          <a
            href={`/project-import#${projectImportHash}`}
            onClick={(event) => {
              event.preventDefault()
              openProjectImportSection(projectImportHash, navigate)
              setOpenMobile(false)
            }}
          >
            {item.icon && <item.icon />}
            <span>{item.title}</span>
            {item.badge && <NavBadge>{item.badge}</NavBadge>}
          </a>
        ) : (
          <Link to={item.url} onClick={() => setOpenMobile(false)}>
            {item.icon && <item.icon />}
            <span>{item.title}</span>
            {item.badge && <NavBadge>{item.badge}</NavBadge>}
          </Link>
        )}
      </SidebarMenuButton>
    </SidebarMenuItem>
  )
}

function SidebarMenuCollapsible({
  item,
  href,
  navigate,
}: {
  item: NavCollapsible
  href: string
  navigate: ReturnType<typeof useNavigate>
}) {
  const { setOpenMobile } = useSidebar()
  return (
    <Collapsible
      asChild
      defaultOpen={checkIsActive(href, item, true)}
      className='group/collapsible'
    >
      <SidebarMenuItem>
        <CollapsibleTrigger asChild>
          <SidebarMenuButton tooltip={item.title}>
            {item.icon && <item.icon />}
            <span>{item.title}</span>
            {item.badge && <NavBadge>{item.badge}</NavBadge>}
            <ChevronRight className='ms-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90 rtl:rotate-180' />
          </SidebarMenuButton>
        </CollapsibleTrigger>
        <CollapsibleContent className='CollapsibleContent'>
          <SidebarMenuSub>
            {item.items.map((subItem) => {
              const workbenchHash = getWorkbenchHash(subItem.url)
              const projectImportHash = getProjectImportHash(subItem.url)

              return (
                <SidebarMenuSubItem key={subItem.title}>
                  <SidebarMenuSubButton
                    asChild
                    isActive={checkIsActive(href, subItem)}
                  >
                    {workbenchHash ? (
                      <a
                        href={`/${workbenchHash}`}
                        onClick={(event) => {
                          event.preventDefault()
                          openWorkbenchSection(workbenchHash)
                          setOpenMobile(false)
                        }}
                      >
                        {subItem.icon && <subItem.icon />}
                        <span>{subItem.title}</span>
                        {subItem.badge && <NavBadge>{subItem.badge}</NavBadge>}
                      </a>
                    ) : projectImportHash ? (
                      <a
                        href={`/project-import#${projectImportHash}`}
                        onClick={(event) => {
                          event.preventDefault()
                          openProjectImportSection(projectImportHash, navigate)
                          setOpenMobile(false)
                        }}
                      >
                        {subItem.icon && <subItem.icon />}
                        <span>{subItem.title}</span>
                        {subItem.badge && <NavBadge>{subItem.badge}</NavBadge>}
                      </a>
                    ) : (
                      <Link
                        to={subItem.url}
                        onClick={() => setOpenMobile(false)}
                      >
                        {subItem.icon && <subItem.icon />}
                        <span>{subItem.title}</span>
                        {subItem.badge && <NavBadge>{subItem.badge}</NavBadge>}
                      </Link>
                    )}
                  </SidebarMenuSubButton>
                </SidebarMenuSubItem>
              )
            })}
          </SidebarMenuSub>
        </CollapsibleContent>
      </SidebarMenuItem>
    </Collapsible>
  )
}

function SidebarMenuCollapsedDropdown({
  item,
  href,
  navigate,
}: {
  item: NavCollapsible
  href: string
  navigate: ReturnType<typeof useNavigate>
}) {
  return (
    <SidebarMenuItem>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <SidebarMenuButton
            tooltip={item.title}
            isActive={checkIsActive(href, item)}
          >
            {item.icon && <item.icon />}
            <span>{item.title}</span>
            {item.badge && <NavBadge>{item.badge}</NavBadge>}
            <ChevronRight className='ms-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90' />
          </SidebarMenuButton>
        </DropdownMenuTrigger>
        <DropdownMenuContent side='right' align='start' sideOffset={4}>
          <DropdownMenuLabel>
            {item.title} {item.badge ? `(${item.badge})` : ''}
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          {item.items.map((sub) => {
            const workbenchHash = getWorkbenchHash(sub.url)
            const projectImportHash = getProjectImportHash(sub.url)

            return (
              <DropdownMenuItem key={`${sub.title}-${sub.url}`} asChild>
                {workbenchHash ? (
                  <a
                    href={`/${workbenchHash}`}
                    className={`${checkIsActive(href, sub) ? 'bg-secondary' : ''}`}
                    onClick={(event) => {
                      event.preventDefault()
                      openWorkbenchSection(workbenchHash)
                    }}
                  >
                    {sub.icon && <sub.icon />}
                    <span className='max-w-52 text-wrap'>{sub.title}</span>
                    {sub.badge && (
                      <span className='ms-auto text-xs'>{sub.badge}</span>
                    )}
                  </a>
                ) : projectImportHash ? (
                  <a
                    href={`/project-import#${projectImportHash}`}
                    className={`${checkIsActive(href, sub) ? 'bg-secondary' : ''}`}
                    onClick={(event) => {
                      event.preventDefault()
                      openProjectImportSection(projectImportHash, navigate)
                    }}
                  >
                    {sub.icon && <sub.icon />}
                    <span className='max-w-52 text-wrap'>{sub.title}</span>
                    {sub.badge && (
                      <span className='ms-auto text-xs'>{sub.badge}</span>
                    )}
                  </a>
                ) : (
                  <Link
                    to={sub.url}
                    className={`${checkIsActive(href, sub) ? 'bg-secondary' : ''}`}
                  >
                    {sub.icon && <sub.icon />}
                    <span className='max-w-52 text-wrap'>{sub.title}</span>
                    {sub.badge && (
                      <span className='ms-auto text-xs'>{sub.badge}</span>
                    )}
                  </Link>
                )}
              </DropdownMenuItem>
            )
          })}
        </DropdownMenuContent>
      </DropdownMenu>
    </SidebarMenuItem>
  )
}

function checkIsActive(href: string, item: NavItem, mainNav = false) {
  const workbenchHash = getWorkbenchHash(item.url)
  if (workbenchHash) {
    const currentHash =
      typeof window === 'undefined' ? '' : window.location.hash
    return href.endsWith(workbenchHash) || currentHash === workbenchHash
  }

  const projectImportHash = getProjectImportHash(item.url)
  if (projectImportHash) {
    const currentHash =
      typeof window === 'undefined' ? '' : window.location.hash.replace(/^#/, '')
    return href.startsWith('/project-import') && currentHash === projectImportHash
  }

  return (
    href === item.url || // /endpint?search=param
    href.split('?')[0] === item.url || // endpoint
    !!item?.items?.filter((i) => i.url === href).length || // if child nav is active
    (mainNav &&
      href.split('/')[1] !== '' &&
      href.split('/')[1] === item?.url?.split('/')[1])
  )
}

function getWorkbenchHash(url: NavItem['url'] | undefined) {
  return typeof url === 'string' && url.startsWith('/#')
    ? url.slice(1)
    : ''
}

function getProjectImportHash(url: NavItem['url'] | undefined) {
  if (typeof url !== 'string') return ''
  const match = url.match(/^\/project-import#(.+)$/)
  return match?.[1] ?? ''
}

function openWorkbenchSection(hash: string) {
  if (typeof window === 'undefined') return

  const nextUrl = `/${hash}`
  if (window.location.pathname !== '/') {
    window.location.assign(nextUrl)
    return
  }

  if (window.location.hash === hash) {
    window.dispatchEvent(new HashChangeEvent('hashchange'))
    return
  }

  window.history.pushState(null, '', hash)
  window.dispatchEvent(new HashChangeEvent('hashchange'))
}

function openProjectImportSection(
  hash: string,
  navigate: ReturnType<typeof useNavigate>
) {
  void navigate({ to: '/project-import', hash })
  window.setTimeout(() => {
    if (window.location.hash !== `#${hash}`) {
      window.history.replaceState(null, '', `/project-import#${hash}`)
    }
    window.dispatchEvent(new HashChangeEvent('hashchange'))
  }, 0)
}
