package secretbus

import (
	"github.com/stubbedev/lys-lib/dbusx"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

const (
	ServiceInterface    = "org.freedesktop.Secret.Service"
	CollectionInterface = "org.freedesktop.Secret.Collection"
	ItemInterface       = "org.freedesktop.Secret.Item"
	SessionInterface    = "org.freedesktop.Secret.Session"
	PromptInterface     = "org.freedesktop.Secret.Prompt"
)

type CollectionEvent struct {
	Collection dbus.ObjectPath `dbus:"collection"`
}

type ItemEvent struct {
	Item dbus.ObjectPath `dbus:"item"`
}

type Completion struct {
	Dismissed bool         `dbus:"dismissed"`
	Result    dbus.Variant `dbus:"result"`
}

var (
	CollectionCreated = dbusx.NewSignal[CollectionEvent](ServiceInterface, "CollectionCreated")
	CollectionDeleted = dbusx.NewSignal[CollectionEvent](ServiceInterface, "CollectionDeleted")
	CollectionChanged = dbusx.NewSignal[CollectionEvent](ServiceInterface, "CollectionChanged")

	ItemCreated = dbusx.NewSignal[ItemEvent](CollectionInterface, "ItemCreated")
	ItemDeleted = dbusx.NewSignal[ItemEvent](CollectionInterface, "ItemDeleted")
	ItemChanged = dbusx.NewSignal[ItemEvent](CollectionInterface, "ItemChanged")

	PromptCompleted = dbusx.NewSignal[Completion](PromptInterface, "Completed")
)
