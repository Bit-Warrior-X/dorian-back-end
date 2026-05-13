package data

type Server struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	IP          string `json:"ip"`
	StatusLabel string `json:"statusLabel"`
	StatusClass string `json:"statusClass"`
	Users       int    `json:"users"`
	License     string `json:"license"`
	Version     string `json:"version"`
	ExpiredDate string `json:"expiredDate"`
	Created     string `json:"created"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	SSHPort     string `json:"sshPort"`
}

type userCredential struct {
	Email    string
	Password string
	Role     string
}

var servers = []Server{
	{
		ID:          "edge-nyc-01",
		Name:        "Edge-NYC-01",
		IP:          "192.168.10.12",
		StatusLabel: "Active",
		StatusClass: "active",
		Users:       124,
		License:     "Unified",
		Version:     "v3.2.1",
		ExpiredDate: "Jan 12, 2027",
		Created:     "Jan 12, 2026",
		Username:    "root",
		Password:    "",
		SSHPort:     "22",
	},
	{
		ID:          "edge-lon-02",
		Name:        "Edge-LON-02",
		IP:          "10.20.30.44",
		StatusLabel: "Maintenance",
		StatusClass: "maintenance",
		Users:       87,
		License:     "L7",
		Version:     "v3.1.4",
		ExpiredDate: "Dec 28, 2026",
		Created:     "Dec 28, 2025",
		Username:    "admin",
		Password:    "",
		SSHPort:     "2222",
	},
	{
		ID:          "edge-sin-05",
		Name:        "Edge-SIN-05",
		IP:          "172.16.4.8",
		StatusLabel: "Inactive",
		StatusClass: "inactive",
		Users:       0,
		License:     "Trial",
		Version:     "v3.0.9",
		ExpiredDate: "Jan 04, 2026",
		Created:     "Nov 04, 2025",
		Username:    "ops",
		Password:    "",
		SSHPort:     "22",
	},
	{
		ID:          "edge-sfo-03",
		Name:        "Edge-SFO-03",
		IP:          "10.12.40.11",
		StatusLabel: "Active",
		StatusClass: "active",
		Users:       203,
		License:     "Unified",
		Version:     "v3.2.0",
		ExpiredDate: "Mar 03, 2027",
		Created:     "Mar 03, 2026",
		Username:    "root",
		Password:    "",
		SSHPort:     "22",
	},
	{
		ID:          "edge-fra-04",
		Name:        "Edge-FRA-04",
		IP:          "10.32.55.90",
		StatusLabel: "Active",
		StatusClass: "active",
		Users:       64,
		License:     "L4",
		Version:     "v3.1.2",
		ExpiredDate: "Aug 21, 2026",
		Created:     "Aug 21, 2025",
		Username:    "admin",
		Password:    "",
		SSHPort:     "2222",
	},
	{
		ID:          "edge-dxb-06",
		Name:        "Edge-DXB-06",
		IP:          "172.20.14.16",
		StatusLabel: "Maintenance",
		StatusClass: "maintenance",
		Users:       45,
		License:     "L7",
		Version:     "v3.1.0",
		ExpiredDate: "Sep 14, 2026",
		Created:     "Sep 14, 2025",
		Username:    "ops",
		Password:    "",
		SSHPort:     "22",
	},
	{
		ID:          "edge-syd-07",
		Name:        "Edge-SYD-07",
		IP:          "192.168.40.31",
		StatusLabel: "Inactive",
		StatusClass: "inactive",
		Users:       0,
		License:     "Trial",
		Version:     "v3.0.7",
		ExpiredDate: "Feb 02, 2026",
		Created:     "Jan 02, 2026",
		Username:    "root",
		Password:    "",
		SSHPort:     "22",
	},
	{
		ID:          "edge-chi-08",
		Name:        "Edge-CHI-08",
		IP:          "10.18.12.77",
		StatusLabel: "Active",
		StatusClass: "active",
		Users:       91,
		License:     "L4",
		Version:     "v3.2.2",
		ExpiredDate: "Apr 18, 2027",
		Created:     "Apr 18, 2026",
		Username:    "admin",
		Password:    "",
		SSHPort:     "2222",
	},
	{
		ID:          "edge-bom-09",
		Name:        "Edge-BOM-09",
		IP:          "172.19.88.22",
		StatusLabel: "Active",
		StatusClass: "active",
		Users:       58,
		License:     "Unified",
		Version:     "v3.1.8",
		ExpiredDate: "Jul 10, 2026",
		Created:     "Jul 10, 2025",
		Username:    "ops",
		Password:    "",
		SSHPort:     "22",
	},
}

var users = []userCredential{
	{Email: "superadmin@gmail.com", Password: "123456", Role: "Admin"},
	{Email: "user@gmail.com", Password: "123456", Role: "User"},
}

func ServerList() []Server {
	copied := make([]Server, len(servers))
	copy(copied, servers)
	return copied
}

func IsValidUser(email, password string) bool {
	for _, user := range users {
		if user.Email == email && user.Password == password {
			return true
		}
	}
	return false
}

func FindUserByCredentials(email, password string) *userCredential {
	for _, user := range users {
		if user.Email == email && user.Password == password {
			matched := user
			return &matched
		}
	}
	return nil
}
