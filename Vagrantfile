require 'getoptlong'

opts = GetoptLong.new(
  [ '--vm-name',        GetoptLong::OPTIONAL_ARGUMENT ],
)
vm_name        = ENV['VM_NAME'] || 'cray-dhcp-kea'

begin
  opts.each do |opt, arg|
    case opt
      when '--vm-name'
        vm_name = arg
    end
  end
  rescue
end

Vagrant.configure("2") do |config|
  config.vagrant.plugins = ["vagrant-vbguest"]
  config.vm.box = "generic/opensuse15"
  config.vm.network "private_network", ip: "192.168.10.10",
    auto_config: false
  config.ssh.password = "vagrant"
  config.vm.synced_folder "./", "/home/vagrant/cray-dhcp-kea"
  config.vm.provider "virtualbox" do |v|
    v.memory = 4096
    v.cpus = 6
  end
  config.vm.provision :shell, path: "bootstrap.sh"
  config.vm.define vm_name
  config.vm.hostname = vm_name
end
