
Vagrant.configure("2") do |config|
  config.vagrant.plugins = ["vagrant-vbguest"]
  config.vm.box = "generic/opensuse15"
  config.vm.network "private_network", ip: "192.168.10.10",
    auto_config: false
  config.ssh.password = "vagrant"
  config.vm.synced_folder "./", "/home/vagrant/cray-dhcp"
  config.vm.provider "virtualbox" do |v|
    v.memory = 4096
    v.cpus = 6
  end
  config.vm.provision :shell, path: "bootstrap.sh"
end
