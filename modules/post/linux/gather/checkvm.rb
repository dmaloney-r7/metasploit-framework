# frozen_string_literal: true
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Linux Gather Virtual Environment Detection',
                      'Description'   => %q(
                        This module attempts to determine whether the system is running
                        inside of a virtual environment and if so, which one. This
                        module supports detection of Hyper-V, VMWare, VirtualBox, Xen,
                        and QEMU/KVM.),
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
                      'Platform'      => [ 'linux' ],
                      'SessionTypes'  => [ 'shell', 'meterpreter' ]))
  end

  # Run Method for when run command is issued
  def run
    print_status("Gathering System info ....")
    vm = nil
    dmi_info = nil
    ls_pci_data = nil

    dmi_info = cmd_exec("/usr/sbin/dmidecode") if is_root?

    # Check DMi Info
    if dmi_info
      case dmi_info
      when /microsoft corporation/i
        vm = "MS Hyper-V"
      when /vmware/i
        vm = "VMware"
      when /virtualbox/i
        vm = "VirtualBox"
      when /qemu/i
        vm = "Qemu/KVM"
      when /domu/i
        vm = "Xen"
      end
    end

    # Check Modules
    unless vm
      loaded_modules = cmd_exec("/sbin/lsmod")
      case loaded_modules.to_s.tr("\n", " ")
      when /vboxsf|vboxguest/i
        vm = "VirtualBox"
      when /vmw_ballon|vmxnet|vmw/i
        vm = "VMware"
      when /xen-vbd|xen-vnif/
        vm = "Xen"
      when /virtio_pci|virtio_net/
        vm = "Qemu/KVM"
      when /hv_vmbus|hv_blkvsc|hv_netvsc|hv_utils|hv_storvsc/
        vm = "MS Hyper-V"
      end
    end

    # Check SCSI Driver
    unless vm
      proc_scsi = begin
                    read_file("/proc/scsi/scsi")
                  rescue
                    ""
                  end
      case proc_scsi.tr("\n", " ")
      when /vmware/i
        vm = "VMware"
      when /vbox/i
        vm = "VirtualBox"
      end
    end

    # Check IDE Devices
    unless vm
      case cmd_exec("cat /proc/ide/hd*/model")
      when /vbox/i
        vm = "VirtualBox"
      when /vmware/i
        vm = "VMware"
      when /qemu/i
        vm = "Qemu/KVM"
      when /virtual [vc]d/i
        vm = "Hyper-V/Virtual PC"
      end
    end

    # Check using lspci
    unless vm
      lspci_data = case get_sysinfo[:distro]
                   when /oracle|centos|suse|redhat|mandrake|slackware|fedora/i
                     cmd_exec("/sbin/lspci")
                   when /debian|ubuntu/
                     cmd_exec("/usr/bin/lspci")
                   else
                     cmd_exec("lspci")
                   end

      case lspci_data.to_s.tr("\n", " ")
      when /vmware/i
        vm = "VMware"
      when /virtualbox/i
        vm = "VirtualBox"
      end
    end

    # Xen bus check
    unless vm
      vm = "Xen" if cmd_exec("ls -1 /sys/bus").to_s.split("\n").include?("xen")
    end

    # Check using lscpu
    unless vm
      case cmd_exec("lscpu")
      when /Xen/i
        vm = "Xen"
      when /KVM/i
        vm = "KVM"
      when /Microsoft/i
        vm = "MS Hyper-V"
      end
    end

    # Check dmesg Output
    unless vm
      dmesg = cmd_exec("dmesg")
      case dmesg
      when /vboxbios|vboxcput|vboxfacp|vboxxsdt|vbox cd-rom|vbox harddisk/i
        vm = "VirtualBox"
      when /vmware virtual ide|vmware pvscsi|vmware virtual platform/i
        vm = "VMware"
      when /xen_mem|xen-vbd/i
        vm = "Xen"
      when /qemu virtual cpu version/i
        vm = "Qemu/KVM"
      when /\/dev\/vmnet/
        vm = "VMware"
      end
    end

    if vm
      print_good("This appears to be a '#{vm}' virtual machine")
      report_vm(vm)
    else
      print_status("This does not appear to be a virtual machine")
    end
  end
end
