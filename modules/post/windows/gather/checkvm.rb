# frozen_string_literal: true
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Windows Gather Virtual Environment Detection',
                      'Description'   => %q(
                        This module attempts to determine whether the system is running
                        inside of a virtual environment and if so, which one. This
                        module supports detectoin of Hyper-V, VMWare, Virtual PC,
                        VirtualBox, Xen, and QEMU.
                      ),
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]))
  end

  # Method for detecting if it is a Hyper-V VM
  def hypervchk(session)
    vm = false
    sfmsvals = registry_enumkeys('HKLM\SOFTWARE\Microsoft')
    if sfmsvals && sfmsvals.include?("Hyper-V")
      vm = true
    elsif sfmsvals && sfmsvals.include?("VirtualMachine")
      vm = true
    end
    unless vm
      if registry_getvaldata('HKLM\HARDWARE\DESCRIPTION\System', 'SystemBiosVersion') =~ /vrtual/i
        vm = true
      end
    end
    unless vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\FADT')
      vm = true if srvvals && srvvals.include?("VRTUAL")
    end
    unless vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\RSDT')
      vm = true if srvvals && srvvals.include?("VRTUAL")
    end
    unless vm
      srvvals = registry_enumkeys('HKLM\SYSTEM\ControlSet001\Services')
      if srvvals && srvvals.include?("vmicheartbeat")
        vm = true
      elsif srvvals && srvvals.include?("vmicvss")
        vm = true
      elsif srvvals && srvvals.include?("vmicshutdown")
        vm = true
      elsif srvvals && srvvals.include?("vmicexchange")
        vm = true
      end
    end
    if vm
      report_note(
        host: session,
        type: 'host.hypervisor',
        data: { hypervisor: "MS Hyper-V" },
        update: :unique_data
      )
      print_status("This is a Hyper-V Virtual Machine")
      return "MS Hyper-V"
    end
  end

  # Method for checking if it is a VMware VM
  def vmwarechk(session)
    vm = false
    srvvals = registry_enumkeys('HKLM\SYSTEM\ControlSet001\Services')
    if srvvals && srvvals.include?("vmdebug")
      vm = true
    elsif srvvals && srvvals.include?("vmmouse")
      vm = true
    elsif srvvals && srvvals.include?("VMTools")
      vm = true
    elsif srvvals && srvvals.include?("VMMEMCTL")
      vm = true
    end
    unless vm
      if registry_getvaldata('HKLM\HARDWARE\DESCRIPTION\System\BIOS', 'SystemManufacturer') =~ /vmware/i
        vm = true
      end
    end
    unless vm
      key_path = 'HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0'
      vm = true if registry_getvaldata(key_path, 'Identifier') =~ /vmware/i
    end
    unless vm
      vmwareprocs = [
        "vmwareuser.exe",
        "vmwaretray.exe"
      ]
      session.sys.process.get_processes.each do |x|
        vmwareprocs.each do |p|
          vm = true if p == x['name'].downcase
        end
      end
    end

    if vm
      report_note(
        host: session,
        type: 'host.hypervisor',
        data: { hypervisor: "VMware" },
        update: :unique_data
      )
      print_status("This is a VMware Virtual Machine")
      return "VMWare"
    end
  end

  # Method for checking if it is a Virtual PC VM
  def checkvrtlpc(session)
    vm = false
    vpcprocs = [
      "vmusrvc.exe",
      "vmsrvc.exe"
    ]
    session.sys.process.get_processes.each do |x|
      vpcprocs.each do |p|
        vm = true if p == x['name'].downcase
      end
    end
    unless vm
      srvvals = registry_enumkeys('HKLM\SYSTEM\ControlSet001\Services')
      if srvvals && srvvals.include?("vpc-s3")
        vm = true
      elsif srvvals && srvvals.include?("vpcuhub")
        vm = true
      elsif srvvals && srvvals.include?("msvmmouf")
        vm = true
      end
    end
    if vm
      report_note(
        host: session,
        type: 'host.hypervisor',
        data: { hypervisor: "VirtualPC" },
        update: :unique_data
      )
      print_status("This is a VirtualPC Virtual Machine")
      return "VirtualPC"
    end
  end

  # Method for checking if it is a VirtualBox VM
  def vboxchk(session)
    vm = false
    vboxprocs = [
      "vboxservice.exe",
      "vboxtray.exe"
    ]
    session.sys.process.get_processes.each do |x|
      vboxprocs.each do |p|
        vm = true if p == x['name'].downcase
      end
    end
    unless vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\DSDT')
      vm = true if srvvals && srvvals.include?("VBOX__")
    end
    unless vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\FADT')
      vm = true if srvvals && srvvals.include?("VBOX__")
    end
    unless vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\RSDT')
      vm = true if srvvals && srvvals.include?("VBOX__")
    end
    unless vm
      key_path = 'HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0'
      vm = true if registry_getvaldata(key_path, 'Identifier') =~ /vbox/i
    end
    unless vm
      if registry_getvaldata('HKLM\HARDWARE\DESCRIPTION\System', 'SystemBiosVersion') =~ /vbox/i
        vm = true
      end
    end
    unless vm
      srvvals = registry_enumkeys('HKLM\SYSTEM\ControlSet001\Services')
      if srvvals && srvvals.include?("VBoxMouse")
        vm = true
      elsif srvvals && srvvals.include?("VBoxGuest")
        vm = true
      elsif srvvals && srvvals.include?("VBoxService")
        vm = true
      elsif srvvals && srvvals.include?("VBoxSF")
        vm = true
      end
    end
    if vm
      report_note(
        host: session,
        type: 'host.hypervisor',
        data: { hypervisor: "VirtualBox" },
        update: :unique_data
      )
      print_status("This is a Sun VirtualBox Virtual Machine")
      return "VirtualBox"
    end
  end

  # Method for checking if it is a Xen VM
  def xenchk(session)
    vm = false
    xenprocs = [
      "xenservice.exe"
    ]
    session.sys.process.get_processes.each do |x|
      xenprocs.each do |p|
        vm = true if p == x['name'].downcase
      end
    end
    unless vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\DSDT')
      vm = true if srvvals && srvvals.include?("Xen")
    end
    unless vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\FADT')
      vm = true if srvvals && srvvals.include?("Xen")
    end
    unless vm
      srvvals = registry_enumkeys('HKLM\HARDWARE\ACPI\RSDT')
      vm = true if srvvals && srvvals.include?("Xen")
    end
    unless vm
      srvvals = registry_enumkeys('HKLM\SYSTEM\ControlSet001\Services')
      if srvvals && srvvals.include?("xenevtchn")
        vm = true
      elsif srvvals && srvvals.include?("xennet")
        vm = true
      elsif srvvals && srvvals.include?("xennet6")
        vm = true
      elsif srvvals && srvvals.include?("xensvc")
        vm = true
      elsif srvvals && srvvals.include?("xenvdb")
        vm = true
      end
    end
    if vm
      report_note(
        host: session,
        type: 'host.hypervisor',
        data: { hypervisor: "Xen" },
        update: :unique_data
      )
      print_status("This is a Xen Virtual Machine")
      return "Xen"
    end
  end

  def qemuchk(session)
    vm = false
    unless vm
      key_path = 'HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0'
      if registry_getvaldata(key_path, 'Identifier') =~ /qemu/i
        print_status("This is a QEMU/KVM Virtual Machine")
        vm = true
      end
    end
    unless vm
      key_path = 'HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0'
      if registry_getvaldata(key_path, 'ProcessorNameString') =~ /qemu/i
        print_status("This is a QEMU/KVM Virtual Machine")
        vm = true
      end
    end

    if vm
      report_note(
        host: session,
        type: 'host.hypervisor',
        data: { hypervisor: "Qemu/KVM" },
        update: :unique_data
      )
      return "Qemu/KVM"
    end
  end

  # run Method
  def run
    print_status("Checking if #{sysinfo['Computer']} is a Virtual Machine .....")
    found = hypervchk(session)
    found ||= vmwarechk(session)
    found ||= checkvrtlpc(session)
    found ||= vboxchk(session)
    found ||= xenchk(session)
    found ||= qemuchk(session)
    if found
      report_vm(found)
    else
      print_status("#{sysinfo['Computer']} appears to be a Physical Machine")
    end
  end
end
