# frozen_string_literal: true
RSpec.shared_examples_for 'Msf::Module::UI::Line::Verbose' do
  it { is_expected.to respond_to :vprint_line }
end
