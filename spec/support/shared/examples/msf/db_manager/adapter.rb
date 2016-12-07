# frozen_string_literal: true
RSpec.shared_examples_for 'Msf::DBManager::Adapter' do
  context 'CONSTANTS' do
    context 'ADAPTER' do
      subject(:adapter) do
        described_class::ADAPTER
      end

      it { is_expected.to eq('postgresql') }
    end
  end

  it { is_expected.to respond_to :driver }
  it { is_expected.to respond_to :drivers }
  it { is_expected.to respond_to :drivers= }
  it { is_expected.to respond_to :initialize_adapter }
end
