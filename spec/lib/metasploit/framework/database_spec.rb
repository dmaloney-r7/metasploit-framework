# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Metasploit::Framework::Database do
  context 'CONSTANTS' do
    context 'CONFIGURATIONS_PATHNAME_PRECEDENCE' do
      subject(:configurations_pathname_precedence) do
        described_class::CONFIGURATIONS_PATHNAME_PRECEDENCE
      end

      it do
        is_expected.to match_array(
          [
            :environment_configurations_pathname,
            :user_configurations_pathname,
            :project_configurations_pathname
          ]
        )
      end
    end
  end

  context '.configurations_pathname' do
    subject(:configurations_pathname) do
      described_class.configurations_pathname(*arguments)
    end

    context 'with options' do
      let(:arguments) do
        [
          {
            path: path
          }
        ]
      end

      context 'with :path' do
        context 'that exists' do
          let(:path) do
            tempfile.path
          end

          let(:tempfile) do
            Tempfile.new(['database', '.yml'])
          end

          it 'returns Pathname(path)' do
            expect(configurations_pathname).to eq(Pathname.new(path))
          end
        end

        context 'that does not exist' do
          let(:path) do
            '/a/configurations/path/that/does/not/exist/database.yml'
          end

          it { is_expected.to be_nil }
        end
      end

      context 'without :path' do
        let(:path) do
          ''
        end

        it 'calls configurations_pathnames' do
          expect(described_class).to receive(:configurations_pathnames).and_call_original

          configurations_pathname
        end

        it 'returns first pathname from configurations_pathnames' do
          expect(configurations_pathname).to eq(described_class.configurations_pathnames.first)
        end
      end
    end

    context 'without options' do
      let(:arguments) do
        []
      end

      it 'calls configurations_pathnames' do
        expect(described_class).to receive(:configurations_pathnames).and_call_original

        configurations_pathname
      end

      it 'returns first pathname from configurations_pathnames' do
        expect(configurations_pathname).to eq(described_class.configurations_pathnames.first)
      end
    end
  end

  context '.configurations_pathnames' do
    subject(:configurations_pathnames) do
      described_class.configurations_pathnames
    end

    before(:example) do
      allow(described_class).to receive(:environment_configurations_pathname).and_return(
        environment_configurations_pathname
      )
    end

    context 'with environment_configurations_pathname' do
      context 'that exists' do
        #
        # lets
        #

        let(:environment_configurations_pathname) do
          Pathname.new(environment_configurations_tempfile.path)
        end

        let(:environment_configurations_tempfile) do
          Tempfile.new(['environment_configurations', '.database.yml'])
        end

        #
        # Callbacks
        #

        before(:example) do
          allow(described_class).to receive(:user_configurations_pathname).and_return(
            user_configurations_pathname
          )
        end

        context 'with user_configurations_pathname' do
          context 'that exists' do
            #
            # lets
            #

            let(:user_configurations_pathname) do
              Pathname.new(user_configurations_tempfile.path)
            end

            let(:user_configurations_tempfile) do
              Tempfile.new(['user_configurations', '.database.yml'])
            end

            #
            # Callbacks
            #

            before(:example) do
              allow(described_class).to receive(:project_configurations_pathname).and_return(
                project_configurations_pathname
              )
            end

            context 'with project_configurations_pathname' do
              context 'that exists' do
                let(:project_configurations_pathname) do
                  Pathname.new(project_configurations_tempfile.path)
                end

                let(:project_configurations_tempfile) do
                  Tempfile.new(['project_configurations', '.database.yml'])
                end

                it 'is [environment_configurations_pathname, user_configurations_pathname, project_configurations_pathname]' do
                  expect(project_configurations_pathname).to exist
                  expect(configurations_pathnames).to match_array(
                    [
                      environment_configurations_pathname,
                      user_configurations_pathname,
                      project_configurations_pathname
                    ]
                  )
                end
              end

              context 'that does not exist' do
                let(:project_configurations_pathname) do
                  Pathname.new('/metasploit-framework/does/not/exist/here/config/database.yml')
                end

                it 'is [environment_configurations_pathname, user_configurations_pathname]' do
                  expect(environment_configurations_pathname).to exist
                  expect(user_configurations_pathname).to exist
                  expect(project_configurations_pathname).not_to exist

                  expect(project_configurations_pathname).not_to exist
                  expect(configurations_pathnames).to match_array(
                    [
                      environment_configurations_pathname,
                      user_configurations_pathname
                    ]
                  )
                end
              end
            end

            context 'without project_configurations_pathname' do
              let(:project_configurations_pathname) do
                nil
              end

              it 'is [environment_configuration_pathname, user_configurations_pathname]' do
                expect(environment_configurations_pathname).to exist
                expect(user_configurations_pathname).to exist

                expect(configurations_pathnames).to match_array(
                  [
                    environment_configurations_pathname,
                    user_configurations_pathname
                  ]
                )
              end
            end
          end

          context 'with does not exist' do
            #
            # lets
            #

            let(:user_configurations_pathname) do
              Pathname.new('/user/configuration/that/does/not/exist/.msf4/database.yml')
            end

            #
            # Callbacks
            #

            before(:example) do
              allow(described_class).to receive(:project_configurations_pathname).and_return(
                project_configurations_pathname
              )
            end

            context 'with project_configurations_pathname' do
              context 'that exists' do
                let(:project_configurations_pathname) do
                  Pathname.new(project_configurations_tempfile.path)
                end

                let(:project_configurations_tempfile) do
                  Tempfile.new(['project_configurations', '.database.yml'])
                end

                it 'is [environment_configurations_pathname, project_configurations_pathname]' do
                  expect(environment_configurations_pathname).to exist
                  expect(user_configurations_pathname).not_to exist
                  expect(project_configurations_pathname).to exist

                  expect(configurations_pathnames).to match_array(
                    [
                      environment_configurations_pathname,
                      project_configurations_pathname
                    ]
                  )
                end
              end

              context 'that does not exist' do
                let(:project_configurations_pathname) do
                  Pathname.new('/metasploit-framework/that/does/not/exist/config/database.yml')
                end

                it 'is [environment_configurations_pathname]' do
                  expect(environment_configurations_pathname).to exist
                  expect(user_configurations_pathname).not_to exist
                  expect(project_configurations_pathname).not_to exist

                  expect(configurations_pathnames).to match_array(
                    [
                      environment_configurations_pathname
                    ]
                  )
                end
              end
            end

            context 'without project_configurations_pathname' do
              let(:project_configurations_pathname) do
                nil
              end

              it 'is [environment_configurations_pathname]' do
                expect(environment_configurations_pathname).to exist
                expect(user_configurations_pathname).not_to exist
                expect(project_configurations_pathname).to be_nil

                expect(configurations_pathnames).to match_array(
                  [
                    environment_configurations_pathname
                  ]
                )
              end
            end
          end
        end

        context 'without user_configurations_pathname' do
          #
          # lets
          #

          let(:user_configurations_pathname) do
            nil
          end

          #
          # Callbacks
          #

          before(:example) do
            allow(described_class).to receive(:project_configurations_pathname).and_return(
              project_configurations_pathname
            )
          end

          context 'with project_configurations_pathname' do
          end

          context 'without project_configurations_pathname' do
            let(:project_configurations_pathname) do
              nil
            end

            it 'contains only the environment_configuration_pathname' do
              expect(configurations_pathnames).to match_array([environment_configurations_pathname])
            end
          end
        end
      end

      context 'that does not exist' do
      end
    end

    context 'without environment_configurations_pathname' do
      #
      # lets
      #

      let(:environment_configurations_pathname) do
        nil
      end

      #
      # Callbacks
      #

      before(:example) do
        allow(described_class).to receive(:user_configurations_pathname).and_return(
          user_configurations_pathname
        )
      end

      context 'with user_configurations_pathname' do
        context 'that exists' do
          #
          # lets
          #

          let(:user_configurations_pathname) do
            Pathname.new(user_configurations_tempfile.path)
          end

          let(:user_configurations_tempfile) do
            Tempfile.new(['user_configurations', '.database.yml'])
          end

          #
          # Callbacks
          #

          before(:example) do
            allow(described_class).to receive(:project_configurations_pathname).and_return(
              project_configurations_pathname
            )
          end

          context 'with project_configurations_pathname' do
            context 'that exists' do
              let(:project_configurations_pathname) do
                Pathname.new(project_configurations_tempfile.path)
              end

              let(:project_configurations_tempfile) do
                Tempfile.new(['project_configurations', '.database.yml'])
              end

              it 'is [user_configurations_pathname, project_configurations_pathname]' do
                expect(environment_configurations_pathname).to be_nil
                expect(user_configurations_pathname).to exist
                expect(project_configurations_pathname).to exist

                expect(configurations_pathnames).to match_array(
                  [
                    user_configurations_pathname,
                    project_configurations_pathname
                  ]
                )
              end
            end

            context 'that does not exist' do
              let(:project_configurations_pathname) do
                Pathname.new('/metasploit-framework/that/does/not/exist/config/database.yml')
              end

              it 'is [user_configurations_pathname]' do
                expect(environment_configurations_pathname).to be_nil
                expect(user_configurations_pathname).to exist
                expect(project_configurations_pathname).not_to exist

                expect(configurations_pathnames).to match_array(
                  [
                    user_configurations_pathname
                  ]
                )
              end
            end
          end

          context 'without project_configurations_pathname' do
            let(:project_configurations_pathname) do
              nil
            end

            it 'is [user_configurations_pathname]' do
              expect(environment_configurations_pathname).to be_nil
              expect(user_configurations_pathname).to exist
              expect(project_configurations_pathname).to be_nil

              expect(configurations_pathnames).to match_array(
                [
                  user_configurations_pathname
                ]
              )
            end
          end
        end

        context 'that does not exist' do
          #
          # lets
          #

          let(:user_configurations_pathname) do
            Pathname.new('/user/configuration/that/does/not/exist/.msf4/database.yml')
          end

          #
          # Callbacks
          #

          before(:example) do
            allow(described_class).to receive(:project_configurations_pathname).and_return(
              project_configurations_pathname
            )
          end

          context 'with project_configurations_pathname' do
            context 'that exists' do
              let(:project_configurations_pathname) do
                Pathname.new(project_configurations_tempfile.path)
              end

              let(:project_configurations_tempfile) do
                Tempfile.new(['project_configurations', '.database.yml'])
              end

              it 'is [project_configurations_pathname]' do
                expect(environment_configurations_pathname).to be_nil
                expect(user_configurations_pathname).not_to exist
                expect(project_configurations_pathname).to exist

                expect(configurations_pathnames).to match_array(
                  [
                    project_configurations_pathname
                  ]
                )
              end
            end

            context 'that does not exist' do
              let(:project_configurations_pathname) do
                Pathname.new('/metasploit-framework/that/does/not/exist/config/database.yml')
              end

              it 'is []' do
                expect(environment_configurations_pathname).to be_nil
                expect(user_configurations_pathname).not_to exist
                expect(project_configurations_pathname).not_to exist

                expect(configurations_pathnames).to eq([])
              end
            end
          end

          context 'without project_configurations_pathname' do
            let(:project_configurations_pathname) do
              nil
            end

            it 'is []' do
              expect(environment_configurations_pathname).to be_nil
              expect(user_configurations_pathname).not_to exist
              expect(project_configurations_pathname).to be_nil

              expect(configurations_pathnames).to eq([])
            end
          end
        end
      end

      context 'without user_configurations_pathname' do
        #
        # lets
        #

        let(:user_configurations_pathname) do
          nil
        end

        #
        # Callbacks
        #

        before(:example) do
          allow(described_class).to receive(:project_configurations_pathname).and_return(
            project_configurations_pathname
          )
        end

        context 'with project_configurations_pathname' do
          context 'that exists' do
            let(:project_configurations_pathname) do
              Pathname.new(project_configurations_tempfile.path)
            end

            let(:project_configurations_tempfile) do
              Tempfile.new(['project_configurations', '.database.yml'])
            end

            it 'is [project_configurations_pathname]' do
              expect(environment_configurations_pathname).to be_nil
              expect(user_configurations_pathname).to be_nil
              expect(project_configurations_pathname).to exist

              expect(configurations_pathnames).to match_array(
                [
                  project_configurations_pathname
                ]
              )
            end
          end

          context 'that does not exist' do
            let(:project_configurations_pathname) do
              Pathname.new('/metasploit-framework/that/does/not/exist/config/database.yml')
            end

            it 'is []' do
              expect(environment_configurations_pathname).to be_nil
              expect(user_configurations_pathname).to be_nil
              expect(project_configurations_pathname).not_to exist

              expect(configurations_pathnames).to eq([])
            end
          end
        end

        context 'without project_configurations_pathname' do
          let(:project_configurations_pathname) do
            nil
          end

          it { is_expected.to eq([]) }
        end
      end
    end
  end

  context '.environment_configurations_pathname' do
    subject(:environment_configurations_pathname) do
      described_class.environment_configurations_pathname
    end

    around(:example) do |example|
      env_before = ENV.to_hash

      begin
        example.run
      ensure
        ENV.update(env_before)
      end
    end

    context 'with MSF_DATABASE_CONFIG' do
      before(:example) do
        ENV['MSF_DATABASE_CONFIG'] = msf_database_config
      end

      context 'with blank' do
        let(:msf_database_config) do
          ''
        end

        it { is_expected.to be_nil }
      end

      context 'without blank' do
        let(:msf_database_config) do
          'msf/database/config/database.yml'
        end

        it 'is Pathname of MSF_DATABASE_CONFIG' do
          expect(environment_configurations_pathname).to eq(Pathname.new(msf_database_config))
        end
      end
    end

    context 'without MSF_DATABASE_CONFIG' do
      before(:example) do
        ENV.delete('MSF_DATABASE_CONFIG')
      end

      it { is_expected.to be_nil }
    end
  end

  context '.project_configurations_pathname' do
    subject(:project_configurations_pathname) do
      described_class.project_configurations_pathname
    end

    it 'is <metasploit-framework>/config/database.yml' do
      root = Pathname.new(__FILE__).realpath.parent.parent.parent.parent.parent
      expect(project_configurations_pathname).to eq(root.join('config', 'database.yml'))
    end
  end

  context '.user_configurations_pathname' do
    subject(:user_configurations_pathname) do
      described_class.user_configurations_pathname
    end

    #
    # lets
    #

    let(:config_root) do
      Dir.mktmpdir
    end

    #
    # Callbacks
    #

    around(:example) do |example|
      begin
        example.run
      ensure
        FileUtils.remove_entry_secure config_root
      end
    end

    before(:example) do
      allow(Msf::Config).to receive(:get_config_root).and_return(config_root)
    end

    it 'is database.yml under the user config root' do
      expect(user_configurations_pathname).to eq(Pathname.new(config_root).join('database.yml'))
    end
  end
end
