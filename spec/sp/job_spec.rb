require "spec_helper"

RSpec.describe SP::Job do
  it "has a version number" do
    expect(SP::Job::VERSION).not_to be nil
  end

  it "does something useful" do
    expect(false).to eq(true)
  end
end
