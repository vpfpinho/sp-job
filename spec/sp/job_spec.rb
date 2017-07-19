require "spec_helper"

RSpec.describe Sp::Job do
  it "has a version number" do
    expect(Sp::Job::VERSION).not_to be nil
  end

  it "does something useful" do
    expect(false).to eq(true)
  end
end
