class User < ApplicationRecord
  has_many :posts
  attr_accessor :remember_token
  before_save :downcase_email
  before_create :create_remember_digest
  validates :name, presence: true, length: { maximum: 50 }
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
  validates :email, presence: true, length: { maximum: 255 },
                    format: { with: VALID_EMAIL_REGEX},
                    uniqueness: { case_sensitive: false }
  has_secure_password
  validates :password, presence: true, length: { minimum: 6 }, allow_nil: true

  # Returns the hash digest of the given string.
  def User.digest(string)
    Digest::SHA1.hexdigest(string)
  end

  # Returns a random token.
    def User.new_token
      SecureRandom.urlsafe_base64
    end

    # Remembers a user in the database for use in persistent sessions.
    def create_remember_digest
      self.remember_token = User.new_token
      self.remember_digest = User.digest(remember_token.to_s)
    end

    # Returns true if the given token matches the digest.
    def authenticated?(remember_token)
      remember_digest == Digest::SHA1.hexdigest(remember_token)
    end

  private
    # Converts email to all lower-case.
    def downcase_email
      self.email.downcase!
    end
end
