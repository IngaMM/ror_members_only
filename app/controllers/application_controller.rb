class ApplicationController < ActionController::Base
  helper_method :logged_in?, :current_user

  # Logs in the given user.
  def log_in(user)
    session[:user_id] = user.id
  end

  # Remembers the user with the help of a permanent cookie
  def remember(user)
    # Update the remember_token
    user.remember_token = User.new_token
    user.update_attribute(:remember_digest, User.digest(user.remember_token))
    # Create cookie
    cookies.permanent.signed[:user_id] = user.id
    cookies.permanent[:remember_token] = user.remember_token
  end

  # Returns the user corresponding to the remember token cookie.
  def current_user
    if (user_id = session[:user_id])
      @current_user ||= User.find_by(id: user_id)
    elsif (user_id = cookies.signed[:user_id])
      user = User.find_by(id: user_id)
      if user && user.authenticated?(cookies[:remember_token])
        log_in user
        @current_user = user
      end
    end
  end

  # Returns true if the user is logged in, false otherwise.
  def logged_in?
    !current_user.nil?
  end

  # Forgets a persistent session.
  def forget(user)
    cookies.delete(:user_id)
    cookies.delete(:remember_token)
  end

  # Logs out the current user.
  def log_out
    forget(current_user)
    session.delete(:user_id)
    @current_user = nil
  end

end
