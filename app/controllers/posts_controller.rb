class PostsController < ApplicationController
  before_action :logged_in_user, only: [:new, :create]

  def new
    @post = Post.new
  end

  def create
    @post = Post.new(post_params)
    @user = current_user
    @post.user_id = @user.id
    if @post.save
      redirect_to posts_path
    else
      render 'new'
    end
  end

  def index
    @posts = Post.all
  end


  private
    # Confirms a logged-in user.
    def logged_in_user
      unless logged_in?
        flash[:danger] = "Please log in."
        redirect_to login_url
      end
    end

    def post_params
      params.require(:post).permit(:title, :body)
    end
end
