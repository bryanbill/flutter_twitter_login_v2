enum Scope {
  /// All the Tweets you can view, including Tweets from protected accounts.
  tweetRead('tweet.read'),

  /// Tweet and Retweet for you.
  tweetWrite('tweet.write'),

  /// Hide and unhide replies to your Tweets.
  tweetModerateWrite('tweet.moderate.write'),

  /// Any account you can view, including protected accounts.
  usersRead('users.read'),

  /// People who follow you and people who you follow.
  followsRead('follows.read'),

  /// Follow and unfollow people for you.
  followsWrite('follows.write'),

  /// Stay connected to your account until you revoke access.
  offlineAccess('offline.access'),

  /// All the Spaces you can view.
  spaceRead('space.read'),

  /// Accounts you’ve muted.
  muteRead('mute.read'),

  /// Mute and unmute accounts for you.
  muteWrite('mute.write'),

  /// Tweets you’ve liked and likes you can view.
  likeRead('like.read'),

  /// Like and un-like Tweets for you.
  likeWrite('like.write'),

  /// Lists, list members, and list followers of lists you’ve created or are a
  /// member of, including private lists.
  listRead('list.read'),

  /// Create and manage Lists for you.
  listWrite('list.write'),

  /// Accounts you’ve blocked.
  blockRead('block.read'),

  /// Block and unblock accounts for you.
  blockWrite('block.write'),

  /// Get Bookmarked Tweets from an authenticated user.
  bookmarkRead('bookmark.read'),

  /// Bookmark and remove Bookmarks from Tweets
  bookmarkWrite('bookmark.write');

  /// The scope value
  final String value;

  const Scope(this.value);

  /// Returns the scope associated with the given [value].
  static Scope toEnum(final String value) {
    for (final scope in values) {
      if (scope.value == value) {
        return scope;
      }
    }

    throw ArgumentError('Invalid scope value: $value');
  }
}
