#!/usr/bin/env python3
"""
Debug Script - Check what users see on chat page
"""

from app import app, db, User, session as flask_session

def debug_chat_for_user(username):
    """Debug what a specific user sees on chat page"""
    
    with app.app_context():
        current_user = User.query.filter_by(username=username).first()
        
        if not current_user:
            print(f"❌ User '{username}' not found!")
            return
        
        print("\n" + "=" * 80)
        print(f"🔍 DEBUG: What '{username}' sees on chat page")
        print("=" * 80)
        
        print(f"\nCurrent User:")
        print(f"  Username: {current_user.username}")
        print(f"  User ID:  {current_user.user_id}")
        print(f"  Role:     {current_user.role}")
        print(f"  Status:   {current_user.status}")
        
        # Query that backend uses
        users = User.query.filter(
            User.username != username,
            User.role != 'admin'
        ).all()
        
        print(f"\n📋 Users that '{username}' should see: {len(users)}")
        print("-" * 80)
        
        if not users:
            print("❌ NO USERS FOUND!")
            print("\n🔍 Checking all users in database:")
            
            all_users = User.query.all()
            print(f"\nTotal users in database: {len(all_users)}")
            
            for u in all_users:
                print(f"  - {u.username} (role={u.role}, status={u.status})")
            
            print("\n💡 Possible reasons:")
            print("  1. Only 1 user exists (need at least 2 normal users)")
            print("  2. All other users are admin")
            print("  3. All other users are blocked")
        else:
            for idx, u in enumerate(users, 1):
                print(f"\n{idx}. {u.username}")
                print(f"   User ID:  {u.user_id}")
                print(f"   Email:    {u.email}")
                print(f"   Role:     {u.role}")
                print(f"   Status:   {u.status}")
                print(f"   Bio:      {u.bio or '(empty)'}")
        
        print("\n" + "=" * 80)

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("\n📖 Usage: python debug_chat.py <username>")
        print("\nExample:")
        print("  python debug_chat.py alice")
        print("  python debug_chat.py bob")
        sys.exit(1)
    
    username = sys.argv[1]
    debug_chat_for_user(username)
