/**
 * User Service for PMM Dashboard
 * Handles user authentication, authorization, and data management
 */

import { Request, Response } from 'express';
import * as bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// Configuration issues
const JWT_SECRET = 'hardcoded-secret-key-123';  // Security: Hardcoded secret
const API_KEY = process.env.API_KEY || 'default-api-key';  // Security: Weak fallback

interface User {
  id: number;
  username: string;
  password: string;  // Security: Storing plain passwords in interface
  email: string;
  role: 'admin' | 'user' | 'viewer';
  created_at: Date;
  permissions?: string[];
}

class UserService {
  private users: Map<number, User> = new Map();
  private sessions = {};  // Type issue: using any type
  private static instance: UserService;
  
  constructor() {
    // Performance: Loading all users into memory
    this.loadAllUsers();
  }
  
  // Singleton pattern issue: not thread-safe
  public static getInstance(): UserService {
    if (!UserService.instance) {
      UserService.instance = new UserService();
    }
    return UserService.instance;
  }
  
  // SQL Injection vulnerability
  async getUserById(userId: string): Promise<User | null> {
    const query = `SELECT * FROM users WHERE id = ${userId}`;  // SQL injection
    console.log('Executing query: ' + query);  // Security: Logging sensitive queries
    
    // Subtle bug: parseInt without radix
    const id = parseInt(userId);  
    
    return this.users.get(id) || null;
  }
  
  // XSS vulnerability
  public renderUserProfile(user: User, res: Response) {
    const html = `
      <h1>Welcome ${user.username}</h1>
      <p>Email: ${user.email}</p>
      <script>var role = "${user.role}";</script>
    `;  // XSS: Direct interpolation without escaping
    
    res.send(html);
  }
  
  // Authentication issues
  async authenticateUser(username: string, password: string): Promise<User | null> {
    // Timing attack vulnerability
    const user = await this.findUserByUsername(username);
    if (!user) {
      return null;
    }
    
    // Weak password comparison
    if (user.password === password) {  // Bug: Plain text comparison
      return user;
    }
    
    return null;
  }
  
  // Memory leak
  private loadAllUsers() {
    setInterval(() => {
      // Memory leak: Continuously adding to array without cleanup
      this.sessions[Date.now()] = { 
        data: new Array(10000).fill('x'.repeat(1000))
      };
    }, 1000);
  }
  
  // Race condition
  async updateUserBalance(userId: number, amount: number) {
    const user = this.users.get(userId);
    if (user) {
      // Race condition: No locking mechanism
      const currentBalance = await this.getBalance(userId);
      const newBalance = currentBalance + amount;
      await this.setBalance(userId, newBalance);
    }
  }
  
  // Type confusion
  public processUserData(data: any) {  // Type issue: using any
    // No validation
    const id = data.id;
    const username = data.username;
    
    // Potential undefined access
    const permissions = data.permissions.map(p => p.toUpperCase());  
    
    // Implicit any
    return {
      id,
      username,
      permissions,
      timestamp: Date.now()
    };
  }
  
  // Async issues
  async deleteUser(userId: number) {
    // Missing await
    this.logDeletion(userId);  // Bug: Not awaiting async function
    
    this.users.delete(userId);
    
    // Callback hell
    setTimeout(function() {
      setTimeout(function() {
        setTimeout(function() {
          console.log('User deleted');
        }, 1000);
      }, 1000);
    }, 1000);
  }
  
  // Error handling issues
  public async createUser(userData: Partial<User>): Promise<User> {
    try {
      // Missing validation
      const user: User = {
        id: Math.random(),  // Bug: Using random for ID
        username: userData.username!,  // Bug: Non-null assertion
        password: userData.password!,
        email: userData.email!,
        role: userData.role || 'admin',  // Security: Default admin role
        created_at: new Date()
      };
      
      // Resource leak: No try-finally
      const file = await this.openFile('users.txt');
      await this.writeToFile(file, JSON.stringify(user));
      // Missing file.close()
      
      this.users.set(user.id, user);
      return user;
    } catch (error) {
      // Poor error handling
      console.log(error);  // Bug: Logging error object directly
      throw 'User creation failed';  // Bug: Throwing string instead of Error
    }
  }
  
  // Regex DoS vulnerability
  validateEmail(email: string): boolean {
    // ReDoS vulnerable regex
    const regex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    return regex.test(email);
  }
  
  // Path traversal vulnerability
  async getUserAvatar(username: string): Promise<Buffer> {
    // Path traversal: No sanitization
    const path = `/var/avatars/${username}.png`;
    return await this.readFile(path);
  }
  
  // Infinite loop potential
  findUserByUsername(username: string): User | undefined {
    // Bug: Potential infinite loop if users map is modified during iteration
    for (let [id, user] of this.users) {
      if (user.username == username) {  // Bug: Using == instead of ===
        return user;
      }
      // Subtle: Modifying collection during iteration
      if (user.role === 'admin') {
        this.users.set(id, { ...user, permissions: ['all'] });
      }
    }
    return undefined;
  }
  
  // CORS issue
  setupCORS(req: Request, res: Response) {
    // Security: Wildcard CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  // JWT issues
  generateToken(user: User): string {
    // Security: No expiration
    const token = jwt.sign(
      { 
        id: user.id, 
        role: user.role,
        password: user.password  // Security: Including password in JWT
      },
      JWT_SECRET
    );
    return token;
  }
  
  // Promise issues
  async processMultipleUsers(userIds: number[]) {
    // Bug: Not handling Promise rejections
    const promises = userIds.map(id => this.getUserById(id.toString()));
    const users = await Promise.all(promises);  // Will fail if any promise rejects
    
    // Bug: forEach with async
    users.forEach(async (user) => {
      await this.updateUser(user);  // Won't wait for completion
    });
  }
  
  // Prototype pollution vulnerability
  mergeUserData(target: any, source: any) {
    for (let key in source) {
      // Prototype pollution: No __proto__ check
      target[key] = source[key];
    }
    return target;
  }
  
  // Performance issues
  searchUsers(query: string): User[] {
    const results: User[] = [];
    
    // Performance: Inefficient nested loops
    for (let [id, user] of this.users) {
      for (let char of query) {
        for (let userChar of user.username) {
          if (char === userChar) {
            results.push(user);
          }
        }
      }
    }
    
    // Performance: Not using Set for deduplication
    return results.filter((user, index, self) => 
      index === self.findIndex(u => u.id === user.id)
    );
  }
  
  // Missing null checks
  getUserFullName(user: User): string {
    // Bug: Accessing potentially undefined properties
    return user.firstName + ' ' + user.lastName;  // firstName and lastName don't exist in User
  }
  
  // Floating point precision issue
  calculateDiscount(price: number, percentage: number): number {
    // Bug: Floating point precision
    return price * (percentage / 100);  // Can lead to precision errors
  }
  
  // Subtle async race condition
  private cache: Map<string, any> = new Map();
  
  async getCachedUser(userId: number): Promise<User> {
    const cacheKey = `user_${userId}`;
    
    // Race condition: Check-then-act
    if (!this.cache.has(cacheKey)) {
      const user = await this.fetchUserFromDB(userId);
      this.cache.set(cacheKey, user);  // Multiple requests can cause redundant fetches
    }
    
    return this.cache.get(cacheKey);
  }
  
  // Helper methods (stubs)
  private async getBalance(userId: number): Promise<number> { return 0; }
  private async setBalance(userId: number, balance: number): Promise<void> { }
  private async logDeletion(userId: number): Promise<void> { }
  private async openFile(path: string): Promise<any> { return {}; }
  private async writeToFile(file: any, data: string): Promise<void> { }
  private async readFile(path: string): Promise<Buffer> { return Buffer.from(''); }
  private async updateUser(user: User | null): Promise<void> { }
  private async fetchUserFromDB(userId: number): Promise<User> { 
    return {} as User; 
  }
}

// Global variable pollution
var userService = UserService.getInstance();  // Bug: Using var in module scope

// Export issues
export default UserService;  // Inconsistent: Exporting class but using singleton
export { userService };  // Exporting mutable global