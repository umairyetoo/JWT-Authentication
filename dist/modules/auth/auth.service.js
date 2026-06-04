"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var AuthService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const bcrypt = __importStar(require("bcrypt"));
const user_service_1 = require("../user/user.service");
const token_service_1 = require("../token/token.service");
let AuthService = AuthService_1 = class AuthService {
    constructor(userService, tokenService) {
        this.userService = userService;
        this.tokenService = tokenService;
        this.logger = new common_1.Logger(AuthService_1.name);
    }
    async register(email, password) {
        const user = await this.userService.createUser(email, password);
        const tokens = await this.tokenService.generateTokenPair(user.id, user.email, user.role);
        this.logger.log(`New user registered: ${user.id}`);
        return { user, ...tokens };
    }
    async login(email, password) {
        const user = await this.userService.findByEmail(email);
        if (!user) {
            throw new common_1.UnauthorizedException('Invalid credentials');
        }
        if (!user.isActive) {
            throw new common_1.ForbiddenException('Account has been suspended');
        }
        const passwordValid = await this.userService.validatePassword(password, user.password);
        if (!passwordValid) {
            throw new common_1.UnauthorizedException('Invalid credentials');
        }
        const tokens = await this.tokenService.generateTokenPair(user.id, user.email, user.role);
        this.logger.log(`User logged in: ${user.id}`);
        const { password: _removed, ...safeUser } = user;
        return { user: safeUser, ...tokens };
    }
    async logout(accessToken, userId) {
        await this.tokenService.revokeAccessToken(accessToken);
        await this.tokenService.revokeAllUserTokens(userId);
        this.logger.log(`User logged out: ${userId}`);
        return { message: 'Logged out successfully' };
    }
    async refresh(refreshToken) {
        return this.tokenService.rotateRefreshToken(refreshToken);
    }
    async changePassword(userId, currentPassword, newPassword) {
        const user = await this.userService.findById(userId);
        if (!user) {
            throw new common_1.UnauthorizedException('User not found');
        }
        const userWithPassword = await this.userService.findByEmail(user.email);
        const valid = await this.userService.validatePassword(currentPassword, userWithPassword.password);
        if (!valid) {
            throw new common_1.UnauthorizedException('Current password is incorrect');
        }
        const hashed = await bcrypt.hash(newPassword, 12);
        await this.userService.updatePassword(userId, hashed);
        await this.tokenService.revokeAllUserTokens(userId);
        this.logger.log(`Password changed for user: ${userId}`);
        return { message: 'Password changed. Please login again.' };
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = AuthService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [user_service_1.UserService,
        token_service_1.TokenService])
], AuthService);
//# sourceMappingURL=auth.service.js.map