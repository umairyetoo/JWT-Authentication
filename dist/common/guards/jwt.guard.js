"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var JwtAuthGuard_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.JwtAuthGuard = void 0;
const common_1 = require("@nestjs/common");
const jwt_1 = require("@nestjs/jwt");
const redis_service_1 = require("../../modules/redis/redis.service");
const jwt_config_1 = require("../../config/jwt.config");
let JwtAuthGuard = JwtAuthGuard_1 = class JwtAuthGuard {
    constructor(jwtService, redisService) {
        this.jwtService = jwtService;
        this.redisService = redisService;
        this.logger = new common_1.Logger(JwtAuthGuard_1.name);
        this.jwtConfig = (0, jwt_config_1.buildJwtConfig)();
    }
    async canActivate(context) {
        const request = context
            .switchToHttp()
            .getRequest();
        const token = this.extractBearerToken(request);
        if (!token) {
            throw new common_1.UnauthorizedException('Authorization token not provided');
        }
        let payload;
        try {
            payload = await this.jwtService.verifyAsync(token, {
                algorithms: ['RS256'],
                publicKey: this.jwtConfig.publicKey,
                issuer: this.jwtConfig.issuer,
                audience: this.jwtConfig.audience,
            });
        }
        catch (err) {
            const message = err.name === 'TokenExpiredError'
                ? 'Token has expired'
                : 'Invalid token';
            this.logger.warn(`Token verification failed: ${err.name}`);
            throw new common_1.UnauthorizedException(message);
        }
        if (payload.type !== 'access') {
            throw new common_1.UnauthorizedException('Invalid token type');
        }
        const isTokenBlacklisted = await this.redisService.isTokenBlacklisted(payload.jti);
        if (isTokenBlacklisted) {
            throw new common_1.UnauthorizedException('Token has been revoked');
        }
        const allRevoked = await this.redisService.areAllUserTokensRevoked(payload.sub);
        if (allRevoked) {
            throw new common_1.UnauthorizedException('Session invalidated. Please login again.');
        }
        request.user = payload;
        return true;
    }
    extractBearerToken(request) {
        const authHeader = request.headers?.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return null;
        }
        const token = authHeader.split(' ')[1];
        return token || null;
    }
};
exports.JwtAuthGuard = JwtAuthGuard;
exports.JwtAuthGuard = JwtAuthGuard = JwtAuthGuard_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [jwt_1.JwtService,
        redis_service_1.RedisService])
], JwtAuthGuard);
//# sourceMappingURL=jwt.guard.js.map