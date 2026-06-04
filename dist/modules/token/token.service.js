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
var TokenService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.TokenService = void 0;
const common_1 = require("@nestjs/common");
const jwt_1 = require("@nestjs/jwt");
const uuid_1 = require("uuid");
const prisma_service_1 = require("../../prisma/prisma.service");
const redis_service_1 = require("../redis/redis.service");
const jwt_config_1 = require("../../config/jwt.config");
let TokenService = TokenService_1 = class TokenService {
    constructor(jwtService, prisma, redisService) {
        this.jwtService = jwtService;
        this.prisma = prisma;
        this.redisService = redisService;
        this.logger = new common_1.Logger(TokenService_1.name);
        this.jwtConfig = (0, jwt_config_1.buildJwtConfig)();
    }
    async generateTokenPair(userId, email, role) {
        const accessJti = (0, uuid_1.v4)();
        const refreshJti = (0, uuid_1.v4)();
        const accessPayload = {
            sub: userId,
            email,
            role,
            jti: accessJti,
            type: 'access',
        };
        const refreshPayload = {
            sub: userId,
            email,
            role,
            jti: refreshJti,
            type: 'refresh',
        };
        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync(accessPayload, {
                algorithm: 'RS256',
                expiresIn: this.jwtConfig.accessExpiry,
                issuer: this.jwtConfig.issuer,
                audience: this.jwtConfig.audience,
                privateKey: this.jwtConfig.privateKey,
            }),
            this.jwtService.signAsync(refreshPayload, {
                algorithm: 'RS256',
                expiresIn: this.jwtConfig.refreshExpiry,
                issuer: this.jwtConfig.issuer,
                audience: this.jwtConfig.audience,
                privateKey: this.jwtConfig.privateKey,
            }),
        ]);
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);
        await this.prisma.refreshToken.create({
            data: {
                jti: refreshJti,
                userId,
                expiresAt,
            },
        });
        this.logger.log(`Token pair generated for user: ${userId}`);
        return { accessToken, refreshToken };
    }
    async rotateRefreshToken(refreshToken) {
        let payload;
        try {
            payload = await this.jwtService.verifyAsync(refreshToken, {
                algorithms: ['RS256'],
                issuer: this.jwtConfig.issuer,
                audience: this.jwtConfig.audience,
                publicKey: this.jwtConfig.publicKey,
            });
        }
        catch {
            throw new common_1.UnauthorizedException('Invalid or expired refresh token');
        }
        if (payload.type !== 'refresh') {
            throw new common_1.UnauthorizedException('Invalid token type');
        }
        const stored = await this.prisma.refreshToken.findUnique({
            where: { jti: payload.jti },
        });
        if (!stored) {
            await this.redisService.blacklistAllUserTokens(payload.sub);
            this.logger.warn(`Refresh token reuse detected for user: ${payload.sub}. All sessions revoked.`);
            throw new common_1.UnauthorizedException('Security violation detected. Please login again.');
        }
        await this.prisma.refreshToken.delete({
            where: { jti: payload.jti },
        });
        return this.generateTokenPair(payload.sub, payload.email, payload.role);
    }
    async revokeAccessToken(accessToken) {
        const payload = this.jwtService.decode(accessToken);
        if (!payload?.jti || !payload?.exp) {
            this.logger.warn('Attempted to revoke token with missing jti or exp');
            return;
        }
        await this.redisService.blacklistToken(payload.jti, payload.exp);
    }
    async revokeAllUserTokens(userId) {
        await this.redisService.blacklistAllUserTokens(userId);
        await this.prisma.refreshToken.deleteMany({
            where: { userId },
        });
        this.logger.log(`All sessions revoked for user: ${userId}`);
    }
};
exports.TokenService = TokenService;
exports.TokenService = TokenService = TokenService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [jwt_1.JwtService,
        prisma_service_1.PrismaService,
        redis_service_1.RedisService])
], TokenService);
//# sourceMappingURL=token.service.js.map