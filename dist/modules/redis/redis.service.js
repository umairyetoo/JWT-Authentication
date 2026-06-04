"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var RedisService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.RedisService = void 0;
const common_1 = require("@nestjs/common");
const ioredis_1 = __importDefault(require("ioredis"));
const redis_config_1 = require("../../config/redis.config");
let RedisService = RedisService_1 = class RedisService {
    constructor() {
        this.logger = new common_1.Logger(RedisService_1.name);
    }
    onModuleInit() {
        const config = (0, redis_config_1.buildRedisConfig)();
        this.client = new ioredis_1.default({
            host: config.host,
            port: config.port,
        });
        this.client.on('connect', () => {
            this.logger.log('Redis connected');
        });
        this.client.on('error', (err) => {
            this.logger.error('Redis connection error', err.message);
        });
    }
    async onModuleDestroy() {
        await this.client.quit();
        this.logger.log('Redis disconnected');
    }
    async blacklistToken(jti, exp) {
        const now = Math.floor(Date.now() / 1000);
        const ttl = exp - now;
        if (ttl <= 0)
            return;
        await this.client.setex(`blacklist:${jti}`, ttl, '1');
        this.logger.log(`Token blacklisted: ${jti}, TTL: ${ttl}s`);
    }
    async isTokenBlacklisted(jti) {
        const result = await this.client.get(`blacklist:${jti}`);
        return result !== null;
    }
    async blacklistAllUserTokens(userId) {
        const TTL_7_DAYS = 7 * 24 * 60 * 60;
        await this.client.setex(`blacklist:user:${userId}`, TTL_7_DAYS, '1');
        this.logger.log(`All tokens revoked for user: ${userId}`);
    }
    async areAllUserTokensRevoked(userId) {
        const result = await this.client.get(`blacklist:user:${userId}`);
        return result !== null;
    }
};
exports.RedisService = RedisService;
exports.RedisService = RedisService = RedisService_1 = __decorate([
    (0, common_1.Injectable)()
], RedisService);
//# sourceMappingURL=redis.service.js.map