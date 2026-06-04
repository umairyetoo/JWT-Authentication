"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildRedisConfig = buildRedisConfig;
function buildRedisConfig() {
    return {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT || '6379', 10),
    };
}
//# sourceMappingURL=redis.config.js.map