-- CreateEnum
CREATE TYPE "GlobalRole" AS ENUM ('none', 'superadmin');

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "globalRole" "GlobalRole" NOT NULL DEFAULT 'none';
