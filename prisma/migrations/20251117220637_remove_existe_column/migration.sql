/*
  Warnings:

  - You are about to drop the column `spectatorLevel` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `spectatorPoints` on the `User` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[level,streamerId]` on the table `SpectatorLevelConfig` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `streamerId` to the `SpectatorLevelConfig` table without a default value. This is not possible if the table is not empty.

*/
-- DropIndex
DROP INDEX "SpectatorLevelConfig_level_key";

-- AlterTable
ALTER TABLE "SpectatorLevelConfig" ADD COLUMN     "streamerId" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "User" DROP COLUMN "spectatorLevel",
DROP COLUMN "spectatorPoints";

-- CreateTable
CREATE TABLE "Loyalty" (
    "id" TEXT NOT NULL,
    "points" INTEGER NOT NULL DEFAULT 0,
    "level" INTEGER NOT NULL DEFAULT 1,
    "spectatorId" TEXT NOT NULL,
    "streamerId" TEXT NOT NULL,

    CONSTRAINT "Loyalty_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Loyalty_spectatorId_streamerId_key" ON "Loyalty"("spectatorId", "streamerId");

-- CreateIndex
CREATE UNIQUE INDEX "SpectatorLevelConfig_level_streamerId_key" ON "SpectatorLevelConfig"("level", "streamerId");

-- AddForeignKey
ALTER TABLE "Loyalty" ADD CONSTRAINT "Loyalty_spectatorId_fkey" FOREIGN KEY ("spectatorId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Loyalty" ADD CONSTRAINT "Loyalty_streamerId_fkey" FOREIGN KEY ("streamerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SpectatorLevelConfig" ADD CONSTRAINT "SpectatorLevelConfig_streamerId_fkey" FOREIGN KEY ("streamerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
