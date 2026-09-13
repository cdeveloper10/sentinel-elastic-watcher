using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class EngineNodes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "engine_nodes",
                columns: table => new
                {
                    NodeId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    LastSeenAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    StartedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Version = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    TickSeconds = table.Column<int>(type: "integer", nullable: false),
                    MaxConcurrentRules = table.Column<int>(type: "integer", nullable: false),
                    ActionsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    NeverActEntries = table.Column<int>(type: "integer", nullable: false),
                    LastTickRulesEvaluated = table.Column<int>(type: "integer", nullable: false),
                    LastTickAlertsRaised = table.Column<int>(type: "integer", nullable: false),
                    LastTickDurationMs = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_engine_nodes", x => x.NodeId);
                });

            migrationBuilder.CreateIndex(
                name: "IX_engine_nodes_LastSeenAt",
                table: "engine_nodes",
                column: "LastSeenAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "engine_nodes");
        }
    }
}
