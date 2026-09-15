using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class ActionReversal : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ReversalError",
                table: "action_executions",
                type: "character varying(1024)",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "ReversedAt",
                table: "action_executions",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ReversedBy",
                table: "action_executions",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_action_executions_ActionType_ReversedAt",
                table: "action_executions",
                columns: new[] { "ActionType", "ReversedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_action_executions_ActionType_ReversedAt",
                table: "action_executions");

            migrationBuilder.DropColumn(
                name: "ReversalError",
                table: "action_executions");

            migrationBuilder.DropColumn(
                name: "ReversedAt",
                table: "action_executions");

            migrationBuilder.DropColumn(
                name: "ReversedBy",
                table: "action_executions");
        }
    }
}
