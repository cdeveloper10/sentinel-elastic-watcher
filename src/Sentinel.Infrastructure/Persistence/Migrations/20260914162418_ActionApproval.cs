using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class ActionApproval : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "ApprovalExpiresAt",
                table: "action_executions",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "DecidedAt",
                table: "action_executions",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DecidedBy",
                table: "action_executions",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DecisionNote",
                table: "action_executions",
                type: "character varying(1024)",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_action_executions_Status_ApprovalExpiresAt",
                table: "action_executions",
                columns: new[] { "Status", "ApprovalExpiresAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_action_executions_Status_ApprovalExpiresAt",
                table: "action_executions");

            migrationBuilder.DropColumn(
                name: "ApprovalExpiresAt",
                table: "action_executions");

            migrationBuilder.DropColumn(
                name: "DecidedAt",
                table: "action_executions");

            migrationBuilder.DropColumn(
                name: "DecidedBy",
                table: "action_executions");

            migrationBuilder.DropColumn(
                name: "DecisionNote",
                table: "action_executions");
        }
    }
}
