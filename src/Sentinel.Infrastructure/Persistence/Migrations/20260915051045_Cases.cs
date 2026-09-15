using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Sentinel.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Cases : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "CaseId",
                table: "alerts",
                type: "integer",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "cases",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    CaseId = table.Column<string>(type: "character varying(48)", maxLength: 48, nullable: false),
                    Title = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    EntityKey = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: false),
                    EntityLabel = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    OpenKey = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: true),
                    Status = table.Column<string>(type: "character varying(24)", maxLength: 24, nullable: false),
                    Severity = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    AssignedTo = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    AlertCount = table.Column<int>(type: "integer", nullable: false),
                    OpenedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastAlertAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ClosedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ClosedBy = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    Disposition = table.Column<string>(type: "character varying(24)", maxLength: 24, nullable: true),
                    ClosingNote = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_cases", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "case_events",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    CaseId = table.Column<int>(type: "integer", nullable: false),
                    At = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Kind = table.Column<string>(type: "character varying(24)", maxLength: 24, nullable: false),
                    Author = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    Text = table.Column<string>(type: "character varying(4096)", maxLength: 4096, nullable: false),
                    AlertId = table.Column<long>(type: "bigint", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_case_events", x => x.Id);
                    table.ForeignKey(
                        name: "FK_case_events_cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_alerts_CaseId",
                table: "alerts",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_case_events_CaseId_At",
                table: "case_events",
                columns: new[] { "CaseId", "At" });

            migrationBuilder.CreateIndex(
                name: "IX_cases_CaseId",
                table: "cases",
                column: "CaseId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_cases_OpenKey",
                table: "cases",
                column: "OpenKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_cases_Status_LastAlertAt",
                table: "cases",
                columns: new[] { "Status", "LastAlertAt" });

            migrationBuilder.AddForeignKey(
                name: "FK_alerts_cases_CaseId",
                table: "alerts",
                column: "CaseId",
                principalTable: "cases",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_alerts_cases_CaseId",
                table: "alerts");

            migrationBuilder.DropTable(
                name: "case_events");

            migrationBuilder.DropTable(
                name: "cases");

            migrationBuilder.DropIndex(
                name: "IX_alerts_CaseId",
                table: "alerts");

            migrationBuilder.DropColumn(
                name: "CaseId",
                table: "alerts");
        }
    }
}
