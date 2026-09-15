using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class CaseTimelineOrder : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_case_events_CaseId_At",
                table: "case_events");

            migrationBuilder.CreateIndex(
                name: "IX_case_events_CaseId_Id",
                table: "case_events",
                columns: new[] { "CaseId", "Id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_case_events_CaseId_Id",
                table: "case_events");

            migrationBuilder.CreateIndex(
                name: "IX_case_events_CaseId_At",
                table: "case_events",
                columns: new[] { "CaseId", "At" });
        }
    }
}
