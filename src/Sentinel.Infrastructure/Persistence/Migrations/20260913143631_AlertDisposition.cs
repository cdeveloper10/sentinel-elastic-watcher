using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AlertDisposition : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Disposition",
                table: "alerts",
                type: "character varying(24)",
                maxLength: 24,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_alerts_RuleId_Disposition",
                table: "alerts",
                columns: new[] { "RuleId", "Disposition" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_alerts_RuleId_Disposition",
                table: "alerts");

            migrationBuilder.DropColumn(
                name: "Disposition",
                table: "alerts");
        }
    }
}
