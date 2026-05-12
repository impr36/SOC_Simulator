# main.py
"""
SOC Simulator - Fixed & Improved Version
With Real Security Logs, Pie Chart, Time Range & Search
"""
import ctypes
import sys
import os

def run_as_admin():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True

    params = " ".join([f'"{arg}"' for arg in sys.argv])
    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        None,
        1
    )
    return False

if not run_as_admin():
    os._exit(0)

from backend import enable_audit_policies
from backend import group_alerts
import customtkinter as ctk
from tkinter import ttk, messagebox
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import os
from tkinter import PhotoImage
from datetime import datetime
from database import initialize_database
from fim_monitor import start_fim_monitor
from forensic_scanner import scan_filesystem
from sysmon_collector import read_sysmon_logs
from backend import calculate_alert_categories
from backend import stop_event

# Now you can call it directly
now = datetime.now()
print(now)

from backend import (
    read_windows_security_logs, 
    simulate_hids_data, 
    simulate_nids_data,
    store_alert, 
    generate_explanation, 
    load_alerts, load_raw_logs, 
    load_incidents, 
    create_logs_folder_and_save,
    mark_alert
)
from config import APP_TITLE, WINDOW_SIZE, SIDEBAR_WIDTH
from backend import background_db_writer

threading.Thread(
    target=background_db_writer,
    daemon=True
).start()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class SOCSimulator(ctk.CTk):
    def __init__(self):
        super().__init__()  
        self.last_scan_duration="N/A"
        self.last_refresh_duration="N/A"
        initialize_database()
        #self.fim_observer=start_fim_monitor("C:\\Users")

        enable_audit_policies()

        self.alert_page=0
        self.alert_page_size=100
        self.has_scanned = False
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.is_closing = False

        # Window config
        self.title(APP_TITLE)
        self.geometry(WINDOW_SIZE)
        self.minsize(1400, 820)

        # Custom Icon
        self.set_custom_icon()

        # Filters
        self.severity_var = ctk.StringVar(value="All")
        self.status_var = ctk.StringVar(value="All")

        self.current_time_range = "24h"
        self.current_search = ""

        # Main container
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True)
        self.last_scan_time = "Never"

        # UI setup
        self.create_sidebar()
        self.create_content_area()
        self.show_tab("dashboard")
        

    def set_custom_icon(self):
        try:
            if os.path.exists("soc_icon.ico"):
                self.iconbitmap("soc_icon.ico")

        except Exception as e:
            print("Icon error:", e)

    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self.main_frame, width=SIDEBAR_WIDTH, corner_radius=0, fg_color="#1a1a2e")
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Logo Section
        logo = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo.pack(pady=30, padx=20, fill="x")
        ctk.CTkLabel(logo, text="🛡️", font=ctk.CTkFont(size=42)).pack()
        ctk.CTkLabel(logo, text="SOC Simulator", font=ctk.CTkFont(size=19, weight="bold")).pack(pady=6)
        ctk.CTkLabel(logo, text="Host & Network IDS", font=ctk.CTkFont(size=12), text_color="gray").pack()

        ctk.CTkFrame(self.sidebar, height=2, fg_color="#33334d").pack(fill="x", padx=20, pady=15)

        # Menu Items
        self.menu_buttons = {}
        menus = [
            ("📊 Dashboard", "dashboard"),
            ("🚨 Alerts", "alerts"),
            ("🛡️ Host IDS", "hids"),
            ("🌐 Network IDS", "nids"),
            ("📜 Detection Rules", "rules"),
            ("📁 Reports", "reports"),
            ("🔎 Forensics Storage", "forensics"),
            ("⚙️ Settings", "settings")
        ]

        for text, name in menus:
            btn = ctk.CTkButton(
                self.sidebar, 
                text=text, 
                height=46, 
                anchor="w",
                fg_color="transparent", 
                hover_color="#16213e",
                font=ctk.CTkFont(size=15),
                corner_radius=8,
                command=lambda n=name: self.show_tab(n)
            )
            btn.pack(pady=2, padx=16, fill="x")
            self.menu_buttons[name] = btn

    def on_close(self):

        import os, time, gc, sqlite3
        import matplotlib.pyplot as plt
    
        if not messagebox.askyesno(
            "Exit SOC Simulator",
            "Are you sure you want to close the application?"
        ):
            return
    
        self.is_closing = True
    
        try:
            stop_event.set()
            time.sleep(2)
        except:
            pass
        
        try:
            for aid in self.tk.call('after', 'info'):
                self.after_cancel(aid)
        except:
            pass
        
        try: plt.close('all')
        except: pass
    
        try:
            conn = sqlite3.connect("soc_simulator.db")
            conn.execute("PRAGMA wal_checkpoint(FULL);")
            conn.commit()
            conn.close()
        except Exception as e:
            print(e)
    
        try: self.destroy()
        except: pass
    
        gc.collect()
    
        time.sleep(2)
    
        for file in [
            "soc_simulator.db",
            "soc_simulator.db-shm",
            "soc_simulator.db-wal"
        ]:
    
            for _ in range(3):
            
                try:
                
                    if os.path.exists(file):
                        os.chmod(file, 0o777)
                        os.remove(file)
                        print(f"Deleted: {file}")
    
                    break
                
                except Exception as e:
                
                    print(f"Retry delete {file}: {e}")
    
                    time.sleep(1)
    
        print("Shutting down app safely...")
    
        os._exit(0)
    
    def create_category_graph(self,parent,alerts_df):

        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

        category_counts=calculate_alert_categories(
            alerts_df
        )

        categories=list(category_counts.keys())

        values=list(category_counts.values())
        for widget in parent.winfo_children():
            widget.destroy()
        fig,ax=plt.subplots(
            figsize=(8,4),
            dpi=100
        )

        ax.plot(
            categories,
            values,
            marker="o"
        )

        ax.set_title(
            "Threat Category Distribution"
        )

        ax.tick_params(
            axis='x',
            rotation=45
        )

        fig.tight_layout()

        self.current_graph_figure = fig

        canvas=FigureCanvasTkAgg(
            fig,
            master=parent
        )

        canvas.draw()

        canvas.get_tk_widget().pack(
            fill="both",
            expand=True
        )
    
    def create_content_area(self):

        self.content_frame = ctk.CTkFrame(
            self.main_frame,
            fg_color="#0f0f1e"
        )

        self.content_frame.pack(
            side="right",
            fill="both",
            expand=True
        )

        # ================= TOP BAR =================
        top = ctk.CTkFrame(
            self.content_frame,
            height=60,
            fg_color="#15244b"
        )

        top.pack(fill="x")

        # ================= TITLE =================
        ctk.CTkLabel(
            top,
            text="SOC Simulator | Real + Simulated IDS",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(side="left", padx=20)

        # ================= TIME FILTER =================
        self.time_var = ctk.StringVar(value="24h")

        self.time_combo = ctk.CTkComboBox(
            top,
            values=[
                "1h",
                "6h",
                "12h",
                "24h",
                "3d",
                "7d",
                "15d",
                "30d"
            ],
            variable=self.time_var,
            width=120
        )

        self.time_combo.pack(
            side="right",
            padx=10,
            pady=10
        )

        ctk.CTkLabel(
            top,
            text="Time:"
        ).pack(side="right", padx=(10, 0))

        # ================= APPLY BUTTON =================
        self.apply_button = ctk.CTkButton(
            top,
            text="Apply",
            width=80,
            command=self.apply_filters
        )

        self.apply_button.pack(
            side="right",
            padx=10
        )

        # ================= SEARCH BAR =================
        self.search_entry = ctk.CTkEntry(
            top,
            placeholder_text="Search alerts...",
            width=250
        )

        # ================= REFRESH BUTTON =================
        self.dashboard_refresh_btn = ctk.CTkButton(
            top,
            text="⟳ Refresh Logs",
            width=140,
            command=self.run_incremental_refresh
        )

       # ================= FORENSICS BUTTON =================
        self.forensics_top_btn = ctk.CTkButton(
            top,
            text="💾 Save Forensics",
            width=160,
            command=self.save_forensics
        )

        # ================= TAB CONTAINER =================
        self.tab_container = ctk.CTkFrame(
            self.content_frame,
            fg_color="transparent"
        )

        self.tab_container.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=20
        )

        self.tabs = {
            name: ctk.CTkFrame(
                self.tab_container,
                fg_color="transparent"
            )
            for name in [
                "dashboard",
                "alerts",
                "hids",
                "nids",
                "rules",
                "reports",
                "forensics",
                "settings"
            ]
        }

        self.populate_tabs()

    def apply_filters(self):

        self.current_time_range=self.time_var.get()
        self.current_search=self.search_entry.get().strip()
        self.update_dashboard_metrics()
        self.update_alerts_display()
        self.update_hids_display()
        self.update_nids_display()
    
    def populate_tabs(self):
        # self.create_dashboard_tab()
        # self.create_alerts_tab()
        # self.create_hids_tab()
        # self.create_nids_tab()
        # self.create_rules_tab()
        # self.create_reports_tab()
        # self.create_forensics_tab()
        # self.create_settings_tab()
        self.loaded_tabs = set()
        self.show_tab("dashboard")


    def show_tab(self, tab_name):

        try:

            # ================= HIDE ALL TABS =================

            for tab in self.tabs.values():
                tab.pack_forget()

            self.current_tab = tab_name

            # ================= LOAD TAB ONLY ONCE =================

            if not hasattr(self, "loaded_tabs"):
                self.loaded_tabs = set()

            if tab_name not in self.loaded_tabs:

                if tab_name == "dashboard":
                    self.create_dashboard_tab()

                elif tab_name == "alerts":
                    self.create_alerts_tab()

                elif tab_name == "hids":
                    self.create_hids_tab()

                elif tab_name == "nids":
                    self.create_nids_tab()

                elif tab_name == "rules":
                    self.create_rules_tab()

                elif tab_name == "reports":
                    self.create_reports_tab()

                elif tab_name == "forensics":
                    self.create_forensics_tab()

                elif tab_name == "settings":
                    self.create_settings_tab()

                self.loaded_tabs.add(tab_name)

            # ================= SHOW SELECTED TAB =================

            self.tabs[tab_name].pack(
                fill="both",
                expand=True
            )

            # ================= SIDEBAR BUTTON HIGHLIGHT =================

            for name, btn in self.menu_buttons.items():

                btn.configure(
                    fg_color="#0a84ff"
                    if name == tab_name
                    else "transparent"
                )

            # ================= TOP BAR CONTROLS =================

            if hasattr(self, "search_entry"):
                self.search_entry.pack_forget()

            if hasattr(self, "dashboard_refresh_btn"):
                self.dashboard_refresh_btn.pack_forget()

            if hasattr(self, "forensics_top_btn"):
                self.forensics_top_btn.pack_forget()

            # ================= DASHBOARD =================

            if tab_name == "dashboard":

                if hasattr(self, "dashboard_refresh_btn"):

                    self.dashboard_refresh_btn.pack(
                        side="right",
                        padx=10,
                        pady=10
                    )

                if hasattr(self, "forensics_top_btn"):

                    self.forensics_top_btn.pack(
                        side="right",
                        padx=10,
                        pady=10
                    )

            # ================= SEARCH ENABLED TABS =================

            elif tab_name in [
                "alerts",
                "hids",
                "nids",
                "reports",
                "forensics"
            ]:

                if hasattr(self, "search_entry"):

                    self.search_entry.pack(
                        side="right",
                        padx=10,
                        pady=10
                    )

        except Exception as e:

            print("Show tab error:", e)

    def on_filter_change(self, *args):
        self.current_time_range = self.time_var.get()
        self.current_search = self.search_var.get().strip()
        self.refresh_all()

    def refresh_all(self):

        try:

            current_tab = None

            for name, tab in self.tabs.items():

                if tab.winfo_ismapped():
                    current_tab = name
                    break

            if current_tab == "dashboard":
               self.update_dashboard_metrics()

            elif current_tab == "alerts":
                self.update_alerts_display()

            elif current_tab == "hids":
                self.update_hids_display()

            elif current_tab == "nids":
                self.update_nids_display()

        except Exception as e:
            print("Refresh error:", e)

    def update_all_displays(self):
        if hasattr(self, 'alerts_tree'): self.update_alerts_display()
        if hasattr(self, 'alert_rows_frame'): self.update_hids_display()
        if hasattr(self, 'nids_tree'): self.update_nids_display()
        if hasattr(self, 'incidents_tree'): self.update_incidents_display()

    # ====================== DASHBOARD ======================
    # def create_dashboard_tab(self):

    #     f = self.tabs["dashboard"]

    #     # # Clear old widgets
    #     # for widget in f.winfo_children():
    #     #     widget.destroy()

    #     # ================= MAIN CONTAINER =================
    #     container = ctk.CTkFrame(f, fg_color="transparent")
    #     container.pack(fill="both", expand=True, padx=30, pady=25)

    #     # ================= TITLE =================
    #     ctk.CTkLabel(
    #         container,
    #         text="SOC Dashboard",
    #         font=ctk.CTkFont(size=28, weight="bold")
    #     ).pack(anchor="w", pady=(0, 20))

    #     # ================= LOAD ALERTS =================
    #     alerts_df = load_alerts(
    #         self.current_time_range,
    #         self.current_search
    #     )

    #     total = len(alerts_df)

    #     high = 0
    #     if not alerts_df.empty and 'severity' in alerts_df.columns:
    #         high = len(
    #             alerts_df[alerts_df['severity'] == "HIGH"]
    #         )

    #  # ================= METRICS =================
    #     # metrics_row = ctk.CTkFrame(
    #     #     container,
    #     #     fg_color="transparent"
    #     # )
    #     # metrics_row.pack(fill="x", pady=10)

    #     # metrics=[

    #     #     (
    #     #         "Total Alerts",
    #     #         total,
    #     #         "#ff5555"
    #     #     ),

    #     #     (
    #     #         "High Severity",
    #     #         high,
    #     #         "#ff3333"
    #     #     ),

    #     #     (
    #     #         "Last Scan",
    #     #         self.last_scan_time
    #     #         if self.last_scan_time!="Never"
    #     #         else "Not Scanned",
    #     #         "#00cc88"
    #     #     ),

    #     #     (
    #     #         "Full Scan Duration",
    #     #         self.last_scan_duration,
    #     #         "#ffaa00"
    #     #     ),

    #     #     (
    #     #         "Refresh Duration",
    #     #         self.last_refresh_duration,
    #     #         "#00bfff"
    #     #     )
    #     # ]

    #     self.total_alert_card = ctk.CTkLabel(
    #         metrics_row,
    #         text="0",
    #         font=ctk.CTkFont(size=32, weight="bold"),
    #         text_color="#ff5555"
    #     )

    #     self.high_alert_card = ctk.CTkLabel(
    #         metrics_row,
    #         text="0",
    #         font=ctk.CTkFont(size=32, weight="bold"),
    #         text_color="#ff3333"
    #     )

    #     self.last_scan_card = ctk.CTkLabel(
    #         metrics_row,
    #         text="Never",
    #         font=ctk.CTkFont(size=24, weight="bold"),
    #         text_color="#00cc88"
    #     )

    #     self.scan_duration_card = ctk.CTkLabel(
    #         metrics_row,
    #         text="0 sec",
    #         font=ctk.CTkFont(size=24, weight="bold"),
    #         text_color="#ffaa00"
    #     )

    #     self.refresh_duration_card = ctk.CTkLabel(
    #         metrics_row,
    #         text="0 sec",
    #         font=ctk.CTkFont(size=24, weight="bold"),
    #         text_color="#00bfff"
    #     )

    #     # ================= PIE CHART =================
    #     pie_section = ctk.CTkFrame(
    #         container,
    #         fg_color="#1e1e2e",
    #         corner_radius=12
    #     )

    #     pie_section.pack(fill="x", pady=25)

    #     ctk.CTkLabel(
    #         pie_section,
    #         text="Severity Breakdown",
    #         font=ctk.CTkFont(size=18, weight="bold")
    #     ).pack(pady=15)

    #     charts_frame=ctk.CTkFrame(
    #         pie_section,
    #         fg_color="transparent"
    #     )

    #     charts_frame.pack(
    #         fill="both",
    #         expand=True
    #     )

    #     left_chart=ctk.CTkFrame(
    #         charts_frame
    #     )

    #     left_chart.pack(
    #         side="left",
    #         fill="both",
    #         expand=True,
    #         padx=10,
    #         pady=10
    #     )

    #     right_chart=ctk.CTkFrame(
    #         charts_frame
    #     )

    #     right_chart.pack(
    #         side="left",
    #         fill="both",
    #         expand=True,
    #         padx=10,
    #         pady=10
    #     )

    #     self.create_pie_chart(left_chart)

    #     self.create_category_graph(
    #         right_chart,
    #         alerts_df
    #     )

    #     # ================= CENTER ACTION AREA =================
    #     self.dashboard_action_frame = ctk.CTkFrame(
    #         container,
    #         fg_color="transparent"
    #     )

    #     self.dashboard_action_frame.pack(pady=40)

    #     self.scan_button = ctk.CTkButton(
    #         self.dashboard_action_frame,
    #         text=(
    #             "✅ Scan Complete"
    #             if getattr(self, "has_scanned", False)
    #             else "🔍 Full System Scan"
    #         ),
    #         width=260,
    #         height=60,
    #         font=ctk.CTkFont(size=18, weight="bold"),
    #         command=self.run_full_scan,
    #         state=(
    #             "disabled"
    #             if getattr(self, "has_scanned", False)
    #             else "normal"
    #         )
    #     )

    #     self.scan_button.pack()

    def create_dashboard_tab(self):

        f = self.tabs["dashboard"]

        dashboard_scroll = ctk.CTkScrollableFrame(
            f,
            fg_color="transparent"
        )

        dashboard_scroll.pack(
            fill="both",
            expand=True
        )

        container = ctk.CTkFrame(
            dashboard_scroll,
            fg_color="transparent"
        )

        container.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=15
        )

        # ================= TITLE =================

        ctk.CTkLabel(
            container,
            text="SOC Dashboard",
            font=ctk.CTkFont(
                size=28,
                weight="bold"
            )
        ).pack(
            anchor="w",
            pady=(0,20)
        )

        # ================= ALERT DATA =================

        alerts_df = load_alerts(
            self.current_time_range,
            self.current_search
        )

        total = len(alerts_df)

        high = 0

        if not alerts_df.empty and 'severity' in alerts_df.columns:

            high = len(
                alerts_df[
                    alerts_df['severity']=="HIGH"
                ]
            )

        # ================= METRICS ROW =================

        metrics_row = ctk.CTkFrame(
            container,
            fg_color="transparent"
        )

        metrics_row.pack(
            fill="x",
            pady=10
        )

        # ================= TOTAL ALERTS =================

        total_card = ctk.CTkFrame(
            metrics_row,
            fg_color="#1e1e2e",
            corner_radius=12
        )

        total_card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=8
        )

        ctk.CTkLabel(
            total_card,
            text="Total Alerts",
            font=ctk.CTkFont(size=14)
        ).pack(pady=(15,5))

        self.total_alert_card = ctk.CTkLabel(
            total_card,
            text=str(total),
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color="#ff5555"
        )

        self.total_alert_card.pack(pady=(0,15))

        # ================= HIGH ALERTS =================

        high_card = ctk.CTkFrame(
            metrics_row,
            fg_color="#1e1e2e",
            corner_radius=12
        )

        high_card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=8
        )

        ctk.CTkLabel(
            high_card,
            text="High Severity",
            font=ctk.CTkFont(size=14)
        ).pack(pady=(15,5))

        self.high_alert_card = ctk.CTkLabel(
            high_card,
            text=str(high),
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color="#ff3333"
        )

        self.high_alert_card.pack(pady=(0,15))

        # ================= LAST SCAN =================

        scan_card = ctk.CTkFrame(
            metrics_row,
            fg_color="#1e1e2e",
            corner_radius=12
        )

        scan_card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=8
        )

        ctk.CTkLabel(
            scan_card,
            text="Last Scan",
            font=ctk.CTkFont(size=14)
        ).pack(pady=(15,5))

        self.last_scan_card = ctk.CTkLabel(
            scan_card,
            text=self.last_scan_time,
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#00cc88"
        )

        self.last_scan_card.pack(pady=(0,15))

        # ================= FULL SCAN DURATION =================

        duration_card = ctk.CTkFrame(
            metrics_row,
            fg_color="#1e1e2e",
            corner_radius=12
        )

        duration_card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=8
        )

        ctk.CTkLabel(
            duration_card,
            text="Full Scan Duration",
            font=ctk.CTkFont(size=14)
        ).pack(pady=(15,5))

        self.scan_duration_card = ctk.CTkLabel(
            duration_card,
            text=self.last_scan_duration,
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#ffaa00"
        )

        self.scan_duration_card.pack(pady=(0,15))

        # ================= REFRESH DURATION =================

        refresh_card = ctk.CTkFrame(
            metrics_row,
            fg_color="#1e1e2e",
            corner_radius=12
        )

        refresh_card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=8
        )

        ctk.CTkLabel(
            refresh_card,
            text="Refresh Duration",
            font=ctk.CTkFont(size=14)
        ).pack(pady=(15,5))

        self.refresh_duration_card = ctk.CTkLabel(
            refresh_card,
            text=self.last_refresh_duration,
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#00bfff"
        )

        self.refresh_duration_card.pack(pady=(0,15))

        # ================= CHART SECTION =================

        chart_section = ctk.CTkFrame(
            container,
            fg_color="#1e1e2e",
            corner_radius=12
        )

        chart_section.pack(
            fill="both",
            expand=True,
            pady=25,
            padx=15
        )

        ctk.CTkLabel(
            chart_section,
            text="Severity Breakdown",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=(15,10))

        # ================= PIE CHART FRAME =================

        self.pie_chart_frame = ctk.CTkFrame(
            chart_section,
            fg_color="#25253a",
            corner_radius=10,
            height=350
        )

        self.pie_chart_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=(10,15)
        )

        # ================= CATEGORY GRAPH FRAME =================

        self.graph_frame = ctk.CTkFrame(
            chart_section,
            fg_color="#25253a",
            corner_radius=10,
            height=350
        )

        self.graph_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=(0,15)
        )

        # ================= RENDER CHARTS =================

        self.create_pie_chart(
            self.pie_chart_frame
        )

        self.create_category_graph(
            self.graph_frame,
            alerts_df
        )

        # ================= ACTION BUTTON =================

        self.dashboard_action_frame = ctk.CTkFrame(
            container,
            fg_color="transparent"
        )

        self.dashboard_action_frame.pack(pady=30)

        self.scan_button = ctk.CTkButton(
            self.dashboard_action_frame,
            text="🔍 Full System Scan",
            width=260,
            height=60,
            font=ctk.CTkFont(
                size=18,
                weight="bold"
            ),
            command=self.run_full_scan
        )

        self.scan_button.pack()

    def update_dashboard_metrics(self):

        alerts_df = load_alerts(
            self.current_time_range,
            self.current_search
        )

        total = len(alerts_df)

        high = 0

        if not alerts_df.empty and 'severity' in alerts_df.columns:

            high = len(
                alerts_df[
                    alerts_df['severity'] == "HIGH"
                ]
            )

        self.total_alert_card.configure(
            text=str(total)
        )

        self.high_alert_card.configure(
            text=str(high)
        )

        self.last_scan_card.configure(
            text=str(self.last_scan_time)
        )

        self.scan_duration_card.configure(
            text=str(self.last_scan_duration)
        )

        self.refresh_duration_card.configure(
            text=str(self.last_refresh_duration)
        )
    
    def run_full_scan(self):
        import time

        scan_start=time.time()
        print("🔍 Full scan triggered")

        messagebox.showinfo(
            "Full Scan",
            "Full historical scan started.\nThis may take several minutes."
        )

        if hasattr(self, "scan_button"):
            self.scan_button.configure(
                text="Scanning...",
                state="disabled"
            )

        def task():

            if self.is_closing:
                return

            try:
                from datetime import datetime
                from backend import (
                    read_windows_security_logs,
                    get_last_raw_log_timestamp
                )

                last_ts = get_last_raw_log_timestamp()

                six_months_hours = 24 * 30 * 6

                security_df = read_windows_security_logs(
                    start_time=None,
                    hours=six_months_hours
                )
                
                sysmon_df=read_sysmon_logs(
                    start_time=last_ts,
                    hours=six_months_hours
                )
                
                df=pd.concat([
                    security_df,
                    sysmon_df
                ],ignore_index=True)

                scan_filesystem()

                print(f"Logs fetched: {len(df)}")

                self.has_scanned = True
                scan_end=time.time()

                self.last_scan_duration=(
                    f"{round(scan_end-scan_start,2)} sec"
                )
                self.last_scan_time = datetime.now().strftime(
                    "%d-%m-%Y %H:%M:%S"
                )

                if not self.is_closing and self.winfo_exists():

                    def refresh_ui():
                    
                        self.after_scan_complete()

                        self.refresh_dashboard()

                        self.update_dashboard_metrics()

                        self.update_alerts_display()

                        self.update_hids_display()

                        self.update_nids_display()

                        messagebox.showinfo(
                            "Scan Complete",
                            f"Scan completed successfully\n\nDuration: {self.last_scan_duration}"
                        )

                    self.after(
                        2000,
                        refresh_ui
                    )

            except Exception as e:

                print("Scan Error:", e)

                if not self.is_closing and self.winfo_exists():

                    self.after(
                        0,
                        lambda: messagebox.showerror(
                            "Scan Error",
                            str(e)
                        )
                    )

        threading.Thread(
            target=task,
            daemon=True
        ).start()

    def run_incremental_refresh(self):
        import time

        refresh_start=time.time()
        print("⟳ Incremental refresh triggered")

        if hasattr(self, "dashboard_refresh_btn"):

            self.dashboard_refresh_btn.configure(
                text="Refreshing...",
                state="disabled"
            )

        def task():

            if self.is_closing:
                return

            try:
                from datetime import datetime
                from backend import (
                    read_windows_security_logs,
                    get_last_raw_log_timestamp
                )

                last_ts = get_last_raw_log_timestamp()

                df = read_windows_security_logs(
                    start_time=last_ts
                )

                print(f"Incremental logs fetched: {len(df)}")

                self.has_scanned = True
                refresh_end=time.time()

                self.last_refresh_duration=(
                    f"{round(refresh_end-refresh_start,2)} sec"
                )
                self.last_scan_time = datetime.now().strftime(
                    "%d-%m-%Y %H:%M:%S"
                )

                if not self.is_closing and self.winfo_exists():

                    self.after(
                        0,
                        lambda: self.after_scan_complete()
                    )

            except Exception as e:

                print("Refresh Error:", e)

                if not self.is_closing and self.winfo_exists():

                    self.after(
                        0,
                        lambda: messagebox.showerror(
                            "Refresh Error",
                            str(e)
                        )
                    )

        threading.Thread(
            target=task,
            daemon=True
        ).start()

    # def after_scan_complete(self):

    #     if not self.winfo_exists():
    #         return

    #     try:

            # ================= REFRESH ALL DATA VIEWS =================

        #     self.refresh_dashboard()
        #     self.update_alerts_display()
        #     self.update_hids_display()
        #     self.update_nids_display()

        #     # ================= REFRESH FORENSICS =================

        #     if hasattr(self, "create_forensics_tab"):
        #         self.create_forensics_tab()

        #     # ================= UPDATE SCAN BUTTON =================

        #     if hasattr(self, "scan_button"):
        #         self.scan_button.configure(
        #             text="✅ Scan Complete"
        #             state="disabled"
        #         )

        #     # ================= RESET REFRESH BUTTON =================

        #     if hasattr(self, "dashboard_refresh_btn"):
        #         self.dashboard_refresh_btn.pack(
        #             side="right",
        #             padx=10,
        #             pady=10
        #         )

        #         self.dashboard_refresh_btn.configure(
        #             text="⟳ Refresh Logs",
        #             state="normal"
        #         )

        #     # ================= SHOW FORENSICS EXPORT BUTTON =================

        #     if hasattr(self, "forensics_top_btn"):
        #         self.forensics_top_btn.pack(
        #             side="right",
        #             padx=10,
        #             pady=10
        #         )

        # except Exception as e:
        #     print("After scan error:", e)


    def after_scan_complete(self):

        try:

            if hasattr(self, "scan_button"):

                self.scan_button.configure(
                    text="✅ Scan Complete",
                    state="disabled"
                )

            if hasattr(self, "dashboard_refresh_btn"):

                self.dashboard_refresh_btn.configure(
                    text="⟳ Refresh Logs",
                    state="normal"
                )

            # SAFE refresh only
            self.after(100, self.update_dashboard_metrics)

        except Exception as e:

            print("After scan error:", e)

    def refresh_dashboard(self):

        try:

            alerts_df = load_alerts(
                self.current_time_range,
                self.current_search
            )

            total_alerts = len(alerts_df)

            high_alerts = len(
                alerts_df[
                    alerts_df["severity"].isin(
                        ["HIGH", "CRITICAL"]
                    )
                ]
            )

            self.total_alert_card.configure(
                text=str(total_alerts)
            )

            self.high_alert_card.configure(
                text=str(high_alerts)
            )

            # Clear old charts
            for widget in self.pie_chart_frame.winfo_children():
                widget.destroy()

            for widget in self.graph_frame.winfo_children():
                widget.destroy()

            # Recreate charts
            self.create_pie_chart(
                self.pie_chart_frame
            )

            self.create_category_graph(
                self.graph_frame,
                alerts_df
            )

            self.update_hids_display()

        except Exception as e:
            print("Dashboard refresh error:", e)

    # def refresh_alerts(self):
    #     if "alerts" in self.tabs:
    #         self.tabs["alerts"].destroy()
    #         self.tabs["alerts"] = ctk.CTkFrame(self.tab_container, fg_color="transparent")
    #         self.tabs["alerts"].pack(fill="both", expand=True)
    #         self.create_alerts_tab()
    
    # def refresh_hids(self):
    #     if "hids" in self.tabs:
    #         self.tabs["hids"].destroy()
    #         self.tabs["hids"] = ctk.CTkFrame(self.tab_container, fg_color="transparent")
    #         self.tabs["hids"].pack(fill="both", expand=True)
    #         self.create_hids_tab()

    # def refresh_all_views(self):
    #     # Reload all tabs content
    #     self.create_dashboard_tab()
    #     self.create_alerts_tab()
    #     self.create_hids_tab()
    
    #     # If NIDS exists
    #     if hasattr(self, "create_nids_tab"):
    #         self.create_nids_tab()
    
    def create_reports_tab(self):
        f = self.tabs["reports"]

        for widget in f.winfo_children():
            widget.destroy()

        ctk.CTkLabel(f, text="📄 Case Reports",
                     font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(30, 10))

        ctk.CTkLabel(f, 
                     text="Analyst decisions and investigation notes",
                     text_color="gray").pack(pady=(0, 20))

        self.reports_frame = ctk.CTkScrollableFrame(f)
        self.reports_frame.pack(fill="both", expand=True, padx=30, pady=10)

        self.load_reports()
    
    def create_pie_chart(self, parent):

        for widget in parent.winfo_children():
            widget.destroy()

        alerts = load_alerts(
            self.current_time_range,
            self.current_search
        )

        if alerts.empty:

            ctk.CTkLabel(
                parent,
                text="🟢 No alerts detected\nSystem is healthy",
                text_color="#00cc88",
                font=ctk.CTkFont(size=18, weight="bold")
            ).pack(pady=40)

            return

        if "severity" not in alerts.columns:
            return

        alerts["severity"] = alerts["severity"].fillna("LOW")

        severity_counts = alerts["severity"].value_counts()

        labels = severity_counts.index.tolist()
        sizes = severity_counts.values.tolist()

        if len(sizes) == 0:
            return

        fig, ax = plt.subplots(
            figsize=(6, 5),
            facecolor="#1e1e2e"
        )

        colors = [
            "#ff4757",
            "#ffa502",
            "#2ed573",
            "#1e90ff"
        ]

        ax.pie(
            sizes,
            labels=labels,
            autopct='%1.1f%%',
            startangle=90,
            colors=colors[:len(labels)],
            textprops={
                "color": "white",
                "fontsize": 11
            }
        )

        ax.set_title(
            "Alert Severity Distribution",
            color="white"
        )

        fig.patch.set_facecolor("#1e1e2e")
        ax.set_facecolor("#1e1e2e")

        self.current_pie_figure = fig

        canvas = FigureCanvasTkAgg(
            fig,
            master=parent
        )

        canvas.draw()

        canvas.get_tk_widget().pack(
            fill="both",
            expand=True,
            pady=10
        )

    def export_logs(self):

        df=load_alerts(
            self.current_time_range,
            self.current_search
        )

        if df.empty:

            messagebox.showwarning(
                "Export",
                "No data to export!"
            )

            return

        os.makedirs("forensics/exports", exist_ok=True)

        filename=os.path.join(
            "forensics/exports",
            f"forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )

        df.to_csv(
            filename,
            index=False
        )

        messagebox.showinfo(
            "Export",
            f"Forensics exported:\n{filename}"
        )

    # ====================== HIDS Tab ======================
    def create_hids_tab(self):
        f = self.tabs["hids"]

        for widget in f.winfo_children():
            widget.destroy()

        ctk.CTkLabel(f, text="🖥️ Host-IDS - Windows Security Logs",
                     font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(20, 10))

        # Small description
        ctk.CTkLabel(f, 
                     text="Real-time Windows Security Event Log Analysis",
                     text_color="gray").pack(pady=(0, 15))

        self.create_alert_table(f)
        self.after(100, self.update_hids_display)

    def read_real_hids(self):
        def task():
            if self.is_closing:
                return

            if self.is_closing:
                return
            df = read_windows_security_logs(hours=24)
            for _, row in df.iterrows():
                alert = row.to_dict()
                alert['explanation'] = generate_explanation(row.get('type',''), row.get('description',''))
                store_alert(alert)
            self.after(0, lambda: (messagebox.showinfo("HIDS", "Real Security Logs loaded!"), self.refresh_all()))
        threading.Thread(target=task, daemon=True).start()

    # ====================== Treeview Helper ======================
    def create_alert_table(self, parent):
        """Creates scrollable container for grouped alerts"""
        # Remove old header if exists
        for widget in parent.winfo_children():
            if isinstance(widget, ctk.CTkFrame) and widget.winfo_children():
                # Skip if it's the main container
                pass

        scroll_container = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll_container.pack(fill="both", expand=True, padx=5, pady=10)

        self.alert_rows_frame = ctk.CTkFrame(scroll_container, fg_color="transparent")
        self.alert_rows_frame.pack(fill="both", expand=True)
        

    def update_alerts_display(self):

        # Prevent multiple threads running simultaneously
        if hasattr(self, "loading_alerts") and self.loading_alerts:
            return

        self.loading_alerts = True

        def task():

            if self.is_closing:
                self.loading_alerts = False
                return

            try:
                df=load_alerts(
                    time_range=self.current_time_range,
                    search_term=self.current_search,
                    limit=self.alert_page_size
                )

                if df.empty:
                    grouped_data = []

                else:
                    # Limit dataset for UI performance
                    # df = df.head(1000).copy()

                    # Safe timestamp conversion
                    df['timestamp'] = pd.to_datetime(
                        df['timestamp'],
                        format='mixed',
                        errors='coerce'
                    )

                    # Remove invalid timestamps
                    df = df.dropna(subset=['timestamp'])

                    grouped_df = group_alerts(df, time_bucket_minutes=20)

                    grouped_data = []

                    for _, row in grouped_df.iterrows():

                        mask = (
                            (df['type'] == row['type']) &
                            (df['severity'] == row['severity']) &
                            (df['log_source'] == row['log_source']) &
                            (
                                df['timestamp'].dt.floor('20min')
                                == row['time_bucket']
                            )
                        )

                        group_events = df[mask].sort_values(
                            by='timestamp',
                            ascending=False
                        ).head(20)

                        grouped_data.append({
                            "type": row['type'],
                            "severity": row['severity'],
                            "source": row['log_source'],
                            "count": int(row['count']),
                            "last_seen": row['last_seen'],
                            "first_seen": row['first_seen'],
                            "data": group_events
                        })

                # Safe UI update
                if not self.is_closing and self.winfo_exists():
                    self.after(
                        0,
                        lambda: self.render_grouped_alerts(grouped_data)
                    )

            except Exception as e:
                print("Alert load error:", e)

            finally:
                self.loading_alerts = False

        threading.Thread(target=task, daemon=True).start()


    def render_grouped_alerts(self, grouped_data):
        if not hasattr(
            self,
            "alert_rows_frame"
        ):
            return

        for widget in self.alert_rows_frame.winfo_children():
            widget.destroy()

        if not grouped_data:
            ctk.CTkLabel(self.alert_rows_frame,
                text="🟢 No alerts detected\nSystem behavior is normal",
                text_color="#00cc88",
                font=ctk.CTkFont(size=16, weight="bold")
            ).pack(pady=100)
            return

        for group in grouped_data[:50]:  # 🔥 LIMIT GROUPS
            main_frame = ctk.CTkFrame(self.alert_rows_frame, fg_color="#1a1a2e", corner_radius=10)
            main_frame.pack(fill="x", pady=10, padx=12)

            # Header
            header = ctk.CTkFrame(main_frame, fg_color="transparent")
            header.pack(fill="x", padx=15, pady=12)

            severity_color = {"HIGH": "#ff4d4d", "MEDIUM": "#ffaa00", "LOW": "#00cc88"}.get(group.get('severity'), "white")

            time_str = str(group['last_seen'])[:19]
            if 'first_seen' in group and group['first_seen'] != group['last_seen']:
                time_str = f"{str(group['first_seen'])[:16]} → {str(group['last_seen'])[:16]}"

            header_text = f"{group['type'].replace('_', ' ').title()}  •  {group['severity']}  •  {group['count']} events"

            ctk.CTkLabel(header, text=header_text, 
                        text_color=severity_color,
                        font=ctk.CTkFont(size=15, weight="bold")).pack(side="left", anchor="w")

            ctk.CTkLabel(header, text=time_str, text_color="#888888").pack(side="left", padx=15)

            # Details Frame
            details_frame = ctk.CTkFrame(main_frame, fg_color="#16213e", corner_radius=8)
            details_frame.pack(fill="x", padx=10, pady=(0, 12))
            details_frame.pack_forget()

            def toggle(df=details_frame):
                if df.winfo_ismapped():
                    df.pack_forget()
                else:
                    df.pack(fill="x")

            ctk.CTkButton(header, text="▼ Expand", width=110, height=30,
                          font=ctk.CTkFont(size=13),
                          command=toggle).pack(side="right")

            # Individual Alert Rows
            for _, row in group['data'].head(20).iterrows():  # 🔥 LIMIT ROWS
                row_frame = ctk.CTkFrame(details_frame, fg_color="transparent")
                row_frame.pack(fill="x", padx=15, pady=5)

                ts = str(row['timestamp'])[:19]
                desc = row.get('description', row.get('explanation', 'No description available'))
                alert_id = row['id']
                status = row.get('status', 'New')

                # Left side - Timestamp
                ctk.CTkLabel(row_frame, text=ts, text_color="#aaaaaa", width=165).pack(side="left")

                # Description
                desc_label = ctk.CTkLabel(row_frame, text=desc, anchor="w")
                desc_label.pack(side="left", fill="x", padx=12)

                # Status
                status_colors = {
                    "New": "#3399ff",
                    "Investigating": "#ffaa00",
                    "True Positive": "#00cc88",
                    "False Positive": "#888888"
                }
                ctk.CTkLabel(row_frame, text=status, 
                            text_color=status_colors.get(status, "white"), 
                            width=110).pack(side="left")

                # Actions
                actions = ctk.CTkFrame(row_frame, fg_color="transparent")
                actions.pack(side="right")

                ctk.CTkButton(actions, text="🟡", width=30, height=30, 
                              command=lambda iid=alert_id: self.update_status(iid, "Investigating")).pack(side="left", padx=1)

                ctk.CTkButton(actions, text="✅", width=30, height=30,
                              command=lambda iid=alert_id: self.ask_comment(iid, "True Positive")).pack(side="left", padx=1)

                ctk.CTkButton(actions, text="❌", width=30, height=30,
                              command=lambda iid=alert_id: self.update_status(iid, "False Positive")).pack(side="left", padx=1)
    
    def update_hids_display(self):

        def task():
            if self.is_closing:
                return
    
            from backend import RULES
    
            df=load_alerts(
                time_range=self.current_time_range,
                search_term=self.current_search,
                limit=1000
            )
    
            if not df.empty:
                # ✅ Load ALL rules dynamically
                hids_types = list(RULES.get("hids_rules", {}).keys())
                df=df[
                        df["log_source"].isin([
                            "Security",
                            "Sysmon"
                        ])
                    ]
    
            # df = df.head(1000)
    
            grouped_df = group_alerts(df, time_bucket_minutes=20)
    
            grouped_data = []
    
            for _, row in grouped_df.iterrows():
                mask = (
                    (df['type'] == row['type']) &
                    (df['severity'] == row['severity']) &
                    (df['log_source'] == row['log_source']) &
                    (pd.to_datetime(df['timestamp']).dt.floor('20min') == row['time_bucket'])
                )
    
                group_events = df[mask].sort_values(
                    by='timestamp',
                    ascending=False
                ).head(20)
    
                grouped_data.append({
                    "type": row['type'],
                    "severity": row['severity'],
                    "source": row['log_source'],
                    "count": int(row['count']),
                    "last_seen": row['last_seen'],
                    "first_seen": row['first_seen'],
                    "data": group_events
                })
    
            if not self.is_closing and self.winfo_exists():
                self.after(0, lambda: self.render_grouped_alerts(grouped_data))
    
        #threading.Thread(target=task, daemon=True).start()
        task()

    def create_alerts_tab(self):
        f = self.tabs["alerts"]

        for widget in f.winfo_children():
            widget.destroy()

        container = ctk.CTkFrame(f, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            container,
            text="🚨 SOC Alert Queue",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(anchor="w", pady=(0, 15))

        # Info label
        ctk.CTkLabel(
            container,
            text="Grouped alerts across all sources • Click group to expand",
            text_color="gray"
        ).pack(anchor="w", pady=(0, 10))

        self.create_alert_table(container)
        self.after(100, self.update_alerts_display)   

    def create_nids_tab(self):
        f = self.tabs["nids"]

        for widget in f.winfo_children():
            widget.destroy()

        ctk.CTkLabel(f, text="🌐 Network-IDS",
                     font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(30, 5))

        ctk.CTkLabel(f, 
                     text="Network Traffic Analysis Module",
                     text_color="gray").pack(pady=(0, 20))
        
        # Status Indicator
        try:
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=2)
            status = "🟢 Network Capture Ready"
            color = "#00cc88"
        except:
            status = "🔴 Network monitoring unavailable (No internet / privileges)"
            color = "#ff4444"

        ctk.CTkLabel(f, text=status, text_color=color, 
                     font=ctk.CTkFont(size=15)).pack(pady=8)

        # Simulation Button
        btn_frame = ctk.CTkFrame(f, fg_color="transparent")
        btn_frame.pack(pady=20)

        ctk.CTkButton(btn_frame, text="🔬 Simulate Network Traffic",
                      width=280, height=45,
                      command=self.simulate_nids).pack()

        ctk.CTkLabel(f, 
                     text="Real packet capture will be added in future version",
                     text_color="#666666", font=ctk.CTkFont(size=13)).pack(pady=30)

        # Show NIDS alerts if any
        self.nids_alerts_frame = ctk.CTkFrame(f, fg_color="transparent")
        self.nids_alerts_frame.pack(fill="both", expand=True, padx=30, pady=10)

        self.after(150, self.update_nids_display)

    def update_nids_display(self):
        if not hasattr(
                self,
                "nids_alerts_frame"
            ):
                return

        for widget in self.nids_alerts_frame.winfo_children():
            widget.destroy()

        df = load_alerts(
            self.current_time_range,
            self.current_search,
            limit=1000
        )

        if df.empty:

            ctk.CTkLabel(
                self.nids_alerts_frame,
                text="No network alerts detected",
                text_color="gray"
            ).pack(pady=40)

            return

        nids_df = df[
            df['type'].isin([
                'port_scan',
                'syn_flood',
                'reconnaissance'
            ])
        ]

        if nids_df.empty:

            ctk.CTkLabel(
                self.nids_alerts_frame,
                text="No NIDS activity found",
                text_color="gray"
            ).pack(pady=40)

            return

        self.create_alert_table(self.nids_alerts_frame)

        grouped = group_alerts(
            nids_df,
            time_bucket_minutes=10
        )

        grouped_data=[]

        for _, row in grouped.iterrows():

            mask=(
                (nids_df['type']==row['type']) &
                (nids_df['severity']==row['severity'])
            )

            events=nids_df[mask]

            grouped_data.append({

                "type": row['type'],
                "severity": row['severity'],
                "source": row['log_source'],
                "count": int(row['count']),
                "last_seen": row['last_seen'],
                "first_seen": row['first_seen'],
                "data": events

            })

        self.render_grouped_alerts(grouped_data)
    
    def simulate_nids(self):
        def task():
            if self.is_closing:
                return
            
            try:
                data = simulate_nids_data(30)
                print(f"Simulating {len(data)} NIDS events...")
                
                for _, row in data.iterrows():
                    alert = row.to_dict()
                    alert['explanation'] = generate_explanation(row.get('type',''), row.get('description',''))
                    store_alert(alert)
                
                self.after(0, lambda: (
                    messagebox.showinfo("NIDS", f"Added {len(data)} simulated network events!"),
                    self.update_nids_display()
                ))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("NIDS Error", str(e)))

        threading.Thread(target=task, daemon=True).start()

    def create_forensics_tab(self):

        import os
        import subprocess
        from datetime import datetime

        f = self.tabs["forensics"]

        for widget in f.winfo_children():
            widget.destroy()

        # ================= TITLE =================

        ctk.CTkLabel(
            f,
            text="📦 Forensics Storage",
            font=ctk.CTkFont(
                size=24,
                weight="bold"
            )
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 5)
        )

        ctk.CTkLabel(
            f,
            text="Exported forensic bundles and investigation packages",
            text_color="gray"
        ).pack(
            anchor="w",
            padx=22,
            pady=(0, 20)
        )

        # ================= SCROLLABLE AREA =================

        scroll = ctk.CTkScrollableFrame(
            f,
            fg_color="transparent"
        )

        scroll.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=10
        )

        export_root = "forensics_exports"

        if not os.path.exists(export_root):

            ctk.CTkLabel(
                scroll,
                text="No forensic bundles found.",
                text_color="gray",
                font=ctk.CTkFont(size=16)
            ).pack(pady=80)

            return

        folders = sorted(
            [
                folder for folder in os.listdir(export_root)
                if os.path.isdir(
                    os.path.join(export_root, folder)
                )
            ],
            reverse=True
        )

        if not folders:

            ctk.CTkLabel(
                scroll,
                text="No forensic bundles exported yet.",
                text_color="gray",
                font=ctk.CTkFont(size=16)
            ).pack(pady=80)

            return

        # ================= BUNDLE CARDS =================

        for folder in folders:

            full_path = os.path.abspath(
                os.path.join(export_root, folder)
            )

            created_time = datetime.fromtimestamp(
                os.path.getctime(full_path)
            ).strftime("%d-%m-%Y %H:%M:%S")

            card = ctk.CTkFrame(
                scroll,
                fg_color="#1e1e2e",
                corner_radius=10
            )

            card.pack(
                fill="x",
                pady=8,
                padx=5
            )

            # ================= LEFT SIDE =================

            left = ctk.CTkFrame(
                card,
                fg_color="transparent"
            )

            left.pack(
                side="left",
                fill="x",
                expand=True,
                padx=15,
                pady=12
            )

            ctk.CTkLabel(
                left,
                text=folder,
                font=ctk.CTkFont(
                    size=16,
                    weight="bold"
                )
            ).pack(anchor="w")

            ctk.CTkLabel(
                left,
                text=f"Created: {created_time}",
                text_color="gray"
            ).pack(anchor="w", pady=2)

            ctk.CTkLabel(
                left,
                text=full_path,
                text_color="#888888",
                wraplength=850,
                justify="left"
            ).pack(anchor="w", pady=(2, 0))

            # ================= OPEN BUTTON =================

            ctk.CTkButton(
                card,
                text="📂 Open Folder",
                width=150,
                height=40,
                command=lambda p=full_path: subprocess.Popen(
                    f'explorer "{p}"'
                )
            ).pack(
                side="right",
                padx=20
            )

    def create_settings_tab(self):
        f = self.tabs["settings"]

        ctk.CTkLabel(f, text="⚙️ Settings",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=20)

        ctk.CTkLabel(f, text="Theme and system settings coming soon",
                 text_color="gray").pack(pady=10)

    def create_rules_tab(self):

        f=self.tabs["rules"]

        for widget in f.winfo_children():
            widget.destroy()

        scroll=ctk.CTkScrollableFrame(
            f,
            fg_color="transparent"
        )

        scroll.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=20
        )

        ctk.CTkLabel(
            scroll,
            text="📋 Detection Rules",
            font=ctk.CTkFont(
                size=24,
                weight="bold"
            )
        ).pack(
            pady=(10,5)
        )

        ctk.CTkLabel(
            scroll,
            text="Configured in detection_rules.json • Edit rules below",
            text_color="gray"
        ).pack(
            pady=(0,20)
        )

        self.rules_frame=ctk.CTkFrame(
            scroll,
            fg_color="transparent"
        )

        self.rules_frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=10
        )

        self.load_rules_ui()


    def render_alert_rows(self, df):
        for widget in self.alert_rows_frame.winfo_children():
            widget.destroy()

        if df.empty:
            ctk.CTkLabel(self.alert_rows_frame,
                text="🟢 No alerts detected\nSystem behavior is normal",
                text_color="#00cc88",
                font=ctk.CTkFont(size=14)
            ).pack(pady=40)
            return

        for _, row in df.iterrows():
            frame = ctk.CTkFrame(self.alert_rows_frame)
            frame.pack(fill="x", pady=3, padx=5)

            severity_color = {
                "HIGH": "#ff4d4d",
                "MEDIUM": "#ffaa00",
                "LOW": "#00cc88"
            }.get(row['severity'], "white")

            status_color = {
                "New": "#3399ff",
                "Investigating": "#ffaa00",
                "True Positive": "#00cc88",
                "False Positive": "#888888"
            }.get(row['status'], "white")

            values = [
                row['id'],
                str(row['timestamp'])[:19],
                row['type'],
                row['severity'],
                row.get('description', ''),
                row.get('log_source', ''),
                row['status']
            ]

            for i, val in enumerate(values):
                color = severity_color if i == 3 else status_color if i == 5 else "white"
                ctk.CTkLabel(frame, text=str(val), text_color=color,
                             width=120 if i != 4 else 200)\
                    .grid(row=0, column=i, padx=5)

            # Action Buttons
            action_frame = ctk.CTkFrame(frame, fg_color="transparent")
            action_frame.grid(row=0, column=6)

            ctk.CTkButton(action_frame, text="🟡", width=30,
                          command=lambda i=row['id']: self.update_status(i, "Investigating"))\
                .pack(side="left", padx=2)

            ctk.CTkButton(action_frame, text="✅", width=30,
                          command=lambda i=row['id']: self.ask_comment(i, "True Positive"))\
                .pack(side="left", padx=2)

            ctk.CTkButton(action_frame, text="❌", width=30,
                          command=lambda i=row['id']: self.update_status(i, "False Positive"))\
                .pack(side="left", padx=2)        

    def update_status(self, alert_id, status):
        try:
            mark_alert(alert_id, status)
            self.refresh_all()           # This will update everything
            messagebox.showinfo("Success", f"Alert marked as {status}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def ask_comment(self, alert_id, status):
        comment = ctk.CTkInputDialog(
            text="Enter your reasoning for this decision:",
            title="Analyst Comment"
        ).get_input()

        if comment and comment.strip():
            mark_alert(alert_id, status)
            self.save_report(alert_id, status, comment)
            self.refresh_all()
            messagebox.showinfo("Success", f"Alert marked as {status}")        

    def save_forensics(self):

        try:

            import os
            import json
            from datetime import datetime
            from tkinter import messagebox

            timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")

            export_folder=os.path.join(
                "forensics_exports",
                f"case_{timestamp}"
            )

            os.makedirs(export_folder, exist_ok=True)

            alerts_df=load_alerts(
                time_range=self.current_time_range,
                limit=5000
            )

            alerts_path=os.path.join(
                export_folder,
                "alerts.csv"
            )

            alerts_df.to_csv(
                alerts_path,
                index=False
            )

            raw_logs_df=load_raw_logs(
                time_range=self.current_time_range,
                limit=10000
            )

            raw_logs_path=os.path.join(
                export_folder,
                "raw_logs.csv"
            )

            raw_logs_df.to_csv(
                raw_logs_path,
                index=False
            )

            # ================= SAVE PIE CHART =================

            try:
            
                if hasattr(self, "current_pie_figure"):
                
                    pie_path = os.path.join(
                        export_folder,
                        "pie_chart.png"
                    )

                    self.current_pie_figure.savefig(
                        pie_path,
                        dpi=300,
                        bbox_inches="tight"
                    )

                    print(f"[FORENSICS] Pie chart saved: {pie_path}")

            except Exception as e:
            
                print("Pie chart export error:", e)

            # ================= SAVE CATEGORY GRAPH =================

            try:
            
                if hasattr(self, "current_graph_figure"):
                
                    graph_path = os.path.join(
                        export_folder,
                        "threat_category_graph.png"
                    )

                    self.current_graph_figure.savefig(
                        graph_path,
                        dpi=300,
                        bbox_inches="tight"
                    )

                    print(f"[FORENSICS] Graph saved: {graph_path}")

            except Exception as e:
            
                print("Graph export error:", e)

            metadata={

                "case_created":timestamp,

                "time_range":self.current_time_range,

                "total_alerts":len(alerts_df),

                "total_raw_logs":len(raw_logs_df),

                "export_folder":export_folder
            }

            metadata_path=os.path.join(
                export_folder,
                "case_metadata.json"
            )

            with open(metadata_path,"w") as f:
                json.dump(metadata,f,indent=4)

            print(f"[FORENSICS] Bundle exported: {export_folder}")

            # ================= REFRESH FORENSICS TAB =================

            try:
            
                if "forensics" in self.loaded_tabs:
                
                    self.loaded_tabs.remove("forensics")

                self.create_forensics_tab()

            except Exception as e:
            
                print("Forensics tab refresh error:", e)

            messagebox.showinfo(
                "Forensics Export",
                f"Forensic bundle exported successfully\n\nLocation:\n{export_folder}"
            )

        except Exception as e:

            print(f"[FORENSICS ERROR] {e}")

            messagebox.showerror(
                "Export Failed",
                str(e)
            )

    def save_report(self, alert_id, status, comment):
        import json, os
        from datetime import datetime

        os.makedirs("reports", exist_ok=True)
        file_path = f"reports/report_{alert_id}_{int(datetime.now().timestamp())}.json"

        report = {
            "alert_id": alert_id,
            "status": status,
            "analyst_note": comment,
            "timestamp": datetime.now().isoformat()
        }

        with open(file_path, "w") as f:
            json.dump(report, f, indent=4)

    def load_reports(self):
        """Load and display saved analyst reports"""
        for widget in self.reports_frame.winfo_children():
            widget.destroy()

        import os, json
        from datetime import datetime

        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            ctk.CTkLabel(self.reports_frame,
                        text="No reports yet.\nMark some alerts as True/False Positive to create reports.",
                        text_color="gray", font=ctk.CTkFont(size=14)).pack(pady=100)
            return

        report_files = [f for f in os.listdir(reports_dir) if f.endswith('.json')]

        if not report_files:
            ctk.CTkLabel(self.reports_frame,
                        text="No reports yet.\nStart triaging alerts in Alert Queue.",
                        text_color="gray").pack(pady=80)
            return

        for file in sorted(report_files, reverse=True):
            try:
                with open(os.path.join(reports_dir, file), 'r') as f:
                    report = json.load(f)

                card = ctk.CTkFrame(self.reports_frame, fg_color="#1e1e2e", corner_radius=8)
                card.pack(fill="x", pady=6, padx=10)

                timestamp = report.get('timestamp', '')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        timestamp = dt.strftime("%d-%m-%Y %H:%M")
                    except:
                        pass

                ctk.CTkLabel(card, text=f"Alert #{report.get('alert_id')} • {timestamp}",
                            font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(12,2))

                ctk.CTkLabel(card, text=f"Status: {report.get('status')}",
                            text_color="#00cc88" if report.get('status') == "True Positive" else "#ffaa00").pack(anchor="w", padx=15)

                if report.get('analyst_note'):
                    ctk.CTkLabel(card, text=f"Note: {report.get('analyst_note')[:120]}...",
                                text_color="gray").pack(anchor="w", padx=15, pady=(0,12))

            except:
                continue
    
    def load_rules_ui(self):
        import json

        for widget in self.rules_frame.winfo_children():
            widget.destroy()

        try:
            with open("detection_rules.json", "r") as f:
                data = json.load(f)
                hids_rules = data.get("hids_rules", {})

            if not hids_rules:
                ctk.CTkLabel(self.rules_frame, 
                            text="No rules found", 
                            text_color="gray").pack(pady=50)
                return

            #for name, rule in hids_rules.items():
            for i, (name, rule) in enumerate(hids_rules.items()):

                if i >= 200:
                    break
                card = ctk.CTkFrame(self.rules_frame, fg_color="#1e1e2e", corner_radius=8)
                card.pack(fill="x", pady=6, padx=10)

                # Left info
                info_frame = ctk.CTkFrame(card, fg_color="transparent")
                info_frame.pack(side="left", fill="x", expand=True, padx=15, pady=12)

                ctk.CTkLabel(info_frame, text=name.replace("_", " ").title(), 
                            font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w")

                details = f"Event ID: {rule.get('event_id', 'N/A')}  |  Threshold: {rule.get('threshold', 'N/A')}  |  Window: {rule.get('window_min', 'N/A')} min  |  Severity: {rule.get('severity', 'N/A')}"
                ctk.CTkLabel(info_frame, text=details, text_color="gray").pack(anchor="w", pady=2)

                # Edit Button
                ctk.CTkButton(card, text="Edit Rule", width=100,
                              command=lambda n=name: self.edit_rule(n)).pack(side="right", padx=15)

        except Exception as e:
            ctk.CTkLabel(self.rules_frame, text=f"Error loading rules: {e}", text_color="red").pack(pady=50)

    def edit_rule(self, rule_name):
        import json
    
        with open("detection_rules.json", "r") as f:
            data = json.load(f)
    
        rule = data["hids_rules"][rule_name]
    
        threshold = ctk.CTkInputDialog(
            text=f"Threshold ({rule['threshold']}):",
            title="Edit Rule").get_input()
    
        window = ctk.CTkInputDialog(
            text=f"Window Minutes ({rule['window_min']}):",
            title="Edit Rule").get_input()
    
        severity = ctk.CTkInputDialog(
            text=f"Severity ({rule['severity']}):",
            title="Edit Rule").get_input()
    
        if threshold:
            rule['threshold'] = int(threshold)
        if window:
            rule['window_min'] = int(window)
        if severity:
            rule['severity'] = severity.upper()
    
        with open("detection_rules.json", "w") as f:
            json.dump(data, f, indent=4)
    
        self.load_rules_ui()
    
    
    def run(self):
        self.mainloop()


if __name__ == "__main__":
    try:
        print("App started successfully")
        app = SOCSimulator()
        app.mainloop()
    except Exception as e:
        print("Startup Error:", e)