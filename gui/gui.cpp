#include "gui.h"
#include "../backend/core.h"
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <cstring>
#include <unistd.h>

namespace gui {

using namespace backend;

static GtkWidget* gwindow = nullptr;
static GtkWidget* ggamelist = nullptr;
static GtkListStore* ggamestore = nullptr;
static GtkWidget* gdllentry = nullptr;
static GtkWidget* gmethodcombo = nullptr;
static GtkWidget* groutingcombo = nullptr;
static GtkWidget* garchcombo = nullptr;
static GtkWidget* gerasecheck = nullptr;
static GtkWidget* gcopycheck = nullptr;
static GtkWidget* gwaitspin = nullptr;
static GtkWidget* gdelaycheck = nullptr;
static GtkWidget* gdelayspin = nullptr;
static GtkWidget* ginjectbtn = nullptr;
static GtkWidget* gstatuslabel = nullptr;
static GtkTextBuffer* glogbuffer = nullptr;
static GtkWidget* glogscroll = nullptr;
static GtkWidget* gdetailname = nullptr;
static GtkWidget* gdetailexe = nullptr;
static GtkWidget* gdetailappid = nullptr;
static GtkWidget* gdetailprefix = nullptr;
static GtkWidget* gdetailpid = nullptr;
static GtkWidget* gemptylabel = nullptr;
static GtkWidget* gactionpanel = nullptr;

static std::vector<runningprocess> grunning;
static std::mutex glogmutex;

static void inserttagged(const std::string& combined);
static void logerror(const std::string& text);
static void loginfo(const std::string& text);

static void inserttagged(const std::string& combined) {
    size_t bar = combined.find('|');
    std::string tag = (bar == std::string::npos) ? "[info]" : combined.substr(0, bar);
    std::string body = (bar == std::string::npos) ? combined : combined.substr(bar + 1);
    std::lock_guard<std::mutex> lock(glogmutex);
    GtkTextIter iter;
    gtk_text_buffer_get_end_iter(glogbuffer, &iter);
    gtk_text_buffer_insert_with_tags_by_name(glogbuffer, &iter, tag.c_str(), -1, tag.c_str(), NULL);
    gtk_text_buffer_insert(glogbuffer, &iter, " ", -1);
    gtk_text_buffer_insert(glogbuffer, &iter, body.c_str(), -1);
    gtk_text_buffer_insert(glogbuffer, &iter, "\n", -1);
    GtkAdjustment* adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(glogscroll));
    if (adj) {
        gtk_adjustment_set_value(adj, gtk_adjustment_get_upper(adj) - gtk_adjustment_get_page_size(adj));
    }
}

static void logsink(const std::string& text) {
    std::string tag = "[info]";
    std::string body = text;
    if (text.rfind("[!]", 0) == 0) {
        tag = "[error]";
        body = text.substr(4);
    } else if (text.rfind("[*]", 0) == 0) {
        tag = "[debug]";
        body = text.substr(4);
    } else if (text.rfind("[+]", 0) == 0) {
        tag = "[info]";
        body = text.substr(4);
    }
    g_idle_add([](gpointer data) -> gboolean {
        inserttagged(*(std::string*)data);
        delete (std::string*)data;
        return G_SOURCE_REMOVE;
    }, new std::string(tag + "|" + body));
}

static void logerror(const std::string& text) {
    g_idle_add([](gpointer data) -> gboolean {
        inserttagged("[error]|" + *(std::string*)data);
        delete (std::string*)data;
        return G_SOURCE_REMOVE;
    }, new std::string(text));
}

static void loginfo(const std::string& text) {
    g_idle_add([](gpointer data) -> gboolean {
        inserttagged("[info]|" + *(std::string*)data);
        delete (std::string*)data;
        return G_SOURCE_REMOVE;
    }, new std::string(text));
}

static void refreshprocesses() {
    grunning = getrunningprocesses();
    gtk_list_store_clear(ggamestore);
    for (const auto& r : grunning) {
        GtkTreeIter iter;
        gtk_list_store_append(ggamestore, &iter);
        gtk_list_store_set(ggamestore, &iter,
            0, r.gamename.c_str(),
            1, r.exename.c_str(),
            2, r.appid.c_str(),
            3, r.pid.c_str(),
            -1);
    }
    if (grunning.empty()) {
        gtk_label_set_text(GTK_LABEL(gstatuslabel), "no games running");
        gtk_widget_set_visible(gemptylabel, TRUE);
        gtk_widget_set_visible(gactionpanel, FALSE);
    } else {
        std::string s = std::to_string(grunning.size()) + " running";
        gtk_label_set_text(GTK_LABEL(gstatuslabel), s.c_str());
        gtk_widget_set_visible(gemptylabel, FALSE);
        gtk_widget_set_visible(gactionpanel, TRUE);
        GtkTreePath* path = gtk_tree_path_new_first();
        gtk_tree_selection_select_path(gtk_tree_view_get_selection(GTK_TREE_VIEW(ggamelist)), path);
        gtk_tree_path_free(path);
    }
}

static void onrefresh(GtkWidget* widget, gpointer data) {
    (void)widget; (void)data;
    loginfo("refreshing running games...");
    refreshprocesses();
    loginfo("refresh complete.");
}

static void onbrowse(GtkWidget* widget, gpointer data) {
    (void)data;
    GtkWidget* dialog = gtk_file_chooser_dialog_new(
        "Select DLL File", GTK_WINDOW(gwindow),
        GTK_FILE_CHOOSER_ACTION_OPEN,
        "Cancel", GTK_RESPONSE_CANCEL,
        "Open", GTK_RESPONSE_ACCEPT,
        NULL);
    GtkFileFilter* filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "Dynamic Link Libraries (*.dll)");
    gtk_file_filter_add_pattern(filter, "*.dll");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char* filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        gtk_entry_set_text(GTK_ENTRY(gdllentry), filename);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static void onselect(GtkTreeSelection* sel, gpointer data) {
    (void)data;
    GtkTreeModel* model;
    GtkTreeIter iter;
    if (!gtk_tree_selection_get_selected(sel, &model, &iter)) return;
    char* name = nullptr;
    char* exe = nullptr;
    char* appid = nullptr;
    char* pid = nullptr;
    gtk_tree_model_get(model, &iter, 0, &name, 1, &exe, 2, &appid, 3, &pid, -1);
    if (name) gtk_label_set_text(GTK_LABEL(gdetailname), name);
    if (exe) gtk_label_set_text(GTK_LABEL(gdetailexe), exe);
    if (appid) gtk_label_set_text(GTK_LABEL(gdetailappid), appid);
    if (pid) gtk_label_set_text(GTK_LABEL(gdetailpid), pid);
    if (pid) {
        for (const auto& r : grunning) {
            if (r.pid == pid) {
                gtk_label_set_text(GTK_LABEL(gdetailprefix), r.prefix.empty() ? "unknown" : r.prefix.c_str());
                break;
            }
        }
    }
    g_free(name); g_free(exe); g_free(appid); g_free(pid);
}

static void ondelaytoggled(GtkToggleButton* btn, gpointer data) {
    (void)data;
    gtk_widget_set_sensitive(gdelayspin, gtk_toggle_button_get_active(btn));
}

static void oninject(GtkWidget* widget, gpointer data) {
    (void)data;
    const char* dllpath = gtk_entry_get_text(GTK_ENTRY(gdllentry));
    if (!dllpath || !*dllpath) {
        logerror("please select a valid dll file first.");
        return;
    }

    GtkTreeSelection* sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(ggamelist));
    GtkTreeModel* model;
    GtkTreeIter iter;
    if (!gtk_tree_selection_get_selected(sel, &model, &iter)) {
        logerror("no target running game selected.");
        return;
    }

    char* pidstr = nullptr;
    gtk_tree_model_get(model, &iter, 3, &pidstr, -1);
    if (!pidstr) {
        logerror("no target running game selected.");
        return;
    }

    runningprocess target;
    for (const auto& r : grunning) {
        if (r.pid == pidstr) { target = r; break; }
    }
    g_free(pidstr);
    if (target.pid.empty()) {
        logerror("target process not found.");
        return;
    }

    const char* method = gtk_combo_box_get_active_id(GTK_COMBO_BOX(gmethodcombo));
    const char* routing = gtk_combo_box_get_active_id(GTK_COMBO_BOX(groutingcombo));
    const char* arch = gtk_combo_box_get_active_id(GTK_COMBO_BOX(garchcombo));
    bool erasepe = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gerasecheck));
    int delaysec = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gdelaycheck))
        ? (int)gtk_spin_button_get_value(GTK_SPIN_BUTTON(gdelayspin)) : 0;
    bool useprotontricks = (routing && strcmp(routing, "protontricks") == 0);

    std::string methodstr = method ? method : "loadlibrary";
    std::string archstr = arch ? arch : "auto";

    loginfo("starting " + methodstr + " injection into '" + target.exename + "' (appid: " + target.appid + ")...");
    loginfo("dll: " + std::string(dllpath));
    loginfo("prefix: " + target.prefix);
    loginfo("routing: " + std::string(useprotontricks ? "protontricks bridge" : "direct wine"));
    gtk_widget_set_sensitive(ginjectbtn, FALSE);

    std::thread([target, dllpath, methodstr, archstr, erasepe, useprotontricks, delaysec]() {
        if (delaysec > 0) sleep(delaysec);
        bool ok = runinjection(
            target.exename, dllpath, target.prefix, target.protondir,
            0, methodstr, useprotontricks, target.appid, erasepe, archstr);
        if (ok) {
            loginfo("injection completed successfully!");
        } else {
            logerror("injection failed. check log details above.");
        }
        g_idle_add([](gpointer data) -> gboolean {
            gtk_widget_set_sensitive(ginjectbtn, TRUE);
            return G_SOURCE_REMOVE;
        }, nullptr);
    }).detach();
}

static void onclearlog(GtkWidget* widget, gpointer data) {
    (void)widget; (void)data;
    gtk_text_buffer_set_text(glogbuffer, "", -1);
}

static const char* ktheme = R"(
window {
    background-color: #232629;
    color: #eff0f1;
    font-family: "Inter", "Segoe UI", "Noto Sans", sans-serif;
    font-size: 9pt;
}
button {
    background-color: #31363b;
    color: #eff0f1;
    border: 1px solid #4a4f54;
    border-radius: 3px;
    padding: 3px 12px;
    font-size: 9pt;
    min-height: 0;
}
button:hover {
    background-color: #3daee2;
    border-color: #3daee2;
    color: #ffffff;
}
button.suggested-action {
    background-color: #27ae60;
    color: #ffffff;
    border: 1px solid #27ae60;
    font-weight: 700;
    padding: 5px 18px;
}
button.suggested-action:hover {
    background-color: #2ecc71;
    border-color: #2ecc71;
}
entry {
    background-color: #1b1e20;
    color: #eff0f1;
    border: 1px solid #4a4f54;
    border-radius: 3px;
    padding: 3px 8px;
    font-size: 9pt;
    min-height: 0;
}
entry:focus {
    border-color: #3daee2;
}
combobox button {
    background-color: #31363b;
    color: #eff0f1;
    border: 1px solid #4a4f54;
    border-radius: 3px;
    padding: 3px 8px;
    min-height: 0;
}
combobox button:hover {
    background-color: #3daee2;
    border-color: #3daee2;
    color: #ffffff;
}
menu {
    background-color: #2b2f33;
    color: #eff0f1;
    border: 1px solid #4a4f54;
}
menuitem {
    padding: 4px 12px;
    font-size: 9pt;
}
menuitem:hover {
    background-color: #3daee2;
    color: #ffffff;
}
popover {
    background-color: #2b2f33;
    border: 1px solid #4a4f54;
}
spinbutton {
    background-color: #1b1e20;
    padding: 2px 4px;
    min-height: 0;
    font-size: 9pt;
}
treeview {
    background-color: #1b1e20;
    color: #eff0f1;
    border: none;
}
treeview:selected {
    background-color: #3daee2;
    color: #ffffff;
}
treeview header button {
    background-color: #31363b;
    border: none;
    border-bottom: 1px solid #3a3f44;
    color: #a0a4a8;
    font-weight: 600;
    padding: 3px 8px;
    font-size: 9pt;
}
textview text {
    background-color: #141618;
    color: #a0a4a8;
    font-family: "JetBrains Mono", "Fira Code", monospace;
    font-size: 8pt;
}
frame {
    border: 1px solid #3a3f44;
    border-radius: 3px;
    background-color: #2b2f33;
}
label.sectiontitle {
    font-size: 9pt;
    font-weight: 700;
    color: #3daee2;
}
label.status {
    font-weight: 600;
    color: #a0a4a8;
    font-size: 9pt;
}
label.detailname {
    font-size: 12pt;
    font-weight: 700;
    color: #eff0f1;
}
label.detailmeta {
    font-size: 8pt;
    color: #a0a4a8;
}
label.empty {
    font-size: 10pt;
    color: #6e7378;
}
label.optlabel {
    font-size: 9pt;
    color: #b8bcc0;
}
checkbutton label {
    font-size: 9pt;
}
)";

static GtkWidget* makesection(const char* title) {
    GtkWidget* frame = gtk_frame_new(NULL);
    GtkWidget* vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 6);
    GtkWidget* label = gtk_label_new(title);
    gtk_widget_set_name(label, "sectiontitle");
    gtk_label_set_xalign(GTK_LABEL(label), 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(frame), vbox);
    return frame;
}

static GtkWidget* buildtoolbar() {
    GtkWidget* toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(toolbar), 4);

    GtkWidget* refresh = gtk_button_new_with_label("Refresh");
    g_signal_connect(refresh, "clicked", G_CALLBACK(onrefresh), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), refresh, FALSE, FALSE, 0);

    GtkWidget* clear = gtk_button_new_with_label("Clear Log");
    g_signal_connect(clear, "clicked", G_CALLBACK(onclearlog), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), clear, FALSE, FALSE, 0);

    GtkWidget* methodlabel = gtk_label_new("Method:");
    gtk_widget_set_name(methodlabel, "optlabel");
    gtk_box_pack_start(GTK_BOX(toolbar), methodlabel, FALSE, FALSE, 0);
    gmethodcombo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(gmethodcombo), "loadlibrary", "LoadLibraryW");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(gmethodcombo), "hijack", "Thread Hijack");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(gmethodcombo), "manual", "Manual Mapping");
    gtk_combo_box_set_active(GTK_COMBO_BOX(gmethodcombo), 0);
    gtk_box_pack_start(GTK_BOX(toolbar), gmethodcombo, FALSE, FALSE, 0);

    GtkWidget* routinglabel = gtk_label_new("Routing:");
    gtk_widget_set_name(routinglabel, "optlabel");
    gtk_box_pack_start(GTK_BOX(toolbar), routinglabel, FALSE, FALSE, 0);
    groutingcombo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(groutingcombo), "protontricks", "Protontricks Bridge");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(groutingcombo), "direct", "Direct Wine");
    gtk_combo_box_set_active(GTK_COMBO_BOX(groutingcombo), 0);
    gtk_box_pack_start(GTK_BOX(toolbar), groutingcombo, FALSE, FALSE, 0);

    GtkWidget* archlabel = gtk_label_new("Arch:");
    gtk_widget_set_name(archlabel, "optlabel");
    gtk_box_pack_start(GTK_BOX(toolbar), archlabel, FALSE, FALSE, 0);
    garchcombo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(garchcombo), "auto", "Auto");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(garchcombo), "64", "64-bit");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(garchcombo), "32", "32-bit");
    gtk_combo_box_set_active(GTK_COMBO_BOX(garchcombo), 0);
    gtk_box_pack_start(GTK_BOX(toolbar), garchcombo, FALSE, FALSE, 0);

    gtk_box_pack_end(GTK_BOX(toolbar), gstatuslabel, FALSE, FALSE, 4);
    return toolbar;
}

static GtkWidget* buildgamelist() {
    GtkWidget* frame = gtk_frame_new(NULL);
    GtkWidget* vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(frame), vbox);

    ggamestore = gtk_list_store_new(4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    ggamelist = gtk_tree_view_new_with_model(GTK_TREE_MODEL(ggamestore));
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(ggamelist), TRUE);

    const char* titles[] = {"Game", "Executable", "AppID", "PID"};
    for (int i = 0; i < 4; i++) {
        GtkCellRenderer* renderer = gtk_cell_renderer_text_new();
        GtkTreeViewColumn* col = gtk_tree_view_column_new_with_attributes(titles[i], renderer, "text", i, NULL);
        gtk_tree_view_column_set_resizable(col, TRUE);
        gtk_tree_view_append_column(GTK_TREE_VIEW(ggamelist), col);
    }

    GtkTreeSelection* sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(ggamelist));
    g_signal_connect(sel, "changed", G_CALLBACK(onselect), NULL);

    GtkWidget* scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll), ggamelist);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);
    return frame;
}

static GtkWidget* builddetailpanel() {
    GtkWidget* frame = gtk_frame_new(NULL);
    GtkWidget* vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 3);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);

    gdetailname = gtk_label_new("");
    gtk_widget_set_name(gdetailname, "detailname");
    gtk_label_set_xalign(GTK_LABEL(gdetailname), 0);
    gtk_box_pack_start(GTK_BOX(vbox), gdetailname, FALSE, FALSE, 0);

    GtkWidget* meta = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gdetailexe = gtk_label_new("");
    gtk_widget_set_name(gdetailexe, "detailmeta");
    gtk_label_set_xalign(GTK_LABEL(gdetailexe), 0);
    gtk_box_pack_start(GTK_BOX(meta), gdetailexe, FALSE, FALSE, 0);
    gdetailappid = gtk_label_new("");
    gtk_widget_set_name(gdetailappid, "detailmeta");
    gtk_label_set_xalign(GTK_LABEL(gdetailappid), 0);
    gtk_box_pack_start(GTK_BOX(meta), gdetailappid, FALSE, FALSE, 0);
    gdetailpid = gtk_label_new("");
    gtk_widget_set_name(gdetailpid, "detailmeta");
    gtk_label_set_xalign(GTK_LABEL(gdetailpid), 0);
    gtk_box_pack_start(GTK_BOX(meta), gdetailpid, FALSE, FALSE, 0);
    gdetailprefix = gtk_label_new("");
    gtk_widget_set_name(gdetailprefix, "detailmeta");
    gtk_label_set_xalign(GTK_LABEL(gdetailprefix), 0);
    gtk_box_pack_start(GTK_BOX(meta), gdetailprefix, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), meta, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(frame), vbox);
    return frame;
}

static GtkWidget* buildactionpanel() {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(box), 6);

    ginjectbtn = gtk_button_new_with_label("Inject DLL");
    gtk_widget_set_name(ginjectbtn, "suggested-action");
    gtk_widget_set_size_request(ginjectbtn, -1, 32);
    g_signal_connect(ginjectbtn, "clicked", G_CALLBACK(oninject), NULL);
    gtk_box_pack_start(GTK_BOX(box), ginjectbtn, FALSE, FALSE, 0);

    GtkWidget* browsebtn = gtk_button_new_with_label("Browse DLL");
    g_signal_connect(browsebtn, "clicked", G_CALLBACK(onbrowse), NULL);
    gtk_box_pack_start(GTK_BOX(box), browsebtn, FALSE, FALSE, 0);

    return box;
}

static GtkWidget* buildlogpanel() {
    GtkWidget* frame = gtk_frame_new(NULL);
    GtkWidget* vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 3);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 6);

    GtkWidget* label = gtk_label_new("Console");
    gtk_widget_set_name(label, "sectiontitle");
    gtk_label_set_xalign(GTK_LABEL(label), 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    glogscroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(glogscroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(glogscroll, -1, 90);
    glogbuffer = gtk_text_buffer_new(NULL);

    gtk_text_buffer_create_tag(glogbuffer, "[error]", "foreground", "#da4453", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(glogbuffer, "[warn]", "foreground", "#f67400", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(glogbuffer, "[info]", "foreground", "#27ae60", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(glogbuffer, "[debug]", "foreground", "#3daee2", NULL);

    GtkWidget* logview = gtk_text_view_new_with_buffer(glogbuffer);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(logview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(logview), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(logview), GTK_WRAP_WORD_CHAR);
    gtk_container_add(GTK_CONTAINER(glogscroll), logview);
    gtk_box_pack_start(GTK_BOX(vbox), glogscroll, TRUE, TRUE, 0);

    gtk_container_add(GTK_CONTAINER(frame), vbox);
    return frame;
}

int run(int argc, char** argv) {
    gtk_init(&argc, &argv);

    GtkCssProvider* provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(provider, ktheme, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    gwindow = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(gwindow), "ProtonDLL");
    gtk_window_set_default_size(GTK_WINDOW(gwindow), 780, 480);
    gtk_window_set_position(GTK_WINDOW(gwindow), GTK_WIN_POS_CENTER);
    g_signal_connect(gwindow, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    gtk_window_set_icon_name(GTK_WINDOW(gwindow), "protondll");
    {
        const char* appdir = std::getenv("APPDIR");
        std::vector<std::string> iconpaths;
        if (appdir) {
            iconpaths.push_back(std::string(appdir) + "/usr/share/icons/hicolor/256x256/apps/protondll.png");
        }
        iconpaths.push_back("packaging/protondll.png");
        iconpaths.push_back("/usr/share/icons/hicolor/256x256/apps/protondll.png");
        for (const auto& p : iconpaths) {
            if (g_file_test(p.c_str(), G_FILE_TEST_EXISTS)) {
                gtk_window_set_icon_from_file(GTK_WINDOW(gwindow), p.c_str(), NULL);
                break;
            }
        }
    }

    gstatuslabel = gtk_label_new("checking...");
    gtk_widget_set_name(gstatuslabel, "status");

    GtkWidget* mainvbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(mainvbox), 6);
    gtk_container_add(GTK_CONTAINER(gwindow), mainvbox);

    gtk_box_pack_start(GTK_BOX(mainvbox), buildtoolbar(), FALSE, FALSE, 0);

    GtkWidget* contenthbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(mainvbox), contenthbox, TRUE, TRUE, 0);

    GtkWidget* leftvbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_box_pack_start(GTK_BOX(contenthbox), leftvbox, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(leftvbox), buildgamelist(), TRUE, TRUE, 0);

    gemptylabel = gtk_label_new("no running games detected.\nstart a proton game, then click refresh.");
    gtk_widget_set_name(gemptylabel, "empty");
    gtk_box_pack_start(GTK_BOX(leftvbox), gemptylabel, FALSE, FALSE, 0);

    GtkWidget* dllrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gdllentry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(gdllentry), "select or enter path to .dll file...");
    gtk_box_pack_start(GTK_BOX(dllrow), gdllentry, TRUE, TRUE, 0);
    GtkWidget* browsebtn = gtk_button_new_with_label("Browse");
    g_signal_connect(browsebtn, "clicked", G_CALLBACK(onbrowse), NULL);
    gtk_box_pack_start(GTK_BOX(dllrow), browsebtn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(leftvbox), dllrow, FALSE, FALSE, 0);

    GtkWidget* optrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gerasecheck = gtk_check_button_new_with_label("Wipe PE Headers");
    gtk_box_pack_start(GTK_BOX(optrow), gerasecheck, FALSE, FALSE, 0);
    gcopycheck = gtk_check_button_new_with_label("Copy to Game Dir");
    gtk_box_pack_start(GTK_BOX(optrow), gcopycheck, FALSE, FALSE, 0);
    gdelaycheck = gtk_check_button_new_with_label("Delay:");
    gtk_box_pack_start(GTK_BOX(optrow), gdelaycheck, FALSE, FALSE, 0);
    gdelayspin = gtk_spin_button_new_with_range(0, 60, 1);
    gtk_widget_set_sensitive(gdelayspin, FALSE);
    gtk_box_pack_start(GTK_BOX(optrow), gdelayspin, FALSE, FALSE, 0);
    g_signal_connect(gdelaycheck, "toggled", G_CALLBACK(ondelaytoggled), NULL);
    gtk_box_pack_start(GTK_BOX(leftvbox), optrow, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(leftvbox), buildlogpanel(), FALSE, FALSE, 0);

    GtkWidget* sep = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
    gtk_box_pack_start(GTK_BOX(contenthbox), sep, FALSE, FALSE, 0);

    gactionpanel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_pack_start(GTK_BOX(contenthbox), gactionpanel, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(gactionpanel), builddetailpanel(), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(gactionpanel), buildactionpanel(), FALSE, FALSE, 0);

    gtk_widget_show_all(gwindow);
    refreshprocesses();

    gtk_main();
    return 0;
}

}
