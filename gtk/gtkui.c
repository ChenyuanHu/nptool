#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include "gtkui.h"

struct gtkui_toolbar {
	GtkWidget *wid;
	GtkToolItem *start;
	GtkToolItem *stop;
};

enum {
	PKTL_NO = 0,
	PKTL_TIME,
	PKTL_SOURCE,
	PKTL_DESTINATION,
	PKTL_PROTOCOL,
	PKTL_LENGTH,
	PKTL_CAPLENGTH,
	PKTL_INFO,
	PKTL_TREE_POINT, /* hide point, use to point to analysetree */
	PKTL_DATA_POINT, /* hide data point, use to point to pktbuf */
	PKTL_COLUMNS
};
#define PKTL_TYPE_LIST \
			G_TYPE_INT, \
			G_TYPE_STRING, \
			G_TYPE_STRING, \
			G_TYPE_STRING, \
			G_TYPE_STRING, \
			G_TYPE_INT, \
			G_TYPE_INT, \
			G_TYPE_STRING, \
			G_TYPE_ULONG, \
			G_TYPE_ULONG

char *pktl_field[] = {
	"No",
	"Time",
	"Source",
	"Destination",
	"Protocol",
	"Length",
	".CapLength",
	"Info",
	".tree-point", /* hide point, use to point to analysetree */
	".data-point", /* hide data point, use to point to pktbuf */
	NULL,
};

struct gtkui_pktlist {
	GtkWidget *wid;
	GtkListStore *store;
	GtkTreeIter *iter;
	GtkTreeSelection *sel;
};
struct gtkui_analytree {
	GtkWidget *wid;
	GtkTreeStore *store;
};
struct gtkui_main_win{
	GtkWidget *window;

	struct gtkui_toolbar *toolbar;

	struct gtkui_pktlist *pktlist;

	struct gtkui_analytree *analytree;

	GtkWidget *byteview;

	GtkWidget *statusbar;

	GtkWidget *vbox;
	GtkWidget *vpaned1;
	GtkWidget *vpaned2;
	GtkWidget *scroll_pkt;
	GtkWidget *scroll_tree;
	GtkWidget *scroll_byte;

};


static struct interface_list *itfc_list;

static pthread_cond_t start_cap_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t start_cap_mutex = PTHREAD_MUTEX_INITIALIZER;
static int start_cap;
static char *cap_ifname;

static void (*exitfun)(void) = NULL;
static void (*stopfun)(void) = NULL;

static struct gtkui_main_win *main_win;

void gui_set_interface_list(struct interface_list *list)
{
	itfc_list = list;
}

static void bar_stop_clicked(GtkWidget *widget, gpointer *arg)
{
	pthread_mutex_lock(&start_cap_mutex);
	start_cap = 0;
	pthread_mutex_unlock(&start_cap_mutex);
	gtk_widget_set_sensitive(GTK_WIDGET(main_win->toolbar->start), TRUE);
	gtk_widget_set_sensitive(widget, FALSE);

	stopfun();
}
static void bar_start_clicked(GtkWidget *widget, gpointer *arg)
{
	GtkWidget *dialog;
	GtkWidget *label;
	GtkWidget *combo;
	gchar *ifname;

	struct interface_list *if_list = itfc_list;

	gint result;
	
	dialog = gtk_dialog_new_with_buttons("Select port to listen in.\n", NULL,
			GTK_DIALOG_MODAL,
			GTK_STOCK_OK, GTK_RESPONSE_OK,
			GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
			NULL);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
	gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);

	label = gtk_label_new("Select net port:");

	combo = gtk_combo_box_new_text();

	while (if_list) {
		gtk_combo_box_append_text(GTK_COMBO_BOX(combo), if_list->name);
		if_list = if_list->next;
	}

	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), label, FALSE, FALSE, 5);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), combo, FALSE, FALSE, 5);

	gtk_widget_show_all(dialog);

	result = gtk_dialog_run(GTK_DIALOG(dialog));

	if (result == GTK_RESPONSE_OK) {
		ifname = gtk_combo_box_get_active_text(GTK_COMBO_BOX(combo));
		if (ifname != NULL) {
			gtk_widget_set_sensitive(widget, FALSE);
			gtk_widget_set_sensitive(GTK_WIDGET(main_win->toolbar->stop), TRUE);

			pthread_mutex_lock(&start_cap_mutex);
			start_cap = 1;
			cap_ifname = ifname;
			pthread_cond_signal(&start_cap_cond);
			pthread_mutex_unlock(&start_cap_mutex);

			g_print("dev name: %s\n", ifname);
		}
	}
	gtk_widget_destroy(dialog);
}
static void gtkui_exit()
{
	printf("exit gui\n");
	if (exitfun != NULL)
		exitfun();
	gtk_main_quit();
}

static GtkWidget* creat_main_window()
{
	GtkWidget *window;
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

	gtk_window_set_title(GTK_WINDOW(window), "NPTool");

	g_signal_connect_swapped(G_OBJECT(window), "destroy",
			G_CALLBACK(gtkui_exit), G_OBJECT(window));

	return window;
}
static struct gtkui_toolbar* build_toolbar()
{
	struct gtkui_toolbar *toolbar;

	toolbar = g_malloc(sizeof(*toolbar));
	if (toolbar == NULL)
		return NULL;

	toolbar->wid = gtk_toolbar_new();
	gtk_toolbar_set_style(GTK_TOOLBAR(toolbar->wid), GTK_TOOLBAR_ICONS);

	toolbar->start = gtk_tool_button_new_from_stock(GTK_STOCK_MEDIA_PLAY);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar->wid), toolbar->start, -1);

	toolbar->stop = gtk_tool_button_new_from_stock(GTK_STOCK_MEDIA_STOP);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar->wid), toolbar->stop, -1);
	gtk_widget_set_sensitive(GTK_WIDGET(toolbar->stop), FALSE);

	g_signal_connect(G_OBJECT(toolbar->start), "clicked",
			G_CALLBACK(bar_start_clicked), NULL);

	g_signal_connect(G_OBJECT(toolbar->stop), "clicked",
			G_CALLBACK(bar_stop_clicked), NULL);
	return toolbar;
}
static int byte_data_to_string(unsigned char *data, char *strdata, int caplen, int strlen, int len)
{
	int i;
	int l;
	l = 0;
	char buf[20];
	strdata[0] = '\0';
	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			l += snprintf(strdata + l, strlen - l, "%.4d    ", i);
			bzero(buf, 20);
		}

		if (i < caplen) {
			l += snprintf(strdata + l, strlen - l, "%.2x ", data[i]);
			buf[i % 16] = data[i] < 127 ? (data[i] > 31 ? data[i] : '.') : '.';
		} else {
			l += snprintf(strdata + l, strlen - l, "** ");
		}

		if (i % 16 == 15)
			l += snprintf(strdata + l, strlen - l, "    %s\n", buf);
	}
	i--;
	if (i % 16 != 15) {
		while(i++ % 16 != 15)
			l += snprintf(strdata + l, strlen - l, "   ");
		l += snprintf(strdata + l, strlen - l, "    %s\n", buf);
	}
	return l;
}
static void update_byteview(GtkWidget *widget, gpointer arg)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTextBuffer *buffer;
	unsigned char *data;
	char *strdata;
	int len;
	int caplen;
	int strlen;

	if (gtk_tree_selection_get_selected(GTK_TREE_SELECTION(widget),
			&model, &iter)) {
		gtk_tree_model_get(model, &iter, 
				PKTL_LENGTH, &len,
				PKTL_CAPLENGTH, &caplen,
				PKTL_DATA_POINT, &data,
				-1);

		strlen = ((len / 16) + 1) * (4 * 16 + 30);
		strdata = g_malloc(strlen);
		if (strdata == NULL) {
			g_print("on_changed malloc err\n");
			return;
		}

		strlen = byte_data_to_string(data, strdata, caplen, strlen, len);

		buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(main_win->byteview));
		gtk_text_buffer_set_text(buffer, strdata, strlen);

		g_free(strdata);
	}
}
static void add_to_gtk_tree(GtkTreeStore *store, GtkTreeIter *parent, 
		struct pkt_analytree *tree)
{
	GtkTreeIter iter;

	/*g_print("-------------\n");
	g_print("parent iter %p\n", parent);
	g_print("tree %p\n", tree);
	g_print("iter %p\n", &iter);
	*/

	if (tree == NULL) {
		/* g_print("-------------\n"); */
		return;
	}

	/*g_print("comment %s\n", tree->comment);
	g_print("child %p\n", tree->child);
	g_print("next %p\n", tree->next);
	g_print("-------------\n");
	*/

	gtk_tree_store_append(store, &iter, parent);
	gtk_tree_store_set(store, &iter, 0, tree->comment, -1);

	add_to_gtk_tree(store, &iter, tree->child);
	add_to_gtk_tree(store, parent, tree->next);
}
static void update_analyse_tree(GtkWidget *widget, gpointer arg)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	struct pkt_analytree *analytree;

	if (gtk_tree_selection_get_selected(
			GTK_TREE_SELECTION(widget),
			&model, &iter)) {
		gtk_tree_model_get(model, &iter, 
				PKTL_TREE_POINT, &analytree,
				-1);

		gtk_tree_store_clear(main_win->analytree->store);
		add_to_gtk_tree(main_win->analytree->store, NULL, analytree);
	}
}
static void pktlist_changed(GtkWidget *widget, gpointer arg)
{
	/* updata byte_view */
	update_byteview(widget, arg);

	/* updata analyse tree */
	update_analyse_tree(widget, arg);
}
static struct gtkui_pktlist* build_pktlist()
{
	struct gtkui_pktlist *pktlist;
	GtkWidget *pktwid;
	GtkListStore *store;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *col;
	GtkTreeIter *iter;
	GtkTreeSelection *sel;
	PangoFontDescription *font_desc;
	gchar *fontname = "DejaVu Sans Mono 10";
	int i;

	pktlist = g_malloc(sizeof(*pktlist));
	if (pktlist == NULL)
		return NULL;
	iter = g_malloc(sizeof(*iter));
	if (iter == NULL)
		return NULL;
	bzero(iter, sizeof(*iter));

	pktwid = gtk_tree_view_new();

	font_desc = pango_font_description_from_string(fontname);
	gtk_widget_modify_font(GTK_WIDGET(pktwid), font_desc);

	for (i = 0; i < PKTL_COLUMNS; i++) {
		renderer = gtk_cell_renderer_text_new();
		col = gtk_tree_view_column_new_with_attributes
				(pktl_field[i], renderer, "text", i, NULL);

		gtk_tree_view_column_set_resizable(col, TRUE);
		gtk_tree_view_column_set_clickable(col, TRUE);
		if (pktl_field[i][0] == '.')
			gtk_tree_view_column_set_visible(col, FALSE);
		else
			gtk_tree_view_column_set_visible(col, TRUE);
		//gtk_tree_view_column_set_sizing(col, GTK_TREE_VIEW_COLUMN_FIXED);
		gtk_tree_view_append_column(GTK_TREE_VIEW(pktwid), col);
	}

	store = gtk_list_store_new(PKTL_COLUMNS, PKTL_TYPE_LIST);

	gtk_tree_view_set_model(GTK_TREE_VIEW(pktwid), GTK_TREE_MODEL(store));

	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(pktwid));

	g_signal_connect(sel, "changed",
			G_CALLBACK(pktlist_changed), NULL);

	pktlist->wid = pktwid;
	pktlist->store = store;
	pktlist->iter = iter;
	pktlist->sel = sel;
	return pktlist;
}

static struct gtkui_analytree* build_analytree()
{
	struct gtkui_analytree *analytree;

	GtkWidget *wid;
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkTreeStore *store;
	
	analytree = g_malloc(sizeof(*analytree));
	if (analytree == NULL)
		return NULL;

	wid = gtk_tree_view_new();

	col = gtk_tree_view_column_new();
	gtk_tree_view_column_set_title(col, "protocol analyse");
	gtk_tree_view_append_column(GTK_TREE_VIEW(wid), col);
	gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(wid), FALSE);

	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, 
			"text", 0);

	store = gtk_tree_store_new(1, G_TYPE_STRING);

	gtk_tree_view_set_model(GTK_TREE_VIEW(wid), GTK_TREE_MODEL(store));
	
	analytree->wid = wid;
	analytree->store = store;
	return analytree;
}
static GtkWidget* build_byteview()
{
	GtkWidget *byteview;
	PangoFontDescription *font_desc;
	gchar *fontname = "DejaVu Sans Mono 10";

	byteview = gtk_text_view_new();

	font_desc = pango_font_description_from_string(fontname);

	gtk_widget_modify_font(GTK_WIDGET(byteview), font_desc);

	gtk_text_view_set_editable(GTK_TEXT_VIEW(byteview), FALSE);

	return byteview;
}
static GtkWidget* build_statusbar()
{
	GtkWidget *statusbar;
	statusbar = gtk_statusbar_new();
	return statusbar;
}
static void main_window_layout(struct gtkui_main_win *main_window)
{
	GtkWidget *scroll_pkt;
	GtkWidget *scroll_tree;
	GtkWidget *scroll_byte;
	GtkWidget *vbox;
	GtkWidget *vpaned1;
	GtkWidget *vpaned2;
	GtkWidget *window;

	window = main_window->window;
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
	gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
	gtk_container_set_border_width(GTK_CONTAINER(window), 3);

	vbox = gtk_vbox_new(FALSE, 0);
	vpaned1 = gtk_vpaned_new();
	vpaned2 = gtk_vpaned_new();

	scroll_pkt = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_pkt),
			GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

	scroll_tree = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_tree),
			GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

	scroll_byte = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_byte),
			GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

	gtk_container_add(GTK_CONTAINER(scroll_pkt), main_window->pktlist->wid);
	gtk_container_add(GTK_CONTAINER(scroll_tree), main_window->analytree->wid);
	gtk_container_add(GTK_CONTAINER(scroll_byte), main_window->byteview);

	gtk_paned_add1(GTK_PANED(vpaned1), scroll_pkt);
	gtk_paned_add2(GTK_PANED(vpaned1), scroll_tree);
	gtk_paned_add1(GTK_PANED(vpaned2), vpaned1);
	gtk_paned_add2(GTK_PANED(vpaned2), scroll_byte);

	gtk_paned_set_position(GTK_PANED(vpaned1), 250);
	gtk_paned_set_position(GTK_PANED(vpaned2), 400);

	gtk_box_pack_start(GTK_BOX(vbox), main_window->toolbar->wid, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), vpaned2, TRUE, TRUE, 3);
	gtk_box_pack_start(GTK_BOX(vbox), main_window->statusbar, FALSE, TRUE, 0);

	gtk_container_add(GTK_CONTAINER(main_window->window), vbox);

	main_window->scroll_pkt = scroll_pkt;
	main_window->scroll_tree = scroll_tree;
	main_window->scroll_byte = scroll_byte;
	main_window->vbox = vbox;
	main_window->vpaned1 = vpaned1;
	main_window->vpaned2 = vpaned2;
}
static struct gtkui_main_win* build_main_window()
{
	struct gtkui_main_win* main_window = g_malloc(sizeof(*main_window));

	if (main_window == NULL)
		return NULL;
	
	bzero(main_window, sizeof(*main_window));

	main_window->window = creat_main_window(GTK_WINDOW_TOPLEVEL);

	main_window->toolbar = build_toolbar();
	main_window->pktlist = build_pktlist();

	main_window->analytree = build_analytree();

	main_window->byteview = build_byteview();

	main_window->statusbar = build_statusbar();

	main_window_layout(main_window);

	gtk_widget_show_all(main_window->window);

	return main_window;
}

static void *gtk_main_pthread(void *arg)
{
	if(!g_thread_supported()) 
		g_thread_init(NULL);  
	gdk_threads_init();  

	gdk_threads_enter();  
	gtk_main ();  
	gdk_threads_leave();

	return (void *)0;
}
pthread_t gui_pthread_start(int *argc, char ***argv)
{
	pthread_t pid;

	start_cap = 0;

	gtk_init(argc, argv);

	main_win = build_main_window();

	if (main_win == NULL) {
		fprintf(stderr, "build_main_window() err\n");
		exit(1);
	}
 
	pid = pthread_create(&pid, NULL, gtk_main_pthread, NULL);
	return pid;
}

int gui_wait_capture(char *if_name)
{
	pthread_mutex_lock(&start_cap_mutex);
	while (start_cap == 0) {
		pthread_cond_wait(&start_cap_cond, &start_cap_mutex);
	}
	strncpy(if_name, cap_ifname, 100);
	pthread_mutex_unlock(&start_cap_mutex);
	return 0;
}

int gui_add_packet(struct pkt_summary *summary, struct pkt_analytree *analytree, 
		unsigned char *data)
{
	GtkListStore *store;
	GtkTreeIter *iter;

	store = main_win->pktlist->store;
	iter = main_win->pktlist->iter;

	gdk_threads_enter();  
	gtk_list_store_append(store, iter);
	gtk_list_store_set(store, iter,
			PKTL_NO, summary->no,
			PKTL_TIME, summary->time,
			PKTL_SOURCE, summary->src,
			PKTL_DESTINATION, summary->dst,
			PKTL_PROTOCOL, summary->proto,
			PKTL_LENGTH, summary->len,
			PKTL_CAPLENGTH, summary->caplen,
			PKTL_INFO, summary->info,
			PKTL_TREE_POINT, (unsigned long)analytree,
			PKTL_DATA_POINT, (unsigned long)data,
			-1);
	gdk_threads_leave();  

	free(summary);
	return 0;
}
void gui_register_exit(void (*fun)(void))
{
	exitfun = fun;
}

void gui_register_stop(void (*fun)(void))
{
	stopfun = fun;
}
