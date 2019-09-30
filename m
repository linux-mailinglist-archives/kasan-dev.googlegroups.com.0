Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBKXKY7WAKGQEC5OFN3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 9588BC2098
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 14:29:30 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id t11sf4448061wrq.19
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 05:29:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569846570; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ksjvpn5boLTQOcEICpHe7RXoKZFm/WH8OKSw5RSkDVdLgROYir4qO/bRmwKvne03Vu
         2r+2CVZNCGwxzH28jFe/YpY+w7zffZSd+0HbhpH8klP9E9Hd/3CBqXnm6tqfUPkjDiZM
         yyZQIJlexyIbrgn6I0rRvJJMYkH2sLJ6XQRBpLlcXgu44ge8570lfGO95LMCZESzDM+G
         m46XkDHyBjHD+oyKw3g3ongO3KsjqV70T7Hn1MIrCmy5TapUjgTu6X9Z6E6v50U8lPXv
         PNXg5fGyiWU0MZAVTEYJuc6NqAMOLkL7FrTlX6kSXEHmYgpZ6DjPxhTwpizk+b5NrrNj
         7nAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GdEICrP8LnJ6Sky6lnn9hnFgZIUxj1oSkem8W6ljThA=;
        b=GRO9XDHllZXa3+NADvlyoogFctCFIEdR3uvzglrjcnw65kqeFCFpPgKgVWHvw7oSnJ
         6G2TxgbNomnlbqczMfIKFX5pbmy9OgB1EGLxwalop/7KWkGO7bvk+OtxOyNr9163cq0d
         8gleQ3Ebfjtoi/Nzsv8QomnpiTuBDAMCrdEGLA0SL7XksoFZ9m0oD+PleLwCKnDOXOk5
         2qxmVvrGeF+Ktup3shI45xWAjmOLevGR+IjOptMAG3mytu2uC1+f2soJ9HJMlgYFI090
         AD05tHNBvQjMxBbsMUeS+vTCr/++cPyWrldjB4PFUmC0osjpHPBCaGITd2ETCWB+BS1H
         D0yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GdEICrP8LnJ6Sky6lnn9hnFgZIUxj1oSkem8W6ljThA=;
        b=HNNpyIfq1XLs2G+MesIVll3q3t90gKN2My5i38X+XXTclE6w+ZoC3+5zFzQ7ouFpa4
         PnqX06jPjfPA9A8xy8SCzxrVoldgNnkHYzqNIWkrsUGTsTOxbvBWnF0bDyvDBz/9QEc0
         d5AuhetNAYOFGmjPnAMdWj9kWJZnUyiueNOukORLcBQiK/VihaVDiofLLB0SUiHxJDzc
         HGyo9qF0w27Vw6wAJb75aU7hzi47d8+W6bLpyvfxBIotC7bCNYIa5hDunWbSLJ2QDb6j
         r9L1mIIwnOZlgzuQbNYWq8dlQ4kroJ0pGafJMFyXkHhndIMHOt8kuFfWQphq8lIsO678
         HDyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GdEICrP8LnJ6Sky6lnn9hnFgZIUxj1oSkem8W6ljThA=;
        b=klCso/0uU6TzNVRO2yhsoGUJ4+K9c+6C57+WUescvpPUmG8a4PiM2kPYDNXnxk+vEx
         DMg1KOj2Y9hsm5vjbELGvnryVj3lY6E3Z6MFFwWUsoQDKz5PvKeTFv6QuO151HWw+1Rw
         XSfY9JnY9rs56MqEv3DcxZs8MEKDwhuyogJIX6SFgwcY4g9RrXolt5BSV3XHm+YMJcjD
         NINHar1yhHuq2EkbClfnhzWtswr1y/4P9qkATkFV/gIUdHe4VCattMx+2313E0A3F4n0
         RQ6WsalSx47PsFDrtabfhJrGukgzB18pwtUo9rx8bA5bboMav3IhtTq3ry0Wz+Vqy2QY
         QfBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVPjeImIADvS3LxiC0z7GiHTgL9F3kwMfhzWfJJQlvy0YB4keZY
	3P7dne0wBBs4ZqoL6FVlSZU=
X-Google-Smtp-Source: APXvYqyPY8m2Cb6w1JmoGRTuN/9Dl32izb42b0BeBT5sQZRO6JckEBzvo/qPQb/9jlduzx/BzaAa6g==
X-Received: by 2002:adf:e689:: with SMTP id r9mr10885577wrm.62.1569846570243;
        Mon, 30 Sep 2019 05:29:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9dc8:: with SMTP id g191ls4997590wme.2.gmail; Mon, 30
 Sep 2019 05:29:29 -0700 (PDT)
X-Received: by 2002:a05:600c:351:: with SMTP id u17mr18023269wmd.130.1569846569684;
        Mon, 30 Sep 2019 05:29:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569846569; cv=none;
        d=google.com; s=arc-20160816;
        b=KKdzYZv3ZgJRTG6ljH6pT9OWP33s5VYIcD+ex+He8l5pZ4EJ8zVCTDo16gkKhxb+TC
         tUaKn3IwPz5j1CHSMgXM1lB+EAAVae6jrMIDk0CPrJRN6+dnNJlkgV6pchQsavkhaRz0
         +Am1khvEi4TS5Ge/0HqNkVuiDxj2T1yHlctx/5KSUBsBwJWEKxupCGVONkFSa1BJKhmC
         PpKu7MZUBAbJaosEVKR6mDKyV2f0Kfl60Z39dMXGCcGi4/Uzr1el1zX19bN6Ank8gJ/q
         jh0GztKnSmXMdR+9CtF0OByDuJoIR743Cg6LuTGLWK13zrfDS9G8Paj0rOSXERkRpMe0
         ySpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=kddbPPdJRegd0pa61SWThDroVjTIoKL5OGlsCWUwpIU=;
        b=Yv9TYpJ0iOD3L7kB0fLIDtpQYnoxyzOdz+7gRQK7fvxQMDXJgSKOteJBOpjqL6nmCC
         UtAdR32hO7nQijfsY+AmBkT0bZPnrAiL8NGpsMKYJrVDcH1YdeWl1N2jc//k7KgV4z+W
         9zqrswh2kYTN9xbzljo8MohZJjMy3+J45A/nW7FJqeaq7q17rzO02J2eQ4QMhkluIJtr
         CGdrdHA2vLIw80GlZFD7GDoywd7waD9/vAMYJMXd8XGbtfHQiydJahyfOEWVXxpZNSlG
         WjSVZiuO3YVHKM+bEa/RWNCo9Cd0EWNsvhggn4jAyp62ifAaMWap9IujvNi7YMU+144S
         KO4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id s65si844306wme.2.2019.09.30.05.29.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Sep 2019 05:29:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id E8F02AFE8;
	Mon, 30 Sep 2019 12:29:28 +0000 (UTC)
From: Vlastimil Babka <vbabka@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Qian Cai <cai@lca.pw>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Matthew Wilcox <willy@infradead.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Michal Hocko <mhocko@kernel.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Dmitry Vyukov <dvyukov@google.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace from debug_pagealloc
Date: Mon, 30 Sep 2019 14:29:15 +0200
Message-Id: <20190930122916.14969-3-vbabka@suse.cz>
X-Mailer: git-send-email 2.23.0
In-Reply-To: <20190930122916.14969-1-vbabka@suse.cz>
References: <20190930122916.14969-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

The commit 8974558f49a6 ("mm, page_owner, debug_pagealloc: save and dump
freeing stack trace") enhanced page_owner to also store freeing stack trace,
when debug_pagealloc is also enabled. KASAN would also like to do this [1] to
improve error reports to debug e.g. UAF issues. Kirill has suggested that the
freeing stack trace saving should be also possible to be enabled separately.

This patch therefore introduces a new kernel parameter page_owner_free to
enable the functionality in addition to the existing page_owner parameter.
The free stack saving is thus enabled in these cases:
1) booting with page_owner=on and debug_pagealloc=on
2) booting a KASAN kernel with page_owner=on
3) booting with page_owner=on and page_owner_free=on

To minimize runtime CPU and memory overhead when not boot-time enabled, the
patch introduces a new static key and struct page_ext_operations.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=203967

Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Suggested-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Suggested-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 .../admin-guide/kernel-parameters.txt         |  8 ++
 Documentation/dev-tools/kasan.rst             |  3 +
 include/linux/page_owner.h                    |  1 +
 mm/page_ext.c                                 |  1 +
 mm/page_owner.c                               | 90 +++++++++++++------
 5 files changed, 78 insertions(+), 25 deletions(-)

diff --git a/Documentation/admin-guide/kernel-parameters.txt b/Documentation/admin-guide/kernel-parameters.txt
index 944e03e29f65..14dcb66e3457 100644
--- a/Documentation/admin-guide/kernel-parameters.txt
+++ b/Documentation/admin-guide/kernel-parameters.txt
@@ -3237,6 +3237,14 @@
 			we can turn it on.
 			on: enable the feature
 
+	page_owner_free=
+			[KNL] When enabled together with page_owner, store also
+			the stack of who frees a page, for error page dump
+			purposes. This is also implicitly enabled by
+			debug_pagealloc=on or KASAN, so only page_owner=on is
+			sufficient in those cases.
+			on: enable the feature
+
 	page_poison=	[KNL] Boot-time parameter changing the state of
 			poisoning on the buddy allocator, available with
 			CONFIG_PAGE_POISONING=y.
diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index b72d07d70239..525296121d89 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -41,6 +41,9 @@ smaller binary while the latter is 1.1 - 2 times faster.
 Both KASAN modes work with both SLUB and SLAB memory allocators.
 For better bug detection and nicer reporting, enable CONFIG_STACKTRACE.
 
+To augment reports with last allocation and freeing stack of the physical page,
+it is recommended to enable also CONFIG_PAGE_OWNER and boot with page_owner=on.
+
 To disable instrumentation for specific files or directories, add a line
 similar to the following to the respective kernel Makefile:
 
diff --git a/include/linux/page_owner.h b/include/linux/page_owner.h
index 8679ccd722e8..0888dd70cc61 100644
--- a/include/linux/page_owner.h
+++ b/include/linux/page_owner.h
@@ -7,6 +7,7 @@
 #ifdef CONFIG_PAGE_OWNER
 extern struct static_key_false page_owner_inited;
 extern struct page_ext_operations page_owner_ops;
+extern struct page_ext_operations page_owner_free_ops;
 
 extern void __reset_page_owner(struct page *page, unsigned int order);
 extern void __set_page_owner(struct page *page,
diff --git a/mm/page_ext.c b/mm/page_ext.c
index 4ade843ff588..5724b637939a 100644
--- a/mm/page_ext.c
+++ b/mm/page_ext.c
@@ -61,6 +61,7 @@
 static struct page_ext_operations *page_ext_ops[] = {
 #ifdef CONFIG_PAGE_OWNER
 	&page_owner_ops,
+	&page_owner_free_ops,
 #endif
 #if defined(CONFIG_IDLE_PAGE_TRACKING) && !defined(CONFIG_64BIT)
 	&page_idle_ops,
diff --git a/mm/page_owner.c b/mm/page_owner.c
index d3cf5d336ccf..a668a735b9b6 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -24,13 +24,16 @@ struct page_owner {
 	short last_migrate_reason;
 	gfp_t gfp_mask;
 	depot_stack_handle_t handle;
-#ifdef CONFIG_DEBUG_PAGEALLOC
+};
+
+struct page_owner_free {
 	depot_stack_handle_t free_handle;
-#endif
 };
 
-static bool page_owner_disabled = true;
+static bool page_owner_enabled = false;
+static bool page_owner_free_enabled = false;
 DEFINE_STATIC_KEY_FALSE(page_owner_inited);
+static DEFINE_STATIC_KEY_FALSE(page_owner_free_stack);
 
 static depot_stack_handle_t dummy_handle;
 static depot_stack_handle_t failure_handle;
@@ -44,7 +47,7 @@ static int __init early_page_owner_param(char *buf)
 		return -EINVAL;
 
 	if (strcmp(buf, "on") == 0)
-		page_owner_disabled = false;
+		page_owner_enabled = true;
 
 	return 0;
 }
@@ -52,10 +55,30 @@ early_param("page_owner", early_page_owner_param);
 
 static bool need_page_owner(void)
 {
-	if (page_owner_disabled)
+	return page_owner_enabled;
+}
+
+static int __init early_page_owner_free_param(char *buf)
+{
+	if (!buf)
+		return -EINVAL;
+
+	if (strcmp(buf, "on") == 0)
+		page_owner_free_enabled = true;
+
+	return 0;
+}
+early_param("page_owner_free", early_page_owner_free_param);
+
+static bool need_page_owner_free(void) {
+
+	if (!page_owner_enabled)
 		return false;
 
-	return true;
+	if (IS_ENABLED(CONFIG_KASAN) || debug_pagealloc_enabled())
+		page_owner_free_enabled = true;
+
+	return page_owner_free_enabled;
 }
 
 static __always_inline depot_stack_handle_t create_dummy_stack(void)
@@ -84,7 +107,7 @@ static noinline void register_early_stack(void)
 
 static void init_page_owner(void)
 {
-	if (page_owner_disabled)
+	if (!page_owner_enabled)
 		return;
 
 	register_dummy_stack();
@@ -94,17 +117,36 @@ static void init_page_owner(void)
 	init_early_allocated_pages();
 }
 
+static void init_page_owner_free(void)
+{
+	if (!page_owner_enabled || !page_owner_free_enabled)
+		return;
+
+	static_branch_enable(&page_owner_free_stack);
+}
+
 struct page_ext_operations page_owner_ops = {
 	.size = sizeof(struct page_owner),
 	.need = need_page_owner,
 	.init = init_page_owner,
 };
 
+struct page_ext_operations page_owner_free_ops = {
+	.size = sizeof(struct page_owner_free),
+	.need = need_page_owner_free,
+	.init = init_page_owner_free,
+};
+
 static inline struct page_owner *get_page_owner(struct page_ext *page_ext)
 {
 	return (void *)page_ext + page_owner_ops.offset;
 }
 
+static inline struct page_owner_free *get_page_owner_free(struct page_ext *page_ext)
+{
+	return (void *)page_ext + page_owner_free_ops.offset;
+}
+
 static inline bool check_recursive_alloc(unsigned long *entries,
 					 unsigned int nr_entries,
 					 unsigned long ip)
@@ -148,25 +190,21 @@ void __reset_page_owner(struct page *page, unsigned int order)
 {
 	int i;
 	struct page_ext *page_ext;
-#ifdef CONFIG_DEBUG_PAGEALLOC
 	depot_stack_handle_t handle = 0;
-	struct page_owner *page_owner;
+	struct page_owner_free *page_owner_free;
 
-	if (debug_pagealloc_enabled())
+	if (static_branch_unlikely(&page_owner_free_stack))
 		handle = save_stack(GFP_NOWAIT | __GFP_NOWARN);
-#endif
 
 	page_ext = lookup_page_ext(page);
 	if (unlikely(!page_ext))
 		return;
 	for (i = 0; i < (1 << order); i++) {
 		__clear_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
-#ifdef CONFIG_DEBUG_PAGEALLOC
-		if (debug_pagealloc_enabled()) {
-			page_owner = get_page_owner(page_ext);
-			page_owner->free_handle = handle;
+		if (static_branch_unlikely(&page_owner_free_stack)) {
+			page_owner_free = get_page_owner_free(page_ext);
+			page_owner_free->free_handle = handle;
 		}
-#endif
 		page_ext = page_ext_next(page_ext);
 	}
 }
@@ -414,6 +452,7 @@ void __dump_page_owner(struct page *page)
 {
 	struct page_ext *page_ext = lookup_page_ext(page);
 	struct page_owner *page_owner;
+	struct page_owner_free *page_owner_free;
 	depot_stack_handle_t handle;
 	unsigned long *entries;
 	unsigned int nr_entries;
@@ -450,16 +489,17 @@ void __dump_page_owner(struct page *page)
 		stack_trace_print(entries, nr_entries, 0);
 	}
 
-#ifdef CONFIG_DEBUG_PAGEALLOC
-	handle = READ_ONCE(page_owner->free_handle);
-	if (!handle) {
-		pr_alert("page_owner free stack trace missing\n");
-	} else {
-		nr_entries = stack_depot_fetch(handle, &entries);
-		pr_alert("page last free stack trace:\n");
-		stack_trace_print(entries, nr_entries, 0);
+	if (static_branch_unlikely(&page_owner_free_stack)) {
+		page_owner_free = get_page_owner_free(page_ext);
+		handle = READ_ONCE(page_owner_free->free_handle);
+		if (!handle) {
+			pr_alert("page_owner free stack trace missing\n");
+		} else {
+			nr_entries = stack_depot_fetch(handle, &entries);
+			pr_alert("page last free stack trace:\n");
+			stack_trace_print(entries, nr_entries, 0);
+		}
 	}
-#endif
 
 	if (page_owner->last_migrate_reason != -1)
 		pr_alert("page has been migrated, last migrate reason: %s\n",
-- 
2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190930122916.14969-3-vbabka%40suse.cz.
