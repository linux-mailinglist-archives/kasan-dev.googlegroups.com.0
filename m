Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOPUVXWAKGQETP7BRSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B0F60BE009
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 16:31:22 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id w22sf848973lfe.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 07:31:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569421882; cv=pass;
        d=google.com; s=arc-20160816;
        b=qqsObgYK0Z4LxCsbnBeJZgEnkZaE6B0cqiDK1aeMX8mxRsPOZgfKkIz2pFxo32EcTE
         brHuT66q9SVEUvZGb8FosoP/EUeAdpklfCKODx/E1V2W324I3zJ4zUEV9NDr29M7MFex
         nXKLsCLn4DJN7H7J13/vTiBYC9ETMxUw9iRLm/UeiGtxXrZOhIw/Kn59Fv5ZwbzdmJmQ
         yTwVjiwBQ+0GAbK55dvkZXTwuI4f538IOtDQF+LfqO38pe+nUPrQ1aHKclcJFo1jgvu3
         7KFDcUl6ZnN8+bGvf5gJMhRekjZ6FtdY8W76QiEbZNRWntdcztU3uu4LHCsDWz8804LP
         Tx2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2dW2ePnILh0feWXJiENEA0hKm6LyRHlKka18thS8IH0=;
        b=aKSvQvrMjF5U5WWuPTITNGTPELDlqp/rqNBglPcRIECMZvWUQmka4idLLw3ZRkITQq
         dWsqjIZGyIg/I9eQqXIkAO4a2B+ckuq+vEMAf2dDAj3fr+EWFjP+/F1rdfNvqf3CeAer
         qkNltw7Xq3qlZw6HOWW2YAu6i7mCJrswEfpTaqqxkVb+h794UbUuao/DVnvfwd4PhpQj
         SkYJcUtJ56/jWc2PzAYxHHBJ1rW/xEkWld41TdxzwJTLL6v/HMxWCTHP4ZAfObYdzSeX
         8dYlf6GGFsQwOtxe7Y7lpgS0wTP61bePG+9za+ANhbu3Fz0YPYsVQfUU60aotOJNwLYn
         AT6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2dW2ePnILh0feWXJiENEA0hKm6LyRHlKka18thS8IH0=;
        b=TdAs289oRY+ALhXLzPw4budd+V6vMTwcSVKLqEWVdb301EgwabQEfpEf0xOJt3gaZo
         IXkz0ssGwMCSvyBZNiBEh82NM/t0Vcft3v3IKpPP9E+w7mEqQ0bUMs/PkenTQS1mopSd
         EYh0vGDnwnihYYOSDturFbeEym+1YnKSqnO9udtmcnDR9BsXEYlZZyv8NJMOWiZLpcPG
         AQcmq0xPE2WAQ5YUEsfNdWK8GFiLAcykO/v7gtaJUcFZac3fUFDpV85O7YD+r4pMwhLH
         p8a+lqVOMry9R9Ox40jRdLrry0qt86D3mFek63FkDn/znTGi9A3uY8ICweG8prSE++9f
         58zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2dW2ePnILh0feWXJiENEA0hKm6LyRHlKka18thS8IH0=;
        b=TZ9Sp7TWe+XwRzDtB5WwxoL20OlfW/OKFCGqOhzDGx8tlGm0PjZeOF6T3645bTw8PH
         hcJvrhGZ3PgZeZVwd60WhrnOVjkMyitGa3f6/gVQEZKUgM1K1EEO/Sl7U7Fyf9/n5ZTC
         ckT1jhJjbf6aDwx173G+D56FDpm7TvK8YdnQ72w8L5NNghgdtd2wYtQZT+/+kyvqHu3Z
         wTO/4IkiBsLyeAu+c5s7moL5EePgSLnBJJ9cyPJ9kaUbJzj+2OSjOMUP+3N+vKJQsu/J
         8gHsT+LwQcG6EwxgWC4RlC5bFllVeXgExFXFaGxCG/TSPGZ+/eHXoNZ8CAND52tEjjGS
         xOQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX5wfkKmlA2xZJcwRV10BoYc4Sf/DG5+ElfdKIL523m1+uPXcwX
	zflsLxSEs2fP3tUMdQp5jZM=
X-Google-Smtp-Source: APXvYqw7vxjOr/zOvT9R4j+HNC83wXu5oaQdpcruWlgiN0oHEM/CePWM8tn6bjak5P5R5UFMMRE2wg==
X-Received: by 2002:ac2:5091:: with SMTP id f17mr6514307lfm.107.1569421882297;
        Wed, 25 Sep 2019 07:31:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:95d4:: with SMTP id y20ls919508ljh.15.gmail; Wed, 25 Sep
 2019 07:31:21 -0700 (PDT)
X-Received: by 2002:a2e:8084:: with SMTP id i4mr6925679ljg.119.1569421881112;
        Wed, 25 Sep 2019 07:31:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569421881; cv=none;
        d=google.com; s=arc-20160816;
        b=bU9bo6Ot3JFRCqBLeZQXA8NT5vmioLWuSu2aCGhfEyyQjqZChowH0gp5dpq4Bvu+2j
         armU5l9uvYo8HiJgQ9q1sMJuR9O4duZonkANYma0FOvE8GGp+2hU88u7o0zxuImXMmJT
         JohCw0u8MOGD9nidz084c88za6u+8vRyRZr+6UFTeOf/9ktV1cdARISlCtLXOrE6m/MW
         LQFWtbApYW9LvEZ5UbtLxLo4jW5TEKMH+mRUuDIXM0Py+9Ht2IMiUCQactXSofeuUaKX
         PhWssqRVrDkfp5d9MAU2ckoWBS15NmBCjOX7OJ+1QyqmIdJD9riKizhftdn/dSC3uBhE
         rurg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=35/hEpDAB6spA1URIfoULOYl2orrr8leQAkG/VWVeFw=;
        b=xzKF1lcArw4EJhVk1tScFZE0eycZTH/khN+mQSPZsnINr/AyUhU8GdUeuqVldAc+wx
         OxDiKPDWq7krzdFES0ymSz02+5UASMsljuXim70EeInvWiL+8zJwjJyf5KG5pd5zWUBr
         CSy4F85HTWEbGvoVex3paNTVNkwUOPsefEMUFRBmihmmck+zgLvs4d2JCN2K+BLk/KGE
         9yHM3Kc3aVVdRRAoE+6JiqXzTF3YAErQlT4ErfzMj/InJMoE0e07teTG/vmLHMybDx7t
         xTc1edOgTPvu+H1fe68c2nBlSrzHtMogCjITNs6zlhzIhbyA9VoCPj5uU6W1dnxWz7Ys
         qYQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id a9si250499lfk.5.2019.09.25.07.31.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 5E0FFAE89;
	Wed, 25 Sep 2019 14:31:19 +0000 (UTC)
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
Subject: [PATCH 2/3] mm, debug, kasan: save and dump freeing stack trace for kasan
Date: Wed, 25 Sep 2019 16:30:55 +0200
Message-Id: <20190925143056.25853-7-vbabka@suse.cz>
X-Mailer: git-send-email 2.23.0
In-Reply-To: <20190925143056.25853-1-vbabka@suse.cz>
References: <20190925143056.25853-1-vbabka@suse.cz>
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
improve error reports to debug e.g. UAF issues. This patch therefore introduces
a helper config option PAGE_OWNER_FREE_STACK, which is enabled when PAGE_OWNER
and either of DEBUG_PAGEALLOC or KASAN is enabled. Boot-time, the free stack
saving is enabled when booting a KASAN kernel with page_owner=on, or non-KASAN
kernel with debug_pagealloc=on and page_owner=on.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=203967

Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Suggested-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
---
 Documentation/dev-tools/kasan.rst |  4 ++++
 mm/Kconfig.debug                  |  4 ++++
 mm/page_owner.c                   | 31 ++++++++++++++++++-------------
 3 files changed, 26 insertions(+), 13 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index b72d07d70239..434e605030e9 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -41,6 +41,10 @@ smaller binary while the latter is 1.1 - 2 times faster.
 Both KASAN modes work with both SLUB and SLAB memory allocators.
 For better bug detection and nicer reporting, enable CONFIG_STACKTRACE.
 
+To augment reports with last allocation and freeing stack of the physical
+page, it is recommended to configure kernel also with CONFIG_PAGE_OWNER = y
+and boot with page_owner=on.
+
 To disable instrumentation for specific files or directories, add a line
 similar to the following to the respective kernel Makefile:
 
diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index 327b3ebf23bf..1ea247da3322 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -62,6 +62,10 @@ config PAGE_OWNER
 
 	  If unsure, say N.
 
+config PAGE_OWNER_FREE_STACK
+	def_bool KASAN || DEBUG_PAGEALLOC
+	depends on PAGE_OWNER
+
 config PAGE_POISONING
 	bool "Poison pages after freeing"
 	select PAGE_POISONING_NO_SANITY if HIBERNATION
diff --git a/mm/page_owner.c b/mm/page_owner.c
index d3cf5d336ccf..f3aeec78822f 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -24,13 +24,14 @@ struct page_owner {
 	short last_migrate_reason;
 	gfp_t gfp_mask;
 	depot_stack_handle_t handle;
-#ifdef CONFIG_DEBUG_PAGEALLOC
+#ifdef CONFIG_PAGE_OWNER_FREE_STACK
 	depot_stack_handle_t free_handle;
 #endif
 };
 
 static bool page_owner_disabled = true;
 DEFINE_STATIC_KEY_FALSE(page_owner_inited);
+static DEFINE_STATIC_KEY_FALSE(page_owner_free_stack);
 
 static depot_stack_handle_t dummy_handle;
 static depot_stack_handle_t failure_handle;
@@ -91,6 +92,8 @@ static void init_page_owner(void)
 	register_failure_stack();
 	register_early_stack();
 	static_branch_enable(&page_owner_inited);
+	if (IS_ENABLED(CONFIG_KASAN) || debug_pagealloc_enabled())
+		static_branch_enable(&page_owner_free_stack);
 	init_early_allocated_pages();
 }
 
@@ -148,11 +151,11 @@ void __reset_page_owner(struct page *page, unsigned int order)
 {
 	int i;
 	struct page_ext *page_ext;
-#ifdef CONFIG_DEBUG_PAGEALLOC
+#ifdef CONFIG_PAGE_OWNER_FREE_STACK
 	depot_stack_handle_t handle = 0;
 	struct page_owner *page_owner;
 
-	if (debug_pagealloc_enabled())
+	if (static_branch_unlikely(&page_owner_free_stack))
 		handle = save_stack(GFP_NOWAIT | __GFP_NOWARN);
 #endif
 
@@ -161,8 +164,8 @@ void __reset_page_owner(struct page *page, unsigned int order)
 		return;
 	for (i = 0; i < (1 << order); i++) {
 		__clear_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
-#ifdef CONFIG_DEBUG_PAGEALLOC
-		if (debug_pagealloc_enabled()) {
+#ifdef CONFIG_PAGE_OWNER_FREE_STACK
+		if (static_branch_unlikely(&page_owner_free_stack)) {
 			page_owner = get_page_owner(page_ext);
 			page_owner->free_handle = handle;
 		}
@@ -450,14 +453,16 @@ void __dump_page_owner(struct page *page)
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
+#ifdef CONFIG_PAGE_OWNER_FREE_STACK
+	if (static_branch_unlikely(&page_owner_free_stack)) {
+		handle = READ_ONCE(page_owner->free_handle);
+		if (!handle) {
+			pr_alert("page_owner free stack trace missing\n");
+		} else {
+			nr_entries = stack_depot_fetch(handle, &entries);
+			pr_alert("page last free stack trace:\n");
+			stack_trace_print(entries, nr_entries, 0);
+		}
 	}
 #endif
 
-- 
2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190925143056.25853-7-vbabka%40suse.cz.
