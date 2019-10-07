Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB3EF5TWAKGQECAYUQDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B5C5CDE15
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 11:18:36 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id l15sf3261424lje.17
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 02:18:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570439916; cv=pass;
        d=google.com; s=arc-20160816;
        b=QrboblezuOjiLQxC4CzgUTJy99tlfPS2+9w27dka4zy9AF+wAxRuCDjgPFPrrBQpoV
         /fO3y6W0C/tmWlfc8NRVwlAzYiBcMNlINfmzaKxIg4oIZB2gg0MubIZhXU2JFUkfWcxY
         T5OO8gfExeQDnu3TpG5UOyNdubS+V41EUo0vGrQ3a55v65aSxWpVU96xzSFwdS7Glpv+
         ROkVeuCfAo6LveNHawa6nnHmOdwtMmlar83+LdAY6Wh2oN5AqjCk58yxLRnG+aOEgpKN
         ptEkopPoroSaTkcGdqVrFg+J0VSlIp4aGTv0sQVJvO2I5aSKn9k5puLd09/naC1ZglRG
         n0pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jgnDseJE/z90Aa+GNxS81nOxJr2TF/LvC1g5/ntjdco=;
        b=BHr5dXy5M15229+o61sDZ76oCPKhIFHZY1ApB5q5we/lXVM7oYZcbyhfbqqIl/pOcF
         uaGIpCRV+XtZtjEC3BFGFDZgHwzHd0dOc93tKjU9GWqVEBdMtZiwvUH5zQE9YG3iGzQc
         YkNKstDilcRO6cDM3VU2N3FEgbNrnE6gDdbTJtSUU6inwApUZKzxfaF7N0V4YNjYjG2y
         e1zvLdLz/MIriPw+NmnqHgLlHM/Bv66LcZEZqcAxHjO5Ubtmx1KvnG20JXGPCiP/jRo/
         omlHyRmvVu3q6SbPG0r47hADCSnsD39L1RgqV/SdmbZV7bPG1zg9pJvEwfGTflTJKNqZ
         6Eww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jgnDseJE/z90Aa+GNxS81nOxJr2TF/LvC1g5/ntjdco=;
        b=bmTbjq9vdhOF3bz5mUg0+BT5iriTe/LE9mgz+AETE6cHd4OxmyOgSfD5/IdEAI5bTc
         qM68gq5Pq/OvTks1IrEwmiFhsBB2NuDWB41AsmWj/0eOHeucBUAG7C1Jj4jdEFHoEKn0
         3WudPnyAUB9eG1b2BmtXJ3ujYPufKLE5/7b4jVmsljLv1HK7U1n/Ky3zVH8B3WVI/B3o
         A8+w6IcH9FDItJBx4oO5qMV6TvsKsNJHsFXjuCwJV5jgf66tH+lBQoWQsgpY0nqhOHvH
         PFzdtqKwF4ObI5pYdmHBUcRkTsIUhWBl3wDini4Jpt2NDG1/zg18x+CHjeuLDojno6zQ
         yqHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jgnDseJE/z90Aa+GNxS81nOxJr2TF/LvC1g5/ntjdco=;
        b=kL2NGZ9zsTAxQ/7CuEv8JW0C4IMIs8geyGRrMeKXNTDl4gYG1HINsWPc+Wnje1xOCs
         WFVKcxcMJe4V7gu8bz4Gg2tIzJ9ujMyGwSuzJR20sh8zuVzO8rHbjyXvCex1b3y+yW3G
         E43si4bPLoEatQQF57TvmZqqh3FSJwz6q0OsgpztmSc4mEXEtSMbnj3ZSDm8Df5rVbUc
         yFlUJs9ePCSj4Kk9OhXhXXRrubk7begX4TRNhmVUt888WNl8MZSebZcxikLwjHR6DWAZ
         UNQRSWN0VP/IuMMrXqCj66tYr9kAk+IsKfKfjOoKfSUWZqZFxpP1wf9I4M7guSIaKDim
         Iy0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWr34oY15vjreTE8FBOe7Py93NbJiGQZbEqjiHrynfnIV1Sb0Q8
	zjnIErEhnuzjX08jQQhOwGc=
X-Google-Smtp-Source: APXvYqybIKQnwnv26Y/uDS4Mqe10kBd91v3fRSu3ql3Ob44m3D8ZG6yhiSphtU7YmW/oq12xc82rFQ==
X-Received: by 2002:ac2:4a6b:: with SMTP id q11mr10296799lfp.132.1570439916177;
        Mon, 07 Oct 2019 02:18:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7d02:: with SMTP id y2ls2055585ljc.8.gmail; Mon, 07 Oct
 2019 02:18:35 -0700 (PDT)
X-Received: by 2002:a2e:918c:: with SMTP id f12mr17616439ljg.121.1570439915408;
        Mon, 07 Oct 2019 02:18:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570439915; cv=none;
        d=google.com; s=arc-20160816;
        b=tajBGHx91RQnvynXseavmNseKBrx06wYUPDA6s/rGO6ABGpwzbgq4cJxtFNSaothRU
         kLYoJ+pioCOsBftTi1g6IzE1HylJ5EZqm5nu+uaZSMe/rOJsN19JKBkfaiKdHwyW+99R
         9N0MOjRW37PgfGjOZf6Z2IrwXOR0NVk9g6p6tm5c2bLm8/tUKE/c2+RW0k4BCgsdU+Hu
         +sBi7mTcKU/RduPLqdmB4R2QTKf6o2eJqvbxgwlkV5B7LfP7YKX1rLZ8evwtI99BmN44
         FqyNb9K1kwh0FvWm7iKR28Tt7Vi6hNktKD9FCA+2AFusrb3Yjf0Gc709KJSGfW9BC6Pe
         siRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=i+dNJGZt1NAA6kFnkncnn77HcoTRgeDGtzIxzTRAKDs=;
        b=jwYE7r3Ac5FtstV1yg6aNDOpdx5Tw4oJli9BbwnUdW1Ny8Jj8yMzKiv4XVRrFLbDnX
         igOJYfSLLpP1AxETWFW0MmS/TQHRsoZU291PosRrIdHTemdFuVuIbvNRIw+gVx6b2mm8
         fDkX4KgPbmxK7xht/tj8sGbJBaq+PCJfGmSbdYeOIOxFLpHDI86aUpr4Pyvo9ZyZg1GE
         QaVbFqU42DkolzQQ5LSoc7lbVyBVkSySGEmBBpgPvcW9phOet5u9k+8gzG/Hy3j1Y2nZ
         eaS+ccHy09BZ3Qexpsxx6SzWrpwojZFJleWU1aiVNTs2wlZy8fivf7ZaEel0LNZpmrtq
         5Hnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id z9si1379960ljj.4.2019.10.07.02.18.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Oct 2019 02:18:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 41809AE5E;
	Mon,  7 Oct 2019 09:18:34 +0000 (UTC)
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
Subject: [PATCH v3 2/3] mm, page_owner: decouple freeing stack trace from debug_pagealloc
Date: Mon,  7 Oct 2019 11:18:07 +0200
Message-Id: <20191007091808.7096-3-vbabka@suse.cz>
X-Mailer: git-send-email 2.23.0
In-Reply-To: <20191007091808.7096-1-vbabka@suse.cz>
References: <20191007091808.7096-1-vbabka@suse.cz>
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
freeing stack trace saving should be also possible to be enabled separately
from KASAN or debug_pagealloc, i.e. with an extra boot option. Qian argued that
we have enough options already, and avoiding the extra overhead is not worth
the complications in the case of a debugging option. Kirill noted that the
extra stack handle in struct page_owner requires 0.1% of memory.

This patch therefore enables free stack saving whenever page_owner is enabled,
regardless of whether debug_pagealloc or KASAN is also enabled. KASAN kernels
booted with page_owner=on will thus benefit from the improved error reports.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=203967

Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Suggested-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Suggested-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
Suggested-by: Qian Cai <cai@lca.pw>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 Documentation/dev-tools/kasan.rst |  3 +++
 mm/page_owner.c                   | 28 +++++++---------------------
 2 files changed, 10 insertions(+), 21 deletions(-)

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
 
diff --git a/mm/page_owner.c b/mm/page_owner.c
index d3cf5d336ccf..de1916ac3e24 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -24,12 +24,10 @@ struct page_owner {
 	short last_migrate_reason;
 	gfp_t gfp_mask;
 	depot_stack_handle_t handle;
-#ifdef CONFIG_DEBUG_PAGEALLOC
 	depot_stack_handle_t free_handle;
-#endif
 };
 
-static bool page_owner_disabled = true;
+static bool page_owner_enabled = false;
 DEFINE_STATIC_KEY_FALSE(page_owner_inited);
 
 static depot_stack_handle_t dummy_handle;
@@ -44,7 +42,7 @@ static int __init early_page_owner_param(char *buf)
 		return -EINVAL;
 
 	if (strcmp(buf, "on") == 0)
-		page_owner_disabled = false;
+		page_owner_enabled = true;
 
 	return 0;
 }
@@ -52,10 +50,7 @@ early_param("page_owner", early_page_owner_param);
 
 static bool need_page_owner(void)
 {
-	if (page_owner_disabled)
-		return false;
-
-	return true;
+	return page_owner_enabled;
 }
 
 static __always_inline depot_stack_handle_t create_dummy_stack(void)
@@ -84,7 +79,7 @@ static noinline void register_early_stack(void)
 
 static void init_page_owner(void)
 {
-	if (page_owner_disabled)
+	if (!page_owner_enabled)
 		return;
 
 	register_dummy_stack();
@@ -148,25 +143,18 @@ void __reset_page_owner(struct page *page, unsigned int order)
 {
 	int i;
 	struct page_ext *page_ext;
-#ifdef CONFIG_DEBUG_PAGEALLOC
 	depot_stack_handle_t handle = 0;
 	struct page_owner *page_owner;
 
-	if (debug_pagealloc_enabled())
-		handle = save_stack(GFP_NOWAIT | __GFP_NOWARN);
-#endif
+	handle = save_stack(GFP_NOWAIT | __GFP_NOWARN);
 
 	page_ext = lookup_page_ext(page);
 	if (unlikely(!page_ext))
 		return;
 	for (i = 0; i < (1 << order); i++) {
 		__clear_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
-#ifdef CONFIG_DEBUG_PAGEALLOC
-		if (debug_pagealloc_enabled()) {
-			page_owner = get_page_owner(page_ext);
-			page_owner->free_handle = handle;
-		}
-#endif
+		page_owner = get_page_owner(page_ext);
+		page_owner->free_handle = handle;
 		page_ext = page_ext_next(page_ext);
 	}
 }
@@ -450,7 +438,6 @@ void __dump_page_owner(struct page *page)
 		stack_trace_print(entries, nr_entries, 0);
 	}
 
-#ifdef CONFIG_DEBUG_PAGEALLOC
 	handle = READ_ONCE(page_owner->free_handle);
 	if (!handle) {
 		pr_alert("page_owner free stack trace missing\n");
@@ -459,7 +446,6 @@ void __dump_page_owner(struct page *page)
 		pr_alert("page last free stack trace:\n");
 		stack_trace_print(entries, nr_entries, 0);
 	}
-#endif
 
 	if (page_owner->last_migrate_reason != -1)
 		pr_alert("page has been migrated, last migrate reason: %s\n",
-- 
2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191007091808.7096-3-vbabka%40suse.cz.
