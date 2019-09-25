Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOPUVXWAKGQETP7BRSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C5122BE00A
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 16:31:22 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id j10sf1719257lja.21
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 07:31:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569421882; cv=pass;
        d=google.com; s=arc-20160816;
        b=TdjcLJvCw5rT+gRg/+ydLrPHV1y4d3OGtIoCSw3Tb5RlfS+/8FnlPAa6wYw1u+ZZmA
         LUtDIc9/RZn3+n4WAOynlAeYlXtIx85ODMuuVaKGf5a1V7kCSZviMJRG69Jdrp1eD0Cd
         1fC1qdvnZPxyJhw2V1oDjbiAaw+evmltGZEB8ojQ/cF71F+5qvMbohbrOveF3QN2Ii0T
         DerbZM419JbCO44l9lkvLIqQqRK+EQKmDGm4aoXlzUsZv5+0UUYYSIcbir77yVDtiS/J
         2m0fL7ll1G3wLMVGe+YJD1tCfaqEAu4EmU2cmQaIHKdAg6E7mY8htLJytz6+VOah5uSK
         WMnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JhJbS0eUzcwEaKIFTq4ufqOx+I7W6RHl1YFczTZwOeM=;
        b=Q69V0npfpplKiFylc+RUjq2BgDOfBTKesYWuPyt0xeCaDpA6mBHA2TpbXVU/xojVmE
         nGXF+a313cy0IVhCKAq2RTJuzil6/axR/6CYuHqAroxCsOkWoRbpBLw06Pc5NLrv5NGl
         HtbazwQsA27E3zfyezzXUPUw9YPh5n/T1bXoTr5so7cHaEZxyNV5AQlb8tGHFWcetbtO
         59+TRv3VbP46wK6ys0pd0E7PiYuYxKkylkXYV8iYV5CXLCidr0vTAgQfjqdyEzg/7v0f
         8E7LEbju0YExeWttA2YdCrbf1OuG1F0vPTiQD0hyz0AVgqcoSy0dVhLMfCz+10HjbhjC
         Qvdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JhJbS0eUzcwEaKIFTq4ufqOx+I7W6RHl1YFczTZwOeM=;
        b=r0/efjlzSsM6A8pZhXsF+30X8jKuKbmqnw+PoQX77Pj6Y0wvxIGdn5d2LX4vtKdbc5
         9+d/Hi7MGHdJK+ZVXzE3rAXkeURubmh2DyHQuXUQu8xXdlXjVBV4/xO9qGD7621ReqQN
         lY10A567G0h0aQ+CUQAT1l4tUbEsS8cvuSFKJ98rA4aQ2uZZd+n8c77P57gID/040uZN
         y3J7hr7affP3SHUThjN0TOrASm91x8eZhjSv1fHfFspull1RTmGRnZJU6PB317/W8bpL
         5fA88nP8MiFTI1KsV+dL8TmI3PXM38E6ghK5zeXFFYiJ6xQveRVWyf383BdQU4aaZadP
         sfsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JhJbS0eUzcwEaKIFTq4ufqOx+I7W6RHl1YFczTZwOeM=;
        b=cD61qYAoF/33ZfYHtMOcBfligvn15mTeWMrXl6+p5cq/E+SPePBfkeFGafTnKdAvSz
         JnLMnG8pUT3a13iZ9XQyr7m8eOXzn0wHX2K4V+GhpbxlHD7SjN9sZWKL8MhY6lXbS1p6
         m5928jUCP4f+pn0SEgJhcPAOKUzl/QsNE8n4eyQhzFbG3C/BC773Nz+q/CmBMBDedW/K
         LgwbQUNuqIyLzT5wk4UX0wVcyeJWUFv4VSP7mh0iAH5AWi3AWyqncXRsdFv6kNjyBe1P
         lj3/4Rb2sC1E4K0WczvxcPknuoTcciOHaRR5ssgOhhycH8AqrdjX3u6RP8EBqE3Fbq/5
         UdmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVtx+bvMMEAfGJ/7KoxHMHPlfTRSrRTQD6JdrSA92PskojiKNS5
	C5skBp22PVullo9apOBF0hE=
X-Google-Smtp-Source: APXvYqyHXZknkMsnQtRlhuxEd0WF7eilr7Gagvepr2j6RDXTruDhuO+SEZBLWXerK0576QvBC+lvYw==
X-Received: by 2002:ac2:44c8:: with SMTP id d8mr6544548lfm.101.1569421882182;
        Wed, 25 Sep 2019 07:31:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:47d5:: with SMTP id u204ls919526lja.5.gmail; Wed, 25 Sep
 2019 07:31:21 -0700 (PDT)
X-Received: by 2002:a2e:8507:: with SMTP id j7mr6853371lji.151.1569421881206;
        Wed, 25 Sep 2019 07:31:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569421881; cv=none;
        d=google.com; s=arc-20160816;
        b=Z/yLfMQbtykfNAH965Wj2Rybtfr2eYLnbzaVe9C+ULxJL0fA4HbPAD5UZfThHS9muA
         1P2dY80qPYImIU80WB3t/aNmf8U1itIoWovFvy1vyQ5wd+vYBLlytCKpLWKroKwv0SzW
         IXV/4PhIlgoZ0qvN8LhfSk1GTlf1uPrAbLzyLXdNq9ANe6k+2H/TL9YXEgWLajA9GrJ3
         yE0X6sqHVKppdoCVkNQtRLcO9FE4D//QXU52ZH6H3P2/6E+aF99q4X7CwLUBKOiTqdz+
         0lUPkcJ8NE1a4UkVM/BohPxYSY3iyQNIMcaopH/Q2lhwiOTI5PlARf9/oooOmM67f8gp
         KnVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=35/hEpDAB6spA1URIfoULOYl2orrr8leQAkG/VWVeFw=;
        b=iF7AgBTxkds3u5kr2Q5wbtg3WlX9wuvYI+O613FFG2+06RjMThohn49WezEao4VgQL
         43iJGZokFA7ozGwnHzui6ki1rLmAGTiAt2VIGQASfWODC6DBmkjd8gJHaomCbaQ8HeO4
         EuXK2M2/YBaN4QsO73P8eWdj7rG8Izg/FOOM6AAd2NFXZ52XpqXOxtkJaK36XMvp7RqB
         uVGoSNx4A3jt7apXHnUugLDCXhQkBc8GpyKBN1E+1cX7ZU9WxZ8C54gqD1Redt3B7a5z
         TThT1+7tRyeyEhZwvq2ZifrAVsYUgDwl2SMMbwbCeyXdpyubjdCHv7vQCR5COxLeBK+m
         +few==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id k2si395451ljj.1.2019.09.25.07.31.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id F14A1B02E;
	Wed, 25 Sep 2019 14:31:18 +0000 (UTC)
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
Date: Wed, 25 Sep 2019 16:30:51 +0200
Message-Id: <20190925143056.25853-3-vbabka@suse.cz>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190925143056.25853-3-vbabka%40suse.cz.
