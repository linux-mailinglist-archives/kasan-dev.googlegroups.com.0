Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBDFS7XVQKGQEP3MELZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B7D9B3753
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2019 11:42:37 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id f63sf5304573wma.7
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2019 02:42:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568626956; cv=pass;
        d=google.com; s=arc-20160816;
        b=N2+Bm3iFsDKo0Sfko7fDRQ3g2MmiikO4FmzpCyzj7LuucvDoP8xNEpm0KyPFxY/kFY
         OvmUwW7Qz3RfV4h5YbSJmBtqtLdhNEew3kIAdlMyZLkDRE5aQaVBpKP1/F+i4DeU+HOr
         7Tvikuc7oyhs7B3aOazRldEn47vXqqZ8fK7U5tONJNDUfmgogNjokeEO/XGJxegPR/eJ
         FypuOlcbEoWGcH/HalZCtcBBkCqtf5TY+6TDqLSy5NRgkFnHSi2Jzgnpkd7DlYZUWIqD
         BZdmI6Av82OFVCdxqw1mxdNuRLY3uTsdKPNQPDFXSNRvxoH3ZfGA43c9RC2ehzmWRWLs
         25Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=htjdXTI5c3eRn/sDFDa7mFS6pGbH6lDO0VAkqNSvajI=;
        b=xgcuaRuGWjnKsXBPbftDyAdRrxTPU4lL1Bdh/OyV34kSpq1Sc05xCJVKcVWCyJQADm
         YWa+0AMhVYhf1SRLhnJF62tGFGt9z2TWH4qm+SrCw+XQG4jPz2SBilu22P57qGnCqmxq
         xNf+Cdmw2LzkfctyvoWqwEBWQHUr5yYR1UyehbX3PPSK9qnMujrJMX+ONNwT/AFJG1U2
         Tyl/UUY0diMUvjDpq56f0i6A9dr2jHz4x7wh2nGa83dGzERaadEDbXqHJ2Vh+nt7Zoje
         oQ0hpzwFMEvotI2ybBO3DsQchHssZhL7I7xgqDusbbm72nmM1+QiNIITLoYcJFxtmtzP
         40aA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=htjdXTI5c3eRn/sDFDa7mFS6pGbH6lDO0VAkqNSvajI=;
        b=j/Oq+jWRp37Kos9gEyn/E34L3I6EPi56nhmW9xMBocExapXNqqNwEb4ldaf8Bd0mzW
         Rm/t569q3BBRUlJDMH74+Mu5mpr5nppCzyy1xc9zKbw+Po5aqIXGiS+L8GlwAPKke7VV
         AUhXlWSljwo/Vf+2dqAn+nokaltmUda+acSi8GUTBNpCmphKMJosnqFb04S4VlYvqT9d
         I7Vgi06tOCSiJpSjC1nej3VE+gdjNloGFQzSAxjaTdP1hCUBNrSqjewMlKpUFoRXb1iK
         jFQWakXtmA3Kt63UThx4VF0ksb7PV0DC/i27bDTIOU4YX9Xs4EZwMK9m/GfK/Z+D81SU
         7F2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=htjdXTI5c3eRn/sDFDa7mFS6pGbH6lDO0VAkqNSvajI=;
        b=JtH3YM3zWXNqRPVIw/aJAKN/GGmizm5wNvMtxZ+apgs1ztqQLV+h0iYoazWhedwOIV
         wMq2F1NIkMwyZMvvwtdAJoWgc5iBCAaF6uUhahnPf7URkWIEYFIlfGpMUMjnbLnFNANF
         CKWFZOkC4QW0B3PWQh8IU7D+qkZX7AXlBNAERKJs35dGwmW9Yqm7RyEmvhTlobWnYSbq
         qsIP992o3xDGbJgps/5IZWEnMlS8Q/yEPvngohEPFbkQkou2VsJapz7YMP9n0ECJXQTU
         khdLAJys0U25QjuNfdJUJaS6qmYDaheyIE0yPItBMQ7XWkp9mMaqURoC2mXkFD4OYIBg
         A3eQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVi4KbcDTlhnT2/5bNBR0Q20QBLVSnK6vfLPSZDwbvK2SeQ9UQ8
	DQxq94PVK2yEyyLWBlP9a0M=
X-Google-Smtp-Source: APXvYqwjboImsj4z6/wNlES6Z4dxX9wGrMuHHWNVOcS58tke6IJbFtB+J/RtdxFj/5XQfbxYlS0YKQ==
X-Received: by 2002:adf:9c81:: with SMTP id d1mr32675000wre.123.1568626956615;
        Mon, 16 Sep 2019 02:42:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1a96:: with SMTP id a144ls4773658wma.3.gmail; Mon, 16
 Sep 2019 02:42:35 -0700 (PDT)
X-Received: by 2002:a1c:a617:: with SMTP id p23mr13317606wme.166.1568626955933;
        Mon, 16 Sep 2019 02:42:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568626955; cv=none;
        d=google.com; s=arc-20160816;
        b=LTrgUV7DK1PKAN45LN3/iRcO6vnLm/Wveeaxguk5hoA+I2dt+x+nGB5CRzbzyr2YEL
         8N3I6ct3baQ8gYnApLf6tGi9J5DMGNoima30PH9ZlfOWqKpHTSDTqU57MteD0/kkWd+0
         ep0w6ZF0UFqPuJnFf7smEymCf5IWkLnIWsQgwcBYkWNrtWKcnuI3IVkpVJGQVrrj1n1I
         xqX32F4fKBlABJRs3XhQb7WqdBHVyJAHFeQ56Vlvg6ymaWi/OQdx6kyZfZgk9IfOij9y
         q9aAEsdPoo3nf7q23q+al8Se9NU5Fjv/raApmZiCi1iTduphKdZUeS38sakK28hDQeQO
         wthw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=zf0doKV7N8XoS5GjMPMgDfjbm1tf2IBXaBc8BeNVwSU=;
        b=GdqHo46oxs6guMlocve2Psv4i4BbU4pUcAAdwmfcftxQQUElYyW1BqIolyeJy3SmVt
         +Nj1zzGY7fdcroplUx9JZQJ5VXYcC6tYaPfCj/ljZtpVWyJN/O1fDRtUovtQm/gQbz05
         mW4gYMlJsNGR6zo9O52YFaB316jwIKJ1zt62K25E52CwGPOzaFw8XbtMMrpXkWOeh5IT
         1oDa3ySzQVpdnoL/0CV3/+7F7l+kTM7cF5EXkQ+8FICdD0ASyRuKPCJJQD+QVdq66yqV
         GEdS7HOPVnLnH3kc5oC9mHxa/VnNaP5tCTgqP79tRdMy92YU676BXD2dbzRZ1LddsEEl
         +RLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id j4si1821671wro.5.2019.09.16.02.42.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Sep 2019 02:42:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id BCBB6AFE2;
	Mon, 16 Sep 2019 09:42:34 +0000 (UTC)
Subject: Re: [PATCH v3] mm/kasan: dump alloc and free stack for page allocator
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Walter Wu <walter-zh.wu@mediatek.com>
Cc: Qian Cai <cai@lca.pw>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>,
 Andrey Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
 <5E358F4B-552C-4542-9655-E01C7B754F14@lca.pw>
 <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
 <1568297308.19040.5.camel@mtksdccf07>
 <613f9f23-c7f0-871f-fe13-930c35ef3105@suse.cz>
 <79fede05-735b-8477-c273-f34db93fd72b@virtuozzo.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <6d58ce86-b2a4-40af-bf40-c604b457d086@suse.cz>
Date: Mon, 16 Sep 2019 11:42:32 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <79fede05-735b-8477-c273-f34db93fd72b@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/12/19 7:05 PM, Andrey Ryabinin wrote:
> 
> Or another alternative option (and actually easier one to implement), leave PAGE_OWNER as is (no "select"s in Kconfigs)
> Make PAGE_OWNER_FREE_STACK like this:
> 
> +config PAGE_OWNER_FREE_STACK
> +	def_bool KASAN || DEBUG_PAGEALLOC
> +	depends on PAGE_OWNER
> +
> 
> So, users that want alloc/free stack will have to enable CONFIG_PAGE_OWNER=y and add page_owner=on to boot cmdline.
> 
> 
> Basically the difference between these alternative is whether we enable page_owner by default or not. But there is always a possibility to disable it.

OK, how about this?

BTW, the bugzilla [1] also mentions that on overflow we might be dumping
the wrong page (including stacks). I'll leave that to somebody familiar
with KASAN internals though.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=203967

----8<----
From 887e3c092c073d996098ac2b101b0feaef110b54 Mon Sep 17 00:00:00 2001
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 16 Sep 2019 11:28:19 +0200
Subject: [PATCH] mm, debug, kasan: save and dump freeing stack trace for kasan

The commit "mm, page_owner, debug_pagealloc: save and dump freeing stack trace"
enhanced page_owner to also store freeing stack trace, when debug_pagealloc is
also enabled. KASAN would also like to do this [1] to improve error reports to
debug e.g. UAF issues. This patch therefore introduces a helper config option
PAGE_OWNER_FREE_STACK, which is enabled when PAGE_OWNER and either of
DEBUG_PAGEALLOC or KASAN is enabled. Boot-time, the free stack saving is
enabled when booting a KASAN kernel with page_owner=on, or non-KASAN kernel
with debug_pagealloc=on and page_owner=on.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=203967

Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Suggested-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 Documentation/dev-tools/kasan.rst |  4 ++++
 include/linux/page_owner.h        |  1 +
 mm/Kconfig.debug                  |  4 ++++
 mm/page_alloc.c                   |  6 +++++-
 mm/page_owner.c                   | 35 +++++++++++++++++++------------
 5 files changed, 36 insertions(+), 14 deletions(-)

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
 
diff --git a/include/linux/page_owner.h b/include/linux/page_owner.h
index 8679ccd722e8..6ffe8b81ba85 100644
--- a/include/linux/page_owner.h
+++ b/include/linux/page_owner.h
@@ -6,6 +6,7 @@
 
 #ifdef CONFIG_PAGE_OWNER
 extern struct static_key_false page_owner_inited;
+extern bool page_owner_free_stack_disabled;
 extern struct page_ext_operations page_owner_ops;
 
 extern void __reset_page_owner(struct page *page, unsigned int order);
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
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index c5d62f1c2851..d9e44671af3f 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -710,8 +710,12 @@ static int __init early_debug_pagealloc(char *buf)
 	if (kstrtobool(buf, &enable))
 		return -EINVAL;
 
-	if (enable)
+	if (enable) {
 		static_branch_enable(&_debug_pagealloc_enabled);
+#ifdef CONFIG_PAGE_OWNER
+		page_owner_free_stack_disabled = false;
+#endif
+	}
 
 	return 0;
 }
diff --git a/mm/page_owner.c b/mm/page_owner.c
index dee931184788..b589bfbc4795 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -24,13 +24,15 @@ struct page_owner {
 	short last_migrate_reason;
 	gfp_t gfp_mask;
 	depot_stack_handle_t handle;
-#ifdef CONFIG_DEBUG_PAGEALLOC
+#ifdef CONFIG_PAGE_OWNER_FREE_STACK
 	depot_stack_handle_t free_handle;
 #endif
 };
 
 static bool page_owner_disabled = true;
+bool page_owner_free_stack_disabled = true;
 DEFINE_STATIC_KEY_FALSE(page_owner_inited);
+static DEFINE_STATIC_KEY_FALSE(page_owner_free_stack);
 
 static depot_stack_handle_t dummy_handle;
 static depot_stack_handle_t failure_handle;
@@ -46,6 +48,9 @@ static int __init early_page_owner_param(char *buf)
 	if (strcmp(buf, "on") == 0)
 		page_owner_disabled = false;
 
+	if (!page_owner_disabled && IS_ENABLED(CONFIG_KASAN))
+		page_owner_free_stack_disabled = false;
+
 	return 0;
 }
 early_param("page_owner", early_page_owner_param);
@@ -91,6 +96,8 @@ static void init_page_owner(void)
 	register_failure_stack();
 	register_early_stack();
 	static_branch_enable(&page_owner_inited);
+	if (!page_owner_free_stack_disabled)
+		static_branch_enable(&page_owner_free_stack);
 	init_early_allocated_pages();
 }
 
@@ -148,11 +155,11 @@ void __reset_page_owner(struct page *page, unsigned int order)
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
 
@@ -161,8 +168,8 @@ void __reset_page_owner(struct page *page, unsigned int order)
 		if (unlikely(!page_ext))
 			continue;
 		__clear_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
-#ifdef CONFIG_DEBUG_PAGEALLOC
-		if (debug_pagealloc_enabled()) {
+#ifdef CONFIG_PAGE_OWNER_FREE_STACK
+		if (static_branch_unlikely(&page_owner_free_stack)) {
 			page_owner = get_page_owner(page_ext);
 			page_owner->free_handle = handle;
 		}
@@ -451,14 +458,16 @@ void __dump_page_owner(struct page *page)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6d58ce86-b2a4-40af-bf40-c604b457d086%40suse.cz.
