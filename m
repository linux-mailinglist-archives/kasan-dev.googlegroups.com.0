Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB3435HVQKGQEPBBJCKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id B5806B106B
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 15:53:51 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id b1sf12034557wru.4
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 06:53:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568296431; cv=pass;
        d=google.com; s=arc-20160816;
        b=PTydRmW+NZ/TV8W0phQudqHJ3LvU4bcp1AeAsrevkoUqFAGQZGyc9y6J29hCU2YdM7
         OnmWAUdPKLq712VOc/guPFbs8AT1KneUFuUzkZcsNMv18MvH5isWHRSIgccp78qHdfEZ
         Y/6acMqttIvfEvT4fxus71g061DtzZNcXLbshUAeYCC2fvIMAKE2M7/1phR5zZyaTx3F
         Fsno/j0vjnaZWJKah0SOG3EW3r7EFDmu7jEG7bQzSgJgZaCuq+0rjRyL169R4Un6Rzek
         pgUNnTHiqE84Ne7PwND7eXvDUvkc+NaqEG+6OuKeT/97ehRNjWyRLryYepQ7meRdw4S5
         7M8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=7gxECs1b23pOT4624jj7Fa4hiYdIgfq+lWDemk7pQw0=;
        b=Q0kXIGWS/p0v3Fwm9M+KxKwzaRwJt5jt/Zy6mDhuzuC7F1qPEr/0ANX5UDvv6IngvJ
         PQG9eQ5X5wulYHlbvE0rG8+WrcD+ReKQ2IqZ/7eVUOmApQx/NXZQOUpkXlZvFLStfEdV
         i0dVgerIrnoVN0eoN8gjO0RPZ/HqkGuxJKmlUsiWsOmaDNGPVVvaopZkwxfR4Rwf/T8O
         tb+2AFtSEubFIEo1TjoXbF3a6HTIxepXo6icVwaVq4/InTDmMy3w9N+kg6oRezz2U8V5
         e/GQF2cDAN+ZhxGiD34uEMtaK1AbNuEDoB4pOQaq9NV6ZZmyfEWBttvH0BkUrjSVK0eU
         isSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7gxECs1b23pOT4624jj7Fa4hiYdIgfq+lWDemk7pQw0=;
        b=Y0ec/tABT9+8KDXXwZO0vh4PTr6yuI747dD1DuV0DB92vXG0fymqkd6g2CzZ17nGEC
         u97azkWGbQIkZcIFu06m3Ov94j0uM3lXD15iw+FFA7lecrMw6y6Z6eUeLrx3qpdMspzg
         VTu5+SRilK4rVHDGcW6dkZsK0ISsDnNQMMjfGGVUxjWNU1vLCA3cC/PsPxIlV05FJeAG
         mgKSk/U2SECjwzR++L/eq1jBmfTqSFxrK6OUOHSJj1cch9BvnUYvQ+hem+vqRmT4+B4/
         cV/TtR5CpZZG/IVJC7UetaqhXzfCc9fbcFn3rqKBOdFfFhh4bBW0OK3Jb+W6mItVNsDo
         qExg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7gxECs1b23pOT4624jj7Fa4hiYdIgfq+lWDemk7pQw0=;
        b=E37r5gxGnEX7ytnzaJNPdKGbIBx+E53fb6QQztbH1lvNA3wywPp6555JAclLCLLlwq
         dOz/MF9YKVAcMc3F3Szay87UvUCAfoK4ffo9oqEz53ajE5rNOdu7K1X/P2f+NXusyIyR
         sGEVgVnDYxmQs81zg6EnC61js5Yz3OBZY3xJtqcF8B1r1BN9VxenxXxG5JTIvn1Vrf/x
         BFB6uYbCCawPeJCi3jy8qfcAw+npnZf+Wb1R87vPrnbPd2Oybxa7sq+CqEUhxsyTKj8Z
         3dc11uyzIRS8PdHe9fP86hxXB4SMVjk+8n6Ph8A0y0QllGqgSM+dAFL/YoAgCWpdbSmZ
         unkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUTH6vFbAnZ3q+Q/W6EixIu5SMABb4fBD7TLStjmSwgipZa6N2m
	0raH80CySfS7L8VIBUzL73Q=
X-Google-Smtp-Source: APXvYqyqkzwlR4orR7YYqQk70phq0J5FRaJgkhVvrzNt9UZaChqie1Sp7nXZa8OqghBm5/3/+KqFgA==
X-Received: by 2002:a7b:cf37:: with SMTP id m23mr84250wmg.53.1568296431364;
        Thu, 12 Sep 2019 06:53:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eacc:: with SMTP id o12ls4306743wrn.5.gmail; Thu, 12 Sep
 2019 06:53:50 -0700 (PDT)
X-Received: by 2002:adf:f812:: with SMTP id s18mr37553309wrp.32.1568296430749;
        Thu, 12 Sep 2019 06:53:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568296430; cv=none;
        d=google.com; s=arc-20160816;
        b=heTgwffmLXV20IyWSIxOyn+P5Ol+chwzihPjTfY1UH4mXUlq1izWBOGdmTF0j7KB+C
         6Xvm/ag1y7Ca8VMw73sSuAlmUMDq0lph7EbRk62Xu/8Iu+VRNbWeSmNwRHFF8I5TuXbN
         Q3/ISCRry53g0NYI1Bf/6b6AhmhyRQ3h4kvig6EhhegaHoEvmoVIOCWcp9XxIVtDeg20
         C4xJXg5l4qMUARXPb038CQuPNNAD7NdjjMCvPdgYG8B8Z6ZwQ3KKa5jyBUYiOay4p/n9
         WorV2P1hDQH3z5SzGkh4vOic9RFFdrjBrFDvLykgI8XRsr/1HTuK3PMkLh/4qBLFOIuP
         94lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=RdkdtKLZBCY+pITVI8UK9xtRHpBoR6viEuOj2dT9DRo=;
        b=ix/ftWmQhAZf4kUBxIe/UZTwheObmJQj3LYKwbvtlrtSL3kZ6/t2jICqLDVsFZa+65
         s7mLiYmj1n+0eyAlKIUcqAhw6a7P25v9isf+MWPPXlcGcFHG5wrufwmQoQM/I5gCHAnn
         sugbZwI41F+NN/W0oRDkScZtI+z14VpAP602HH/biqR6Kd/DSZseGfZACX4XkyP79cWd
         a6pJ97lxnDnWkLLUnEFznCzMNRxIRKWrWWpGLWzKHd7/OTVnA9LAKSqyolLb/+BZln/s
         wx7Eo8lgKhlce1zpiWWjN4voc4tmmaJdHMGzVi2wilqdQsUXyBn2WCTi/+qwyE2odFbY
         ULIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id 5si131063wmf.1.2019.09.12.06.53.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Sep 2019 06:53:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id AD654B7D4;
	Thu, 12 Sep 2019 13:53:49 +0000 (UTC)
Subject: Re: [PATCH v3] mm/kasan: dump alloc and free stack for page allocator
To: Qian Cai <cai@lca.pw>, Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>,
 Andrey Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
 <5E358F4B-552C-4542-9655-E01C7B754F14@lca.pw>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
Date: Thu, 12 Sep 2019 15:53:48 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <5E358F4B-552C-4542-9655-E01C7B754F14@lca.pw>
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

On 9/11/19 5:19 PM, Qian Cai wrote:
> 
> The new config looks redundant and confusing. It looks to me more of a document update
> in Documentation/dev-tools/kasan.txt to educate developers to select PAGE_OWNER and
> DEBUG_PAGEALLOC if needed.
 
Agreed. But if you want it fully automatic, how about something
like this (on top of mmotm/next)? If you agree I'll add changelog
and send properly.

----8<----

From a528d14c71d7fdf5872ca8ab3bd1b5bad26670c9 Mon Sep 17 00:00:00 2001
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 12 Sep 2019 15:51:23 +0200
Subject: [PATCH] make KASAN enable page_owner with free stack capture

---
 include/linux/page_owner.h |  1 +
 lib/Kconfig.kasan          |  4 ++++
 mm/Kconfig.debug           |  5 +++++
 mm/page_alloc.c            |  6 +++++-
 mm/page_owner.c            | 37 ++++++++++++++++++++++++-------------
 5 files changed, 39 insertions(+), 14 deletions(-)

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
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 6c9682ce0254..dc560c7562e8 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -41,6 +41,8 @@ config KASAN_GENERIC
 	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	select STACKDEPOT
+	select PAGE_OWNER
+	select PAGE_OWNER_FREE_STACK
 	help
 	  Enables generic KASAN mode.
 	  Supported in both GCC and Clang. With GCC it requires version 4.9.2
@@ -63,6 +65,8 @@ config KASAN_SW_TAGS
 	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	select STACKDEPOT
+	select PAGE_OWNER
+	select PAGE_OWNER_FREE_STACK
 	help
 	  Enables software tag-based KASAN mode.
 	  This mode requires Top Byte Ignore support by the CPU and therefore
diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index 327b3ebf23bf..a71d52636687 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -13,6 +13,7 @@ config DEBUG_PAGEALLOC
 	depends on DEBUG_KERNEL
 	depends on !HIBERNATION || ARCH_SUPPORTS_DEBUG_PAGEALLOC && !PPC && !SPARC
 	select PAGE_POISONING if !ARCH_SUPPORTS_DEBUG_PAGEALLOC
+	select PAGE_OWNER_FREE_STACK if PAGE_OWNER
 	---help---
 	  Unmap pages from the kernel linear mapping after free_pages().
 	  Depending on runtime enablement, this results in a small or large
@@ -62,6 +63,10 @@ config PAGE_OWNER
 
 	  If unsure, say N.
 
+config PAGE_OWNER_FREE_STACK
+	def_bool n
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
index dee931184788..d4551d7012d0 100644
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
@@ -46,6 +48,11 @@ static int __init early_page_owner_param(char *buf)
 	if (strcmp(buf, "on") == 0)
 		page_owner_disabled = false;
 
+	if (IS_ENABLED(CONFIG_KASAN)) {
+		page_owner_disabled = false;
+		page_owner_free_stack_disabled = false;
+	}
+
 	return 0;
 }
 early_param("page_owner", early_page_owner_param);
@@ -91,6 +98,8 @@ static void init_page_owner(void)
 	register_failure_stack();
 	register_early_stack();
 	static_branch_enable(&page_owner_inited);
+	if (!page_owner_free_stack_disabled)
+		static_branch_enable(&page_owner_free_stack);
 	init_early_allocated_pages();
 }
 
@@ -148,11 +157,11 @@ void __reset_page_owner(struct page *page, unsigned int order)
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
 
@@ -161,8 +170,8 @@ void __reset_page_owner(struct page *page, unsigned int order)
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
@@ -451,14 +460,16 @@ void __dump_page_owner(struct page *page)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c4d2518f-4813-c941-6f47-73897f420517%40suse.cz.
