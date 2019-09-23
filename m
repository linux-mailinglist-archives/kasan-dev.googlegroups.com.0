Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB3UAULWAKGQE2PNXMNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id F18E9BAF3E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2019 10:21:02 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id t13sf9025832edr.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2019 01:21:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569226862; cv=pass;
        d=google.com; s=arc-20160816;
        b=U31bnrobB4EhJmifqo+gdUlTmOVbuwFiMUrSU7Qi8a/C4f8goTrJ/2od/OvXZ2kLmW
         v+2MNJ5LvYTiLosK4EdkyxOcHXtZqPoM6GS9DNU2sOsQUzTq92q+y/B6F3Mn8C59OOok
         4UVPsI2XsYedujm3TQXtDxatAo51ia9P62Kpyc7C0h+HxmJwh+z80BLL0ggWq66RMu42
         t+kRS9QLE+m+pMCtkMIFA38/bZeyyuWXNbEZpdrlmBnJ6kwMTh8H7ekoRzFua+JBr4Fs
         OMY7zW134p5KVUqLfLdMer+aNetFVhrTLirEihBWsnSc5wQCCBaU969ECCmx1gr884/I
         IqBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=wL4dbeQbOSyRzpRp5G7oIyFYHQnWmu1rgWONFChO9mQ=;
        b=iLa0bm5Q94HXsd494Cowgqdo8SXcscuCN3R7NWR/ChpL7FaIbdFSPdw1iWFRWxRZPI
         5m13TZnBDF2uff1YoG6eVu2Cn/W0lIRiaVIEsDGYfXML+/wqePrhGbE01M+DjeuYprV8
         gzhCpOrKgcmuyOjLvnSeKWlYqWBrDtsRP1zPa5ibAXVZWSXBr1iXM/DMpIgRKyF0YeWL
         zhhBWVIZE3QX4aczxDLdpMUMtcdEz0Tw7kipYTMQHIicOegOeaUsWjupYUEaJreloi3e
         gsQqx5trbKXRck14NCXXz0mhtGrM849n5NM3iZmemV1wx0bckamKjzHIa+1keBWeO7oT
         3Ejw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wL4dbeQbOSyRzpRp5G7oIyFYHQnWmu1rgWONFChO9mQ=;
        b=KU5ncxj8XU7ERBLFDcWj108QUgLePDyB/zva3jU66RovHjD3v5WJPpA02AiPihMmd4
         bhXISGk+S6+DrGUfbNN0zeN0s9x3rbvukLIQu3RmpzgZH3hmtuo4kniWDhlsR5ypw6uF
         mxDLwTYeaVJqkfOJ663RPIr6IpMTrWCNI9aCk3AF29x/cWeubtduGetXsyZxdJHS8Q0+
         AO04tp8WHt5k8OWGQeh1VLkqiBXfhrUkwK1Igc0ooa1GntcKIGz8xl5oDWkUzVuNLDlM
         wF7I6jUow8M2hWEHz2SFUkpoptKl39D4JVENAJjgiYLtfzs1dnngRbOZu1ulO27b2sgR
         whXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wL4dbeQbOSyRzpRp5G7oIyFYHQnWmu1rgWONFChO9mQ=;
        b=DoELW8GR1rdLNCXRdNfSbdgU7ugJG4DpLp8MPDuBir57Am176mkheGF5KfTIa8IXyi
         zydxo0qHQFpEqcmMmbbi9ikbfAxlwhw3yi+paJ0a85rZUz4OX1/yH03Dsvd6C63aZZyD
         lzoNIk2vwGKjryC5dDh3KPYxDsmley2tgA26tRVz7Ow8CzPtnKBI+MGyKqfq9QN+rH8Q
         ufLygW4IOlWIchF4SHrG7V7/UbuDPvO5kZrlmy9W6IaPVCKne9dyy+Pcf6JHcPVMKi0L
         Z7V+3cHjX2425qpGT4EGZyEYhEHl9QuD0Qyh3O6CjV2ynEXUx5vvxUD/CEaDkFls/ivr
         xYuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVdsXGSaxSWXIMlRyOOAE/CCm2TlY7rj6duHU8jz+PQYVz8m3VR
	VZ60acWpn7A1gOv6YZu6ei8=
X-Google-Smtp-Source: APXvYqxmFVAjyp9smQCvkYA99nxy96u6b3NkhDl76yrJQFcfloVZ+PTIx6ODyS9s55B7ErSe+GjGbQ==
X-Received: by 2002:a17:906:168f:: with SMTP id s15mr28324537ejd.109.1569226862609;
        Mon, 23 Sep 2019 01:21:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d98d:: with SMTP id u13ls59476eds.12.gmail; Mon, 23 Sep
 2019 01:21:02 -0700 (PDT)
X-Received: by 2002:a50:ac03:: with SMTP id v3mr35726120edc.113.1569226862109;
        Mon, 23 Sep 2019 01:21:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569226862; cv=none;
        d=google.com; s=arc-20160816;
        b=hOb9aRjZOoEwzvyNq55egVnnqyqF6ahuErG5SQXsufUpqSk3c3jXLmU9xVeHp5J/g7
         RQgExzBZ+M3aWuOUvKcfgSNiPQmoJKHJra3Z3/oY1csNp+EEWK5HqQ5uKcp9IDGum4Hf
         G15gPRkmCFuXPJ2ut5JG8g16qSHoQyDPiRKsGPrZJdVLwmD+52KqPZh43a0B+AKrPoHE
         9QeA+T7SpjhQ3QTvSrNqABD97OV7qibmrv9T17VyehKWMqubpACQ8rMcSciRb5QxIKkp
         PQpln8r//Y4T+uggOXubgdqu/KZm1wSZGIUrYFkEL/3mXozgI9G+bJJiSbUYSzQu2V6U
         /tig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=jdSqg+UUGVQnSY8ltldMRLzBxb5XNJ23zU+siPY55+M=;
        b=IGZnGF7NpJnFfRAWFpxg+kfDoFwK+nSJtH5Y9ptUff7Gedn4UpCj8yV3W6a1heQetz
         Ihga4pcf2yQ6w1iO0wUa/N96sksUa0ANZm3GKlZfqjNROfDo/jfvAbEbtFk/krYc3qln
         +6RRp2BxdnVIWimcUSjbdqImfWTWISUFMU85KeSFrFuHMdXh6yt5uwp11GUHcAztXeUY
         TdLw6Lfu01ZRdkxsgDxXiJrXQL4sPX3eHdnfES45fV2H6em1zmq87qkobNtVcUY32Dzs
         j27UpmC4sMkcZj/Skk8ucM/Y6rTI3Bjs1x4eC19uL//MzcfE9rzwAut11k2tptX6IHRu
         1lTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id r3si789822eds.2.2019.09.23.01.21.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Sep 2019 01:21:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 1B798ACE3;
	Mon, 23 Sep 2019 08:21:01 +0000 (UTC)
Subject: [PATCH] mm, debug, kasan: save and dump freeing stack trace for kasan
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
 <6d58ce86-b2a4-40af-bf40-c604b457d086@suse.cz>
 <4e76e7ce-1d61-524a-622b-663c01d19707@virtuozzo.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <d98bf550-367d-0744-025a-52307248ec82@suse.cz>
Date: Mon, 23 Sep 2019 10:20:59 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <4e76e7ce-1d61-524a-622b-663c01d19707@virtuozzo.com>
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

On 9/16/19 5:57 PM, Andrey Ryabinin wrote:
> I'd rather keep all logic in one place, i.e. "if (!page_owner_disabled && (IS_ENABLED(CONFIG_KASAN) || debug_pagealloc_enabled())"
> With this no changes in early_debug_pagealloc() required and CONFIG_DEBUG_PAGEALLOC_ENABLE_DEFAULT=y should also work correctly.

OK.

----8<----

From 7437c43f02682fdde5680fa83e87029f7529e222 Mon Sep 17 00:00:00 2001
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
index dee931184788..8b6b05676158 100644
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
@@ -451,14 +454,16 @@ void __dump_page_owner(struct page *page)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d98bf550-367d-0744-025a-52307248ec82%40suse.cz.
