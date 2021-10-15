Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB24EUWFQMGQEWFI62MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A1AA42ECEB
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Oct 2021 10:57:16 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id u23-20020a50a417000000b003db23c7e5e2sf7641247edb.8
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Oct 2021 01:57:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634288236; cv=pass;
        d=google.com; s=arc-20160816;
        b=hCPPOMAtfCdlqtF4WbBqa+plbXZzEcujBe+YUmiWtYmaKH9+rWcS9M4weu4m46Rte1
         u5uf7w/zEC6/9J+5HSPuMFlfRkZJRePg0M2v74jKuUiE6VvbF8PWY0K2YfRNMdXVCBT8
         ExUT++mlFQO0YvxgqM/4E+7Em8PMwNG2v9JfU5zHUGoRtDvEFdO4bJ+Gg8L2/O00BTld
         6vNekeJl0gn0oudFWLd+XJxUK08wUFN/2ClkH0XJkWYljCs+ihf4p4rtaI9JdoK05TqT
         grfO3+tHNJyYU1h4CXD9RZ4FCm0rvy91XlXVMrGlCvxDecKo5YklOQer71CVAO0IOwHU
         V9Xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=8HGW1M23ss3L/92Eb4cgu475wdQANN5CNzyrmi6BPGM=;
        b=09k+LMHmXVA/h6rk/nhjxOFeSJWuktfp/fBO2eZBgjL8h/Xw+ZJ32O4bb8Wd/8Rfmc
         i5075xdfL3w018wDGZojNQu2iVsUbqm7rP4hTfez7szE075ABeH06rzwBrLurNoULWU5
         N2CmwsN4FfESlfaxZv5kMPBSS/uZP4I/SgIRiNW9h1B3yjIT9Vj79iOVwwwZ0Y7iTrQo
         /LkJRYpcXqqTshMHxd4nhLsK9JOL3x/PhQ19sQfZnlB9VvLxJcrcxXfuz8L345oKkKNd
         8GuG8DCw3E8Bn5psPrcTBKdHlrN9JE6XRDGDH68biOhkIbhQEmuZxB7Eh87x5AQ9bqgV
         iXEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="F/r+O+h+";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=8Ac48pcX;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8HGW1M23ss3L/92Eb4cgu475wdQANN5CNzyrmi6BPGM=;
        b=QP84qYgGI27dWVy8CemUFCfPPlqnrbZ3zWC4uj4WrlUlscyXx2xeAEJA60GwYHkaDy
         MtyvMO0H9JQZdcu966N+zbjOGE84TOlqttIMZ2j2QuEjgejQySzENyYe47sv7S1bLue0
         ya7Juav4GKvZLPBlzbssOC+eA7uABaJyQQ34btDLQYTCzdqnmJzx90C2KaCEKDDdtM77
         D9YvnD6GoiMBq4gIrtA5sjcjE46CAMSYnbBNVXKsspzK4dilQnbIAOac7P3F37XebwHH
         wENESSeUkpRzggxvhKFTl+TYokzL5tXWs66ubRxT6YVpx3v1fQMeal3fkQe/XDqEwAfK
         o1Jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8HGW1M23ss3L/92Eb4cgu475wdQANN5CNzyrmi6BPGM=;
        b=BZdsLahzu5wUvaBQBemSJ1MWrmZgy8bsl8loSdNXPjmZJm7eYZQpS5dM6Sz9XWcgb0
         nhq4DoFjfTXRtj+mlveiz0QtKodJjjw+oaU3+5dKziinZL17i2t1k7kZMgxSQUkvG32F
         E1qAFC/4rckGnZPybXgFYNfpgP/SYt/C0KizkmWsQLCtpRV+GqBpCZCLxwlrVwM2dRPD
         9tUo+I63tsHsYDJFbIqtiGi6j0q//9FlasyWBC49BNzDxhhxOOwrv/oa1KPokmqF/1QV
         OA4Y56hvFxrGoilB6z6yodvSeeVyUrQSWqkPFegWOhYLh3S6GA1IDqeMNgIEMh7XBt9G
         BBuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530I7C90d3kyoALuSA2qxAF9mV1IwixtAk8kHnQrO8fPMZGBx+R3
	ZSIi4Qbu0Ke2YRJX8J6xrXw=
X-Google-Smtp-Source: ABdhPJz9La8AKvw3Gbk3dNiJPdIaAHdfrbrMcZofd7oBLBlKgEMb5jAd2nd5eTUXgJgtMacyfye1Lg==
X-Received: by 2002:a17:907:76e1:: with SMTP id kg1mr5347693ejc.329.1634288236040;
        Fri, 15 Oct 2021 01:57:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:8d88:: with SMTP id ry8ls3194159ejc.6.gmail; Fri, 15
 Oct 2021 01:57:15 -0700 (PDT)
X-Received: by 2002:a17:906:d937:: with SMTP id rn23mr5297591ejb.101.1634288234963;
        Fri, 15 Oct 2021 01:57:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634288234; cv=none;
        d=google.com; s=arc-20160816;
        b=bog1rv+xZnUAju6lTzPvpMsdROu6/tOoWoU78RdDUPxEcUtGtbkbQOq7Cnpwy21s8D
         vspBUnw9t5TnHWWmRUqBCDz48AjPEt5FWKs6LAsUdWJ9vfp+uSh85b2XjZ0tmHVqaNLJ
         xpLIedLHzCLo1aeDjk0wzPgO4LdW5iZnB7/Ks4PzEKWlryw01LI5GLuNZ2NuWNBo1Zey
         4yPDNEfkddc7gjWCVTbsukdIn0pn0qPV0GREzsbTKffySXjVndhqIVnfWPvi6TCcswmh
         C0gKITx1/NARBMUanq9zxQuQ7FuGZ9O7AKDOKmvTRXWj3ZFEqc0sDEPg2QktBHS10zgV
         tVZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=1gJCQ4LKq38Wz8fQyxCuZehL+Con9ahBr+7Hnu4iI6I=;
        b=KnSWb2helVLwhA0moB0f7st7QEoZVydlxveD+ae6PIC5vLws0Hsi92YDoCpyM39FqX
         6gec5q9fmBHcEn2x8HK5+AaghYA3XwQmW2vRkKkA5Kj+/Jb3dv/0aLrpA/5mGzFogiH3
         D7qKL6sn8sz5aWl/t2ROQl665c2hv0w+5Hx6HfpVFuE8JMrRIx+bOJGGt7z/QYV7ixGS
         zumbXDs3+KnCnwwiRiOTlRsofh1WQTxep6L0tRe1huaAtyxvZLftWftu+e5aRKs2L43g
         DhG83Tqhe2HwncYHezuQerqCswTYEEKo6NuOWp14xyv8amHzsSzUBVZ+xpTgG2S6tjtP
         7t1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="F/r+O+h+";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=8Ac48pcX;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id r21si346983edq.2.2021.10.15.01.57.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Oct 2021 01:57:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 7E2EF21A5C;
	Fri, 15 Oct 2021 08:57:14 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3098F13B87;
	Fri, 15 Oct 2021 08:57:14 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id CuQlC2pCaWHeIgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 15 Oct 2021 08:57:14 +0000
Message-ID: <6abd9213-19a9-6d58-cedc-2414386d2d81@suse.cz>
Date: Fri, 15 Oct 2021 10:57:13 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: [PATCH v3] lib/stackdepot: allow optional init and stack_table
 allocation by kvmalloc()
Content-Language: en-US
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
 Marco Elver <elver@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>,
 Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann <tzimmermann@suse.de>,
 David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Geert Uytterhoeven <geert@linux-m68k.org>, Oliver Glitta
 <glittao@gmail.com>, Imran Khan <imran.f.khan@oracle.com>,
 Mike Rapoport <rppt@kernel.org>, kernel test robot <oliver.sang@intel.com>
References: <20211012090621.1357-1-vbabka@suse.cz>
 <20211013073005.11351-1-vbabka@suse.cz>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20211013073005.11351-1-vbabka@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="F/r+O+h+";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=8Ac48pcX;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/13/21 09:30, Vlastimil Babka wrote:
> Currently, enabling CONFIG_STACKDEPOT means its stack_table will be allocated
> from memblock, even if stack depot ends up not actually used. The default size
> of stack_table is 4MB on 32-bit, 8MB on 64-bit.
> 
> This is fine for use-cases such as KASAN which is also a config option and
> has overhead on its own. But it's an issue for functionality that has to be
> actually enabled on boot (page_owner) or depends on hardware (GPU drivers)
> and thus the memory might be wasted. This was raised as an issue [1] when
> attempting to add stackdepot support for SLUB's debug object tracking
> functionality. It's common to build kernels with CONFIG_SLUB_DEBUG and enable
> slub_debug on boot only when needed, or create only specific kmem caches with
> debugging for testing purposes.
> 
> It would thus be more efficient if stackdepot's table was allocated only when
> actually going to be used. This patch thus makes the allocation (and whole
> stack_depot_init() call) optional:
> 
> - Add a CONFIG_STACKDEPOT_ALWAYS_INIT flag to keep using the current
>   well-defined point of allocation as part of mem_init(). Make CONFIG_KASAN
>   select this flag.
> - Other users have to call stack_depot_init() as part of their own init when
>   it's determined that stack depot will actually be used. This may depend on
>   both config and runtime conditions. Convert current users which are
>   page_owner and several in the DRM subsystem. Same will be done for SLUB
>   later.
> - Because the init might now be called after the boot-time memblock allocation
>   has given all memory to the buddy allocator, change stack_depot_init() to
>   allocate stack_table with kvmalloc() when memblock is no longer available.
>   Also handle allocation failure by disabling stackdepot (could have
>   theoretically happened even with memblock allocation previously), and don't
>   unnecessarily align the memblock allocation to its own size anymore.
> 
> [1] https://lore.kernel.org/all/CAMuHMdW=eoVzM1Re5FVoEN87nKfiLmM2+Ah7eNu2KXEhCvbZyA@mail.gmail.com/
...
> ---
> Changes in v3:
> - stack_depot_init_mutex made static and moved inside stack_depot_init()
>   Reported-by: kernel test robot <lkp@intel.com>
> - use !stack_table condition instead of stack_table == NULL
>   reported by checkpatch on freedesktop.org patchwork

The last change above was missing because I forgot git commit --amend before
git format-patch. More importantly there was a bot report for FLATMEM. Please
add this fixup. Thanks.

----8<----
From a971a1670491f8fbbaab579eef3c756a5263af95 Mon Sep 17 00:00:00 2001
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 7 Oct 2021 10:49:09 +0200
Subject: [PATCH] lib/stackdepot: allow optional init and stack_table
 allocation by kvmalloc() - fixup

On FLATMEM, we call page_ext_init_flatmem_late() just before kmem_cache_init()
which means stack_depot_init() (called by page owner init) will not recognize
properly it should use kvmalloc() and not memblock_alloc(). memblock_alloc()
will also not issue a warning and return a block memory that can be invalid and
cause kernel page fault when saving stacks, as reported by the kernel test
robot [1].

Fix this by moving page_ext_init_flatmem_late() below kmem_cache_init() so that
slab_is_available() is true during stack_depot_init(). SPARSEMEM doesn't have
this issue, as it doesn't do page_ext_init_flatmem_late(), but a different
page_ext_init() even later in the boot process.

Thanks to Mike Rapoport for pointing out the FLATMEM init ordering issue.

While at it, also actually resolve a checkpatch warning in stack_depot_init()
from DRM CI, which was supposed to be in the original patch already.

[1] https://lore.kernel.org/all/20211014085450.GC18719@xsang-OptiPlex-9020/

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
Reported-by: kernel test robot <oliver.sang@intel.com>
---
 init/main.c      | 7 +++++--
 lib/stackdepot.c | 2 +-
 2 files changed, 6 insertions(+), 3 deletions(-)

diff --git a/init/main.c b/init/main.c
index ca2765c8e45c..0ab632f681c5 100644
--- a/init/main.c
+++ b/init/main.c
@@ -845,9 +845,12 @@ static void __init mm_init(void)
 	stack_depot_early_init();
 	mem_init();
 	mem_init_print_info();
-	/* page_owner must be initialized after buddy is ready */
-	page_ext_init_flatmem_late();
 	kmem_cache_init();
+	/*
+	 * page_owner must be initialized after buddy is ready, and also after
+	 * slab is ready so that stack_depot_init() works properly
+	 */
+	page_ext_init_flatmem_late();
 	kmemleak_init();
 	pgtable_init();
 	debug_objects_mem_init();
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 049d7d025d78..1f8ea6d0899b 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -172,7 +172,7 @@ __ref int stack_depot_init(void)
 	static DEFINE_MUTEX(stack_depot_init_mutex);
 
 	mutex_lock(&stack_depot_init_mutex);
-	if (!stack_depot_disable && stack_table == NULL) {
+	if (!stack_depot_disable && !stack_table) {
 		size_t size = (STACK_HASH_SIZE * sizeof(struct stack_record *));
 		int i;
 
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6abd9213-19a9-6d58-cedc-2414386d2d81%40suse.cz.
