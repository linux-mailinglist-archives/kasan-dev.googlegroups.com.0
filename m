Return-Path: <kasan-dev+bncBC7OD3FKWUERBJXKUKXQMGQE7A7D5JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id BB190873E99
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:43 +0100 (CET)
Received: by mail-ua1-x940.google.com with SMTP id a1e0cc1a2514c-7cede81ecf8sf1235771241.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749542; cv=pass;
        d=google.com; s=arc-20160816;
        b=gAbwiEVDEfipVeJnuJpH4FOjnE1BpTz3RfCLZrCYhwsBx+s313+Tjd3Sy5J7wcoM7D
         rM4YCq/gLNTJnA/2Fy3TlGq3CHrzCmaCM5jzD3AyWvdR5xMoMJUdvPIBG1TmsdqrkIyk
         qqR/NYeYxyHBXDiFdtGzRXq2Pvp02relRSoCVv58EfRVsanDg+/+JbQNkMijRp+NWaLv
         rTTv31gosVSt7XW4dTv1hoI2XHTz56+EzvcWMY4IYyIhbNW2NWcYutyLIGMzvjszlaZV
         fo85EzESYvtN3gXAUCsivAocNCJnUycwLbmI7N16jO0+Yd0BXWV7oyXbpIrJf2vgpmcl
         iOWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=dlpuz0vJA12f4KhK46Nguj+2kmPrFSXsPIXuMUTMbqo=;
        fh=tYS2wOQ6FQKAm8XmjVrmWTIl2pobaTE7eh0e9SiNWLg=;
        b=twBKk+h9HNZUe9ERvDibNyiwE8M3/EcklkC03+3f7P0WgQRGp9yD4Q2/NBHceBSbf/
         FZMFN67ukksTN7FVCHJSqrLohJTtXcv2TDTon2jlvlAV63PdD9Ts3SG6CSDvul4MDurr
         1o+D51sUMMjsXC2v3+tfupxlxx5edvKEoJFexKRqgOMY+j5F2N7fBlimWnSPuG9gNK3b
         ak3M85J81SJxwo9LC2jzHm4JUc3C3+6I40GDAiiVr7TieffILOBO3yYJ6HnpkteMS8Ky
         USx2yUveP3bO75L9COcguLdT4f0JQwS6VGPBxIJtHMtOfy+TSKjDvPqRjSDARoAU8pMd
         bnXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AfUmsDO5;
       spf=pass (google.com: domain of 3jbxozqykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3JbXoZQYKCWgYaXKTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749542; x=1710354342; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dlpuz0vJA12f4KhK46Nguj+2kmPrFSXsPIXuMUTMbqo=;
        b=P/Z/S3JnrIYHu3dIc+p80yKKRn8fLhP8BAhrfOIZ1sj+yw8Km5eqKAqysViMqJzEVu
         oLuT3uo09RqrDoNPzoPrRwAGUZLpSznTFuvn0vrOnj0OtyuFTq09Um3mdhdlFegRmeyM
         DqaI+eZPSc1Fgi8z60lV06y6ydzPCKaxRm9E4r/WSCKISzU+bb70+iXS9KJB54t4/1ik
         fTMEubGTDhg8Illjm/xyuFzmXAty1N56DLegJOg0okd4fWIdi1uCBi0rTCDs9sAjC2vC
         fUyrTWZi/WYe0otwdbbs0Gm5sfJa0sepHRqFzl1hpaz09Z2axqm9V9BZLm08KEsZxM6p
         i9JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749542; x=1710354342;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dlpuz0vJA12f4KhK46Nguj+2kmPrFSXsPIXuMUTMbqo=;
        b=gvRxdF21aUZ+vYtOa9tvwWOBah8/ok+usLbG2cafgGUq5cB5UZDcgb2bFCZcwBgSll
         36XEkh3uuNwo5Pq6fF+Hp5EukAPhUTk+Rogc0rV6442su1mdkGlJ5I0TtroSANopI3jU
         bVf4i+NPGJNB8n5NeP6LXmlw2nDbDXBYcZmCsK74m1wyL6dtjfdqzJ3hg3QMzPig1Lgw
         /8RCIF0hdLbgyZUZ3feIbMqiFCkFM+NpLpA1lWmfnBBhP/RI7bk8mf6VfjoYQBf6lGai
         meVyy3mF8tVyajfzojHawtljp5/ivnhBa3cBKNwPKAOKvVfdiRikgYQLfB7myiHz9tlF
         sXBA==
X-Forwarded-Encrypted: i=2; AJvYcCUvhwe/TNTkME91OyK0rGcdcMBa8D/s45qufYIgYZ3TXrXMade0JLrlNVGSJ0FwV57s5SXALWRFcmla2uVomhC+VmPndoD5WQ==
X-Gm-Message-State: AOJu0YwcLMXLj1rlKx4kTy5IXAd9fO4Lue8uMlr/Hmi0ooyBA0G+Sn6G
	BFEZXpCgiRWj+lSWSu/mXlLafL3Pxs/8LzbSKqecrkHiJJM5OLVY
X-Google-Smtp-Source: AGHT+IF+TtzDlM6n7v7NlP2xh4vbRlgWxjK5qz2FBRL79GVCb0OnMLI4MEMemMkSDUjpCGa8LtnBFA==
X-Received: by 2002:a67:f918:0:b0:472:6e7f:888b with SMTP id t24-20020a67f918000000b004726e7f888bmr5566869vsq.32.1709749542526;
        Wed, 06 Mar 2024 10:25:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:40e:b0:68f:58a7:be1b with SMTP id
 z14-20020a056214040e00b0068f58a7be1bls62846qvx.1.-pod-prod-09-us; Wed, 06 Mar
 2024 10:25:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUY0OG44nOs/Upgk+IA+YlNbe66BYHJnJHAwahyYkXoYpYAzMThJhpDci6OT9rHNoWcQpn8J6xIIMXspjPC/va1JTSMBsfpGVws7g==
X-Received: by 2002:a05:620a:3de:b0:787:9863:eb7b with SMTP id r30-20020a05620a03de00b007879863eb7bmr5674364qkm.74.1709749541678;
        Wed, 06 Mar 2024 10:25:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749541; cv=none;
        d=google.com; s=arc-20160816;
        b=IA0I8N5RTrlfqVnzWuw5pOkZdoXxmS2mpl5+v/IrrQNv4ANccBggy5HaBDi+GkpB1h
         wW/q7LpnlTIBvZUsG07PKsg0eFW1kjNcQOhTSGmrr8qVl7aktjV8op8diIdx0GuD1Y/L
         +CtbpCQGZt9i2ING9yCoAbsHcCU7il/IXIvceSTWUn9Ns25u6yCzkg8P20NhBGQZGiUL
         5olUBSYbeZ9v5yCrMbky1qMQiViS1oipFuDPNuhoEbQE/nnU7XKEOb5CzQIc9YmEhKHu
         0/3YraBzXe/5pr2ch79ey2FaZeAAXoQ5NLv9xoq9g2msG9nGYJd5znLZ6T/yz8+05W2F
         Kk7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=iFNwLDi8a6FCybl7tYSum2P7lYcwvuLcMH/fhzJCtO0=;
        fh=AzeCi46r2G59bQLMFtXZoKDWTjzdhHIbuFy22L+LKGQ=;
        b=q96gkxsXgAad1ipbz9YM5a48Sf0r6CR75JYnXCCNXo3+JWbRz30xhmRbkDgTkXv8Jh
         et5az8XkD7BJ2mL57dLsj3AzWSui7kAXaPzG1CPTgalYfR259DfqxoQah8oEW9Kd2XB4
         FxTj5ohN4zjhTw4e4+i6YZOIAsyo0IysBdGRlv5aUXdD1VYn9jwT4HIuFfR+XosaPcvg
         K8CDM/oXvZSV9Xt7R81ZTXRm0bYwhCaN2pV6Iih3DMhKbQvYDUMfzC1iCaeOz13f9O4f
         Nc1ZfvTePNx4RtBXdOvGflocozR8PZi3ezIAsd1D2dYZB5Atgi/25eXAiyEH6bUbHx1n
         nHIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AfUmsDO5;
       spf=pass (google.com: domain of 3jbxozqykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3JbXoZQYKCWgYaXKTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id br12-20020a05620a460c00b00788451a2852si3823qkb.5.2024.03.06.10.25.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jbxozqykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60904453110so165907b3.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXrV7e/X9W8IHElpc8GpgmX0mL9MVGBrgQ70TeiebhZzoiZv1aSZpWkOooN6w3Fg3wsL6L6Ju7crKuHNlvOiLzjRs5acyNIoSJgtQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:690c:3504:b0:608:769c:d72a with SMTP id
 fq4-20020a05690c350400b00608769cd72amr4800532ywb.5.1709749541184; Wed, 06 Mar
 2024 10:25:41 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:24 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-27-surenb@google.com>
Subject: [PATCH v5 26/37] mempool: Hook up to memory allocation profiling
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=AfUmsDO5;       spf=pass
 (google.com: domain of 3jbxozqykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3JbXoZQYKCWgYaXKTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

This adds hooks to mempools for correctly annotating mempool-backed
allocations at the correct source line, so they show up correctly in
/sys/kernel/debug/allocations.

Various inline functions are converted to wrappers so that we can invoke
alloc_hooks() in fewer places.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/mempool.h | 73 ++++++++++++++++++++---------------------
 mm/mempool.c            | 36 ++++++++------------
 2 files changed, 49 insertions(+), 60 deletions(-)

diff --git a/include/linux/mempool.h b/include/linux/mempool.h
index 7be1e32e6d42..69e65ca515ee 100644
--- a/include/linux/mempool.h
+++ b/include/linux/mempool.h
@@ -5,6 +5,8 @@
 #ifndef _LINUX_MEMPOOL_H
 #define _LINUX_MEMPOOL_H
 
+#include <linux/sched.h>
+#include <linux/alloc_tag.h>
 #include <linux/wait.h>
 #include <linux/compiler.h>
 
@@ -39,18 +41,32 @@ void mempool_exit(mempool_t *pool);
 int mempool_init_node(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
 		      mempool_free_t *free_fn, void *pool_data,
 		      gfp_t gfp_mask, int node_id);
-int mempool_init(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
+
+int mempool_init_noprof(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
 		 mempool_free_t *free_fn, void *pool_data);
+#define mempool_init(...)						\
+	alloc_hooks(mempool_init_noprof(__VA_ARGS__))
 
 extern mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
 			mempool_free_t *free_fn, void *pool_data);
-extern mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
+
+extern mempool_t *mempool_create_node_noprof(int min_nr, mempool_alloc_t *alloc_fn,
 			mempool_free_t *free_fn, void *pool_data,
 			gfp_t gfp_mask, int nid);
+#define mempool_create_node(...)					\
+	alloc_hooks(mempool_create_node_noprof(__VA_ARGS__))
+
+#define mempool_create(_min_nr, _alloc_fn, _free_fn, _pool_data)	\
+	mempool_create_node(_min_nr, _alloc_fn, _free_fn, _pool_data,	\
+			    GFP_KERNEL, NUMA_NO_NODE)
 
 extern int mempool_resize(mempool_t *pool, int new_min_nr);
 extern void mempool_destroy(mempool_t *pool);
-extern void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask) __malloc;
+
+extern void *mempool_alloc_noprof(mempool_t *pool, gfp_t gfp_mask) __malloc;
+#define mempool_alloc(...)						\
+	alloc_hooks(mempool_alloc_noprof(__VA_ARGS__))
+
 extern void *mempool_alloc_preallocated(mempool_t *pool) __malloc;
 extern void mempool_free(void *element, mempool_t *pool);
 
@@ -62,19 +78,10 @@ extern void mempool_free(void *element, mempool_t *pool);
 void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data);
 void mempool_free_slab(void *element, void *pool_data);
 
-static inline int
-mempool_init_slab_pool(mempool_t *pool, int min_nr, struct kmem_cache *kc)
-{
-	return mempool_init(pool, min_nr, mempool_alloc_slab,
-			    mempool_free_slab, (void *) kc);
-}
-
-static inline mempool_t *
-mempool_create_slab_pool(int min_nr, struct kmem_cache *kc)
-{
-	return mempool_create(min_nr, mempool_alloc_slab, mempool_free_slab,
-			      (void *) kc);
-}
+#define mempool_init_slab_pool(_pool, _min_nr, _kc)			\
+	mempool_init(_pool, (_min_nr), mempool_alloc_slab, mempool_free_slab, (void *)(_kc))
+#define mempool_create_slab_pool(_min_nr, _kc)			\
+	mempool_create((_min_nr), mempool_alloc_slab, mempool_free_slab, (void *)(_kc))
 
 /*
  * a mempool_alloc_t and a mempool_free_t to kmalloc and kfree the
@@ -83,17 +90,12 @@ mempool_create_slab_pool(int min_nr, struct kmem_cache *kc)
 void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data);
 void mempool_kfree(void *element, void *pool_data);
 
-static inline int mempool_init_kmalloc_pool(mempool_t *pool, int min_nr, size_t size)
-{
-	return mempool_init(pool, min_nr, mempool_kmalloc,
-			    mempool_kfree, (void *) size);
-}
-
-static inline mempool_t *mempool_create_kmalloc_pool(int min_nr, size_t size)
-{
-	return mempool_create(min_nr, mempool_kmalloc, mempool_kfree,
-			      (void *) size);
-}
+#define mempool_init_kmalloc_pool(_pool, _min_nr, _size)		\
+	mempool_init(_pool, (_min_nr), mempool_kmalloc, mempool_kfree,	\
+		     (void *)(unsigned long)(_size))
+#define mempool_create_kmalloc_pool(_min_nr, _size)			\
+	mempool_create((_min_nr), mempool_kmalloc, mempool_kfree,	\
+		       (void *)(unsigned long)(_size))
 
 /*
  * A mempool_alloc_t and mempool_free_t for a simple page allocator that
@@ -102,16 +104,11 @@ static inline mempool_t *mempool_create_kmalloc_pool(int min_nr, size_t size)
 void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data);
 void mempool_free_pages(void *element, void *pool_data);
 
-static inline int mempool_init_page_pool(mempool_t *pool, int min_nr, int order)
-{
-	return mempool_init(pool, min_nr, mempool_alloc_pages,
-			    mempool_free_pages, (void *)(long)order);
-}
-
-static inline mempool_t *mempool_create_page_pool(int min_nr, int order)
-{
-	return mempool_create(min_nr, mempool_alloc_pages, mempool_free_pages,
-			      (void *)(long)order);
-}
+#define mempool_init_page_pool(_pool, _min_nr, _order)			\
+	mempool_init(_pool, (_min_nr), mempool_alloc_pages,		\
+		     mempool_free_pages, (void *)(long)(_order))
+#define mempool_create_page_pool(_min_nr, _order)			\
+	mempool_create((_min_nr), mempool_alloc_pages,			\
+		       mempool_free_pages, (void *)(long)(_order))
 
 #endif /* _LINUX_MEMPOOL_H */
diff --git a/mm/mempool.c b/mm/mempool.c
index dbbf0e9fb424..c47ff883cf36 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -240,17 +240,17 @@ EXPORT_SYMBOL(mempool_init_node);
  *
  * Return: %0 on success, negative error code otherwise.
  */
-int mempool_init(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
-		 mempool_free_t *free_fn, void *pool_data)
+int mempool_init_noprof(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
+			mempool_free_t *free_fn, void *pool_data)
 {
 	return mempool_init_node(pool, min_nr, alloc_fn, free_fn,
 				 pool_data, GFP_KERNEL, NUMA_NO_NODE);
 
 }
-EXPORT_SYMBOL(mempool_init);
+EXPORT_SYMBOL(mempool_init_noprof);
 
 /**
- * mempool_create - create a memory pool
+ * mempool_create_node - create a memory pool
  * @min_nr:    the minimum number of elements guaranteed to be
  *             allocated for this pool.
  * @alloc_fn:  user-defined element-allocation function.
@@ -265,17 +265,9 @@ EXPORT_SYMBOL(mempool_init);
  *
  * Return: pointer to the created memory pool object or %NULL on error.
  */
-mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
-				mempool_free_t *free_fn, void *pool_data)
-{
-	return mempool_create_node(min_nr, alloc_fn, free_fn, pool_data,
-				   GFP_KERNEL, NUMA_NO_NODE);
-}
-EXPORT_SYMBOL(mempool_create);
-
-mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
-			       mempool_free_t *free_fn, void *pool_data,
-			       gfp_t gfp_mask, int node_id)
+mempool_t *mempool_create_node_noprof(int min_nr, mempool_alloc_t *alloc_fn,
+				      mempool_free_t *free_fn, void *pool_data,
+				      gfp_t gfp_mask, int node_id)
 {
 	mempool_t *pool;
 
@@ -291,7 +283,7 @@ mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
 
 	return pool;
 }
-EXPORT_SYMBOL(mempool_create_node);
+EXPORT_SYMBOL(mempool_create_node_noprof);
 
 /**
  * mempool_resize - resize an existing memory pool
@@ -374,7 +366,7 @@ int mempool_resize(mempool_t *pool, int new_min_nr)
 EXPORT_SYMBOL(mempool_resize);
 
 /**
- * mempool_alloc - allocate an element from a specific memory pool
+ * mempool_alloc_noprof - allocate an element from a specific memory pool
  * @pool:      pointer to the memory pool which was allocated via
  *             mempool_create().
  * @gfp_mask:  the usual allocation bitmask.
@@ -387,7 +379,7 @@ EXPORT_SYMBOL(mempool_resize);
  *
  * Return: pointer to the allocated element or %NULL on error.
  */
-void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
+void *mempool_alloc_noprof(mempool_t *pool, gfp_t gfp_mask)
 {
 	void *element;
 	unsigned long flags;
@@ -454,7 +446,7 @@ void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
 	finish_wait(&pool->wait, &wait);
 	goto repeat_alloc;
 }
-EXPORT_SYMBOL(mempool_alloc);
+EXPORT_SYMBOL(mempool_alloc_noprof);
 
 /**
  * mempool_alloc_preallocated - allocate an element from preallocated elements
@@ -562,7 +554,7 @@ void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data)
 {
 	struct kmem_cache *mem = pool_data;
 	VM_BUG_ON(mem->ctor);
-	return kmem_cache_alloc(mem, gfp_mask);
+	return kmem_cache_alloc_noprof(mem, gfp_mask);
 }
 EXPORT_SYMBOL(mempool_alloc_slab);
 
@@ -580,7 +572,7 @@ EXPORT_SYMBOL(mempool_free_slab);
 void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data)
 {
 	size_t size = (size_t)pool_data;
-	return kmalloc(size, gfp_mask);
+	return kmalloc_noprof(size, gfp_mask);
 }
 EXPORT_SYMBOL(mempool_kmalloc);
 
@@ -597,7 +589,7 @@ EXPORT_SYMBOL(mempool_kfree);
 void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data)
 {
 	int order = (int)(long)pool_data;
-	return alloc_pages(gfp_mask, order);
+	return alloc_pages_noprof(gfp_mask, order);
 }
 EXPORT_SYMBOL(mempool_alloc_pages);
 
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-27-surenb%40google.com.
