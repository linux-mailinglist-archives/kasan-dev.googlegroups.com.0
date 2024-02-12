Return-Path: <kasan-dev+bncBC7OD3FKWUERBXNAVKXAMGQEVP7EHZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 04430851FF5
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:47 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1d3d9d2d97bsf94855ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774045; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lv+Qy72fqVoGIjWBVvxZbillNyTcSEx7dqPf6ti0hHI7V9oJbl4j1DUUJjVznXiKFZ
         /jc6Rl6fyk1XMgHiPLtMQzxvtL+YATlSgZ+UB/zyeyLhcSgjK6fV9E5hyhLq4ZKIzRmy
         Z7z0VcrMGt4+LsrDxhh+Mhm2/f2hXMnk6HFtiDV1yel3MGtm3uu0kRbzUy6fdjv+n9mi
         zUOnY4TvalkLw4tonLDSL0U3Iljb252GjMhvmsly2NHlwITuNEbGz6sVvLci3cI9jyLh
         zR6lxlKE0471quLxRswyIzeBJeWw2+PdIt1XSA4R8lLeP9Jm+cyQ7D87Ze0WmFd1KrD2
         nUBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=mza3mmbq1ZlbTPDOzOqIIKa4/TPyxvqC2MZ5AAfKjrA=;
        fh=Qs5R/h2OIAPPBobXk6cjJZ5XsLvmhxTc9+Ph6xVbxKM=;
        b=DPQfBQqu3T6EySFKFrtfeUh9EmsX0un0Yw30Mo8XkXT8SpBhKoOohB9c4XYdxFyWxT
         OWQFj1lj4BI4kZYGbx3zlpO0Suscwd3OhNPpr3HwkedYddGhkCqz8xBaNInKRYr4S7EV
         9NPryEeQoCU2L9z+xxXzpZxWWAxD1AJVoWkM9mdTvBT1Zp+PRQlr5DiGDmGN9OnpQcNn
         +ZtVYYBXDuMWkKWDVQlk7jPVBjUH+LjvsBQYl287LZLFXloI5rhwfOv8FeTsqaESeNFM
         pQ6ziipxOUqx7BjbRTzJKtgkMFjAzwkMzLgJGle53/587+j83WiH4klD57T8Lfv9zGJx
         Hf2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XlqpRGHv;
       spf=pass (google.com: domain of 3xjdkzqykcdsprobk8dlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3XJDKZQYKCdsPROBK8DLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774045; x=1708378845; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mza3mmbq1ZlbTPDOzOqIIKa4/TPyxvqC2MZ5AAfKjrA=;
        b=xFmFRzeqkwVPNW/M4V/m+4HlVdBsvabwmaHIGBZM/g8m/wSHCWXi6WSWXjriXL51R1
         JjUZJCg8xJGI/gWxPG+Q8Wkmxsagcnx+mxtjXfKo+cJa+QwwLmoJVw+Lb4M1IOmXEVZ3
         9eC8ZUlZ9bKAYky7hwVxdEJOuKwK5n80CYBR0V3bS7LXZTlK6Smp29VGXYQ/IFUcRreZ
         FgSOcVDmwvn1WlO0yQedfRbvFrGgcf8BpECfRT+MO6mmlo0biEMR9RCgAflgu3mGWZfU
         wU0IdYJ+QAcz5qNwnko3GkMKoszlHh8PkF/YfdLCIm7tpzwI1gX/SC1ml8hWpOWvS+vD
         cRIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774045; x=1708378845;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mza3mmbq1ZlbTPDOzOqIIKa4/TPyxvqC2MZ5AAfKjrA=;
        b=d0tSJ3+97aPfcJ1/JYbBpxURS+LTaElY1CrfCA4hfIbBE7nuyjfIghGmAwoK93g3nJ
         G1II+5lWnbQ+k6QgN6iHAvYPaSjJsP6mUg8Sdxnq/f7dyDvb+uKpXg+HW9A7hCdEDij8
         YOWgQ1x5z6q2Cih4oOyf+6Pbw0iKvYQJ9aVhneCH5oA7IggzDfmt+9dZL7caHaItFz9T
         XCmCSuBTXS+97KEsfW2kSF+04I7mXQ7IuM6688/xJyX8B5ZTtMrwBwWsS/YcQetqnV8A
         Kq1X4YJuFzCP84EJTpghag28ooqFqFYXT4pCj24hbzci9w4NgQe+seEy4zYggFIglQnz
         iK3A==
X-Forwarded-Encrypted: i=2; AJvYcCVPmuqvhuwZH4jCZBQ4QnvJyPzC1EgHjNc9Bkdm5qDQ0R2TODBpVPaoIU0+UuMFmMMA1bYxWq0cyqqTHDd+tQJ/lAUL3PoZCA==
X-Gm-Message-State: AOJu0Yyw7g8jS1/5fA1hTF39AQkIni8mOoJ1DG6BY0ZmZfsKeHIMbBMO
	j40oxt3WhHg6mgOVRG0FOLROOdmqxjeBQmFIIQ0TcspcG53ObjRq
X-Google-Smtp-Source: AGHT+IHh571Sert5ey4A1vYQwsakE+Tw3nvt83uwhY1Ht3ru5J1UP6HaDByzepub28l1uicJcC3vQA==
X-Received: by 2002:a17:903:7cb:b0:1d9:6c20:b900 with SMTP id ko11-20020a17090307cb00b001d96c20b900mr17056plb.7.1707774045577;
        Mon, 12 Feb 2024 13:40:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5590:0:b0:59a:347a:de04 with SMTP id e138-20020a4a5590000000b0059a347ade04ls2574041oob.2.-pod-prod-07-us;
 Mon, 12 Feb 2024 13:40:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUD/gtAucx9D39PVGaeDk5ZdwcWm4QJx/Ft2MLM7LLSdd1YaAX9w61wz4blEqn7gV2hlbvBI7zLKPtjlhs7QUPHyDeTSBbPW4W/fg==
X-Received: by 2002:a4a:6548:0:b0:59d:4fb3:6530 with SMTP id z8-20020a4a6548000000b0059d4fb36530mr4255771oog.0.1707774044627;
        Mon, 12 Feb 2024 13:40:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774044; cv=none;
        d=google.com; s=arc-20160816;
        b=KdC7RIqRHn+9CxBni5Uy1uDd+gTGKExXyQ/CIn/Webggh7vE617UEDEgySLWCF0yIe
         DygsGBtAxJZ7hhS/gBTHfqnZJk4Y9ISMPWMx0psyR5B5Cr1kOjnz1fYoqN581qSPKLGV
         6G4hjvDSQB5xc76bF4xUau4JM3KJAIFTw4F+dNB7nGMutl4KQSpBhoDLumkD6LCKjqJm
         AcJJtXrL5ftr4cIh0IGjVxzqxIY5FrdYgB5/VzzzjHLqrUWrha6zMUIkBSaRF3+e+xA8
         T+beGK4GXEJIr2J6alG8RrffiABC+3C1vYC8cUbaOUpOVk2oB+u5e7JS2mt7XSECgq6m
         Ek5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DSEwnOfj2VuhpdkIHZ8VNVuKfvBXo1I5xAUr9MF0J1M=;
        fh=rCyu/g+QPdTOWpl06T2rLivB4UB0oWiW7/f4sBb29rI=;
        b=dOxgvtfgbdV6IRkQggmOXWH1PW7x2WpHLa6hSjWciwlQykqbdZD32e+IzxPb2fCe5m
         G/cMJbzdUX7HmWCA+PfBbWYvhMTnn0erW5h9kp2ftpaYPKuMe4tPJdaVjw5J7vZX80xI
         3ULaygjT3GDOn3yfJHvGHPy3X63WVXlmuwJIvoykXd5ipl96uJjSuAmh06ZuofYSzGFK
         Qxr9uGWXMzd4q2EbLAlnjP1n7IXg65nlSGWKTLpwrQauSqI9iJnOcAp7WrQ18RrUnRd7
         BD67emk8L2M2DscI9qjnrrCz5SebWHO4qlB7EDKIcW9ILbf8Ny/2IVMff91gMttz4Omt
         bkog==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XlqpRGHv;
       spf=pass (google.com: domain of 3xjdkzqykcdsprobk8dlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3XJDKZQYKCdsPROBK8DLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXzr3RPsjJoo5YjvNb1JxPwa/cNWdG10KP5XeCLBUqdPajAoItIndcBeSFo81XtMnyoEtBVJYMgxK/a4QLqhKECJGIoL/Q6+fE5Aw==
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id i16-20020ad44110000000b0068ed0794675si53604qvp.5.2024.02.12.13.40.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xjdkzqykcdsprobk8dlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60753c3fab9so16582297b3.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXBLTcs+y39dZQdvzQAYsu00Dmuc9b2qH8b33dj9d54zmIys4edyowMEDVwf24lOYRjqe6IvV9PfZu9OEWrFALuNTT1rfdP7Ps4gg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a0d:e8c2:0:b0:607:79be:9120 with SMTP id
 r185-20020a0de8c2000000b0060779be9120mr169543ywe.0.1707774044127; Mon, 12 Feb
 2024 13:40:44 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:19 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-34-surenb@google.com>
Subject: [PATCH v3 33/35] codetag: debug: mark codetags for reserved pages as empty
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XlqpRGHv;       spf=pass
 (google.com: domain of 3xjdkzqykcdsprobk8dlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3XJDKZQYKCdsPROBK8DLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--surenb.bounces.google.com;
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

To avoid debug warnings while freeing reserved pages which were not
allocated with usual allocators, mark their codetags as empty before
freeing.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/alloc_tag.h   | 2 ++
 include/linux/mm.h          | 8 ++++++++
 include/linux/pgalloc_tag.h | 2 ++
 mm/mm_init.c                | 9 +++++++++
 4 files changed, 21 insertions(+)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index 1f3207097b03..102caf62c2a9 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -95,6 +95,7 @@ static inline void set_codetag_empty(union codetag_ref *ref)
 #else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
 static inline bool is_codetag_empty(union codetag_ref *ref) { return false; }
+static inline void set_codetag_empty(union codetag_ref *ref) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
@@ -155,6 +156,7 @@ static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
 static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes) {}
 static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
 				 size_t bytes) {}
+static inline void set_codetag_empty(union codetag_ref *ref) {}
 
 #endif
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index f5a97dec5169..ac1b661987ed 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -5,6 +5,7 @@
 #include <linux/errno.h>
 #include <linux/mmdebug.h>
 #include <linux/gfp.h>
+#include <linux/pgalloc_tag.h>
 #include <linux/bug.h>
 #include <linux/list.h>
 #include <linux/mmzone.h>
@@ -3112,6 +3113,13 @@ extern void reserve_bootmem_region(phys_addr_t start,
 /* Free the reserved page into the buddy system, so it gets managed. */
 static inline void free_reserved_page(struct page *page)
 {
+	union codetag_ref *ref;
+
+	ref = get_page_tag_ref(page);
+	if (ref) {
+		set_codetag_empty(ref);
+		put_page_tag_ref(ref);
+	}
 	ClearPageReserved(page);
 	init_page_count(page);
 	__free_page(page);
diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
index 0174aff5e871..ae9b0f359264 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -93,6 +93,8 @@ static inline void pgalloc_tag_split(struct page *page, unsigned int nr)
 
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
+static inline union codetag_ref *get_page_tag_ref(struct page *page) { return NULL; }
+static inline void put_page_tag_ref(union codetag_ref *ref) {}
 static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
 				   unsigned int order) {}
 static inline void pgalloc_tag_sub(struct page *page, unsigned int order) {}
diff --git a/mm/mm_init.c b/mm/mm_init.c
index e9ea2919d02d..f5386632fe86 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -2566,6 +2566,7 @@ void __init set_dma_reserve(unsigned long new_dma_reserve)
 void __init memblock_free_pages(struct page *page, unsigned long pfn,
 							unsigned int order)
 {
+	union codetag_ref *ref;
 
 	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
 		int nid = early_pfn_to_nid(pfn);
@@ -2578,6 +2579,14 @@ void __init memblock_free_pages(struct page *page, unsigned long pfn,
 		/* KMSAN will take care of these pages. */
 		return;
 	}
+
+	/* pages were reserved and not allocated */
+	ref = get_page_tag_ref(page);
+	if (ref) {
+		set_codetag_empty(ref);
+		put_page_tag_ref(ref);
+	}
+
 	__free_pages_core(page, order);
 }
 
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-34-surenb%40google.com.
