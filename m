Return-Path: <kasan-dev+bncBC7OD3FKWUERBF7KUKXQMGQEFKHYWLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DC32873E8D
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:29 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1dcf7b4daf8sf405675ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749527; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lvy7P7pN3WYeXc9xFbQS4xbkyygawLBNDcImTRN3fPcZW/nW7AHhJR+2WTM8HCIN/d
         K8mssJA1F+m3MTpLEbuyVlMEfgwvbg6bQAdta/8q/Q93fciqn/C6belkK6mJJZuxrUMU
         fJWc9K8dpUpabZT7ywc55EfgMi3BO4IseqQv8m0ZFWLScj9+lzgMdITJ+lmTPpvyvSOx
         FQCCD1DtAe52ZidH9hKNzsaqe0GvIwmcKE0l5XdXrY2+zEV34IiwYf3XtaKXgzINOIiA
         XLycqlxw2IF3CbfmB0yoccGKhK91F6AXkg3vWpmN0+jBNyAgZKZ+OXK7G/KarMVppUTI
         gIig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=aKP23IDu152nHy5CGGNOmXK4i1KVUQF+cgxQ+Lnur5I=;
        fh=C4WzWZf6yYkjOj7CIPc6pQSJ3YdVUKny4MH5XSI8PS0=;
        b=le6ozUvYTXhm6xk0oeKFMvrnEKwh4CxuOb3InsT+tgH/pqjJz+/fT+Y1ROmt05vWRz
         Rnp1ooyHJQfbNpV2EAqoCXjZniQI8PfQSoQvvEBKuYFI1xbmZquhSftT1SIMvetrfoHw
         +z5lOucAF2vaF9Jo0GXJtWO6/M+ZqAAIhBZiDB89OPzmDs+DtzFPc8PyUWhEjfeRNHvC
         t3hySheAgkSfK9Ce3HS1iarM1LXDfNiA5ZMzMtcK4rEJ3A0ONOdLL/gsMdSv/pd8hmJ4
         HG5Br2LOImpZ06C6JOOJPgLR1PfOEV2VVjK4sM/oOwAPeGntvD5+vtUEKydx9LRk4q9J
         ybww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2csOFJU+;
       spf=pass (google.com: domain of 3fbxozqykcvgikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3FbXoZQYKCVgIKH4D16EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749527; x=1710354327; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=aKP23IDu152nHy5CGGNOmXK4i1KVUQF+cgxQ+Lnur5I=;
        b=RZ0cvgh85HvJrO4SPXlbEgXY9FXQAoYQrXd0BuBGcIIOBZ7Zl2Arp3t9361V9UTjjz
         aztKkDIzagvP2HUiQZwIqChtBo2C2dzS4e9TlX8sLEC/u5/u3R9SscjAn6CVjhVH1LLV
         gNc45x4y+7uahx0qSV7pZaPLSEVN+XgqiMT/hN2dLrVCJ2ULcuL67Ku5oKZVFK+CiIOp
         TNkdqnkukcupZpyTFyjeWuJOZddDxYLl3/ZCyB7dd0us1vywA74xoaCbP7FABOA3qbs0
         +OwgOj/NCgozmFrGGAkN0JOVRuh6YkhHEv/Xv2GCx24vlo90TWcgeuRfxgxNn2EYgZ+A
         GI3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749527; x=1710354327;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aKP23IDu152nHy5CGGNOmXK4i1KVUQF+cgxQ+Lnur5I=;
        b=EY+P1nITEX4KVtTVppNu21rUHpWQxdChJRdtnOhYAdH1TWIrP7yaBDDhboGD5Gwudf
         r2NkR/8UHWi0CSxuwdfejsLa5DqX4A3clJtPEm3qF4rdEyuUPcj/UpeFa4IWjXWnfKfM
         EEzB+v7Adbnm0Fu6lnD6tUWxHNi7/M/9rEc5EJESjXWWrrPbYh+v4TxLpxFeywBs4Xt7
         pXbXU6dFt2oO1STlpukRtRA7WjOABmXBFHYHG55T62b+tWqEEKTXcxkwS3KK71NXVg6q
         zqT9bKgTH2WFE/5LNGqIuMBXyC3k2kaNmp+z2JDfVD0NAwpQu3N/pfjl9tg64ao8c7VW
         KVxQ==
X-Forwarded-Encrypted: i=2; AJvYcCUADczfxnCF5nkqtsk4Sg0pDz4ZEP6G8i+yWgEvk+FQybH+atgoZ4znsBGnZzUWttiExBXixCLUU1iRzJjuGWYjJ3r3/XuADw==
X-Gm-Message-State: AOJu0YxdPRF6mJYPGBA+S5UAIhnK1q4uW3gKOsDT6lgbhtP24lstCm6/
	Gv9iraBy8wJOPBL52933Y8FArwuY8AP6W8n/zBCvZVwGeYi5+wAn
X-Google-Smtp-Source: AGHT+IEBqKZy7nIReyTKz79KdPG1x0yNTiww9wGWxOvEoIw5bdxMgnJnqVMpIMWOm4EkRQGpR8+5IA==
X-Received: by 2002:a17:902:ec92:b0:1dc:afff:9f96 with SMTP id x18-20020a170902ec9200b001dcafff9f96mr6688470plg.44.1709749527715;
        Wed, 06 Mar 2024 10:25:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec8e:b0:1db:600b:52c with SMTP id
 x14-20020a170902ec8e00b001db600b052cls103814plg.0.-pod-prod-08-us; Wed, 06
 Mar 2024 10:25:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUoZ9reW+dpEuuZn1MVmA06H2MmEY0sOaGW0ySw00MV/sBIEUUvyUJdQJgRxEIc8SJoGILT904hNjiorSH/pwrXpv7KeNKwFaojMw==
X-Received: by 2002:a17:902:d490:b0:1dd:2b94:17d3 with SMTP id c16-20020a170902d49000b001dd2b9417d3mr7928701plg.43.1709749526687;
        Wed, 06 Mar 2024 10:25:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749526; cv=none;
        d=google.com; s=arc-20160816;
        b=NqJ13a4znJYEFVIX06lgw+zZybnp8suGJrFTsO3fmGfu6XmQ4ikMY+/uYke0RSrTyw
         AT5GjXjUV70wtwD9gUzRG1f/LdbYQ4zlF/+8TgrRpf+1BHqRVBdhlWm7WcXq+ZP/XV0e
         QvlnVd8wHA+Qf0E/khE8DfSwzMaVmMdHNW+YqiPtPQq0DuEw+JW05bDJMs9omKAhE+c4
         AuN7Sxd/4b5f2SGBUsRHUQDzygAIVN4j1RWbPNEZ1IFyKlOr61Utrcq/J/FRlFA6NPS2
         ja9wH0brh7k/qHQ3pPjKhZxIvjnchWMBkrdM0LH0TgRUTzImDESShSUdwCjVRAtJ39Tj
         oe2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=UytzFxvo2MN54m2UV3o6+O9sIke62l96NyrXCwye1Yc=;
        fh=mTNeyraCTps8Ke5msK4JgPU7R11XOoDVFdkZFKD0we4=;
        b=HY2ky+soBow/Bm0rx7TegKE8ifAWiOyKY4I92BNBMqjdHhGR3Cp7XpkEY0THg/AyMu
         aUNeWAAbaXxb4zqbfWPp/cbIItJNEjUr6HLgSRBdmt0w8bIedX48BXvSIn7zjexLWDcJ
         KCwlIPjQkJc4Fa3zKxIiu3Kbhz7vq+pew2MjRsKUedFoDs7i2W0LV9l6be+FWFENIfpJ
         sOV67d5GFJURi9FYp6zoL8aybv349N7/OM0Xgm8FHzCYoBUXQr7ZEgmOPwhEUVTzFngT
         Gplo1pYBKeXlthxulQ5qlGJgCy08stR0gywyCFy9nfm6Y02CQPnCaBhOlQR+qVYo7Cgt
         0peQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2csOFJU+;
       spf=pass (google.com: domain of 3fbxozqykcvgikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3FbXoZQYKCVgIKH4D16EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id kh14-20020a170903064e00b001dd49701596si4058plb.7.2024.03.06.10.25.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fbxozqykcvgikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-607838c0800so13134777b3.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUXs6/uNfuQV/o33eI61tR6x9iXca8Xbd0w39ROHyq27xFB0SnwUlCwj/CnSZp/tgLUHmLYens6fmW/TvVArVrU6DJNZxEFtld9mQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a81:7948:0:b0:609:5bd8:de84 with SMTP id
 u69-20020a817948000000b006095bd8de84mr1217843ywc.0.1709749525732; Wed, 06 Mar
 2024 10:25:25 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:17 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-20-surenb@google.com>
Subject: [PATCH v5 19/37] mm: create new codetag references during page splitting
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
 header.i=@google.com header.s=20230601 header.b=2csOFJU+;       spf=pass
 (google.com: domain of 3fbxozqykcvgikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3FbXoZQYKCVgIKH4D16EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--surenb.bounces.google.com;
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

When a high-order page is split into smaller ones, each newly split
page should get its codetag. After the split each split page will be
referencing the original codetag. The codetag's "bytes" counter
remains the same because the amount of allocated memory has not
changed, however the "calls" counter gets increased to keep the
counter correct when these individual pages get freed.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/alloc_tag.h   |  9 +++++++++
 include/linux/pgalloc_tag.h | 30 ++++++++++++++++++++++++++++++
 mm/huge_memory.c            |  2 ++
 mm/page_alloc.c             |  2 ++
 4 files changed, 43 insertions(+)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index 28c0005edae1..bc9b1b99a55b 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -106,6 +106,15 @@ static inline void __alloc_tag_ref_set(union codetag_ref *ref, struct alloc_tag
 	this_cpu_inc(tag->counters->calls);
 }
 
+static inline void alloc_tag_ref_set(union codetag_ref *ref, struct alloc_tag *tag)
+{
+	alloc_tag_add_check(ref, tag);
+	if (!ref || !tag)
+		return;
+
+	__alloc_tag_ref_set(ref, tag);
+}
+
 static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag, size_t bytes)
 {
 	alloc_tag_add_check(ref, tag);
diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
index b49ab955300f..9e6ad8e0e4aa 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -67,11 +67,41 @@ static inline void pgalloc_tag_sub(struct page *page, unsigned int order)
 	}
 }
 
+static inline void pgalloc_tag_split(struct page *page, unsigned int nr)
+{
+	int i;
+	struct page_ext *page_ext;
+	union codetag_ref *ref;
+	struct alloc_tag *tag;
+
+	if (!mem_alloc_profiling_enabled())
+		return;
+
+	page_ext = page_ext_get(page);
+	if (unlikely(!page_ext))
+		return;
+
+	ref = codetag_ref_from_page_ext(page_ext);
+	if (!ref->ct)
+		goto out;
+
+	tag = ct_to_alloc_tag(ref->ct);
+	page_ext = page_ext_next(page_ext);
+	for (i = 1; i < nr; i++) {
+		/* Set new reference to point to the original tag */
+		alloc_tag_ref_set(codetag_ref_from_page_ext(page_ext), tag);
+		page_ext = page_ext_next(page_ext);
+	}
+out:
+	page_ext_put(page_ext);
+}
+
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
 static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
 				   unsigned int order) {}
 static inline void pgalloc_tag_sub(struct page *page, unsigned int order) {}
+static inline void pgalloc_tag_split(struct page *page, unsigned int nr) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING */
 
diff --git a/mm/huge_memory.c b/mm/huge_memory.c
index a81a09236c16..d596449b5bc8 100644
--- a/mm/huge_memory.c
+++ b/mm/huge_memory.c
@@ -38,6 +38,7 @@
 #include <linux/sched/sysctl.h>
 #include <linux/memory-tiers.h>
 #include <linux/compat.h>
+#include <linux/pgalloc_tag.h>
 
 #include <asm/tlb.h>
 #include <asm/pgalloc.h>
@@ -2946,6 +2947,7 @@ static void __split_huge_page(struct page *page, struct list_head *list,
 	/* Caller disabled irqs, so they are still disabled here */
 
 	split_page_owner(head, order, new_order);
+	pgalloc_tag_split(head, 1 << order);
 
 	/* See comment in __split_huge_page_tail() */
 	if (folio_test_anon(folio)) {
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index eb5cae9b967d..39dc4dcf14f5 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2663,6 +2663,7 @@ void split_page(struct page *page, unsigned int order)
 	for (i = 1; i < (1 << order); i++)
 		set_page_refcounted(page + i);
 	split_page_owner(page, order, 0);
+	pgalloc_tag_split(page, 1 << order);
 	split_page_memcg(page, order, 0);
 }
 EXPORT_SYMBOL_GPL(split_page);
@@ -4850,6 +4851,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
 		struct page *last = page + nr;
 
 		split_page_owner(page, order, 0);
+		pgalloc_tag_split(page, 1 << order);
 		split_page_memcg(page, order, 0);
 		while (page < --last)
 			set_page_refcounted(last);
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-20-surenb%40google.com.
