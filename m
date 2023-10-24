Return-Path: <kasan-dev+bncBC7OD3FKWUERBZUV36UQMGQELUPJK2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id CB0607D5247
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:20 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1c9b774f193sf37752345ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155239; cv=pass;
        d=google.com; s=arc-20160816;
        b=j9GcG8TsTHqen1EcmnGib3kKR/DNb8Zl6sRrEXfWzUx+fDgDAXi8W5//eLOYh+g2GC
         0Snx759iA/elx2zPtYtd0C7kuBchbbkyb5U7q+e3vtL6g90KrljKkB6qcvGf2nGtpxsH
         GEcs8oNac4Ctvhi7MBMWqpjKxKrNwgWOq70obDWRypKnWqbfLP5kS0YC7lUhejWJxvw3
         A/ejLTsvuLPe9mtfB5vsbQWqRxuLiZD2o/PZUcBecOCbmnkHtAviegaSyR2z/DsV5wAZ
         qGUb0los5qpT0qulwdMUu78oaDx1VDP4H1d+IpEah3n6abpTH1Mtxc3EegvNU/TwvJtD
         +01Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=FiSEAYtsX+kolDwC/oc5zGv9TWPWvsVFiXIYonsB7oI=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=pgPJ0wICywqxOafEjgYEKEGQwb5le6xuD2mgQDesnAwLakXhCZ2JHC/7oyHgpKncsC
         yyRM5sIRwRqzFzBP8KLrIBJCufEmXN/0o4ThMOmEaZVh7ofg1EOvf4hUDrIpYMHdYunC
         Dod3ECSNookfE1mLaFitTQ64IPAQEjtrVr8el6RcOpj5zvW3jzMnX8h7OoB60zSsABYM
         c55Df/GtoFjvpTbEcFPwjUIUWGNpP7IOdkeHnbiUy98nxrFfAJeMily5RwBddMtH0Wwr
         bSxLB2PO4/uyn5YhLW4MwaPbfte/6a+WyAGif6VpCn0aop2PMM9vTqYo3KY8VNbm3R2w
         ReVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xwCH0hu5;
       spf=pass (google.com: domain of 35co3zqykcyo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=35co3ZQYKCYo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155239; x=1698760039; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=FiSEAYtsX+kolDwC/oc5zGv9TWPWvsVFiXIYonsB7oI=;
        b=NtXMIYVJkINFyBmL5weKI6tG5MVtYSoco78e5icWpL3KrZsIdkBIDVPoQTtsqS7T+r
         uo94zLJ6iUP9Dg9CL+a/bgJsnyw0orIClmcQloh9LMsLP4kA6iaoVWM1tRem3Bhx+bAS
         LQG7IhJ8b6g/b2QjveLLJ5JNbciUWK/8mw2eG/hTmN+0l1YkMXSI6g3CShW0FSfG2kTV
         QckdHmGzlD7mblLrH3TpbetGf1hN2ThvIDBtnSaxoCSgT550hLpNq58ss0u2N2VoiSnb
         IEDWuWMa7cKpWcUOcdohLMc+uxtDWy4hZQIPslgbbw6o50L9Bagu6zd7kOj7Eq0RMs5L
         3ijQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155239; x=1698760039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FiSEAYtsX+kolDwC/oc5zGv9TWPWvsVFiXIYonsB7oI=;
        b=ev091lVSx7A2n8Ou7rg3ebVMCp9ksUg8XrV+SppmTZlkTNsvdFXxmd/kaY/NW0Rbj3
         +xLpg0iznKRG0FRlEe5LGRaV7Nr5A2Npw/KKz8VvhVMj9gBQOxXO33cvjlorlZRnP+mO
         GraIFQK9d1gOxbGuLwrsR6U8M2MLM++6zPP9j+jWrYwStwhzgwZZznMTOruBJ5PLhR6j
         eFrmIIj4R3nLdGL7aU7T4kCWYnjt92w0gcXZbs9IB5TZBroZ18qf31/zbjo5XhwS6bbD
         zvAagWa+K5AriRxEosyAfvkex/QvBkWwhlmg1/E0Dqz05KuzqApBWplwrHdevL/CdGXb
         WoBA==
X-Gm-Message-State: AOJu0YzGdN794Pk2q0dhLOC3D3B9ds03CQlHpO2Z1rk4Iwc9G53j7OCk
	BDO+pEOxcgI6Hz6C2p2bGus=
X-Google-Smtp-Source: AGHT+IGGgUYpE3Lcz3TbsB+5Q4f2OarSOEKVziWajOL87Xw992IgFPQXIq4Sx2fx8KGTvqeuxnxXtw==
X-Received: by 2002:a17:902:e482:b0:1c9:e3ea:74fd with SMTP id i2-20020a170902e48200b001c9e3ea74fdmr10092795ple.11.1698155239024;
        Tue, 24 Oct 2023 06:47:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b12:b0:277:3b93:d44e with SMTP id
 lx18-20020a17090b4b1200b002773b93d44els930801pjb.0.-pod-prod-03-us; Tue, 24
 Oct 2023 06:47:18 -0700 (PDT)
X-Received: by 2002:a17:90a:4b0f:b0:27d:ed83:fdff with SMTP id g15-20020a17090a4b0f00b0027ded83fdffmr11936781pjh.16.1698155238028;
        Tue, 24 Oct 2023 06:47:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155238; cv=none;
        d=google.com; s=arc-20160816;
        b=TvlLSiAPsVwRbxvmWJgnXRbpLkZZbo9wOfH08qduW2t44FqZI1FdKFQv3Pa8lnkYS3
         oAbc/3HMs/oREHTIctZTYcu98qbEh24gW9zQyyRLPH8n5jHTEBXkQDaMGt0LnvXAfHsh
         hr3fci9/lUo0CLpUO44EWL3hliQWuDED/u3g8CuaKfAFm+FfD2xFU6slx2TblKBYWqq/
         Ov21kL2hh4sfDAiiqiDeShOJHbm2cKVxImo4taiuQ17cftaZ7O6oe7+elSTdofaBQJI3
         cSpP1+hint1n2ZityGdM4tGKgJEWsi5WSuihRcXbM1/aUauIFzG7ExjcQn17rRnfh+RI
         ryHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Xnkv01D37mdYs16/e0X4XkgAogHBJsuQ+iVjrKs+el4=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=ta0V0uATNUz9db67FhD6lX2CIiodhnF1fanqLv4YN9vIWEaVWjtRT5clHFwZw37H03
         D1OllqnpSpoU3SRWAL17YkTEfqF0kUghutmDcCes593V/1jya3LjmRjIzykmtVXp/wBz
         7fSIq067wOA6GCwMOWz8fzcYBaGlgfeRtqbmA2CDdsTc71Y6W0IZniwAZCFWULe+YK+y
         Hy6rbURfpCP8sWRmzDqn450jYcZlFUJm9I68CZEUaBl+BjQdGlK1z64c4f45Xugs6Wao
         uMFn11vlkyWVczdGogUqk/deZGV5bV51NArxGge2F9PhTuk75shkvAYx58qaSiIDQWaS
         mGhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xwCH0hu5;
       spf=pass (google.com: domain of 35co3zqykcyo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=35co3ZQYKCYo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id p1-20020a17090a868100b0027d0d9abe6esi595790pjn.3.2023.10.24.06.47.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35co3zqykcyo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5a824ef7a83so58262237b3.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:17 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a0d:d954:0:b0:5a7:bfcf:2cb8 with SMTP id
 b81-20020a0dd954000000b005a7bfcf2cb8mr268838ywe.1.1698155237063; Tue, 24 Oct
 2023 06:47:17 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:13 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-17-surenb@google.com>
Subject: [PATCH v2 16/39] lib: introduce support for page allocation tagging
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=xwCH0hu5;       spf=pass
 (google.com: domain of 35co3zqykcyo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=35co3ZQYKCYo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com;
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

Introduce helper functions to easily instrument page allocators by
storing a pointer to the allocation tag associated with the code that
allocated the page in a page_ext field.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/page_ext.h    |  1 -
 include/linux/pgalloc_tag.h | 73 +++++++++++++++++++++++++++++++++++++
 lib/Kconfig.debug           |  1 +
 lib/alloc_tag.c             | 17 +++++++++
 mm/mm_init.c                |  1 +
 mm/page_alloc.c             |  4 ++
 mm/page_ext.c               |  4 ++
 7 files changed, 100 insertions(+), 1 deletion(-)
 create mode 100644 include/linux/pgalloc_tag.h

diff --git a/include/linux/page_ext.h b/include/linux/page_ext.h
index be98564191e6..07e0656898f9 100644
--- a/include/linux/page_ext.h
+++ b/include/linux/page_ext.h
@@ -4,7 +4,6 @@
 
 #include <linux/types.h>
 #include <linux/stacktrace.h>
-#include <linux/stackdepot.h>
 
 struct pglist_data;
 
diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
new file mode 100644
index 000000000000..a060c26eb449
--- /dev/null
+++ b/include/linux/pgalloc_tag.h
@@ -0,0 +1,73 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * page allocation tagging
+ */
+#ifndef _LINUX_PGALLOC_TAG_H
+#define _LINUX_PGALLOC_TAG_H
+
+#include <linux/alloc_tag.h>
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+
+#include <linux/page_ext.h>
+
+extern struct page_ext_operations page_alloc_tagging_ops;
+extern struct page_ext *page_ext_get(struct page *page);
+extern void page_ext_put(struct page_ext *page_ext);
+
+static inline union codetag_ref *codetag_ref_from_page_ext(struct page_ext *page_ext)
+{
+	return (void *)page_ext + page_alloc_tagging_ops.offset;
+}
+
+static inline struct page_ext *page_ext_from_codetag_ref(union codetag_ref *ref)
+{
+	return (void *)ref - page_alloc_tagging_ops.offset;
+}
+
+static inline union codetag_ref *get_page_tag_ref(struct page *page)
+{
+	if (page && mem_alloc_profiling_enabled()) {
+		struct page_ext *page_ext = page_ext_get(page);
+
+		if (page_ext)
+			return codetag_ref_from_page_ext(page_ext);
+	}
+	return NULL;
+}
+
+static inline void put_page_tag_ref(union codetag_ref *ref)
+{
+	page_ext_put(page_ext_from_codetag_ref(ref));
+}
+
+static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
+				   unsigned int order)
+{
+	union codetag_ref *ref = get_page_tag_ref(page);
+
+	if (ref) {
+		alloc_tag_add(ref, task->alloc_tag, PAGE_SIZE << order);
+		put_page_tag_ref(ref);
+	}
+}
+
+static inline void pgalloc_tag_sub(struct page *page, unsigned int order)
+{
+	union codetag_ref *ref = get_page_tag_ref(page);
+
+	if (ref) {
+		alloc_tag_sub(ref, PAGE_SIZE << order);
+		put_page_tag_ref(ref);
+	}
+}
+
+#else /* CONFIG_MEM_ALLOC_PROFILING */
+
+static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
+				   unsigned int order) {}
+static inline void pgalloc_tag_sub(struct page *page, unsigned int order) {}
+
+#endif /* CONFIG_MEM_ALLOC_PROFILING */
+
+#endif /* _LINUX_PGALLOC_TAG_H */
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 475a14e70566..e1eda1450d68 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -972,6 +972,7 @@ config MEM_ALLOC_PROFILING
 	depends on PROC_FS
 	depends on !DEBUG_FORCE_WEAK_PER_CPU
 	select CODE_TAGGING
+	select PAGE_EXTENSION
 	help
 	  Track allocation source code and record total allocation size
 	  initiated at that code location. The mechanism can be used to track
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
index 4fc031f9cefd..2d5226d9262d 100644
--- a/lib/alloc_tag.c
+++ b/lib/alloc_tag.c
@@ -3,6 +3,7 @@
 #include <linux/fs.h>
 #include <linux/gfp.h>
 #include <linux/module.h>
+#include <linux/page_ext.h>
 #include <linux/proc_fs.h>
 #include <linux/seq_buf.h>
 #include <linux/seq_file.h>
@@ -124,6 +125,22 @@ static bool alloc_tag_module_unload(struct codetag_type *cttype,
 	return module_unused;
 }
 
+static __init bool need_page_alloc_tagging(void)
+{
+	return true;
+}
+
+static __init void init_page_alloc_tagging(void)
+{
+}
+
+struct page_ext_operations page_alloc_tagging_ops = {
+	.size = sizeof(union codetag_ref),
+	.need = need_page_alloc_tagging,
+	.init = init_page_alloc_tagging,
+};
+EXPORT_SYMBOL(page_alloc_tagging_ops);
+
 static struct ctl_table memory_allocation_profiling_sysctls[] = {
 	{
 		.procname	= "mem_profiling",
diff --git a/mm/mm_init.c b/mm/mm_init.c
index 50f2f34745af..8e72e431dc35 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -24,6 +24,7 @@
 #include <linux/page_ext.h>
 #include <linux/pti.h>
 #include <linux/pgtable.h>
+#include <linux/stackdepot.h>
 #include <linux/swap.h>
 #include <linux/cma.h>
 #include "internal.h"
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 95546f376302..d490d0f73e72 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -52,6 +52,7 @@
 #include <linux/psi.h>
 #include <linux/khugepaged.h>
 #include <linux/delayacct.h>
+#include <linux/pgalloc_tag.h>
 #include <asm/div64.h>
 #include "internal.h"
 #include "shuffle.h"
@@ -1093,6 +1094,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			__memcg_kmem_uncharge_page(page, order);
 		reset_page_owner(page, order);
 		page_table_check_free(page, order);
+		pgalloc_tag_sub(page, order);
 		return false;
 	}
 
@@ -1135,6 +1137,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
 	reset_page_owner(page, order);
 	page_table_check_free(page, order);
+	pgalloc_tag_sub(page, order);
 
 	if (!PageHighMem(page)) {
 		debug_check_no_locks_freed(page_address(page),
@@ -1535,6 +1538,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 
 	set_page_owner(page, order, gfp_flags);
 	page_table_check_alloc(page, order);
+	pgalloc_tag_add(page, current, order);
 }
 
 static void prep_new_page(struct page *page, unsigned int order, gfp_t gfp_flags,
diff --git a/mm/page_ext.c b/mm/page_ext.c
index 4548fcc66d74..3c58fe8a24df 100644
--- a/mm/page_ext.c
+++ b/mm/page_ext.c
@@ -10,6 +10,7 @@
 #include <linux/page_idle.h>
 #include <linux/page_table_check.h>
 #include <linux/rcupdate.h>
+#include <linux/pgalloc_tag.h>
 
 /*
  * struct page extension
@@ -82,6 +83,9 @@ static struct page_ext_operations *page_ext_ops[] __initdata = {
 #if defined(CONFIG_PAGE_IDLE_FLAG) && !defined(CONFIG_64BIT)
 	&page_idle_ops,
 #endif
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	&page_alloc_tagging_ops,
+#endif
 #ifdef CONFIG_PAGE_TABLE_CHECK
 	&page_table_check_ops,
 #endif
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-17-surenb%40google.com.
