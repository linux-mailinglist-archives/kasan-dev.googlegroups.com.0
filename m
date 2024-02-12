Return-Path: <kasan-dev+bncBC7OD3FKWUERBNFAVKXAMGQEZH2FWOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BC49851FD4
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:05 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-68058b0112csf70499886d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774004; cv=pass;
        d=google.com; s=arc-20160816;
        b=MEx0/hyn+yEgp3b3Nhy8di9XcDpZKnwTJtzYqoxlvQwANt/GgrVvx6rwrdjPZ+FEeZ
         FlEO2Zc4lkOzXsvYEHRu6yXcPTw3uJ9apD0dXUZXpOtyA8InMl1yhztRLht+/lLB7dSM
         8QcBwBlcigKAePNOUXLXLMhi+t/KqiWoNkUs5nj85qoD1ynYDrZJF+YJVWzN/MLu7xNE
         wSybq8Kj2vVGu/xFGs1udpkg6tFEZD/nSrq0dFU/6vE8n3T0RWlHjpGDFqZ9sUO4p1iU
         9OPq/0ulw7v4lFjLAINomIJr8Sn+2V3P3X/RNRt9coqK5nlHPji7Cu4xSLPwPfCx7IUW
         e3zQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+Wpn9USgqp16hFGmNA94LrkwCQvHs6W9X4Yz8pxK/Go=;
        fh=cT9mr5IFGJ/C0hSmAuiHxp32uB6VIE5kiADy3Vvlmhw=;
        b=ujOfeQiUGgKhYGzZ85SBLevUA2Vx4sPwpNR8uieTbn06gJGuv94CEABK3rH1ZT/iRG
         X6WYqH5sbFpEJsivY2Hwxw75bNyWPViLQrb3+4RFViDGohwotQMm6UCsNuupVvGm3X5q
         bYk45xHm5Gh8XYxzaQEkopSIig9qibO2DBLy1KhxYkWJ9sfXU8w89cM/6aj0pqNjsiac
         ysiCrjfXoGLUlx2PCNFSJEx+4xJ2ICGY79dN6OaOnKDuQIachOrmLrZbm3XdSQy3SR2X
         ji7sBCdW4vtm0zAa4Hr39Iu3fkA8grRh6fQ9H4fBUSIbhXpumVKzg1O8A/1Ddhv9zZDh
         gt9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IBd2E4vi;
       spf=pass (google.com: domain of 3m5dkzqykcbikmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3M5DKZQYKCbIkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774004; x=1708378804; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+Wpn9USgqp16hFGmNA94LrkwCQvHs6W9X4Yz8pxK/Go=;
        b=bl/4LvHXvAPWre6CZsP2awgjafgL5Prqf8yLKndOU1fL6odE3B02DP5XBy6HKBon/S
         oTZBtRGMHtG5qDxTZnqw75hLDECq9w1H0RLH7B+c8SY/imZhF6OXCpmjI+vzqJLKZSe8
         340/GkaLQLeJjNaZIYjOIhWlQOKgSATuBxVEEu555WZTvjZZp4oW6gD+5JIkshe2bihw
         gpXRRFknXy4+KZ0SUegQPs35jwWo0xl7b2uK1YljMdvgoqH8ah7SOsIDkckl1UzvB7B9
         4FeSE1LCKDok8pn8+Mmy/NkecPbCffT0aEBhhfpqEBZp1ZbodShpPmuXsx0yljWJcPd6
         yYwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774004; x=1708378804;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+Wpn9USgqp16hFGmNA94LrkwCQvHs6W9X4Yz8pxK/Go=;
        b=AKVg5SRCFv0mq4igHFEKbiHoYFEijwLT+S/mHRnwz4jGUoCGKx5cNjOm70lwI2Lsyb
         8H2lBC5L8+CgiSLconkXoXfw72CB3FufeB/8HdAjtroloj1pAhAu1DKfN7gC2CJA1x19
         TggbhkyL4bW9kiNbSfhlUapvXR1cR7G+suX4qjvqL4RX6uva1MSdDH9Yibx1iVnYRxKe
         I5ziCjGmD952ljpv4pTs01msLImRObjx3+bIcAJuCQyO8m22ze+o8PvNwD+5vyEWO27H
         BlGZLoo24VXe6ANJbZpDj/73PCHB5wZozLZpYCNtipTbsFasuHqyPwdEKnMbSDe0XWGi
         Os8Q==
X-Forwarded-Encrypted: i=2; AJvYcCX4FsyXidvExKcgIj7xeUJhaGu15X8XMcraYvW3wHZD2HUwZY64yE2G3fVOSgPKyHO0sRmweRQVII5Kvh+2tigUS2EGY0hYeQ==
X-Gm-Message-State: AOJu0YxDeNeLQyCXf24viBp1bnpppTS6brmxfL08aBNF+hr+I5Gi2G3c
	4/IkIp6GFGOCzeYCmDRrbZf2hwVabZRqdg0qnGoBuKiaJylOrbLZ
X-Google-Smtp-Source: AGHT+IFICVXfJZJw6vyjsMwp0pHfg3YfRBsjpZ/dyz5G+3q2wv+HbNkqAHxJvnC8hT1HwKeZcrPdsA==
X-Received: by 2002:a05:6214:528d:b0:68d:113:6d41 with SMTP id kj13-20020a056214528d00b0068d01136d41mr8259139qvb.40.1707774004116;
        Mon, 12 Feb 2024 13:40:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2a4c:b0:68d:14b3:ae2f with SMTP id
 jf12-20020a0562142a4c00b0068d14b3ae2fls810040qvb.1.-pod-prod-06-us; Mon, 12
 Feb 2024 13:40:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWYZAmKBqW4dRaBZyTo/qrSXuFPFCz43d6qAQ3chzop+8yEm0srETTQ0+9XMYJ5S6uQbrlSbjBugS6/UNssW4y60zf4xPbLaCb0ag==
X-Received: by 2002:a1f:eb81:0:b0:4c0:1a89:e636 with SMTP id j123-20020a1feb81000000b004c01a89e636mr4125865vkh.14.1707774003488;
        Mon, 12 Feb 2024 13:40:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774003; cv=none;
        d=google.com; s=arc-20160816;
        b=rpiNwYSPTdeCdAf3jFmrQszQUZkozWX0XmYOF6h9yKC2BoaBlRgGvTpANixkG0UrOs
         pPOyHRhOJQ0wrnRI9VZdZxpdbDbm04XnxMBUzxKuF4bPWBBJqtUG4YI4VMzMLuqfDMcf
         tFR/DNKZROK+VYpLETMfLhvcDXrXfsepcLBCC4F4vPeuInfNlF1f3JyuDpN1VxADV5PL
         5WJ09FrXjcuxXfbKv/5ZsfAf7p3RYjdo/eF3iZhZeY2PRWOtc84cFkpBgjXo86vnoppE
         9EhSR7GR5mHin+kwX7oN0fOUoSvIJXmuZWXmKzOp5hLtlfXTBWDL82O2Ks09w/VMjdsS
         /ITw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=kt8cg7NInhDJR3c6J+BP4SUIPENq39NpOtUeNq0nwQE=;
        fh=1LuRsQVixDtWTMOqbHbLaqQ8eMGGR3NbmHag6HgCSiw=;
        b=QYJe9TBzS+K2mtiBp5WUE6p3gSW0iN+XycCc3f4LeCestsS5hj2eUMEp1DHGH5GMtB
         hrMSLCRzItm6gp5B2QyvfeUq/JPdvl4j1MSt86QEHHFXWCGflC28yVGqjKsJM4/JpkQj
         5maswJU426kqauHqAZzNNwDJt06am8DwUrJ5HmB0e6ybRe3K0DhTXNzQKlGF4TO9UyfU
         X49zRzoZs7znolmfoyuWCKXFXJO4YcSNoZZDLJqpL1VNCeH8BJjaT4durMguPfp518Py
         G0P80yc9fzrDlJ/hFi0JO0z6s2yXdH7udZDu+GQl5TOs9IIhOb+FJNZcCqJF9REJ2Snq
         1NVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IBd2E4vi;
       spf=pass (google.com: domain of 3m5dkzqykcbikmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3M5DKZQYKCbIkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUgFxVNB/U+Imj32kbg4d8n/s2f0rmBRA5Xk9CVPAq8c0LfpSwCjE2Y2AM35sMiQbZ7UofQCBsa5gDHkdjk2DhP+jjMB4VGb4QuyA==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id w27-20020a05612205bb00b004c06c3ffcd9si731688vko.4.2024.02.12.13.40.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3m5dkzqykcbikmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5ecfd153ccfso73581137b3.2
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:03 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUX8eFfeXPZ8qs/H2XF/mwiAxCJrn8hwsUmeQJ0e7xTT3aADv4crF6cQtgG+/Nhc6GPGv5iU36VCIc1Ib+SrWBmpdWExBB/atUiZw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:690c:c07:b0:604:42a3:3adc with SMTP id
 cl7-20020a05690c0c0700b0060442a33adcmr2207535ywb.10.1707774003026; Mon, 12
 Feb 2024 13:40:03 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:00 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-15-surenb@google.com>
Subject: [PATCH v3 14/35] lib: introduce support for page allocation tagging
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
 header.i=@google.com header.s=20230601 header.b=IBd2E4vi;       spf=pass
 (google.com: domain of 3m5dkzqykcbikmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3M5DKZQYKCbIkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
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
index 78d258ca508f..7bbdb0ddb011 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -978,6 +978,7 @@ config MEM_ALLOC_PROFILING
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
index 2c19f5515e36..e9ea2919d02d 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -24,6 +24,7 @@
 #include <linux/page_ext.h>
 #include <linux/pti.h>
 #include <linux/pgtable.h>
+#include <linux/stackdepot.h>
 #include <linux/swap.h>
 #include <linux/cma.h>
 #include <linux/crash_dump.h>
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 150d4f23b010..edb79a55a252 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -53,6 +53,7 @@
 #include <linux/khugepaged.h>
 #include <linux/delayacct.h>
 #include <linux/cacheinfo.h>
+#include <linux/pgalloc_tag.h>
 #include <asm/div64.h>
 #include "internal.h"
 #include "shuffle.h"
@@ -1100,6 +1101,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 		/* Do not let hwpoison pages hit pcplists/buddy */
 		reset_page_owner(page, order);
 		page_table_check_free(page, order);
+		pgalloc_tag_sub(page, order);
 		return false;
 	}
 
@@ -1139,6 +1141,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
 	reset_page_owner(page, order);
 	page_table_check_free(page, order);
+	pgalloc_tag_sub(page, order);
 
 	if (!PageHighMem(page)) {
 		debug_check_no_locks_freed(page_address(page),
@@ -1532,6 +1535,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 
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
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-15-surenb%40google.com.
