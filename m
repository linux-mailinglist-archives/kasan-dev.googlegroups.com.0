Return-Path: <kasan-dev+bncBC7OD3FKWUERBFW6X6RAMGQEJTKSODQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E2CC6F33DB
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:51 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-74e0e819d7fsf145051285a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960150; cv=pass;
        d=google.com; s=arc-20160816;
        b=v4b0mGtBRLlMQNvkk0mOazxNUMk7jgpy67S2eOvglI1CjOaokRgys4k6SxhD8bp3p8
         sjTDW9O1v4KhmbJhTw9Uw+Ow0j49sqpu6NwBRrb/y8HuHXn9TdpLTry6SQzldObNgLlH
         6R05yV1zYhbtmfoSYv+OBXviXofiwcqofDOEI321v8DWGuphvYB8eebtJF+Zfumfe15Z
         KE3GZBEYA4AngdBvtW0jzBa9sF9EBE+gt9OCRUd/axbwf0nzn3WbnhmvPLTE/PdVvDiB
         H0hk3/wTvpwOMCzyrJpDUZvlR6bACwFK3+/0FW9gYtrgOy54qpy+haFOY/mhmsq16+WB
         4FvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=EwjHsArou4puiP33NwnALbJwZBK3iyJvtbti+P7eIQo=;
        b=C34RzW0Tml4+dyIwUhkK6M8BZm7LBVBfxtX7Vt4KQwgHAfJ0Tz5qWF3ZVJ4TqmLZzU
         /QPJzIHu2sC6KEpJjw1mlrcDBmFurtcYoXWA5fMcFrBKi7YC17vAAbWry1584D1xPoaT
         rJGMBj05mc+9Ly9z/b2PbgzATabYde8RBTdVIOS9XG/itqqgmn/ZEcglBRpnRZqiEZ2S
         HR4631JbAJpxqfRoevRBFvJyrnER8YRtDWBRWb6NXg+AlcpcPqRjPfU+4b0dteg46ecg
         0//Mi1glAyD8aP21eCZ6M+q5nYjsAjLJCTen7iMsyEjcS42QQmJNh9AkOUFYzw+ve7H8
         KviA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=PkT7GX0U;
       spf=pass (google.com: domain of 3fe9pzaykcvwmol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Fe9PZAYKCVwMOL8H5AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960150; x=1685552150;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EwjHsArou4puiP33NwnALbJwZBK3iyJvtbti+P7eIQo=;
        b=M4oZM96pjh1K/+fBxhDX91HApfJElFfFkRo4oPCEor/LTnQa1CG4DFNZB9N4Xhwyzi
         oOeWNthAgL7qcujxeBi058swjP04rYQ9kxp7QLrPLWI+0CHyttlKOKwXS9ZMbL5K3la0
         3s6o4aFPuK1fnMU4cZgJKR4EfdelF5JqNSmU8y2nXLSJwwT6zHIUgPk5j03CKguyQbc7
         cKmrqKnb6JwOPtlNeCUovEhkPwacL0nuBNu+Z5p26UmgKjevuPp17KBbYfRyx60VwGDA
         GJ/kOIPDiDEC6RJrqCbPLhqS5dbMMNfcHrJemYYsDl/4M+83/sy3y44/ab2xkJEtFcrn
         RB7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960150; x=1685552150;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EwjHsArou4puiP33NwnALbJwZBK3iyJvtbti+P7eIQo=;
        b=PjCzfuwHFH3CqwwcNBBBJLNId+UpK6fpxwnVpeMhZohxM/hI6P+7QErt8Xk/R35PHW
         i/usGtn6EKZlvcdvAMiOjGXNa1vXKD1sEGQZ1KuRot3Zc5WLXSkLW3Tdp6LV112PSEAi
         kSPoMhy/ga4fW4mQXKW4upoxmHOQTESGcn+83j3QntkQQTyw5RWSt7DEvAA1IYJw0nJs
         4+L//koHiU3IO0sp5tq4VYea2o9Wt7KQkPUZNeAu/vca3EKtdrNvvzxXfeclhdeUFMAZ
         qGK0R/vNHQcKYzgX6K4q/JAx9BvSMPSFV32VKDEy/zGsZx/6EHRYABAEFYGynL6oITyR
         Z8FQ==
X-Gm-Message-State: AC+VfDzdCTv1gY/pAYYsYQ0X7CjWRxbfB4yb2SBWEPnJ1LCTQwAtNy/Y
	sZ4oXtJBSQ09KZCnZNJ2GCI=
X-Google-Smtp-Source: ACHHUZ4CGbvEdltO0XijZ/mP7q1poyR7noIoiQfGGWzm8/y9U+wk4qRigq+JE3MZwxgGpo4CZkr/zg==
X-Received: by 2002:a05:622a:1803:b0:3ef:3ead:149 with SMTP id t3-20020a05622a180300b003ef3ead0149mr5177725qtc.13.1682960150123;
        Mon, 01 May 2023 09:55:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:bce:b0:5e8:5d19:1c9d with SMTP id
 ff14-20020a0562140bce00b005e85d191c9dls7414519qvb.6.-pod-prod-gmail; Mon, 01
 May 2023 09:55:49 -0700 (PDT)
X-Received: by 2002:ad4:5743:0:b0:5f1:5f73:aec1 with SMTP id q3-20020ad45743000000b005f15f73aec1mr999165qvx.19.1682960149626;
        Mon, 01 May 2023 09:55:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960149; cv=none;
        d=google.com; s=arc-20160816;
        b=Ip9KGZAKryGcZbzLlYilTy6v0D4I8iTBxFLJylmh9KOkXJED/vcYa78M5xUTYuY8AC
         7m1i94UyItsqnqy3IIErGJsMC+aWbCJMhdYCBbr8q8DYfd462Maza34obBrUqZlLuejh
         b9x9kgtlaaC9ObsTwfVm+qc8/UuGfhDYtqNT2uVu4srgvwzPr7UcENkn/84Vl18rh4QY
         EePXAcQ/iGUpm8DO4okhEEMSrgWXdVR2XcyoZQzYC+e6hsFP3NIB1Dv+cmmP8+jxP68l
         kZgpg0M6om+c6AWieFZu9aF2fBYJg+lk9+sOvNuMmsHMXI4na3YQF0ZYtLmGb9GgNP1U
         2cRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ANclwoiguD8BsbfKgYnGL1LnBw+SqNV6XnzUrNDvkRU=;
        b=U4/kHBKglaguwDdCoFY4nksAl8c8+MCojA18+hW7UFM1lQwSzAjgU+b77rO/pDGHje
         DktT59Cv9K2aDRJzN/J964dXBn5dNLc5s/KDde11oP+5I1IRywzKSwV/k8BXcPso9yE0
         4S3pi9l8zWRetvMoqsSIO9TIImxE36AQY6SKC+1yO9zRzUgo52vuCYsxjqjVkKkXgBtm
         EAG5kPhuAg2x8KOFT+MBbISXH+TAsHvT/oJXBzqhvYGtOFmRTjTjul6MJJp7iz92PC+v
         o4kY67fm7AwJBNoTt7xOjFHfdGQW3bixI+i9H+YjQlSwuxifpEt6BNeVytM+maqiq30W
         0umA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=PkT7GX0U;
       spf=pass (google.com: domain of 3fe9pzaykcvwmol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Fe9PZAYKCVwMOL8H5AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id i3-20020ad44ba3000000b0061b5c30b3a3si132740qvw.8.2023.05.01.09.55.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fe9pzaykcvwmol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a6f15287eso27706851276.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:49 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:dbd2:0:b0:b99:cd69:cc32 with SMTP id
 g201-20020a25dbd2000000b00b99cd69cc32mr11391322ybf.0.1682960149191; Mon, 01
 May 2023 09:55:49 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:28 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-19-surenb@google.com>
Subject: [PATCH 18/40] lib: introduce support for page allocation tagging
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
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=PkT7GX0U;       spf=pass
 (google.com: domain of 3fe9pzaykcvwmol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Fe9PZAYKCVwMOL8H5AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--surenb.bounces.google.com;
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
 include/linux/pgalloc_tag.h | 33 +++++++++++++++++++++++++++++++++
 lib/Kconfig.debug           |  1 +
 lib/alloc_tag.c             | 17 +++++++++++++++++
 mm/page_ext.c               | 12 +++++++++---
 4 files changed, 60 insertions(+), 3 deletions(-)
 create mode 100644 include/linux/pgalloc_tag.h

diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
new file mode 100644
index 000000000000..f8c7b6ef9c75
--- /dev/null
+++ b/include/linux/pgalloc_tag.h
@@ -0,0 +1,33 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * page allocation tagging
+ */
+#ifndef _LINUX_PGALLOC_TAG_H
+#define _LINUX_PGALLOC_TAG_H
+
+#include <linux/alloc_tag.h>
+#include <linux/page_ext.h>
+
+extern struct page_ext_operations page_alloc_tagging_ops;
+struct page_ext *lookup_page_ext(const struct page *page);
+
+static inline union codetag_ref *get_page_tag_ref(struct page *page)
+{
+	if (page && mem_alloc_profiling_enabled()) {
+		struct page_ext *page_ext = lookup_page_ext(page);
+
+		if (page_ext)
+			return (void *)page_ext + page_alloc_tagging_ops.offset;
+	}
+	return NULL;
+}
+
+static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
+{
+	union codetag_ref *ref = get_page_tag_ref(page);
+
+	if (ref)
+		alloc_tag_sub(ref, PAGE_SIZE << order);
+}
+
+#endif /* _LINUX_PGALLOC_TAG_H */
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index da0a91ea6042..d3aa5ee0bf0d 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -967,6 +967,7 @@ config MEM_ALLOC_PROFILING
 	depends on DEBUG_FS
 	select CODE_TAGGING
 	select LAZY_PERCPU_COUNTER
+	select PAGE_EXTENSION
 	help
 	  Track allocation source code and record total allocation size
 	  initiated at that code location. The mechanism can be used to track
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
index 3c4cfeb79862..4a0b95a46b2e 100644
--- a/lib/alloc_tag.c
+++ b/lib/alloc_tag.c
@@ -4,6 +4,7 @@
 #include <linux/fs.h>
 #include <linux/gfp.h>
 #include <linux/module.h>
+#include <linux/page_ext.h>
 #include <linux/seq_buf.h>
 #include <linux/uaccess.h>
 
@@ -159,6 +160,22 @@ static bool alloc_tag_module_unload(struct codetag_type *cttype, struct codetag_
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
 static int __init alloc_tag_init(void)
 {
 	struct codetag_type *cttype;
diff --git a/mm/page_ext.c b/mm/page_ext.c
index dc1626be458b..eaf054ec276c 100644
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
@@ -90,7 +94,7 @@ static struct page_ext_operations *page_ext_ops[] __initdata = {
 unsigned long page_ext_size;
 
 static unsigned long total_usage;
-static struct page_ext *lookup_page_ext(const struct page *page);
+struct page_ext *lookup_page_ext(const struct page *page);
 
 bool early_page_ext __meminitdata;
 static int __init setup_early_page_ext(char *str)
@@ -199,7 +203,7 @@ void __meminit pgdat_page_ext_init(struct pglist_data *pgdat)
 	pgdat->node_page_ext = NULL;
 }
 
-static struct page_ext *lookup_page_ext(const struct page *page)
+struct page_ext *lookup_page_ext(const struct page *page)
 {
 	unsigned long pfn = page_to_pfn(page);
 	unsigned long index;
@@ -219,6 +223,7 @@ static struct page_ext *lookup_page_ext(const struct page *page)
 					MAX_ORDER_NR_PAGES);
 	return get_entry(base, index);
 }
+EXPORT_SYMBOL(lookup_page_ext);
 
 static int __init alloc_node_page_ext(int nid)
 {
@@ -278,7 +283,7 @@ static bool page_ext_invalid(struct page_ext *page_ext)
 	return !page_ext || (((unsigned long)page_ext & PAGE_EXT_INVALID) == PAGE_EXT_INVALID);
 }
 
-static struct page_ext *lookup_page_ext(const struct page *page)
+struct page_ext *lookup_page_ext(const struct page *page)
 {
 	unsigned long pfn = page_to_pfn(page);
 	struct mem_section *section = __pfn_to_section(pfn);
@@ -295,6 +300,7 @@ static struct page_ext *lookup_page_ext(const struct page *page)
 		return NULL;
 	return get_entry(page_ext, pfn);
 }
+EXPORT_SYMBOL(lookup_page_ext);
 
 static void *__meminit alloc_page_ext(size_t size, int nid)
 {
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-19-surenb%40google.com.
