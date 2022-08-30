Return-Path: <kasan-dev+bncBC7OD3FKWUERB6MLXKMAMGQERNED7CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9650C5A6F84
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:47 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id e1-20020a17090a7c4100b001fd7e8c4eb1sf4397787pjl.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896186; cv=pass;
        d=google.com; s=arc-20160816;
        b=fJsmPiVgFo2urznqRRWLz7Q2Ii+GB2vVXVHzCYNjri8PBwn62FMJ9oJPUbbvCiid9r
         7m6TxSrOkMtkRuhkrvmoovVkkdXE9+dmBKrI1cSWwtqFfF+gBngbFGEOLXY7H50OkDMg
         5nOvgX4JiN9UHo/+kAfxq8bI/MgDE94x+cA4Suj/VkNxhyHtFPRrm9Avac6l2hjK9Qtc
         S+ICZtEKXIEYKpvs+PIO/X4UTQG1ckiXoIUVZk3DqW7pwPypWBalS5WG0JZgSWYMNXhk
         CTjn7rRsfTHRr+2An4VsrkVkiQ08AgRQixvLFJZS3iENPkA69kkHXFo5XzSjuxlQX96h
         a36w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=i6NN0ma6A6Qn7oejh0UTExNbknfnhaqtzerjgVsA7ak=;
        b=lPZN324TpfG4APsDhDDrn/jCcA02Icqt/Mi6FkWxs1HCAarU9HboG1Dqcn9nAKqWrV
         p2t1ME/QE0DzzY3exZe97R+x2/fQRXwczr7kX6m3hvdqxKd7xtS7Z0OpyJ9xIAPTH1Qj
         2X92C9FcyuilCWLoyDyD4FWZ+HFojZesXHrsOHuOXybv5gLQ0tKknIENsE7hAW3WTSld
         c0p/1RiCHiQ/FVLg5xy0F+LK6F/3iuxQwtd8Z8DdhqFf4jv1AwWqhhY69LQ3pd3REbSp
         t9GaVvmXMwXWoshzCiFYI30G8awGQhbs/UBlreVHkiln0O0+gPBQ9S1XElmqVFOK6t+y
         3TIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U5dHm0IS;
       spf=pass (google.com: domain of 3-iuoywykcv0npm9i6bjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3-IUOYwYKCV0NPM9I6BJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=i6NN0ma6A6Qn7oejh0UTExNbknfnhaqtzerjgVsA7ak=;
        b=oZCs9joVAcFsV9azMfpq6s2ptuDx3pmyL0jG/8gDPccfHVWSN//KHxWy61P2zB2z6a
         GZ29CKJGPtV0NzhDBJlogWtcfu49+4NKCjwLp97U+ky+RuZ3iXrRbrXGmVzdJEhPYdDK
         BaKvU8lqAsn+V3h38Xrj0h9dGWYygJUXZvh9MdrSDjcU2ICLc50fFccC5jb1MvslJUw4
         w9NPnZzjK70zmlSjwJ9yoE3RBUJPWaUs141TKyeKpRU3K9vOkwknoKAZXJRqau+DYU+b
         J0aQ1S7Kof98HzWEAsvbo+/OdX/QvuhqPEoW9Y+g9N2sn7/H9z9flzkZ1uLxi4aYVCE5
         PntA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=i6NN0ma6A6Qn7oejh0UTExNbknfnhaqtzerjgVsA7ak=;
        b=xlqSoX/kst+a1rh1kxu5fZEJN6bhEKdDxvCTMD+b0r9IvUHSr8AvJO2iKj9aCbWxym
         +EzDz5KbqMoN3i1O8Z7j/L0qJuVtozogCVB5tjX5j9ATCfmC0Up5q43JvaAp7mPTUBpP
         MAQBnyWI+XFYHSFHUYBuYDp67KjzWCJ5U0sW73NHsfYNyqmkcGTkQ3G/vgKLsHKS+EPX
         UdkhJJv91mNy2ZKf3+89TJHN0vXY+0vXgyN1aGt9rZylBWlmiAiYAqysVUts3Ca/q+cd
         4m50Yg3Vs8ENP12zziGxHrtwwnLV6l9bcgTtB//5ObWtrva0sA1pIXqeIzMFzNPSqEWV
         WLQw==
X-Gm-Message-State: ACgBeo1LnFIQpCJ8j6+WRDC1yNItpnC+kngpfSQzKecEjUV7WoUUKBbM
	sm0q4LvSkd9Xak7zY02nyas=
X-Google-Smtp-Source: AA6agR4ihU+eUrErVZw5fMfl7Bu01BapbKmjhH+EXw1dytg24gMQCy2S/FhmFOvO3ef78TSSV3mTlg==
X-Received: by 2002:a05:6a00:1a47:b0:52e:6a8c:5430 with SMTP id h7-20020a056a001a4700b0052e6a8c5430mr23038747pfv.48.1661896185859;
        Tue, 30 Aug 2022 14:49:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bcc3:b0:16c:2ae8:5b94 with SMTP id
 o3-20020a170902bcc300b0016c2ae85b94ls8296502pls.0.-pod-prod-gmail; Tue, 30
 Aug 2022 14:49:45 -0700 (PDT)
X-Received: by 2002:a17:903:2d0:b0:172:b63b:3a1e with SMTP id s16-20020a17090302d000b00172b63b3a1emr23182028plk.76.1661896185129;
        Tue, 30 Aug 2022 14:49:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896185; cv=none;
        d=google.com; s=arc-20160816;
        b=ra4NzTgxUsUEZSVa4vxbWKuZ0XiZT2vGhS/K+7Ndm8PbSN0JXEH21XUgPJhCXLNe8t
         mqzUtexLQRbeY9e7CCYZhWLq1GtgvQyU/XnXpVMtpt/IBY4lFgnzUWgjwOG+9f+1wd3Z
         PfWM8U8gpZ+ds41XJvgbOoyHx7Jheh1d7bnn9muLg9HSqxF+V4udiY/sc9uUBvjSRlrQ
         2rvzEzVnxZsiz+dDGn2S2+wUxxFqqwIbVzVTU9rbpZ6uhDTDMzbXCJa2DtOQHjElm8v7
         YuwmBLmOYQgHYcPHv6iQgne/GPwfUbenl1IidUM4Tyqa6VKur8lkBU0H+sB8g28nH6fE
         iwXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=6wmSIFSfHrn7NaG14r3E9vE6XZmoNzeOL4K0xpw9Sss=;
        b=agY/wKi0oT1Kf658QSnhUWPRx8dlPfADXdQy9krJWylpUWHTX3+QgkH2DyhcVKrBQH
         Jj+H/7QrXWaaS2cO+QnbkyTyrqGIwKkklZib4GNX1C2iTwwpghzqa0t/dA5LCHMZfK8n
         qxQq47E6ZFFWWWmLbXuNANqnvRxYxrY4KFEkhIlQFLMgFn9xAssn7QzbAFTzQkBQfBbz
         +IfIZA9FBv1xMBMbXgs7vr6ID3DZF0TvOGe7KwNQo6p+9T8dNtur44+L7EYAcG5DIzFY
         4g81Kj9tnycQRiwT14YTSX7ght6YwSKoiRJXhatchBC1nRjM7YIDcF2uIuHF8eEr1EDp
         3hRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U5dHm0IS;
       spf=pass (google.com: domain of 3-iuoywykcv0npm9i6bjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3-IUOYwYKCV0NPM9I6BJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id ot13-20020a17090b3b4d00b001fe0d661525si4785pjb.0.2022.08.30.14.49.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-iuoywykcv0npm9i6bjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-335ff2ef600so189311647b3.18
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:45 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a81:47c4:0:b0:341:2cab:a63c with SMTP id
 u187-20020a8147c4000000b003412caba63cmr8994715ywa.58.1661896184744; Tue, 30
 Aug 2022 14:49:44 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:48:57 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-9-surenb@google.com>
Subject: [RFC PATCH 08/30] lib: introduce page allocation tagging
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=U5dHm0IS;       spf=pass
 (google.com: domain of 3-iuoywykcv0npm9i6bjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3-IUOYwYKCV0NPM9I6BJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--surenb.bounces.google.com;
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

Introduce CONFIG_PAGE_ALLOC_TAGGING which provides helper functions to
easily instrument page allocators and adds a page_ext field to store a
pointer to the allocation tag associated with the code that allocated
the page.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/pgalloc_tag.h | 28 ++++++++++++++++++++++++++++
 lib/Kconfig.debug           | 11 +++++++++++
 lib/Makefile                |  1 +
 lib/pgalloc_tag.c           | 22 ++++++++++++++++++++++
 mm/page_ext.c               |  6 ++++++
 5 files changed, 68 insertions(+)
 create mode 100644 include/linux/pgalloc_tag.h
 create mode 100644 lib/pgalloc_tag.c

diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
new file mode 100644
index 000000000000..f525abfe51d4
--- /dev/null
+++ b/include/linux/pgalloc_tag.h
@@ -0,0 +1,28 @@
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
+	struct page_ext *page_ext = lookup_page_ext(page);
+
+	return page_ext ? (void *)page_ext + page_alloc_tagging_ops.offset
+			: NULL;
+}
+
+static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
+{
+	if (page)
+		alloc_tag_sub(get_page_tag_ref(page), PAGE_SIZE << order);
+}
+
+#endif /* _LINUX_PGALLOC_TAG_H */
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 795bf6993f8a..6686648843b3 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -978,6 +978,17 @@ config ALLOC_TAGGING
 	select CODE_TAGGING
 	select LAZY_PERCPU_COUNTER
 
+config PAGE_ALLOC_TAGGING
+	bool "Enable page allocation tagging"
+	default n
+	select ALLOC_TAGGING
+	select PAGE_EXTENSION
+	help
+	  Instrument page allocators to track allocation source code and
+	  collect statistics on the number of allocations and their total size
+	  initiated at that code location. The mechanism can be used to track
+	  memory leaks with a low performance impact.
+
 source "lib/Kconfig.kasan"
 source "lib/Kconfig.kfence"
 
diff --git a/lib/Makefile b/lib/Makefile
index dc00533fc5c8..99f732156673 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -229,6 +229,7 @@ obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
 
 obj-$(CONFIG_CODE_TAGGING) += codetag.o
 obj-$(CONFIG_ALLOC_TAGGING) += alloc_tag.o
+obj-$(CONFIG_PAGE_ALLOC_TAGGING) += pgalloc_tag.o
 
 lib-$(CONFIG_GENERIC_BUG) += bug.o
 
diff --git a/lib/pgalloc_tag.c b/lib/pgalloc_tag.c
new file mode 100644
index 000000000000..7d97372ca0df
--- /dev/null
+++ b/lib/pgalloc_tag.c
@@ -0,0 +1,22 @@
+// SPDX-License-Identifier: GPL-2.0-only
+#include <linux/mm.h>
+#include <linux/module.h>
+#include <linux/pgalloc_tag.h>
+#include <linux/seq_file.h>
+
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
diff --git a/mm/page_ext.c b/mm/page_ext.c
index 3dc715d7ac29..a22f514ff4da 100644
--- a/mm/page_ext.c
+++ b/mm/page_ext.c
@@ -9,6 +9,7 @@
 #include <linux/page_owner.h>
 #include <linux/page_idle.h>
 #include <linux/page_table_check.h>
+#include <linux/pgalloc_tag.h>
 
 /*
  * struct page extension
@@ -76,6 +77,9 @@ static struct page_ext_operations *page_ext_ops[] __initdata = {
 #if defined(CONFIG_PAGE_IDLE_FLAG) && !defined(CONFIG_64BIT)
 	&page_idle_ops,
 #endif
+#ifdef CONFIG_PAGE_ALLOC_TAGGING
+	&page_alloc_tagging_ops,
+#endif
 #ifdef CONFIG_PAGE_TABLE_CHECK
 	&page_table_check_ops,
 #endif
@@ -152,6 +156,7 @@ struct page_ext *lookup_page_ext(const struct page *page)
 					MAX_ORDER_NR_PAGES);
 	return get_entry(base, index);
 }
+EXPORT_SYMBOL(lookup_page_ext);
 
 static int __init alloc_node_page_ext(int nid)
 {
@@ -221,6 +226,7 @@ struct page_ext *lookup_page_ext(const struct page *page)
 		return NULL;
 	return get_entry(section->page_ext, pfn);
 }
+EXPORT_SYMBOL(lookup_page_ext);
 
 static void *__meminit alloc_page_ext(size_t size, int nid)
 {
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-9-surenb%40google.com.
