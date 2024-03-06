Return-Path: <kasan-dev+bncBC7OD3FKWUERBDHKUKXQMGQEEJCXGPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F4AF873E83
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:17 +0100 (CET)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-609df41adddsf368437b3.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749516; cv=pass;
        d=google.com; s=arc-20160816;
        b=GVOrag4MHj2kkD29bg8bICPz6ZSDJBcwrYwR/fir7Ir8Xt1OwmIJ8pStNBATNjq0Ft
         71A7Ok/c9wHea3OgiSct1ZQlj7Mq/2JeElzKVXNDOcBz6sxPnGYdgBKzpMBtKR5Powjw
         d3CAYOgDvvmo4IFX5rPH0Dk+CRz/Npg660vjjqbxlfY7VD33Utki15EFYJl0fG1oelrg
         J56FUhDe2oMuPyT1f271fEwA4ybluD7VKaNTX5Si7cPxsMKOykWTzDYZ9C0Y1NEgZK3+
         aWrxiPXiKxa89SBpsx2JEoxzyT+w+efD4kSYZKw6GoKXVSQkmTO/s3fyw6oZJXDAPfIL
         lsdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=d+VnD/UcwggtqV9zJMLlqO1pUD1Z2EAcTAXkhlk/8Ns=;
        fh=54P3Bg72OzWLQwsmnE7G68CrtythhpZ/buDpjS6ppSI=;
        b=hhLTmIWqIyxuNxNUkn5PwhepQv87q83Y/yEQKRBcRTGlOci0++cfDEu/H50Xv0Ng1x
         yz/mEliEoB9Y4ONCQtUjqRHZMMLtGvsVU1bs4Ds6LmkEiTKWKz745Ay4oP2R3H7Tq2A5
         Rcc3v4wOBQ26mdV4qzUkTH7zs2fvB4nLXMz5qT0Q/W3fKhIZ5Jkh/xpPDMaUHgxpx+PK
         jF4/Fvr0sQfGAVjeiOtdiezGyyKMIXo7fijoGKQKe7j9+wblTKiL5vXireiF/qkzOS0L
         ZHY6IvF2jhC8IVTrpPLJiT02EWJkr7qsTAKhtGbXw6KctLq2zUV9zSEaGhIKY4YCqgxN
         vaEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BtLf0baf;
       spf=pass (google.com: domain of 3crxozqykcu0796t2qv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3CrXoZQYKCU0796t2qv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749516; x=1710354316; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=d+VnD/UcwggtqV9zJMLlqO1pUD1Z2EAcTAXkhlk/8Ns=;
        b=VGCEFo5QY8J550O0YaGlrweV9rCDFV+9A0HE/1Vyasxtps1kTrp4vkl0/xPGZ6PQvP
         S5C01aAVtJJkBS1QphdAGQ5NSnHR3u9fDsROiV473ekNUwiuk/it/t+NftRLKZniw9gT
         Xx82WqHc2vexrA2YzXflehUWyCsqLQ690xVa9Xmv2ChK73N3SKyuAZT9GRMId0QFWzhH
         70+zAAa3OCPOJ4IcQf2lJ2EkF1lmgDb2nFDltVMG2EqY/wY+LzOrvUskxhwRrBs2oHE1
         Gb0NE5nAWbAFTuEDVlsxATalkj0SK6Ipy5PV8Hw5y+A1BdJR/XVKXvMiNw7cGCOmsbmu
         u3Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749516; x=1710354316;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=d+VnD/UcwggtqV9zJMLlqO1pUD1Z2EAcTAXkhlk/8Ns=;
        b=lFlq2J5WALP/MFPqtXNwy9CysmAqf9oeYlrieYZYaK09m1AN/X15JJXxzYWH06iMzR
         /hRoVOyuRKYn1ZWgn+T4SZicRVcwZMNGA4TBnJzlnC+MW9Xw9Ogai9h5FxYO+/bcLU4I
         BMLq01D5G91gDLpAr87ld4lXBMSpztT/Jkr0ZvPLykNjTDNoJQywAPi6xeS8pGZ2CAgN
         zMXgObk1/7vI9g2s9WSj0ps6+30DaWBKiH1n6kYrFmEODVsPrABsb90dmFNrgWLncVjL
         591gADg4Q6UXQFXtwB50ksSjb/qO4BozAED/OHQzQzShXtvUs21Z+jhwBALy8S6BWPH3
         nErg==
X-Forwarded-Encrypted: i=2; AJvYcCURIK9XSlRMRQAY8ipW5D+dI+454sfQlXSd0m+38SJF6SqN35VAAu8U6c0QQGdDPJkYlgEkLRUGMunUqp7/39sKPyohi/tsFA==
X-Gm-Message-State: AOJu0YyZsTmpjPnrZ2Y7KwTpXv4PsXxKkFrpAPguEMEcH/4mQVAFRK1X
	sRX71egOfKWWTTlpQ6fs/BKKWlRDMrPkX3dLlLma+jDH9DoPjnK2
X-Google-Smtp-Source: AGHT+IHokPH1fOMdteoT+IPyEgE2DIqa9MMLAXftQzGClocHfGcVq2ld7Bv4Wb0zQYHn8ZlhZPV01Q==
X-Received: by 2002:a5b:70e:0:b0:dcd:36c1:ecb7 with SMTP id g14-20020a5b070e000000b00dcd36c1ecb7mr8377662ybq.54.1709749516135;
        Wed, 06 Mar 2024 10:25:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:69d2:0:b0:dcc:717f:41b7 with SMTP id e201-20020a2569d2000000b00dcc717f41b7ls111570ybc.0.-pod-prod-07-us;
 Wed, 06 Mar 2024 10:25:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWR4VlZaeiIKJnqMkwSdCD8YtuwtFVnfinDy7WFXi9x9XZ8jv91D9EU/hMwRqvx9PqO3bkCKMQKTsHSOVU8EfY2sryLfuqZPd/a8Q==
X-Received: by 2002:a05:690c:fcb:b0:607:8c3e:1605 with SMTP id dg11-20020a05690c0fcb00b006078c3e1605mr17686096ywb.10.1709749515367;
        Wed, 06 Mar 2024 10:25:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749515; cv=none;
        d=google.com; s=arc-20160816;
        b=eclvfqJKS7IgKoL7cflU/7MaqqGo9dNSR5UHtk1mPecCNEDnVI71ExMAUqPKv125Gy
         Hk8Cquo/7SYFTIPvwVyqDMANcOjPOXKtl7cdWVw6ZeJgtSCluG1tV6UzX/iOn28lWBiz
         M+0HVkyGVRmNHIP9pAFjQd0zD16xv2k+8PVJDgVCUxkwOzelTLGJcZGP82Mfd7IbSUku
         ZpdkZFknettmGCdV1OVJUsrtxlSEINlUvVBneuQSU6dKCt8ivogDGJgpLJBSON6GK0Um
         l0G0iE7fOpLcRZRW63cU1CX4xzdYfQ3CtFCFMQXR79jIU1N0wFHhgWz1VfNOlP7bUS1z
         rSxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nqAwBcStn3+iWVa0bV8AV7qbDJDX846MDYUJTJVUXBw=;
        fh=RDhG3GCNSctMClek18v5NhWrgk7rKggyc+2u02BPeZw=;
        b=B7xURGCAeju6zCv0wvPjeJaW+ljR+ug8mWmUukyjxG9Kt5D6kSxJ3OUT9WYCBwFP31
         U+NoBFpxTanpRDodtaoLDtQD4+vTSejJ+n5hqXjPfr0LCSLu8K85rz1Rt4pIo004FT24
         2siQdcgrcHFMXzLkLByrG9GiwSbY/+lpOws4175TWIGgtpgaN3hihA6mUpmMGdL8Ywtf
         NX2edQiEbHmktHYtKs7PSXzwlzlEoMubq67yCnoCK8IJvvn/ykbT6ZtD3nkVS5cda8EU
         KUeLoAQtQNp2pY9HQTIQi1cT4dcpN9TMCjLvYz13A5/1VsYKgkJwuxQRwWRYUwWlMIVD
         uEuQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BtLf0baf;
       spf=pass (google.com: domain of 3crxozqykcu0796t2qv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3CrXoZQYKCU0796t2qv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id y200-20020a0dd6d1000000b00609da8cc7ebsi176121ywd.3.2024.03.06.10.25.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 3crxozqykcu0796t2qv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-609db871b90so313857b3.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVlFqWGj1wqc1TTAl1b11U99qj79P2E/5Pyn/VOADX2+qYEby0Eo52PjpXnhYU4LpcLR1Q8Quw5C3TpSu5KecffNDaLJbGqc2Kw3A==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:1744:b0:dcf:6b50:9bd7 with SMTP id
 bz4-20020a056902174400b00dcf6b509bd7mr3993743ybb.7.1709749514977; Wed, 06 Mar
 2024 10:25:14 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:12 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-15-surenb@google.com>
Subject: [PATCH v5 14/37] lib: introduce support for page allocation tagging
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
 header.i=@google.com header.s=20230601 header.b=BtLf0baf;       spf=pass
 (google.com: domain of 3crxozqykcu0796t2qv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3CrXoZQYKCU0796t2qv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--surenb.bounces.google.com;
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
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/page_ext.h    |  1 -
 include/linux/pgalloc_tag.h | 78 +++++++++++++++++++++++++++++++++++++
 lib/Kconfig.debug           |  1 +
 lib/alloc_tag.c             | 17 ++++++++
 mm/mm_init.c                |  1 +
 mm/page_alloc.c             |  4 ++
 mm/page_ext.c               |  4 ++
 7 files changed, 105 insertions(+), 1 deletion(-)
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
index 000000000000..b49ab955300f
--- /dev/null
+++ b/include/linux/pgalloc_tag.h
@@ -0,0 +1,78 @@
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
+/* Should be called only if mem_alloc_profiling_enabled() */
+static inline union codetag_ref *get_page_tag_ref(struct page *page)
+{
+	if (page) {
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
+	if (mem_alloc_profiling_enabled()) {
+		union codetag_ref *ref = get_page_tag_ref(page);
+
+		if (ref) {
+			alloc_tag_add(ref, task->alloc_tag, PAGE_SIZE << order);
+			put_page_tag_ref(ref);
+		}
+	}
+}
+
+static inline void pgalloc_tag_sub(struct page *page, unsigned int order)
+{
+	if (mem_alloc_profiling_enabled()) {
+		union codetag_ref *ref = get_page_tag_ref(page);
+
+		if (ref) {
+			alloc_tag_sub(ref, PAGE_SIZE << order);
+			put_page_tag_ref(ref);
+		}
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
index 0dd6ab986246..3e06320474d4 100644
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
index f09c8a422bc2..cb5adec4b2e2 100644
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
@@ -115,6 +116,22 @@ static bool alloc_tag_module_unload(struct codetag_type *cttype,
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
index 549e76af8f82..2fd9bf044a79 100644
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
index 16241906a368..9a91c8074556 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -54,6 +54,7 @@
 #include <linux/khugepaged.h>
 #include <linux/delayacct.h>
 #include <linux/cacheinfo.h>
+#include <linux/pgalloc_tag.h>
 #include <asm/div64.h>
 #include "internal.h"
 #include "shuffle.h"
@@ -1101,6 +1102,7 @@ __always_inline bool free_pages_prepare(struct page *page,
 		/* Do not let hwpoison pages hit pcplists/buddy */
 		reset_page_owner(page, order);
 		page_table_check_free(page, order);
+		pgalloc_tag_sub(page, order);
 		return false;
 	}
 
@@ -1140,6 +1142,7 @@ __always_inline bool free_pages_prepare(struct page *page,
 	page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
 	reset_page_owner(page, order);
 	page_table_check_free(page, order);
+	pgalloc_tag_sub(page, order);
 
 	if (!PageHighMem(page)) {
 		debug_check_no_locks_freed(page_address(page),
@@ -1533,6 +1536,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 
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
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-15-surenb%40google.com.
