Return-Path: <kasan-dev+bncBC7OD3FKWUERBVWE6GXQMGQE26HSVCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 1666B885DAE
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:44 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-22224c6d3c0sf1335796fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039063; cv=pass;
        d=google.com; s=arc-20160816;
        b=iXbbkFwKfCNWnBhk9AroXnlOAj3KHV19DUBvYYSZjUemI9cTlf4ct564zuURwavn07
         NXY2aXkqy077vYp45ciakHfrgKHJ+82u7PARraL5hqihLna0H/0x4dlLZF0R8qfw7D2j
         dU8u3ZaajMMqRe96Ot2D51ySEnV2hdRZkT2qQKdnIpoXA6L75oqeCdMdZ9pJnnv6V3uI
         NnU4KtteUrTQ4+ID2BP7Yn1jI8+Qsz5gDr1hh2QH4U3dD3Xh3cRaY//iNZIucESoHkhd
         IOm+p0zIs5D86pAPgWUr+Igv3rmxnhCsQ6PKmtkXkfv7CXMsUgv7daxslIiJfeWEeuCD
         WkSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=nYvZ/npEEleup6Znlf1VWykrQicC4qWL7L4YI8q/z2I=;
        fh=7R8T9D8ilycEhPXSczy+ZPJMrRxx9mwHv+vI27LFKkY=;
        b=q/bPSHeCyD9ZewmWwjyAyFhB4qaR9GRhrJuFiU8DrGd2za1drhlM61N8PkywqOVcia
         vnoS0H5OjNVpSnv/BIHlDgpswZ95SW1lL3uEDr5i75G5G5Yn39WYuYf/Nl21Oa94ZpPH
         Cc13M1Q7143XgzVnUhe4EKcx8gAl0nLz0LSLxU18cGhi6QFUfZibafrDGCMc8KyvLhXe
         5CmzogIAvnoOdOvl1aojMrzL5+mAT8qJSZOm80rJiu4fob3W1QfNcWdPcNCnDdnLMEF4
         zWvYPNxBzkJ6/8wyhU8X31HoQAoAPJxUPI0qPD7r5TaI+dTqAUCc9bPZHuzJoYAIHA0q
         jf/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=krmlQHsU;
       spf=pass (google.com: domain of 3vgl8zqykcuevxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3VGL8ZQYKCUEvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039063; x=1711643863; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nYvZ/npEEleup6Znlf1VWykrQicC4qWL7L4YI8q/z2I=;
        b=u2x5uihFVpX6CZOtzIgKQ0Rdvigy5U9/Y3hZyHcZe72xTAFUyHErRUo2x/7lIq/630
         Zcs9P0aQq2ELJxh3ytgtdsgamDcee/e+LMMBZecvvJErx1lILr0vm/qTtrQyN7BLN9BM
         92McuRTX7lKrL3PbNriz4lLu2nbRitWWkDQPQ5XQ0Rxl+UVJtS7OkN12YrE7OcDXlkG1
         X/whZcL9m0VFDsEXZu+cb4mF53FqPHNbcoDUYkn0AEv4r44CbYzYa6dQb2FSJkBv8ZlG
         ystYi26IZ8QYWKaQ6W9pgxWd3sNYLE3uaWw6FTmVpjq+u0QnQ1y2gKiEJe/ixurc/Lhm
         e0GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039063; x=1711643863;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nYvZ/npEEleup6Znlf1VWykrQicC4qWL7L4YI8q/z2I=;
        b=tkRRl36/Zw7k0tGHT3UeAfYCTj3axswErnaQvmomTlzs3BGlcsZwUuSrlF2VEJtz1O
         rORGn65/uUl2SPQ8EP5j6tp1raj1aJDjdBd+bJImDWg2p0b7AA9b7PUWhIxyFAUZzHbG
         gSXBiAjz9QK9kaQi/7CEtDF9kpN+6s2ivdf/6bRHAKdjSgM4KynGbBCS5TeRSyoUOmY2
         qKTI2wDDc43w8SXKZ7acQcSggTsfJh+r50qavabbizCSl1vmKgZkcxdyfhrWtjAk7MAR
         L2o3k7CaYZN5IBDr54ERoFCeseUN/ySMNhE8y0L1TdPLIexvTTwq7GrWnpnSO/0WvxP7
         oDBQ==
X-Forwarded-Encrypted: i=2; AJvYcCXX3Cvhte/4vtz/S7F9kyjD1wRIgBTua54tX8jEmvHBy/OWbL5bnn6ZUbpkHts5Eo0SQ0T0Awg9qYR231t3R270WVIBWWsfxg==
X-Gm-Message-State: AOJu0YzeV8mtoPJSeNE5o/RYhojytzujSaXmYVtZBGAQxfP8FZFrtj13
	Ca8NsJwvHRLJ0XCW5ii6fmJ7/imJ23NCPEa+Z6eu9xmXFSsnz9El
X-Google-Smtp-Source: AGHT+IFJL6qaLJj67oPIqvVXHKuba/71RvV7z+Ay1xmTx8T+c9YtV5pz2yjkZJPW69+XIdOjLIz1eg==
X-Received: by 2002:a05:6870:d202:b0:21e:7751:312c with SMTP id g2-20020a056870d20200b0021e7751312cmr2957946oac.30.1711039062872;
        Thu, 21 Mar 2024 09:37:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:80c:b0:229:bad9:aa10 with SMTP id
 fw12-20020a056870080c00b00229bad9aa10ls1338268oab.1.-pod-prod-05-us; Thu, 21
 Mar 2024 09:37:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8HXiVIGmm+gsRA4Bl8cFpdrsW0yUnTf1X3JJ3W4MyHbzFWV6Gq5vgWMN1nWF2PUQH1RiLQ32GkK2fbElC8EmpFbykDODQnnO8oQ==
X-Received: by 2002:a05:6870:332a:b0:220:daa3:4800 with SMTP id x42-20020a056870332a00b00220daa34800mr3055848oae.40.1711039061224;
        Thu, 21 Mar 2024 09:37:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039061; cv=none;
        d=google.com; s=arc-20160816;
        b=FifNeOEi9pDArDpTYt9HwB0n5FC8Rpj33szUDZ/OtmIeFEhXFrnorPD5RmPYlxKklG
         iBoofFiPeEF3o0DWB5c0/02IGhAruwNzwJU91HiT3TUqUrZONQg0h8DST3ew7yUfLn9L
         f9Je2MhFIYO3/3RJZX74cas6bYITBGdRI4jE211iUYmiu8/NGYZ0eO8bJrEIDoxHl17N
         B9Ge9c/PPZwm5X0HvrH8BMFKblV649iFoWgZ4+FsUp/FwdyBJxRuCjxiH0Ffijw71vYs
         x3dgGW1dSgI1cJ8fWSELUB4SCAodiKQqjOLCHkWtJTNj3mJhELEFkXUzpYRVd4fsAIp3
         R5lA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=VEuENejKrKvwi5jd3fEQOIFk9pMWLkQIYT8gJCjoD3E=;
        fh=BHUXduSCS8LqQnsr7dhRJjAGWegPuK9J44KcAm+ydpc=;
        b=qMgwRnLoxQNEYFZCFtesLrfAI5PrgNR4dUJQ1CTvVfZuSQJugpqnlEJIUnZH83Hnu8
         ZEwI/b6CVkoZvOxYyf5n4SuTA+poQnWW0Bfz6F3ezDlolCaRD+FmtiJXb5kAQ5WHo72Q
         cJ44C0S1j5mhplkPcUT1RavczRLjhSoHQG6egviIiV8NnzRNf8LoVjY6PqdZLlneonTH
         fwtqMxl7BqCeJlU4NFxD0t2nH5gwKl0Oq3pGiX7EBypeZJNueU9OnGrO+uo6d2Xo9RdI
         IZDtKTbTNO4OWGabc4NBUGYHHdVl35N08z9diy8D5E9PUboyCNgaYo88fje8H6XKKTL5
         mZOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=krmlQHsU;
       spf=pass (google.com: domain of 3vgl8zqykcuevxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3VGL8ZQYKCUEvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id oo6-20020a0568715a8600b00221d92ba892si27269oac.4.2024.03.21.09.37.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vgl8zqykcuevxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dbf216080f5so1808138276.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUp5M6X6jyqJK6aQzZB7x1zVA+fRXJTbLqm3mlVJ7NHSrcRGIPK6z07U+CGxwhhOtz4h0rm9dg1IH8GHbu4/O2OepIYjXLNYUbYAQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:1507:b0:dcd:ad52:6932 with SMTP id
 q7-20020a056902150700b00dcdad526932mr5791743ybu.5.1711039060482; Thu, 21 Mar
 2024 09:37:40 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:36 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-15-surenb@google.com>
Subject: [PATCH v6 14/37] lib: introduce support for page allocation tagging
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
	glider@google.com, elver@google.com, dvyukov@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=krmlQHsU;       spf=pass
 (google.com: domain of 3vgl8zqykcuevxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3VGL8ZQYKCUEvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
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
index 000000000000..66bd021eb46e
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
+				   unsigned int nr)
+{
+	if (mem_alloc_profiling_enabled()) {
+		union codetag_ref *ref = get_page_tag_ref(page);
+
+		if (ref) {
+			alloc_tag_add(ref, task->alloc_tag, PAGE_SIZE * nr);
+			put_page_tag_ref(ref);
+		}
+	}
+}
+
+static inline void pgalloc_tag_sub(struct page *page, unsigned int nr)
+{
+	if (mem_alloc_profiling_enabled()) {
+		union codetag_ref *ref = get_page_tag_ref(page);
+
+		if (ref) {
+			alloc_tag_sub(ref, PAGE_SIZE * nr);
+			put_page_tag_ref(ref);
+		}
+	}
+}
+
+#else /* CONFIG_MEM_ALLOC_PROFILING */
+
+static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
+				   unsigned int nr) {}
+static inline void pgalloc_tag_sub(struct page *page, unsigned int nr) {}
+
+#endif /* CONFIG_MEM_ALLOC_PROFILING */
+
+#endif /* _LINUX_PGALLOC_TAG_H */
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index d9a6477afdb1..ca2c466056d5 100644
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
index 370a057dae97..3e48afcd0faa 100644
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
index 4491d0240bc6..48cdd25261ea 100644
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
+		pgalloc_tag_sub(page, 1 << order);
 		return false;
 	}
 
@@ -1140,6 +1142,7 @@ __always_inline bool free_pages_prepare(struct page *page,
 	page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
 	reset_page_owner(page, order);
 	page_table_check_free(page, order);
+	pgalloc_tag_sub(page, 1 << order);
 
 	if (!PageHighMem(page)) {
 		debug_check_no_locks_freed(page_address(page),
@@ -1533,6 +1536,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 
 	set_page_owner(page, order, gfp_flags);
 	page_table_check_alloc(page, order);
+	pgalloc_tag_add(page, current, 1 << order);
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-15-surenb%40google.com.
