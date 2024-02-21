Return-Path: <kasan-dev+bncBC7OD3FKWUERB25D3GXAMGQE3DXFNJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 38AB085E77F
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:32 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-21e61f157b9sf1078673fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544491; cv=pass;
        d=google.com; s=arc-20160816;
        b=pClQJ+I2FRMOslak4CEtklDi0mKBGHVLJ6agIQ67IZGVsAm9JDBuvcSG1Edo40yvqU
         RGnrfp6cGpvlLzulGWlR+WWKwEtrnNig+dg2zDo+1Ge4DEpHgs3IoAQ7q2ZPBqpd20kn
         rYHV9DwhiAqV/6LfkWeR+CjS3BWHTglNThQOM5aEk5PHGBe7yej3NnogteTrHH/lu/Bw
         rgSr2zRcOzCeG8te2sw+d81IAm/21vONPJhK9q3RRuVC2lL1oo6/IwkLa5Kstb+axCLZ
         aJZuFZTxRpKfhGeoAtKNRqmaUTkSzvQhCOvGQRsKNDF1S9pn3j1Jm5+bjbv1TVtH1WDU
         Wo7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=JsApkUYG8FyFG/a52AlfxP136kUfhwbO8IR9K1bIN3U=;
        fh=DBQsIwkwIX89vvn7ap56mRMPSaDvMoeU4Di7QEObsjk=;
        b=HhwrhG1xHyExkdXOVJbWztrvmeL6WBw4cCZl4DHSyOeNOY4CLfjvv2NiI4G072WvEZ
         HB0nmntpPXiFhFsLWcKPhi6HVP2PoA/8RhxuDTOFfjDNMX/nzswMhlSFQtmroWtRlfGu
         RPM/W9YCmbqnIpd4y/A77zTuX22jjW9WsYSkzLoVPcdn/+p2i9R+05duR8IzOzqUgRQn
         4kt8Dx5FGBikCEExf+Df0mD6Kfz2sWC1t+Q8uEyJV47lsd4VfFD1GXX8umCHbXpJC2xQ
         4psQI0xARrdptIy2njETR+Pn1hrjSIUrb78fBp1t27pW0o8HwKusSE6tp0vzOOzK0ujJ
         KtoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PSMMeKwI;
       spf=pass (google.com: domain of 36vhwzqykcrwkmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=36VHWZQYKCRwKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544491; x=1709149291; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JsApkUYG8FyFG/a52AlfxP136kUfhwbO8IR9K1bIN3U=;
        b=bUP/7EVeo1lxJakh5aXQ0qQHXbQl6GLsYB6N7aKgr1CYvuZNMec5cUEDkCtMgwPybB
         CIjaPbg5f7FU0nGfWwYzV6bLtfH+b8vZMc9p7b/dYdMIvJiAtHOVsXTuX/bJxNJAgSJU
         g2ghAJecIQtY1ls4Q8XaM9SAnidunEhcDsNwzSj4sMbVICYAu4nwprYxcFSeC0HJ4gs+
         cNrqRPEp8rx9z+867V6CyczpafuJzvDgcIsw4SgGwyL15cGtuTu7Be6X2YVCzAhjZXGd
         hLj0MxJnrAlM/j172HP6WkxSAQqhPAoJUNKJSNY2O+9aCYrjpO1yXygQ81MVYjceD0wJ
         rHyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544491; x=1709149291;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JsApkUYG8FyFG/a52AlfxP136kUfhwbO8IR9K1bIN3U=;
        b=a7Kyouyj1+s6jYjsorqQypIJzr6qN1OA7OohUgh9yi5S9LBvlJb/4y2a4mZrMJeEQh
         1d9Y1ba9Qa2kCy5ydMlXFoFqOKfLb3fAzcvHmbppdCB3CuqJP6O9Un93kBBNGysXsB04
         4XVtawhMPduGRe8xxKntIQlmr2DWORiFPVNkHX7GKemXGoF1KNjzImAkoKb0ixY61dvh
         HtIPULTX6C2XVQhBJrwsGYTg5uYlYStwlU4MSEwYJccEseGhHLQ69UGOyVwvLFNKgfXa
         WHBxLg2l70GhcfaSDTM8gHTo66AoS9XxgiZ4WU3rsn8+DWjsPBhO9qN8Z/idUPyT954c
         fBoA==
X-Forwarded-Encrypted: i=2; AJvYcCV47nmSCpGL0ctShgq7jhOPbIage4ZMeFd92KUuRjcPu1ZTrqhTo+tyQQbpx6KFzsWON9SLcM1tuBiRNU8hsVIFcDjL5Pkzrw==
X-Gm-Message-State: AOJu0YwxPYfaLrXH0YY4viPosq9oCWbkDXM47gWGDbrS2q6ykBrmyYyc
	UFMJnjGMwuBtw3+o3ggDbt62wg1++Co/P5ArSke8NrHtKmANPLhE
X-Google-Smtp-Source: AGHT+IHOlTSjRBwD87SOlz3TUKYW3CEdMEMLYu6hCEWaZKYV33Yi+8sm9L9dfZdnme2BH2iDw3cWsg==
X-Received: by 2002:a05:6870:d393:b0:21e:c59b:7300 with SMTP id k19-20020a056870d39300b0021ec59b7300mr11749417oag.38.1708544491104;
        Wed, 21 Feb 2024 11:41:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ec8f:b0:21a:1435:cce5 with SMTP id
 eo15-20020a056870ec8f00b0021a1435cce5ls6846196oab.0.-pod-prod-05-us; Wed, 21
 Feb 2024 11:41:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUovYpSh1RB4Ffxpx+FNpmNsr2sskxhexSX5W+NX1EphGX+jMxHFV3rC+8qIPoRNh2oei/MEUZvSSPlc296U9ByTdYNI5/sZYVQxw==
X-Received: by 2002:a05:6870:1704:b0:21e:f544:2e50 with SMTP id h4-20020a056870170400b0021ef5442e50mr9496462oae.31.1708544489999;
        Wed, 21 Feb 2024 11:41:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544489; cv=none;
        d=google.com; s=arc-20160816;
        b=t6NO/ak3w3Mqk3vtavXqKsrvAx9n/X4dTJGFUGRNdyfuZbRBEJ00TOEdq4H/snR7Jz
         xOrwHRjSSl5VtkIbQbzDFJxsqaehhKVf99HCwwzlwUbgGK8v9PNmQGVN5/YmKqZKwatK
         CJZMCfK5cEevs6r/ST4ZhtpU06wed8BJZ/9TMtNDBph6X3CQ+o7yfLoREdn3WaQWEONb
         pPtCmK6DQ1r2MLd9694/SsoDI9TVwaEk+v+14hKc8YbufC2Dq0fG4OeItplj7JRzOKd9
         ugTJHFaRY9/ElkcVP70NDG6vsYJ3XxBZHtYmseAFg8t1+9mpwtZoUew8xr/BhOkXZygQ
         kdtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=NsY6yp7iUYgjdAZV5EeYqd6Hb5QC4jbV+S+/t/cRTHY=;
        fh=V0wjActr/qUi26EO9eO0S2gq1gr2r56OgsMQ+1pQEXE=;
        b=NQEWzOx2hdDNgVV6AYGIIVn2WD4wKYVT/4Z/8ewt7CxeRL9GmFqNOGTI2z3AeCvO4e
         6tKMsFt9KbSMb0SiRwTMxZIUQFziYw07OwH1724pmsxllP0w3d790nYJ+jQGXiHCTdnQ
         I1flRzBRwFZLREC2TLldEQ3ABZmPJVOMkTsz3GzKbCX7KG2roVTWpcgcyqiah1FDt/Cm
         0a0yxc7i0CaR/kPkdZEX9/lipmKoOfCIPwVwnn1vPIMiGQoDnSlc3Gnq2ljdX9yLoN9h
         D9+ys/GYOvLBZ4GP3mG9/dxJB4xTZuP/7gaki7z26jCb8UId21XQ35J8EbSxiUoiT51B
         3DnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PSMMeKwI;
       spf=pass (google.com: domain of 36vhwzqykcrwkmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=36VHWZQYKCRwKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id m65-20020a632644000000b005dc851134acsi899918pgm.1.2024.02.21.11.41.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 36vhwzqykcrwkmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dced704f17cso3554427276.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:29 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUrFcKMbTFZ0XdORZmFrSLWEacwZnkl4ydOKvZlr8PX2tnmFI+ZpqZvwiU15pdOIUKeTbq3i0uIsGEjCtXqpNpAygUSdT9whqYPWA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a25:26cf:0:b0:dcc:41ad:fb3b with SMTP id
 m198-20020a2526cf000000b00dcc41adfb3bmr6925ybm.10.1708544489081; Wed, 21 Feb
 2024 11:41:29 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:28 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-16-surenb@google.com>
Subject: [PATCH v4 15/36] lib: introduce support for page allocation tagging
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
 header.i=@google.com header.s=20230601 header.b=PSMMeKwI;       spf=pass
 (google.com: domain of 36vhwzqykcrwkmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=36VHWZQYKCRwKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
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
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-16-surenb%40google.com.
