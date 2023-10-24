Return-Path: <kasan-dev+bncBC7OD3FKWUERB74V36UQMGQEVBN5ZDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 703277D5264
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:44 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-6ce37a2b2e9sf6590488a34.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155263; cv=pass;
        d=google.com; s=arc-20160816;
        b=VYnNTMLi8laI6xT3XvAdrIjo1e6gpCxqGhy8qqlZHNSYJErfr+v45/4USEbHogntX7
         lEeqSk3zoAo2L5JMikRdNP07qx/eyCWbrtslu6iLw4iCgr2RtR4gchyOmQr7tev4E5vA
         UkmEE9uHTkjnOiBhZ7qYge7JWOgeKScIwGxTzokkJ1+t/H4roTq2V4MBqAETAN8amNNz
         QGrdPAy012OG9KAwhS4kvJnI2QDuuXSlg0JoEmKXnpHjSlTd8GXJf/x+MqagrJa2k++C
         WxSoH/DHgUc1o/Noj0wCCbEsYGbOtnDN0E38gKu2miDvVlKZcYuBT/pD6/+WhVyJgyPH
         xVvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=pgyO3mqGiYSrq+W04XLGt9zbWrMTx9dYl2A9tkDfZkw=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=j4MPC7KHbTf/D8svNvXK6KWxKh4tOWC9IbLjj1gcYgtw4qHbpG0F0kFt3id0qkuSEx
         oyvNkGaPMBKXv352uHxxcjxChdtL0JcnIaDpmd88enuYBiU+mzDnJkIXZnpwjjuwEEC4
         TLj7+m/GF9BUPtPjs8KLNQmGM62e3W94BlCFdxnCN8itnIkCy13S3QHOZ3ht/YOzKVwT
         GoFSzQaSFSduhDODuRQsJJvN/pXCgwghSGqBWSMCPQ16h0Rdqwukna1yQu+oCPa9F9x4
         m3FJG4s+7Xzn1wSULJDA2U+/R9W8FnwRwNX88ILCmNFA0TafVG9HGpYeg17VIVTgfS/m
         2JRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=N8uHipkZ;
       spf=pass (google.com: domain of 3_co3zqykcaiuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3_co3ZQYKCaIUWTGPDIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155263; x=1698760063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pgyO3mqGiYSrq+W04XLGt9zbWrMTx9dYl2A9tkDfZkw=;
        b=BSwNTxuRjMF39swW2DwIhbcA5XMxUy0XGucypCmIHmxDUFBzuIR7+tyLzhmmkxVWXu
         i4SPNIggiSMH7Rzi4TCGVTg27VVzpPZU7cT0BGRNKBlv5+eg94vuaS22l4xUep75tj9Q
         Qk+V+0DCtQf7o8GQ5mkCsz4ZYYY9Hcd4fSHFVpCp2SNXWoGESUA2Fh+GzNuhh+v5g/FY
         fOE1mRH+yLmHh4lUZB8pYWaR5ksFBN+lURcFWEUSRx/YryJQbvS5GLCUdYpgH4WH0o1C
         ubdZNiGpC65C8YwE+KeYG75HzI7fVrd8yAXVXwi74ZZnTZXlSLDbqYN29HPjl5RgAac4
         48ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155263; x=1698760063;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pgyO3mqGiYSrq+W04XLGt9zbWrMTx9dYl2A9tkDfZkw=;
        b=Vt1AyvFTGFrN8T3NZh9pd/quZC2QraKBiZsstHgzaoj2BRVDxBmvjBoQs5b5/Mt+xG
         0iy++qRTsY+PL+E2FIGtniLiEZD4K9cQwhLn5uEO8qyiZuY0cMXCrncDvje+AoIfM6F3
         dijQQCizLgvP3QkpVwLRmVcJSPx7Ne5Ylc9abnqHpW2oPuq2UXQeIuFI8Ogz/0FqY47H
         4C3IVrzxinZQE2bLNqI1sghFl70ZxCEyyuFmolLkAPcm2SiGe+6t6XbwL7t40nsLY/iQ
         nAtquI8e+HbO95QKNy9Wyiu3jhVFS+/rg+hYC3B5FC6fo6O6zdgauji6vfRncqofMTbr
         OeRg==
X-Gm-Message-State: AOJu0YycBdlaK7qYwLyf83Rj9DruBSr5g7O8PnHA8OYd0/v6tcNpnGdI
	D76IBraOGQ/m7Xs+BWcd7ms=
X-Google-Smtp-Source: AGHT+IGkMRJQvCNR+nBN8hmKPnVa5P94Jw7tHrIWSIBrKj39Daq608pWyRliCfDK2P+vXoNbRF4gWg==
X-Received: by 2002:a05:6830:7182:b0:6c6:50fb:cd0b with SMTP id el2-20020a056830718200b006c650fbcd0bmr15909483otb.6.1698155263297;
        Tue, 24 Oct 2023 06:47:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:58a9:0:b0:66d:d64:429a with SMTP id ea9-20020ad458a9000000b0066d0d64429als4911981qvb.0.-pod-prod-02-us;
 Tue, 24 Oct 2023 06:47:42 -0700 (PDT)
X-Received: by 2002:a05:6102:20c2:b0:45a:b096:ec80 with SMTP id i2-20020a05610220c200b0045ab096ec80mr1262121vsr.31.1698155262300;
        Tue, 24 Oct 2023 06:47:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155262; cv=none;
        d=google.com; s=arc-20160816;
        b=yCrXxGOHU+cYdiVUOY50EwRW1IInxkP+kO5P6VaKMIdvFAq+PyT4cXupzunf9tOxhJ
         +Aq3DjDQYzEFkK+HH9LRlbw3aeUT3wZybqwiKjWnscPkyBL98xj1AZKYlVeszFJyrsHa
         4+Wo7fMcYSLufxD3SkeXcvzBhALW0znYve9H1YF4yhy+hgRu1xaQsx14y8twySHgX3VJ
         WjW9yR9AeD9VfILE7Uz8v0aoFYL/oR0ugGCLqSaDw+9Mf52g62ax+ySdlP67hP3WvdFn
         9ZiMhNoUH51pfDm8SNNriwEaboIIHXk5xL4F+eASf53QY0AHCDS07VHztbNLJm/9QFKy
         fktg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=wChZbZdPrjdzw8yNa1DdlAJuF9I/RLt/gyhxqa0kGe0=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=fQgf0yi18y6Ya+zvyIpRdSyzvn0vJiJZZbrYFA1gKyaata2j7Hu11YOVamXcFdfih9
         drZIYqssjHiYYuux/+/epeK59myJKkPoShzIqF2KmWdMHt1EYfQBRN+f8oJ/8/+hpiKH
         jRXwJJUM+Isb6IoH1/TZ5jlqPtcBT8eq5WisrFa+LI0XJl2RTvt3b2BrqSMJaTX5Q2vI
         QSlaX/5C62kvh1veRD2qgeMi7Hsj/Da24F5KmewDTaewjkXUkOm+E7GpZgpPXSwbgRsR
         yh9HZdKO9UT1Q75GCIAwNH6MxtNk4IfcjVv6tldUC9b0/DGZay149o7DXEmAU4eFv3sv
         YNXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=N8uHipkZ;
       spf=pass (google.com: domain of 3_co3zqykcaiuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3_co3ZQYKCaIUWTGPDIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id h3-20020a0561023d8300b004508d6fcf6csi960476vsv.1.2023.10.24.06.47.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_co3zqykcaiuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-d9b9f56489fso5395355276.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:42 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:7755:0:b0:d9a:519f:d0e6 with SMTP id
 s82-20020a257755000000b00d9a519fd0e6mr234250ybc.6.1698155261852; Tue, 24 Oct
 2023 06:47:41 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:24 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-28-surenb@google.com>
Subject: [PATCH v2 27/39] xfs: Memory allocation profiling fixups
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
 header.i=@google.com header.s=20230601 header.b=N8uHipkZ;       spf=pass
 (google.com: domain of 3_co3zqykcaiuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3_co3ZQYKCaIUWTGPDIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--surenb.bounces.google.com;
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

This adds an alloc_hooks() wrapper around kmem_alloc(), so that we can
have allocations accounted to the proper callsite.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 fs/xfs/kmem.c |  4 ++--
 fs/xfs/kmem.h | 10 ++++------
 2 files changed, 6 insertions(+), 8 deletions(-)

diff --git a/fs/xfs/kmem.c b/fs/xfs/kmem.c
index c557a030acfe..9aa57a4e2478 100644
--- a/fs/xfs/kmem.c
+++ b/fs/xfs/kmem.c
@@ -8,7 +8,7 @@
 #include "xfs_trace.h"
 
 void *
-kmem_alloc(size_t size, xfs_km_flags_t flags)
+kmem_alloc_noprof(size_t size, xfs_km_flags_t flags)
 {
 	int	retries = 0;
 	gfp_t	lflags = kmem_flags_convert(flags);
@@ -17,7 +17,7 @@ kmem_alloc(size_t size, xfs_km_flags_t flags)
 	trace_kmem_alloc(size, flags, _RET_IP_);
 
 	do {
-		ptr = kmalloc(size, lflags);
+		ptr = kmalloc_noprof(size, lflags);
 		if (ptr || (flags & KM_MAYFAIL))
 			return ptr;
 		if (!(++retries % 100))
diff --git a/fs/xfs/kmem.h b/fs/xfs/kmem.h
index b987dc2c6851..c4cf1dc2a7af 100644
--- a/fs/xfs/kmem.h
+++ b/fs/xfs/kmem.h
@@ -6,6 +6,7 @@
 #ifndef __XFS_SUPPORT_KMEM_H__
 #define __XFS_SUPPORT_KMEM_H__
 
+#include <linux/alloc_tag.h>
 #include <linux/slab.h>
 #include <linux/sched.h>
 #include <linux/mm.h>
@@ -56,18 +57,15 @@ kmem_flags_convert(xfs_km_flags_t flags)
 	return lflags;
 }
 
-extern void *kmem_alloc(size_t, xfs_km_flags_t);
 static inline void  kmem_free(const void *ptr)
 {
 	kvfree(ptr);
 }
 
+extern void *kmem_alloc_noprof(size_t, xfs_km_flags_t);
+#define kmem_alloc(...)			alloc_hooks(kmem_alloc_noprof(__VA_ARGS__))
 
-static inline void *
-kmem_zalloc(size_t size, xfs_km_flags_t flags)
-{
-	return kmem_alloc(size, flags | KM_ZERO);
-}
+#define kmem_zalloc(_size, _flags)	kmem_alloc((_size), (_flags) | KM_ZERO)
 
 /*
  * Zone interfaces
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-28-surenb%40google.com.
