Return-Path: <kasan-dev+bncBC7OD3FKWUERBJUMXKMAMGQELGFGXEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id B5E375A6FA9
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:31 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id n6-20020a4a6106000000b0044b2434319esf5754710ooc.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896230; cv=pass;
        d=google.com; s=arc-20160816;
        b=deVLxFe03EC3V22zx4z861XYSfyXGn8U8hw0tpacKHTEPI2g2BI53MCL3EcIwwBRxr
         tu4UpRBCIrKV+nINqvlzDc0APUglsNcXZ90SS90DEcDOgO7tP3BjpehTakH5L4pa4Cn/
         362PNbXo1yejDtXxTkY8GczTwxNG039+SZvAgwy1UvqSfzLTM8I46wzF2NOitCxDFloE
         EPyWjCfubUbRUOyNVMhjfKZI7O+ELOOzPCts/SOWR7A/Tnkg1wd7KavtiCNOm0kOUsr9
         ZS2xizzfV/1G56owbH3wfEDpDa7zKvRb6atbMBdg6CLJmw15hm5PdxMg4FgcSN/wqM0r
         CmzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=0pHd19y55e6BogyIqhpL2+GJrppct4gnYRbDHn1EXGM=;
        b=GR1HJQQYPODJu5LQ4+I+AEHBeVVeLf5Vz33JEttvOkqmqFCpb8o7VO/z4LeTcwEPgq
         ag51jFCqhTPl8vantdYqLbrctJmymMQkVt6ggW+6EOS4iKoZRRde5pkMQ+mnq2jjlqsk
         c00KW+TK1Trfzu9g+6ZZwmtA/hNjpK+9NEYClPIAlmJ+2FnYnLW2M27dW02/0JgXvOhI
         qtEHfvAMLCHNOQzXR70JVG3+UnPTXzPjy2X6Cb7M9Dbnd1qFi0O9ulDqFI+J8qq3aJPn
         4De0rSqUnKi1XEd1ajAuuu1wWPQKPi7Zk+nmJYJGLIZ9VIiDpfel5EnEmvtTDIrgd2bi
         Lo2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="EmELHff/";
       spf=pass (google.com: domain of 3jyyoywykcyo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JYYOYwYKCYo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=0pHd19y55e6BogyIqhpL2+GJrppct4gnYRbDHn1EXGM=;
        b=KQqmEjqOPNiEI9Uv6NUTYKWsTcX6+1PXxcYGvreIkaFG1GlhASTfGbXFh9yOztWXAd
         e72oCm/5BbIAU931YgNToWupSUlXN7nn7HUuXHmHioywNTln2pwRhnaW4cY9gsOvyBzE
         D2kIDdH+sgVDeWzcGDwTsIGY9M/1daQRuJQEt5Gi9b5Sa69mHa0nRM7u6x8TiZw8xbo3
         904Eh4nskYd22FKm+62qVpcz9EhQA574noF2rnrK6cSh0pWx1oXtlSoDk+5PNqBt5qHX
         cOBEyNhCrpxhhP502kC2IhYsVYPO/czR3UPslC75ZUcMmUJ17s3BjQ0fDrVXalO+sfWC
         siFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=0pHd19y55e6BogyIqhpL2+GJrppct4gnYRbDHn1EXGM=;
        b=MxBEu/zb4IYl/2mUHwIBlHI20w7T9mIvyeWtWHB1bz4N2IW2FSoMg41EQ5c3RLyLno
         xyGQDvZdc5IPhzhhBYEGmANFnCkXBtXqggg6iOrDO8Zj0gZsrGygb5yXBIE5ahW32z1E
         zgW+K92cTb27RI2SqKqpF2SxcXGStlbxxD+sTYcdPJY42VyU+BndcvaW8IKjxJ4avJjH
         EgCKmf2yiyZDlpBcmbw9PY+BJtGiIyaXRMwewdSs/c1y4gQ7XdVAb8+UDC9u1u9+dm7X
         2PXgxtI8YekJlo/YO6xuq+Zvxq4OAXYdrqsOGww37i1QjBRgr5rnhJYsuumBA99EfIWy
         PSSA==
X-Gm-Message-State: ACgBeo1ErYMug8VlYXoUngZ9oBmCvi/IMKMSmK227PITfc+UbxZZFIIl
	sVEkYCKzOM7oGl4VGdCDMm4=
X-Google-Smtp-Source: AA6agR4Ir8+EcVDm6h0+Vk+fyaZo+D8R5+ZbAbOGr7wNjSBC8mWNvJVPZWJnhymF64gcvs8bOQL0Zw==
X-Received: by 2002:a9d:d83:0:b0:639:c1a4:4d78 with SMTP id 3-20020a9d0d83000000b00639c1a44d78mr7605927ots.100.1661896230721;
        Tue, 30 Aug 2022 14:50:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9596:b0:11c:88f5:79d7 with SMTP id
 k22-20020a056870959600b0011c88f579d7ls4218095oao.3.-pod-prod-gmail; Tue, 30
 Aug 2022 14:50:30 -0700 (PDT)
X-Received: by 2002:a05:6870:c884:b0:118:ae35:e200 with SMTP id er4-20020a056870c88400b00118ae35e200mr34955oab.244.1661896230288;
        Tue, 30 Aug 2022 14:50:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896230; cv=none;
        d=google.com; s=arc-20160816;
        b=LKcoz928yyM+2ivj/JJjKqAxpyd7Y0F4U3CUNXF1w66ZWfTz+xt9r5ZCyQXVUFAW8x
         wOvQUPHMJGXGNdO1/JKtmXTa2fiYmn7LImHye078C64h0WLQTtQadtACH2SUlcjmmCs2
         He5YXDDmdIEffj3q/MFcFja0hJjmI1qYlCS4VtDjcDCu1jnD6pM1lOLy6NhYAiIcd8LG
         v3O3lLRRxcQvI60j7l+MFmJLnP4WoOkBzO0mVaZoq5Yq2v9KOBruTXzqcm0BxkhKBsWH
         nAnUPQFAtNl0Scl+ASP096ZlpOOEe8SxvISqMWx0LeqkWoBO89nupJ+xbHegC2eTFff9
         +NQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=QqkrsGdR9RIQpztjH+HKE2iaQK76d4alLlYGvP5mtuk=;
        b=T1sq+6sbAXMf17P4xgbZCKZHw2kspsNynKvxlq0n68G3I+N++w+dUO+x/eM/UGFt1i
         0Ff107YZREIM6cimV65xHiAKsrn5rOLl4OQGZ7yZ9oTqlX1dmEz+UHL9iDhdgmBy7LYh
         1ODRbs7u0buKCRzgAi/B17foi6XWeFMz0vDdxNpShnZ8Oi97mJKERsNznyt0dATkVJcn
         UHNgMESfka4r/srQbLbp6maXf7aGMW1i8BGezrWQJHC3aPFFZodXQiOoXj9w2Ksu2qWP
         iwXySUuV2ys7pdgT47v0bas5sy9lTMuhdBJ0cYAIKQjZe764QmvK1jHSnsGboN42LIMS
         allA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="EmELHff/";
       spf=pass (google.com: domain of 3jyyoywykcyo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JYYOYwYKCYo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id z42-20020a056870462a00b0011c14eefa66si1291778oao.5.2022.08.30.14.50.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jyyoywykcyo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id d135-20020a25688d000000b0069578d248abso727206ybc.21
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:30 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:4246:0:b0:699:186f:76ca with SMTP id
 p67-20020a254246000000b00699186f76camr13282039yba.272.1661896229901; Tue, 30
 Aug 2022 14:50:29 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:14 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-26-surenb@google.com>
Subject: [RFC PATCH 25/30] lib/time_stats: New library for statistics on events
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
 header.i=@google.com header.s=20210112 header.b="EmELHff/";       spf=pass
 (google.com: domain of 3jyyoywykcyo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JYYOYwYKCYo685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com;
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

This adds a small new library for tracking statistics on events that
have a duration, i.e. a start and end time.

 - number of events
 - rate/frequency
 - average duration
 - max duration
 - duration quantiles

This code comes from bcachefs, and originally bcache: the next patch
will be converting bcache to use this version, and a subsequent patch
will be using code_tagging to instrument all wait_event() calls in the
kernel.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/time_stats.h |  44 +++++++
 lib/Kconfig                |   3 +
 lib/Makefile               |   1 +
 lib/time_stats.c           | 236 +++++++++++++++++++++++++++++++++++++
 4 files changed, 284 insertions(+)
 create mode 100644 include/linux/time_stats.h
 create mode 100644 lib/time_stats.c

diff --git a/include/linux/time_stats.h b/include/linux/time_stats.h
new file mode 100644
index 000000000000..7ae929e6f836
--- /dev/null
+++ b/include/linux/time_stats.h
@@ -0,0 +1,44 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef _LINUX_TIMESTATS_H
+#define _LINUX_TIMESTATS_H
+
+#include <linux/spinlock_types.h>
+#include <linux/types.h>
+
+#define NR_QUANTILES	15
+
+struct quantiles {
+	struct quantile_entry {
+		u64	m;
+		u64	step;
+	}		entries[NR_QUANTILES];
+};
+
+struct time_stat_buffer {
+	unsigned int	nr;
+	struct time_stat_buffer_entry {
+		u64	start;
+		u64	end;
+	}		entries[32];
+};
+
+struct time_stats {
+	spinlock_t	lock;
+	u64		count;
+	/* all fields are in nanoseconds */
+	u64		average_duration;
+	u64		average_frequency;
+	u64		max_duration;
+	u64		last_event;
+	struct quantiles quantiles;
+
+	struct time_stat_buffer __percpu *buffer;
+};
+
+struct seq_buf;
+void time_stats_update(struct time_stats *stats, u64 start);
+void time_stats_to_text(struct seq_buf *out, struct time_stats *stats);
+void time_stats_exit(struct time_stats *stats);
+
+#endif /* _LINUX_TIMESTATS_H */
diff --git a/lib/Kconfig b/lib/Kconfig
index fc6dbc425728..884fd9f2f06d 100644
--- a/lib/Kconfig
+++ b/lib/Kconfig
@@ -744,3 +744,6 @@ config ASN1_ENCODER
 
 config POLYNOMIAL
        tristate
+
+config TIME_STATS
+	bool
diff --git a/lib/Makefile b/lib/Makefile
index 489ea000c528..e54392011f5e 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -232,6 +232,7 @@ obj-$(CONFIG_ALLOC_TAGGING) += alloc_tag.o
 obj-$(CONFIG_PAGE_ALLOC_TAGGING) += pgalloc_tag.o
 
 obj-$(CONFIG_CODETAG_FAULT_INJECTION) += dynamic_fault.o
+obj-$(CONFIG_TIME_STATS) += time_stats.o
 
 lib-$(CONFIG_GENERIC_BUG) += bug.o
 
diff --git a/lib/time_stats.c b/lib/time_stats.c
new file mode 100644
index 000000000000..30362364fdd2
--- /dev/null
+++ b/lib/time_stats.c
@@ -0,0 +1,236 @@
+// SPDX-License-Identifier: GPL-2.0-only
+
+#include <linux/gfp.h>
+#include <linux/jiffies.h>
+#include <linux/kernel.h>
+#include <linux/ktime.h>
+#include <linux/percpu.h>
+#include <linux/seq_buf.h>
+#include <linux/spinlock.h>
+#include <linux/time_stats.h>
+#include <linux/timekeeping.h>
+
+static inline unsigned int eytzinger1_child(unsigned int i, unsigned int child)
+{
+	return (i << 1) + child;
+}
+
+static inline unsigned int eytzinger1_right_child(unsigned int i)
+{
+	return eytzinger1_child(i, 1);
+}
+
+static inline unsigned int eytzinger1_next(unsigned int i, unsigned int size)
+{
+	if (eytzinger1_right_child(i) <= size) {
+		i = eytzinger1_right_child(i);
+
+		i <<= __fls(size + 1) - __fls(i);
+		i >>= i > size;
+	} else {
+		i >>= ffz(i) + 1;
+	}
+
+	return i;
+}
+
+static inline unsigned int eytzinger0_child(unsigned int i, unsigned int child)
+{
+	return (i << 1) + 1 + child;
+}
+
+static inline unsigned int eytzinger0_first(unsigned int size)
+{
+	return rounddown_pow_of_two(size) - 1;
+}
+
+static inline unsigned int eytzinger0_next(unsigned int i, unsigned int size)
+{
+	return eytzinger1_next(i + 1, size) - 1;
+}
+
+#define eytzinger0_for_each(_i, _size)			\
+	for ((_i) = eytzinger0_first((_size));		\
+	     (_i) != -1;				\
+	     (_i) = eytzinger0_next((_i), (_size)))
+
+#define ewma_add(ewma, val, weight)					\
+({									\
+	typeof(ewma) _ewma = (ewma);					\
+	typeof(weight) _weight = (weight);				\
+									\
+	(((_ewma << _weight) - _ewma) + (val)) >> _weight;		\
+})
+
+static void quantiles_update(struct quantiles *q, u64 v)
+{
+	unsigned int i = 0;
+
+	while (i < ARRAY_SIZE(q->entries)) {
+		struct quantile_entry *e = q->entries + i;
+
+		if (unlikely(!e->step)) {
+			e->m = v;
+			e->step = max_t(unsigned int, v / 2, 1024);
+		} else if (e->m > v) {
+			e->m = e->m >= e->step
+				? e->m - e->step
+				: 0;
+		} else if (e->m < v) {
+			e->m = e->m + e->step > e->m
+				? e->m + e->step
+				: U32_MAX;
+		}
+
+		if ((e->m > v ? e->m - v : v - e->m) < e->step)
+			e->step = max_t(unsigned int, e->step / 2, 1);
+
+		if (v >= e->m)
+			break;
+
+		i = eytzinger0_child(i, v > e->m);
+	}
+}
+
+static void time_stats_update_one(struct time_stats *stats,
+				  u64 start, u64 end)
+{
+	u64 duration, freq;
+
+	duration	= time_after64(end, start)
+		? end - start : 0;
+	freq		= time_after64(end, stats->last_event)
+		? end - stats->last_event : 0;
+
+	stats->count++;
+
+	stats->average_duration = stats->average_duration
+		? ewma_add(stats->average_duration, duration, 6)
+		: duration;
+
+	stats->average_frequency = stats->average_frequency
+		? ewma_add(stats->average_frequency, freq, 6)
+		: freq;
+
+	stats->max_duration = max(stats->max_duration, duration);
+
+	stats->last_event = end;
+
+	quantiles_update(&stats->quantiles, duration);
+}
+
+void time_stats_update(struct time_stats *stats, u64 start)
+{
+	u64 end = ktime_get_ns();
+	unsigned long flags;
+
+	if (!stats->buffer) {
+		spin_lock_irqsave(&stats->lock, flags);
+		time_stats_update_one(stats, start, end);
+
+		if (stats->average_frequency < 32 &&
+		    stats->count > 1024)
+			stats->buffer =
+				alloc_percpu_gfp(struct time_stat_buffer,
+						 GFP_ATOMIC);
+		spin_unlock_irqrestore(&stats->lock, flags);
+	} else {
+		struct time_stat_buffer_entry *i;
+		struct time_stat_buffer *b;
+
+		preempt_disable();
+		b = this_cpu_ptr(stats->buffer);
+
+		BUG_ON(b->nr >= ARRAY_SIZE(b->entries));
+		b->entries[b->nr++] = (struct time_stat_buffer_entry) {
+			.start = start,
+			.end = end
+		};
+
+		if (b->nr == ARRAY_SIZE(b->entries)) {
+			spin_lock_irqsave(&stats->lock, flags);
+			for (i = b->entries;
+			     i < b->entries + ARRAY_SIZE(b->entries);
+			     i++)
+				time_stats_update_one(stats, i->start, i->end);
+			spin_unlock_irqrestore(&stats->lock, flags);
+
+			b->nr = 0;
+		}
+
+		preempt_enable();
+	}
+}
+EXPORT_SYMBOL(time_stats_update);
+
+static const struct time_unit {
+	const char	*name;
+	u32		nsecs;
+} time_units[] = {
+	{ "ns",		1		},
+	{ "us",		NSEC_PER_USEC	},
+	{ "ms",		NSEC_PER_MSEC	},
+	{ "sec",	NSEC_PER_SEC	},
+};
+
+static const struct time_unit *pick_time_units(u64 ns)
+{
+	const struct time_unit *u;
+
+	for (u = time_units;
+	     u + 1 < time_units + ARRAY_SIZE(time_units) &&
+	     ns >= u[1].nsecs << 1;
+	     u++)
+		;
+
+	return u;
+}
+
+static void pr_time_units(struct seq_buf *out, u64 ns)
+{
+	const struct time_unit *u = pick_time_units(ns);
+
+	seq_buf_printf(out, "%llu %s", div_u64(ns, u->nsecs), u->name);
+}
+
+void time_stats_to_text(struct seq_buf *out, struct time_stats *stats)
+{
+	const struct time_unit *u;
+	u64 freq = READ_ONCE(stats->average_frequency);
+	u64 q, last_q = 0;
+	int i;
+
+	seq_buf_printf(out, "count:          %llu\n", stats->count);
+	seq_buf_printf(out, "rate:           %llu/sec\n",
+		       freq ? div64_u64(NSEC_PER_SEC, freq) : 0);
+	seq_buf_printf(out, "frequency:      ");
+	pr_time_units(out, freq);
+	seq_buf_putc(out, '\n');
+
+	seq_buf_printf(out, "avg duration:   ");
+	pr_time_units(out, stats->average_duration);
+	seq_buf_putc(out, '\n');
+
+	seq_buf_printf(out, "max duration:   ");
+	pr_time_units(out, stats->max_duration);
+	seq_buf_putc(out, '\n');
+
+	i = eytzinger0_first(NR_QUANTILES);
+	u = pick_time_units(stats->quantiles.entries[i].m);
+	seq_buf_printf(out, "quantiles (%s): ", u->name);
+	eytzinger0_for_each(i, NR_QUANTILES) {
+		q = max(stats->quantiles.entries[i].m, last_q);
+		seq_buf_printf(out, "%llu ", div_u64(q, u->nsecs));
+		last_q = q;
+	}
+
+	seq_buf_putc(out, '\n');
+}
+EXPORT_SYMBOL_GPL(time_stats_to_text);
+
+void time_stats_exit(struct time_stats *stats)
+{
+	free_percpu(stats->buffer);
+	stats->buffer = NULL;
+}
+EXPORT_SYMBOL_GPL(time_stats_exit);
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-26-surenb%40google.com.
