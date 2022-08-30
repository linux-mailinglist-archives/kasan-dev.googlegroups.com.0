Return-Path: <kasan-dev+bncBC7OD3FKWUERB3ELXKMAMGQEXJ65IMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 84AD25A6F7A
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:34 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id h12-20020a4ad28c000000b00448bee68970sf5844026oos.10
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896173; cv=pass;
        d=google.com; s=arc-20160816;
        b=WTfPphS3SO4GL2Yf63wnzCo7dD8+H4AllJrZTZcADhqW9Hi5gZsR7TkcupcDtRzu3u
         rUYM3jpg5TqKSWFR7H1xiQ2dInxzHDF8FFa1ngGaZti1oUxontLb4DU/J+TXlNUcWo+d
         GQ1AyGTQAm3ydhpdpBj3/Hnp9ZL78cor3obld2hO08+jeIKj0IfsqA+VXyzvDAgLzRq9
         cTkbuBEvnYQeKudmJ1I3LBt2N19+4V6tFz/Wab6TpqtMBdR1KNCQgsn3Qi5ZpiWTyLp3
         CrMorRl8EYBOVlfru65Ihxi5Uh6HyBFxTEEmibMydQDiDGSBFleoIMeGLmXpZEB3IUSE
         4jKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SGnrYQZO8uivHHNNgEVLBbA7WEU1Ncw4P2qrvQLsvvM=;
        b=pVwgS5O5gRWZsQAuoL8i3vMfMIFcf3z+XuqG4SgVstnn+N1+UM/mPRePIETAZtt1/i
         DOUWWgb0NjgMiTYsD9n86Pjh7jyUUzIFacDslDae0iLFp4GbUgxC5XHpgivjThyxdgj2
         G/LOsTydUHBNYpj3memg7FdVAO22yiApgHIsbSR8TwbDvDXthZ9xawriZOfco9JioQgE
         oKKjMHa/WX6Xyv9o8rOLwmWnqTrc/cU8eppkz8OsdSoaOE0dKiMiOMBkoiVOauZb2yEo
         hkphzrPrjBrNO/FbN/ifUtTijzlMp03XbxiXX2c8JH2LN20+WYNT05GP3qf4vDyF1OFy
         ZhxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hsapsq4I;
       spf=pass (google.com: domain of 37iuoywykcvebdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=37IUOYwYKCVEBDAx6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=SGnrYQZO8uivHHNNgEVLBbA7WEU1Ncw4P2qrvQLsvvM=;
        b=dh2J4T3YpK7Yh+bgNWbH8eJo4wdgh3Q+J6+U/4XinsbSg+nIV0g0KxaCBtP3WPYBS2
         I0pAw3bPiO4u9dJktUfjXT3mGOmDQHF4YGKkWH24rt++hIkm8ynZCEFtELZaxTR8xDBj
         ypvHCzBShp3HhpiQZFWFtv1YwhJ+ESsbfgK7LWjLtt0jUFZnxhESytqRaUau3ZcmPgPh
         9dIlRhHwkrKPP9BXhbg2FYf7EN+ntrAIx4pwCb/s/v/Cm33pR+HJBxmzCKFbcadyDLsT
         L9tNak9fNlGLafi72U8zfJOuNFrs1bUD4DqHs99a25KfR0PO8PMLr09lh1Gewou/hS19
         WJBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=SGnrYQZO8uivHHNNgEVLBbA7WEU1Ncw4P2qrvQLsvvM=;
        b=qCnxTuyr07cLhB3M1QqevL56Fo9K0wYTkmHS6RtHf2StDVikZm2lAXUGxIdCOsPnqd
         G7j/giQXJyqU+VDnXnRKw7Sg/mhn73meprQfc3QvNVRSuBYp9x+TumhLxVaxEiSR/QZW
         AubAi1jFQ135xcuQFKkPXcJcGu16v+F4oFF/frVthXUFsLGXsC02Tt6/RNT7F2eOWAVW
         tadtlSXvidvakXJhY9UsVQD9Lpg/LA92BKlrJS9RhcZpaEOovAb0hlCh+anudONIrngh
         hZm238lR77ocDMUH8ao2ZGkJ1HjJwSjhG1dtX0WsNK1TacY4Qoi8wjZmHbMdNaxcweEu
         c+Og==
X-Gm-Message-State: ACgBeo3ca2baT593dJ9mQmTTlCatpwM5un/vO0bEKUCnprt1ULXS7vro
	XapqTof6tvQtu4FYsEko3GA=
X-Google-Smtp-Source: AA6agR7fOYn38nKPwi6DHL08wp9YlcB30uaGTfoF0kCt91skqtJO1oF0iJPC0kFdBS7OBnATv8FbTw==
X-Received: by 2002:a05:6808:201f:b0:343:5aa7:606a with SMTP id q31-20020a056808201f00b003435aa7606amr28963oiw.178.1661896173095;
        Tue, 30 Aug 2022 14:49:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:13c8:b0:342:fca9:5e23 with SMTP id
 d8-20020a05680813c800b00342fca95e23ls3793851oiw.11.-pod-prod-gmail; Tue, 30
 Aug 2022 14:49:32 -0700 (PDT)
X-Received: by 2002:a05:6808:de0:b0:345:8f90:b51 with SMTP id g32-20020a0568080de000b003458f900b51mr28168oic.230.1661896172572;
        Tue, 30 Aug 2022 14:49:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896172; cv=none;
        d=google.com; s=arc-20160816;
        b=Ym0mtpjHmjt5XFvxYjtGlc7hoV5W6Ln+n5RC2mlXxoFzMycW9lFGBiBxjrFc/rqz9c
         RTFzZyY53oG37oBrECBeS1n2C5Zig9W1d6cATSeZFVTyEGLTcWruc2fZaI7LWb28PTJb
         Z8eiR+9DVNz8lTBmdrH/Vhpdie8+EaxLXYPbrQnGa8omLfydfB924AJ66T9F0y6slHa5
         wIBqYeluU1HokOl3HEmrzYBqa/3XCDkYewUv5Xgm0szXYFluqyMhRC0dif1alT3lzHXV
         64lJFsgOqG3AJ27Zk9k/JlFaJ9Nx0ax08BkAmnGLEPh/twrg8F6Xi0D0oKMXs2v79pvX
         mkWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Ax7BfvJ0osMGjEtA73bq+7eMx40gLvPyn7aoZ5x/9O0=;
        b=LA5QSPBzAj+X0LqhNivu/sLoeWQICMPHBm/uK7j4CYzkL0CS8FNNLPZ5QMXdpVcwjd
         ea+3rsKtgh612A1WkJkka2yOEPl4qppo74YKV5YSw37hfMi/LF/SzGQBFQ520siIG1UV
         YH9/TreGWd0MQeAmSe8Cf0xLcdR2xNV450r1/NYGcXRha1x70hPbWbzUk5kpDYgWLht+
         p/NYq9+ciy1FqXnIcwZAebJ6ysoFmAnwXySEy6m7Li67dewqUB/Ht1cORjGd52TLsHNO
         wTFpN5h+OgTf4g9YHG2loLgvTiAk9G9J+x2J4rlqGRoy7ofP3Zl68xSCRP5jG8iu4klc
         zMsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hsapsq4I;
       spf=pass (google.com: domain of 37iuoywykcvebdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=37IUOYwYKCVEBDAx6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id u15-20020a0568301f4f00b0063892f97dadsi683523oth.3.2022.08.30.14.49.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37iuoywykcvebdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id k126-20020a253d84000000b0068bb342010dso712154yba.1
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:32 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:3406:0:b0:69c:857b:7fd3 with SMTP id
 b6-20020a253406000000b0069c857b7fd3mr3099193yba.404.1661896172108; Tue, 30
 Aug 2022 14:49:32 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:48:52 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-4-surenb@google.com>
Subject: [RFC PATCH 03/30] Lazy percpu counters
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
 header.i=@google.com header.s=20210112 header.b=hsapsq4I;       spf=pass
 (google.com: domain of 37iuoywykcvebdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=37IUOYwYKCVEBDAx6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--surenb.bounces.google.com;
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

This patch adds lib/lazy-percpu-counter.c, which implements counters
that start out as atomics, but lazily switch to percpu mode if the
update rate crosses some threshold (arbitrarily set at 256 per second).

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/lazy-percpu-counter.h |  67 +++++++++++++
 lib/Kconfig                         |   3 +
 lib/Makefile                        |   2 +
 lib/lazy-percpu-counter.c           | 141 ++++++++++++++++++++++++++++
 4 files changed, 213 insertions(+)
 create mode 100644 include/linux/lazy-percpu-counter.h
 create mode 100644 lib/lazy-percpu-counter.c

diff --git a/include/linux/lazy-percpu-counter.h b/include/linux/lazy-percpu-counter.h
new file mode 100644
index 000000000000..a22a2b9a9f32
--- /dev/null
+++ b/include/linux/lazy-percpu-counter.h
@@ -0,0 +1,67 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Lazy percpu counters:
+ * (C) 2022 Kent Overstreet
+ *
+ * Lazy percpu counters start out in atomic mode, then switch to percpu mode if
+ * the update rate crosses some threshold.
+ *
+ * This means we don't have to decide between low memory overhead atomic
+ * counters and higher performance percpu counters - we can have our cake and
+ * eat it, too!
+ *
+ * Internally we use an atomic64_t, where the low bit indicates whether we're in
+ * percpu mode, and the high 8 bits are a secondary counter that's incremented
+ * when the counter is modified - meaning 55 bits of precision are available for
+ * the counter itself.
+ *
+ * lazy_percpu_counter is 16 bytes (on 64 bit machines), raw_lazy_percpu_counter
+ * is 8 bytes but requires a separate unsigned long to record when the counter
+ * wraps - because sometimes multiple counters are used together and can share
+ * the same timestamp.
+ */
+
+#ifndef _LINUX_LAZY_PERCPU_COUNTER_H
+#define _LINUX_LAZY_PERCPU_COUNTER_H
+
+struct raw_lazy_percpu_counter {
+	atomic64_t			v;
+};
+
+void __lazy_percpu_counter_exit(struct raw_lazy_percpu_counter *c);
+void __lazy_percpu_counter_add(struct raw_lazy_percpu_counter *c,
+			       unsigned long *last_wrap, s64 i);
+s64 __lazy_percpu_counter_read(struct raw_lazy_percpu_counter *c);
+
+static inline void __lazy_percpu_counter_sub(struct raw_lazy_percpu_counter *c,
+					     unsigned long *last_wrap, s64 i)
+{
+	__lazy_percpu_counter_add(c, last_wrap, -i);
+}
+
+struct lazy_percpu_counter {
+	struct raw_lazy_percpu_counter	v;
+	unsigned long			last_wrap;
+};
+
+static inline void lazy_percpu_counter_exit(struct lazy_percpu_counter *c)
+{
+	__lazy_percpu_counter_exit(&c->v);
+}
+
+static inline void lazy_percpu_counter_add(struct lazy_percpu_counter *c, s64 i)
+{
+	__lazy_percpu_counter_add(&c->v, &c->last_wrap, i);
+}
+
+static inline void lazy_percpu_counter_sub(struct lazy_percpu_counter *c, s64 i)
+{
+	__lazy_percpu_counter_sub(&c->v, &c->last_wrap, i);
+}
+
+static inline s64 lazy_percpu_counter_read(struct lazy_percpu_counter *c)
+{
+	return __lazy_percpu_counter_read(&c->v);
+}
+
+#endif /* _LINUX_LAZY_PERCPU_COUNTER_H */
diff --git a/lib/Kconfig b/lib/Kconfig
index dc1ab2ed1dc6..fc6dbc425728 100644
--- a/lib/Kconfig
+++ b/lib/Kconfig
@@ -498,6 +498,9 @@ config ASSOCIATIVE_ARRAY
 
 	  for more information.
 
+config LAZY_PERCPU_COUNTER
+	bool
+
 config HAS_IOMEM
 	bool
 	depends on !NO_IOMEM
diff --git a/lib/Makefile b/lib/Makefile
index ffabc30a27d4..cc7762748708 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -163,6 +163,8 @@ obj-$(CONFIG_DEBUG_PREEMPT) += smp_processor_id.o
 obj-$(CONFIG_DEBUG_LIST) += list_debug.o
 obj-$(CONFIG_DEBUG_OBJECTS) += debugobjects.o
 
+obj-$(CONFIG_LAZY_PERCPU_COUNTER) += lazy-percpu-counter.o
+
 obj-$(CONFIG_BITREVERSE) += bitrev.o
 obj-$(CONFIG_LINEAR_RANGES) += linear_ranges.o
 obj-$(CONFIG_PACKING)	+= packing.o
diff --git a/lib/lazy-percpu-counter.c b/lib/lazy-percpu-counter.c
new file mode 100644
index 000000000000..299ef36137ee
--- /dev/null
+++ b/lib/lazy-percpu-counter.c
@@ -0,0 +1,141 @@
+// SPDX-License-Identifier: GPL-2.0-only
+
+#include <linux/atomic.h>
+#include <linux/gfp.h>
+#include <linux/jiffies.h>
+#include <linux/lazy-percpu-counter.h>
+#include <linux/percpu.h>
+
+/*
+ * We use the high bits of the atomic counter for a secondary counter, which is
+ * incremented every time the counter is touched. When the secondary counter
+ * wraps, we check the time the counter last wrapped, and if it was recent
+ * enough that means the update frequency has crossed our threshold and we
+ * switch to percpu mode:
+ */
+#define COUNTER_MOD_BITS		8
+#define COUNTER_MOD_MASK		~(~0ULL >> COUNTER_MOD_BITS)
+#define COUNTER_MOD_BITS_START		(64 - COUNTER_MOD_BITS)
+
+/*
+ * We use the low bit of the counter to indicate whether we're in atomic mode
+ * (low bit clear), or percpu mode (low bit set, counter is a pointer to actual
+ * percpu counters:
+ */
+#define COUNTER_IS_PCPU_BIT		1
+
+static inline u64 __percpu *lazy_percpu_counter_is_pcpu(u64 v)
+{
+	if (!(v & COUNTER_IS_PCPU_BIT))
+		return NULL;
+
+	v ^= COUNTER_IS_PCPU_BIT;
+	return (u64 __percpu *)(unsigned long)v;
+}
+
+static inline s64 lazy_percpu_counter_atomic_val(s64 v)
+{
+	/* Ensure output is sign extended properly: */
+	return (v << COUNTER_MOD_BITS) >>
+		(COUNTER_MOD_BITS + COUNTER_IS_PCPU_BIT);
+}
+
+static void lazy_percpu_counter_switch_to_pcpu(struct raw_lazy_percpu_counter *c)
+{
+	u64 __percpu *pcpu_v = alloc_percpu_gfp(u64, GFP_ATOMIC|__GFP_NOWARN);
+	u64 old, new, v;
+
+	if (!pcpu_v)
+		return;
+
+	preempt_disable();
+	v = atomic64_read(&c->v);
+	do {
+		if (lazy_percpu_counter_is_pcpu(v)) {
+			free_percpu(pcpu_v);
+			return;
+		}
+
+		old = v;
+		new = (unsigned long)pcpu_v | 1;
+
+		*this_cpu_ptr(pcpu_v) = lazy_percpu_counter_atomic_val(v);
+	} while ((v = atomic64_cmpxchg(&c->v, old, new)) != old);
+	preempt_enable();
+}
+
+/**
+ * __lazy_percpu_counter_exit: Free resources associated with a
+ * raw_lazy_percpu_counter
+ *
+ * @c: counter to exit
+ */
+void __lazy_percpu_counter_exit(struct raw_lazy_percpu_counter *c)
+{
+	free_percpu(lazy_percpu_counter_is_pcpu(atomic64_read(&c->v)));
+}
+EXPORT_SYMBOL_GPL(__lazy_percpu_counter_exit);
+
+/**
+ * __lazy_percpu_counter_read: Read current value of a raw_lazy_percpu_counter
+ *
+ * @c: counter to read
+ */
+s64 __lazy_percpu_counter_read(struct raw_lazy_percpu_counter *c)
+{
+	s64 v = atomic64_read(&c->v);
+	u64 __percpu *pcpu_v = lazy_percpu_counter_is_pcpu(v);
+
+	if (pcpu_v) {
+		int cpu;
+
+		v = 0;
+		for_each_possible_cpu(cpu)
+			v += *per_cpu_ptr(pcpu_v, cpu);
+	} else {
+		v = lazy_percpu_counter_atomic_val(v);
+	}
+
+	return v;
+}
+EXPORT_SYMBOL_GPL(__lazy_percpu_counter_read);
+
+/**
+ * __lazy_percpu_counter_add: Add a value to a lazy_percpu_counter
+ *
+ * @c: counter to modify
+ * @last_wrap: pointer to a timestamp, updated when mod counter wraps
+ * @i: value to add
+ */
+void __lazy_percpu_counter_add(struct raw_lazy_percpu_counter *c,
+			       unsigned long *last_wrap, s64 i)
+{
+	u64 atomic_i;
+	u64 old, v = atomic64_read(&c->v);
+	u64 __percpu *pcpu_v;
+
+	atomic_i  = i << COUNTER_IS_PCPU_BIT;
+	atomic_i &= ~COUNTER_MOD_MASK;
+	atomic_i |= 1ULL << COUNTER_MOD_BITS_START;
+
+	do {
+		pcpu_v = lazy_percpu_counter_is_pcpu(v);
+		if (pcpu_v) {
+			this_cpu_add(*pcpu_v, i);
+			return;
+		}
+
+		old = v;
+	} while ((v = atomic64_cmpxchg(&c->v, old, old + atomic_i)) != old);
+
+	if (unlikely(!(v & COUNTER_MOD_MASK))) {
+		unsigned long now = jiffies;
+
+		if (*last_wrap &&
+		    unlikely(time_after(*last_wrap + HZ, now)))
+			lazy_percpu_counter_switch_to_pcpu(c);
+		else
+			*last_wrap = now;
+	}
+}
+EXPORT_SYMBOL(__lazy_percpu_counter_add);
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-4-surenb%40google.com.
