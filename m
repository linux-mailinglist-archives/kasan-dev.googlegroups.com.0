Return-Path: <kasan-dev+bncBC7OD3FKWUERB7O5X6RAMGQEQ3ROVGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F8856F33C0
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:26 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id a1e0cc1a2514c-76e7bd716d1sf646586241.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960125; cv=pass;
        d=google.com; s=arc-20160816;
        b=wxQ56DXFye+wAHjRiJuROdSVgLH/xxQ7PyO4jqlCDGPb3quOxl6gEXbR9I8orNoSv+
         7moysx6wCEaT9HTcFt5NySJPaSVrOA7Tf1C4z+IZLNEQMVB2qNfMIdt6gTwCresBdu3u
         kRZ6Gg3slTtmtpkVJFu6gh6qmgRy8ouiYHSbUoj4YF/ac382vDMtgRwjFnhS7oeLARCv
         TQRRKrKS9Yj1wLGE91DjzaLeddZwqJDwLEows1HwGwYrrFD6mPV+RRDgvfYGAh0vMcI6
         a28x4gwkxYY7V9bnviJp/U7Rw/eh2G96kcdNNLOfpoVAAEpNQeptykyMdWBmlu2J9vtV
         rEZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=CZ8txPp/Akh9EwD/3LoNn5Fl7M/jYJbvHGlFCp3Nb94=;
        b=Ep9mQJVKbnw/LPk0zceVAH1AKhpKOSVB6M2dIRgro9LYTwizOj10HiiB/eVB8nWRrU
         zgzVfjJ27+FfEjKWM5UjLw2mp37cRBNZwIsEvArWoKAa6g8P1jaKJJ3HCMQhigrC9hnZ
         6H9hy8zloIo0sRJOZyH8Nx0riAJZtlguIEiddxDuZBW8Wnhh6mL+76HT8w7HSX4VaZM7
         xJlWDStGq9Bp9JcS2lcWu3gTWB46WXaxABFSvzAcMOlMEXduyrAbxPITAPBn3W0ghfrD
         m9XTwXTzKsrMvCpPKDGSe5Hm4kia9wu8gxlqevuJh4LAMpOiEM0VFkpHkFoLazWj3/+A
         428w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=uyQWn2Ht;
       spf=pass (google.com: domain of 3_o5pzaykcumxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_O5PZAYKCUMxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960125; x=1685552125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=CZ8txPp/Akh9EwD/3LoNn5Fl7M/jYJbvHGlFCp3Nb94=;
        b=mhfIt2Vq45ZEsmSgWVZ67nvv4EyPrE0OisMg3DsT3nOKEY5umJ5cIzclmoU2fYhqh+
         eno1mDUhBPyqRnMAiiJyiN5UUPdEhUgEr4ynQpD8ThY47HdoZAkpUm0XZfvAPOSgNYQJ
         r/ZqFnJb04/DzH4qvrnpiQetBV2XXntkC8bk3Yd9tHxdZeUHfi/Zi+bxTF77alp0jkFw
         wx3NhFNRYqWDUJXv+JWIBWu92lInDm8oCgTjAHEZ3fXBUHaZFxAicZbFrES0grgLi6cY
         RfXLuxcu/F74Jsfx1R8p6tW4epaJjnkxe2NQjQOjRBlwMvVuZNEpuEFS5YoHf2D++Icq
         Hbnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960125; x=1685552125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CZ8txPp/Akh9EwD/3LoNn5Fl7M/jYJbvHGlFCp3Nb94=;
        b=cBwTTmIit2XjHz0UOSvch4KMr2WX+5wwNGgDKtHBgeWxsZExCz8Yk7QpG5DiZqtP1P
         SKvJud8vq7SyKveTMX10B+eKHpGsmuLK8x5o2B9yz9WGvU/rpxQawda//JMxpr2W2NYK
         V7EvEHGFqKd0cTK8fHYuVaQetjnvl22NYwXjmJV0PWfC7djyINgMhvBhNg0CrXUj9jzT
         lBZsFtbXybqNSN7jmuHn01rZeTIyVH6cj+v8i+ebyG7q8J13Qh7eab3zcwxRhk6jmRXD
         o2ylk9dlIMoreU824B2+gpLSzresZgrvJdCbdw7STUfjxIu1zM/KCXfDzMI+s1mjBxYz
         NZiQ==
X-Gm-Message-State: AC+VfDyGH3Al9z0eaQHuqwDDI3q3VrZQKjdnw7oUEMXH/RY6tf5V6zD1
	KeNsSD/IUro1WOwX50O4vQI=
X-Google-Smtp-Source: ACHHUZ4b3YqEGLF3oQ7L+u3GTHnCm9K1DQNjtdzMf81fwBR1t1eY/u3aUrmX3kgOWYgJIMgLsIxaiQ==
X-Received: by 2002:a67:e1d3:0:b0:42d:bb69:668d with SMTP id p19-20020a67e1d3000000b0042dbb69668dmr6873892vsl.4.1682960125213;
        Mon, 01 May 2023 09:55:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3f54:b0:426:b068:aa4a with SMTP id
 l20-20020a0561023f5400b00426b068aa4als2747129vsv.9.-pod-prod-gmail; Mon, 01
 May 2023 09:55:24 -0700 (PDT)
X-Received: by 2002:a05:6102:a9d:b0:42f:46d3:31ce with SMTP id n29-20020a0561020a9d00b0042f46d331cemr5602170vsg.28.1682960124487;
        Mon, 01 May 2023 09:55:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960124; cv=none;
        d=google.com; s=arc-20160816;
        b=1FBTm//1goe/dVDKzMuEC7d4kSkIaok5FtRo/4DVwffiIfiCRJ9i5VV/mfvgX83sCJ
         0FnUr51WRM2yRp6JKvMdUP272/YwuPsVOvskCFLkU1/zAB26kAUOG1NaPWho1+nMmxYm
         lO1JkHEgEG432Ryx5bTd3iXSHZdcgbSZPBBYneUGIw1+42SRCz9pB5w9px4oIqTpG6a2
         UI6VzvaEkiy23izs+BLZoB4zzyIh6vcGAQWJ9XgTeE/J5thg3t49UzxnWTNh7dGTIuyB
         3ZGFaEWPOep+/unMp7WnbtAABcaQcqXUa66rRbLry1Q+i8m4gnTpEPU4EjCphltkudGl
         GT7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=O9K7OqGn67XevhyLqxW8/t3YPJ+QYtYh9lmzl+bkJrg=;
        b=gLAFyHG07gE16Z4xRAay1BTDAzM5BsVG2gKinFXIc5cytANrVtW/f7T2x7PDrTvdo8
         XeIdrVbIozd1/SrKD9EvAhfhbp9VhRIdcV2+EzN7eqkpEy+TzrJM78IBUrqgMiNFeRAc
         Mh/7269IOvKiDshnl1Ax1vT8vA/Dz1vnrWO42ApQUv+7XZVx/Wln83Z/HNo0hVGJejrf
         xr2MUR9wItSn3OquXzpgvFajnh1dx3b1Cm/sM20/R5/mcQCY7QbgrXgdmNG+kQx70tya
         Py/KRtlRqaTTGwIw3lX7StK0Q3mEkwilKFP2zdp3KlGgx+4gmpwGf68JXOCZf2bSEDcB
         OJOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=uyQWn2Ht;
       spf=pass (google.com: domain of 3_o5pzaykcumxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_O5PZAYKCUMxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id az40-20020a05613003a800b0077d31fab956si112424uab.1.2023.05.01.09.55.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_o5pzaykcumxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a7df507c5so5360157276.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:24 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a05:6902:100e:b0:b8f:47c4:58ed with SMTP id
 w14-20020a056902100e00b00b8f47c458edmr8682966ybt.9.1682960124020; Mon, 01 May
 2023 09:55:24 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:17 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-8-surenb@google.com>
Subject: [PATCH 07/40] Lazy percpu counters
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
 header.i=@google.com header.s=20221208 header.b=uyQWn2Ht;       spf=pass
 (google.com: domain of 3_o5pzaykcumxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_O5PZAYKCUMxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
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
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/lazy-percpu-counter.h | 102 ++++++++++++++++++++++
 lib/Kconfig                         |   3 +
 lib/Makefile                        |   2 +
 lib/lazy-percpu-counter.c           | 127 ++++++++++++++++++++++++++++
 4 files changed, 234 insertions(+)
 create mode 100644 include/linux/lazy-percpu-counter.h
 create mode 100644 lib/lazy-percpu-counter.c

diff --git a/include/linux/lazy-percpu-counter.h b/include/linux/lazy-percpu-counter.h
new file mode 100644
index 000000000000..45ca9e2ce58b
--- /dev/null
+++ b/include/linux/lazy-percpu-counter.h
@@ -0,0 +1,102 @@
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
+ */
+
+#ifndef _LINUX_LAZY_PERCPU_COUNTER_H
+#define _LINUX_LAZY_PERCPU_COUNTER_H
+
+#include <linux/atomic.h>
+#include <asm/percpu.h>
+
+struct lazy_percpu_counter {
+	atomic64_t			v;
+	unsigned long			last_wrap;
+};
+
+void lazy_percpu_counter_exit(struct lazy_percpu_counter *c);
+void lazy_percpu_counter_add_slowpath(struct lazy_percpu_counter *c, s64 i);
+void lazy_percpu_counter_add_slowpath_noupgrade(struct lazy_percpu_counter *c, s64 i);
+s64 lazy_percpu_counter_read(struct lazy_percpu_counter *c);
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
+/**
+ * lazy_percpu_counter_add: Add a value to a lazy_percpu_counter
+ *
+ * @c: counter to modify
+ * @i: value to add
+ */
+static inline void lazy_percpu_counter_add(struct lazy_percpu_counter *c, s64 i)
+{
+	u64 v = atomic64_read(&c->v);
+	u64 __percpu *pcpu_v = lazy_percpu_counter_is_pcpu(v);
+
+	if (likely(pcpu_v))
+		this_cpu_add(*pcpu_v, i);
+	else
+		lazy_percpu_counter_add_slowpath(c, i);
+}
+
+/**
+ * lazy_percpu_counter_add_noupgrade: Add a value to a lazy_percpu_counter,
+ * without upgrading to percpu mode
+ *
+ * @c: counter to modify
+ * @i: value to add
+ */
+static inline void lazy_percpu_counter_add_noupgrade(struct lazy_percpu_counter *c, s64 i)
+{
+	u64 v = atomic64_read(&c->v);
+	u64 __percpu *pcpu_v = lazy_percpu_counter_is_pcpu(v);
+
+	if (likely(pcpu_v))
+		this_cpu_add(*pcpu_v, i);
+	else
+		lazy_percpu_counter_add_slowpath_noupgrade(c, i);
+}
+
+static inline void lazy_percpu_counter_sub(struct lazy_percpu_counter *c, s64 i)
+{
+	lazy_percpu_counter_add(c, -i);
+}
+
+#endif /* _LINUX_LAZY_PERCPU_COUNTER_H */
diff --git a/lib/Kconfig b/lib/Kconfig
index 5c2da561c516..7380292a8fcd 100644
--- a/lib/Kconfig
+++ b/lib/Kconfig
@@ -505,6 +505,9 @@ config ASSOCIATIVE_ARRAY
 
 	  for more information.
 
+config LAZY_PERCPU_COUNTER
+	bool
+
 config HAS_IOMEM
 	bool
 	depends on !NO_IOMEM
diff --git a/lib/Makefile b/lib/Makefile
index 876fcdeae34e..293a0858a3f8 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -164,6 +164,8 @@ obj-$(CONFIG_DEBUG_PREEMPT) += smp_processor_id.o
 obj-$(CONFIG_DEBUG_LIST) += list_debug.o
 obj-$(CONFIG_DEBUG_OBJECTS) += debugobjects.o
 
+obj-$(CONFIG_LAZY_PERCPU_COUNTER) += lazy-percpu-counter.o
+
 obj-$(CONFIG_BITREVERSE) += bitrev.o
 obj-$(CONFIG_LINEAR_RANGES) += linear_ranges.o
 obj-$(CONFIG_PACKING)	+= packing.o
diff --git a/lib/lazy-percpu-counter.c b/lib/lazy-percpu-counter.c
new file mode 100644
index 000000000000..4f4e32c2dc09
--- /dev/null
+++ b/lib/lazy-percpu-counter.c
@@ -0,0 +1,127 @@
+// SPDX-License-Identifier: GPL-2.0-only
+
+#include <linux/atomic.h>
+#include <linux/gfp.h>
+#include <linux/jiffies.h>
+#include <linux/lazy-percpu-counter.h>
+#include <linux/percpu.h>
+
+static inline s64 lazy_percpu_counter_atomic_val(s64 v)
+{
+	/* Ensure output is sign extended properly: */
+	return (v << COUNTER_MOD_BITS) >>
+		(COUNTER_MOD_BITS + COUNTER_IS_PCPU_BIT);
+}
+
+static void lazy_percpu_counter_switch_to_pcpu(struct lazy_percpu_counter *c)
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
+ * lazy_percpu_counter_exit: Free resources associated with a
+ * lazy_percpu_counter
+ *
+ * @c: counter to exit
+ */
+void lazy_percpu_counter_exit(struct lazy_percpu_counter *c)
+{
+	free_percpu(lazy_percpu_counter_is_pcpu(atomic64_read(&c->v)));
+}
+EXPORT_SYMBOL_GPL(lazy_percpu_counter_exit);
+
+/**
+ * lazy_percpu_counter_read: Read current value of a lazy_percpu_counter
+ *
+ * @c: counter to read
+ */
+s64 lazy_percpu_counter_read(struct lazy_percpu_counter *c)
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
+EXPORT_SYMBOL_GPL(lazy_percpu_counter_read);
+
+void lazy_percpu_counter_add_slowpath(struct lazy_percpu_counter *c, s64 i)
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
+		if (c->last_wrap &&
+		    unlikely(time_after(c->last_wrap + HZ, now)))
+			lazy_percpu_counter_switch_to_pcpu(c);
+		else
+			c->last_wrap = now;
+	}
+}
+EXPORT_SYMBOL(lazy_percpu_counter_add_slowpath);
+
+void lazy_percpu_counter_add_slowpath_noupgrade(struct lazy_percpu_counter *c, s64 i)
+{
+	u64 atomic_i;
+	u64 old, v = atomic64_read(&c->v);
+	u64 __percpu *pcpu_v;
+
+	atomic_i  = i << COUNTER_IS_PCPU_BIT;
+	atomic_i &= ~COUNTER_MOD_MASK;
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
+}
+EXPORT_SYMBOL(lazy_percpu_counter_add_slowpath_noupgrade);
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-8-surenb%40google.com.
