Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2PA7W7QMGQECHWCFPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id F1220A8B473
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 10:55:07 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id a640c23a62f3a-ac79e4764e5sf28462366b.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 01:55:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744793707; cv=pass;
        d=google.com; s=arc-20240605;
        b=jHQ3+bEQXK2EF5EboMiuDwh0BAJzWHXxNi6xy7Km+Eu+e1XvWWSnKZu/vP5hUYhxLB
         3L/LMeJ5yExKMtNjUp5lljUZqZmcUlHm0ohWAGmnDhA+2xTevWno/IPxWr+CcxdIcqsW
         /lop72ZfizEZwSGkWUtJMFk6mG5Dkdj3BW4Bo9Y6LFRpKKQSiNCygAprvHKwFcNC8pnO
         AFMTt4ZGKBmPFKdPecFjHydTYl4DfD/B5ceinG7h4lKZoeQy9Xbx9Vd9qP1wUDoIgGgM
         XKxyZdH9PlE9blGL1tYzo1Sk/GAUHL+QnqO6dbv6zC3hlcFKx5h6EolmisMRUGrEzrG1
         L59Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=gtgSzVMJCNxuppOuq6BJCm32OHukTua7kt2m+0hSBbQ=;
        fh=pQWf2qGCiiUvuu8Gukfej6lzq10pnnESP5+UorNxX+g=;
        b=P3jB/F6OquDYCvdeiwIgZV9vJGTybeY9cFnOkBN/91LqcrWdnffGlnSiaBLIZ9t9/z
         dgxLR/TEOtoxJKyV6WWcEy2fJyWYPIz8Un88H2NRI6Hrqx/M0c9tg7P0af23ilqRJs69
         JyeH3HwdiEp8U3IcS8bKFK8YMfQuEnd82cyJH2xXa/AMuVXmVhAAM640wqyOsv9s85c6
         I+Hxi2C8MGCquPAaNZV2aR79V8vZ6K4cHVwL1GEiwYrF39EfO12MeFNaV85ZcEbSwXiu
         pBub7VG8HaoRbCYUjdrI46hXTTHKFv7s//2OBds17NSoqzYhrnHxXRnengX/sBSQ9Oso
         7NFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="3jKve/yE";
       spf=pass (google.com: domain of 3znd_zwykcysv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ZnD_ZwYKCYsv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744793707; x=1745398507; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gtgSzVMJCNxuppOuq6BJCm32OHukTua7kt2m+0hSBbQ=;
        b=sSP3jYyLz14zqJrVn++zOaqLoPMLBo4JQLp6lXSiMXTxdHnqef781nel4CjKe0D5Uj
         h+KpnoNHv8oIbmYZdP+van+7sKqGBAsAbumWxSCMQrM4DRBnzqeTLY9rh/UzezWow5ES
         CEctzZjKHaQ+/pM8JximBmoNwAobs/sPckwXyCL4WgH4wV/+w19EAbTg+BkqCv/QNtJr
         CAT8yafN+Ss5hemsuhzjJAppATkBwB09POwqk8G5DRI7fkUOkhMW2NPxdzYFwwJr47E1
         gvbnKLCZSqPRLEDzwYwaDcKFU4UVqptiMh3NpTYAGcHY4MX9i0GF1BNqRxkk3BcCZgWz
         MLCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744793707; x=1745398507;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gtgSzVMJCNxuppOuq6BJCm32OHukTua7kt2m+0hSBbQ=;
        b=OxU15OfsXwpEOb0LTl28eGmZ9tRC23V3CVrvOUrzz1UNTQX+2earU5zyZP6H4idZBr
         u0Ihs3ke7p49T285S7pNV8/v9COydOY+7Hqd3BhVhmW6CPMv/wcghUL6ZK5n0tIFb5/M
         LTiIwpR3hAV9D8519lYRiZ2RnxzC2BnRSoN6oou+ZTuq3WxZ8jAKoTrxm5qpeNk/ujTL
         vLSK2fGpTuwBFl7Ry4gN9EtDnEDlDzrkufw+J4MXG9megxTanRm+o+uS38tIOrKbTloM
         kSS8gr5OrNGuZlf7b/qvlybuACynM2PCF3f5qVR3Eay+SlofNZaRU1dAbwAV7aEIVLFG
         5DGQ==
X-Forwarded-Encrypted: i=2; AJvYcCWu+uTNko+OkOxuIN5ewr23m08c2KiR6nucDmVyFITAezSxgbJg9+/UzfJLLZUYOHzEyftErw==@lfdr.de
X-Gm-Message-State: AOJu0YwMTLsCmvBNQBkBhcYuvo4VgjP7Fc0UaLY5D5tWtFyAeToPZftR
	4y0WfyVGrhxS2TpQ3n6X3URDHRJ6LyVjwwNf2LycMN7LlaAd14iE
X-Google-Smtp-Source: AGHT+IGkjh8yJGNzDHhGwplRMfNzKfXDdZFqNoXLCiKSNogySGuGVPfXc544eKHKOHUmQt31gkuGNQ==
X-Received: by 2002:a05:6402:51d3:b0:5ed:c6aa:8c68 with SMTP id 4fb4d7f45d1cf-5f4b73449dfmr745140a12.5.1744793706476;
        Wed, 16 Apr 2025 01:55:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJSJzJ1jp+lawLZc/EqJlt6Hr40/kxWY7z4wqQ94cSJow==
Received: by 2002:a50:aa89:0:b0:5e4:b7fb:b4bc with SMTP id 4fb4d7f45d1cf-5f45952320bls110093a12.0.-pod-prod-06-eu;
 Wed, 16 Apr 2025 01:55:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+u78fy+cljo2GXRo+yvD7et7rQMeUjk/5C8Rj/vi5Qz7cYA3N7/lWTSqwYbnxyTM30F8Artzwcgs=@googlegroups.com
X-Received: by 2002:a05:6402:3511:b0:5ed:2762:727a with SMTP id 4fb4d7f45d1cf-5f4b748bc8cmr926057a12.11.1744793702648;
        Wed, 16 Apr 2025 01:55:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744793702; cv=none;
        d=google.com; s=arc-20240605;
        b=GiY9iiVy3Ba9bjacCZ32SFkTwZLp9lr2rLwE8JZiXg7qdyw/gwhZ3HbbDqkGBa+65s
         S+kAV07X+Gr2Aayamm53XPhot/c7FuZToI/paQwPOa9/2keUJZ0K2eP4aDuLFQn6Nspb
         vYNiOXiu5ahuHxlYZKXL+K8vHe4zzMqDNiiHTHgStz+KRxGX4/8DK3FaaUVKURnV7vNP
         TMHq5xPver4pcCPioe0gP6Wo2+A+7OZFEkTxUndnJP8brMwceqTz7sMTlqw7ZeLtMsIA
         JPu4u3CRWIa3wZqXAMZVH7e0HqVkqWFRfsfYiPuoPcA02IeYaQf7wFznl/HQP9WCx9Lq
         dI+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=sEqgbWaFKnoyLR0T1Nn8MCFuEM6WZXK8ceBl3Z/X9PI=;
        fh=gQnP7qr+pZ7XdWzdDoCYmbhfY644FEhySWJyLOuocTM=;
        b=kutyxnflFue5zMTBYb0JBGTdCmyCU0njxz0sjyN0oTdisFVFtKK4PVrHekfxLUKveS
         UnWnoXlWqmRNyOqxlr5H2EGElMjVJX69mfHpuh9NayR/VcLqQBFi5up6UmT1iZoW/WS9
         ToZjo2dx9AOdTeY22DttwOeC5T9NSp9whZKVGJoId8BZ0I/F2hG1UOxz6hmZKoCAXI9q
         Yo3wQsk8KuNFPGx/eZXkcL8FqIW5Sy/zSgR1mgAzYLQjNfxxe24nCJv8qpVrcFN0TUim
         SzdM5Qh8L7oU2PY4TRQibwYazsTqYsoiaG+bxEzgELqh09HM7KU0uGRbbqd9HGZlMxpJ
         FSSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="3jKve/yE";
       spf=pass (google.com: domain of 3znd_zwykcysv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ZnD_ZwYKCYsv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5f36f52542asi311742a12.5.2025.04.16.01.55.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 01:55:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3znd_zwykcysv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-ac7791ecb7bso55557366b.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 01:55:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVRazEWY++6Eyl50oeYHCzunygMswyNa/Y23DCfzr6Belg1HMMqnXpxpmv7D26sdSwv3zLV7hHufTE=@googlegroups.com
X-Received: from ejce27.prod.google.com ([2002:a17:906:375b:b0:ac7:9acb:58d3])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:6091:b0:acb:37ae:619c
 with SMTP id a640c23a62f3a-acb427d0d30mr81725666b.15.1744793702149; Wed, 16
 Apr 2025 01:55:02 -0700 (PDT)
Date: Wed, 16 Apr 2025 10:54:40 +0200
In-Reply-To: <20250416085446.480069-1-glider@google.com>
Mime-Version: 1.0
References: <20250416085446.480069-1-glider@google.com>
X-Mailer: git-send-email 2.49.0.604.gff1f9ca942-goog
Message-ID: <20250416085446.480069-3-glider@google.com>
Subject: [PATCH 2/7] kcov: factor out struct kcov_state
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="3jKve/yE";       spf=pass
 (google.com: domain of 3znd_zwykcysv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ZnD_ZwYKCYsv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Group several kcov-related fields (area, size, mode, sequence) that
are stored in various structures, into `struct kcov_state`, so that
these fields can be easily passed around and manipulated.

This prepares us for the upcoming change that will introduce more
kcov state.

Also update the MAINTAINERS entry.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 MAINTAINERS                |   1 +
 include/linux/kcov-state.h |  31 ++++++++
 include/linux/kcov.h       |  14 ++--
 include/linux/sched.h      |  16 +---
 kernel/kcov.c              | 149 ++++++++++++++++---------------------
 5 files changed, 106 insertions(+), 105 deletions(-)
 create mode 100644 include/linux/kcov-state.h

diff --git a/MAINTAINERS b/MAINTAINERS
index 00e94bec401e1..2f9bea40d9760 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -12511,6 +12511,7 @@ L:	kasan-dev@googlegroups.com
 S:	Maintained
 B:	https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
 F:	Documentation/dev-tools/kcov.rst
+F:	include/linux/kcov-state.h
 F:	include/linux/kcov.h
 F:	include/uapi/linux/kcov.h
 F:	kernel/kcov.c
diff --git a/include/linux/kcov-state.h b/include/linux/kcov-state.h
new file mode 100644
index 0000000000000..4c4688d01c616
--- /dev/null
+++ b/include/linux/kcov-state.h
@@ -0,0 +1,31 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_KCOV_STATE_H
+#define _LINUX_KCOV_STATE_H
+
+#ifdef CONFIG_KCOV
+struct kcov_state {
+	/* See kernel/kcov.c for more details. */
+	/*
+	 * Coverage collection mode enabled for this task (0 if disabled).
+	 * This field is used for synchronization, so it is kept outside of
+	 * the below struct.
+	 */
+	unsigned int mode;
+
+	struct {
+		/* Size of the area (in long's). */
+		unsigned int size;
+
+		/* Buffer for coverage collection, shared with the userspace. */
+		void *area;
+
+		/*
+		 * KCOV sequence number: incremented each time kcov is
+		 * reenabled, used by kcov_remote_stop(), see the comment there.
+		 */
+		int sequence;
+	} s;
+};
+#endif /* CONFIG_KCOV */
+
+#endif /* _LINUX_KCOV_STATE_H */
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 932b4face1005..e1f7d793c1cb3 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -2,7 +2,7 @@
 #ifndef _LINUX_KCOV_H
 #define _LINUX_KCOV_H
 
-#include <linux/sched.h>
+#include <linux/kcov-state.h>
 #include <uapi/linux/kcov.h>
 
 struct task_struct;
@@ -30,14 +30,14 @@ enum kcov_mode {
 void kcov_task_init(struct task_struct *t);
 void kcov_task_exit(struct task_struct *t);
 
-#define kcov_prepare_switch(t)                   \
-	do {                                     \
-		(t)->kcov_mode |= KCOV_IN_CTXSW; \
+#define kcov_prepare_switch(t)                         \
+	do {                                           \
+		(t)->kcov_state.mode |= KCOV_IN_CTXSW; \
 	} while (0)
 
-#define kcov_finish_switch(t)                     \
-	do {                                      \
-		(t)->kcov_mode &= ~KCOV_IN_CTXSW; \
+#define kcov_finish_switch(t)                           \
+	do {                                            \
+		(t)->kcov_state.mode &= ~KCOV_IN_CTXSW; \
 	} while (0)
 
 /* See Documentation/dev-tools/kcov.rst for usage details. */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 9c15365a30c08..70077ad51083c 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -42,6 +42,7 @@
 #include <linux/restart_block.h>
 #include <uapi/linux/rseq.h>
 #include <linux/seqlock_types.h>
+#include <linux/kcov-state.h>
 #include <linux/kcsan.h>
 #include <linux/rv.h>
 #include <linux/livepatch_sched.h>
@@ -1485,26 +1486,13 @@ struct task_struct {
 #endif /* CONFIG_TRACING */
 
 #ifdef CONFIG_KCOV
-	/* See kernel/kcov.c for more details. */
-
-	/* Coverage collection mode enabled for this task (0 if disabled): */
-	unsigned int			kcov_mode;
-
-	/* Size of the kcov_area: */
-	unsigned int			kcov_size;
-
-	/* Buffer for coverage collection: */
-	void				*kcov_area;
-
+	struct kcov_state		kcov_state;
 	/* KCOV descriptor wired with this task or NULL: */
 	struct kcov			*kcov;
 
 	/* KCOV common handle for remote coverage collection: */
 	u64				kcov_handle;
 
-	/* KCOV sequence number: */
-	int				kcov_sequence;
-
 	/* Collect coverage from softirq context: */
 	unsigned int			kcov_softirq;
 #endif
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 7cc6123c2baa4..8fcbca236bec5 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -13,6 +13,7 @@
 #include <linux/init.h>
 #include <linux/jiffies.h>
 #include <linux/kcov.h>
+#include <linux/kcov-state.h>
 #include <linux/kmsan-checks.h>
 #include <linux/log2.h>
 #include <linux/mm.h>
@@ -54,24 +55,16 @@ struct kcov {
 	 *  - each code section for remote coverage collection
 	 */
 	refcount_t refcount;
-	/* The lock protects mode, size, area and t. */
+	/* The lock protects state and t. */
 	spinlock_t lock;
-	enum kcov_mode mode;
-	/* Size of arena (in long's). */
-	unsigned int size;
-	/* Coverage buffer shared with user space. */
-	void *area;
+	struct kcov_state state;
+
 	/* Task for which we collect coverage, or NULL. */
 	struct task_struct *t;
 	/* Collecting coverage from remote (background) threads. */
 	bool remote;
 	/* Size of remote area (in long's). */
 	unsigned int remote_size;
-	/*
-	 * Sequence is incremented each time kcov is reenabled, used by
-	 * kcov_remote_stop(), see the comment there.
-	 */
-	int sequence;
 };
 
 struct kcov_remote_area {
@@ -92,12 +85,8 @@ static struct list_head kcov_remote_areas = LIST_HEAD_INIT(kcov_remote_areas);
 struct kcov_percpu_data {
 	void *irq_area;
 	local_lock_t lock;
-
-	unsigned int saved_mode;
-	unsigned int saved_size;
-	void *saved_area;
 	struct kcov *saved_kcov;
-	int saved_sequence;
+	struct kcov_state saved_state;
 };
 
 static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) = {
@@ -184,7 +173,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
 	 */
 	if (!in_task() && !(in_softirq_really() && t->kcov_softirq))
 		return false;
-	mode = READ_ONCE(t->kcov_mode);
+	mode = READ_ONCE(t->kcov_state.mode);
 	/*
 	 * There is some code that runs in interrupts but for which
 	 * in_interrupt() returns false (e.g. preempt_schedule_irq()).
@@ -219,10 +208,10 @@ void notrace __sanitizer_cov_trace_pc(void)
 	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
 		return;
 
-	area = t->kcov_area;
+	area = t->kcov_state.s.area;
 	/* The first 64-bit word is the number of subsequent PCs. */
 	pos = READ_ONCE(area[0]) + 1;
-	if (likely(pos < t->kcov_size)) {
+	if (likely(pos < t->kcov_state.s.size)) {
 		/* Previously we write pc before updating pos. However, some
 		 * early interrupt code could bypass check_kcov_mode() check
 		 * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
@@ -252,10 +241,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 
 	/*
 	 * We write all comparison arguments and types as u64.
-	 * The buffer was allocated for t->kcov_size unsigned longs.
+	 * The buffer was allocated for t->kcov_state.size unsigned longs.
 	 */
-	area = (u64 *)t->kcov_area;
-	max_pos = t->kcov_size * sizeof(unsigned long);
+	area = (u64 *)t->kcov_state.s.area;
+	max_pos = t->kcov_state.s.size * sizeof(unsigned long);
 
 	count = READ_ONCE(area[0]);
 
@@ -356,33 +345,31 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_switch);
 #endif /* ifdef CONFIG_KCOV_ENABLE_COMPARISONS */
 
 static void kcov_start(struct task_struct *t, struct kcov *kcov,
-		       unsigned int size, void *area, enum kcov_mode mode,
-		       int sequence)
+		       struct kcov_state *state)
 {
-	kcov_debug("t = %px, size = %u, area = %px\n", t, size, area);
+	kcov_debug("t = %px, size = %u, area = %px\n", t, state->s.size,
+		   state->s.area);
 	t->kcov = kcov;
 	/* Cache in task struct for performance. */
-	t->kcov_size = size;
-	t->kcov_area = area;
-	t->kcov_sequence = sequence;
-	/* See comment in check_kcov_mode(). */
+	t->kcov_state.s = state->s;
 	barrier();
-	WRITE_ONCE(t->kcov_mode, mode);
+	/* See comment in check_kcov_mode(). */
+	WRITE_ONCE(t->kcov_state.mode, state->mode);
 }
 
 static void kcov_stop(struct task_struct *t)
 {
-	WRITE_ONCE(t->kcov_mode, KCOV_MODE_DISABLED);
+	WRITE_ONCE(t->kcov_state.mode, KCOV_MODE_DISABLED);
 	barrier();
 	t->kcov = NULL;
-	t->kcov_size = 0;
-	t->kcov_area = NULL;
+	t->kcov_state.s.size = 0;
+	t->kcov_state.s.area = NULL;
 }
 
 static void kcov_task_reset(struct task_struct *t)
 {
 	kcov_stop(t);
-	t->kcov_sequence = 0;
+	t->kcov_state.s.sequence = 0;
 	t->kcov_handle = 0;
 }
 
@@ -395,10 +382,10 @@ void kcov_task_init(struct task_struct *t)
 static void kcov_reset(struct kcov *kcov)
 {
 	kcov->t = NULL;
-	kcov->mode = KCOV_MODE_INIT;
+	kcov->state.mode = KCOV_MODE_INIT;
 	kcov->remote = false;
 	kcov->remote_size = 0;
-	kcov->sequence++;
+	kcov->state.s.sequence++;
 }
 
 static void kcov_remote_reset(struct kcov *kcov)
@@ -438,7 +425,7 @@ static void kcov_put(struct kcov *kcov)
 {
 	if (refcount_dec_and_test(&kcov->refcount)) {
 		kcov_remote_reset(kcov);
-		vfree(kcov->area);
+		vfree(kcov->state.s.area);
 		kfree(kcov);
 	}
 }
@@ -495,8 +482,8 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	unsigned long flags;
 
 	spin_lock_irqsave(&kcov->lock, flags);
-	size = kcov->size * sizeof(unsigned long);
-	if (kcov->area == NULL || vma->vm_pgoff != 0 ||
+	size = kcov->state.s.size * sizeof(unsigned long);
+	if (kcov->state.s.area == NULL || vma->vm_pgoff != 0 ||
 	    vma->vm_end - vma->vm_start != size) {
 		res = -EINVAL;
 		goto exit;
@@ -504,7 +491,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	spin_unlock_irqrestore(&kcov->lock, flags);
 	vm_flags_set(vma, VM_DONTEXPAND);
 	for (off = 0; off < size; off += PAGE_SIZE) {
-		page = vmalloc_to_page(kcov->area + off);
+		page = vmalloc_to_page(kcov->state.s.area + off);
 		res = vm_insert_page(vma, vma->vm_start + off, page);
 		if (res) {
 			pr_warn_once("kcov: vm_insert_page() failed\n");
@@ -524,8 +511,8 @@ static int kcov_open(struct inode *inode, struct file *filep)
 	kcov = kzalloc(sizeof(*kcov), GFP_KERNEL);
 	if (!kcov)
 		return -ENOMEM;
-	kcov->mode = KCOV_MODE_DISABLED;
-	kcov->sequence = 1;
+	kcov->state.mode = KCOV_MODE_DISABLED;
+	kcov->state.s.sequence = 1;
 	refcount_set(&kcov->refcount, 1);
 	spin_lock_init(&kcov->lock);
 	filep->private_data = kcov;
@@ -560,10 +547,10 @@ static int kcov_get_mode(unsigned long arg)
 static void kcov_fault_in_area(struct kcov *kcov)
 {
 	unsigned long stride = PAGE_SIZE / sizeof(unsigned long);
-	unsigned long *area = kcov->area;
+	unsigned long *area = kcov->state.s.area;
 	unsigned long offset;
 
-	for (offset = 0; offset < kcov->size; offset += stride)
+	for (offset = 0; offset < kcov->state.s.size; offset += stride)
 		READ_ONCE(area[offset]);
 }
 
@@ -602,7 +589,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		 * at task exit or voluntary by KCOV_DISABLE. After that it can
 		 * be enabled for another task.
 		 */
-		if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
+		if (kcov->state.mode != KCOV_MODE_INIT || !kcov->state.s.area)
 			return -EINVAL;
 		t = current;
 		if (kcov->t != NULL || t->kcov != NULL)
@@ -611,9 +598,8 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		if (mode < 0)
 			return mode;
 		kcov_fault_in_area(kcov);
-		kcov->mode = mode;
-		kcov_start(t, kcov, kcov->size, kcov->area, kcov->mode,
-			   kcov->sequence);
+		kcov->state.mode = mode;
+		kcov_start(t, kcov, &kcov->state);
 		kcov->t = t;
 		/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
 		kcov_get(kcov);
@@ -630,7 +616,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		kcov_put(kcov);
 		return 0;
 	case KCOV_REMOTE_ENABLE:
-		if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
+		if (kcov->state.mode != KCOV_MODE_INIT || !kcov->state.s.area)
 			return -EINVAL;
 		t = current;
 		if (kcov->t != NULL || t->kcov != NULL)
@@ -642,9 +628,9 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		if ((unsigned long)remote_arg->area_size >
 		    LONG_MAX / sizeof(unsigned long))
 			return -EINVAL;
-		kcov->mode = mode;
+		kcov->state.mode = mode;
 		t->kcov = kcov;
-		t->kcov_mode = KCOV_MODE_REMOTE;
+		t->kcov_state.mode = KCOV_MODE_REMOTE;
 		kcov->t = t;
 		kcov->remote = true;
 		kcov->remote_size = remote_arg->area_size;
@@ -719,14 +705,14 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 		if (area == NULL)
 			return -ENOMEM;
 		spin_lock_irqsave(&kcov->lock, flags);
-		if (kcov->mode != KCOV_MODE_DISABLED) {
+		if (kcov->state.mode != KCOV_MODE_DISABLED) {
 			spin_unlock_irqrestore(&kcov->lock, flags);
 			vfree(area);
 			return -EBUSY;
 		}
-		kcov->area = area;
-		kcov->size = size;
-		kcov->mode = KCOV_MODE_INIT;
+		kcov->state.s.area = area;
+		kcov->state.s.size = size;
+		kcov->state.mode = KCOV_MODE_INIT;
 		spin_unlock_irqrestore(&kcov->lock, flags);
 		return 0;
 	case KCOV_REMOTE_ENABLE:
@@ -822,13 +808,11 @@ static void kcov_remote_softirq_start(struct task_struct *t)
 	struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
 	unsigned int mode;
 
-	mode = READ_ONCE(t->kcov_mode);
+	mode = READ_ONCE(t->kcov_state.mode);
 	barrier();
 	if (kcov_mode_enabled(mode)) {
-		data->saved_mode = mode;
-		data->saved_size = t->kcov_size;
-		data->saved_area = t->kcov_area;
-		data->saved_sequence = t->kcov_sequence;
+		data->saved_state.s = t->kcov_state.s;
+		data->saved_state.mode = mode;
 		data->saved_kcov = t->kcov;
 		kcov_stop(t);
 	}
@@ -839,13 +823,8 @@ static void kcov_remote_softirq_stop(struct task_struct *t)
 	struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
 
 	if (data->saved_kcov) {
-		kcov_start(t, data->saved_kcov, data->saved_size,
-			   data->saved_area, data->saved_mode,
-			   data->saved_sequence);
-		data->saved_mode = 0;
-		data->saved_size = 0;
-		data->saved_area = NULL;
-		data->saved_sequence = 0;
+		kcov_start(t, data->saved_kcov, &data->saved_state);
+		data->saved_state = (struct kcov_state){ 0 };
 		data->saved_kcov = NULL;
 	}
 }
@@ -854,12 +833,11 @@ void kcov_remote_start(u64 handle)
 {
 	struct task_struct *t = current;
 	struct kcov_remote *remote;
+	struct kcov_state state;
+	unsigned long flags;
+	unsigned int size;
 	struct kcov *kcov;
-	unsigned int mode;
 	void *area;
-	unsigned int size;
-	int sequence;
-	unsigned long flags;
 
 	if (WARN_ON(!kcov_check_handle(handle, true, true, true)))
 		return;
@@ -872,8 +850,8 @@ void kcov_remote_start(u64 handle)
 	 * Check that kcov_remote_start() is not called twice in background
 	 * threads nor called by user tasks (with enabled kcov).
 	 */
-	mode = READ_ONCE(t->kcov_mode);
-	if (WARN_ON(in_task() && kcov_mode_enabled(mode))) {
+	state.mode = READ_ONCE(t->kcov_state.mode);
+	if (WARN_ON(in_task() && kcov_mode_enabled(state.mode))) {
 		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 		return;
 	}
@@ -903,8 +881,8 @@ void kcov_remote_start(u64 handle)
 	 * Read kcov fields before unlock to prevent races with
 	 * KCOV_DISABLE / kcov_remote_reset().
 	 */
-	mode = kcov->mode;
-	sequence = kcov->sequence;
+	state.mode = kcov->state.mode;
+	state.s.sequence = kcov->state.s.sequence;
 	if (in_task()) {
 		size = kcov->remote_size;
 		area = kcov_remote_area_get(size);
@@ -927,12 +905,14 @@ void kcov_remote_start(u64 handle)
 
 	/* Reset coverage size. */
 	*(u64 *)area = 0;
+	state.s.area = area;
+	state.s.size = size;
 
 	if (in_serving_softirq()) {
 		kcov_remote_softirq_start(t);
 		t->kcov_softirq = 1;
 	}
-	kcov_start(t, kcov, size, area, mode, sequence);
+	kcov_start(t, kcov, &state);
 
 	local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 }
@@ -1009,7 +989,7 @@ void kcov_remote_stop(void)
 
 	local_lock_irqsave(&kcov_percpu_data.lock, flags);
 
-	mode = READ_ONCE(t->kcov_mode);
+	mode = READ_ONCE(t->kcov_state.mode);
 	barrier();
 	if (!kcov_mode_enabled(mode)) {
 		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
@@ -1030,9 +1010,9 @@ void kcov_remote_stop(void)
 	}
 
 	kcov = t->kcov;
-	area = t->kcov_area;
-	size = t->kcov_size;
-	sequence = t->kcov_sequence;
+	area = t->kcov_state.s.area;
+	size = t->kcov_state.s.size;
+	sequence = t->kcov_state.s.sequence;
 
 	kcov_stop(t);
 	if (in_serving_softirq()) {
@@ -1045,8 +1025,9 @@ void kcov_remote_stop(void)
 	 * KCOV_DISABLE could have been called between kcov_remote_start()
 	 * and kcov_remote_stop(), hence the sequence check.
 	 */
-	if (sequence == kcov->sequence && kcov->remote)
-		kcov_move_area(kcov->mode, kcov->area, kcov->size, area);
+	if (sequence == kcov->state.s.sequence && kcov->remote)
+		kcov_move_area(kcov->state.mode, kcov->state.s.area,
+			       kcov->state.s.size, area);
 	spin_unlock(&kcov->lock);
 
 	if (in_task()) {
@@ -1089,10 +1070,10 @@ static void __init selftest(void)
 	 * potentially traced functions in this region.
 	 */
 	start = jiffies;
-	current->kcov_mode = KCOV_MODE_TRACE_PC;
+	current->kcov_state.mode = KCOV_MODE_TRACE_PC;
 	while ((jiffies - start) * MSEC_PER_SEC / HZ < 300)
 		;
-	current->kcov_mode = 0;
+	current->kcov_state.mode = 0;
 	pr_err("done running self test\n");
 }
 #endif
-- 
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416085446.480069-3-glider%40google.com.
