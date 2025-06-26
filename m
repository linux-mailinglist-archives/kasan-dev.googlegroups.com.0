Return-Path: <kasan-dev+bncBCCMH5WKTMGRBM446XBAMGQEWBXVUUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8418CAE9F2B
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:42:15 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-3a4f8192e2csf597911f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:42:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945332; cv=pass;
        d=google.com; s=arc-20240605;
        b=e9LU20onLDrKNNASq90QbStnnDptIW4+ZBWS0AZOwZsJLnwNRnLZuOtb3Nmq+t6p2s
         DBUeoXfp2PrGnPmruz0mMY9d0p0/0RLu+wURIIvfpO9zBvAhpE4wHsiElXuDt/hC7Y9F
         +rPYEhJsD8z/SFJcWpLMR3brJfRHPXZLsWSzjhAHKDyvXbNEqUucvcD3Jp05XV+azHvL
         UPOs4JKcu7Y1h9syh4fhju6lD9WvYV/2DrBezj+G0RjlNJdwwGJxzwts94Pc5mPhII7E
         52HRtAYTNS7O/CRE6zu9OX2zK1C13LGowDVW/KozvtKA0hTA6D2wzeo7ZlBs9o7McniZ
         s20w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=5B/07KIfenYlp74SV5SGf5YuCB25nwbcnGQXSyxWLDg=;
        fh=3y5N89OnxVdO/nEDKCf3g3HpqaOOIOAlgJzNQgTBq88=;
        b=eQsHiAKID6PAUFMDla5pVv2F8V3qXn1oES+H4g2b1CkfPLR62KsVdtPoRXXpXeoWNC
         ihQ59SpK+URFi2ivb2TmVnEWQak+6jA6H4zfoaq/Q6tINCuY04U8OTUZfFu/6ALBPjv+
         D8vRAypAx7cySskVDQugzTaEDbiPZrVWGY8w6i2zn4yqDEg8m0uQCpsaAauBqf7woxzb
         tjWtUzCRbQDG3sG/6YwUopFtv4JfBzcVUdROpg2MumVD/UXT8BTleXOCdyjiZ3Ra5JbY
         RWLfEDRBEuV2UCV5QqD96b/Iqomqp4l+jU+I4P3Qd0iYCUuBCU3yTkyvncc6i87Ma4RA
         5n1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hjnK+nSQ;
       spf=pass (google.com: domain of 3mu5daaykcyww1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3MU5daAYKCYww1ytu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945332; x=1751550132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=5B/07KIfenYlp74SV5SGf5YuCB25nwbcnGQXSyxWLDg=;
        b=tzPpWSJ7V2tRhE+GvoyU9dOANSQhGKhf8IsbZhG6h0kh2ThWx11TvMtzgzxtOqc0h+
         fXetdBMM/goMQTCDiVyr84Cn9ZwdOQCrGQSpdNidwhcXu+vNqnaMRNCDBMbsvdRcJE/u
         qcKUFiEvdWeHtu9nnN5Qza2+GLfAfFqPVkgzI3KEAf6ga1yiAMkRDlTXE7dfScnyyrMt
         MJRIJm8fA4uE/FJ3si9T/GpEY4aJvLdbOwKhNP3BR58rAjn/OTDU3OKWVdpM6E9viEFZ
         oHTTTde+7QyV3LfcVuR9l+ispzBZbXm39UMi8HHSWLwzXFddxetTrlY93JL0XCWH98TA
         FKaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945332; x=1751550132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5B/07KIfenYlp74SV5SGf5YuCB25nwbcnGQXSyxWLDg=;
        b=HmXrP+FWC2HFHYOKvobEknlpnkJerSKTx6VOKXEphMJwrhXNNRtZAtdOKTD7RdCKDM
         Z4VKgOeULC/kEnpBtQ3DvPbRIA2EE8gjunjhd0fDDOL6RZ78jn/Pux3lp94+Rz7UkVUP
         IQ2aQp8AUVADymtBQJMqmfwl/+LFlDNZllRKTtQLtgRlBBXcB6DSrX4yIrS6wG0VpuYn
         ivpCyi3R3DScTb/ieGwBho+3u80wXuR2p2t+ZnyFYta5xFOP2sSkMX5dvI6oaoL8kK8J
         wSbvFhxymKN+VBKW3NxqJF6A1FWx36B3vmiSA1U6fYmkAGtHWxsDXJKFKQI73kDdi9BI
         mrCQ==
X-Forwarded-Encrypted: i=2; AJvYcCV3VdYj5WwynBueE/71hdTGnN38hx0dkWnS1MbBW4gaaRPpeviXbK8YuzoUBqu66ngQKiweng==@lfdr.de
X-Gm-Message-State: AOJu0YyW928sRXZC361pC2kLz9YBMa6JcwLgUad3+qcUjDgVJELS17n9
	Qoy/X0RbYAuHinTel3wwotyOfjJM47JgPiwSb6YJ6CJrK3hjD9D8KVrW
X-Google-Smtp-Source: AGHT+IE/oQ5YTQGJD6PcKf91+RixvGtUhiDsLYYtqFgLwCZH4w485QMwQ0nOEepODDGdzG0KnTLJKg==
X-Received: by 2002:a05:6000:1888:b0:3a4:f038:af74 with SMTP id ffacd0b85a97d-3a6ed65b664mr6132969f8f.51.1750945332232;
        Thu, 26 Jun 2025 06:42:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcZMYjxDFKPRLZ9xIMRr8QrhLaRlXocqCEuOH44urpQ0Q==
Received: by 2002:a05:600c:4ed1:b0:43e:ad2b:6916 with SMTP id
 5b1f17b1804b1-453889b7bebls5947095e9.0.-pod-prod-07-eu; Thu, 26 Jun 2025
 06:42:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAyu62UP4jlLTsVafjUHy//kA5JUO+WLab6Vf2TQl8GlWlRyMUgOcVR1x93a3b7DGzg/GqXHf3Vk0=@googlegroups.com
X-Received: by 2002:a05:600c:1d92:b0:450:d104:29eb with SMTP id 5b1f17b1804b1-45381aa5656mr70414005e9.5.1750945329688;
        Thu, 26 Jun 2025 06:42:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945329; cv=none;
        d=google.com; s=arc-20240605;
        b=k0TUtredhFxkMTZk9zw4HAVI8m3CbLXFOOIYJOfRiMhlfbdZQavL/AYehKL+16MEO0
         QzGBLA+j4FZyP3jUs1IUT5PjP8GPeFq3MKasK1x9XtNC5or1AtFSl91oLzObn34a3mDP
         1EmEncrPU8KTEes81u0tQ0AUFmgtekSOuWcTzl/QSc9/ri92WSigWkpXnpop1nQxP7n/
         U0mtrDcguMvqno2GdiuZ1bL24BeXzEzmbm7GpgRQsXtoyjxWkSjZNWs8L43d0XA3LKNV
         bdLKujxSMNCJyyDkFQqQpC1TMJJZvNnLR/aIL12NxN887uyu3LLXxwbJejcBgowZlx/S
         8F5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=FJiMSG3aUxEuiCh3YiYxcirsWMG54X+LrVgKBYabMpk=;
        fh=2KM65I1YoiHeM5A9ebWTjB7rP7sg4jcXr7suasvUVBE=;
        b=e1+YGA6kYC+plvXVN2d0Z2axTJHPYrgIqDKQWYgoKmZiqcM2lyA+2PsFn2hC27/d0W
         456Q+YM9aBIOymIHJPSVORw2Lzl5H9aEVLaHLlsa5VQH4cn0as0xsaaGEXj8C0kxxPcn
         CINdUpmakE+JjTM91iCR82uu2nVu4jdxwdfKY4FG5yOAwHUvLcEi6N9W1e1L9ydCn+Yk
         gTGMVQQ+Pxi6IF+gp0YmoMwHuN7USbkbY5z0B9+f1dqLqtGgCZ9iKUIOwbLFHZgh77kj
         cO/kd9st5fIRf5fuphSdoQfctVMRn6tYG8aFkB2vdYnBlLTHqkrswP+oDZNiPZwO2GKD
         Zgqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hjnK+nSQ;
       spf=pass (google.com: domain of 3mu5daaykcyww1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3MU5daAYKCYww1ytu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-453814a99f3si1642015e9.1.2025.06.26.06.42.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:42:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mu5daaykcyww1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45359bfe631so5240805e9.0
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:42:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWNbn2G4mjPJxBEwww37VgtC/ehPXag1pO+T7BVNmsayL8fUwLrsxMgERBLHuOJNX/k7eXDFZcMW4A=@googlegroups.com
X-Received: from wmbfs17.prod.google.com ([2002:a05:600c:3f91:b0:450:cfda:ece7])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1914:b0:43d:172:50b1
 with SMTP id 5b1f17b1804b1-45381af206cmr68815395e9.29.1750945329192; Thu, 26
 Jun 2025 06:42:09 -0700 (PDT)
Date: Thu, 26 Jun 2025 15:41:49 +0200
In-Reply-To: <20250626134158.3385080-1-glider@google.com>
Mime-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com>
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250626134158.3385080-3-glider@google.com>
Subject: [PATCH v2 02/11] kcov: apply clang-format to kcov code
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
 header.i=@google.com header.s=20230601 header.b=hjnK+nSQ;       spf=pass
 (google.com: domain of 3mu5daaykcyww1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3MU5daAYKCYww1ytu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--glider.bounces.google.com;
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

kcov used to obey clang-format style, but somehow diverged over time.
This patch applies clang-format to kernel/kcov.c and
include/linux/kcov.h, no functional change.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I49c21babad831e5d134ad8a4d4adffd1f5abc1dd

v2:
 - factor out handles_off in kcov_ioctl() for prettier formatting
---
 include/linux/kcov.h |  54 +++++++++++------
 kernel/kcov.c        | 134 ++++++++++++++++++++++---------------------
 2 files changed, 105 insertions(+), 83 deletions(-)

diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 75a2fb8b16c32..932b4face1005 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -25,20 +25,20 @@ enum kcov_mode {
 	KCOV_MODE_REMOTE = 4,
 };
 
-#define KCOV_IN_CTXSW	(1 << 30)
+#define KCOV_IN_CTXSW (1 << 30)
 
 void kcov_task_init(struct task_struct *t);
 void kcov_task_exit(struct task_struct *t);
 
-#define kcov_prepare_switch(t)			\
-do {						\
-	(t)->kcov_mode |= KCOV_IN_CTXSW;	\
-} while (0)
+#define kcov_prepare_switch(t)                   \
+	do {                                     \
+		(t)->kcov_mode |= KCOV_IN_CTXSW; \
+	} while (0)
 
-#define kcov_finish_switch(t)			\
-do {						\
-	(t)->kcov_mode &= ~KCOV_IN_CTXSW;	\
-} while (0)
+#define kcov_finish_switch(t)                     \
+	do {                                      \
+		(t)->kcov_mode &= ~KCOV_IN_CTXSW; \
+	} while (0)
 
 /* See Documentation/dev-tools/kcov.rst for usage details. */
 void kcov_remote_start(u64 handle);
@@ -119,23 +119,41 @@ void __sanitizer_cov_trace_switch(kcov_u64 val, void *cases);
 
 #else
 
-static inline void kcov_task_init(struct task_struct *t) {}
-static inline void kcov_task_exit(struct task_struct *t) {}
-static inline void kcov_prepare_switch(struct task_struct *t) {}
-static inline void kcov_finish_switch(struct task_struct *t) {}
-static inline void kcov_remote_start(u64 handle) {}
-static inline void kcov_remote_stop(void) {}
+static inline void kcov_task_init(struct task_struct *t)
+{
+}
+static inline void kcov_task_exit(struct task_struct *t)
+{
+}
+static inline void kcov_prepare_switch(struct task_struct *t)
+{
+}
+static inline void kcov_finish_switch(struct task_struct *t)
+{
+}
+static inline void kcov_remote_start(u64 handle)
+{
+}
+static inline void kcov_remote_stop(void)
+{
+}
 static inline u64 kcov_common_handle(void)
 {
 	return 0;
 }
-static inline void kcov_remote_start_common(u64 id) {}
-static inline void kcov_remote_start_usb(u64 id) {}
+static inline void kcov_remote_start_common(u64 id)
+{
+}
+static inline void kcov_remote_start_usb(u64 id)
+{
+}
 static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
 {
 	return 0;
 }
-static inline void kcov_remote_stop_softirq(unsigned long flags) {}
+static inline void kcov_remote_stop_softirq(unsigned long flags)
+{
+}
 
 #endif /* CONFIG_KCOV */
 #endif /* _LINUX_KCOV_H */
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 187ba1b80bda1..0dd42b78694c9 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -4,27 +4,28 @@
 #define DISABLE_BRANCH_PROFILING
 #include <linux/atomic.h>
 #include <linux/compiler.h>
+#include <linux/debugfs.h>
 #include <linux/errno.h>
 #include <linux/export.h>
-#include <linux/types.h>
 #include <linux/file.h>
 #include <linux/fs.h>
 #include <linux/hashtable.h>
 #include <linux/init.h>
 #include <linux/jiffies.h>
+#include <linux/kcov.h>
 #include <linux/kmsan-checks.h>
+#include <linux/log2.h>
 #include <linux/mm.h>
 #include <linux/preempt.h>
 #include <linux/printk.h>
+#include <linux/refcount.h>
 #include <linux/sched.h>
 #include <linux/slab.h>
 #include <linux/spinlock.h>
-#include <linux/vmalloc.h>
-#include <linux/debugfs.h>
+#include <linux/types.h>
 #include <linux/uaccess.h>
-#include <linux/kcov.h>
-#include <linux/refcount.h>
-#include <linux/log2.h>
+#include <linux/vmalloc.h>
+
 #include <asm/setup.h>
 
 #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
@@ -52,36 +53,36 @@ struct kcov {
 	 *  - task with enabled coverage (we can't unwire it from another task)
 	 *  - each code section for remote coverage collection
 	 */
-	refcount_t		refcount;
+	refcount_t refcount;
 	/* The lock protects mode, size, area and t. */
-	spinlock_t		lock;
-	enum kcov_mode		mode;
+	spinlock_t lock;
+	enum kcov_mode mode;
 	/* Size of arena (in long's). */
-	unsigned int		size;
+	unsigned int size;
 	/* Coverage buffer shared with user space. */
-	void			*area;
+	void *area;
 	/* Task for which we collect coverage, or NULL. */
-	struct task_struct	*t;
+	struct task_struct *t;
 	/* Collecting coverage from remote (background) threads. */
-	bool			remote;
+	bool remote;
 	/* Size of remote area (in long's). */
-	unsigned int		remote_size;
+	unsigned int remote_size;
 	/*
 	 * Sequence is incremented each time kcov is reenabled, used by
 	 * kcov_remote_stop(), see the comment there.
 	 */
-	int			sequence;
+	int sequence;
 };
 
 struct kcov_remote_area {
-	struct list_head	list;
-	unsigned int		size;
+	struct list_head list;
+	unsigned int size;
 };
 
 struct kcov_remote {
-	u64			handle;
-	struct kcov		*kcov;
-	struct hlist_node	hnode;
+	u64 handle;
+	struct kcov *kcov;
+	struct hlist_node hnode;
 };
 
 static DEFINE_SPINLOCK(kcov_remote_lock);
@@ -89,14 +90,14 @@ static DEFINE_HASHTABLE(kcov_remote_map, 4);
 static struct list_head kcov_remote_areas = LIST_HEAD_INIT(kcov_remote_areas);
 
 struct kcov_percpu_data {
-	void			*irq_area;
-	local_lock_t		lock;
-
-	unsigned int		saved_mode;
-	unsigned int		saved_size;
-	void			*saved_area;
-	struct kcov		*saved_kcov;
-	int			saved_sequence;
+	void *irq_area;
+	local_lock_t lock;
+
+	unsigned int saved_mode;
+	unsigned int saved_size;
+	void *saved_area;
+	struct kcov *saved_kcov;
+	int saved_sequence;
 };
 
 static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) = {
@@ -149,7 +150,7 @@ static struct kcov_remote_area *kcov_remote_area_get(unsigned int size)
 
 /* Must be called with kcov_remote_lock locked. */
 static void kcov_remote_area_put(struct kcov_remote_area *area,
-					unsigned int size)
+				 unsigned int size)
 {
 	INIT_LIST_HEAD(&area->list);
 	area->size = size;
@@ -171,7 +172,8 @@ static __always_inline bool in_softirq_really(void)
 	return in_serving_softirq() && !in_hardirq() && !in_nmi();
 }
 
-static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
+static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
+				    struct task_struct *t)
 {
 	unsigned int mode;
 
@@ -354,8 +356,8 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_switch);
 #endif /* ifdef CONFIG_KCOV_ENABLE_COMPARISONS */
 
 static void kcov_start(struct task_struct *t, struct kcov *kcov,
-			unsigned int size, void *area, enum kcov_mode mode,
-			int sequence)
+		       unsigned int size, void *area, enum kcov_mode mode,
+		       int sequence)
 {
 	kcov_debug("t = %px, size = %u, area = %px\n", t, size, area);
 	t->kcov = kcov;
@@ -566,14 +568,14 @@ static void kcov_fault_in_area(struct kcov *kcov)
 }
 
 static inline bool kcov_check_handle(u64 handle, bool common_valid,
-				bool uncommon_valid, bool zero_valid)
+				     bool uncommon_valid, bool zero_valid)
 {
 	if (handle & ~(KCOV_SUBSYSTEM_MASK | KCOV_INSTANCE_MASK))
 		return false;
 	switch (handle & KCOV_SUBSYSTEM_MASK) {
 	case KCOV_SUBSYSTEM_COMMON:
-		return (handle & KCOV_INSTANCE_MASK) ?
-			common_valid : zero_valid;
+		return (handle & KCOV_INSTANCE_MASK) ? common_valid :
+						       zero_valid;
 	case KCOV_SUBSYSTEM_USB:
 		return uncommon_valid;
 	default:
@@ -611,7 +613,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		kcov_fault_in_area(kcov);
 		kcov->mode = mode;
 		kcov_start(t, kcov, kcov->size, kcov->area, kcov->mode,
-				kcov->sequence);
+			   kcov->sequence);
 		kcov->t = t;
 		/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
 		kcov_get(kcov);
@@ -642,40 +644,40 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			return -EINVAL;
 		kcov->mode = mode;
 		t->kcov = kcov;
-	        t->kcov_mode = KCOV_MODE_REMOTE;
+		t->kcov_mode = KCOV_MODE_REMOTE;
 		kcov->t = t;
 		kcov->remote = true;
 		kcov->remote_size = remote_arg->area_size;
 		spin_lock_irqsave(&kcov_remote_lock, flags);
 		for (i = 0; i < remote_arg->num_handles; i++) {
-			if (!kcov_check_handle(remote_arg->handles[i],
-						false, true, false)) {
+			if (!kcov_check_handle(remote_arg->handles[i], false,
+					       true, false)) {
 				spin_unlock_irqrestore(&kcov_remote_lock,
-							flags);
+						       flags);
 				kcov_disable(t, kcov);
 				return -EINVAL;
 			}
 			remote = kcov_remote_add(kcov, remote_arg->handles[i]);
 			if (IS_ERR(remote)) {
 				spin_unlock_irqrestore(&kcov_remote_lock,
-							flags);
+						       flags);
 				kcov_disable(t, kcov);
 				return PTR_ERR(remote);
 			}
 		}
 		if (remote_arg->common_handle) {
-			if (!kcov_check_handle(remote_arg->common_handle,
-						true, false, false)) {
+			if (!kcov_check_handle(remote_arg->common_handle, true,
+					       false, false)) {
 				spin_unlock_irqrestore(&kcov_remote_lock,
-							flags);
+						       flags);
 				kcov_disable(t, kcov);
 				return -EINVAL;
 			}
 			remote = kcov_remote_add(kcov,
-					remote_arg->common_handle);
+						 remote_arg->common_handle);
 			if (IS_ERR(remote)) {
 				spin_unlock_irqrestore(&kcov_remote_lock,
-							flags);
+						       flags);
 				kcov_disable(t, kcov);
 				return PTR_ERR(remote);
 			}
@@ -698,6 +700,7 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 	unsigned int remote_num_handles;
 	unsigned long remote_arg_size;
 	unsigned long size, flags;
+	size_t handles_off;
 	void *area;
 
 	kcov = filep->private_data;
@@ -728,13 +731,14 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 		spin_unlock_irqrestore(&kcov->lock, flags);
 		return 0;
 	case KCOV_REMOTE_ENABLE:
-		if (get_user(remote_num_handles, (unsigned __user *)(arg +
-				offsetof(struct kcov_remote_arg, num_handles))))
+		handles_off = offsetof(struct kcov_remote_arg, num_handles);
+		if (get_user(remote_num_handles,
+			     (unsigned __user *)(arg + handles_off)))
 			return -EFAULT;
 		if (remote_num_handles > KCOV_REMOTE_MAX_HANDLES)
 			return -EINVAL;
-		remote_arg_size = struct_size(remote_arg, handles,
-					remote_num_handles);
+		remote_arg_size =
+			struct_size(remote_arg, handles, remote_num_handles);
 		remote_arg = memdup_user((void __user *)arg, remote_arg_size);
 		if (IS_ERR(remote_arg))
 			return PTR_ERR(remote_arg);
@@ -758,11 +762,11 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 }
 
 static const struct file_operations kcov_fops = {
-	.open		= kcov_open,
-	.unlocked_ioctl	= kcov_ioctl,
-	.compat_ioctl	= kcov_ioctl,
-	.mmap		= kcov_mmap,
-	.release        = kcov_close,
+	.open = kcov_open,
+	.unlocked_ioctl = kcov_ioctl,
+	.compat_ioctl = kcov_ioctl,
+	.mmap = kcov_mmap,
+	.release = kcov_close,
 };
 
 /*
@@ -836,8 +840,8 @@ static void kcov_remote_softirq_stop(struct task_struct *t)
 
 	if (data->saved_kcov) {
 		kcov_start(t, data->saved_kcov, data->saved_size,
-				data->saved_area, data->saved_mode,
-				data->saved_sequence);
+			   data->saved_area, data->saved_mode,
+			   data->saved_sequence);
 		data->saved_mode = 0;
 		data->saved_size = 0;
 		data->saved_area = NULL;
@@ -891,7 +895,7 @@ void kcov_remote_start(u64 handle)
 		return;
 	}
 	kcov_debug("handle = %llx, context: %s\n", handle,
-			in_task() ? "task" : "softirq");
+		   in_task() ? "task" : "softirq");
 	kcov = remote->kcov;
 	/* Put in kcov_remote_stop(). */
 	kcov_get(kcov);
@@ -931,12 +935,11 @@ void kcov_remote_start(u64 handle)
 	kcov_start(t, kcov, size, area, mode, sequence);
 
 	local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
-
 }
 EXPORT_SYMBOL(kcov_remote_start);
 
 static void kcov_move_area(enum kcov_mode mode, void *dst_area,
-				unsigned int dst_area_size, void *src_area)
+			   unsigned int dst_area_size, void *src_area)
 {
 	u64 word_size = sizeof(unsigned long);
 	u64 count_size, entry_size_log;
@@ -944,8 +947,8 @@ static void kcov_move_area(enum kcov_mode mode, void *dst_area,
 	void *dst_entries, *src_entries;
 	u64 dst_occupied, dst_free, bytes_to_move, entries_moved;
 
-	kcov_debug("%px %u <= %px %lu\n",
-		dst_area, dst_area_size, src_area, *(unsigned long *)src_area);
+	kcov_debug("%px %u <= %px %lu\n", dst_area, dst_area_size, src_area,
+		   *(unsigned long *)src_area);
 
 	switch (mode) {
 	case KCOV_MODE_TRACE_PC:
@@ -967,8 +970,8 @@ static void kcov_move_area(enum kcov_mode mode, void *dst_area,
 	}
 
 	/* As arm can't divide u64 integers use log of entry size. */
-	if (dst_len > ((dst_area_size * word_size - count_size) >>
-				entry_size_log))
+	if (dst_len >
+	    ((dst_area_size * word_size - count_size) >> entry_size_log))
 		return;
 	dst_occupied = count_size + (dst_len << entry_size_log);
 	dst_free = dst_area_size * word_size - dst_occupied;
@@ -1100,7 +1103,8 @@ static int __init kcov_init(void)
 
 	for_each_possible_cpu(cpu) {
 		void *area = vmalloc_node(CONFIG_KCOV_IRQ_AREA_SIZE *
-				sizeof(unsigned long), cpu_to_node(cpu));
+						  sizeof(unsigned long),
+					  cpu_to_node(cpu));
 		if (!area)
 			return -ENOMEM;
 		per_cpu_ptr(&kcov_percpu_data, cpu)->irq_area = area;
-- 
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626134158.3385080-3-glider%40google.com.
