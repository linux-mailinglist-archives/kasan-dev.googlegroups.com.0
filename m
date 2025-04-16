Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZXA7W7QMGQEKXHDXCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 105B2A8B471
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 10:55:04 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-39130f02631sf2695623f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 01:55:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744793703; cv=pass;
        d=google.com; s=arc-20240605;
        b=XFvxPZFZGiznIiyTKAuieMqYuzeshnoVIadMt/5qn+LR/Dx7lFZjj+tj1ndvmFRQ+5
         toOOYbEz1z4szMWCKHvFeSEOqZyz4K3OeNnNEQ7uBg1VgaDxVmXCRxM2T/tZQM4g5XTS
         bEIU6eRcGPk2ONmupdzsXj4Z3nJOXHsa5OIWfKyWmK5KcRtgNClSQtgHFcVQfSh1NqkZ
         Knr6F0w2I0v4R9svMlqMfNYhfL7F58bViGbmDoi7uM4vWHPoy3iOSlhki8EtYRs70LP9
         Wq0VSWY0P4ROxHNKn/udRygp1LwO/DZ2aAMXEDflmdk5uuYW2zdty1x20Z915Ihug0ct
         33ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=EU9eEJ++yXXa8RrOEwfSeFBFqq1TDI1DgVZQ8CHKswM=;
        fh=xmEWHg2qtuvRm2KQjn72+glYE6FCm3wPoiKngwE+gks=;
        b=YNoaPPJ9FYgb+Elvurtgws8yopUFsumqMtTfRj6A5YJBiZ8YrwahKEATvClthwHTg7
         17p95Da28Zsa+i7qVwTwxm1Lx6a20YMGz6/+JPNgxCQVKf6TUe5GLuOlSk2R4Qbnap5F
         6WV0AzZbyv//I5lAXiDs5JypCSdQY8xab25vTD3R0c6i+pzaTFXhfhqnBdkLdjSkZXLN
         mVOhoyyP+2fVz4HkrI8s6+nKSP/iCAgzVDiYHAOiceNRaY2NAVjaXnsY+n10tT/cFHu3
         DET5K1AvKVSY8TX6zLpRmVKdTAhXFsPNdMzuUTeHUgDk6EWaVp+UlOcI/MMPGX+TOu/E
         WtFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wF2Lag8I;
       spf=pass (google.com: domain of 3y3d_zwykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Y3D_ZwYKCYgsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744793703; x=1745398503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EU9eEJ++yXXa8RrOEwfSeFBFqq1TDI1DgVZQ8CHKswM=;
        b=FKCEcp3fgm1sLFo/XBpKDsPN5RXCB2y65/InhzNEHIZ6ed3GsmVl3zgFODsvwekb/b
         jV8K8meYpJdtj2aRYD49+awInCJP9Ha2+SsiVkmk+Q+JAdwPK40YbijRhDrskbFdz4cv
         i5ghDf1xfKveMUi+8wroVFOTKFIC/OXQ53clYSuGKsU2NH4kBfkD55bonYpvR2/R31a/
         cQdDieC07BTQT/5gUFH8mym2ZgnI1kXLG+Y1tCIyu8RSJqWMpKMSkUagKyFKDbVIrEzp
         yqdE7ScEbciwy+gsKmol5rP3d5pUCMa9lA3OnHhMUHP40X8x/ZIiKIGM/NAqc8oAeHS1
         23ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744793703; x=1745398503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EU9eEJ++yXXa8RrOEwfSeFBFqq1TDI1DgVZQ8CHKswM=;
        b=UMJjydaTCFknDl0nA9VS8g+miV9yypLKO5w1mDBo+u5129Cqhg1OXuuIMdv7VUvOBt
         Zk42kQrmQR+c9Lt+UfsxW9/jEjLrmUaLHQ021NeQjyNLZCRKYOIScGNY261VgDnET4Gq
         jNcG4NKM4S2NbQrXRfslz7TIfFpLEyYRkf9RW6xMBlaP7dLhlpyjobRCxQAK/0WZShL/
         xbost3MoXJtFt7eGDmJbX3btAThQe3ZGJZ53RbcNtzWR4BYwFGFxW40pw9sz++J80z0n
         2RT6YJFb/pjHK5jp1py6UBLCkeMukk5INhApoqOd8mmne2gftNpUzsHTfkHDgBQrBrM5
         8IdQ==
X-Forwarded-Encrypted: i=2; AJvYcCVhkHTxJtEqV1Gbrgrbrz2hd65gNRTRjDjCGVWiVE8NVGX/OrZs0x823Dw9ynrrh0oLkeyOAg==@lfdr.de
X-Gm-Message-State: AOJu0Yw4y7Mgod4syzRPHP8jfWNiOvxch4bLV3TfzLjlsd82Iygx/4Dy
	olnIgM43JbSr/gG8jvtS+0ZYwGfocgOE2z8bqusHimPy3f1GaiBX
X-Google-Smtp-Source: AGHT+IHEHR2AyHY8dxRfRS9xmo/64P5GSMvMO+7fvNsVmDFPtufnHWRLHgLB9vECJalPCT5gfBBFYQ==
X-Received: by 2002:a05:6000:18af:b0:391:454:5eb8 with SMTP id ffacd0b85a97d-39ee5bb004cmr879629f8f.48.1744793702571;
        Wed, 16 Apr 2025 01:55:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJMJ6ZjEjOshyLUepz99OZyPExJx1u6VHKAwCbNnZcyzw==
Received: by 2002:a05:6000:2909:b0:39c:13fe:1ad with SMTP id
 ffacd0b85a97d-39d8dfbc3d5ls1629104f8f.1.-pod-prod-01-eu; Wed, 16 Apr 2025
 01:55:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZmLM+qaAJHA5XSVIkGfSbYAfcmdo7wkgSTGHkhuxal/Dn+9PbaUYhmhAd+v8bXcuJcvC73kICkis=@googlegroups.com
X-Received: by 2002:a05:6000:1867:b0:39e:cbca:922f with SMTP id ffacd0b85a97d-39ee5b12f23mr743500f8f.12.1744793699916;
        Wed, 16 Apr 2025 01:54:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744793699; cv=none;
        d=google.com; s=arc-20240605;
        b=buWcsBIspSAR9tDRlsWvNs4rXYD49Arzr4v58F//6Uvp332jznYzxKdzR0OEUtjCfx
         Go3CDmed9b5jaqTD1yo/NEOxnEBjQeBc3006ezW2VW47INSM20mnXuX6pH+9lFrHcBXf
         CcEsZKBDDgjTo3IJ0CP1EqmtztXkFVy5+7c+BQGN+rvg4Au2LQUTaAlygaLPHCp9o34j
         FuJqcBPipXWNROVwioI69uwKGv2Jl9pTqoLO41pMmIzCELUT2MrKmWdGKwCP1vWNgboY
         v/+NmWMTZSSN1LCUvtnT2TfRJECKQGBlKxSEtJAY964HP3C/xR/3z394FSYO5WSWqXIv
         HLjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=fawUJ+aFly0mZ/Doql3hbHEHCvseg6enUQu7sHu+ODc=;
        fh=aVFeE2y+uCwxtYscJtfEuhUr4Il2UfH+nZAGufOykd4=;
        b=NZo1rPiiu08jRkoamofxMtsH3ESJtHz2cJ7Y6aUpJcWd6XuZWDth4R3Tka03Iluu3p
         bdbRpZPK5OhVhE+Xt8VkBRLqVj41y4gPGXLf41Zts0/nbaMS0x4JH+3bTMBhP+qRzrqs
         JwkUj/SrisJYBU9WAUKPFt9Q0VirNdsmFBrQzOsP/LwXKspdTTAhzybWoBIhP3PK7prX
         x8j/dq7zAxJ/h7q+UB53l4AbvlAouTSfagPAIHNnsGiILzRymeb/wHz4YKsnKWrgF+lK
         jEXlmrmypLHkTCz2x11D0B2yXglH51aOLaJ1GZtnyrEzC9gz1uOlO78o1YOEtiuTp6qk
         Psmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wF2Lag8I;
       spf=pass (google.com: domain of 3y3d_zwykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Y3D_ZwYKCYgsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4405b33f28asi265985e9.0.2025.04.16.01.54.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 01:54:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3y3d_zwykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ab39f65dc10so76234166b.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 01:54:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV3TevxYJJK3oekx7bTtNFwGETVA0dKyiFbV35hOz0Ii0QwG2lNxwRMSeeJmRVQCvSs6d9CVD3+9RE=@googlegroups.com
X-Received: from ejaz16.prod.google.com ([2002:a17:906:2410:b0:ac2:ea20:40ac])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:d2a:b0:ac7:efed:3ab
 with SMTP id a640c23a62f3a-acb429e5b2amr87507766b.21.1744793699499; Wed, 16
 Apr 2025 01:54:59 -0700 (PDT)
Date: Wed, 16 Apr 2025 10:54:39 +0200
In-Reply-To: <20250416085446.480069-1-glider@google.com>
Mime-Version: 1.0
References: <20250416085446.480069-1-glider@google.com>
X-Mailer: git-send-email 2.49.0.604.gff1f9ca942-goog
Message-ID: <20250416085446.480069-2-glider@google.com>
Subject: [PATCH 1/7] kcov: apply clang-format to kcov code
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
 header.i=@google.com header.s=20230601 header.b=wF2Lag8I;       spf=pass
 (google.com: domain of 3y3d_zwykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Y3D_ZwYKCYgsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
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
index 187ba1b80bda1..7cc6123c2baa4 100644
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
@@ -728,13 +730,15 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 		spin_unlock_irqrestore(&kcov->lock, flags);
 		return 0;
 	case KCOV_REMOTE_ENABLE:
-		if (get_user(remote_num_handles, (unsigned __user *)(arg +
-				offsetof(struct kcov_remote_arg, num_handles))))
+		if (get_user(remote_num_handles,
+			     (unsigned __user *)(arg +
+						 offsetof(struct kcov_remote_arg,
+							  num_handles))))
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
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416085446.480069-2-glider%40google.com.
