Return-Path: <kasan-dev+bncBCCMH5WKTMGRBENNT3CAMGQEQWM7E2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 38FBBB13E38
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 17:26:11 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-455f79a2a16sf33466415e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 08:26:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753716370; cv=pass;
        d=google.com; s=arc-20240605;
        b=kJrchpuxaKvdUbbFiS1uOsCfZ7+OUxRMDeIK9nX8k2riWw2N6POP77mcivpbM7vtBI
         qhrMCkqOojPVDtSu7TTKtZLLBApp3mxT46OrILdFjicnBHNLbUfBc1saxKHInGGO2ucu
         99yLwZIglgenS58N2ZzKgCb2aVJl+2Yn9F6cc19TrpSLkiR5L1cCcuJ6PhWfSSBwbtKB
         jRcEfbPBKJw2ZjpJOcVUFD6FqkwVAAYJg2ooVCGjJxuv8KC5oYP6P++1ZWNxa88QdXfS
         XaFF1FwwB+ulCL6R19VCypehB3iWNCwIBFj/vZUPrK8DrWu6vmMLZAIpzW2a5lhcSsaT
         sWpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Pkr/iuz+IX1g+Cx4evjYl7fUQj3/lJg7TdW5REu0y7U=;
        fh=NI4x1yVZhXnHbOqXF+/cvJzpF1RjlQah+j6EhjUyk88=;
        b=CYhaNclPw5fLV2EigWZ+xqYIm6zd9LS5x10yDKLFdFBy4EKqER1klCZMrvuS3LyisZ
         nbo1qVLhgutlUcCKsq3YM+ExgiRs5cKWNU46rol+jlivx2+g5VFBpXHCnJUCVP5Ojw2I
         tPUNSbRRJ3w97VnqAoMT4ukqj8apYpdDf8x885sqoIOiciZNAYuPh4qQamRBwNXDC4WY
         GQrMLvUGKVESFElDj1gbuzSKHJqu5Q0QwS5xAHmL/scvDX07qrnWJpiHHdBarVbEe2mS
         X1cLUQtZplyDiG+I+hm7RDzJG30k2zMglTx5hz08IBIAtodRKm+kDkIaFt3qSTzYc3cD
         +uOQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p2W6SyBG;
       spf=pass (google.com: domain of 3jzahaaykcsqglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3jZaHaAYKCSQGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753716370; x=1754321170; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Pkr/iuz+IX1g+Cx4evjYl7fUQj3/lJg7TdW5REu0y7U=;
        b=TVZU+Tq4BMIJxxs9gipyO0BipGGWRllGIV9CZ1Ntw5WwOYqQoTmOYLy4K0jTCTafsU
         K7OyJk/GXdE0E4i0/GhW8bm9TMyfGHbdjl05RPpAdbPvUU+bOaI6nl7GgByfDmgFktE/
         XbdW1b5WTvDrhxD8viz18V7BRgYBtKkvQquSQZ0V3ejKeXeIlcJmaKdnVdx1NT1gdy6R
         IWUR4CBDsStSUW65fT1dPPTJnY50d21IhjCWveTrCRyFQqXp2NGDcjAJArtjJJXiyEWA
         OVy36XhcK28uoVnVk7EQSGigKSeZ0YLhfZsYwWPvaE228ol/NBn7cS1Gk3ZV1Ea13NnI
         ZcWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753716370; x=1754321170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Pkr/iuz+IX1g+Cx4evjYl7fUQj3/lJg7TdW5REu0y7U=;
        b=eS5yTQVBPzMUHqpHIWs8677EQ17ECnOfR8i8btJYTRpv8yp13ACllDZM0jFJ6fNb+M
         BhuwvmtRirlpNjCQfQRo83jEQh9++AJnppHfhribaK5Noll1wIQUTr+QmJdhSk8bPaTi
         uhINZeEgE41XAI0FyhWcBSAqyvhHB1ljfV8UbygTbFbvLjIlbioI7xk7IMJLgsan02Ov
         8Isw/q+givd7fZmPIGx1+35OhjWDjAcCqLRaGVZU1Qq/8N9rZ4VP+XZGAGUBMooq6CU3
         5sATScjwZlSaa//hqU1CYfoGFNd/oAMLn7RGbhrT1QDfnRUXK1zxh1NHPVniLKSG9vlL
         NuwA==
X-Forwarded-Encrypted: i=2; AJvYcCVrwNu1L8pkmpzjiOX3wnlT63RIjEJLc25Dp7skWIXyBlDg57rGmdC7bpef5qzYEB26yxNhjw==@lfdr.de
X-Gm-Message-State: AOJu0YzfFRq/eo3jSp2Ho6Pml505pQ+JP5GjBb6093TNKwXEhjhq4AKs
	5tAcWwYNiTR0TvRoZCHR13j/X4c3VgjzF/TiF0/zdXkLuqxG8ojXIWk1
X-Google-Smtp-Source: AGHT+IHshMJkRVFxc+LwwFneN456WHt3ZFpX6wDUf2UlOBvMAPd71Qr5sTdFh3I82tAG3KYI6/YHBg==
X-Received: by 2002:a05:600c:6215:b0:456:1ab0:d56d with SMTP id 5b1f17b1804b1-4587da7a4admr64590725e9.7.1753716370145;
        Mon, 28 Jul 2025 08:26:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdwsMnV0yoe5at1AhCxGCxPpgUiDISg44czQObzUQt/fg==
Received: by 2002:a05:600c:1c29:b0:456:107b:aa63 with SMTP id
 5b1f17b1804b1-4586e5c3ff6ls23540385e9.0.-pod-prod-02-eu; Mon, 28 Jul 2025
 08:26:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKVflHf3fuZYGz2pSfkY+zvD/fONSxco6EMiHBbVykMXjIHhxXyOrV4htZwLYGFDYioTJOndBVNIA=@googlegroups.com
X-Received: by 2002:a05:6000:26d2:b0:3b7:6429:da6 with SMTP id ffacd0b85a97d-3b7766684c2mr8289608f8f.42.1753716367304;
        Mon, 28 Jul 2025 08:26:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753716367; cv=none;
        d=google.com; s=arc-20240605;
        b=FPveGFPfu6Qn3w7Oozx9wSe5Q0KJacIGX6JWpruVJ3u7Ygy8uUdcPsUASaHpv7jH3u
         bFcK+0VWWzRxjTDlNBMnmijlte8HpJ8qQDnMAB6QuSOeROD+b9KcMY7/nihBctW+K4XU
         4x7/5mvT58b0thIJ7GriqD7SBO0GVnv8yvSYr0g7wNxai5HtB1ApLYyPOTAYJuCGHWCF
         lfh88yN3l+q6IXqTK0/hOwCm5yJtOk+FKj5rmenavUhYupmyrqwiTTI8QCrdnwTZ379x
         IT5+gC+aPDM7Wx7SF8yAc7l9Dj/D81N9SmQ4roqmuEP517nHIX7dLda7bVn8U69exxVU
         efRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=x81fL8jUmjkAzRsxHSSAhVNkBiMxf9fqzVJGZhSQsxk=;
        fh=nlZ7bWokJQHJLkhYdZ/UOjZUndlGaFtraWS2SgONXJY=;
        b=gG0ttD6j+jQYFPSmjbrFN7mWiCkwK7w/YH8DLsuBAeDbsmT1nkJM2SQd6xIrz5N6Gh
         tkvRtqLs29JSDt71YMc8SmSqPdMEl80QeCPEszBNPd/YoNAXplzKkCHug+KqhgjnhBEy
         YyuEfyRQVFAwUNP/B8EAw3bpgDR24DI2dMU6/VPJfssNm1BJGUHIPrhiMx8A/+EYjkT3
         9Mfm0286Mt2GNd9EGS5AzOPoAtIjsIVhAJZY77kCo+l+kQ3wXll9QPaX0zzG/TyOM9KC
         tXhoLm9m97s7BBt4gvIW4G+ni1Y3kpN7vSPvTl6xkBlJrMvCB1NgPt0EiToErg9CKYAF
         2hvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p2W6SyBG;
       spf=pass (google.com: domain of 3jzahaaykcsqglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3jZaHaAYKCSQGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4586ec6dc93si1677455e9.1.2025.07.28.08.26.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 08:26:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jzahaaykcsqglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-612be84c047so4878601a12.2
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 08:26:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWkBTw6b/DGY8jb9cWFr60t/6hgCz6yBLG9b6BLdx3uJ/+iqA7F3lYYRSxJsuUqqbceoalg54k9azk=@googlegroups.com
X-Received: from edbdn24.prod.google.com ([2002:a05:6402:22f8:b0:608:89ec:59b3])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:84c:b0:614:f982:6335
 with SMTP id 4fb4d7f45d1cf-614f98266b1mr10815929a12.22.1753716365086; Mon, 28
 Jul 2025 08:26:05 -0700 (PDT)
Date: Mon, 28 Jul 2025 17:25:41 +0200
In-Reply-To: <20250728152548.3969143-1-glider@google.com>
Mime-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.470.g6ba607880d-goog
Message-ID: <20250728152548.3969143-4-glider@google.com>
Subject: [PATCH v3 03/10] kcov: factor out struct kcov_state
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
 header.i=@google.com header.s=20230601 header.b=p2W6SyBG;       spf=pass
 (google.com: domain of 3jzahaaykcsqglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3jZaHaAYKCSQGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
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

Group several kcov-related fields (area, size, sequence) that are
stored in various structures, into `struct kcov_state`, so that
these fields can be easily passed around and manipulated.
Note that now the spinlock in struct kcov applies to every member
of struct kcov_state, including the sequence number.

This prepares us for the upcoming change that will introduce more
kcov state.

Also update the MAINTAINERS entry: add include/linux/kcov_types.h,
add myself as kcov reviewer.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v3:
 - fix comments by Dmitry Vyukov:
   - adjust a comment in sched.h
   - fix incorrect parameters passed to kcov_start()

v2:
 - add myself to kcov MAINTAINERS
 - rename kcov-state.h to kcov_types.h
 - update the description
 - do not move mode into struct kcov_state
 - use '{ }' instead of '{ 0 }'

Change-Id: If225682ea2f6e91245381b3270de16e7ea40df39
---
 MAINTAINERS                |   2 +
 include/linux/kcov.h       |   2 +-
 include/linux/kcov_types.h |  22 ++++++++
 include/linux/sched.h      |  13 +----
 kernel/kcov.c              | 112 ++++++++++++++++---------------------
 5 files changed, 77 insertions(+), 74 deletions(-)
 create mode 100644 include/linux/kcov_types.h

diff --git a/MAINTAINERS b/MAINTAINERS
index c0b444e5fd5ad..6906eb9d88dae 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13008,11 +13008,13 @@ F:	include/linux/kcore.h
 KCOV
 R:	Dmitry Vyukov <dvyukov@google.com>
 R:	Andrey Konovalov <andreyknvl@gmail.com>
+R:	Alexander Potapenko <glider@google.com>
 L:	kasan-dev@googlegroups.com
 S:	Maintained
 B:	https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
 F:	Documentation/dev-tools/kcov.rst
 F:	include/linux/kcov.h
+F:	include/linux/kcov_types.h
 F:	include/uapi/linux/kcov.h
 F:	kernel/kcov.c
 F:	scripts/Makefile.kcov
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 75a2fb8b16c32..2b3655c0f2278 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -2,7 +2,7 @@
 #ifndef _LINUX_KCOV_H
 #define _LINUX_KCOV_H
 
-#include <linux/sched.h>
+#include <linux/kcov_types.h>
 #include <uapi/linux/kcov.h>
 
 struct task_struct;
diff --git a/include/linux/kcov_types.h b/include/linux/kcov_types.h
new file mode 100644
index 0000000000000..53b25b6f0addd
--- /dev/null
+++ b/include/linux/kcov_types.h
@@ -0,0 +1,22 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_KCOV_STATE_H
+#define _LINUX_KCOV_STATE_H
+
+#ifdef CONFIG_KCOV
+/* See kernel/kcov.c for more details. */
+struct kcov_state {
+	/* Size of the area (in long's). */
+	unsigned int size;
+
+	/* Buffer for coverage collection, shared with the userspace. */
+	void *area;
+
+	/*
+	 * KCOV sequence number: incremented each time kcov is reenabled, used
+	 * by kcov_remote_stop(), see the comment there.
+	 */
+	int sequence;
+};
+#endif /* CONFIG_KCOV */
+
+#endif /* _LINUX_KCOV_STATE_H */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index aa9c5be7a6325..7901fece5aba3 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -42,6 +42,7 @@
 #include <linux/restart_block.h>
 #include <uapi/linux/rseq.h>
 #include <linux/seqlock_types.h>
+#include <linux/kcov_types.h>
 #include <linux/kcsan.h>
 #include <linux/rv.h>
 #include <linux/uidgid_types.h>
@@ -1516,16 +1517,11 @@ struct task_struct {
 #endif /* CONFIG_TRACING */
 
 #ifdef CONFIG_KCOV
-	/* See kernel/kcov.c for more details. */
-
 	/* Coverage collection mode enabled for this task (0 if disabled): */
 	unsigned int			kcov_mode;
 
-	/* Size of the kcov_area: */
-	unsigned int			kcov_size;
-
-	/* Buffer for coverage collection: */
-	void				*kcov_area;
+	/* KCOV buffer state for this task. */
+	struct kcov_state		kcov_state;
 
 	/* KCOV descriptor wired with this task or NULL: */
 	struct kcov			*kcov;
@@ -1533,9 +1529,6 @@ struct task_struct {
 	/* KCOV common handle for remote coverage collection: */
 	u64				kcov_handle;
 
-	/* KCOV sequence number: */
-	int				kcov_sequence;
-
 	/* Collect coverage from softirq context: */
 	unsigned int			kcov_softirq;
 #endif
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 187ba1b80bda1..5170f367c8a1b 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -23,6 +23,7 @@
 #include <linux/debugfs.h>
 #include <linux/uaccess.h>
 #include <linux/kcov.h>
+#include <linux/kcov_types.h>
 #include <linux/refcount.h>
 #include <linux/log2.h>
 #include <asm/setup.h>
@@ -53,24 +54,17 @@ struct kcov {
 	 *  - each code section for remote coverage collection
 	 */
 	refcount_t		refcount;
-	/* The lock protects mode, size, area and t. */
+	/* The lock protects mode, state and t. */
 	spinlock_t		lock;
 	enum kcov_mode		mode;
-	/* Size of arena (in long's). */
-	unsigned int		size;
-	/* Coverage buffer shared with user space. */
-	void			*area;
+	struct kcov_state	state;
+
 	/* Task for which we collect coverage, or NULL. */
 	struct task_struct	*t;
 	/* Collecting coverage from remote (background) threads. */
 	bool			remote;
 	/* Size of remote area (in long's). */
 	unsigned int		remote_size;
-	/*
-	 * Sequence is incremented each time kcov is reenabled, used by
-	 * kcov_remote_stop(), see the comment there.
-	 */
-	int			sequence;
 };
 
 struct kcov_remote_area {
@@ -92,11 +86,9 @@ struct kcov_percpu_data {
 	void			*irq_area;
 	local_lock_t		lock;
 
-	unsigned int		saved_mode;
-	unsigned int		saved_size;
-	void			*saved_area;
+	enum kcov_mode		saved_mode;
 	struct kcov		*saved_kcov;
-	int			saved_sequence;
+	struct kcov_state	saved_state;
 };
 
 static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) = {
@@ -217,10 +209,10 @@ void notrace __sanitizer_cov_trace_pc(void)
 	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
 		return;
 
-	area = t->kcov_area;
+	area = t->kcov_state.area;
 	/* The first 64-bit word is the number of subsequent PCs. */
 	pos = READ_ONCE(area[0]) + 1;
-	if (likely(pos < t->kcov_size)) {
+	if (likely(pos < t->kcov_state.size)) {
 		/* Previously we write pc before updating pos. However, some
 		 * early interrupt code could bypass check_kcov_mode() check
 		 * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
@@ -250,10 +242,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 
 	/*
 	 * We write all comparison arguments and types as u64.
-	 * The buffer was allocated for t->kcov_size unsigned longs.
+	 * The buffer was allocated for t->kcov_state.size unsigned longs.
 	 */
-	area = (u64 *)t->kcov_area;
-	max_pos = t->kcov_size * sizeof(unsigned long);
+	area = (u64 *)t->kcov_state.area;
+	max_pos = t->kcov_state.size * sizeof(unsigned long);
 
 	count = READ_ONCE(area[0]);
 
@@ -354,15 +346,13 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_switch);
 #endif /* ifdef CONFIG_KCOV_ENABLE_COMPARISONS */
 
 static void kcov_start(struct task_struct *t, struct kcov *kcov,
-			unsigned int size, void *area, enum kcov_mode mode,
-			int sequence)
+		       enum kcov_mode mode, struct kcov_state *state)
 {
-	kcov_debug("t = %px, size = %u, area = %px\n", t, size, area);
+	kcov_debug("t = %px, size = %u, area = %px\n", t, state->size,
+		   state->area);
 	t->kcov = kcov;
 	/* Cache in task struct for performance. */
-	t->kcov_size = size;
-	t->kcov_area = area;
-	t->kcov_sequence = sequence;
+	t->kcov_state = *state;
 	/* See comment in check_kcov_mode(). */
 	barrier();
 	WRITE_ONCE(t->kcov_mode, mode);
@@ -373,14 +363,14 @@ static void kcov_stop(struct task_struct *t)
 	WRITE_ONCE(t->kcov_mode, KCOV_MODE_DISABLED);
 	barrier();
 	t->kcov = NULL;
-	t->kcov_size = 0;
-	t->kcov_area = NULL;
+	t->kcov_state.size = 0;
+	t->kcov_state.area = NULL;
 }
 
 static void kcov_task_reset(struct task_struct *t)
 {
 	kcov_stop(t);
-	t->kcov_sequence = 0;
+	t->kcov_state.sequence = 0;
 	t->kcov_handle = 0;
 }
 
@@ -396,7 +386,7 @@ static void kcov_reset(struct kcov *kcov)
 	kcov->mode = KCOV_MODE_INIT;
 	kcov->remote = false;
 	kcov->remote_size = 0;
-	kcov->sequence++;
+	kcov->state.sequence++;
 }
 
 static void kcov_remote_reset(struct kcov *kcov)
@@ -436,7 +426,7 @@ static void kcov_put(struct kcov *kcov)
 {
 	if (refcount_dec_and_test(&kcov->refcount)) {
 		kcov_remote_reset(kcov);
-		vfree(kcov->area);
+		vfree(kcov->state.area);
 		kfree(kcov);
 	}
 }
@@ -493,8 +483,8 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	unsigned long flags;
 
 	spin_lock_irqsave(&kcov->lock, flags);
-	size = kcov->size * sizeof(unsigned long);
-	if (kcov->area == NULL || vma->vm_pgoff != 0 ||
+	size = kcov->state.size * sizeof(unsigned long);
+	if (kcov->state.area == NULL || vma->vm_pgoff != 0 ||
 	    vma->vm_end - vma->vm_start != size) {
 		res = -EINVAL;
 		goto exit;
@@ -502,7 +492,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	spin_unlock_irqrestore(&kcov->lock, flags);
 	vm_flags_set(vma, VM_DONTEXPAND);
 	for (off = 0; off < size; off += PAGE_SIZE) {
-		page = vmalloc_to_page(kcov->area + off);
+		page = vmalloc_to_page(kcov->state.area + off);
 		res = vm_insert_page(vma, vma->vm_start + off, page);
 		if (res) {
 			pr_warn_once("kcov: vm_insert_page() failed\n");
@@ -523,7 +513,7 @@ static int kcov_open(struct inode *inode, struct file *filep)
 	if (!kcov)
 		return -ENOMEM;
 	kcov->mode = KCOV_MODE_DISABLED;
-	kcov->sequence = 1;
+	kcov->state.sequence = 1;
 	refcount_set(&kcov->refcount, 1);
 	spin_lock_init(&kcov->lock);
 	filep->private_data = kcov;
@@ -558,10 +548,10 @@ static int kcov_get_mode(unsigned long arg)
 static void kcov_fault_in_area(struct kcov *kcov)
 {
 	unsigned long stride = PAGE_SIZE / sizeof(unsigned long);
-	unsigned long *area = kcov->area;
+	unsigned long *area = kcov->state.area;
 	unsigned long offset;
 
-	for (offset = 0; offset < kcov->size; offset += stride)
+	for (offset = 0; offset < kcov->state.size; offset += stride)
 		READ_ONCE(area[offset]);
 }
 
@@ -600,7 +590,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		 * at task exit or voluntary by KCOV_DISABLE. After that it can
 		 * be enabled for another task.
 		 */
-		if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
+		if (kcov->mode != KCOV_MODE_INIT || !kcov->state.area)
 			return -EINVAL;
 		t = current;
 		if (kcov->t != NULL || t->kcov != NULL)
@@ -610,8 +600,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			return mode;
 		kcov_fault_in_area(kcov);
 		kcov->mode = mode;
-		kcov_start(t, kcov, kcov->size, kcov->area, kcov->mode,
-				kcov->sequence);
+		kcov_start(t, kcov, mode, &kcov->state);
 		kcov->t = t;
 		/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
 		kcov_get(kcov);
@@ -628,7 +617,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		kcov_put(kcov);
 		return 0;
 	case KCOV_REMOTE_ENABLE:
-		if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
+		if (kcov->mode != KCOV_MODE_INIT || !kcov->state.area)
 			return -EINVAL;
 		t = current;
 		if (kcov->t != NULL || t->kcov != NULL)
@@ -722,8 +711,8 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 			vfree(area);
 			return -EBUSY;
 		}
-		kcov->area = area;
-		kcov->size = size;
+		kcov->state.area = area;
+		kcov->state.size = size;
 		kcov->mode = KCOV_MODE_INIT;
 		spin_unlock_irqrestore(&kcov->lock, flags);
 		return 0;
@@ -821,10 +810,8 @@ static void kcov_remote_softirq_start(struct task_struct *t)
 	mode = READ_ONCE(t->kcov_mode);
 	barrier();
 	if (kcov_mode_enabled(mode)) {
+		data->saved_state = t->kcov_state;
 		data->saved_mode = mode;
-		data->saved_size = t->kcov_size;
-		data->saved_area = t->kcov_area;
-		data->saved_sequence = t->kcov_sequence;
 		data->saved_kcov = t->kcov;
 		kcov_stop(t);
 	}
@@ -835,13 +822,9 @@ static void kcov_remote_softirq_stop(struct task_struct *t)
 	struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
 
 	if (data->saved_kcov) {
-		kcov_start(t, data->saved_kcov, data->saved_size,
-				data->saved_area, data->saved_mode,
-				data->saved_sequence);
-		data->saved_mode = 0;
-		data->saved_size = 0;
-		data->saved_area = NULL;
-		data->saved_sequence = 0;
+		kcov_start(t, data->saved_kcov, data->saved_mode,
+			   &data->saved_state);
+		data->saved_state = (struct kcov_state){};
 		data->saved_kcov = NULL;
 	}
 }
@@ -850,12 +833,12 @@ void kcov_remote_start(u64 handle)
 {
 	struct task_struct *t = current;
 	struct kcov_remote *remote;
+	struct kcov_state state;
+	enum kcov_mode mode;
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
@@ -900,7 +883,7 @@ void kcov_remote_start(u64 handle)
 	 * KCOV_DISABLE / kcov_remote_reset().
 	 */
 	mode = kcov->mode;
-	sequence = kcov->sequence;
+	state.sequence = kcov->state.sequence;
 	if (in_task()) {
 		size = kcov->remote_size;
 		area = kcov_remote_area_get(size);
@@ -923,12 +906,14 @@ void kcov_remote_start(u64 handle)
 
 	/* Reset coverage size. */
 	*(u64 *)area = 0;
+	state.area = area;
+	state.size = size;
 
 	if (in_serving_softirq()) {
 		kcov_remote_softirq_start(t);
 		t->kcov_softirq = 1;
 	}
-	kcov_start(t, kcov, size, area, mode, sequence);
+	kcov_start(t, kcov, mode, &state);
 
 	local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 
@@ -1027,9 +1012,9 @@ void kcov_remote_stop(void)
 	}
 
 	kcov = t->kcov;
-	area = t->kcov_area;
-	size = t->kcov_size;
-	sequence = t->kcov_sequence;
+	area = t->kcov_state.area;
+	size = t->kcov_state.size;
+	sequence = t->kcov_state.sequence;
 
 	kcov_stop(t);
 	if (in_serving_softirq()) {
@@ -1042,8 +1027,9 @@ void kcov_remote_stop(void)
 	 * KCOV_DISABLE could have been called between kcov_remote_start()
 	 * and kcov_remote_stop(), hence the sequence check.
 	 */
-	if (sequence == kcov->sequence && kcov->remote)
-		kcov_move_area(kcov->mode, kcov->area, kcov->size, area);
+	if (sequence == kcov->state.sequence && kcov->remote)
+		kcov_move_area(kcov->mode, kcov->state.area, kcov->state.size,
+			       area);
 	spin_unlock(&kcov->lock);
 
 	if (in_task()) {
-- 
2.50.1.470.g6ba607880d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728152548.3969143-4-glider%40google.com.
