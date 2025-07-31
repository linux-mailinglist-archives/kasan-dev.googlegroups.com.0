Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWVRVXCAMGQEPLRVTDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F72AB1709E
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:51:56 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-6157ba67602sf310199a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 04:51:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753962715; cv=pass;
        d=google.com; s=arc-20240605;
        b=lIZmFlu8kcCoXFDGFLAPomZfimAEADogmDWuH3vgxurXE6ekWR0ANRgLll1+5zZuPE
         n5P7ogoEf15gJy9lTTuhD21nVQKv+bnnAmhc9KHfI3MmlQl7KUBSvtDfqlLj90BaxxxQ
         MMtArJx0AIhRQx3D782EP2b5JIVIHmrYQ9Q4X2ZNWyTzgNINS5bNqKsh7n2faCYu43O+
         Dw850rxtNQjrnlqlroCCRNbrvG1ZDRuVRbEyTHSdLgwSsfnC1eTYsALRJEuKhXPnWa8x
         KuVfdMHHgtuCfO0YpaUzz+sWi2DwZaJ/Q+EvVvR9MblNdtEx8Y/9X/aDFx00cD2Ac5iM
         hGaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=xc3zQAxIY/BtY4Yl/JE+ud8bNqGTvzl1IoYw56m4rS0=;
        fh=vY7ZYUTdCmRNVFDa/0u4kvs0nPoNvGXtN+43/xLAPsA=;
        b=i+EyGeXuxz+QznUi5Hi9tUyOYmdh+YcP9XB/rOUjSkpxjKz2Eurpf41OkvmUdQdW2d
         KEDYRKaocjYVawKUYLrfEbfD9LMnujpjJFKZZwyaWfv5dJUi1yBCArf6STAiiOqW/HbL
         2HP/CBCnPrEnvqfga4rbhYYj8n90znZdgscc8qEdUi9aUEb24/yRfs8/dLiPGLZyfk3A
         6a9eLNoR4hcQFoiLb2JJ9UUhRdR22nWAdnBj/zSfaBOsVgT/RMqJeKGnxP2b+Nq8vH9b
         Yw82Gaz+6v6ALIFbDHYfUWtCafl8Pl7iYNls6V5Sy2y/eei9w5s8GV33XXXeQhB07MId
         uBnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dohAep5u;
       spf=pass (google.com: domain of 32filaaykcqmjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=32FiLaAYKCQMjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753962715; x=1754567515; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xc3zQAxIY/BtY4Yl/JE+ud8bNqGTvzl1IoYw56m4rS0=;
        b=J4nkZvWcKSHV988oD2V4pJUPfsKFajdAoSPqWguyw1oIusLx9Z4SRcgIjGOGyVM4Ed
         PbJhuI3XrWLZCp/CgY+r4crCeR3SrnTUlVagdmqwK8pkkTtSLhr2B3hOmTiwImJgb6UP
         hse1YlqbKUNKeTZ+DUSxQH+k/e9w/R14QeU1ZYM7KUce8el1RtSfXbpUx2cO3KPMxqry
         ZSbgpsM+aH2Zg9c0fRi2omqcXEvn1L1H9uWF9+ksCnpXt55wWZu5GzAq91D4+pFGx1bd
         j/qSF1YAzfgNSNfQmBnmDk6AQFzOp+8qkn0GIqH+na3eytS7xoRr5jFqzM0eMabw3txL
         Mg/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753962715; x=1754567515;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xc3zQAxIY/BtY4Yl/JE+ud8bNqGTvzl1IoYw56m4rS0=;
        b=LtPR/dKDUIfV/EGByYwYiPY8sHbpyjvH6ZlFzgjDkJVexga3yCidBxVwgVCPBekK2K
         dPcegrmDE84vlNbH7lzfwUowbUePEZuaOju2hiuiVDx8HRa9xSPbeQBOj1PORhUkGyqe
         AgCKNZpGVfwE115d5XMBKGuQftxs4txmRq//DJxnxi/hxZu7NI2ezyk0v+TzJa9EYzwb
         K9/j+yQ6kf/Hu2VRCmzNDOiqlBg+ySLl9ozUMGN7arTQiA5oO4u4Dd2f42FSv0MTqXus
         p85ym03envDa8WGt6VN+sRiaASJeolEEnq/QndA71VOvdEJqzY4TmWgJ90xSh+VNp/z9
         BkPA==
X-Forwarded-Encrypted: i=2; AJvYcCVL5g5UHq/6e3NFsUF34gkcZKtk47X+YPOIpLWxy+OsntsnM5/sSr9mP8xlz6ovLEH1SsvU4w==@lfdr.de
X-Gm-Message-State: AOJu0YxSMPW48IC4s85AopLgwiiA455RZWSAQVTUNpAUKAPs1nCLNpyB
	mmSeFmhRbANZj2pSIPEcxcJ9Wk1MAACAzP5F6g+oT7WR+hdlaw9N+ejE
X-Google-Smtp-Source: AGHT+IHlKB9GVJGhcDJl/a9cJ7qvGBMLOmMvz6NOTr1kzwH5Duzw+fzxU4/qhJGeycOGi7OpUd6Jmw==
X-Received: by 2002:a05:6402:51cd:b0:615:87a6:58a7 with SMTP id 4fb4d7f45d1cf-61587b5a205mr7819802a12.33.1753962715438;
        Thu, 31 Jul 2025 04:51:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcdvWPs78wF0mzWo+lgGsiopm+C4f9wR/QjVvrGHCalyg==
Received: by 2002:a05:6402:5206:b0:60c:44d6:282c with SMTP id
 4fb4d7f45d1cf-615a5dc1704ls836110a12.1.-pod-prod-04-eu; Thu, 31 Jul 2025
 04:51:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2AdQkL8fldCi4KB8y18PwuqTGrGo5BKi0k2KiX9KvbTtizwbD5h5gw86rb1f2X/86rIbLpwwdMOk=@googlegroups.com
X-Received: by 2002:a05:6402:3593:b0:615:600c:2e26 with SMTP id 4fb4d7f45d1cf-61586f3acb7mr5985620a12.9.1753962712529;
        Thu, 31 Jul 2025 04:51:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753962712; cv=none;
        d=google.com; s=arc-20240605;
        b=aCo/1YcHlPTnoOhNDKuPTjeEyVoVqAFph+xWBh8FejUM1LfCNfEjW9BHtB9mlufzPW
         A/QJtKN4s0nhoLR6KNqZJh7PY8HZKMmUd2b1pQxTJjFslf0754NS/fGeNKwVWbeA3uGw
         8LCxiqspYKZYt5aa7rxMTQBY+qcMQX5kDttb/NAq7BxkSrw9HwlYxp9Dfh1K+7vQKKu4
         KKFokLfZ7d46jR+3eoezurG08EtukTqsjl17WjDB1iEZlux/at1LKDzla0j7XhR/m/r7
         SvOyTP+MW/n6UKdXIHY8qpMZrX1/ahMfeDdoZ/Dl166lnacrKcfJYqcAjgZvHWd4knL7
         YaiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DzEkgpRCnk/Bq1twXrDYYtTyuJB3TyxcrLIFIKrRv4o=;
        fh=iyJG2igo3wvQmbvSxMQTcQro8daO6Zh9VjLsjUb2NAM=;
        b=Rl1Hsek+5nH5a2PyghVIFjtqPX1MsAsy5Lrzii3i8nW1q32ZZEI2L3YWnC4wjtwKme
         zhFldoH/mxOq4v6dhq0uo4Cr0OJvQ4z+oplhky//YchVIEZx2AR1WiX1HU/JoUmpijPd
         2vxEE7fruI5T6roccqbBT3OCdAptbxa/ddjNFr9fbDjwTUrVkyYsiKOulOqBv5fXpRBo
         Ou6N8SnNA4OdbU+DHzBnSComx1xhi27+f/4eKaoCl/zShyoBKDLKeK62UhF5G+r+Sr8v
         oXtDXcbyBpuHg6pNQKaCBxeQ6MNRzjqojPsdvftbsC+KmW94LlTHn4J+qxMTEbpPmDwq
         Acrw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dohAep5u;
       spf=pass (google.com: domain of 32filaaykcqmjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=32FiLaAYKCQMjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-615a8f29032si49693a12.1.2025.07.31.04.51.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 04:51:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32filaaykcqmjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-af91e018025so50545166b.1
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 04:51:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWmOMDnA1tUVl8HxDl6De/UV6vTCFuuQabf1rEceFBFgF3OQXJsCIucR/4PEsx7GG6/an1uxWq05dM=@googlegroups.com
X-Received: from ejcss8.prod.google.com ([2002:a17:907:c008:b0:ae3:64a9:78cd])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:728c:b0:ad8:85df:865b
 with SMTP id a640c23a62f3a-af8fd978528mr766051066b.33.1753962712055; Thu, 31
 Jul 2025 04:51:52 -0700 (PDT)
Date: Thu, 31 Jul 2025 13:51:32 +0200
In-Reply-To: <20250731115139.3035888-1-glider@google.com>
Mime-Version: 1.0
References: <20250731115139.3035888-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250731115139.3035888-4-glider@google.com>
Subject: [PATCH v4 03/10] kcov: factor out struct kcov_state
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=dohAep5u;       spf=pass
 (google.com: domain of 32filaaykcqmjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=32FiLaAYKCQMjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
v4:
 - add Reviewed-by: Dmitry Vyukov

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
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731115139.3035888-4-glider%40google.com.
