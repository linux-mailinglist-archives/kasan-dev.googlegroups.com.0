Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOM46XBAMGQEZ5B7BUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 80351AE9F2D
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:42:20 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-60c4d140b4bsf971830a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:42:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945338; cv=pass;
        d=google.com; s=arc-20240605;
        b=cnBiUEzqKZLu9gEUctWe714gvAab7O5znSK639Gbd61hme4CSX8Bi3+uAAeAb719tw
         8aQvanlw9oIj28ajGpyqVQsxLsu/f13yj9cTdD2w1MvaTCgykElWiVlHxG6jmgTs/BYI
         EKx7ElyUtt2dHli8Y+tUeaWIQWMncy7vW3Gq+4zWDurnIuifdCarUpDMThp1zC4Lw8dI
         AWRAmVEiQMU2dJxZdjp/WrgapEXyUuaUljkZtezgERK0giVDIu4D8+UaOoxBd8KEXibD
         lzjSEhLu+EkxLAbhsqHgiYDtqqUyaR0o7Xj5sRXxfzSdS64otPG6GWhX2HubNsKPBlWb
         VC1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ZKn/ZYdUms2NyRbidhtaTtjL+88qHCyYaTMktNMjd7c=;
        fh=KF3Fc+G6w3McLVZrjBEdnTEbZUTXtzW7td8tz1VAN3s=;
        b=dX6nM6So05UDWbufWqor342APtiHIcs6Nf7so1Gsq4IT+3l3FDEch8ye5GT0BPF6AS
         LcWBAWaACI+fbcxjeqW4z62HsSgeR43Xnu09UaXm5P1+nhHBmFDXMZaa3t8BhQ+gftVY
         QGeqE6FXfcZF6+9/A+eU9YqvK/a4A77lRyV27617xNOe8CN9nc2e5mDrnWyxR16lY00e
         TVsfINuiHtC5V14mtW12dFzzNmB5eIxkIW6JXDgwD6/0ntpguqaLFyOkzoZYtXtc0gzS
         JIxk6lEp3o5UY5h/NHlk/goP1b+5tcEs1G8Ho1P5r67DohSuWw20Xvdp69uKKMVrTBBG
         BAjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pObgJ6+F;
       spf=pass (google.com: domain of 3nk5daaykcze163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Nk5daAYKCZE163yzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945338; x=1751550138; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZKn/ZYdUms2NyRbidhtaTtjL+88qHCyYaTMktNMjd7c=;
        b=WheXHZcpg1Wj1+CnmsVsW0qgA5RaVqED17XmInrfZw+0y81uC/XJT9UwQCJCGEz+JB
         i1XqhNzC3PKPJeo01078SYS3xM7jppROCoLQWsLxkdCKUYb0FjhEouZkj0FzRQLlnX2T
         4de8u4CpW+Yr8d1YNWRFkLZ5pwY+9ZDYiXLYDOyxB05ZwEZNn/E1+977WvLzTos2RDNw
         3ZlqfMeC6b4UqRaTc9v8sS8r8nnK8sPNz8hExBdfuh9itdrsH2ApjivNURaHS52JWUyf
         WBu7M9AVVA2/X1Lnq6tKvZG9v3Q9CBjpA6ky9MoIVrKq8ABbWG64XBUBPvB1Rnmxe9O/
         1awQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945338; x=1751550138;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZKn/ZYdUms2NyRbidhtaTtjL+88qHCyYaTMktNMjd7c=;
        b=D+Qcyw26RRczr02/V/AlRXrT6HMvIC5SpKiFe1eY4N0RsKo4pabYg2rp3U+i7981gZ
         CRSDD3qC8fK6aiXuunix4XsVmG4LXOUyTXxQH8aqlVkx5vOUlFdnnP2TholiqQ4JSuP3
         IXkJLllRw+rSac18feVtOZnSKFybWalnPhv279IoQ5BJhQcl2Gm5YRBrq4aJnqg0zgoA
         ZoxgqyPKnqkz7b9/Pu2SUXqiugO33nZLLizaDCoWfmkIbWCgm2+cIvRngTsz27qI6d+e
         b9CPvbOIg3ULNdUMK1Cj0AuMJXpZ7P8Ktk7yoombBh6EOvCGQSjMESKdksrtfuWfIYlV
         XkIA==
X-Forwarded-Encrypted: i=2; AJvYcCX4xS70X1MVyxjbDBqiaUqiw0+AZPjyaE7lo5XSFmQ8HOqy0hn70lSti+6C0xsfR0XvxQ6IFg==@lfdr.de
X-Gm-Message-State: AOJu0YyQY4rIpjf64BccujqsVN7NMKT5mxEJ6g/EeLyrIr988zS9yM0U
	2suZ9/gM7Tc2yHuQaVebSKJGOC5pVqPt5tu90hoxtNSfTfLS7NeUTJEt
X-Google-Smtp-Source: AGHT+IFiSrMY34cUY/wnGp8/oerd8+vwBwIZHfhs792FjN2qn7R0+LyEJRa4A2VnpTY4mRfyE1NEMQ==
X-Received: by 2002:a05:6402:26cb:b0:60c:42ce:27c4 with SMTP id 4fb4d7f45d1cf-60c4de9c13cmr5790274a12.21.1750945337534;
        Thu, 26 Jun 2025 06:42:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeJoqq+mZLTS2EKKA3rPx0Sl2g0e8hOozpZBQKjBL867g==
Received: by 2002:a05:6402:1e95:b0:601:d62c:75ed with SMTP id
 4fb4d7f45d1cf-60c65db1703ls967948a12.1.-pod-prod-02-eu; Thu, 26 Jun 2025
 06:42:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWeExdZDKvB4YX1j3wAnN1K9mzjHSEoufVQIfUHCHtm9SbfNy0ulkeWJbj7xVVh+vZ09Z+Mf/sgQVA=@googlegroups.com
X-Received: by 2002:a17:907:1b1d:b0:ad8:8a46:f156 with SMTP id a640c23a62f3a-ae0bebe9b1emr734928466b.6.1750945334886;
        Thu, 26 Jun 2025 06:42:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945334; cv=none;
        d=google.com; s=arc-20240605;
        b=PSlUVjbfBN3LK7Vl4dbo8heTr9WeEuaW9DDN3JuTr2XnTKYWXWGaE7KeqnFc2/ZGu6
         xxveshAN5wbdgtNIxtcUg57N5Kzk5lEpFacIHq5QzQYufo9KoropKZLVGRcoTjhrFmPD
         I5stD4p+ESRAoLylREiejoAN8pM0OpmX80xIiVhgB7wfHvnCwBqhmJGIj76lNH0zKzKQ
         YoSBVm5aBjiUv5t2XfBE3dZKlyOmJPeQHbr6RLREdWbphzxZHfEwC9In0tdw+MNrjFMF
         TFEdrWldAbRjXDU2Ung1H1hkoAdNFLmTa/7BTMN18vqr8AATrVRFpGcxH8sOYr3ePZ//
         lPLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Y9JptD8OjEc0dymN3Sn1kMVYGpGedrlrt38g4yTKhTU=;
        fh=E7F8dSS+HSz3dq3srAeUDsCbycSseWvDGh4ZX1Jf5VI=;
        b=N9TCqfNSx93+8fhXxQ38b+j+6B8mCg2fPRDfjZuAjywKxVQTzt6dT+PhTA4HipGIko
         eQ7pt9NpIlVgi6VDb/GlOrI4vdstK3E8/hsystsZ1Lb/rKCEJx72YAzsMuC+ioZCTeRa
         HAA6fQ6uXcbP7yY2QWUiLhSCl0e+wT+p2HQGJeJa4GZR/v+nqrUlQCSulpdVSRIiODUA
         mFqdQsCxHqrZmlVK141kbqZyhziBE2WTxDByauSRzIUQToX7wykLlstVejpdyc68MilD
         7WKfUZ716ZnlUM2PLw0NJbsdIvH6MToHvlzjCAHe7NLsQx+r97NGaZlPHy+Dk1ROBcbJ
         sphw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pObgJ6+F;
       spf=pass (google.com: domain of 3nk5daaykcze163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Nk5daAYKCZE163yzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-ae201feee2bsi110166b.1.2025.06.26.06.42.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:42:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nk5daaykcze163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-3a58939191eso351150f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:42:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUp0s4IA4U9AjLCF6Kw0/A4kjdFRznhIGvMFfW1eDGrpJrbx9Zi1lBm3Um1KTu9YdwoDsV0u1hAJLY=@googlegroups.com
X-Received: from wmsr19.prod.google.com ([2002:a05:600c:8b13:b0:442:ddf8:99dc])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:4614:b0:3a5:276b:1ec0
 with SMTP id ffacd0b85a97d-3a6ed65b1d4mr6390427f8f.45.1750945334487; Thu, 26
 Jun 2025 06:42:14 -0700 (PDT)
Date: Thu, 26 Jun 2025 15:41:51 +0200
In-Reply-To: <20250626134158.3385080-1-glider@google.com>
Mime-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com>
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250626134158.3385080-5-glider@google.com>
Subject: [PATCH v2 04/11] kcov: factor out struct kcov_state
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
 header.i=@google.com header.s=20230601 header.b=pObgJ6+F;       spf=pass
 (google.com: domain of 3nk5daaykcze163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Nk5daAYKCZE163yzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--glider.bounces.google.com;
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

Also update the MAINTAINERS entry: add include/linux/kcov_types..h,
add myself as kcov reviewer.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Change-Id: If225682ea2f6e91245381b3270de16e7ea40df39

v2:
 - add myself to kcov MAINTAINERS
 - rename kcov-state.h to kcov_types.h
 - update the description
 - do not move mode into struct kcov_state
 - use '{ }' instead of '{ 0 }'
---
 MAINTAINERS                |   2 +
 include/linux/kcov.h       |   2 +-
 include/linux/kcov_types.h |  22 +++++++
 include/linux/sched.h      |  13 +----
 kernel/kcov.c              | 115 ++++++++++++++++---------------------
 5 files changed, 78 insertions(+), 76 deletions(-)
 create mode 100644 include/linux/kcov_types.h

diff --git a/MAINTAINERS b/MAINTAINERS
index dd844ac8d9107..5bbc78b0fa6ed 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -12823,11 +12823,13 @@ F:	include/linux/kcore.h
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
index 932b4face1005..0e425c3524b86 100644
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
index f96ac19828934..68af8d6eaee3a 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -42,6 +42,7 @@
 #include <linux/restart_block.h>
 #include <uapi/linux/rseq.h>
 #include <linux/seqlock_types.h>
+#include <linux/kcov_types.h>
 #include <linux/kcsan.h>
 #include <linux/rv.h>
 #include <linux/livepatch_sched.h>
@@ -1512,16 +1513,11 @@ struct task_struct {
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
+	/* kcov buffer state for this task. */
+	struct kcov_state		kcov_state;
 
 	/* KCOV descriptor wired with this task or NULL: */
 	struct kcov			*kcov;
@@ -1529,9 +1525,6 @@ struct task_struct {
 	/* KCOV common handle for remote coverage collection: */
 	u64				kcov_handle;
 
-	/* KCOV sequence number: */
-	int				kcov_sequence;
-
 	/* Collect coverage from softirq context: */
 	unsigned int			kcov_softirq;
 #endif
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 0dd42b78694c9..ff7f118644f49 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -13,6 +13,7 @@
 #include <linux/init.h>
 #include <linux/jiffies.h>
 #include <linux/kcov.h>
+#include <linux/kcov_types.h>
 #include <linux/kmsan-checks.h>
 #include <linux/log2.h>
 #include <linux/mm.h>
@@ -54,24 +55,17 @@ struct kcov {
 	 *  - each code section for remote coverage collection
 	 */
 	refcount_t refcount;
-	/* The lock protects mode, size, area and t. */
+	/* The lock protects state and t. */
 	spinlock_t lock;
 	enum kcov_mode mode;
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
@@ -92,12 +86,9 @@ static struct list_head kcov_remote_areas = LIST_HEAD_INIT(kcov_remote_areas);
 struct kcov_percpu_data {
 	void *irq_area;
 	local_lock_t lock;
-
-	unsigned int saved_mode;
-	unsigned int saved_size;
-	void *saved_area;
+	enum kcov_mode saved_mode;
 	struct kcov *saved_kcov;
-	int saved_sequence;
+	struct kcov_state saved_state;
 };
 
 static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) = {
@@ -219,10 +210,10 @@ void notrace __sanitizer_cov_trace_pc(void)
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
@@ -252,10 +243,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 
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
 
@@ -356,17 +347,15 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_switch);
 #endif /* ifdef CONFIG_KCOV_ENABLE_COMPARISONS */
 
 static void kcov_start(struct task_struct *t, struct kcov *kcov,
-		       unsigned int size, void *area, enum kcov_mode mode,
-		       int sequence)
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
-	/* See comment in check_kcov_mode(). */
+	t->kcov_state = *state;
 	barrier();
+	/* See comment in check_kcov_mode(). */
 	WRITE_ONCE(t->kcov_mode, mode);
 }
 
@@ -375,14 +364,14 @@ static void kcov_stop(struct task_struct *t)
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
 
@@ -398,7 +387,7 @@ static void kcov_reset(struct kcov *kcov)
 	kcov->mode = KCOV_MODE_INIT;
 	kcov->remote = false;
 	kcov->remote_size = 0;
-	kcov->sequence++;
+	kcov->state.sequence++;
 }
 
 static void kcov_remote_reset(struct kcov *kcov)
@@ -438,7 +427,7 @@ static void kcov_put(struct kcov *kcov)
 {
 	if (refcount_dec_and_test(&kcov->refcount)) {
 		kcov_remote_reset(kcov);
-		vfree(kcov->area);
+		vfree(kcov->state.area);
 		kfree(kcov);
 	}
 }
@@ -495,8 +484,8 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	unsigned long flags;
 
 	spin_lock_irqsave(&kcov->lock, flags);
-	size = kcov->size * sizeof(unsigned long);
-	if (kcov->area == NULL || vma->vm_pgoff != 0 ||
+	size = kcov->state.size * sizeof(unsigned long);
+	if (kcov->state.area == NULL || vma->vm_pgoff != 0 ||
 	    vma->vm_end - vma->vm_start != size) {
 		res = -EINVAL;
 		goto exit;
@@ -504,7 +493,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	spin_unlock_irqrestore(&kcov->lock, flags);
 	vm_flags_set(vma, VM_DONTEXPAND);
 	for (off = 0; off < size; off += PAGE_SIZE) {
-		page = vmalloc_to_page(kcov->area + off);
+		page = vmalloc_to_page(kcov->state.area + off);
 		res = vm_insert_page(vma, vma->vm_start + off, page);
 		if (res) {
 			pr_warn_once("kcov: vm_insert_page() failed\n");
@@ -525,7 +514,7 @@ static int kcov_open(struct inode *inode, struct file *filep)
 	if (!kcov)
 		return -ENOMEM;
 	kcov->mode = KCOV_MODE_DISABLED;
-	kcov->sequence = 1;
+	kcov->state.sequence = 1;
 	refcount_set(&kcov->refcount, 1);
 	spin_lock_init(&kcov->lock);
 	filep->private_data = kcov;
@@ -560,10 +549,10 @@ static int kcov_get_mode(unsigned long arg)
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
 
@@ -602,7 +591,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		 * at task exit or voluntary by KCOV_DISABLE. After that it can
 		 * be enabled for another task.
 		 */
-		if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
+		if (kcov->mode != KCOV_MODE_INIT || !kcov->state.area)
 			return -EINVAL;
 		t = current;
 		if (kcov->t != NULL || t->kcov != NULL)
@@ -612,8 +601,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			return mode;
 		kcov_fault_in_area(kcov);
 		kcov->mode = mode;
-		kcov_start(t, kcov, kcov->size, kcov->area, kcov->mode,
-			   kcov->sequence);
+		kcov_start(t, kcov, mode, &kcov->state);
 		kcov->t = t;
 		/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
 		kcov_get(kcov);
@@ -630,7 +618,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		kcov_put(kcov);
 		return 0;
 	case KCOV_REMOTE_ENABLE:
-		if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
+		if (kcov->mode != KCOV_MODE_INIT || !kcov->state.area)
 			return -EINVAL;
 		t = current;
 		if (kcov->t != NULL || t->kcov != NULL)
@@ -725,8 +713,8 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
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
@@ -825,10 +813,8 @@ static void kcov_remote_softirq_start(struct task_struct *t)
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
@@ -839,13 +825,9 @@ static void kcov_remote_softirq_stop(struct task_struct *t)
 	struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
 
 	if (data->saved_kcov) {
-		kcov_start(t, data->saved_kcov, data->saved_size,
-			   data->saved_area, data->saved_mode,
-			   data->saved_sequence);
-		data->saved_mode = 0;
-		data->saved_size = 0;
-		data->saved_area = NULL;
-		data->saved_sequence = 0;
+		kcov_start(t, data->saved_kcov, t->kcov_mode,
+			   &data->saved_state);
+		data->saved_state = (struct kcov_state){};
 		data->saved_kcov = NULL;
 	}
 }
@@ -854,12 +836,12 @@ void kcov_remote_start(u64 handle)
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
@@ -904,7 +886,7 @@ void kcov_remote_start(u64 handle)
 	 * KCOV_DISABLE / kcov_remote_reset().
 	 */
 	mode = kcov->mode;
-	sequence = kcov->sequence;
+	state.sequence = kcov->state.sequence;
 	if (in_task()) {
 		size = kcov->remote_size;
 		area = kcov_remote_area_get(size);
@@ -927,12 +909,14 @@ void kcov_remote_start(u64 handle)
 
 	/* Reset coverage size. */
 	*(u64 *)area = 0;
+	state.area = area;
+	state.size = size;
 
 	if (in_serving_softirq()) {
 		kcov_remote_softirq_start(t);
 		t->kcov_softirq = 1;
 	}
-	kcov_start(t, kcov, size, area, mode, sequence);
+	kcov_start(t, kcov, t->kcov_mode, &state);
 
 	local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
 }
@@ -1030,9 +1014,9 @@ void kcov_remote_stop(void)
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
@@ -1045,8 +1029,9 @@ void kcov_remote_stop(void)
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
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626134158.3385080-5-glider%40google.com.
