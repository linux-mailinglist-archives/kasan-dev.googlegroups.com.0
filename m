Return-Path: <kasan-dev+bncBC7OD3FKWUERBBHKUKXQMGQE4BZ6YYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 23104873E7B
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:10 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-299ba5ae65esf5313824a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749508; cv=pass;
        d=google.com; s=arc-20160816;
        b=PzURMWtIdNi1dMmIjIz7/lVyT6tqOc4vqmM6oqYeV1/hRdxjD0/8pVUmKRslxgrwKW
         Sfx7/ajTMEZ38QfDzzrZdrBQFQI69U/qn+9pWkrrscpcmj+zS6IFghrZxQov9h43+DFZ
         czsaBljtLTJiOX/MHGGdYNd6P8Ji3tOp3cny/vmagq/xgcBh8yi8cikmRxbJ2jdAcluU
         L/Hu9KI3zZ6e4pCwN1FjDb1NU392MkQbZc8r6UmfMR7ZhcVcAMT9rHG7+iW1FdlZYqW/
         g/bABpXHYxGpbbB/NTa5kcZ96yQzA4dVJkR65HuCddU15MUTGTkDeUi6H58DnijZ2rrA
         vVRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=taBqqDvcExMJISpzE4Ot+yMwXSL/JByAuo9MsZOt2qQ=;
        fh=wRqitkwTIqcHI6xzLaWof519zbwonzF9kg73Sp5FVRs=;
        b=CvDJ9z4VulifwlGSCPZ81PyY1p5vCGbETY3zLohafl0f39Io/bkSxQDXFnm6k3v2Bf
         xSjGCkY0ME1T4fmH4/rPWTcTzNIFQDnP0ZN9L9ohx9oi+LWAVaMCHsU5VXyeB5rrJ2W9
         qu0uCwG3mcnh/IVORYqzzlzOzHKl++ufrQHmIGDhI6KF7DUiVdApaNubTOvSqPm1bf/V
         WJhEu4XEXISxvHIp1xwKv25B1BRFuru08PwbBk7T99UfxN67Ie3LvPQnMVkkIq78C/Hm
         cUahtVfLTHuJ7sT4q4ovTmEIVDjOmtPBZVoMur3h97BpZMWwr4lTvGiI1pQ3bpwFc9ji
         XvSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AmujXIdS;
       spf=pass (google.com: domain of 3arxozqykcuuz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3ArXoZQYKCUUz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749508; x=1710354308; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=taBqqDvcExMJISpzE4Ot+yMwXSL/JByAuo9MsZOt2qQ=;
        b=Tkj7nUoi3JkTloLwPUo9Az9kZseAjHp5Xer4KG5a4v7SEzcmLEvY8qcXSu1eYEvT7F
         M65xnKNxdgjSMFQ5VGWg4CpOX08YbGgyyezGyACgTgXt+TRyedC6QmWfIb8s7t35jz9W
         HJpjzS7h3dzL+S1B2byPv4c7w/z5XkjrOtmqIQe0jZZXaebKGYfpmckxUh2Q/EZ6beJ7
         i4Tvg4DoWypAcQoiYkFCTJtLB/GOQTVVWjeEBdKHygP0Vab1hF+E74Y4sfDVOPFmE8ZR
         5V7ZRQEVXP8jg+ZPbD4CLa3/rAGx09ngQLlXX2038VXyxJKjyMd8C5u8JLML3p3eQwze
         WSvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749508; x=1710354308;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=taBqqDvcExMJISpzE4Ot+yMwXSL/JByAuo9MsZOt2qQ=;
        b=BVgWTKVoYQUJZXdjb1SvJD4aTL4i8N9T1TPbY0S26ALSMVDziUGo6PdsHpxiV8Uo5x
         3hHJhkJ1n3UyJ+hkY50dn3c3B21h6qnkoISWwe19cLUMpZDYFqJkEUIj0Vs3x15I1y31
         NY5nKSmlKRUrEDI31oKSNReYlZx2kkUG4Ixpi+Rz/MCfzVjDoZrot4+GY8jcdbtppuCo
         jp/GkEGgZPQxV0g+/rLhpH0aYrprDDiFudXSnPexmFG4c5F/EFNh8pqfK0NqQ+p+s1Ni
         XcO8KKD3I3Iq31sQDvNQ4/TRe65DDk2YGXWjWKr3v2rJvNfs4sbZg4U8lXwm2eLwA53Z
         prIA==
X-Forwarded-Encrypted: i=2; AJvYcCWKORmtO00Bk1uXwGIF8X27wnuxD5Xubv7tMJTYeW45y0NZMPmhxKjTu6pMPUIbz3+X4ShbCH46d1mHdWB4s8KfPszzE6z3fQ==
X-Gm-Message-State: AOJu0YwynVM39HHSCnv6AV5SOdClw/Kz3Xvew0KuWL1K9o1/dCaYVhDm
	OeBcucKB9xEUhndi2KsLoSI9Fw7bAVZrsFmQyS5JkD1uRh2jQAME
X-Google-Smtp-Source: AGHT+IHeqpmPNsG5Dgb/47Lh9enSzLbT4X44rzINoI1xrAhHzmlwbzodFheWiKRfjL1A5H2zj5hKdw==
X-Received: by 2002:a17:90a:6805:b0:299:1c53:113f with SMTP id p5-20020a17090a680500b002991c53113fmr13975526pjj.0.1709749508464;
        Wed, 06 Mar 2024 10:25:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:df85:b0:29b:7c53:abf0 with SMTP id
 p5-20020a17090adf8500b0029b7c53abf0ls45233pjv.0.-pod-prod-05-us; Wed, 06 Mar
 2024 10:25:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWQ09dEiWgaRkxokLVvFo2c7WG1PmJW4u1oDeJPpbBsZb6Rsqp7aDe3e8H8ovyUtjAYEOtHP77oJU/a25sXBMhD6K1KCAmlQdDh5g==
X-Received: by 2002:a17:90a:8a87:b0:299:389e:b611 with SMTP id x7-20020a17090a8a8700b00299389eb611mr11338975pjn.47.1709749507420;
        Wed, 06 Mar 2024 10:25:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749507; cv=none;
        d=google.com; s=arc-20160816;
        b=KAD6oZOKWpdX7HxGZn4ibJD692+/i27DaSo+3x2MOtIabyJHEj+2I/+F1rDajj8Cco
         Xc2PRMapoi7BmS84vpmyhrtNcP+I/B76JBxQztkQSKYaHuo0IEin60AY7f8KChr/6VSX
         N1B6psTLWtudjY58Pdng0CZT196ww+0TnlGLwDVVf+6bDn9WQaFFLsh3Q3qsOcqF3/VW
         LW24bjRouaQxKMr+H4fOJMptXvZVeksQmn5k4sVcdQkZtXAfDmjLK/29rJCLcJzGJgSx
         2d4lzMwugGsDFVESVEfoWcz+VMMYbj+ddZafgHM4yH641+1ZrsHKYQss7TMrgd9/b4YT
         bg6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BNgaGcRDgPcaIXeO4Fkb/yIfx8W6judwG+Ary21N5qY=;
        fh=QJEMIBELtYYm02fUqXQfwN8QMTLZ5pPq2mzVvcjmrFc=;
        b=MMv9AUApNtVg3sT9OaZWX2IU1jwr8J599onWXechCK5IOnY6jmsrrHG+SHw5FU1htd
         f7dhziwnDxvQre1X3MHNjP6JG6yYhlDtRkodysdZkDec1CH5dfCHbGzxnMaIgIEh7XAS
         yRTK34ylddLwFsGEvu6Pcw0utdB5Q7CdoXDO0DEj078lmRi2ml5h8jDaqciWNKcf/uRN
         lGh8/QP2w+wM8+avbtiyXHZSusN6UMy8xZ6RCfxA8ZFkz38u0yJQbPaWFIgObSKaMzZr
         /cge/ooGhHDS8+aijCb239FzUYkbDROstK+0rFmmKiHG3Xd7U5+uU5xblpYRFg5iFX67
         HkDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AmujXIdS;
       spf=pass (google.com: domain of 3arxozqykcuuz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3ArXoZQYKCUUz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p19-20020a17090adf9300b002993c104736si171429pjv.0.2024.03.06.10.25.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3arxozqykcuuz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dcdc3db67f0so1396000276.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX3dr8vPcCCMfJEUFgnZxL7FCZXfasCgu7jpOMNrLA7cj0whcDdOHE8vY5yIq6rRctLE4YZVA+wLSrD62dkwm6V7/CnOModyGdKOg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:1504:b0:dbd:b4e8:1565 with SMTP id
 q4-20020a056902150400b00dbdb4e81565mr1895059ybu.4.1709749506288; Wed, 06 Mar
 2024 10:25:06 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:08 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-11-surenb@google.com>
Subject: [PATCH v5 10/37] lib: code tagging framework
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=AmujXIdS;       spf=pass
 (google.com: domain of 3arxozqykcuuz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3ArXoZQYKCUUz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com;
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

Add basic infrastructure to support code tagging which stores tag common
information consisting of the module name, function, file name and line
number. Provide functions to register a new code tag type and navigate
between code tags.

Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/codetag.h |  68 +++++++++++++
 lib/Kconfig.debug       |   4 +
 lib/Makefile            |   1 +
 lib/codetag.c           | 219 ++++++++++++++++++++++++++++++++++++++++
 4 files changed, 292 insertions(+)
 create mode 100644 include/linux/codetag.h
 create mode 100644 lib/codetag.c

diff --git a/include/linux/codetag.h b/include/linux/codetag.h
new file mode 100644
index 000000000000..7734269cdb63
--- /dev/null
+++ b/include/linux/codetag.h
@@ -0,0 +1,68 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * code tagging framework
+ */
+#ifndef _LINUX_CODETAG_H
+#define _LINUX_CODETAG_H
+
+#include <linux/types.h>
+
+struct codetag_iterator;
+struct codetag_type;
+struct codetag_module;
+struct seq_buf;
+struct module;
+
+/*
+ * An instance of this structure is created in a special ELF section at every
+ * code location being tagged.  At runtime, the special section is treated as
+ * an array of these.
+ */
+struct codetag {
+	unsigned int flags; /* used in later patches */
+	unsigned int lineno;
+	const char *modname;
+	const char *function;
+	const char *filename;
+} __aligned(8);
+
+union codetag_ref {
+	struct codetag *ct;
+};
+
+struct codetag_type_desc {
+	const char *section;
+	size_t tag_size;
+};
+
+struct codetag_iterator {
+	struct codetag_type *cttype;
+	struct codetag_module *cmod;
+	unsigned long mod_id;
+	struct codetag *ct;
+};
+
+#ifdef MODULE
+#define CT_MODULE_NAME KBUILD_MODNAME
+#else
+#define CT_MODULE_NAME NULL
+#endif
+
+#define CODE_TAG_INIT {					\
+	.modname	= CT_MODULE_NAME,		\
+	.function	= __func__,			\
+	.filename	= __FILE__,			\
+	.lineno		= __LINE__,			\
+	.flags		= 0,				\
+}
+
+void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
+struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype);
+struct codetag *codetag_next_ct(struct codetag_iterator *iter);
+
+void codetag_to_text(struct seq_buf *out, struct codetag *ct);
+
+struct codetag_type *
+codetag_register_type(const struct codetag_type_desc *desc);
+
+#endif /* _LINUX_CODETAG_H */
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index ef36b829ae1f..5485a5780fa7 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -968,6 +968,10 @@ config DEBUG_STACKOVERFLOW
 
 	  If in doubt, say "N".
 
+config CODE_TAGGING
+	bool
+	select KALLSYMS
+
 source "lib/Kconfig.kasan"
 source "lib/Kconfig.kfence"
 source "lib/Kconfig.kmsan"
diff --git a/lib/Makefile b/lib/Makefile
index 6b09731d8e61..6b48b22fdfac 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -235,6 +235,7 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) += \
 	of-reconfig-notifier-error-inject.o
 obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
 
+obj-$(CONFIG_CODE_TAGGING) += codetag.o
 lib-$(CONFIG_GENERIC_BUG) += bug.o
 
 obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
diff --git a/lib/codetag.c b/lib/codetag.c
new file mode 100644
index 000000000000..8b5b89ad508d
--- /dev/null
+++ b/lib/codetag.c
@@ -0,0 +1,219 @@
+// SPDX-License-Identifier: GPL-2.0-only
+#include <linux/codetag.h>
+#include <linux/idr.h>
+#include <linux/kallsyms.h>
+#include <linux/module.h>
+#include <linux/seq_buf.h>
+#include <linux/slab.h>
+
+struct codetag_type {
+	struct list_head link;
+	unsigned int count;
+	struct idr mod_idr;
+	struct rw_semaphore mod_lock; /* protects mod_idr */
+	struct codetag_type_desc desc;
+};
+
+struct codetag_range {
+	struct codetag *start;
+	struct codetag *stop;
+};
+
+struct codetag_module {
+	struct module *mod;
+	struct codetag_range range;
+};
+
+static DEFINE_MUTEX(codetag_lock);
+static LIST_HEAD(codetag_types);
+
+void codetag_lock_module_list(struct codetag_type *cttype, bool lock)
+{
+	if (lock)
+		down_read(&cttype->mod_lock);
+	else
+		up_read(&cttype->mod_lock);
+}
+
+struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype)
+{
+	struct codetag_iterator iter = {
+		.cttype = cttype,
+		.cmod = NULL,
+		.mod_id = 0,
+		.ct = NULL,
+	};
+
+	return iter;
+}
+
+static inline struct codetag *get_first_module_ct(struct codetag_module *cmod)
+{
+	return cmod->range.start < cmod->range.stop ? cmod->range.start : NULL;
+}
+
+static inline
+struct codetag *get_next_module_ct(struct codetag_iterator *iter)
+{
+	struct codetag *res = (struct codetag *)
+			((char *)iter->ct + iter->cttype->desc.tag_size);
+
+	return res < iter->cmod->range.stop ? res : NULL;
+}
+
+struct codetag *codetag_next_ct(struct codetag_iterator *iter)
+{
+	struct codetag_type *cttype = iter->cttype;
+	struct codetag_module *cmod;
+	struct codetag *ct;
+
+	lockdep_assert_held(&cttype->mod_lock);
+
+	if (unlikely(idr_is_empty(&cttype->mod_idr)))
+		return NULL;
+
+	ct = NULL;
+	while (true) {
+		cmod = idr_find(&cttype->mod_idr, iter->mod_id);
+
+		/* If module was removed move to the next one */
+		if (!cmod)
+			cmod = idr_get_next_ul(&cttype->mod_idr,
+					       &iter->mod_id);
+
+		/* Exit if no more modules */
+		if (!cmod)
+			break;
+
+		if (cmod != iter->cmod) {
+			iter->cmod = cmod;
+			ct = get_first_module_ct(cmod);
+		} else
+			ct = get_next_module_ct(iter);
+
+		if (ct)
+			break;
+
+		iter->mod_id++;
+	}
+
+	iter->ct = ct;
+	return ct;
+}
+
+void codetag_to_text(struct seq_buf *out, struct codetag *ct)
+{
+	if (ct->modname)
+		seq_buf_printf(out, "%s:%u [%s] func:%s",
+			       ct->filename, ct->lineno,
+			       ct->modname, ct->function);
+	else
+		seq_buf_printf(out, "%s:%u func:%s",
+			       ct->filename, ct->lineno, ct->function);
+}
+
+static inline size_t range_size(const struct codetag_type *cttype,
+				const struct codetag_range *range)
+{
+	return ((char *)range->stop - (char *)range->start) /
+			cttype->desc.tag_size;
+}
+
+#ifdef CONFIG_MODULES
+static void *get_symbol(struct module *mod, const char *prefix, const char *name)
+{
+	DECLARE_SEQ_BUF(sb, KSYM_NAME_LEN);
+	const char *buf;
+
+	seq_buf_printf(&sb, "%s%s", prefix, name);
+	if (seq_buf_has_overflowed(&sb))
+		return NULL;
+
+	buf = seq_buf_str(&sb);
+	return mod ?
+		(void *)find_kallsyms_symbol_value(mod, buf) :
+		(void *)kallsyms_lookup_name(buf);
+}
+
+static struct codetag_range get_section_range(struct module *mod,
+					      const char *section)
+{
+	return (struct codetag_range) {
+		get_symbol(mod, "__start_", section),
+		get_symbol(mod, "__stop_", section),
+	};
+}
+
+static int codetag_module_init(struct codetag_type *cttype, struct module *mod)
+{
+	struct codetag_range range;
+	struct codetag_module *cmod;
+	int err;
+
+	range = get_section_range(mod, cttype->desc.section);
+	if (!range.start || !range.stop) {
+		pr_warn("Failed to load code tags of type %s from the module %s\n",
+			cttype->desc.section,
+			mod ? mod->name : "(built-in)");
+		return -EINVAL;
+	}
+
+	/* Ignore empty ranges */
+	if (range.start == range.stop)
+		return 0;
+
+	BUG_ON(range.start > range.stop);
+
+	cmod = kmalloc(sizeof(*cmod), GFP_KERNEL);
+	if (unlikely(!cmod))
+		return -ENOMEM;
+
+	cmod->mod = mod;
+	cmod->range = range;
+
+	down_write(&cttype->mod_lock);
+	err = idr_alloc(&cttype->mod_idr, cmod, 0, 0, GFP_KERNEL);
+	if (err >= 0)
+		cttype->count += range_size(cttype, &range);
+	up_write(&cttype->mod_lock);
+
+	if (err < 0) {
+		kfree(cmod);
+		return err;
+	}
+
+	return 0;
+}
+
+#else /* CONFIG_MODULES */
+static int codetag_module_init(struct codetag_type *cttype, struct module *mod) { return 0; }
+#endif /* CONFIG_MODULES */
+
+struct codetag_type *
+codetag_register_type(const struct codetag_type_desc *desc)
+{
+	struct codetag_type *cttype;
+	int err;
+
+	BUG_ON(desc->tag_size <= 0);
+
+	cttype = kzalloc(sizeof(*cttype), GFP_KERNEL);
+	if (unlikely(!cttype))
+		return ERR_PTR(-ENOMEM);
+
+	cttype->desc = *desc;
+	idr_init(&cttype->mod_idr);
+	init_rwsem(&cttype->mod_lock);
+
+	err = codetag_module_init(cttype, NULL);
+	if (unlikely(err)) {
+		kfree(cttype);
+		return ERR_PTR(err);
+	}
+
+	mutex_lock(&codetag_lock);
+	list_add_tail(&cttype->link, &codetag_types);
+	mutex_unlock(&codetag_lock);
+
+	return cttype;
+}
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-11-surenb%40google.com.
