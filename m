Return-Path: <kasan-dev+bncBC7OD3FKWUERBLFAVKXAMGQEPNF4G3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id C92C7851FCD
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:39:57 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1db2c98e0e9sf3906295ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:39:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707773996; cv=pass;
        d=google.com; s=arc-20160816;
        b=bPy6SULc7eZ03W3fvX0mMwp/IHmAIn1FIumKf/WCvdJ0PRLZJsITs+ALsVci0kVwY4
         iV6Aot+VvxtwGdfLZYUQH0Kr+KWJGim+pdENuyc9QCWblh9zZ9F356dI1yKGrKDEMd3w
         2hWvboYBe/+GFFXEqwcySCmiXOBrvuWYlI/F60ViyBTRr7zRX4xkyDVQ6pz+DvX2WPyr
         aV/YKSUqLnWmhTW/3R1AFS1HMaX1wlufBQA7HVmTRVMQFn/AJaQUKlrgBnFbAyYGFWVF
         x4rMJg8ADb1xlL0HBW/SBHb5T5h0EPZMUUEjwWJU7QNSflwDq/c4EZZ21wp8uR4hNGt/
         R6ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=qYb3i8OH1bwZpaHD9GmiD+Gu05sgaghKjvoGPSQSGjY=;
        fh=1bKo/Dsyd+VVBkO2IGypuag5/I1kvt88X7v+DnJ2mQY=;
        b=JVbDffDo6W2p8Uir3jaUmRGK4S4GGj/ZSWyEXPs1SEPKtl34s/sgXEBmdxVrNnVOvS
         NC0MG3Tpp6HX9IPer7Rf9qUPn55/4uaHoeWKVoEdWZs1l6u6L1NpzNxqXHBhs5GyFO+S
         b//okTg/U1D/tefI0wCBsqliZXaaKw74jPpIy6es0vmZpeGscd0c5WpUGOHPTXgUTjPd
         Te2A6UPN07Q8pH/3yi4KzLQ+F8B/M6Wk/UAP9SexGa+jomjHrSrv1e42PbiQ5U6KEwfI
         +tTnD8A1J1+Z/0RegldgXk/vu5D+DibrSeCZxtjOoxe9WqrEMCA8Vdb8TsR7sr4aPEOG
         4DhQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Kl4eR9um;
       spf=pass (google.com: domain of 3kpdkzqykcakbdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KpDKZQYKCakbdaNWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707773996; x=1708378796; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qYb3i8OH1bwZpaHD9GmiD+Gu05sgaghKjvoGPSQSGjY=;
        b=KCIS4ExzrbAvLzvE9ZV2FY1k+dWAGA6TsgNw1yoyPY+/H9aROLHzlqwUMFNc2oVtSk
         Nrji76oBVeZrzncDA5gyZ922zpzgrlfKARJI0ZYW7a19BFJlsDfvokpI0AzVDtG0b9dV
         +7JUeHwjY0NizOUMoKDraxn9R7LTjxe5lvmfPxfe7U7irNUWdFqIy2bTmlUj4qeCjfmq
         TN4eN+XZw2ZeyQAx3c3PsjGMq0PJ6kU4aszXW3YNB3IQMMV3rCytOzHXA1h6Mfpx6D7r
         4hcftg+DCIkLzXY/xPnVjzX+r7dz170W6IbGbEZMUzJVIkYpEBrxYKS8KtL5FDAbU1Cc
         HPZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707773996; x=1708378796;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qYb3i8OH1bwZpaHD9GmiD+Gu05sgaghKjvoGPSQSGjY=;
        b=tFvjwbQGmcI7dr3LpPfWb/vZIE/Y/1VqsTtJ6i2znHNAW5AtcV02KEi93DYezHFkl7
         OvcuJhi0airnH6xjVMRNV6/f73c/CZiOye3tiHoqqUmOP85YA6U6k3bpky8TcQq3T7Oe
         TtlFoqmD+7yNTkZm6A/kOm/DFJDE/UQYTculJM06spqGpfa16Qq1Lml8DkGHNaKaai+j
         SPL0dSySCiyCf+httVJKPaHhMgI7dzqWWpC7ML//6xAcsTqVgp46hgScGUJzC0ToGMef
         qctEXqaBD+yk5jqaik5XTgmhCn52fUs60B79gPuDn0mFd/b0IDhw3zcgUCAYRcIH5s0e
         L9Aw==
X-Forwarded-Encrypted: i=2; AJvYcCUvMt28ywyeH8tFYpoE8fL3DWTz8gJnE4iIcLbBEl1pfr7soLiPj64OhNT2GrgFSEf93DC1nSElX/o5sEaijb04TZJa0uwE3w==
X-Gm-Message-State: AOJu0YwSTi3T2YXL9Z/S4v1mMD+FsbypqY8W2tbQUuGjUmarsoaseVqR
	LykzfxDVApwEgbD/wbC5qRtlkVxIzLkZohH3wNf3TY/4nVN+/72u
X-Google-Smtp-Source: AGHT+IFjmtilIHO5TmUG2zOrJa5SiR/ArHssPx+Rq6qzxm0lspwmYbOzmM1Uit9DTTdfm9lfV04WKw==
X-Received: by 2002:a17:902:748a:b0:1d9:a647:5566 with SMTP id h10-20020a170902748a00b001d9a6475566mr8857565pll.4.1707773996290;
        Mon, 12 Feb 2024 13:39:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eecd:b0:1d9:fa6d:af0b with SMTP id
 h13-20020a170902eecd00b001d9fa6daf0bls2049247plb.2.-pod-prod-06-us; Mon, 12
 Feb 2024 13:39:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXnJq1NkxWzQzut14ie6OTb4/V07iBecODiv94uPIwdDfUZdEEuZbCr/hfpQYoGo05edJx5P7VVyHYZil7oCErCuYSB4Ur0Quzo0w==
X-Received: by 2002:a17:902:bf42:b0:1db:2d82:e803 with SMTP id u2-20020a170902bf4200b001db2d82e803mr575784pls.20.1707773995255;
        Mon, 12 Feb 2024 13:39:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707773995; cv=none;
        d=google.com; s=arc-20160816;
        b=Ihoj5gtqEQ3oehLW7V+CK94d3P30JY2QXnkgUxTYWj99fTIPMvj+IM2VFlYq+n4TTS
         pdMIeOOnt7kFORfJX0YxamwBOWz8EgldCvXFhEl3HTLYmMAr0cdBoeygyJ6oxL6oNQQi
         9Q7sAq8aBDOhMP9B61fpKzbzcY6QM4fENMzvL1ye85p5Imko6066vOh/8K8JV4AVNHFQ
         /iFfSfw55iaeAVe6n+Z7ogr/LfZTCaeYaa9LvvL6SYjJAOVqUa3nSV+n67DEyK7U78bN
         KxdKkHRTjCH70iMxXsU8Kg63x1c3ahoyR9VRaEN1uYxUipl6DEjvjqHcsMMjV/Pbwb/k
         +ivg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=3+XWH7AoCI6Q7n29IBIT816HNKsBqFH+UYcKnJYD23I=;
        fh=5VAm/Z7ymzT+I2NP7DyUR3EOBuIA35zpd4ILHbDhyko=;
        b=FkFIPVWAd9j+Oo2geRxyJhOTtKBTfT2Fr93hWwGJ6J+8mEXdJuO8mu7G9mow/wM6IV
         rDkuhl1q3/lHqpJTKSWoMif/wVsNHOSVkVbwjEEsRDcGHNRt6BuZDyFG6J6KqY7YIxYW
         fQarQ6h6YYBY9dwtYF4fLuO4gy5aZ6Wrk/y7ninaxri2+K6bqmr+HKa6RJjRNbrJaKth
         dwxjBbjWQJAJKNwJDG5BoP163Ms59FxGupQrNxPKzZR0c7Ejehh0Em3q3gUd3GBMFBdB
         p7U7+ek0Z65w7PoMwiiAHZhZ4poJWOfcUTGdebskrLFXpY4XusxiqH5niwF016rb9gMF
         7Kcg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Kl4eR9um;
       spf=pass (google.com: domain of 3kpdkzqykcakbdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KpDKZQYKCakbdaNWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCVkYWPIq+MFgaKfU2MzRYdGIUuBkZPEY4SjlQ9AIuRmFVRS4LukZkZpjKJp44lMaZeJI1Tz3A0mgu8M5nCHHOozo/KhHrJMB7pHew==
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id k5-20020a170902760500b001d92eb54a56si87462pll.12.2024.02.12.13.39.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:39:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kpdkzqykcakbdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc6b269b172so5948319276.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:39:55 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXdkaWW8rKu2Gbw2fxQVEYpaRvFGR3vcXyuoEQiDHY/UnFxYM+xaQMqRu5+VG0hC/aAjhzDBjOEDe3DSVfDqBP0jyizgnSgsWq+vQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a25:2614:0:b0:dc6:b7c2:176e with SMTP id
 m20-20020a252614000000b00dc6b7c2176emr130871ybm.4.1707773994229; Mon, 12 Feb
 2024 13:39:54 -0800 (PST)
Date: Mon, 12 Feb 2024 13:38:56 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-11-surenb@google.com>
Subject: [PATCH v3 10/35] lib: code tagging framework
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Kl4eR9um;       spf=pass
 (google.com: domain of 3kpdkzqykcakbdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KpDKZQYKCakbdaNWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--surenb.bounces.google.com;
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
 include/linux/codetag.h |  71 ++++++++++++++
 lib/Kconfig.debug       |   4 +
 lib/Makefile            |   1 +
 lib/codetag.c           | 199 ++++++++++++++++++++++++++++++++++++++++
 4 files changed, 275 insertions(+)
 create mode 100644 include/linux/codetag.h
 create mode 100644 lib/codetag.c

diff --git a/include/linux/codetag.h b/include/linux/codetag.h
new file mode 100644
index 000000000000..a9d7adecc2a5
--- /dev/null
+++ b/include/linux/codetag.h
@@ -0,0 +1,71 @@
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
+#define CODE_TAG_INIT {					\
+	.modname	= KBUILD_MODNAME,		\
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
index 975a07f9f1cc..0be2d00c3696 100644
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
index 000000000000..7708f8388e55
--- /dev/null
+++ b/lib/codetag.c
@@ -0,0 +1,199 @@
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
+	seq_buf_printf(out, "%s:%u module:%s func:%s",
+		       ct->filename, ct->lineno,
+		       ct->modname, ct->function);
+}
+
+static inline size_t range_size(const struct codetag_type *cttype,
+				const struct codetag_range *range)
+{
+	return ((char *)range->stop - (char *)range->start) /
+			cttype->desc.tag_size;
+}
+
+static void *get_symbol(struct module *mod, const char *prefix, const char *name)
+{
+	char buf[64];
+	int res;
+
+	res = snprintf(buf, sizeof(buf), "%s%s", prefix, name);
+	if (WARN_ON(res < 1 || res > sizeof(buf)))
+		return NULL;
+
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
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-11-surenb%40google.com.
