Return-Path: <kasan-dev+bncBC7OD3FKWUERBHUMXKMAMGQEPBTH6FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id CC19F5A6FA6
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:23 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id s15-20020a5b044f000000b00680c4eb89f1sf711942ybp.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896223; cv=pass;
        d=google.com; s=arc-20160816;
        b=JeTyFqOU8QNcTbHd9eyHErSHZhRBZIIBvuG6QMt0m0Q1HKBY9zANSCifQfapvJCP0Q
         i7bgejWD9Iu5mSCePLc2eeOvvfFOEIUpYVVa6GtpCqQDWqISzt+/6gtmT5uiibWqNZGL
         0Vs4DfTQuqZMavVKPTSv6wUwmp5NrRxXaxZEypmz1yFZ/diUEChwuZvrSSNb5ZKbGSdI
         E5fwtpwxVbX0AFZX2+5bDsOk0ZpimyBeDgtMHTndaycninUF5fniDafO1od8+x5Fl1Tj
         H9RF8U1ADC8pYAqvsQVkPvAxsIHfkww6/9SUqfl3tKs42bvYWtDcyPCMvhr6T5xWEZjz
         kXBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=IocZi+Qyw9NcDqmYzv0U8t1xGUlBPlrU/6DbcZXYLRU=;
        b=PKz9B74BY18coJ9bbbE39mlBfBuWcnM8I5s/DbRiKTfduj8DXF10OBYP/GSuvEMboJ
         hCjRFXX+JmxPNaC3bgsgMLgLQeU9/L8Aiuku+/TOlow5usOxWWVtelx6fOBdBl/dGn82
         cthe+EFxTuF7cGZCVB7FWRiehmFcv3Rrpdtt9iXTZmPJS0rZHcPtrRq88PkJB+p8CfA6
         O/q4wJeeuLTLrbCSZrbOlVatdG+0eAs708Sge5R1GzZU7A/C5l75TedkB6ueT6yjjk1j
         SBPKnMmH1M+ODQqKwmZFAVRg7GZz2GVm2BtbJoHtj3eHMb6aXbNwuvB5y4yIi/z5Sg8w
         fOJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E6n8RLBD;
       spf=pass (google.com: domain of 3hyyoywykcyiy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3HYYOYwYKCYIy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=IocZi+Qyw9NcDqmYzv0U8t1xGUlBPlrU/6DbcZXYLRU=;
        b=I0mZnmorGhBFAAFrGEmcDZwRxA9NEPwLJx0k4X1AKCBXDm0H7ADyCnSL7r0Q6tcLWO
         0vrhYwYy9AK5CNeAHxLRDseu5v8gPgZIF5LAYBF8nuI8TW/rHVshz+DeIjbiJJaq0Z26
         Wf2kGIYjEMIcIBO8eB/cC/bxOdLvubBb5RJi2PcWiEUluPYojiqwvkjZPqxuMtuvde2e
         6bbrK7Pp3VbihuapcbesudkCeZi1rj0XX9X12R1w4SHPMGHWvCDspIUxuyDJV1XCJ/WU
         CDloCH0dXv0MBdBh79pPIFhCJniNtF/BR+Y5kZ09TEfR4p24oBzJCMNE7/pnjlDjDTZi
         bGXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=IocZi+Qyw9NcDqmYzv0U8t1xGUlBPlrU/6DbcZXYLRU=;
        b=wl5JTb+d6OO6N20tUQowvpWfxbuY1VfjPVqCphJmmTtNjcROaW1ZdX2Ml914cyRUmp
         QH/bpThrFHPl1Vs67y+m9x/Gzg92yeFzs1W68jaqDtsUrxist1Ru2XcQSxF7hxKWQSGf
         w0efywR3voTp+I1hIUSpQCCWM9iCXswwiDxcyU2VwaOHihL0cJFLZR7N3wW0OOUTZczK
         6N4xotw5SvrmS8wvH663cvtvAI1YdT2VU2V3BloJq1VcnmFmsoCiLA4ZYrlE8vY8KGvI
         2iZAWwTEheSCrqJR7jq6E8Ma3/Tbw/2SSxL4RrFS1o3GjCiX2Ykq3ddJDhS4pN9GYWYE
         ETOg==
X-Gm-Message-State: ACgBeo2G8Vq4D9lNStscjvRcg/iyHMxV4fDGkf+m6yodW5zZoCe9MEO5
	zNwNe+58+ohdjKLmgvJilrU=
X-Google-Smtp-Source: AA6agR5o3N7U9IIwg4SzVjzCAJxUu1Ttm259U4CZJF81xArl4UXQw33PSdMO99DOmCNGl3xCqXx4Xg==
X-Received: by 2002:a05:6902:10c1:b0:695:f378:f36c with SMTP id w1-20020a05690210c100b00695f378f36cmr13928955ybu.419.1661896222874;
        Tue, 30 Aug 2022 14:50:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b38a:0:b0:696:4c31:6ddf with SMTP id m10-20020a25b38a000000b006964c316ddfls4901344ybj.9.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:50:22 -0700 (PDT)
X-Received: by 2002:a25:bb0d:0:b0:687:7ba9:c69e with SMTP id z13-20020a25bb0d000000b006877ba9c69emr12314156ybg.562.1661896222297;
        Tue, 30 Aug 2022 14:50:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896222; cv=none;
        d=google.com; s=arc-20160816;
        b=Wbb2hOmssqHbNV8hvbGvgbdUcHm2Inw1tASPgs6JbXAWbaDq4GwGkuwk5C3zlSshSw
         QzADW0uXDmOVlJEAQDmLSclPNGEVGSk+qTxxMIG4SvFUJ1+tSr18WnnaR+FmWnbtkPKF
         Wc0h6YpdKs2qDe3EYry1VxVkgLB3XslqQTpbPz1sRD+9P50zs7TNorNCIeUwlLA01OML
         xr7PRw3UxmbuLjM1+/nNUvAJ8G/0Q56kNi0aAgi8v841jpv6JLXcFfygunhugNPJM33g
         PvJzCvDb8g2ohlc+W1qDQI09uQi1A3eH+guoWBAjVsdkjE6x0zpHr4/2c2jQA0oiPBNW
         7ByQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=OQ1/DMahF4uWAfLYh5vc64TkQSOW6G8gA0sp/Oew5U4=;
        b=Di82Cfe5KoOmeLRoCIV7IhWGc+pDyf1kKnciPVn+PMy/biI5t1I/ykNDai783ViZfM
         7cQDbD1HQjqpfG3N/ETnHmRzE/vkeVBMtUsYrKN7+rfpf0V+e6UrswZKCKgpAOQsVu7V
         pZzPUa9EcF8itef7TqbtFXvPcVknEdDWLRJscgHBo5nV6xXUHpvV3f8l60AW4gIXz9nA
         qCpO4JFTfWQupgi4dToFL/vNSJaI5lNA0/hXNBCSj04kW2nOFMQVJop0njQTAPMcOcsP
         xpnciSq0090MWRrbpB445Jru+XvB/qIZaZ04ExTLWDZTw8gs8gApXhq7vKRPaZO48XNw
         8+ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E6n8RLBD;
       spf=pass (google.com: domain of 3hyyoywykcyiy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3HYYOYwYKCYIy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id q3-20020a815c03000000b0033dca312115si882316ywb.4.2022.08.30.14.50.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hyyoywykcyiy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id n16-20020a258d10000000b0068df1e297c0so720461ybl.15
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:22 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:6985:0:b0:695:8355:f894 with SMTP id
 e127-20020a256985000000b006958355f894mr13667557ybc.648.1661896221989; Tue, 30
 Aug 2022 14:50:21 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:11 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-23-surenb@google.com>
Subject: [RFC PATCH 22/30] Code tagging based fault injection
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
 header.i=@google.com header.s=20210112 header.b=E6n8RLBD;       spf=pass
 (google.com: domain of 3hyyoywykcyiy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3HYYOYwYKCYIy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com;
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

This adds a new fault injection capability, based on code tagging.

To use, simply insert somewhere in your code

  dynamic_fault("fault_class_name")

and check whether it returns true - if so, inject the error.
For example

  if (dynamic_fault("init"))
      return -EINVAL;

There's no need to define faults elsewhere, as with
include/linux/fault-injection.h. Faults show up in debugfs, under
/sys/kernel/debug/dynamic_faults, and can be selected based on
file/module/function/line number/class, and enabled permanently, or in
oneshot mode, or with a specified frequency.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/asm-generic/codetag.lds.h |   3 +-
 include/linux/dynamic_fault.h     |  79 +++++++
 include/linux/slab.h              |   3 +-
 lib/Kconfig.debug                 |   6 +
 lib/Makefile                      |   2 +
 lib/dynamic_fault.c               | 372 ++++++++++++++++++++++++++++++
 6 files changed, 463 insertions(+), 2 deletions(-)
 create mode 100644 include/linux/dynamic_fault.h
 create mode 100644 lib/dynamic_fault.c

diff --git a/include/asm-generic/codetag.lds.h b/include/asm-generic/codetag.lds.h
index 64f536b80380..16fbf74edc3d 100644
--- a/include/asm-generic/codetag.lds.h
+++ b/include/asm-generic/codetag.lds.h
@@ -9,6 +9,7 @@
 	__stop_##_name = .;
 
 #define CODETAG_SECTIONS()		\
-	SECTION_WITH_BOUNDARIES(alloc_tags)
+	SECTION_WITH_BOUNDARIES(alloc_tags)		\
+	SECTION_WITH_BOUNDARIES(dynamic_fault_tags)
 
 #endif /* __ASM_GENERIC_CODETAG_LDS_H */
diff --git a/include/linux/dynamic_fault.h b/include/linux/dynamic_fault.h
new file mode 100644
index 000000000000..526a33209e94
--- /dev/null
+++ b/include/linux/dynamic_fault.h
@@ -0,0 +1,79 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef _LINUX_DYNAMIC_FAULT_H
+#define _LINUX_DYNAMIC_FAULT_H
+
+/*
+ * Dynamic/code tagging fault injection:
+ *
+ * Originally based on the dynamic debug trick of putting types in a special elf
+ * section, then rewritten using code tagging:
+ *
+ * To use, simply insert a call to dynamic_fault("fault_class"), which will
+ * return true if an error should be injected.
+ *
+ * Fault injection sites may be listed and enabled via debugfs, under
+ * /sys/kernel/debug/dynamic_faults.
+ */
+
+#ifdef CONFIG_CODETAG_FAULT_INJECTION
+
+#include <linux/codetag.h>
+#include <linux/jump_label.h>
+
+#define DFAULT_STATES()		\
+	x(disabled)		\
+	x(enabled)		\
+	x(oneshot)
+
+enum dfault_enabled {
+#define x(n)	DFAULT_##n,
+	DFAULT_STATES()
+#undef x
+};
+
+union dfault_state {
+	struct {
+		unsigned int		enabled:2;
+		unsigned int		count:30;
+	};
+
+	struct {
+		unsigned int		v;
+	};
+};
+
+struct dfault {
+	struct codetag		tag;
+	const char		*class;
+	unsigned int		frequency;
+	union dfault_state	state;
+	struct static_key_false	enabled;
+};
+
+bool __dynamic_fault_enabled(struct dfault *df);
+
+#define dynamic_fault(_class)				\
+({							\
+	static struct dfault				\
+	__used						\
+	__section("dynamic_fault_tags")			\
+	__aligned(8) df = {				\
+		.tag	= CODE_TAG_INIT,		\
+		.class	= _class,			\
+		.enabled = STATIC_KEY_FALSE_INIT,	\
+	};						\
+							\
+	static_key_false(&df.enabled.key) &&		\
+		__dynamic_fault_enabled(&df);		\
+})
+
+#else
+
+#define dynamic_fault(_class)	false
+
+#endif /* CODETAG_FAULT_INJECTION */
+
+#define memory_fault()		dynamic_fault("memory")
+
+#endif /* _LINUX_DYNAMIC_FAULT_H */
diff --git a/include/linux/slab.h b/include/linux/slab.h
index 89273be35743..4be5a93ed15a 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -17,6 +17,7 @@
 #include <linux/types.h>
 #include <linux/workqueue.h>
 #include <linux/percpu-refcount.h>
+#include <linux/dynamic_fault.h>
 
 
 /*
@@ -468,7 +469,7 @@ static inline void slab_tag_dec(const void *ptr) {}
 
 #define krealloc_hooks(_p, _do_alloc)					\
 ({									\
-	void *_res = _do_alloc;						\
+	void *_res = !memory_fault() ? _do_alloc : NULL;		\
 	slab_tag_add(_p, _res);						\
 	_res;								\
 })
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 2790848464f1..b7d03afbc808 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1982,6 +1982,12 @@ config FAULT_INJECTION_STACKTRACE_FILTER
 	help
 	  Provide stacktrace filter for fault-injection capabilities
 
+config CODETAG_FAULT_INJECTION
+	bool "Code tagging based fault injection"
+	select CODE_TAGGING
+	help
+	  Dynamic fault injection based on code tagging
+
 config ARCH_HAS_KCOV
 	bool
 	help
diff --git a/lib/Makefile b/lib/Makefile
index 99f732156673..489ea000c528 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -231,6 +231,8 @@ obj-$(CONFIG_CODE_TAGGING) += codetag.o
 obj-$(CONFIG_ALLOC_TAGGING) += alloc_tag.o
 obj-$(CONFIG_PAGE_ALLOC_TAGGING) += pgalloc_tag.o
 
+obj-$(CONFIG_CODETAG_FAULT_INJECTION) += dynamic_fault.o
+
 lib-$(CONFIG_GENERIC_BUG) += bug.o
 
 obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
diff --git a/lib/dynamic_fault.c b/lib/dynamic_fault.c
new file mode 100644
index 000000000000..4c9cd18686be
--- /dev/null
+++ b/lib/dynamic_fault.c
@@ -0,0 +1,372 @@
+// SPDX-License-Identifier: GPL-2.0-only
+
+#include <linux/ctype.h>
+#include <linux/debugfs.h>
+#include <linux/dynamic_fault.h>
+#include <linux/kernel.h>
+#include <linux/module.h>
+#include <linux/seq_buf.h>
+
+static struct codetag_type *cttype;
+
+bool __dynamic_fault_enabled(struct dfault *df)
+{
+	union dfault_state old, new;
+	unsigned int v = df->state.v;
+	bool ret;
+
+	do {
+		old.v = new.v = v;
+
+		if (new.enabled == DFAULT_disabled)
+			return false;
+
+		ret = df->frequency
+			? ++new.count >= df->frequency
+			: true;
+		if (ret)
+			new.count = 0;
+		if (ret && new.enabled == DFAULT_oneshot)
+			new.enabled = DFAULT_disabled;
+	} while ((v = cmpxchg(&df->state.v, old.v, new.v)) != old.v);
+
+	if (ret)
+		pr_debug("returned true for %s:%u", df->tag.filename, df->tag.lineno);
+
+	return ret;
+}
+EXPORT_SYMBOL(__dynamic_fault_enabled);
+
+static const char * const dfault_state_strs[] = {
+#define x(n)	#n,
+	DFAULT_STATES()
+#undef x
+	NULL
+};
+
+static void dynamic_fault_to_text(struct seq_buf *out, struct dfault *df)
+{
+	codetag_to_text(out, &df->tag);
+	seq_buf_printf(out, "class:%s %s \"", df->class,
+		       dfault_state_strs[df->state.enabled]);
+}
+
+struct dfault_query {
+	struct codetag_query q;
+
+	bool		set_enabled:1;
+	unsigned int	enabled:2;
+
+	bool		set_frequency:1;
+	unsigned int	frequency;
+};
+
+/*
+ * Search the tables for _dfault's which match the given
+ * `query' and apply the `flags' and `mask' to them.  Tells
+ * the user which dfault's were changed, or whether none
+ * were matched.
+ */
+static int dfault_change(struct dfault_query *query)
+{
+	struct codetag_iterator ct_iter;
+	struct codetag *ct;
+	unsigned int nfound = 0;
+
+	codetag_lock_module_list(cttype, true);
+	codetag_init_iter(&ct_iter, cttype);
+
+	while ((ct = codetag_next_ct(&ct_iter))) {
+		struct dfault *df = container_of(ct, struct dfault, tag);
+
+		if (!codetag_matches_query(&query->q, ct, ct_iter.cmod, df->class))
+			continue;
+
+		if (query->set_enabled &&
+		    query->enabled != df->state.enabled) {
+			if (query->enabled != DFAULT_disabled)
+				static_key_slow_inc(&df->enabled.key);
+			else if (df->state.enabled != DFAULT_disabled)
+				static_key_slow_dec(&df->enabled.key);
+
+			df->state.enabled = query->enabled;
+		}
+
+		if (query->set_frequency)
+			df->frequency = query->frequency;
+
+		pr_debug("changed %s:%d [%s]%s #%d %s",
+			 df->tag.filename, df->tag.lineno, df->tag.modname,
+			 df->tag.function, query->q.cur_index,
+			 dfault_state_strs[df->state.enabled]);
+
+		nfound++;
+	}
+
+	pr_debug("dfault: %u matches", nfound);
+
+	codetag_lock_module_list(cttype, false);
+
+	return nfound ? 0 : -ENOENT;
+}
+
+#define DFAULT_TOKENS()		\
+	x(disable,	0)	\
+	x(enable,	0)	\
+	x(oneshot,	0)	\
+	x(frequency,	1)
+
+enum dfault_token {
+#define x(name, nr_args)	TOK_##name,
+	DFAULT_TOKENS()
+#undef x
+};
+
+static const char * const dfault_token_strs[] = {
+#define x(name, nr_args)	#name,
+	DFAULT_TOKENS()
+#undef x
+	NULL
+};
+
+static unsigned int dfault_token_nr_args[] = {
+#define x(name, nr_args)	nr_args,
+	DFAULT_TOKENS()
+#undef x
+};
+
+static enum dfault_token str_to_token(const char *word, unsigned int nr_words)
+{
+	int tok = match_string(dfault_token_strs, ARRAY_SIZE(dfault_token_strs), word);
+
+	if (tok < 0) {
+		pr_debug("unknown keyword \"%s\"", word);
+		return tok;
+	}
+
+	if (nr_words < dfault_token_nr_args[tok]) {
+		pr_debug("insufficient arguments to \"%s\"", word);
+		return -EINVAL;
+	}
+
+	return tok;
+}
+
+static int dfault_parse_command(struct dfault_query *query,
+				enum dfault_token tok,
+				char *words[], size_t nr_words)
+{
+	unsigned int i = 0;
+	int ret;
+
+	switch (tok) {
+	case TOK_disable:
+		query->set_enabled = true;
+		query->enabled = DFAULT_disabled;
+		break;
+	case TOK_enable:
+		query->set_enabled = true;
+		query->enabled = DFAULT_enabled;
+		break;
+	case TOK_oneshot:
+		query->set_enabled = true;
+		query->enabled = DFAULT_oneshot;
+		break;
+	case TOK_frequency:
+		query->set_frequency = 1;
+		ret = kstrtouint(words[i++], 10, &query->frequency);
+		if (ret)
+			return ret;
+
+		if (!query->set_enabled) {
+			query->set_enabled = 1;
+			query->enabled = DFAULT_enabled;
+		}
+		break;
+	}
+
+	return i;
+}
+
+static int dynamic_fault_store(char *buf)
+{
+	struct dfault_query query = { NULL };
+#define MAXWORDS 9
+	char *tok, *words[MAXWORDS];
+	int ret, nr_words, i = 0;
+
+	buf = codetag_query_parse(&query.q, buf);
+	if (IS_ERR(buf))
+		return PTR_ERR(buf);
+
+	while ((tok = strsep_no_empty(&buf, " \t\r\n"))) {
+		if (nr_words == ARRAY_SIZE(words))
+			return -EINVAL;	/* ran out of words[] before bytes */
+		words[nr_words++] = tok;
+	}
+
+	while (i < nr_words) {
+		const char *tok_str = words[i++];
+		enum dfault_token tok = str_to_token(tok_str, nr_words - i);
+
+		if (tok < 0)
+			return tok;
+
+		ret = dfault_parse_command(&query, tok, words + i, nr_words - i);
+		if (ret < 0)
+			return ret;
+
+		i += ret;
+		BUG_ON(i > nr_words);
+	}
+
+	pr_debug("q->function=\"%s\" q->filename=\"%s\" "
+		 "q->module=\"%s\" q->line=%u-%u\n q->index=%u-%u",
+		 query.q.function, query.q.filename, query.q.module,
+		 query.q.first_line, query.q.last_line,
+		 query.q.first_index, query.q.last_index);
+
+	ret = dfault_change(&query);
+	if (ret < 0)
+		return ret;
+
+	return 0;
+}
+
+struct dfault_iter {
+	struct codetag_iterator ct_iter;
+
+	struct seq_buf		buf;
+	char			rawbuf[4096];
+};
+
+static int dfault_open(struct inode *inode, struct file *file)
+{
+	struct dfault_iter *iter;
+
+	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
+	if (!iter)
+		return -ENOMEM;
+
+	codetag_lock_module_list(cttype, true);
+	codetag_init_iter(&iter->ct_iter, cttype);
+	codetag_lock_module_list(cttype, false);
+
+	file->private_data = iter;
+	seq_buf_init(&iter->buf, iter->rawbuf, sizeof(iter->rawbuf));
+	return 0;
+}
+
+static int dfault_release(struct inode *inode, struct file *file)
+{
+	struct dfault_iter *iter = file->private_data;
+
+	kfree(iter);
+	return 0;
+}
+
+struct user_buf {
+	char __user		*buf;	/* destination user buffer */
+	size_t			size;	/* size of requested read */
+	ssize_t			ret;	/* bytes read so far */
+};
+
+static int flush_ubuf(struct user_buf *dst, struct seq_buf *src)
+{
+	if (src->len) {
+		size_t bytes = min_t(size_t, src->len, dst->size);
+		int err = copy_to_user(dst->buf, src->buffer, bytes);
+
+		if (err)
+			return err;
+
+		dst->ret	+= bytes;
+		dst->buf	+= bytes;
+		dst->size	-= bytes;
+		src->len	-= bytes;
+		memmove(src->buffer, src->buffer + bytes, src->len);
+	}
+
+	return 0;
+}
+
+static ssize_t dfault_read(struct file *file, char __user *ubuf,
+			   size_t size, loff_t *ppos)
+{
+	struct dfault_iter *iter = file->private_data;
+	struct user_buf	buf = { .buf = ubuf, .size = size };
+	struct codetag *ct;
+	struct dfault *df;
+	int err;
+
+	codetag_lock_module_list(iter->ct_iter.cttype, true);
+	while (1) {
+		err = flush_ubuf(&buf, &iter->buf);
+		if (err || !buf.size)
+			break;
+
+		ct = codetag_next_ct(&iter->ct_iter);
+		if (!ct)
+			break;
+
+		df = container_of(ct, struct dfault, tag);
+		dynamic_fault_to_text(&iter->buf, df);
+		seq_buf_putc(&iter->buf, '\n');
+	}
+	codetag_lock_module_list(iter->ct_iter.cttype, false);
+
+	return err ?: buf.ret;
+}
+
+/*
+ * File_ops->write method for <debugfs>/dynamic_fault/conrol.  Gathers the
+ * command text from userspace, parses and executes it.
+ */
+static ssize_t dfault_write(struct file *file, const char __user *ubuf,
+			    size_t len, loff_t *offp)
+{
+	char tmpbuf[256];
+
+	if (len == 0)
+		return 0;
+	/* we don't check *offp -- multiple writes() are allowed */
+	if (len > sizeof(tmpbuf)-1)
+		return -E2BIG;
+	if (copy_from_user(tmpbuf, ubuf, len))
+		return -EFAULT;
+	tmpbuf[len] = '\0';
+	pr_debug("read %zu bytes from userspace", len);
+
+	dynamic_fault_store(tmpbuf);
+
+	*offp += len;
+	return len;
+}
+
+static const struct file_operations dfault_ops = {
+	.owner	= THIS_MODULE,
+	.open	= dfault_open,
+	.release = dfault_release,
+	.read	= dfault_read,
+	.write	= dfault_write
+};
+
+static int __init dynamic_fault_init(void)
+{
+	const struct codetag_type_desc desc = {
+		.section = "dynamic_fault_tags",
+		.tag_size = sizeof(struct dfault),
+	};
+	struct dentry *debugfs_file;
+
+	cttype = codetag_register_type(&desc);
+	if (IS_ERR_OR_NULL(cttype))
+		return PTR_ERR(cttype);
+
+	debugfs_file = debugfs_create_file("dynamic_faults", 0666, NULL, NULL, &dfault_ops);
+	if (IS_ERR(debugfs_file))
+		return PTR_ERR(debugfs_file);
+
+	return 0;
+}
+module_init(dynamic_fault_init);
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-23-surenb%40google.com.
