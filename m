Return-Path: <kasan-dev+bncBC7OD3FKWUERB5ULXKMAMGQE74PMQYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id EE7825A6F83
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:43 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id b19-20020a9d6b93000000b00637113961absf6625466otq.5
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896183; cv=pass;
        d=google.com; s=arc-20160816;
        b=A6KPPWDV82zuAqedc1a6SYlBC8pOQHbSjvLnF9duW27ZHVQQ/4zFHHrzrOg51IZj4l
         f8pHaOBbsQBMG+oPhTpxAep99EHT1q4hFwMkAC4t9MkiF1DGHa+Jm1ZAYULpR2EvzjY+
         ywvZ35OgDhFzCDW3M3lY8oKWmUu4yTr9Uql/Mvv1SutbOzBFswJ8peCFCVuCbl/0q+gO
         4aAnsN/j8aYIfFACjTtOtmP1q7sZ51vrqtqyQKNqHVq5xIPnsYK9ZEEXCjXpkDPg+HXw
         2NnJlg2Fc080ycVaQ814wT6GTB/QSxbVqCC91J7cg5mEPGA/E3MeMtjDkScPIPauS5r3
         C/Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=/zROtJfjxJIJtzcclNMIQNLy7i0tOc7e1CvrT/E78k4=;
        b=vKe/5OlXbPKWdPdEyuf4HQ12ntWl5BIVXVhav6Qs5oILjjeKZ1F492YFfOSsDxn9zQ
         cisVcJZmP1n4mA8ucuMfWZ2fWaC2eiPvNSnaKlfjt+bUrgkeNuXpISbcizzN1fV8AlJV
         fanauhfeo4KyDzRRf8WV6tXcbVmlq61rkPjK1z1puc73fcXT8w7Lt01ivAvrWtoco7g2
         dWJzMf5R4ePZcCIZUtFfnd0sdAjZTbZp7CUwsaojQqTSJYAgzFc6o5ypRVSQW8vGa2pj
         f8pfyVW37C1S2EZ1GhZNMAusiJ9sJnBt5n2BUdC6mA5/3G/wHgQleM5EKAN6KOVZrZFN
         6i2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dSiwJ3rj;
       spf=pass (google.com: domain of 39yuoywykcvokmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=39YUOYwYKCVoKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=/zROtJfjxJIJtzcclNMIQNLy7i0tOc7e1CvrT/E78k4=;
        b=RUXDANMYE6W4UQL/0FtH4sA6LgWTvyPVTjQuIwDvo8g8xSTNb8qNNA13+9iK89xI3z
         lKGzpW7nNrnSqA81nuC8SwSXDfiiRIKGCJob42ExcnIKkRU8foVBX5mV5qaPqn1O4uFI
         muZMXapJ2cC0Wm7JHAb8O3qbfmczrpoAwrP61qCypZdP9pflf5uKDEzmkaFVse7R+nqc
         aKItkdt/QRkqG7NfBk/xuvOP1nUpC1f6pk5a55TI8CE0cGXGgu7rFXrHXjtHCZiUlpSA
         3CEih7i0wa++IeuGGUfp/el/ZpnJ2hmIYPDdhcClw1gKDyB1M/uNEE23h4glWJ2Rm8L7
         mV9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=/zROtJfjxJIJtzcclNMIQNLy7i0tOc7e1CvrT/E78k4=;
        b=VzrB1PZbbgrJx01r+iaK4yNJrk6mI7YPvNYDWZNXMHhAl6iALOPzte5R7uSbWNoLdV
         izlgogiOOR22FBu1tQ1RcsLFca7EbmkKNV0Dy7A1P3CIzOffUVhWmKybjFPdodTmCuAL
         Bbc4TxQdWNYpRhflFiVFCGiyKt0ph315We0MpJr/6z2ZRZIEgroOxTJzQSkPgEyHlrse
         QDdWBV5D3BqYeFvf95E2YLBHU9gHa/5fd9FEqnMR6uh/kNOtnjdQnGzNT0AylUATLhpq
         RWrcyWac51PeiJJKKhcmIVkbHFuIiWRPd17jsohsZqKEHcOrd61+RbkqHkJmYuK0NLQ3
         Enww==
X-Gm-Message-State: ACgBeo2kdOlBC1DrOWVSQ5Oc0zCCjBxv3/2QyUBjTn7f+lY9bSaYs0uc
	XaO/rDzMvGDBVQXjIPvmQnA=
X-Google-Smtp-Source: AA6agR437FGpS5BzegEO/9CUHI7FgzBRYm5RwMp45luu06rTHBzpjUseKMJK+uJETn58eiWnDXhuBg==
X-Received: by 2002:a05:6870:648d:b0:11d:268f:90f0 with SMTP id cz13-20020a056870648d00b0011d268f90f0mr35137oab.178.1661896182880;
        Tue, 30 Aug 2022 14:49:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:605:0:b0:344:8f41:1800 with SMTP id 5-20020aca0605000000b003448f411800ls3852208oig.10.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:49:42 -0700 (PDT)
X-Received: by 2002:aca:eb8a:0:b0:342:fe2e:7509 with SMTP id j132-20020acaeb8a000000b00342fe2e7509mr30656oih.118.1661896182421;
        Tue, 30 Aug 2022 14:49:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896182; cv=none;
        d=google.com; s=arc-20160816;
        b=WEVzbbfUaBoJI08J1zico1zYVVWgDOMEIwRL7OOt7Yui5S54GIysb/Gpij6BjITFMW
         sqBEcpkYQVltNG0I+lMJkiTcEZFxhPex8lVg97MYqHnAmp8trUqGukDVUxxftAC+9BV0
         XksJnFBA4cR+/VRQwBVsoXpFHFINMBhcmdqzrXDw11NvaC2n8+2FxWGXYuCi/s4K1vNx
         1afRMuoI8g+LvwA11zzYHst0Hu4cfQBSF2ZT1msmzAu6HQrdGJD1IcRVQr8hg2ei6N43
         d50ymcQjuSA4qWIHOEYmbpvF6B/wSgjPaVc7Jw2sznSzzISNaQMBz5JqITMHbq0AQuvH
         SFnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=v/Q5RZvHm0ms6516zJ+eaQEhTJBhgieG8iYB8LZreqU=;
        b=ns1ukLM4tTFlalvUJ1+bM7Mz1PnK9VB4ifblylTqvsxoEs/dSNgzgNl1FlCyeKGTHW
         9pIkuBvWfDH1LbAsZQKuXjzlLRihW/WgTQuEf9ThaZc/lDSQjhf6Yu/xEc3la/CmYUjL
         qrOSDZTLlFYS2KL51GR8/mIy79PHZokoaABkk4lu0/z2B71V5Yg0JsM8d7h/XF/00LUO
         cNdKWZSjBm2h+wgZqGuO7B28D5ch7+ABjJMwiydYfUyMtBpZi2jKCd2fzoK6KVCrJ9cf
         NVWcjHoQqchEws5gbVrpVxwqYqWE7mY8qVQfHFiDbGGg9ba6ZvjxD3SIWNLG9lD/4LMQ
         2cTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dSiwJ3rj;
       spf=pass (google.com: domain of 39yuoywykcvokmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=39YUOYwYKCVoKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id t133-20020aca5f8b000000b0033a351b0b4asi685796oib.3.2022.08.30.14.49.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39yuoywykcvokmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-33dce8cae71so188547257b3.8
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:42 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:2586:0:b0:695:9529:c9a6 with SMTP id
 l128-20020a252586000000b006959529c9a6mr13158054ybl.591.1661896181976; Tue, 30
 Aug 2022 14:49:41 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:48:56 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-8-surenb@google.com>
Subject: [RFC PATCH 07/30] lib: add support for allocation tagging
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
 header.i=@google.com header.s=20210112 header.b=dSiwJ3rj;       spf=pass
 (google.com: domain of 39yuoywykcvokmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=39YUOYwYKCVoKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
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

Introduce CONFIG_ALLOC_TAGGING which provides definitions to easily
instrument allocators. It also registers an "alloc_tags" codetag type
with defbugfs interface to output allocation tags information.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/asm-generic/codetag.lds.h |  14 +++
 include/asm-generic/vmlinux.lds.h |   3 +
 include/linux/alloc_tag.h         |  66 +++++++++++++
 lib/Kconfig.debug                 |   5 +
 lib/Makefile                      |   2 +
 lib/alloc_tag.c                   | 158 ++++++++++++++++++++++++++++++
 scripts/module.lds.S              |   7 ++
 7 files changed, 255 insertions(+)
 create mode 100644 include/asm-generic/codetag.lds.h
 create mode 100644 include/linux/alloc_tag.h
 create mode 100644 lib/alloc_tag.c

diff --git a/include/asm-generic/codetag.lds.h b/include/asm-generic/codetag.lds.h
new file mode 100644
index 000000000000..64f536b80380
--- /dev/null
+++ b/include/asm-generic/codetag.lds.h
@@ -0,0 +1,14 @@
+/* SPDX-License-Identifier: GPL-2.0-only */
+#ifndef __ASM_GENERIC_CODETAG_LDS_H
+#define __ASM_GENERIC_CODETAG_LDS_H
+
+#define SECTION_WITH_BOUNDARIES(_name)	\
+	. = ALIGN(8);			\
+	__start_##_name = .;		\
+	KEEP(*(_name))			\
+	__stop_##_name = .;
+
+#define CODETAG_SECTIONS()		\
+	SECTION_WITH_BOUNDARIES(alloc_tags)
+
+#endif /* __ASM_GENERIC_CODETAG_LDS_H */
diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index 7515a465ec03..c2dc2a59ab2e 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -50,6 +50,8 @@
  *               [__nosave_begin, __nosave_end] for the nosave data
  */
 
+#include <asm-generic/codetag.lds.h>
+
 #ifndef LOAD_OFFSET
 #define LOAD_OFFSET 0
 #endif
@@ -348,6 +350,7 @@
 	__start___dyndbg = .;						\
 	KEEP(*(__dyndbg))						\
 	__stop___dyndbg = .;						\
+	CODETAG_SECTIONS()						\
 	LIKELY_PROFILE()		       				\
 	BRANCH_PROFILE()						\
 	TRACE_PRINTKS()							\
diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
new file mode 100644
index 000000000000..b3f589afb1c9
--- /dev/null
+++ b/include/linux/alloc_tag.h
@@ -0,0 +1,66 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * allocation tagging
+ */
+#ifndef _LINUX_ALLOC_TAG_H
+#define _LINUX_ALLOC_TAG_H
+
+#include <linux/bug.h>
+#include <linux/codetag.h>
+#include <linux/container_of.h>
+#include <linux/lazy-percpu-counter.h>
+
+/*
+ * An instance of this structure is created in a special ELF section at every
+ * allocation callsite. At runtime, the special section is treated as
+ * an array of these. Embedded codetag utilizes codetag framework.
+ */
+struct alloc_tag {
+	struct codetag			ct;
+	unsigned long			last_wrap;
+	struct raw_lazy_percpu_counter	call_count;
+	struct raw_lazy_percpu_counter	bytes_allocated;
+} __aligned(8);
+
+static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
+{
+	return container_of(ct, struct alloc_tag, ct);
+}
+
+#define DEFINE_ALLOC_TAG(_alloc_tag)					\
+	static struct alloc_tag _alloc_tag __used __aligned(8)		\
+	__section("alloc_tags") = { .ct = CODE_TAG_INIT }
+
+#define alloc_tag_counter_read(counter)					\
+	__lazy_percpu_counter_read(counter)
+
+static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes)
+{
+	struct alloc_tag *tag = ct_to_alloc_tag(ref->ct);
+
+	__lazy_percpu_counter_add(&tag->call_count, &tag->last_wrap, -1);
+	__lazy_percpu_counter_add(&tag->bytes_allocated, &tag->last_wrap, -bytes);
+	ref->ct = NULL;
+}
+
+#define alloc_tag_sub(_ref, _bytes)					\
+do {									\
+	if ((_ref) && (_ref)->ct)					\
+		__alloc_tag_sub(_ref, _bytes);				\
+} while (0)
+
+static inline void __alloc_tag_add(struct alloc_tag *tag, union codetag_ref *ref, size_t bytes)
+{
+	ref->ct = &tag->ct;
+	__lazy_percpu_counter_add(&tag->call_count, &tag->last_wrap, 1);
+	__lazy_percpu_counter_add(&tag->bytes_allocated, &tag->last_wrap, bytes);
+}
+
+#define alloc_tag_add(_ref, _bytes)					\
+do {									\
+	DEFINE_ALLOC_TAG(_alloc_tag);					\
+	if (_ref && !WARN_ONCE(_ref->ct, "alloc_tag was not cleared"))	\
+		__alloc_tag_add(&_alloc_tag, _ref, _bytes);		\
+} while (0)
+
+#endif /* _LINUX_ALLOC_TAG_H */
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 22bc1eff7f8f..795bf6993f8a 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -973,6 +973,11 @@ config CODE_TAGGING
 	bool
 	select KALLSYMS
 
+config ALLOC_TAGGING
+	bool
+	select CODE_TAGGING
+	select LAZY_PERCPU_COUNTER
+
 source "lib/Kconfig.kasan"
 source "lib/Kconfig.kfence"
 
diff --git a/lib/Makefile b/lib/Makefile
index 574d7716e640..dc00533fc5c8 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -228,6 +228,8 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) += \
 obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
 
 obj-$(CONFIG_CODE_TAGGING) += codetag.o
+obj-$(CONFIG_ALLOC_TAGGING) += alloc_tag.o
+
 lib-$(CONFIG_GENERIC_BUG) += bug.o
 
 obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
new file mode 100644
index 000000000000..082fbde184ef
--- /dev/null
+++ b/lib/alloc_tag.c
@@ -0,0 +1,158 @@
+// SPDX-License-Identifier: GPL-2.0-only
+#include <linux/alloc_tag.h>
+#include <linux/debugfs.h>
+#include <linux/fs.h>
+#include <linux/gfp.h>
+#include <linux/module.h>
+#include <linux/seq_buf.h>
+#include <linux/uaccess.h>
+
+#ifdef CONFIG_DEBUG_FS
+
+struct alloc_tag_file_iterator {
+	struct codetag_iterator ct_iter;
+	struct seq_buf		buf;
+	char			rawbuf[4096];
+};
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
+static int alloc_tag_file_open(struct inode *inode, struct file *file)
+{
+	struct codetag_type *cttype = inode->i_private;
+	struct alloc_tag_file_iterator *iter;
+
+	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
+	if (!iter)
+		return -ENOMEM;
+
+	codetag_lock_module_list(cttype, true);
+	iter->ct_iter = codetag_get_ct_iter(cttype);
+	codetag_lock_module_list(cttype, false);
+	seq_buf_init(&iter->buf, iter->rawbuf, sizeof(iter->rawbuf));
+	file->private_data = iter;
+
+	return 0;
+}
+
+static int alloc_tag_file_release(struct inode *inode, struct file *file)
+{
+	struct alloc_tag_file_iterator *iter = file->private_data;
+
+	kfree(iter);
+	return 0;
+}
+
+static void alloc_tag_to_text(struct seq_buf *out, struct codetag *ct)
+{
+	struct alloc_tag *tag = ct_to_alloc_tag(ct);
+	char buf[10];
+
+	string_get_size(alloc_tag_counter_read(&tag->bytes_allocated), 1,
+			STRING_UNITS_2, buf, sizeof(buf));
+
+	seq_buf_printf(out, "%8s %8lld ", buf, alloc_tag_counter_read(&tag->call_count));
+	codetag_to_text(out, ct);
+	seq_buf_putc(out, '\n');
+}
+
+static ssize_t alloc_tag_file_read(struct file *file, char __user *ubuf,
+				   size_t size, loff_t *ppos)
+{
+	struct alloc_tag_file_iterator *iter = file->private_data;
+	struct user_buf	buf = { .buf = ubuf, .size = size };
+	struct codetag *ct;
+	int err = 0;
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
+		alloc_tag_to_text(&iter->buf, ct);
+	}
+	codetag_lock_module_list(iter->ct_iter.cttype, false);
+
+	return err ? : buf.ret;
+}
+
+static const struct file_operations alloc_tag_file_ops = {
+	.owner	= THIS_MODULE,
+	.open	= alloc_tag_file_open,
+	.release = alloc_tag_file_release,
+	.read	= alloc_tag_file_read,
+};
+
+static int dbgfs_init(struct codetag_type *cttype)
+{
+	struct dentry *file;
+
+	file = debugfs_create_file("alloc_tags", 0444, NULL, cttype,
+				   &alloc_tag_file_ops);
+
+	return IS_ERR(file) ? PTR_ERR(file) : 0;
+}
+
+#else /* CONFIG_DEBUG_FS */
+
+static int dbgfs_init(struct codetag_type *) { return 0; }
+
+#endif /* CONFIG_DEBUG_FS */
+
+static void alloc_tag_module_unload(struct codetag_type *cttype, struct codetag_module *cmod)
+{
+	struct codetag_iterator iter = codetag_get_ct_iter(cttype);
+	struct codetag *ct;
+
+	for (ct = codetag_next_ct(&iter); ct; ct = codetag_next_ct(&iter)) {
+		struct alloc_tag *tag = ct_to_alloc_tag(ct);
+
+		__lazy_percpu_counter_exit(&tag->call_count);
+		__lazy_percpu_counter_exit(&tag->bytes_allocated);
+	}
+}
+
+static int __init alloc_tag_init(void)
+{
+	struct codetag_type *cttype;
+	const struct codetag_type_desc desc = {
+		.section	= "alloc_tags",
+		.tag_size	= sizeof(struct alloc_tag),
+		.module_unload	= alloc_tag_module_unload,
+	};
+
+	cttype = codetag_register_type(&desc);
+	if (IS_ERR_OR_NULL(cttype))
+		return PTR_ERR(cttype);
+
+	return dbgfs_init(cttype);
+}
+module_init(alloc_tag_init);
diff --git a/scripts/module.lds.S b/scripts/module.lds.S
index 3a3aa2354ed8..e73a8781f239 100644
--- a/scripts/module.lds.S
+++ b/scripts/module.lds.S
@@ -12,6 +12,8 @@
 # define SANITIZER_DISCARDS
 #endif
 
+#include <asm-generic/codetag.lds.h>
+
 SECTIONS {
 	/DISCARD/ : {
 		*(.discard)
@@ -47,6 +49,7 @@ SECTIONS {
 	.data : {
 		*(.data .data.[0-9a-zA-Z_]*)
 		*(.data..L*)
+		CODETAG_SECTIONS()
 	}
 
 	.rodata : {
@@ -62,6 +65,10 @@ SECTIONS {
 		*(.text.__cfi_check)
 		*(.text .text.[0-9a-zA-Z_]* .text..L.cfi*)
 	}
+#else
+	.data : {
+		CODETAG_SECTIONS()
+	}
 #endif
 }
 
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-8-surenb%40google.com.
