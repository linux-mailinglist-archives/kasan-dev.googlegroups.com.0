Return-Path: <kasan-dev+bncBC7OD3FKWUERBXMV36UQMGQES5IZNRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id ACDBF7D523B
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:10 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-41cd5077ffesf1510091cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155229; cv=pass;
        d=google.com; s=arc-20160816;
        b=xtPRBIWFJ4wBFA4vmEmWsqoVrN3mcRmEhd68DLTYjOKgyW6W/z3MBzSwDCgKuzQgcz
         vRWYGs1b3bYxxse/zfATMfYT2P2geegQxUz/gX1fRksxvGDYXgJpNhR7Cai8IgDmsNQ9
         ZIdQ2fzO60L2s54z57xhCapsvvID2SGFsNDSr/4cdH6sle25pzjHB21NrgVsx4nRNmLs
         ibcRVBmrP04dD94svCZ8NIx/No/CfQtixSG160EhVcsIThDQuQyaUCY4G2RYre8fjfUG
         cyzXWijlW5qgO8L2YDVVSNWg+jWBYyTmqfWfVcXwQlRen0AVtfL5F+oNf2+GRbDOuOZF
         +PXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=6eAqsYycIS2ghrnCKGJEL/CaCCBxCLyWDq7rTywqIgM=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=nFCJxw9OSqOlYCFA4HuEoh3s/W44qdekBq14sF5El3I4psvOHptSfS9pOD6NF+S+ml
         4p4cfPGDJD8qugzZNbTw46f0PKv1ZYI/AsOzgcIOo6Ufv/Rv6YLbeibMa2VOz3rpN4al
         k/dInBaeBaVp+Lv2B/ESoHfemOEAN3ycmjoGGBnSijZN+6lOBRPmlknWzImATwOtZaGB
         SC5HWdNK4vazvSVWQFflcd9VgCronm70KdxxvOzTsY/BsEngUt9nM0Mb8LeRohTon/NA
         xu1y8CsESo5+mSu8br1t+k88CujCtqMyfQu9vsRBT7vC1Dsi7ah8aBIhsbZsaAdTY4kY
         O7XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JYPfnObL;
       spf=pass (google.com: domain of 33mo3zqykcyexzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=33Mo3ZQYKCYExzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155229; x=1698760029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6eAqsYycIS2ghrnCKGJEL/CaCCBxCLyWDq7rTywqIgM=;
        b=tv9SpoMGK5uF5i6KqIfjwpAwz8H0gnxJdEhFQxf8Oau5sOOsW1f2BnOXbBjQ6ySbD7
         NwpfoAFVrPyXLh7tBBysfF3k/WZ2iZwflxB6eMIzIP9k9wkj5pmavlfeJUe7vprqgjQ0
         htDRZdAqjnuszcjy7nWM16HPR/lY5iK2wCQjOUHlMin6PHOCqLzwSCk6Y0cpQfmrIBzF
         0fz2SvJSd5zDf66F5SGzrSK2had6A7KDD8/mBs58r3wHNufq+MAzEbZiPIzIzldd0QIr
         mqlThfb2ig+YvbO8ueZNXdd9PGJyU9rQfyfHt0Y4zWHfbkrlCO+scZdlFx2ZG4XeZY+4
         vYVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155229; x=1698760029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6eAqsYycIS2ghrnCKGJEL/CaCCBxCLyWDq7rTywqIgM=;
        b=p7t1k6WLLJjGtoR1E06u6ZvH4zOQpfOc7CrVzWdczP7vhmVDg3sSwDDHQUacIkHMdU
         8IP8er3DXBCZbqaB/2orm30hyqg/x3Bzntd3fpj2kvLVF5lVYkkzcPyg15t8b/UT/h5J
         WJL0Oyppn9l7zsWUPnmEJum4c+wiyUquOxlbgDplrVzMuHcfx3PZShxK2BHMZ70dV6e9
         hDBQIFrlUZuVHczbHIeY0ONmeWT7mZ9aKq+dlGKxfmn0kinsI3ku8iVcOyqCxNUneE6g
         9o9ctHs8Lhke0SBnRL6Q1lqYJWxPZyeBohTvWyq+B/RKdp21yxyttJKgIpybyJBNkJFR
         J7hQ==
X-Gm-Message-State: AOJu0YwtUkPNR48jWb8N9FSFtF1iQk3UVYP5XaI6cnpT8S4UwAy1B5eu
	YjQ8Xk+dGnO1x6pKCyP7geY=
X-Google-Smtp-Source: AGHT+IF2OZh9aWrvmV4HDMyx6vjlbilkDa+RoGsh99CKZQEDTKkdOd17AoH1IwTtkFpfh02XVNaZ9w==
X-Received: by 2002:a05:622a:268f:b0:41c:bdc5:7c32 with SMTP id kd15-20020a05622a268f00b0041cbdc57c32mr208745qtb.7.1698155229683;
        Tue, 24 Oct 2023 06:47:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:419f:b0:65b:e4f:d22f with SMTP id
 ld31-20020a056214419f00b0065b0e4fd22fls1322075qvb.2.-pod-prod-05-us; Tue, 24
 Oct 2023 06:47:08 -0700 (PDT)
X-Received: by 2002:a05:6102:e0c:b0:45a:aab9:b613 with SMTP id o12-20020a0561020e0c00b0045aaab9b613mr1449544vst.21.1698155228724;
        Tue, 24 Oct 2023 06:47:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155228; cv=none;
        d=google.com; s=arc-20160816;
        b=bWVNWCblZIPUbEr5emL1atl/MnpSGpms2S+kxrY9JsjRMkHIgdm20/hv8o43EvKqko
         TSKqREqhNuNSJa4xwBFo2GmDI55IejnbdFLtKpjDbgzBJa+N2S7xIaPeEYh+Iwen5cgV
         k+jmWYxtOCoBTBdOOFL4Nhbeypx5DHyHA1WVRKT7Pf8FB3rv9Qps3SKPneSb6+OEsIPE
         fI++tx8F44UOpQ6PfFgF4PxZaADkUbK3UkzBdUUqYFmQzh0FqqWm7FYFdeoK2+/hMl3b
         c3HexNadzmNnDoTfnSu03/xKSRbaf9Nj1YOyWuUv94tUND6UJ4YiRBSuIb8Rdkt1k+dx
         J8VQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=9NoZOXA8j9UYH0qbl3Heb4+Wi1EaC598WUGqABNW4pA=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=cD7ALeigD+xS0Mj9VjXxfm48fxdZPQxrWI4Ns5Q6wvFdhyB6nkjcvtGbkHesgMs+VE
         49fqNvJFzoTN3C5EZ0pW3P0eJddH9Y4pZiKRtizOrSIzbrBOPh4mMOtyPKkaknmBd8bZ
         9A1ccmwlsR6eOGM4FcOq7mm2/o0i1m3hSgizdR0yEBh4NEODRrlXjNf5XeajlA4or75W
         BT8K+CgIPF79UXwp8pQxwlO0FG1EgcBUj0gkuoQ1OAOX0YQS0i0Wfu6Rh98p9LimuiZu
         0bUszfcFdNKkFEYkE2RUqgStEuDSCnHAkxjdwHEctUR5yDb0LltNr+J6W8bRuAsG5/AI
         0fag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JYPfnObL;
       spf=pass (google.com: domain of 33mo3zqykcyexzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=33Mo3ZQYKCYExzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id p19-20020ab03b93000000b007a5003d1b38si375920uaw.1.2023.10.24.06.47.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33mo3zqykcyexzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5a7ba10cb90so61769687b3.3
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:08 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a81:a08c:0:b0:57a:e0b:f63 with SMTP id
 x134-20020a81a08c000000b0057a0e0b0f63mr272098ywg.7.1698155228147; Tue, 24 Oct
 2023 06:47:08 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:09 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-13-surenb@google.com>
Subject: [PATCH v2 12/39] lib: code tagging framework
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=JYPfnObL;       spf=pass
 (google.com: domain of 33mo3zqykcyexzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=33Mo3ZQYKCYExzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
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
index fa307f93fa2e..2acbef24e93e 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -962,6 +962,10 @@ config DEBUG_STACKOVERFLOW
 
 	  If in doubt, say "N".
 
+config CODE_TAGGING
+	bool
+	select KALLSYMS
+
 source "lib/Kconfig.kasan"
 source "lib/Kconfig.kfence"
 source "lib/Kconfig.kmsan"
diff --git a/lib/Makefile b/lib/Makefile
index 740109b6e2c8..b50212b5b999 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -233,6 +233,7 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) += \
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-13-surenb%40google.com.
