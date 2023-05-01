Return-Path: <kasan-dev+bncBC7OD3FKWUERBC66X6RAMGQENE4D4SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C6B86F33CE
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:40 +0200 (CEST)
Received: by mail-ua1-x940.google.com with SMTP id a1e0cc1a2514c-7756f4b4a8esf562034241.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960139; cv=pass;
        d=google.com; s=arc-20160816;
        b=WzS54Rws9wLOJJU2VwAOiMf/ztga5kLwUs9mKPtQXMkCE+XXjUHRtb8KE3NPZyV0Hg
         Er9732mOv/zKEIqxvxrg8y6Uojg95TXQWj4GIiwo4iWU18luzU+NHH7TylpG0XL2InBc
         6u7mnJdsNc3pFV3PiRv8pZhJdH8nxeGSXzhfstTXZsQL2ltbEI83HzShPOXZfwoOy3Eh
         wb4ijWFndN/RGsDBNyY6mPxvRR5BYNMSk2MDl7d5bC31TFetvdHid0CcBVIb1gTagGMY
         1VPAJvlh8EllfrHvOGXPYO+ijfwsmOEfcjZNEMevliupjWaIHpMfE71IifYnGh+g+lbT
         F5Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Y2ZUv8AMDBDyOU2WEhIIvd1rf5/c9z2YSFlZVpg6dB0=;
        b=fXYN2/qJJMUA/OpX953z60tN5ZHnQK/5NKnel5T51ml4r6OiHYvKmlzTrpteqHg6cF
         pwQ9q9DNxe9Pnbr4BE3ABJQNXKEnYeXbRsiWC21GhbZef/4/mM0q9YmE6JmMekeNVU48
         giC3l7f6o1CrPrd8oh6cKthCrRHxB0Qhveam0rQgQuHgpetErrXWKEU3SpZtLaLkRECn
         GfzYZ9cHxOkV6ZskbAX3+UcEPNinPogq0rXBcrw9+F1rexVSuvxUwnf6jgZpctdACEoe
         FJYTMq0/yGPvj8euGuGFlQOLL8CqlCnkpVzN5pNYvj0s3bA44Xohxx2DMd7qWV5YgJvJ
         XJoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=1K0fFEAK;
       spf=pass (google.com: domain of 3cu9pzaykcvebdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Cu9PZAYKCVEBDAx6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960139; x=1685552139;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Y2ZUv8AMDBDyOU2WEhIIvd1rf5/c9z2YSFlZVpg6dB0=;
        b=UV0iEoofxv1kyZxpJTNBtZtzpMsLmfNUNVr/zIUo1JZDcpOMw6cEjhPc0PBwG0uFpf
         3TZ1U2SYKdYnpDQn0W51jvOLtXHhOQMB4VEYtQ+JZ1e8MjmNuqfyXeqlS/pSncpmAoCe
         wI2OvlVvS50uRV7S7cGjBkezu4zoH3hDVH3+o0ULUZ5hsC0b1Ww2T/YYyywG/2fVl02O
         gHwFcub21P+Uzo593Xxahap1m9G6ugo8LoiphvZjQPOcPv4TG4e0cr1puT9izXaAut+1
         DnEMWHAgzoxc3wWRiCIlPh/BHxmiUZUxYPLNsDAQnXzRm7yzBWwPGmTXrwNoKh2vuVJz
         UA5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960139; x=1685552139;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Y2ZUv8AMDBDyOU2WEhIIvd1rf5/c9z2YSFlZVpg6dB0=;
        b=Z2IKT2ETMKuFy5GtFEYDabxadZRPF/W0K2gJpHPCPF4fNp7/JIlPkfcHQslb6P4mtl
         QBZPFycEEbW2ncIe9zcRCcepcDadcHypB8yTSZQAviFx3m/IWAyOEQgPjUPMTHZwL8wG
         bEbqYbp2jauSrtkdHpCkiAvvNaHWsYE4cMBwxjXL1aNQdqKF9i7H4Jh4qt3aCQxl80+s
         6NvFzlDYJyNfGB3q86Y4nFv1Hyro8orrb6mPJaD6xd9cNpRITQFJ1nOh0jIE77AWOgCm
         TTnHpMiSMl48UElu3Wn/jUpaSdSvYRdemlHVJU5Sqg8RnBU6XUoMUWAaGcL3ICgN0k+5
         ccNw==
X-Gm-Message-State: AC+VfDwFpPLu7pUgB11koeNQhYtQ225Ird1w7hC0OPaQ6Qa7EXM//XW9
	sDGW6gkbOo1s6wK7X5LlSL4=
X-Google-Smtp-Source: ACHHUZ6LWUxPMqd0YtCeK5JNQlYsaJx9YDXb+08W1gcExKXUeg8CMEIOLLBK8pSsz59KSWFw6sLUCA==
X-Received: by 2002:ab0:4a9c:0:b0:755:9b3:fef8 with SMTP id s28-20020ab04a9c000000b0075509b3fef8mr6236282uae.2.1682960139320;
        Mon, 01 May 2023 09:55:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:32d6:b0:41f:41ea:30ac with SMTP id
 o22-20020a05610232d600b0041f41ea30acls2751027vss.5.-pod-prod-gmail; Mon, 01
 May 2023 09:55:38 -0700 (PDT)
X-Received: by 2002:a67:ead6:0:b0:42f:f725:58b4 with SMTP id s22-20020a67ead6000000b0042ff72558b4mr4955827vso.4.1682960138655;
        Mon, 01 May 2023 09:55:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960138; cv=none;
        d=google.com; s=arc-20160816;
        b=ibf0Lcz38m9lgKojVkOf1W8tdtiHqx08yA9L9DUP+I/ihChEDcIhq8BKsPZ1EZFj+A
         d9fv/57OGlxaXutKRIpMa6S9nDPDuSeg0qUkI1QZbWDwAhq7B33wxX8ndYI8QLctpQfX
         eKZx+kzQcti6xiqZoGnWffXZjXddz4lLa+KTabDpfxkxL9kVixl7je4USpGYHwx5sGxP
         e82EPraP6fNmcgTj4eyfcmAxYez9fl6tcA5jpxae7IS2Lnt/+F+U9O2jBKc3GvfZall/
         J5AsGOvEklAlCeGNA5xa80oQVvHLw1JZ+H3jG40HGV/q6qvh3wytr3vrU+5+IxX562Y2
         hvnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=esQmYNSNwAFEEht8P+eJjy3027KPfc8B0JiLBlMM/Bo=;
        b=hIDB8ONTxe0CokAz1R0lWNb/5fdbE96U9OgpzmwbQNpXydLX3TlAfkSkGwi7ph1San
         IddlylwdaTulLbV82XyVyE3pnEW8E+BzVlifALeFMc6/3F1kHvePWH3HZfUk5e/1gZ/A
         BmHNpceXp5bEzcDjJKpKqccaHe6MX+5hxsFnka1AkFGlOMZCfgtOBckNKlFZXvy4vXWo
         Vr0tPs37bcDvlzugZNSUdv86NrWkeP6MOBUahAa9sZUqXAwCXVeKJGGsQnGMA60tphuX
         BDssPFC8o1KqEI6YDAWcndcumxPr6tdCPAPtUEJjBzTT1d2caCBNuD9NWuyQwpeYaBKm
         JAag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=1K0fFEAK;
       spf=pass (google.com: domain of 3cu9pzaykcvebdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Cu9PZAYKCVEBDAx6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id az40-20020a05613003a800b0077d31fab956si112449uab.1.2023.05.01.09.55.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cu9pzaykcvebdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a77926afbso5336381276.3
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:38 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:c00b:0:b0:b99:4887:c736 with SMTP id
 c11-20020a25c00b000000b00b994887c736mr8510714ybf.3.1682960138280; Mon, 01 May
 2023 09:55:38 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:23 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-14-surenb@google.com>
Subject: [PATCH 13/40] lib: code tagging framework
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
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=1K0fFEAK;       spf=pass
 (google.com: domain of 3cu9pzaykcvebdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Cu9PZAYKCVEBDAx6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--surenb.bounces.google.com;
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
index ce51d4dc6803..5078da7d3ffb 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -957,6 +957,10 @@ config DEBUG_STACKOVERFLOW
 
 	  If in doubt, say "N".
 
+config CODE_TAGGING
+	bool
+	select KALLSYMS
+
 source "lib/Kconfig.kasan"
 source "lib/Kconfig.kfence"
 source "lib/Kconfig.kmsan"
diff --git a/lib/Makefile b/lib/Makefile
index 293a0858a3f8..28d70ecf2976 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -228,6 +228,7 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) += \
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
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-14-surenb%40google.com.
