Return-Path: <kasan-dev+bncBC7OD3FKWUERBTOE6GXQMGQEPWBYITQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 91AC3885DA7
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:34 +0100 (CET)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-60cd073522csf21746557b3.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039053; cv=pass;
        d=google.com; s=arc-20160816;
        b=V1hgcnhy4Awo1Jm2S14E4+alBhkWsQI5Lgz10NexCRaL39F2HkpnhDdMS+AFBQ5agU
         8+UXMXqyLRhpmvy4ugD4bMRitr9OYA/1hsFc6zIf58US5YC2sGzp8a2kLCgklGoq986s
         +EKQQ95FYhQZ7xTbEIlHqIbHXwa2CW59hpZpRfPRT51f1EUBLh2joy1HwTvvlwgfjI7d
         cwHkbY/SC9wIjajb7hMK9AzIcMNE4X97hJYDu6dVOr7GxgmybFJX60JYytLQ5GCTD6cf
         me+5WQ3+ZuNxbDde1AQaIf1P9SYf3al3+Txo/JZyYmUBDh+Y4g6ibX3oAz2rcwa/vHfe
         BY5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=FZaZGi6xjwc5k1CQ6m+fCPDESqDwPwGE9uhpQ2045wI=;
        fh=5WNtRmTWG6buAkawfhGolLly3ZQQZM4QtucGafM1W3U=;
        b=MbRehWRZZtxjScOrpe/GhTsk5GQRTGj2VRan3gdgHxMQes89ig/pozW6Vu3asEFZf1
         OY8h/drs8+v2n7ITTPEcdKgJ0RmkQE+zQCB6a/Vf7MmHf8pqHJ8Z9h1cuNLKtVJdYJFB
         8BnZYw9yOqCznbHBnwwXo1Rd+5DnA2DvpYjvFmlgwiD2cgUdVVg4OeBDSowQ8nFZ2Vnr
         h71wTurv8/XeW4rMne2nolf+KQ7kS918yCgRHE1NOkMsJUBQKw6LcRJYhUuXgMcAHrXn
         JrhSlD5PkZfvg1dw20GQy26ge5kybGtJApSX4ggEmiP3A19T9V1I8Hp3ZXkPoiqNNHMt
         +0Ww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=25YeLcyE;
       spf=pass (google.com: domain of 3s2l8zqykctgmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3S2L8ZQYKCTgmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039053; x=1711643853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=FZaZGi6xjwc5k1CQ6m+fCPDESqDwPwGE9uhpQ2045wI=;
        b=l3zeXmoyGM09QjP05tjPXwvndE4tSa1yQdOJ/19PO1vX5XkT9dMF47FuWRQZqtXlWk
         qJz6dbmx0D1cgKl8oIpr/XMnvXX4SPsIPhTWnfUsibw14mQvBZFbiBuL32k3Nl7mKBKm
         yjU54U4zviqpPhE3yEW2ScFpDS7oeFRfYunth4i9tNe7thoNkn5IgfXNAIWiV3tIP39A
         yYpKCnWlI1r8U8VAELpasXG8BGcQTygMnWzexa1CmdS7HgAZJWqQM4J42E/yTxI8RIPW
         TX9/kc8qVefo/0NxKyLO/cA1Jwm0Xm4KLFlLg/PMXgfn0CenmXMea5PBq0Lnc2i9ss3O
         t2jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039053; x=1711643853;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FZaZGi6xjwc5k1CQ6m+fCPDESqDwPwGE9uhpQ2045wI=;
        b=RBD9u27knHhO7uhGLSzS6Fuben7wMbMz3Cj3ZCU5tdDYtzhuQU8Za12kzPhnUlu8uI
         Lf1UCfuFt/uABHn4HYOsq5ngeBxvH6KD3ZjDpDzFjFdfjGji0l782Hc9srTWdVqIqD0k
         NbLW5blBdiQIQyjWJx1nW6EWCw3F8ZB5vSn+M5HWkK/nAW5eboKNQ+SnZVl2V44oQlm+
         NsJI5E+TPTPcPOj6hs3pJnHvTvG81gcjuvAP3K1Ta9wImdE3QJLzJtLumr8Yb4ys80Jj
         tpxjmEsnnGRv69TfwjdexRKvjT2JAP/NORYiaLgoDKb9V3pEVhRupBmnkO4at961yeHT
         4mFw==
X-Forwarded-Encrypted: i=2; AJvYcCXNPYOI1klmv+EibT2lq4azgQ5/x206Viu92pHDskCyWEU+jW8X22IW2viXXp1o3C/JmWFFJ7SnqXTI+qvIk3oaUC+twk5YQg==
X-Gm-Message-State: AOJu0YwR+OGXeSFGwMeI70+7FTUuYdlA/sOa2YX0w7aSuF3yL0iHKrRZ
	/jQ+rcIyn8k6CNDzwNhDxMJjb8o3tPpc+Mdln62FFhUOQWDzPcpE
X-Google-Smtp-Source: AGHT+IEy/VKwivj6WYQMWr7EUcsNFCDMZWgKJ6ODnpqyJuqvI6KZMIAI2ZxPl194lWjZPRKtguqq8Q==
X-Received: by 2002:a25:ced1:0:b0:dc6:b617:a28c with SMTP id x200-20020a25ced1000000b00dc6b617a28cmr9403900ybe.5.1711039053275;
        Thu, 21 Mar 2024 09:37:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:df97:0:b0:dcb:bfe0:81b8 with SMTP id w145-20020a25df97000000b00dcbbfe081b8ls1016634ybg.0.-pod-prod-09-us;
 Thu, 21 Mar 2024 09:37:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLCeqRcuZN49lUUdED0XEpxhbtCDMtQugBKxTJKyk05t+DArRtY8I21N3X3PbmQoLi8LN8MnZoRFXogIRlC+eGC8uSF01au1W5aQ==
X-Received: by 2002:a05:6902:1b13:b0:dcc:f8e5:c8c8 with SMTP id eh19-20020a0569021b1300b00dccf8e5c8c8mr9900029ybb.45.1711039052096;
        Thu, 21 Mar 2024 09:37:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039052; cv=none;
        d=google.com; s=arc-20160816;
        b=wvcT+NOU+HDB+FmH1CTBcBvpAMUtHlo6Jushq3Bp9CBRI9pxycoQwsa7CHapo39L2k
         lmf+1TIKfnfnVq7/vJnQr5tbWACFihOqPlag874xNggUvtqMe8rTalWsinGqKw+F8YiW
         NVXlhYYU0uqor83oa/8HY952bTHa7TmINJRVselwYiPK7ef7Bwr6mXlZdq5jzG15BYnj
         it2Q4+bH/e03lXPcKrw4Ws7jKJG8FdoRsJBfV1AI6NyAogSWJPxx/FfRZJtNE+Uf7tIy
         4QpEkwcx8CjPvo8Xu7SnqGsdyo0s3bzvFqgG3Sf+7yFGRzzqz5IggnXnS9P23zfEsISa
         JF+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hrfC4K8F/Q+T2mI4qsQQV2fR1wUsQY/g8GL2B+37hNg=;
        fh=3gmEVVMiXi2issI+mfCmUTuts/Hv4Ass5Ac0hf6TXtQ=;
        b=QXzXc76DcBifVLwV/KWVedZkRBE5L5LAbrMJti0G8rZ1wmEL0nLTQJyxmLcDe9TmyP
         hauL7PoLSa6b1pvSl/Enz/J1BiZG4TMzpL7lXqeEjn1hkhFmS82XvfclwJiWkihPyzqA
         CNS1A7D6BmPjNYbgqc9ecJUKHnuOghcy+YyrHOdN6M6kBqmGY7xJ3jfQPGi6U7D9D2JJ
         mkCaF/dHo/jcZNJNaJdshuFigdPkfmp/waxoGQ3M1Yhrs+p3eVJEayPwyeuyGSrWt07l
         2SVIpX50O4LIyui9f9yKrufr0fIKHjqKr4gc3hL9VOXmUZicsjtgo/9+NbtIqj+SwvI8
         zk9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=25YeLcyE;
       spf=pass (google.com: domain of 3s2l8zqykctgmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3S2L8ZQYKCTgmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id v13-20020a25ab8d000000b00dcc3d9efcb7si1723732ybi.3.2024.03.21.09.37.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3s2l8zqykctgmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60a54004e9fso21449657b3.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUq6+PaGJycebBXKtIliIbNZQYoNOa6JLMHMBLUfhADVBFtb9fdwCWqJbUh+jD9k6q2sj+S59hDX1+CpmrHwPoBCwsBhyUaCD0ElQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a0d:ca91:0:b0:610:fc58:5b83 with SMTP id
 m139-20020a0dca91000000b00610fc585b83mr1060972ywd.8.1711039051683; Thu, 21
 Mar 2024 09:37:31 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:32 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-11-surenb@google.com>
Subject: [PATCH v6 10/37] lib: code tagging framework
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
	glider@google.com, elver@google.com, dvyukov@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=25YeLcyE;       spf=pass
 (google.com: domain of 3s2l8zqykctgmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3S2L8ZQYKCTgmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
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
index 733ee2ac0138..d2dbdd45fd9a 100644
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
index ffc6b2341b45..910335da8f13 100644
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-11-surenb%40google.com.
