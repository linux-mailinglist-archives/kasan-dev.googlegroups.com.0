Return-Path: <kasan-dev+bncBC7OD3FKWUERBYND3GXAMGQEFTDFKXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BCF485E779
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:23 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-dcc0bcf9256sf7888753276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544482; cv=pass;
        d=google.com; s=arc-20160816;
        b=I5vwnF0rcf+741FfG6YUEYAApdfbuqavtl+96g70vfwZW5kEIwwgUvqtBsBDfH9gUY
         BsS9DAY88w5OLnYKO3UXJt4teoow+sfJ+qbgvrssNtFCA528ymA94jL7Zrhc1VAJCiey
         TR6ivGU4DUb3gMXzxzZGHxcaor5hb0aQqHRRKx9lufgkMjOtE8xoga/KSuO2BTtX0YXB
         XA/rxK5Ey9NdvXTnRpoPasF8SsA7Vd2vtaL8hxRYPsRw/vDThBAPjKDrxcFD7Sbs0Cg2
         trM/M2xeXQ9zOEE3CDQxazRoK0wmb2BD9oCua4WdowfVnggKCWoc6Vl97UeauN++CARe
         DsOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=laEAXYPLs1O7OFKPzxOPtEor4JiBfULE2svNX4PmNzY=;
        fh=aAJbXYe33iiTcXMjXvrXVnFVtqK4XTVZiTh+8jg9fzw=;
        b=plfBZ1NYHET1eyDp3NYipGPu8JLM9hxcO8izkZ7FNq/Li3NDTfiMMxeHXfeqaTg9bT
         0R7d4GVCyovzupJZVFF1IpIBA0wd8llCdkpM3Pw1iJdCUyz8l+DQdeKvaI97t2He7cF/
         HrHkYlHdBawinv12QZVQ8j4hx6V318bkEVeBD6Rqw4NN3R7E48B3rVdWNdImP2BFAzVB
         b+kKg8jgQ1ak7enf5mEImaAueV7Oa7F+AJ1CJDVcmq/IvOw6E7dFcp7nir3u4/+xJBlm
         JpYal6S0Il35vKaCxfJscRq6ucpuBmLOOrMmlzJFncuDr4dadrTTUBx6FoesYcdsJU/u
         Ghlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nBfvRDoz;
       spf=pass (google.com: domain of 34fhwzqykcrmbdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=34FHWZQYKCRMBDAx6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544482; x=1709149282; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=laEAXYPLs1O7OFKPzxOPtEor4JiBfULE2svNX4PmNzY=;
        b=Ki+WSUngOdlnHikxasBNvp9ajnyr+5P2hPZZXrnruzFQYQvzQoWbBt9nJtf1aWT/4i
         wfEDqaLTeb/pXjkOUvn0oxETFu0vDYtGOOOdcXRK71oikZ4Z0ra71s68bopf4etTxP2b
         +DEJ8rL5drqeQDdhiXvOqG9/qnF4ucccaWQ+iTbfnJPHeGAvRFDwKKHbwxkLqTqW6w3b
         oYA3tQlcMb8y9Fd0iQiyPfBemSpUSCeh9nNWBli2Zumh8oe5081MtoeTQYPmg5X7VHYl
         aGOHlm1xLt/Z8927a6CEHK9CBV3DeSSVFYyHH3a8EZ/40WpY4g/vq9/b7qGq2ePHu8UG
         CK3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544482; x=1709149282;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=laEAXYPLs1O7OFKPzxOPtEor4JiBfULE2svNX4PmNzY=;
        b=q3nYTmsOTvkLWb9b0ON+FDN1sqprNFn+kFYBFWpbxhKVICMULJVvgppn6jg72kO5Wj
         ldVvJw6NpMsieUupkiEFTKDGphaMkVQ6/b0rIBN1J49NspHhw/pRkQXEQRvOc6knnvGN
         +aFQhKPgfuTI2ubokmyQ/cLkdfx7YpqTX8ozhRbmRavHi2lv64kZkIsLwBd/694C37P6
         wbY85D03CBfdIcNNcfkbWjCjFKa8mxAExeD6WtZfMjGzf5kh3t8+v506hnK3JOLLyvQq
         uIYv8/7ii17tL7rvRKuSbpEnFd2CQEOs1MxKiwahDN40xfuBko2fqUXnlLC9vWxS3NeF
         ZfGQ==
X-Forwarded-Encrypted: i=2; AJvYcCUZsR+YrGGxhuUoMBJ57Xd4cLvqClA5y/tajzKyF2JeqS6CMirS1OgEjR7D9z8jz8IHR+XbJTD7Wlvrqu+6qpDMQCViEn+rkQ==
X-Gm-Message-State: AOJu0YwYHMjSzIjqnKY2z7hiyD1n9i5BMe41igVdvwb5E6HFScZScPqH
	TLChPLp36DUtkNr/rdlgV5Bp3O5Twtdc38emuFIQugdfnurWUCaN
X-Google-Smtp-Source: AGHT+IHmeTzk3xRb7Sdsw13yIEE6cUc6Da4JY5wNDzX6NWSyq87sZ7URYsECxwsuRRy7iRC+kS/5/w==
X-Received: by 2002:a5b:b41:0:b0:dcc:f8e5:c8d4 with SMTP id b1-20020a5b0b41000000b00dccf8e5c8d4mr298683ybr.32.1708544482051;
        Wed, 21 Feb 2024 11:41:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:74ce:0:b0:dcd:202d:6bd6 with SMTP id p197-20020a2574ce000000b00dcd202d6bd6ls3351696ybc.1.-pod-prod-03-us;
 Wed, 21 Feb 2024 11:41:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU8O0P74LRHmR7ADB453SmD0JJoXeSfwTU1wRCe+usIe9TZ5yD3a12n7GODI+CVvTpAL31bkSrbUOQZYOKLy4uR4hICMAkFJ+Udgg==
X-Received: by 2002:a81:5f04:0:b0:5df:4993:4371 with SMTP id t4-20020a815f04000000b005df49934371mr17695488ywb.39.1708544481055;
        Wed, 21 Feb 2024 11:41:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544481; cv=none;
        d=google.com; s=arc-20160816;
        b=RReVpyQ9Cn4ZzWI62gd9cC8XkAQ3RbMcrH0gALH7dI+hsfpqsB2J1NGFc14199WWtS
         S/Ak8hhGVLTZvR/6JVYc3+REC1V9pDpeLS2BsjZKd04xJDPj83ucAy/xhFR3Y9KzDGsX
         w0CTagGQdgryp8E/0lmsP0ZKpxuC2U0hW1yk4IQIW6GXHEGIKMtOVP1lBFJib3uqdDvp
         s1ERWSOIzu4amxPI1BHj+lXGRiCa1fNOBXY3L6YhbSljavtm8pTtYrgxlGPGDxFyzw74
         zoquxra9xkt2a6Z8+hphR8w8j4Rxq6To1d0YRaygoSL6KR7cMCZkGxI0oFz018a/hsc6
         Jq2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=2W4P7NFQiFc4UeX84KC+r4Xo/VJXM+I42piR5xvvbG0=;
        fh=vFoaxoDSfXvQM3Sey0SFvddjmvoSwitkC9FSArGpzAY=;
        b=D+s2RyvkbQA7F1nUDgg4aLZ7RdJ2e6zwda+1kOtFraERyJaUpU8X6CElA8DqkKfXoS
         Jyw28FRg5j/q8fnBdULMqnuTzZ1sLCHnkdIDYH9tnKlmjESpu75l6lZqPPFZUuzLQa+l
         /9zA7hWibR1QNqWGu2T9yXubYac0r8uhAkb4qOwcJRSpmHch5F4V+3PN7qwXJxEhhJnv
         XONLkOWspx9J6Oux99NaImQPRryxHuP6zekBwxGCN7vRblgoTjrK4veIuOK9Q4hQzYOF
         JEJ24+eFGUrESRmZgKvQeaLWPpt0nuC9K7fAqFOIncqz4s+AWb5vYE8fp9UXYtZ9Fq2N
         nrxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nBfvRDoz;
       spf=pass (google.com: domain of 34fhwzqykcrmbdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=34FHWZQYKCRMBDAx6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id l23-20020a81ad57000000b006079da1b99asi1311944ywk.4.2024.02.21.11.41.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 34fhwzqykcrmbdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6087e575573so22028017b3.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWiup2ogvhYLnrWwPh51/CxaANkDvZVScmhSZFYls+sOmzmaoHSAcf4jkcZF7WbFtDM+XaT2Xx+tqWxn+ELt4GtZZnabH8csnG4bA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:6902:1209:b0:dcc:c57c:8873 with SMTP id
 s9-20020a056902120900b00dccc57c8873mr68426ybu.9.1708544480467; Wed, 21 Feb
 2024 11:41:20 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:24 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-12-surenb@google.com>
Subject: [PATCH v4 11/36] lib: code tagging framework
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
 header.i=@google.com header.s=20230601 header.b=nBfvRDoz;       spf=pass
 (google.com: domain of 34fhwzqykcrmbdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=34FHWZQYKCRMBDAx6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--surenb.bounces.google.com;
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
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-12-surenb%40google.com.
