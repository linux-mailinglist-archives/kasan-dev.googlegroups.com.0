Return-Path: <kasan-dev+bncBC7OD3FKWUERB4ULXKMAMGQEE2GVGXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 70AA45A6F81
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:39 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id i1-20020a170902cf0100b001730caeec78sf8621401plg.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896178; cv=pass;
        d=google.com; s=arc-20160816;
        b=aFDQ6nsa1ZuuQbzHQ1HBJNXLREll5L8hkTzQjuH20+UmUJagk8gxi8Yj0gUa5zrSLf
         6fES8zeS519UDZwxV0Y48Wp2cZXRJPPuIkEK+9vpLqC5A8n9Jpc0jdpZ1jrrkGvXrCMa
         sf4y7KHTRb6duEQDm790up1UR5d3/e9Q/Tae4jU96Ea7mWP6oqg3p9XpC9RpKYsHrdLh
         GhXqlCUDos8X4Yhcg4j4w7KyY9ABFXkWNfNlVJf4cryuhMzzosnMdVaLMclQOTLuNCU4
         ZQhy4u2t8GACHoLVUpp8rLl+1GDm//VDp83UIuY0be0j1BwccdYK2vLVTKoClLR5IKdB
         BX0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=7y0L4HY0qEApIlNVukjFeldvGPfx/lusX/A6ee86sVc=;
        b=FQ8Kp7HRMUp8h/B/FAkBuA/NZh+jUzoqyqx+eb5pSfn7/samGMuIlS4bFx6+648QJX
         09DhxFTYqiH1w7a9rOIxpUQHDHUya+tpwtWnAUYNUmOpkcg9/AyhR/ctymXD9gDbgW4T
         LBw00DeJ8tIixylfWCv50Q4YPLAAuhSbPEA+rToDfNuN6ntlZ+xpToqAm20er8Z1i8Mb
         E3zhbgOj1iuqAk5XWFUTQQbYRGIfNEHGoCR7o2bw5YlC3mcDPLfrfPqTqVFdwBYhECDX
         Rh+/xxLMMoV8Wdry/SPXWmtXq6NcaFSbZakDTewKSW/SGGD81HzYO5AInh8zoS3JCWR2
         BMOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IB5sn3g8;
       spf=pass (google.com: domain of 38yuoywykcvygif2bz4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=38YUOYwYKCVYGIF2Bz4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=7y0L4HY0qEApIlNVukjFeldvGPfx/lusX/A6ee86sVc=;
        b=m1kYVuYOhmzw3T+TWWL0sxPXoGwrI3TArE2ONBNw/jwWTn33vZ+2CKGvYQvLOkTXJ3
         qeryGFZuizDXJgfoL7ESI+b0sSvljy28Bx67wdb+j/kHh6ANfek6JE3NVG3LJQWHsn2f
         KJJ+x8hmTKfz5FuScsZ9kaF5P+O0e9xXHKJZhc8fzi/lG2JjYmnSNUGfQj70qHWMOz0c
         5F2vnsECnMalDSOFBY/lWsY1v34nXK24/fckBHJE4hgyljsm9cJbtdGbDGJz5xXo/9fT
         gYOXKz1pbsdq+fe06f4blau/JorDMiYPT2kXsqYDVS22CS/cV7E76w8s+p92JUBzutSz
         0qUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=7y0L4HY0qEApIlNVukjFeldvGPfx/lusX/A6ee86sVc=;
        b=4M1oYHB+V0JFzeikawONTGu+9drBl9qqWRiDXxTbT30qV/Vj3tsdGZkpCCvS5w0Iee
         SIOkKaC0U+y4rKaftewTUNnZDXutDDAAxJx2zTELCtsTCQ2f8UMUBZ6zyp+eHl4W+xfg
         RjQapIWqknx6HLP5DVbB646OgKr9X1CweTVHz9tjkgyKygPF0tSAj0AMVXBbqf78J4ij
         C09w6oknVhXFlMOs1PnXju0Wk6bS21qsPT2S+uCVZlizIMKnvjp8kV/4P7juIWXYKQYq
         E4OxMuTr8DQBh1/jBioTh5DITcbSfVB1QX64PZvp/xQB+q9W1Y1PHtoI0pUZOVeLZSrz
         3klA==
X-Gm-Message-State: ACgBeo3WhPKUuNnVvQQm2d/dB/a3XdZlv0JRktVdesafQwCYwtrhSnBs
	6+1JkbPA1215QtP/lqOiFew=
X-Google-Smtp-Source: AA6agR52le9ekZ8K+EmbIQgqFCUrfu9Pm9GsSJZZlclI4ocpRMHlOmYWXATfoUXmP8Of6doOUnR8+g==
X-Received: by 2002:a63:174c:0:b0:42a:81ff:6913 with SMTP id 12-20020a63174c000000b0042a81ff6913mr19125884pgx.625.1661896178127;
        Tue, 30 Aug 2022 14:49:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:14b:b0:170:d739:8cc9 with SMTP id
 r11-20020a170903014b00b00170d7398cc9ls8248498plc.10.-pod-prod-gmail; Tue, 30
 Aug 2022 14:49:37 -0700 (PDT)
X-Received: by 2002:a17:903:124f:b0:171:4c36:a6bf with SMTP id u15-20020a170903124f00b001714c36a6bfmr22910971plh.0.1661896177423;
        Tue, 30 Aug 2022 14:49:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896177; cv=none;
        d=google.com; s=arc-20160816;
        b=VzxihT+JSjfgfG6AP978pgquKF7scB16BIAj3YYUWOPxNIyh+PaByvJrgN5vl3lOer
         AU4vz1x05vrECYLvrgadoMO7Fv/4etTQHEO8oe0GW3i0jRPpva1adubIUj9TD5yJOeF4
         cmk64p21FDm99IQjj3izG+vTqjkHql3DkQ83DJ+z3nSShw0BBFoDB7JBInBhYT7T95mP
         5HhC40P+PySURlpVkucZfURTzYYrc7wEXvsQKdvhEH+DtV2FN4MGOwjp6YYfT4PyoneR
         Gc4JxjOw4zc/Ib9q9wPo8/5fUBnM1AiMlldVbm01iSZOAfXpTVCUhALUMHPxEa06Pkxy
         739Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=kcUwO49ZlU6bl/Tm+t4qMFM3AvAt3rlv3WDq12yXCn8=;
        b=k2IqhiCGzr99W2rZKYvunwFII3RJwAGT042dNLegvD1bkkYboBf8Jj0ZpB7SV+3AjS
         PuqtBxFNyuS0suhXq/yXZiK+g2Ykw8+asn3/cSD6HvuXVEpPZiA+j7I5Oi2yh7IliNsb
         iSfH5GPakD4Gl32wLiEJuBcEYgNq4XmBHsGhXBrASDV3hdNdojMkweFhXvKO5AM2c7xL
         9iEXdsOl0FVQBjj6qcmpuvumapUXIN9CvxSwqGlhWr2AUoU2PZq+AAeN7AcbSH8zdjFn
         U5Ej4y6lcLYtMHboq6Ndy09RrSt+k82HzqAGb/u27A+8eFcz/X15ZT5jE6u2PcvUWQlT
         dSOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IB5sn3g8;
       spf=pass (google.com: domain of 38yuoywykcvygif2bz4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=38YUOYwYKCVYGIF2Bz4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id ot13-20020a17090b3b4d00b001fe0d661525si4785pjb.0.2022.08.30.14.49.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38yuoywykcvygif2bz4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-335ff2ef600so189309657b3.18
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:37 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a5b:18d:0:b0:695:a9d7:44b5 with SMTP id
 r13-20020a5b018d000000b00695a9d744b5mr13051126ybl.549.1661896177035; Tue, 30
 Aug 2022 14:49:37 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:48:54 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-6-surenb@google.com>
Subject: [RFC PATCH 05/30] lib: code tagging framework
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
 header.i=@google.com header.s=20210112 header.b=IB5sn3g8;       spf=pass
 (google.com: domain of 38yuoywykcvygif2bz4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=38YUOYwYKCVYGIF2Bz4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--surenb.bounces.google.com;
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
index bcbe60d6c80c..22bc1eff7f8f 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -969,6 +969,10 @@ config DEBUG_STACKOVERFLOW
 
 	  If in doubt, say "N".
 
+config CODE_TAGGING
+	bool
+	select KALLSYMS
+
 source "lib/Kconfig.kasan"
 source "lib/Kconfig.kfence"
 
diff --git a/lib/Makefile b/lib/Makefile
index cc7762748708..574d7716e640 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -227,6 +227,7 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) += \
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-6-surenb%40google.com.
