Return-Path: <kasan-dev+bncBC7OD3FKWUERBGMMXKMAMGQED6ZLTJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id C06F15A6FA4
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:23 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id w187-20020a1fadc4000000b0037ceefea1c7sf2062143vke.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896218; cv=pass;
        d=google.com; s=arc-20160816;
        b=nqplQbMherzjEfvqmWxuRtbS/I27UMvrIz4ic0F5sw6GPh/RiyuAjKyvlbEpopKO7Z
         LTYH3W8IL60rG/c7y7Z9kbeX+241dTXyYjztL8gRb5IsysZ2CshWCDBxjVPRHC9pO0oU
         UIPJgpaJ0YIeXGKBLpMQtgK+e33J6b9tcuzfGhP0LAEh6AmatFXHPHaLv8zgS5BvVq1W
         VmLbzK3rag9fItkzCYsuWFzEp/i0b6lZ93HRwAtq4wa+JzXCioVDUQ+bzUG+cDafOQ0z
         1M9Twkape+LLnIYc79F6r6NPm2kL2zfoubmEPs1btYX2Jvhi86GLZPXM6ynDxk8o3gFY
         E6xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=C3K6bVpIQu6ryjOrpXUPUKKiV2pFZVUZnY6nBkb1uro=;
        b=QRAPSu612nYu4dAI7dDlJ3eKtCyWB9pa2b82MQgcEljiFhQ6cPhsSTAKZJQbh9bjhn
         0DHEB7PcXUfQG4ATTU0rCEq7jhUR6uLns5iFk6E+zIS9w63PyLQXxKNGIc86hfooceCO
         IYYzWEUx+k9ANriBcrbwfEkgGW/4GsGFBSPKYBZ8/AhadBl2lOotRhAADN09wOXHNFXR
         rY24gfwXPq6sz6gtgx/ZELHELind0GyO0utibLdVvFfnCfnImY4Ilg/P9wDzFXapD8b6
         UxJj0CpF5LKQjly5eAsunVvRnKk0iHv2q9fVwzeugHsUEtuibNtr/S2fwPUIv1XsY27n
         U0yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VhiQWzTM;
       spf=pass (google.com: domain of 3giyoywykcx0tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3GIYOYwYKCX0tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=C3K6bVpIQu6ryjOrpXUPUKKiV2pFZVUZnY6nBkb1uro=;
        b=d7Dcpi7HSLJ6nIzCgzy4q4/GozSldgFWUc2NltWhIQiNP3KuXMIoUKUg3MwBzz/Yig
         8Qgy6HTpHmUxQXg1kVzwHhV0WdOsTVJdwPDhFjGNNX2otaq0eV1ZtHnBFJCe9ByxvBpP
         neEIgW14ZZTYTu4d7odJkHuBx/RhRhzG0IRl/H9VDLXpF8OlK2mO9EHiRw1yZB4noavY
         VW3YL2e53+a2K/4vCfmQ11Iv07aqieYU2fXkXDbcfMfb+F3JPWbOW+2MRWf8I8l/ob0y
         YL7Sa3NEd/WjJZ9MVFQxS3jsgiH3jai2tSbIQwS+LQbYMmOfdm2mKccKgpwEUp8zKVEI
         UYyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=C3K6bVpIQu6ryjOrpXUPUKKiV2pFZVUZnY6nBkb1uro=;
        b=UrjaWb+SL0cxWvQjKreUy7tEFfm41e3xF7nKNwC6ahEHue15VHr0QmYBVM4vV6snjY
         lJ1CcIgfURqmDf5CKzMAtNgqD6nAJQCMWWHLUZlieY8OLlKaa8u+eqrBr0Ph2nGpt2ko
         V5XMN9V4Y+BBhHbvGmbBYbe26SMu3ZL3y4O7QXuYiqbYAEbJeW88MFmbZwj1o8/q2+5S
         YAjYT8aSgyk8yNKfFL3DjEX0rcQyqUg8q3sQJldFcipPAqlI2wkmCCnjxCOdG1QkQQWB
         E+VDV3Id3A3ysKHmGDNjQ5uOaM7GRJf9qDqY82in1HbZjv57BUV62zLM9zNVPURdxf4L
         0LyQ==
X-Gm-Message-State: ACgBeo1NrAJAax7qghH9470Gi62YOX+XzlecgoWuZnWNxevg5bAKe68m
	2z0Bze6AR/O11fRBsZirj2o=
X-Google-Smtp-Source: AA6agR4+X3MVr6vBsyxLaA2hGuJD7Ei5BnVTeV/rLhG3kOcYg06te90gLRG2OBO63/Vco6es/jVq1g==
X-Received: by 2002:a05:6102:159f:b0:38a:dce8:fd06 with SMTP id g31-20020a056102159f00b0038adce8fd06mr6083219vsv.2.1661896217753;
        Tue, 30 Aug 2022 14:50:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:912:b0:390:7a36:3f with SMTP id x18-20020a056102091200b003907a36003fls1741266vsh.9.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:50:17 -0700 (PDT)
X-Received: by 2002:a67:d19a:0:b0:388:aa13:75d8 with SMTP id w26-20020a67d19a000000b00388aa1375d8mr5945375vsi.12.1661896217205;
        Tue, 30 Aug 2022 14:50:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896217; cv=none;
        d=google.com; s=arc-20160816;
        b=hiiB/Lz1qBDxXMQz3ALowDhoUbvbrf6h+0OjoeIyWRQqGqVD+96Unqe/L0roZg6dI4
         y1D5IUQJnYhFnBx/g9zQTZC7752oHMgC+QyqIl61L3LKOOqht/BtXS64Pr+NURivFTxw
         ZgEAoh/xphnu3QlTAcYZhBXs6TMGWWfGWrLDokVi8VGyAdlSv9CWEVXnftXQWlHM+oHX
         enMNQBJSI3TFkhjoyxDKmx1EQykmgdaIWZYNiU7p+s9aS2hDzWT5h4xU3O9pOW437WtQ
         VEoeVKVwfpvfdds4RsgG/5U8+X+CujJPX55RDaqVmvNmd5N7Nt8ZV5/2LUevXTZo6Pme
         qJ+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=k1RBq3yq4U5V/3OJ4fp4kBxfnryZ2+wdIlpTdmkxoTI=;
        b=E3YMBSxcEW0kyFQWPzSObG9oIPTmBa2ubtLok5LH8mHN9XGiIqOyiSFo4xtnLKINea
         4VU6VXini2Or5LjZ90N1QocklMNFs6qgjmzRgfwuDC4DlupHvKNhcCrnygEY4CPWWomg
         R3b4c0MbhU9kplkc0Livp3U5gczNs8MLNds7jdwFjbQ9SFjrFDR3QmTPBNZsQ92HBJqk
         mEhMenAR4UjfvN3j9JeRqpBvpHp3i6vkydqJOS8u50wtH4e9kDNNCCOFoMUWYC40ZUKb
         tiEK0TYFtTzUsweSYWfwgtFliYuMUveZyXeV8DxBcCydmuYGjNLwrF4PHfgkznxqvafc
         DMVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VhiQWzTM;
       spf=pass (google.com: domain of 3giyoywykcx0tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3GIYOYwYKCX0tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id w126-20020a1f9484000000b003760f8bf2a0si455962vkd.2.2022.08.30.14.50.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3giyoywykcx0tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-337ed9110c2so189633387b3.15
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:17 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:ef45:0:b0:696:45b0:7b5d with SMTP id
 w5-20020a25ef45000000b0069645b07b5dmr12075882ybm.368.1661896216803; Tue, 30
 Aug 2022 14:50:16 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:09 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-21-surenb@google.com>
Subject: [RFC PATCH 20/30] lib: introduce support for storing code tag context
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
 header.i=@google.com header.s=20210112 header.b=VhiQWzTM;       spf=pass
 (google.com: domain of 3giyoywykcx0tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3GIYOYwYKCX0tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
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

Add support for code tag context capture when registering a new code tag
type. When context capture for a specific code tag is enabled,
codetag_ref will point to a codetag_ctx object which can be attached
to an application-specific object storing code invocation context.
codetag_ctx has a pointer to its codetag_with_ctx object with embedded
codetag object in it. All context objects of the same code tag are placed
into codetag_with_ctx.ctx_head linked list. codetag.flag is used to
indicate when a context capture for the associated code tag is
initialized and enabled.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/codetag.h     |  50 +++++++++++++-
 include/linux/codetag_ctx.h |  48 +++++++++++++
 lib/codetag.c               | 134 ++++++++++++++++++++++++++++++++++++
 3 files changed, 231 insertions(+), 1 deletion(-)
 create mode 100644 include/linux/codetag_ctx.h

diff --git a/include/linux/codetag.h b/include/linux/codetag.h
index 0c605417ebbe..57736ec77b45 100644
--- a/include/linux/codetag.h
+++ b/include/linux/codetag.h
@@ -5,8 +5,12 @@
 #ifndef _LINUX_CODETAG_H
 #define _LINUX_CODETAG_H
 
+#include <linux/container_of.h>
+#include <linux/spinlock.h>
 #include <linux/types.h>
 
+struct kref;
+struct codetag_ctx;
 struct codetag_iterator;
 struct codetag_type;
 struct seq_buf;
@@ -18,15 +22,38 @@ struct module;
  * an array of these.
  */
 struct codetag {
-	unsigned int flags; /* used in later patches */
+	unsigned int flags; /* has to be the first member shared with codetag_ctx */
 	unsigned int lineno;
 	const char *modname;
 	const char *function;
 	const char *filename;
 } __aligned(8);
 
+/* codetag_with_ctx flags */
+#define CTC_FLAG_CTX_PTR	(1 << 0)
+#define CTC_FLAG_CTX_READY	(1 << 1)
+#define CTC_FLAG_CTX_ENABLED	(1 << 2)
+
+/*
+ * Code tag with context capture support. Contains a list to store context for
+ * each tag hit, a lock protecting the list and a flag to indicate whether
+ * context capture is enabled for the tag.
+ */
+struct codetag_with_ctx {
+	struct codetag ct;
+	struct list_head ctx_head;
+	spinlock_t ctx_lock;
+} __aligned(8);
+
+/*
+ * Tag reference can point to codetag directly or indirectly via codetag_ctx.
+ * Direct codetag pointer is used when context capture is disabled or not
+ * supported. When context capture for the tag is used, the reference points
+ * to the codetag_ctx through which the codetag can be reached.
+ */
 union codetag_ref {
 	struct codetag *ct;
+	struct codetag_ctx *ctx;
 };
 
 struct codetag_range {
@@ -46,6 +73,7 @@ struct codetag_type_desc {
 			    struct codetag_module *cmod);
 	void (*module_unload)(struct codetag_type *cttype,
 			      struct codetag_module *cmod);
+	void (*free_ctx)(struct kref *ref);
 };
 
 struct codetag_iterator {
@@ -53,6 +81,7 @@ struct codetag_iterator {
 	struct codetag_module *cmod;
 	unsigned long mod_id;
 	struct codetag *ct;
+	struct codetag_ctx *ctx;
 };
 
 #define CODE_TAG_INIT {					\
@@ -63,9 +92,28 @@ struct codetag_iterator {
 	.flags		= 0,				\
 }
 
+static inline bool is_codetag_ctx_ref(union codetag_ref *ref)
+{
+	return !!(ref->ct->flags & CTC_FLAG_CTX_PTR);
+}
+
+static inline
+struct codetag_with_ctx *ct_to_ctc(struct codetag *ct)
+{
+	return container_of(ct, struct codetag_with_ctx, ct);
+}
+
 void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
 struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype);
 struct codetag *codetag_next_ct(struct codetag_iterator *iter);
+struct codetag_ctx *codetag_next_ctx(struct codetag_iterator *iter);
+
+bool codetag_enable_ctx(struct codetag_with_ctx *ctc, bool enable);
+static inline bool codetag_ctx_enabled(struct codetag_with_ctx *ctc)
+{
+	return !!(ctc->ct.flags & CTC_FLAG_CTX_ENABLED);
+}
+bool codetag_has_ctx(struct codetag_with_ctx *ctc);
 
 void codetag_to_text(struct seq_buf *out, struct codetag *ct);
 
diff --git a/include/linux/codetag_ctx.h b/include/linux/codetag_ctx.h
new file mode 100644
index 000000000000..e741484f0e08
--- /dev/null
+++ b/include/linux/codetag_ctx.h
@@ -0,0 +1,48 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * code tag context
+ */
+#ifndef _LINUX_CODETAG_CTX_H
+#define _LINUX_CODETAG_CTX_H
+
+#include <linux/codetag.h>
+#include <linux/kref.h>
+
+/* Code tag hit context. */
+struct codetag_ctx {
+	unsigned int flags; /* has to be the first member shared with codetag */
+	struct codetag_with_ctx *ctc;
+	struct list_head node;
+	struct kref refcount;
+} __aligned(8);
+
+static inline struct codetag_ctx *kref_to_ctx(struct kref *refcount)
+{
+	return container_of(refcount, struct codetag_ctx, refcount);
+}
+
+static inline void add_ctx(struct codetag_ctx *ctx,
+			   struct codetag_with_ctx *ctc)
+{
+	kref_init(&ctx->refcount);
+	spin_lock(&ctc->ctx_lock);
+	ctx->flags = CTC_FLAG_CTX_PTR;
+	ctx->ctc = ctc;
+	list_add_tail(&ctx->node, &ctc->ctx_head);
+	spin_unlock(&ctc->ctx_lock);
+}
+
+static inline void rem_ctx(struct codetag_ctx *ctx,
+			   void (*free_ctx)(struct kref *refcount))
+{
+	struct codetag_with_ctx *ctc = ctx->ctc;
+
+	spin_lock(&ctc->ctx_lock);
+	/* ctx might have been removed while we were using it */
+	if (!list_empty(&ctx->node))
+		list_del_init(&ctx->node);
+	spin_unlock(&ctc->ctx_lock);
+	kref_put(&ctx->refcount, free_ctx);
+}
+
+#endif /* _LINUX_CODETAG_CTX_H */
diff --git a/lib/codetag.c b/lib/codetag.c
index 288ccfd5cbd0..2762fda5c016 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -1,5 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0-only
 #include <linux/codetag.h>
+#include <linux/codetag_ctx.h>
 #include <linux/idr.h>
 #include <linux/kallsyms.h>
 #include <linux/module.h>
@@ -91,6 +92,139 @@ struct codetag *codetag_next_ct(struct codetag_iterator *iter)
 	return ct;
 }
 
+static struct codetag_ctx *next_ctx_from_ct(struct codetag_iterator *iter)
+{
+	struct codetag_with_ctx *ctc;
+	struct codetag_ctx *ctx = NULL;
+	struct codetag *ct = iter->ct;
+
+	while (ct) {
+		if (!(ct->flags & CTC_FLAG_CTX_READY))
+			goto next;
+
+		ctc = ct_to_ctc(ct);
+		spin_lock(&ctc->ctx_lock);
+		if (!list_empty(&ctc->ctx_head)) {
+			ctx = list_first_entry(&ctc->ctx_head,
+					       struct codetag_ctx, node);
+			kref_get(&ctx->refcount);
+		}
+		spin_unlock(&ctc->ctx_lock);
+		if (ctx)
+			break;
+next:
+		ct = codetag_next_ct(iter);
+	}
+
+	iter->ctx = ctx;
+	return ctx;
+}
+
+struct codetag_ctx *codetag_next_ctx(struct codetag_iterator *iter)
+{
+	struct codetag_ctx *ctx = iter->ctx;
+	struct codetag_ctx *found = NULL;
+
+	lockdep_assert_held(&iter->cttype->mod_lock);
+
+	if (!ctx)
+		return next_ctx_from_ct(iter);
+
+	spin_lock(&ctx->ctc->ctx_lock);
+	/*
+	 * Do not advance if the object was isolated, restart at the same tag.
+	 */
+	if (!list_empty(&ctx->node)) {
+		if (list_is_last(&ctx->node, &ctx->ctc->ctx_head)) {
+			/* Finished with this tag, advance to the next */
+			codetag_next_ct(iter);
+		} else {
+			found = list_next_entry(ctx, node);
+			kref_get(&found->refcount);
+		}
+	}
+	spin_unlock(&ctx->ctc->ctx_lock);
+	kref_put(&ctx->refcount, iter->cttype->desc.free_ctx);
+
+	if (!found)
+		return next_ctx_from_ct(iter);
+
+	iter->ctx = found;
+	return found;
+}
+
+static struct codetag_type *find_cttype(struct codetag *ct)
+{
+	struct codetag_module *cmod;
+	struct codetag_type *cttype;
+	unsigned long mod_id;
+	unsigned long tmp;
+
+	mutex_lock(&codetag_lock);
+	list_for_each_entry(cttype, &codetag_types, link) {
+		down_read(&cttype->mod_lock);
+		idr_for_each_entry_ul(&cttype->mod_idr, cmod, tmp, mod_id) {
+			if (ct >= cmod->range.start && ct < cmod->range.stop) {
+				up_read(&cttype->mod_lock);
+				goto found;
+			}
+		}
+		up_read(&cttype->mod_lock);
+	}
+	cttype = NULL;
+found:
+	mutex_unlock(&codetag_lock);
+
+	return cttype;
+}
+
+bool codetag_enable_ctx(struct codetag_with_ctx *ctc, bool enable)
+{
+	struct codetag_type *cttype = find_cttype(&ctc->ct);
+
+	if (!cttype || !cttype->desc.free_ctx)
+		return false;
+
+	lockdep_assert_held(&cttype->mod_lock);
+	BUG_ON(!rwsem_is_locked(&cttype->mod_lock));
+
+	if (codetag_ctx_enabled(ctc) == enable)
+		return false;
+
+	if (enable) {
+		/* Initialize context capture fields only once */
+		if (!(ctc->ct.flags & CTC_FLAG_CTX_READY)) {
+			spin_lock_init(&ctc->ctx_lock);
+			INIT_LIST_HEAD(&ctc->ctx_head);
+			ctc->ct.flags |= CTC_FLAG_CTX_READY;
+		}
+		ctc->ct.flags |= CTC_FLAG_CTX_ENABLED;
+	} else {
+		/*
+		 * The list of context objects is intentionally left untouched.
+		 * It can be read back and if context capture is re-enablied it
+		 * will append new objects.
+		 */
+		ctc->ct.flags &= ~CTC_FLAG_CTX_ENABLED;
+	}
+
+	return true;
+}
+
+bool codetag_has_ctx(struct codetag_with_ctx *ctc)
+{
+	bool no_ctx;
+
+	if (!(ctc->ct.flags & CTC_FLAG_CTX_READY))
+		return false;
+
+	spin_lock(&ctc->ctx_lock);
+	no_ctx = list_empty(&ctc->ctx_head);
+	spin_unlock(&ctc->ctx_lock);
+
+	return !no_ctx;
+}
+
 void codetag_to_text(struct seq_buf *out, struct codetag *ct)
 {
 	seq_buf_printf(out, "%s:%u module:%s func:%s",
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-21-surenb%40google.com.
