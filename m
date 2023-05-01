Return-Path: <kasan-dev+bncBC7OD3FKWUERBOW6X6RAMGQE3QNQH2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FFAF6F33F7
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:28 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1aaf6ef3580sf7903685ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960187; cv=pass;
        d=google.com; s=arc-20160816;
        b=w2sXZoLEVo0ihS8ippkl6LE77UdznloXKuCbg07PY1qj/wlI57UcX9WcDUDstseR+g
         hf3/t//uUn71FRZ9YURpTwYIdH/iUKJKttQNPBnDOx5A93KBvj+xyNFVZjlngRw5u9bL
         MnYbbvVG1QiyC3pWNICJOhRebnJc0VtSlUx7Fannds2p8q/giYao2yhdEABnEfVOv81l
         VKu5SVtWuKwVVJLna8YPRFLa+A0LJtdR7JBR2mEIlLx7Pb9S4hw987y1USipnYTPoq1Z
         yRMgBKKN87t2LdJaUERu8HaMkRsxkwdNx7KF/tNrWCKMC3UAijA+GVrEiEI27RKEtzld
         +XRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=FynLRsvyT7HcrI8WPmiqSEAbLithOySrHfc23Y2moLc=;
        b=ddV3Ur0Qmql9jgrLz7Ob7GlleucQgsYtqnQ/G8xH3ci1lb1VG/0QHIItnmt6ZK4O5W
         9fQ0eLNmWp1E2p1Ul24RW81CldZjj0HeIs5NoZ3wwfg+9m/ApufTSljrI20gk7J5i9VS
         DN6Cm/68CbQHxRPU2ZuAAxKUbsupMzr0q9G0nIiCxta9rWsLsYidajEgb3T6nZrMWRo/
         P35AtYmQbEuSwiAiJ2iFW9iqJ9mDzNq6Uhn4rykoQSHHEBNymkVIGvCMGieba3Ut70U+
         3mnWqQnZJPAxP7tivE+6ovh7qgccX3I/OOVA1LdGqS4NXcLqpE3yXuzSv0Ihxz4QN90w
         cOPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="2XuV/LXF";
       spf=pass (google.com: domain of 3oe9pzaykcyawyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Oe9PZAYKCYAwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960187; x=1685552187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=FynLRsvyT7HcrI8WPmiqSEAbLithOySrHfc23Y2moLc=;
        b=fXJKq0ZvZ7idJ21Q4Rz2DYVLwn5rZbdx+JPAvD7dqsvLzCUTELLljmxD3W5mIZbmZ+
         yDP6mShCQMKsSU8nPKqfADoWyJXaS/vQi3BXzX4FiBlNDB4PgIi+7z9x0w6XoWbVE3Gr
         PVudzIpCQr+vBAYeOVKEX+ac5n8BFU9v4WqVrhqAX+7xTkGScCuyb1KloYqckHaGeCyF
         4L7TAFzZvVETZ4wZSM0YF+w72J/4NMmewcwlm/W8BJZ95jFAseZIuzbGcCN5rkztK+Mg
         0B0PBbxGygQ5P2jlAVvm/vQSGcLeJ5bUBUctwfSVwTAD+/w6tv039+SjyTYVuuw4O+So
         +0IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960187; x=1685552187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FynLRsvyT7HcrI8WPmiqSEAbLithOySrHfc23Y2moLc=;
        b=MCzhAT+/8kJAFuaRW+wDdmGsWa9Kd3sscGbZHwNSnMMKD2JYEf1Hh4MVTjz5TnDOtm
         4wue+Bh9nuHCAqsTq0kIEFa4Wz3zkvxx0upbxvQTIO7zPmyo7F0zXi/MEq56AttS1oWd
         yz8bx+8WbuP6ebgBlKuFSYCOeGf3X+PeRqVT1YmPLwBVw2+RonZMQwo3TRN/fE13QvXk
         ulRXRU1mru3gI26xvFV3Q/aR99KqAm6deTGHviupgS3+xLIXKAlMjj0jaZ/WAfWZJFYQ
         FHo8prWZvcjpJP732yL3Dj0RzQFJlUx3ig/xc1/FZLjUnSA0aKCRIJLCoFVo3fyjM/dU
         Plng==
X-Gm-Message-State: AC+VfDxOskuTiOoiyJeAx+oQ1j72fMWqVt1M84li5rXPcBJf8AU/M7oA
	VPlH6pU0bULXiIE1oI+Wcgg=
X-Google-Smtp-Source: ACHHUZ6gtAqgwl/agnDINDlRlDwweTmOyFeHzv6zznLuTWEIRp5zAFMDA+JTCzX2gEvYuHfYIwtQlw==
X-Received: by 2002:a17:902:8b8b:b0:1a9:2a51:2d73 with SMTP id ay11-20020a1709028b8b00b001a92a512d73mr4495128plb.4.1682960187108;
        Mon, 01 May 2023 09:56:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1789:b0:63b:d9:eaf6 with SMTP id
 s9-20020a056a00178900b0063b00d9eaf6ls4064374pfg.2.-pod-prod-gmail; Mon, 01
 May 2023 09:56:26 -0700 (PDT)
X-Received: by 2002:a05:6a00:21c3:b0:63f:34d9:d725 with SMTP id t3-20020a056a0021c300b0063f34d9d725mr18426520pfj.14.1682960186350;
        Mon, 01 May 2023 09:56:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960186; cv=none;
        d=google.com; s=arc-20160816;
        b=v29TCQDEEGsL189tQ1n/gjxvgpmMWOGhQQXHcOF3YZ4rbnAH8FtVUNcJiso5P5bquv
         cyuL3xXDHrY1BpyOgIXdT3pB8TBgoJp4xZAlcoWGC+510/gdlFQYH5alm3Ywmm7K9dAc
         1YfZ5OyZcQVi4Z/QgGwIurQVh0URVCSrn3xc8QHpGNiU47SBVYaOJeILRtkhHaIMgZD9
         JYI8+uXRCSdNN3GLEN4KyoEcfmlGtI9CNmXuMMuqrOPQcJZs+Ui/19SW4wlB3C51vjmW
         wvH4xCJA7vqOIZYAbLKnjNH0fT9uaVPvD+5d5MUSaPOQmqyi4w86DN9fy42yH+IdUkni
         G7pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=tlYphv1i8nYyRhT88mmnNNep9iAUv9BwOK+gAme7uDQ=;
        b=uFRsZ+s1QUjciLgQcmhojd1jHYdF0h//M4fw0abwupHgnFQGGv3qTOjA7We6HhIirV
         CMjLM7ySE0FNNNrFmTzPo9L+otH26+XalPK2wbrjAjuBKCGvOkSlDaMYwUgUmdfHqgFI
         pt6FY3XQiUqx08x5AD/Ern1Xl3cnD95M91JgyAkd+rXQxnsg6Z++E1EIu0nuu0dCVB/9
         jD578bND/ngq9AB09FsBRiL9kh4+U+dKKQdr/j2OJKVNPzw+ZnQ67C8+GhaEXWFGNrV2
         o89bVxe+gA0Xs3Wn8aHKEz+q5B1nTfR7n8d7NaYQf4h0ktq/MsRvM+C/LK9arqqQMt3F
         6NWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="2XuV/LXF";
       spf=pass (google.com: domain of 3oe9pzaykcyawyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Oe9PZAYKCYAwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id o16-20020a056a0015d000b0063b78539553si1640369pfu.3.2023.05.01.09.56.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oe9pzaykcyawyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-b9a7766d1f2so3281628276.3
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:26 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a05:6902:1003:b0:b8f:54f5:89ff with SMTP id
 w3-20020a056902100300b00b8f54f589ffmr9086045ybt.11.1682960185390; Mon, 01 May
 2023 09:56:25 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:44 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-35-surenb@google.com>
Subject: [PATCH 34/40] lib: code tagging context capture support
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
 header.i=@google.com header.s=20221208 header.b="2XuV/LXF";       spf=pass
 (google.com: domain of 3oe9pzaykcyawyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Oe9PZAYKCYAwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com;
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
index 87207f199ac9..9ab2f017e845 100644
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
 	bool (*module_unload)(struct codetag_type *cttype,
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
index 84f90f3b922c..d891bbe4481d 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -1,5 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0-only
 #include <linux/codetag.h>
+#include <linux/codetag_ctx.h>
 #include <linux/idr.h>
 #include <linux/kallsyms.h>
 #include <linux/module.h>
@@ -92,6 +93,139 @@ struct codetag *codetag_next_ct(struct codetag_iterator *iter)
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
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-35-surenb%40google.com.
