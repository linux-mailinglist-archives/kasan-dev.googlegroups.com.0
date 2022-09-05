Return-Path: <kasan-dev+bncBCCMH5WKTMGRBRWV26MAMGQEEO2J4VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 229AD5AD25C
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:43 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id v67-20020a1cac46000000b003a615c4893dsf5316706wme.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380742; cv=pass;
        d=google.com; s=arc-20160816;
        b=qwZl2o6jQ4TfMEG7v1RbiETHSnTP6kM7pQyhaw1PyIc2LDITuPmlKyHfmwVRvV626O
         o0vCwRskpguX4fioDpAdleswnioEbLdGkDwaOSk0BIxNEYYiyrkFOIXxdVnwkGuNuoMo
         Q76KrFlDXubrMURf1Cdcgu9WTu2juAyzc4244v431FwN+oAtaUj164/46JvpZvpnrqlo
         KyX+YxpyQ1scQJHwaKuhhsDUSBkF2K7z3ZMA9BYsjps+ei4ZTxH07uIraaceNyGt1SA5
         Cg6vZWo+K6VmSrLTU5x1RfRVFi+sRycrO3muHZNMo3DrkbvO8scJLzca/BUU+UzCpIIZ
         7SPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=tZ/d1qBrKaWQmTYsGdDIHCrWkSHtxbYBq21ayFeq9w4=;
        b=w1ubCppre/dcoPPZ3nRNiCGmJubTGGvE3z4RPztFWRsfedK6h42/vvyAaR6u/Y8rPd
         smlU4wLKuPKlZ6LWs6TtmIYCm7w4J9uwjEDc6EsuCcTyY6RK2kpWOmXn8WA2ZpDiuVEC
         ZMY8sSOGgZqbiPogfF2WOTK9XUKZnLcNeV6tMamaUgnTaunTlwMvFMl5mlJ+nnLB+MVJ
         vSGIgAC+u3Z6XaOOAuhHrC3DygtC5syDM9loDXF+c8WZOkXQBYXuoMvS4nYYU27wyuMs
         bpNfmg1AkuKm5KnlmDB2sf6ubSO/CEU2DyYfQPbDDjjYHr8pgtAdE70v1OCJCLV0nl4m
         MYIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JUFMkLir;
       spf=pass (google.com: domain of 3xeovywykcriy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3xeoVYwYKCRIy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=tZ/d1qBrKaWQmTYsGdDIHCrWkSHtxbYBq21ayFeq9w4=;
        b=m7czVBivepBJgjf4OOQWWxbQ/SESPZQbnev1fxRfQrNXTHTL4IMdoovUFl9rg34a7i
         ZP1jNCgm/Cud5L+xfNNoBKlyPxvuZz4oPThVdYVGkYROC8cEVIPyQFTCgQF/cbVv4VTw
         kjCES6Pl1+D7MS83fJUvkUY9sJ1DzmhY/r3bdT0TyToNWLPyvZjHJqdP9IOIdBhOuV97
         UDaiNsqohEmxFw3AhVmFKDc5WA87raIoXUEPsl/TeXYP60VVomgbORPoRPSXR+k6YfGc
         MwTn6VW+FX9UqMzxkQPzFT7P2u5ctgyB+/02I49KPZU0tTgl3wHG6iO0pQe9tNpMLA6r
         uEaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=tZ/d1qBrKaWQmTYsGdDIHCrWkSHtxbYBq21ayFeq9w4=;
        b=I25cqUr9x7v3dtJTnUT7GD8UuQ/kuZxLhsjo6uqYPNFhXNcOYLG9Icy7mCt7d5noan
         8V/ecT/UzAP4L4KLi8VzChvIG4SJY3PR6++4JT0SWxnrC82q2z55ZgacXjPNihlhHBC1
         q0fYsq7wFdIz2AM9othYYd0aQ2LgtBE877RPybHGeIPKR5PKEinw+ZtN91phEWVElEbw
         wMDIFACv44bxGfTFZhEmg4OlgbNwNtwzWaQfUcqJkln+ZSV88QzeUwCGbk2a65310xQd
         Pkp8Ox8I/tIXLIfSPmVwGAuPgiVxXIUBuGyLIHrEY2WMfSWfVMRYKEvVi9Lx/KZptf54
         UmkA==
X-Gm-Message-State: ACgBeo0crCi6h89uherndpTw+Hg3y8X02ImXtqKQW52fdNJOLzKEGXlg
	l5xgJgkDlQASkUuIAHVeepg=
X-Google-Smtp-Source: AA6agR6lHDAn6rxaN3PH3f0Q2K7/aSjU+xTJlBovDK/0YWyCP+MT+G7KU/R2qB3bXWim1g0Nk2BHBg==
X-Received: by 2002:adf:df8c:0:b0:228:b268:5ede with SMTP id z12-20020adfdf8c000000b00228b2685edemr1510632wrl.141.1662380742818;
        Mon, 05 Sep 2022 05:25:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:60c7:0:b0:228:c8fc:9de8 with SMTP id x7-20020a5d60c7000000b00228c8fc9de8ls1531363wrt.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:25:41 -0700 (PDT)
X-Received: by 2002:adf:e649:0:b0:228:a8f6:42b4 with SMTP id b9-20020adfe649000000b00228a8f642b4mr1702753wrn.167.1662380741827;
        Mon, 05 Sep 2022 05:25:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380741; cv=none;
        d=google.com; s=arc-20160816;
        b=mUBPPe3cG7CGuONI6NcDpp5xM5IY+Uhha6D1EyILIlaVKdzwxYHpLuMKT03p0SO4ga
         167NJMv0wkZ3LT+owNUv2ccNrnHvb/MH3bBAUpSdCDmUA6nduULD/n+AFZWFiq9yDEgl
         vbKikUbUTQRNOJ/KN7EHRawV8qTcISJTqMPcV+FZXa/CIGeJhbKOwuUCsmJlcKtpS0ao
         kBmxNzNCDq0tCVPc3yUYkl6Jb1MDaRrVFaGyCiTr/hTh0Bwln/im3CFAG5naV7kgKLuE
         M14w3piRlDEJv/MRsxtLUlalquLtwHPtRmrYPzjiaixq6OFaw3yK2kVJNjf64ZkZg7B8
         aVcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hpHoy1zlF7EBf883UoQvMWO5+jjHkQm5Cfi8gPN98eQ=;
        b=rwERue99VSmR8kDAN/XFAOoaTwOnncs8D5VMUAVgo/RGf5q3hB12/ZkdDBjyehFLxn
         OoDgiwyx6zQZdjRplVPHyaVFHsgG3pknhHOoA0T5PbKx0NlGSew6aRYqc64QIvsCM6gO
         2yfDfIOh+mhnJ6RlHVBj+5QLxjBhPxeJmtaS0XUiY3isHRyULyu9aIfbntwNcxJV9s2A
         5JvyeqGesBZkBcVh5Ya6r7nXt60BkwlriAHwy9ZdPVV4S+cQUxLe/YejtMNqEVlrAUVF
         eWAwpuM90J3Ql1y812NIbp/s6O1R+o5ZPiN5rPQmuJIoFBhGpXMcdEpc7W/MZzn9RkUP
         lmYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JUFMkLir;
       spf=pass (google.com: domain of 3xeovywykcriy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3xeoVYwYKCRIy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id n20-20020a05600c501400b003a5b20f80f5si734077wmr.1.2022.09.05.05.25.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xeovywykcriy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id gn30-20020a1709070d1e00b0074144af99d1so2276196ejc.17
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:41 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:aa7:cb13:0:b0:448:3759:8c57 with SMTP id
 s19-20020aa7cb13000000b0044837598c57mr33923922edt.8.1662380741433; Mon, 05
 Sep 2022 05:25:41 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:24 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-17-glider@google.com>
Subject: [PATCH v6 16/44] kmsan: handle task creation and exiting
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JUFMkLir;       spf=pass
 (google.com: domain of 3xeovywykcriy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3xeoVYwYKCRIy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Tell KMSAN that a new task is created, so the tool creates a backing
metadata structure for that task.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- move implementation of kmsan_task_create() and kmsan_task_exit() here

v4:
 -- change sizeof(type) to sizeof(*ptr)

v5:
 -- do not export KMSAN hooks that are not called from modules
 -- minor comment fix

Link: https://linux-review.googlesource.com/id/I0f41c3a1c7d66f7e14aabcfdfc7c69addb945805
---
 include/linux/kmsan.h | 21 +++++++++++++++++++++
 kernel/exit.c         |  2 ++
 kernel/fork.c         |  2 ++
 mm/kmsan/core.c       | 10 ++++++++++
 mm/kmsan/hooks.c      | 17 +++++++++++++++++
 mm/kmsan/kmsan.h      |  2 ++
 6 files changed, 54 insertions(+)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 5c4e0079054e6..354aee6f7b1a2 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -15,9 +15,22 @@
 
 struct page;
 struct kmem_cache;
+struct task_struct;
 
 #ifdef CONFIG_KMSAN
 
+/**
+ * kmsan_task_create() - Initialize KMSAN state for the task.
+ * @task: task to initialize.
+ */
+void kmsan_task_create(struct task_struct *task);
+
+/**
+ * kmsan_task_exit() - Notify KMSAN that a task has exited.
+ * @task: task about to finish.
+ */
+void kmsan_task_exit(struct task_struct *task);
+
 /**
  * kmsan_alloc_page() - Notify KMSAN about an alloc_pages() call.
  * @page:  struct page pointer returned by alloc_pages().
@@ -139,6 +152,14 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
 
 #else
 
+static inline void kmsan_task_create(struct task_struct *task)
+{
+}
+
+static inline void kmsan_task_exit(struct task_struct *task)
+{
+}
+
 static inline int kmsan_alloc_page(struct page *page, unsigned int order,
 				   gfp_t flags)
 {
diff --git a/kernel/exit.c b/kernel/exit.c
index 84021b24f79e3..f5d620c315662 100644
--- a/kernel/exit.c
+++ b/kernel/exit.c
@@ -60,6 +60,7 @@
 #include <linux/writeback.h>
 #include <linux/shm.h>
 #include <linux/kcov.h>
+#include <linux/kmsan.h>
 #include <linux/random.h>
 #include <linux/rcuwait.h>
 #include <linux/compat.h>
@@ -741,6 +742,7 @@ void __noreturn do_exit(long code)
 	WARN_ON(tsk->plug);
 
 	kcov_task_exit(tsk);
+	kmsan_task_exit(tsk);
 
 	coredump_task_exit(tsk);
 	ptrace_event(PTRACE_EVENT_EXIT, code);
diff --git a/kernel/fork.c b/kernel/fork.c
index 90c85b17bf698..7cf3eea01ceef 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -37,6 +37,7 @@
 #include <linux/fdtable.h>
 #include <linux/iocontext.h>
 #include <linux/key.h>
+#include <linux/kmsan.h>
 #include <linux/binfmts.h>
 #include <linux/mman.h>
 #include <linux/mmu_notifier.h>
@@ -1026,6 +1027,7 @@ static struct task_struct *dup_task_struct(struct task_struct *orig, int node)
 	tsk->worker_private = NULL;
 
 	kcov_task_init(tsk);
+	kmsan_task_create(tsk);
 	kmap_local_fork(tsk);
 
 #ifdef CONFIG_FAULT_INJECTION
diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 009ac577bf3fc..fd007d53e9f53 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -44,6 +44,16 @@ bool kmsan_enabled __read_mostly;
  */
 DEFINE_PER_CPU(struct kmsan_ctx, kmsan_percpu_ctx);
 
+void kmsan_internal_task_create(struct task_struct *task)
+{
+	struct kmsan_ctx *ctx = &task->kmsan_ctx;
+	struct thread_info *info = current_thread_info();
+
+	__memset(ctx, 0, sizeof(*ctx));
+	ctx->allow_reporting = true;
+	kmsan_internal_unpoison_memory(info, sizeof(*info), false);
+}
+
 void kmsan_internal_poison_memory(void *address, size_t size, gfp_t flags,
 				  unsigned int poison_flags)
 {
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 000703c563a4d..6f3e64b0b61f8 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -27,6 +27,23 @@
  * skipping effects of functions like memset() inside instrumented code.
  */
 
+void kmsan_task_create(struct task_struct *task)
+{
+	kmsan_enter_runtime();
+	kmsan_internal_task_create(task);
+	kmsan_leave_runtime();
+}
+
+void kmsan_task_exit(struct task_struct *task)
+{
+	struct kmsan_ctx *ctx = &task->kmsan_ctx;
+
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+
+	ctx->allow_reporting = false;
+}
+
 void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags)
 {
 	if (unlikely(object == NULL))
diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index 6b9deee3b7f32..04954b83c5d65 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -179,6 +179,8 @@ void kmsan_internal_set_shadow_origin(void *address, size_t size, int b,
 				      u32 origin, bool checked);
 depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id);
 
+void kmsan_internal_task_create(struct task_struct *task);
+
 bool kmsan_metadata_is_contiguous(void *addr, size_t size);
 void kmsan_internal_check_memory(void *addr, size_t size, const void *user_addr,
 				 int reason);
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-17-glider%40google.com.
