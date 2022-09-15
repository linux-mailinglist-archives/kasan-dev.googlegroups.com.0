Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNP6RSMQMGQETZFFBDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id C03DD5B9E10
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:25 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id sc31-20020a1709078a1f00b0077ef3eec7d7sf5441139ejc.16
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254325; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ohi6ZVb8owbXgdQm7jVjrrwoBjPfDbiCn9XMdafpCHWrmF7Zl9zNijSNT2PhqCYkY+
         PqEmD4nEGa7CqHqwUjzHoRpo3N+MLsJdHZjAOted2Gnhx7FB0AwETF/IbVlfxJhHoNh3
         fmHmzfXxYQvXOM5wolo2j+uUm3jQPKw+EaGzdZOrKeayw+E3MJgVv+es+hRox5PXpPGD
         OBdtwyqRc94VbjTA3er7+nwcvcBFfHz8MHK4XAyAzZorimT1hZFdo28COX2R9YCaFLY7
         xRElEiH8Soj2e+AMwQ+zSqGYfjHD19pwcv6qOcVDgwXB7s0k5YICyhfFhvDGqEKoFuOi
         ziAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=9a7wg9TmMn5NYZRM9xu8CtUhBWmmx1B2G7Wv49AdaEM=;
        b=tov+QaSr3fXFswwSxEv0LhoFR3UQ6A+b+wmEz4n27ML0e7q9HZiNcpkRfUgLRNEg52
         jzRylDR9rhq9YAaYy+lvywGS71RCcKYDEptSzHBbt7lkY4oP7e/UU788nOTc1tleAEDb
         S174MSRw6u2mroozxOZo6mD2n2AzUF2z4v5BCt/ywPxbnb61Xpb3GTHpg/V9AIW5DdTC
         SCTZ6CPFXz1Jj/29viqm98GmDO+jtRtYTKYq9tb1epAaZmXooqgDfP39tMoHFrxpqU2b
         qoOKyCyBMjWdkEXl5ynI8g9sFJrpOzsx9Sx6mLVAXIWqmM/Q5HA7/KYrMTRAm3h8/3YN
         Jz7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=d96TG3Hx;
       spf=pass (google.com: domain of 3mj8jywykcv0bgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Mj8jYwYKCV0BGD89MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=9a7wg9TmMn5NYZRM9xu8CtUhBWmmx1B2G7Wv49AdaEM=;
        b=TRmYLtvIx9Z1lKI3OrpFreoemw6DIhz68ehiA5Y+9rfOkljysdOpHiNvP3OJN8OSEm
         zUcsQNFypUdeqCMoZOYsHFRcUEmDICSooh6ZMG9YUdM09gyWE+sslyG3G581tCE+6fZU
         6XS9sM5CVoXSIxY1M9oZWZyQ0FHmNyOIbn94G+dKd1BOuPbl3r4YRP82yoUnL+xVXtVe
         8Z0EgxKeKtgNeSuE70wFcBHmsrabXLU/auNVL/l5GM9F3InxJ8/Tw0eGRHFfZYloScNf
         0Z8OnUjZDWTdpkcMirHp9P67IotiRd7tsP9t25xRxr7kdTRqcEsJQ5DGw9firrnswPNX
         +W3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=9a7wg9TmMn5NYZRM9xu8CtUhBWmmx1B2G7Wv49AdaEM=;
        b=1rCNqdvefcGoFFRQxQni/gFyMrAPBigl/E9tWYtMJj7aKQshtumQHeAGbcPTNDiqWX
         /JDVEhRdggoXyT3yz01KJIHBHT9yEhfrn8+Q5dscX7fYFyOaDd7weajJXfmNr/kV48Fj
         EVw6dd2en7WciRAfXePLG4a4KMHXPS2D3IUAXj46QTKt58QvY+QuCeBy3vwik1PvyD2l
         PDnbMhEkCp5n76ky922rIsXgK27UwoLX/79zoVm5QkOTRlNec0aLffUhvaT7JXEHb91l
         Fo+FcXSRtDSpL83FG2g09rCDi9FJWjTkKQGs4+CWe/tnpQp+8z/ESqr+RyI6G8nsTuuY
         n76g==
X-Gm-Message-State: ACrzQf0h3hugPyfrikUVwRf8p6GaLdWbPFTJutgWmNr7CBYyu+xUo41Q
	au9aS96bkbdviQxvHZUSyq0=
X-Google-Smtp-Source: AMsMyM5DtldC2r0oyNODksR/uIbtFLy3BAWId3gXVSkvpEcPcvr7uQy38nbemPIFeXhvegswRZ1fiQ==
X-Received: by 2002:a05:6402:5189:b0:451:791e:f328 with SMTP id q9-20020a056402518900b00451791ef328mr273401edd.282.1663254325436;
        Thu, 15 Sep 2022 08:05:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:af49:b0:776:305f:399f with SMTP id
 ly9-20020a170906af4900b00776305f399fls2523408ejb.1.-pod-prod-gmail; Thu, 15
 Sep 2022 08:05:24 -0700 (PDT)
X-Received: by 2002:a17:907:3e27:b0:774:3e36:f00e with SMTP id hp39-20020a1709073e2700b007743e36f00emr299140ejc.83.1663254322753;
        Thu, 15 Sep 2022 08:05:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254322; cv=none;
        d=google.com; s=arc-20160816;
        b=hL2rrGtZuiZq2pjY8LvO8TGiE3XbUwYrZ21tVz0G7NFVRxdGRCslM+Fw72Xa/oyRNk
         HXsYEb3mdrRezRxzhupLnK9y7sYQfCAlBJ9Ts9emN3v4Oj+0ekXad8qSX1RqtxiZl/i7
         4uODlQUdiG68giLwPBTdjoQK5q9anzqQ1cwdQdhIqTc5He3DwLfdGbhAFl63lKSqVo5D
         XWmDNbOZVhF0vCNHQlNWydgqD1rV1muk6iAAbtB2V+t/vi+58W2fIJWwWBxXUZJc6MjI
         7MseFgFa2poKs2aXdAh47bKGVQDYvWXs5mJ1Jkf6xCLnEMZy3VSUbh1CK+oLVJUEL0Y6
         Gjuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uEBXmIOJ/jVJ62g3MgOZ1PWj/PPm6Zng9ZXCGF8oCGQ=;
        b=qWYinMwY5pFNlihPLcSpvc566vILkrxbZdZE7pLMXVfZHwSEUgw+ZjAY3cSofMibfs
         Gd+JjJ+RjZg5FzyObZEmUkT8faZCfT4YPhd/OzdldizDV4+mXMEN7cUO/1WGGLE94jgZ
         QLzxkc0tCNkSfK3r4qcOmnibSB023CvUK6eMG4EdT2IiO8O8DIO3DuaFI+nJcvMv2hWf
         Zxp/qFa95X8hBkrJTzSDEOsHOthYKot4AeOVAveQ0CVZ3RMfzgS90t+8rsRfZT3+WZqw
         O9WFgO2bBGm4uzzOlNwoD6tXHuBDjnbZZ5BIkEJSn6SZyZuqCuACLflEBYF+k3ViBQJe
         Jddw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=d96TG3Hx;
       spf=pass (google.com: domain of 3mj8jywykcv0bgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Mj8jYwYKCV0BGD89MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id w21-20020a170907271500b0073d9d812170si580690ejk.1.2022.09.15.08.05.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mj8jywykcv0bgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id gv43-20020a1709072beb00b0077c3f58a03eso5566049ejc.4
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:22 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:907:7215:b0:780:3153:cca2 with SMTP id
 dr21-20020a170907721500b007803153cca2mr279565ejc.427.1663254322378; Thu, 15
 Sep 2022 08:05:22 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:50 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-17-glider@google.com>
Subject: [PATCH v7 16/43] kmsan: handle task creation and exiting
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=d96TG3Hx;       spf=pass
 (google.com: domain of 3mj8jywykcv0bgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Mj8jYwYKCV0BGD89MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--glider.bounces.google.com;
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
index 8a9e92068b150..a438f5ee3aed5 100644
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
index 5330138fda5bc..112dce135c7f6 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -37,6 +37,16 @@ bool kmsan_enabled __read_mostly;
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
index 97d48b45dba58..77ee068c04ae9 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -180,6 +180,8 @@ void kmsan_internal_set_shadow_origin(void *address, size_t size, int b,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-17-glider%40google.com.
