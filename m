Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAMH7SKQMGQEV5GTBYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 03B3156351D
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:02 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id k5-20020a05600c0b4500b003941ca130f9sf1114060wmr.0
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685441; cv=pass;
        d=google.com; s=arc-20160816;
        b=zc5S5ib89e6qjcyj6RaC4PXMDdc5lb+rc0chQtcjuqIs+8NLRyCPk/lOYFjcIdrl10
         4bkEG/pQQYmBd6/EQigpjVu6MW8C0Ev/3lFxkrfEI/a8xxv0KG25zAgwF4SlvdIeKhxH
         5zm3pgj/KVTgiGfS2t1TcO5SOqy/uK9zBuoqt/u+CiIKHrpLsTd1NOEILjiOXj5+sqSl
         pzowdsRkEDCBes8hvrrpFQL59kyARZXy28oUoqZ05AvJnVO6yoXO5CvHcr2XfqZXstLY
         qstYc9wG74y5bc2FxzgcBSCgZ32k0u89OJTPMxC/3ihrF4U6jUIqGQhTTxdvQv8SJt2S
         Al7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=S9TeGsYEGDyLkS94+I6lza9e++IxEBc5Bpyx9baYaec=;
        b=SDZooFa+uNuFX0sLTe6jE7W69rCtYOFm0FkgH1MjQlJgmoG0+g+MS+JwCLxULLWoyn
         Lusn8MFSAUDvPXphgfBw+OxPE2gGT8cctwYpIXs7tQxquWMSIuYq7DQslx5rK5/N0xoV
         PYxdIJtyAKsBGQxLPiCDqEXnHk3duYfD4HMzpPou37ymFaqYQVbOOnLTYTjqCZHp99j+
         6N5nA8PvMRTHsIxXF/S2SOQdBRYGSlzf3bWS5Vp5SKjhidaRGSPC2Zaa1g0zzcfR0C7h
         1AuEOPoBAwXnSZ0CVoKaFnQArS2EihAqZnUPJ61kXJ7w6ldwOu0F0HhXu6WZeWl1dhzR
         fODA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="RS/M11Vi";
       spf=pass (google.com: domain of 3gao_ygykcz8fkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3gAO_YgYKCZ8FKHCDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S9TeGsYEGDyLkS94+I6lza9e++IxEBc5Bpyx9baYaec=;
        b=U+efuiD5z1csr+YtBL2naT+0CL1iNTtN94KXgSx5pbuYAl4TTCGj9XLkVYTMVIfBkF
         XvWkBN9bYUQr2hTPpeUatRTEDepW2hSLjseiMfUNsx0Cd/U97iSMBjGvqTOZnCZRKraH
         wonIAtBOL5KkafY5jgLtYj5kfwpUO7KjPWkUGh9aivDFPqhgY6t1OMicJBT2f+IJuZgD
         F0c6WfmKcz40vNh8Q36K1jnRdkL2X0Q94k6crBse34txbJQRtb3IqCD1k47Oz2O89FlI
         /NkfIwzN2v2TJIhBtRBjJptQKUJx00uCYMGPQo9W5OleFp75WlhWJxOZAITCE4YZjjQF
         EHWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S9TeGsYEGDyLkS94+I6lza9e++IxEBc5Bpyx9baYaec=;
        b=Yy0wRTR7R6deMdKAGkMRMmrAEwJV9jdab3jI315/zkOVQyvjG6w4k5D0TBfmProOk0
         af7R6FUZybIwhWUod35dQwAFnTlkXwks6kHOwEPJlkXebpKsFZKlnwAqYxbRt8BN9u5v
         rPtoyBv37IIiaQVUPHg0DgLshlQoYZ5ulKT/18l+1d2kU8wutM+BzJ1nQVEkDFLE0cpr
         ffnO6SXh1wmCraCaVUBWgcIrdDdaAOZ+u9lq3FWBPgYZvkHa2g5/KX2J0IffNjexVuin
         h417snlTKg/JTcm8tPI9S8AKF5MfIce2Ev1iykVcl2QAlaur4qefUGXlpGcFuPBnDWY5
         sUog==
X-Gm-Message-State: AJIora9UbXYzfxE9su5Dbzhms1SpSmOPWAUzDIJyRN491t13Rthzwh+q
	qXe70452Zjr6Utub3gZOhQE=
X-Google-Smtp-Source: AGRyM1tQPsEe3fn381/8OT3fVM4TvRYNKmzQ9Yc/2mGm/Jha2xSSzHG+HtFGcQxICrLxsUdRr4maRw==
X-Received: by 2002:a05:600c:210a:b0:3a0:3be1:718f with SMTP id u10-20020a05600c210a00b003a03be1718fmr18561945wml.181.1656685441685;
        Fri, 01 Jul 2022 07:24:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4ec7:b0:39c:871d:313f with SMTP id
 g7-20020a05600c4ec700b0039c871d313fls3475101wmq.2.canary-gmail; Fri, 01 Jul
 2022 07:24:00 -0700 (PDT)
X-Received: by 2002:a1c:720f:0:b0:3a0:2ac9:5231 with SMTP id n15-20020a1c720f000000b003a02ac95231mr16697976wmc.39.1656685440729;
        Fri, 01 Jul 2022 07:24:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685440; cv=none;
        d=google.com; s=arc-20160816;
        b=FTp7gwz3OY37fcYwJXztA5ruhOKYgxuURtPW6fKYjITzJwqW83FODLidWso8q9w0Lc
         LHxinVBtIKPqus4wOOK8XpfWvvNRv5cElfkR9zA8gT6tuw9NzceBaeFuOXWV2s78rg3i
         2yMvXN3b/eye371onlucgm4qwQtE6ROV0I7g9+yBH26PzGBKvbEcPd9BzBbjahWjxBXt
         Vv9/eYZ1vQlYqdJ/ZKwpBmQzvdG6F6l9tuXiRdjqyGHF1oOktADI94LoOXM2ypbKlBfh
         vhg2Z+bBetfumeKJE0T6P833jgkgClDSm3nmrgzrStE2/2EAVh6XpzxIdbet9jQLhIYB
         ZTgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=MuviuQokEzhvfg2Z0+25mg/6MRU0laLu6ns1H0kafhg=;
        b=ewZ+0Evsu49Cdtb+yNBtlSRGM5brVMduMpYuwTnLZuRj4v+S0Rru/QP9uLqrTmYrs/
         ZLF8GJ2bgtfXSR4T+VKRWhvZOmw2hSKJ5lZNziFCFERlrvoGHx9gimBCDgPkLAeW3QbF
         DqTFMjUcuTJxe/lymjpdK1jBRUlOOb/kA3607yqzpzvrNRqslNqYFbRr3fOHEihEgNlL
         x94wIwb69mZ4seEDDGQ2N5T+BfYrSwqD0TO8JiY3MYprKRT0gfZbILI+mnzyV3L6Pxdy
         DmCUaJ2OdbvuU1rU6XJpoUQxV9fM2C4AytYDBRedYHAqob7Q/wjo7VRpzeSqVXAuvQhA
         /C4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="RS/M11Vi";
       spf=pass (google.com: domain of 3gao_ygykcz8fkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3gAO_YgYKCZ8FKHCDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id m7-20020adffa07000000b0021a07a20517si789883wrr.7.2022.07.01.07.24.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gao_ygykcz8fkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id oz40-20020a1709077da800b00722ef1e93bdso835257ejc.17
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:00 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:430a:b0:435:8ec9:31ec with SMTP id
 m10-20020a056402430a00b004358ec931ecmr19482900edc.248.1656685440344; Fri, 01
 Jul 2022 07:24:00 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:41 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-17-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 16/45] kmsan: handle task creation and exiting
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
 header.i=@google.com header.s=20210112 header.b="RS/M11Vi";       spf=pass
 (google.com: domain of 3gao_ygykcz8fkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3gAO_YgYKCZ8FKHCDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--glider.bounces.google.com;
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

Link: https://linux-review.googlesource.com/id/I0f41c3a1c7d66f7e14aabcfdfc7c69addb945805
---
 include/linux/kmsan.h | 17 +++++++++++++++++
 kernel/exit.c         |  2 ++
 kernel/fork.c         |  2 ++
 mm/kmsan/core.c       | 10 ++++++++++
 mm/kmsan/hooks.c      | 19 +++++++++++++++++++
 mm/kmsan/kmsan.h      |  2 ++
 6 files changed, 52 insertions(+)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index fd76cea338878..b71e2032222e9 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -16,6 +16,7 @@
 
 struct page;
 struct kmem_cache;
+struct task_struct;
 
 #ifdef CONFIG_KMSAN
 
@@ -42,6 +43,14 @@ struct kmsan_ctx {
 	bool allow_reporting;
 };
 
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
@@ -163,6 +172,14 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
 
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
index f072959fcab7f..1784b7a741ddd 100644
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
index 9d44f2d46c696..6dfca6f00ec82 100644
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
index 16fb8880a9c6d..7eabed03ed10b 100644
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
index 052e17b7a717d..43a529569053d 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -26,6 +26,25 @@
  * skipping effects of functions like memset() inside instrumented code.
  */
 
+void kmsan_task_create(struct task_struct *task)
+{
+	kmsan_enter_runtime();
+	kmsan_internal_task_create(task);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_task_create);
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
+EXPORT_SYMBOL(kmsan_task_exit);
+
 void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags)
 {
 	if (unlikely(object == NULL))
diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index d3c400ca097ba..c7fb8666607e2 100644
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-17-glider%40google.com.
