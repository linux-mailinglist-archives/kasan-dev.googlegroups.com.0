Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFGDUCJQMGQE3UMX3CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AB5D5103F3
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:09 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id o8-20020a170906974800b006f3a8be7502sf2043540ejy.8
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991508; cv=pass;
        d=google.com; s=arc-20160816;
        b=f417kdJd4lqIP6jk0Y+XWE+1AdCox10uogX1ojj7B6USsC3mKNRJlkFlBx1A4YRwqv
         8vyBwIXUDIuR/rofE8Vb5YQ4/wCuF7T5pCcSkOofjNVlxbq+UwzZoVicuhIQ7I4cTSlh
         UiXEheM1hrw7Xvv0FA67A9qsr8CZtpsXc/OmBExoFjU3wJVuLlnCJhEdbeuxrmm56FKB
         xMdKAd7Srp3pbEytzNTmQ/uqIIuFIoPL+FInhoB6dlc7HFTtfmwOaWCYURsK0ysZCCnx
         KM3uUKLKOGMAsppCJN7Zp/0Q/j7EABFJy4/+JxL+jOOAxIu/Ub0vEi6JJhWcmRSANOJa
         f4HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=WtJ3/OQ4Vg30P3RcfNofKUdCA9Y0wzC+Q02n9oovyhc=;
        b=dXqYAR8TIGgqi3c+NmZXt8xsbDdF/oV5HlzksF0TbGJ+fREB1Q149rOFymXtiH8gXT
         qrpB1A/FA2Vu+udCHzy285/0lOr9I2LZGG6ZSdy0MsIE4NYgIjeOA+Jss1owSkTREJCT
         SfOhnHuAbYEfIROLps99xSqN6tMi87Ghgcg6mgnZC24HdsmiYyHyca7HABXrLiYl7Onr
         kXLxU5zJht1IsK4UAuC+9+vhL7cYSelKDkQe4DhmBL/omuZocDws+TRtHwqbiWrXKW9n
         lIjvQqt++vJMlqCydAJ9C6Z5pgkCF99bRYQwKZGhsI1WlHh0S08+KIWSqAJd5BkHxziv
         3p3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qHuNE5uJ;
       spf=pass (google.com: domain of 3kyfoygykcza052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kyFoYgYKCZA052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WtJ3/OQ4Vg30P3RcfNofKUdCA9Y0wzC+Q02n9oovyhc=;
        b=WReDHwBVqMTa/KFbO2pnjkzLIm8KQJGjDW9b6PzlSqLAodE40opi3rVdMNMWc3D6fr
         Mutr+SfLWpqCtVrWJuJoWsjvx08fZIjGvQb+46TebEaQZzr28U//j7lWJOuJMWtv/woY
         w8bYbqdpupkjfzZjfAjGVPT65NZMsGteYcaZA+faABHiRjsl+0fCHlwX6WmVmyup9CXN
         TZaWt4L7RpJw3FG/6z0Kmj94mZ0sQ1TO2zE3HIUqjtrM8xzwNefSIf6iSxB+jw3ODwXj
         J4FG1b9Iwfp+yXHCxZo6mieo1I5B9WF3+JH3IVfCPM46oUX2c/x2OvSyWtyUkJDr0SPd
         Z+UA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WtJ3/OQ4Vg30P3RcfNofKUdCA9Y0wzC+Q02n9oovyhc=;
        b=SCbPlMkpGjKuTNLT/LwVjRTZP5/JuvBgnHfCPuyeynrTJ4TiPLlv8oR4REXNLxyRn4
         5cMhgWEMBkZ8fm9T9FJ4lFb8fo++eBFIOTb0SJdOdTem9IF1Eokloct7fl5XcY6B0fxH
         IrpZOWFkgYojFhlriUwKlZoDZgEL7KveVKHDiMEUmunjAHEYsylvXc2Sjodd9zKysEle
         BxcI7Bk3vzFoxAqYMmTmML9n3ktM4wHCRW2RaHliQg1dUq9XxcKzBasFpVuMJdJ4d6LK
         BRNUcitXh3zrDPBBjhQFdhPiS+9lySXIb69GRai5x4TY3YrQtvIZEomyOfO5rb93gMmY
         F7cQ==
X-Gm-Message-State: AOAM533gSN0n+3p/0twkYfNrxncw3sk3Ko4rNPMF4OX99kpa5QfJg9PY
	yZKzPOW52BjnzgMSxzph/qg=
X-Google-Smtp-Source: ABdhPJyB1K4FTR5AgQd5+sq1Yv6e1XEGjKssczo10j8jG+Q2w3oosi8E3ip/51x5ja8SCTTIhl7EmA==
X-Received: by 2002:a17:906:2709:b0:6f0:13d5:d58f with SMTP id z9-20020a170906270900b006f013d5d58fmr22089500ejc.443.1650991508828;
        Tue, 26 Apr 2022 09:45:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:478d:b0:6e8:95ff:b734 with SMTP id
 cw13-20020a170906478d00b006e895ffb734ls5358253ejc.5.gmail; Tue, 26 Apr 2022
 09:45:07 -0700 (PDT)
X-Received: by 2002:a17:907:d29:b0:6f2:48a0:7186 with SMTP id gn41-20020a1709070d2900b006f248a07186mr21185911ejc.102.1650991507767;
        Tue, 26 Apr 2022 09:45:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991507; cv=none;
        d=google.com; s=arc-20160816;
        b=gmWSNmzZg2+j//8rEsxJpXawKyD/BtYLu5Cn6SY2xQFtC0WvF2PFZTO3lC6HjmpYfP
         rvlTKH6J9Cdwkw9p0+cbP8HQmzZn4bc8GXxSkY3lPxi3q+ZHKkHM29OxfHJwsqnPZpc0
         /VCvLl2xR+HASF7qjd/esSdcuWg26iWMgHxuV04S3B5oTnECwcCoYYfWcQ+pPoNpd3Mc
         QwYz1hO6Evsz+prPALEyxe+8GfZAAANQdY62esCvZb+m7bbw4wYvVwEZXow0rMDP3jEL
         2UtxRh4zpv6fuLGxNUWmO4D2KQsldYycMbxzJyqeRVb8jutxATon4em8p/B6SSdn+x5U
         yQQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=d8pL6jrPvx0aomk5qPe/O8+76gWOKR1XrEif20OjnQY=;
        b=NWemKDtK9LLtwU2FjV6rLyYe2GSssmDr5ZIH7XL9lO9pKtOKBfKkdVCFli2S+ZNGvy
         qRjxumAtC/A0pBWH0mtWSZrmJHH4mP7hp9zUKmnpKtF6D3wnKjqAg88q3v5NvD9zW6TT
         xVhxDX6bBRLlefMMwYM0xVUIaA4XjCSXE4Q8Zo8ppOqyWjYUQTsKtX4P8elPP0wF00+k
         qPh2GfzEFNzPO4IS92M98FJtsjF1rDEF+FAME8NexFkrgyspBI8pJdlyaL1cSY8/IT+m
         KIM3sLxGVQ/hCSorrtTbN8e75mNTf57FwKxQ1z2nw9UPii+MxQDoc8XJMe8uNxyKi3Tx
         21IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qHuNE5uJ;
       spf=pass (google.com: domain of 3kyfoygykcza052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kyFoYgYKCZA052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id z23-20020a50f157000000b00425ac5c09aesi708928edl.1.2022.04.26.09.45.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kyfoygykcza052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id 13-20020a170906328d00b006982d0888a4so9272183ejw.9
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:07 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:486:b0:413:bd00:4f3f with SMTP id
 k6-20020a056402048600b00413bd004f3fmr26069921edv.103.1650991507458; Tue, 26
 Apr 2022 09:45:07 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:47 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-19-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 18/46] kmsan: handle task creation and exiting
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qHuNE5uJ;       spf=pass
 (google.com: domain of 3kyfoygykcza052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kyFoYgYKCZA052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
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
index ed3630068e2ef..dca42e0e91991 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -17,6 +17,7 @@
 
 struct page;
 struct kmem_cache;
+struct task_struct;
 
 #ifdef CONFIG_KMSAN
 
@@ -43,6 +44,14 @@ struct kmsan_ctx {
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
@@ -164,6 +173,14 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
 
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
index 9796897560ab1..a6178bd28c409 100644
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
@@ -1027,6 +1028,7 @@ static struct task_struct *dup_task_struct(struct task_struct *orig, int node)
 	tsk->worker_private = NULL;
 
 	kcov_task_init(tsk);
+	kmsan_task_create(tsk);
 	kmap_local_fork(tsk);
 
 #ifdef CONFIG_FAULT_INJECTION
diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 933d864d9d467..4b405abbb6c03 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -44,6 +44,16 @@ bool kmsan_enabled __read_mostly;
  */
 DEFINE_PER_CPU(struct kmsan_ctx, kmsan_percpu_ctx);
 
+void kmsan_internal_task_create(struct task_struct *task)
+{
+	struct kmsan_ctx *ctx = &task->kmsan_ctx;
+
+	__memset(ctx, 0, sizeof(struct kmsan_ctx));
+	ctx->allow_reporting = true;
+	kmsan_internal_unpoison_memory(current_thread_info(),
+				       sizeof(struct thread_info), false);
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
index bfe38789950a6..a1b5900ffd97b 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -172,6 +172,8 @@ void kmsan_internal_set_shadow_origin(void *address, size_t size, int b,
 				      u32 origin, bool checked);
 depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id);
 
+void kmsan_internal_task_create(struct task_struct *task);
+
 bool kmsan_metadata_is_contiguous(void *addr, size_t size);
 void kmsan_internal_check_memory(void *addr, size_t size, const void *user_addr,
 				 int reason);
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-19-glider%40google.com.
