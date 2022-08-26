Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCWEUOMAMGQEGUC6LWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 45F8B5A2A6A
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:59 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id m22-20020a7bca56000000b003a652939bd1sf615060wml.9
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526539; cv=pass;
        d=google.com; s=arc-20160816;
        b=S2WnZzegG6QKjvPa1WjrAzUQORMuGUz+YA67x93iD7y2AjAE5c7WtyW65NSKwE3Ekw
         XRL8/JPT4BhbWeCRHwJqK4qSdxKah9Z4JOeEaeeyYmXQI+Gp50OQJbXEWEW77Tzi6k+I
         g0MyTPhSHn4EZS5yAxMtVqvgwrqvCwOP0/5Gz62n70cJMKvj+1D6pEiTIVTnSk2Gl+hH
         AehozwdQpCWetqnlnH6+AJN9aPFHQHCr66aqnzL5ZESgznq2DG8vvZwcIZ5BEKj33v+B
         9k+GYOoEK+xvdGprmLFLC+Xcy9alYrKThmjTfHTfAbRp13uitVfTj/6CV6QJ2OyGkkC7
         cGzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=bSvAgrdzaGrz05S5TIpfi3l2BKTrr/o1+fm+rWiCkSE=;
        b=dFNyqVsbpBPpYQEw9SU9SnOme+JMlC9X/g+wF2JhRIlFDuxDj+axth4i7yVCyZUSip
         fdQ/Ksoss+vBRXKIjKsfa5Tzc2r+tzGmdmzmAi11rtfQRjMXrYKgKvB4nsPymHjcj169
         qYZ/CmIadQGFnri95iNRwAStvGUB8MxJFEVmC4hozxVb12n9hdr4/jgKJFiSZK/2MLpf
         0XsywoU04qqeUat2XouM3NNo5WOEFMs/CMaAcox/CeasMZiv/gYoEoWrwTaT2B85fkpE
         ljaQuVa5f/GEg3MGiETkCUCdfIfQ4lLOS8f9Wf6d2AjFF0EKw2c7RdzAG2WkGgfcNDea
         JZ5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PxLdCUrn;
       spf=pass (google.com: domain of 3ceiiywykcraw1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3CeIIYwYKCRAw1ytu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=bSvAgrdzaGrz05S5TIpfi3l2BKTrr/o1+fm+rWiCkSE=;
        b=QFP/lG28pJqY0zvU1sM2XimDoq/7AwMOlj4bUjlFnEiRJrNpuxJsx+wDtynOg4DeP5
         qXeyFw8+SvtRbVqpSMW1FpeQjhWk8XzaDWBdodye4zjERu5RiCb1YdKzzC1gND7AsnbR
         nRPeGJNSL/dUb7jo6lk1XbzfzqkS3USWEDtXaE2mGwnDw7guBzrIefYVcU9mZ/Pk8zj4
         YC11ShDbHEY+N8dIw8V6FiAtz+4royp91YCTAAr+z87LaHR28MgCYjS4EOcc/0F/U9Gt
         Kr9DBc3f4VftPtCpDYhxjXQOPEymF++k/6xmWBjgXamyPbIjC60z9Bj2plGGU2sQAIMB
         RUhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=bSvAgrdzaGrz05S5TIpfi3l2BKTrr/o1+fm+rWiCkSE=;
        b=0dpgWbZPLgmDvl8SLj3Vm8UMpAyJUkEK6Etg/GC4EX+/fGC+pQSYVMdAXVS/8/2Oou
         dr4dW6IQArY2PbEMT+AANr6otENv/xP1mtBPLEf6P8ipz6pMlSbQkEL0Rb6gi4+3uwbL
         8QicT9ZhrTxfaLzdyycmRSU4bFKVH/JVPiE8cdR2fvffS6qTuue8iRdiPrU+c6l+CUYL
         qU3WrIai6TrNSt3ZpWoltxKrspREEEQs0E+0h96gACYnh1JmFgTjf/tp95pzmbumBQcz
         LdzPZtIULN359HlQ+ZNf9FOJQP+wXY/WlPhM9+PjseeQGDBF0dqbO/mZPCDiUfrMDu/a
         1HbA==
X-Gm-Message-State: ACgBeo2KVg5IgvNFkVMXhfhbpL/VtZrEuvI+9svxxvZLQ+Q8Y0RR9XMP
	frGvAzgA+FN0W8o24VtenAs=
X-Google-Smtp-Source: AA6agR68g0tzaNCRMYNm9WXnMTjDVOVVK6PqsgKUJ18uPMKiL4fy/ubuyVLUdt7yll8wp85KUBOZUQ==
X-Received: by 2002:adf:d1c5:0:b0:222:cbe8:f9fa with SMTP id b5-20020adfd1c5000000b00222cbe8f9famr48627wrd.383.1661526538943;
        Fri, 26 Aug 2022 08:08:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbc5:0:b0:3a5:abc9:1b3b with SMTP id n5-20020a7bcbc5000000b003a5abc91b3bls27589wmi.1.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:08:58 -0700 (PDT)
X-Received: by 2002:a05:600c:34c2:b0:3a5:d2f5:9d02 with SMTP id d2-20020a05600c34c200b003a5d2f59d02mr5902955wmq.153.1661526538033;
        Fri, 26 Aug 2022 08:08:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526538; cv=none;
        d=google.com; s=arc-20160816;
        b=jT6AjOHnulHjk6Mc3lTEiOJ5YnRatDMalD7WYkVYiqy/ZXj1Zv1OQ+++4Mp2rG4ZVL
         TshVRsJBkKPcUwrExh0QfZUnOlz/sZSRdVWiHXIGGbAMnWakuhQc5U0OTyit7Bbj6YkH
         Z6cvmwgaUW4I0dXBYwtNv/0pJHynwrQqnZuP80HATU3VEkB+aoT22aEmggfPwa9BeSZW
         d271Wfqaf0FdRZsB2M8rmaVZuGfX+UXotkM0TtBa76dlY0+2GloRYrlE7loOTbpm241j
         bb9/03UyBzETUn09hCTPe14MTJzbj+Lj2/44IBdbxDKLqppmgwczDrRYn8/wCx1z2k8f
         x31A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Oj/n9T6llj5wDAAKfJeFunm60o607TLggj1MRB6CXqU=;
        b=0hLIk8RTs67C7NYeMLfAW7gd2WNPHC6wacCHYQWv1g2PzmvYpcuH0im1VNtHsfaJNe
         lPItdBCPpUKCOBJNUg2ZPWqyw4rSzwnBvy0xe096XmHLEv4R704oF2N2aMEtXi/7Hll7
         g73rasnvHtNiY5tYNR6WUFTL/+rtLKwDw7gD1FFsjJTNqJL+oDLeAs8q95PYc2pqUl8r
         XFvCvSG1ggqoEgkWM0KHCy3kuaW2AqgG/yD1KVE4cbw19LhejZrO3dHo1NEGOrqAtVAt
         BfVnr2GK1PStfjislWz2BqD/T1F3d4ajBZrC7zO3q52g41noI4Xf5I4PDdGLO9A5v+qH
         m9cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PxLdCUrn;
       spf=pass (google.com: domain of 3ceiiywykcraw1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3CeIIYwYKCRAw1ytu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id r5-20020a1c2b05000000b003a66dd18895si573684wmr.4.2022.08.26.08.08.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ceiiywykcraw1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 203-20020a1c02d4000000b003a5f5bce876so4197922wmc.2
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:57 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a5d:6483:0:b0:225:7fb7:f163 with SMTP id
 o3-20020a5d6483000000b002257fb7f163mr49905wri.391.1661526537522; Fri, 26 Aug
 2022 08:08:57 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:39 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-17-glider@google.com>
Subject: [PATCH v5 16/44] kmsan: handle task creation and exiting
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
 header.i=@google.com header.s=20210112 header.b=PxLdCUrn;       spf=pass
 (google.com: domain of 3ceiiywykcraw1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3CeIIYwYKCRAw1ytu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--glider.bounces.google.com;
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
index fd76cea338878..5ec056380a43b 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -16,6 +16,7 @@
 
 struct page;
 struct kmem_cache;
+struct task_struct;
 
 #ifdef CONFIG_KMSAN
 
@@ -42,6 +43,18 @@ struct kmsan_ctx {
 	bool allow_reporting;
 };
 
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
@@ -163,6 +176,14 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
 
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
index a5dec6e62b4ef..a640e0cccbb64 100644
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
index 519a7a1dcb4aa..4ab8c629acd0c 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -26,6 +26,23 @@
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-17-glider%40google.com.
