Return-Path: <kasan-dev+bncBCCMH5WKTMGRBC6W26MAMGQE6NSPOXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DF535AD288
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:52 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id l19-20020a056402255300b0043df64f9a0fsf5759163edb.16
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380812; cv=pass;
        d=google.com; s=arc-20160816;
        b=o0QtFVJwjpiaCNqDCJIKELVExwJ2zkT3qQ8Z0U5/pOAX/AETbb2V3mPbm+ndPK8K9V
         tu6TvQbxuSDgXd5ZMKP1jtm19wjv3OJwKJVYt3Oop1HyLOOnzlYFoZXnFIB5pLcVU9Cp
         se6nAYbVJydF6v+aUxRiIKEdqeo4blbg+4submcQvUdWpvyXhwOxu7ocfJbKG/cJOe5a
         ba6F7onFK34+a+GLOMVdKm3ZApVHuYhZzNJPckPOFcLqyiVdDww1qnugdapjBAwrDvln
         6SF0m8QpD/yj7ZI2MSg3Zypw43QylVFTHTPvB/QlVfKb9qPd090XGLnMQ4SNCWKnnLAZ
         Smvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=8RCnjr2B70zewiyj+hOBb57uT9YmjaUI3nA2Dwouscc=;
        b=M9+QMi0/n4pTluMUw5YERamB7TwVxI3iPoFMUz0r95QnH5mIwuOusY88KPv7osrDm5
         TND/g1NTh5yfiWe8AaTl6dQRj9pFcUFAHTsMjw/p/YjMeXxSvy3h0O6QvNbp/Dy0TIsE
         fnRHJAsOkACbWaOvKqxP2bpv7vdtSI3RxldKYPl74/yJe9oVQYnH7c/T8y5mwUXGF87F
         pttvzq3GlT2cRH012bo5c8Vx0JXQm5nRAVyiKPBZUIKlxqKbZPLnsyYir8GJuP2UFVOE
         0lHiiWfnXfTELEcas1IExF9w3Ij69ct9kCoG+W7gC9sfZwsezzUIOkVzp3m1DNnniGPE
         kzIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=S7wqzmIT;
       spf=pass (google.com: domain of 3cusvywykcvc5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3CusVYwYKCVc5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=8RCnjr2B70zewiyj+hOBb57uT9YmjaUI3nA2Dwouscc=;
        b=r/rolCOww80ZqIdu8G29EjkB83UbBqha08LFaBAInY+YRPAR62ENWZYhMuVQkDhhz6
         QkvZYvW0xj1oHbv1xogTUfssGcObzOygvFauq9pJJTUqAYPcV3DCOc8RACDBFcj1X4me
         /MrZt/IlS9GGKdHfdIre8a+DQXbQMRIf1BoJUl2pCSQbteyfdaeGpil6dvUUkfL/Q6wE
         8cR1SklE9BkoKxekU7jo+8x1jklzIvP3gX1FUxjw8cptVRJxe4xJGiFC5wtLG9aQmE7Z
         CSf9QKEJHqpOas8gwYNX2/+DZ0CTIvJTrCxYFqEjMMGPguvydhfGJstrxNCsZ3EFmm/o
         ZveA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=8RCnjr2B70zewiyj+hOBb57uT9YmjaUI3nA2Dwouscc=;
        b=DWDYac/OXX/nrcrf93ALjMqUte3twx+OqHrjYGuN4bxyT1GUDcO/FjXH0awYmfMiZ6
         zSbBAkjQT5yckL0BDf74PA7IBh19YPcl9YDI/IOnR6UcJzyxAkncseP15n8NTFe08guQ
         WYs0N5SZxh29DK/sRqKjGCGTqQsiffcBcs2jGYhOHvtO+L+soGQ748dXJIgJ4nr4ZBHw
         79UUg1wRa3xiR3ijki1l67gThQN9c8psASbkklma8vDDcp9UqgWlhaivhh1Td2kUGcPd
         64dzqyapzsb1+uphTZZbBqL3DnFhezUIRl6tGx+GJHc/A3xC4hG7UBaxYLMLyuRXBkDE
         Gi8Q==
X-Gm-Message-State: ACgBeo21gkhES4+99/YNvchXFWBy3wZACoTbekT6VnASW3X+9Z+h4UDA
	wuLI27Wjq0BWPSA/57Jra7M=
X-Google-Smtp-Source: AA6agR7DnMGPx7LW96ku4LJDV63aktWGsQzrIXo9Y3VoVgHuQlDXwXXlh1vzab8hJx/3j4PTmA+maQ==
X-Received: by 2002:a17:906:fe46:b0:73d:939a:ec99 with SMTP id wz6-20020a170906fe4600b0073d939aec99mr35881729ejb.169.1662380811900;
        Mon, 05 Sep 2022 05:26:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:848a:b0:730:6d43:91d with SMTP id
 m10-20020a170906848a00b007306d43091dls3419217ejx.6.-pod-prod-gmail; Mon, 05
 Sep 2022 05:26:50 -0700 (PDT)
X-Received: by 2002:a17:907:2d2b:b0:731:2179:5ba with SMTP id gs43-20020a1709072d2b00b00731217905bamr37657007ejc.207.1662380810878;
        Mon, 05 Sep 2022 05:26:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380810; cv=none;
        d=google.com; s=arc-20160816;
        b=XMbGzv4c8ExUaueRErKl7m+XcwxpfFObYkvz4jZ4dnn5yDJl15ezNbNdLq7AVUz4oK
         uekV0s+6BEOLRLh8aQ+GiO11uzrXEnWyBmpFYpe9203bec0sFvYaap4dzHBo/eZQqYrB
         JC3HdtUjeTJK7vYHEilcD5+lPP9vgaseowpVOtp9k+sFCaV62imEGbPmGyqvsfKitLHI
         3Y8uszAi9foQQCTyb9rEJL2eZQKQqoRKHza5t2htvnMWycyqwS4dvV7ZosqDdlgWr/+a
         lQxs5SZULPYzDAoJzXKQNLL5GwY6swtqy1v01i7YyHxRb8N5u7rylaEqCNi/o4RG3yak
         /MMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=S+kwzH5LfDyg6tc+T47KWRR4zTWxpHjqyuN2TRvGEwc=;
        b=W+ZwvSkH522c3bF5kDDvOG3HIC+qmOPz8/ixI7N6Ula+0giLpIWQHSe9xk34WQwwEJ
         J7jgJvo4bb5wYR8okT02q6m/mktMdV5ZsrIf6v1hPVl//9z4PZFlAcaxVzeYSUv7EmiG
         f9SYAoandVVY+Ux1RE3EsMV1W8zWr7RmKBeX9KKC+Ad+hxfupZtImHRLHmtpZwvvldls
         nMXSaO9EXF8uJ1+fGcBjE7KoBfpfUr/On/aOdCj+YjWLUZ+fg9VkXqVZjw/f1wXv8/HR
         40xM65vDS/ZB2xz88Peht7gKKcYbX1Fx5eEh37qlnb59s31dxkNvilo4CaN7rGtcRDwK
         691A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=S7wqzmIT;
       spf=pass (google.com: domain of 3cusvywykcvc5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3CusVYwYKCVc5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id og36-20020a1709071de400b007415240d93dsi373825ejc.2.2022.09.05.05.26.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cusvywykcvc5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id y12-20020a056402358c00b00448898f1c33so5692432edc.7
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:50 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a50:ff13:0:b0:43e:76d3:63e1 with SMTP id
 a19-20020a50ff13000000b0043e76d363e1mr42442604edu.271.1662380810584; Mon, 05
 Sep 2022 05:26:50 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:49 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-42-glider@google.com>
Subject: [PATCH v6 41/44] entry: kmsan: introduce kmsan_unpoison_entry_regs()
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
 header.i=@google.com header.s=20210112 header.b=S7wqzmIT;       spf=pass
 (google.com: domain of 3cusvywykcvc5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3CusVYwYKCVc5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
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

struct pt_regs passed into IRQ entry code is set up by uninstrumented
asm functions, therefore KMSAN may not notice the registers are
initialized.

kmsan_unpoison_entry_regs() unpoisons the contents of struct pt_regs,
preventing potential false positives. Unlike kmsan_unpoison_memory(),
it can be called under kmsan_in_runtime(), which is often the case in
IRQ entry code.

Signed-off-by: Alexander Potapenko <glider@google.com>

---
Link: https://linux-review.googlesource.com/id/Ibfd7018ac847fd8e5491681f508ba5d14e4669cf
---
 include/linux/kmsan.h | 15 +++++++++++++++
 kernel/entry/common.c |  5 +++++
 mm/kmsan/hooks.c      | 26 ++++++++++++++++++++++++++
 3 files changed, 46 insertions(+)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index c473e0e21683c..e38ae3c346184 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -214,6 +214,17 @@ void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
  */
 void kmsan_handle_urb(const struct urb *urb, bool is_out);
 
+/**
+ * kmsan_unpoison_entry_regs() - Handle pt_regs in low-level entry code.
+ * @regs:	struct pt_regs pointer received from assembly code.
+ *
+ * KMSAN unpoisons the contents of the passed pt_regs, preventing potential
+ * false positive reports. Unlike kmsan_unpoison_memory(),
+ * kmsan_unpoison_entry_regs() can be called from the regions where
+ * kmsan_in_runtime() returns true, which is the case in early entry code.
+ */
+void kmsan_unpoison_entry_regs(const struct pt_regs *regs);
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -310,6 +321,10 @@ static inline void kmsan_handle_urb(const struct urb *urb, bool is_out)
 {
 }
 
+static inline void kmsan_unpoison_entry_regs(const struct pt_regs *regs)
+{
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
diff --git a/kernel/entry/common.c b/kernel/entry/common.c
index 063068a9ea9b3..846add8394c41 100644
--- a/kernel/entry/common.c
+++ b/kernel/entry/common.c
@@ -5,6 +5,7 @@
 #include <linux/resume_user_mode.h>
 #include <linux/highmem.h>
 #include <linux/jump_label.h>
+#include <linux/kmsan.h>
 #include <linux/livepatch.h>
 #include <linux/audit.h>
 #include <linux/tick.h>
@@ -24,6 +25,7 @@ static __always_inline void __enter_from_user_mode(struct pt_regs *regs)
 	user_exit_irqoff();
 
 	instrumentation_begin();
+	kmsan_unpoison_entry_regs(regs);
 	trace_hardirqs_off_finish();
 	instrumentation_end();
 }
@@ -352,6 +354,7 @@ noinstr irqentry_state_t irqentry_enter(struct pt_regs *regs)
 		lockdep_hardirqs_off(CALLER_ADDR0);
 		ct_irq_enter();
 		instrumentation_begin();
+		kmsan_unpoison_entry_regs(regs);
 		trace_hardirqs_off_finish();
 		instrumentation_end();
 
@@ -367,6 +370,7 @@ noinstr irqentry_state_t irqentry_enter(struct pt_regs *regs)
 	 */
 	lockdep_hardirqs_off(CALLER_ADDR0);
 	instrumentation_begin();
+	kmsan_unpoison_entry_regs(regs);
 	rcu_irq_enter_check_tick();
 	trace_hardirqs_off_finish();
 	instrumentation_end();
@@ -452,6 +456,7 @@ irqentry_state_t noinstr irqentry_nmi_enter(struct pt_regs *regs)
 	ct_nmi_enter();
 
 	instrumentation_begin();
+	kmsan_unpoison_entry_regs(regs);
 	trace_hardirqs_off_finish();
 	ftrace_nmi_enter();
 	instrumentation_end();
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 79d7e73e2cfd8..35f6b6e6a908c 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -348,6 +348,32 @@ void kmsan_unpoison_memory(const void *address, size_t size)
 }
 EXPORT_SYMBOL(kmsan_unpoison_memory);
 
+/*
+ * Version of kmsan_unpoison_memory() that can be called from within the KMSAN
+ * runtime.
+ *
+ * Non-instrumented IRQ entry functions receive struct pt_regs from assembly
+ * code. Those regs need to be unpoisoned, otherwise using them will result in
+ * false positives.
+ * Using kmsan_unpoison_memory() is not an option in entry code, because the
+ * return value of in_task() is inconsistent - as a result, certain calls to
+ * kmsan_unpoison_memory() are ignored. kmsan_unpoison_entry_regs() ensures that
+ * the registers are unpoisoned even if kmsan_in_runtime() is true in the early
+ * entry code.
+ */
+void kmsan_unpoison_entry_regs(const struct pt_regs *regs)
+{
+	unsigned long ua_flags;
+
+	if (!kmsan_enabled)
+		return;
+
+	ua_flags = user_access_save();
+	kmsan_internal_unpoison_memory((void *)regs, sizeof(*regs),
+				       KMSAN_POISON_NOCHECK);
+	user_access_restore(ua_flags);
+}
+
 void kmsan_check_memory(const void *addr, size_t size)
 {
 	if (!kmsan_enabled)
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-42-glider%40google.com.
