Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUGEUOMAMGQE2BSZLFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EDED5A2A93
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:10:09 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id t13-20020a056402524d00b0043db1fbefdesf1249221edd.2
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:10:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526609; cv=pass;
        d=google.com; s=arc-20160816;
        b=HanB0pQKkWVyVMJ11tDMXJat0r/01NfOV4D4qCKDheALAxwbh2SMpByF08vQ8uv+OG
         ThsTkYiq4OwpJ8tS/ERmvvX/7EX9b3w7fT0L7fjukE7/n+2vy0vhzpiokZsYYex53qFS
         fKiwGH0JQ5Gp0jY63D/JHB5E8lIYm0O1KIZFQeBAx3XGp/yiBNa5bIPBu+tB8eXyjoLJ
         fqUou0TtTslgvofgiacQ+tRb4hSwCdqLIdVAXKH0FNFE5qujQGr7VOQ+sV37BORp90Wb
         Yd+kDpZ7OpOmxPBjxwV+Ao2fWsM69LDaUx52kFsFPKu62ROJmLTl9pU2Ev9lNBNZije+
         khhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=4V0RtByw2kCoMRf9vOzty4Yqnaijea88JV4gpLSzrW8=;
        b=ZrWjjf0XlEaVxWdSWySkpVzRRLRoA38EnNHh2zpVye/acs1lD++qs1ZTC1XXeYSpry
         tvysjGBb95eHFUi354mzddp9vGKDUih16/7JjXV/lP8Z1FvhMZce4jYFUfsSGn0aSwzM
         YLF3eHzkGaXCmS13+GIY/L02fJdKYM8W01AhAS/oabiX788PModZF8zHUba4yPFUyrqL
         j6/I2p9dnwkWmdbj12kjfX9uFaA8ObckQ8kSwkKujDgKvum0M2WB2RUufSy8yVeMDX2G
         Au+KDCrW11dJurrymPpTWBVqP9/xa13iprG3qF9nZPWuZaZurmtau0TbZ4xClFGFRI5Z
         acdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XuSgIJWo;
       spf=pass (google.com: domain of 3t-iiywykcvy49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3T-IIYwYKCVY49612F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=4V0RtByw2kCoMRf9vOzty4Yqnaijea88JV4gpLSzrW8=;
        b=IM1Xxl9KnlxC8arswj7WNK/G3bsO+pBu/ie9UFl59Dcr5US3wMzHxxY0wvS91bk675
         SVa7cBCnGUzHs2hYs3Po7dXyr2NiFbiNj3/bIb7T/vk6kmcZPdEEBzJekdmifv8vXeEo
         eFTuT/5x5TVYMZjay2AAegGRJyKrBYCy6XsqoiIyNAW2L+khanmEMxvVJ2pVTfham3Q/
         jhcA3utxjkRBm8FtQF6kmWCnsdrUB0gQA9xy6jTiYYMo0bCVmk0N6MnjJcd+yPm/7pv0
         yYqi5lZmgtb5zZSiSBp1RlqWGHsd1P+JnAwYEoMYUJclEdeT9CGOb79hs7RCchtjzb7x
         eTHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=4V0RtByw2kCoMRf9vOzty4Yqnaijea88JV4gpLSzrW8=;
        b=EnecoNdGJJUz3FeVBPFAXFG6ADy61i18oTMb0auA5tBHfIHLLKqn56XflDvsMINFde
         0s1haJY7vUwgUS8LDnlb8nc/QnRzHkHqSZlbOB2XfCbI3rSSYvWFi0RuhMd/gPh30mM6
         mNQY97xnS1mXGG+zNRALtGwIej92JCdAGPZ0JDs5NGoSWPboGtODV1Vpla5qQo2gVK08
         /vGUfJOxQqA28spg6xQE6HWvNIbqIo4gNoxr3jRlobMxjU/74tzh2HlzWAkZgYQJc2DS
         CESUYIFjD0k0Zmbg/B0JZeg9jYOwGY4fniy9+YX9B7Sz950P6eGeVA4zGK/gMekZd6iF
         dmEg==
X-Gm-Message-State: ACgBeo3leQ8Rys9N5KbK/oNNVQlZAw6Se5wAJ5l+E7DarpzHa2VV8+i7
	Yx+fh6fUa8mS1NArAKsTFaM=
X-Google-Smtp-Source: AA6agR4gHkHnpO2QlSiMiCVyUzHo9Njd+m7pQOtuOLuu0NPIztIButca55JAVCpKsFBK5ygldUIT/w==
X-Received: by 2002:a17:906:d54d:b0:73c:d3e0:5144 with SMTP id cr13-20020a170906d54d00b0073cd3e05144mr5728952ejc.753.1661526609177;
        Fri, 26 Aug 2022 08:10:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4408:b0:43d:b3c4:cd21 with SMTP id
 y8-20020a056402440800b0043db3c4cd21ls4519714eda.2.-pod-prod-gmail; Fri, 26
 Aug 2022 08:10:08 -0700 (PDT)
X-Received: by 2002:a05:6402:e98:b0:441:a982:45bc with SMTP id h24-20020a0564020e9800b00441a98245bcmr6864332eda.239.1661526608186;
        Fri, 26 Aug 2022 08:10:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526608; cv=none;
        d=google.com; s=arc-20160816;
        b=iJ/MjGa2+wfwGd/WuM5w2chp6ae9Yfvb+20nSrfpcJNUNVRWGQNtB5TulIVU5rDE4w
         6txaw+O4sWHkj8VS6Tw4m7hky8K8uEdx7Cxh/5kpcgQTEwVpL0q5oRDVDqtdMb8fZ+ai
         6RQhMTZIdfXp7tPVxtGHu7spsYYhY05hG9yZZRikqAk/NkqU7AHVJpLf7AVS4+6LQGoe
         nd5UnX1I/o5NUH+b8vIzAHVIDppT8IOylV6JYC7FRNKb0Bt/dClSy4dXoSzYh9GKRzla
         HatiGjHfdux/zwfyOnapEIl7wj9WVnxUtKhmESRKN9xn9Ml4vaAnf6NCSWj2Mu0Rgh8b
         hAmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=VDn7tLtoTqUri5wCNae2jgpDMB9XRf/m0RZ2a2IuTLU=;
        b=IBLKUySN59mhBDeHLENcmuNr+qEgr0GdFm2bMPhLrnReLobAtJ49AAml3+stvCtUtP
         De5J5j3MJOnPpyy2XZAnx/nynwZ1TiCEMPusCck135J5O1GwPR8lTx7z1IRmQrF+rb9Y
         VIjoMv5+8TY0jJH44RmHAIf1imVF+kc8yZV41cXcMrhXbENauBwzBlXMR5E2JW0WHkeG
         i+E3tXQ6ZGNTCvk+2+CED33aVwU0el5yrf6wI+5JyfkPWgNsGXK+1MTv4qcSYKxliDNW
         nWkWU69dKJFFavr8xkYuj7C9r75VnB/034xlu7m092CmlCJDT52gz3WOYhpPHequYh9r
         DiOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XuSgIJWo;
       spf=pass (google.com: domain of 3t-iiywykcvy49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3T-IIYwYKCVY49612F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id c2-20020a056402120200b00448019f3895si34426edw.2.2022.08.26.08.10.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:10:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3t-iiywykcvy49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id s3-20020a056402520300b00446f5068565so1237232edd.7
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:10:08 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:1f87:b0:43b:b88d:1d93 with SMTP id
 c7-20020a0564021f8700b0043bb88d1d93mr7088766edc.314.1661526607921; Fri, 26
 Aug 2022 08:10:07 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:08:04 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-42-glider@google.com>
Subject: [PATCH v5 41/44] entry: kmsan: introduce kmsan_unpoison_entry_regs()
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
 header.i=@google.com header.s=20210112 header.b=XuSgIJWo;       spf=pass
 (google.com: domain of 3t-iiywykcvy49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3T-IIYwYKCVY49612F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--glider.bounces.google.com;
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
index 84dddf3aa5f8b..f4015a7546e39 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -238,6 +238,17 @@ void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
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
@@ -334,6 +345,10 @@ static inline void kmsan_handle_urb(const struct urb *urb, bool is_out)
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
index 58334fa32ff86..14d6c78a793b8 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -347,6 +347,32 @@ void kmsan_unpoison_memory(const void *address, size_t size)
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-42-glider%40google.com.
