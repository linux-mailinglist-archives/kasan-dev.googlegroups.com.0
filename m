Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5H6RSMQMGQE7HIVBSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 822FC5B9E32
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:29 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id h133-20020a1c218b000000b003b3263d477esf9722970wmh.8
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254389; cv=pass;
        d=google.com; s=arc-20160816;
        b=JA1JPASRkULYGo7EYRXa2a4LD3owclLkNkUBMqUnahdO0ukzh2oxclKBsigsulEqHO
         p4dwo7yFcTs4oYX7ivqWzagZcoOlcSVGOjStKW2UD2KNIQ9EjkIhsSFadjIPUjiwNyB8
         ZW4hLtLFK1RqTDcS3sxmAIddZa2gLvMpi19172QGmxYhCB0SA7EtYlyhZCE1EvHHB2+n
         glWn3bcbvlynr1IznD7eSjY9hFJ8IGI1yydMrN6F8yRiGnpZld3AwgRKLrTJku+Ezc2Q
         ZX75OXUKd91waXiDH1JN5cP9jpefXNpASS48wqtD0iLUhb7dCIJw36le0hx9fzxxmq3W
         tgwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=GPA/Wulwb18LMqLiO20imeXRW/XqD70ew+Obc7FK5YI=;
        b=wXqBmDRpI4a0LZLllZlshqiEUAAXNElpbvQ/fftgzKgG8YBCAD7m9GHURG+R9hkFUS
         h/TlE/stDZ3yGQwkyF/OG4LWEaPRsKAzTT3X8iWOQj/nut0JJTWBow1u060sENtJOAmN
         M5YcQgV1cSPo071Gcetlshg1lVsL4C8Qa9CjtcBKs3UdlD3W17Mlt3osftB/AnEe587y
         9Gp36z01MBaJSvZVdB6e/Yf+94Dy4tOL3OCBF9rI6BANsAB3MnNW4VkbHstf2Q2kT+UD
         FiiVh7Umpm+N29RAesC4HJ7EOvrNkbOJ91u15qLRU7/b3c3FMKpG57FfmfKflYrMTODN
         g5Rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ikiVkwTW;
       spf=pass (google.com: domain of 3cz8jywykcz4ejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3cz8jYwYKCZ4EJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=GPA/Wulwb18LMqLiO20imeXRW/XqD70ew+Obc7FK5YI=;
        b=mv6t4d/T7qRLKbZPpWA/Dy5SAQIwwH0gbjpwLT81Nl5zmr1lWGDyxTVOLxpccuxKMh
         e9xF/Nl4VLg0AP2UWE4fKlKm4cybd7+/AzjGQM0LbZkgDjrS65HNx0GzcXE9KAe79Hrj
         nqeI3t22YcsR/oBI3mdV/N8EI8sP3zDkqtV19TQS6dvLKGkRyYhWpo65T7wCrStxzMDT
         h8dZMh83OTUW+2amcTZEPEkqsRDK1i6+wb6cjZzIXk3i3XFg0PqarPt/KVEGUvHsFZLR
         sfR3cVN2obVQdBUCumSevso5KaxGnYz/1tLisoWsjSMRylfH5r0MQF11rjoZ/1himJ70
         A/Jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=GPA/Wulwb18LMqLiO20imeXRW/XqD70ew+Obc7FK5YI=;
        b=S+M+Uw/W/frQNlYZjbc/a5CAE5eCc3Mlgkh6Z9ZFa78emJ3GYDXMht8/DCWLnj3U7I
         YqXjSyEJ0SPBXUBK+bK0OYLJCy8HMLbFfIqgcYfVe6vlR+twv0zqIfWTuCoQ1D2j0Ro+
         cwzMW3juEGNY4Xmemb30DhJkMIZPkeTEycVJy+iZa9qt9t7i0xulJrpq+iCNoBYJPsra
         8OgpR4sFvPC7mC6CGb9X3k2o+jk4pmSCAaAV1JAIwx2axiN+1cchqraY7nnJ21h4vhZT
         SMLyexdoN9HRyPYKG+MQ/vRCnMeWFot/bOfIW9NAmv8brrb/sBSsoWnXJ203tHIa+FK6
         eDng==
X-Gm-Message-State: ACrzQf0EQH3KKKj51KhIF3X2oXz9bDFRyS6sMMIxUrJjS8CI/TBRu8Mf
	CMjP9/EtbK/ZU6cKrP+5BQU=
X-Google-Smtp-Source: AMsMyM4nC3L1vmWxaFM6fXfYJ0qJPfDENhP6dBAy5I0+3tmtvw0eBKJl9iWlwdXh9XIeQB5CRdWi3Q==
X-Received: by 2002:a5d:4a41:0:b0:228:48c6:7386 with SMTP id v1-20020a5d4a41000000b0022848c67386mr48446wrs.649.1663254389176;
        Thu, 15 Sep 2022 08:06:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5102:b0:3b4:76ca:bee3 with SMTP id
 o2-20020a05600c510200b003b476cabee3ls4926197wms.0.-pod-canary-gmail; Thu, 15
 Sep 2022 08:06:28 -0700 (PDT)
X-Received: by 2002:a05:600c:4856:b0:3b4:9aa3:cb57 with SMTP id j22-20020a05600c485600b003b49aa3cb57mr201131wmo.116.1663254388132;
        Thu, 15 Sep 2022 08:06:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254388; cv=none;
        d=google.com; s=arc-20160816;
        b=TiJHNyExVjt5nBljnQygax4LH8vxunBaviO2hlpVVfcTjj9b5ul2kYvKQeQLkLx0sl
         C30m0DolYumq/qT9eKTyDCJXtI2BbMO/xcwkgLIKWPyv50CLlXqnQSum0fJUQNE0J49U
         YrIMcaAFaARp31r6wP2IlmMY7WEIO+sNtTou5+xGvT4ItAB5V8AjarLdgDgA+4zCd6Vn
         c8SkgGct+l1ZduAql1j0/fcyD8mBxdXnqcKmygubWfFvnJqnYSr5bEDsDKTW5JynByIO
         ghj6VUzpL1uDjvfG5Bsk8Gl67J3cTfl8ywoCKEOtFwGMoRSHJJ6xoQkkw2NvhOpqHIBf
         rszw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=S+kwzH5LfDyg6tc+T47KWRR4zTWxpHjqyuN2TRvGEwc=;
        b=QTrypbljBFOHWvfP8bL5TPXhkFRteCJtqxcqSKluG+IkeUmXUc8e+fQ7sNfCOseAuI
         FHxYsCPvdzpTGRs4jM2kCcC5MkJmeBRzx2NXlJ2D66FJpMgwo0BbNfARxBr81eUjB0md
         nq8PFzdabbgTjyh5qUGSa9DRaoKE37r6GTojwY6HTmNMa4gJdhENrrleAh+9CnKAPiB7
         xsznL3mV2jVlkqjhdzvwrA+MFsmYlP6Mhow+BPI4Ze1DVkr2dv8JYyyFKt6Nf8H7eUbZ
         Q1KQ6bUD4NqneyfMqxvAn2RBCtM5YVzyaPkgAO6NRaPZoCmX1VlPLk0uGZ4nlJ4up3Xj
         JGYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ikiVkwTW;
       spf=pass (google.com: domain of 3cz8jywykcz4ejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3cz8jYwYKCZ4EJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id bz7-20020a056000090700b0022ad6de79d6si47941wrb.3.2022.09.15.08.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cz8jywykcz4ejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id q32-20020a05640224a000b004462f105fa9so13078309eda.4
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:28 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:906:5a5a:b0:770:86d0:fd8 with SMTP id
 my26-20020a1709065a5a00b0077086d00fd8mr329690ejc.164.1663254387679; Thu, 15
 Sep 2022 08:06:27 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:14 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-41-glider@google.com>
Subject: [PATCH v7 40/43] entry: kmsan: introduce kmsan_unpoison_entry_regs()
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
 header.i=@google.com header.s=20210112 header.b=ikiVkwTW;       spf=pass
 (google.com: domain of 3cz8jywykcz4ejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3cz8jYwYKCZ4EJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-41-glider%40google.com.
