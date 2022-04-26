Return-Path: <kasan-dev+bncBCCMH5WKTMGRBK6DUCJQMGQEZYW2XAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F3015103FD
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:32 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id c62-20020a1c3541000000b0038ec265155fsf1481995wma.6
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991532; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZIZMZNTBZ6QRWVvRxChNFKEjnCLiPlvQL8w7Ip4lo5canh0Ap+nImLya6ZPs49fJXn
         FgkVxvCJNx/Oh74CtAhSPqGU5VMwZoYyZXkFUwAf52yQGZUkFPCTGoFKqaKzNu70vqlG
         rUaQqhaU1Kt5XP5TeUBpdq7gwFTHNWrXZRNXivhO3dum9QxdL1/Dc8DtDfQIAT7Tlz3/
         E5LXbHWhwomZXMOi98ezhAM6UhOkjNpUCjqPJ05RARMB9Sf6hBEZ4UHb9nccmZ+KFtnp
         1KfZXYuB3sU/H+69xSsZIah/vmycBsGkqcfdkd5V1SN7Zfmw/9wPA5L0iq/HQrANq7iL
         mthw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=4TH22Rzd9RAHKwnTFUL3vN21cTodVJYS5ivIgpRkOok=;
        b=mjM2nuFa0jTt2A3BXiahUJuE5cP+SPRR9o4DvBeVTrYE6bPpcvcpt1PTFOapITF3q4
         yFvjSfwPQka4p4D9DwznpuWcmzyopycWnInYPXvSBdUNwMollGD2fLh8EBb3eaPszoYO
         r7+gC+XTRCMraiCi8jcLGZOMo7QGDYjPGPxaTc+JEdU/UjeOyF8R1rph+KIfW/xd16bd
         oisqlLl3vUHDTwLoJzge2ArUyfq02qZE8JcYieiJKdMC4IoOVO+7aOV6Mc05UpIaRUP3
         /2VJBcaJ+QWNbovDc34DwE1j8ETYHer0XJ/badpUdM5F2e6LF619vH+QDRdr7M9M3Tho
         BXfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fcJ50fxU;
       spf=pass (google.com: domain of 3qifoygykcacnspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3qiFoYgYKCacNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4TH22Rzd9RAHKwnTFUL3vN21cTodVJYS5ivIgpRkOok=;
        b=IzHWXjzXEW5KDCR/VJlNMQze//i++wvNsITd7IJ5fsuyc490xnAfWn9hRAR8lsMWYR
         JZ272TibILojceSMHNkqPQX18PE5FEOJ+dVn9aEJ8i1pnC9vwuG6dxpB9fhVbHrycVuV
         /Npw7MAfevHGe1zo9ZjICi3O2zUB/HhVWgvtTySBY8FWzwNpAimqKnctqWncDWszk1pM
         YADmEeXhChXKwVWTUuAz5s+8oTLXQhU0NPc6qArfjETTF9Du/M3B/9+AoPeCwbq+vNGm
         fiPpYe35jB0hTa39Ux+tFhgJZmyCwkOWmxCXf1SLQhtaZ9vXVktQmEowfTNpU+zxUJDC
         qm7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4TH22Rzd9RAHKwnTFUL3vN21cTodVJYS5ivIgpRkOok=;
        b=EpenlXjzuXw3Zw67e/UOS6FVRr1qb4BskKPy9MtCivr/iRktQYF+1/NVco8b6Wl65C
         mDwLSB2a3ntH+6iXjJy8hqADDEJvAIJ2gGvOQGd+DAWe2L7aBYf/5iAtMljvGrE6/jbl
         +e1Bkshg5WVy/GhDEEj2mQ6rnBlAFyqeH8RpV2dyZ3LMeRYN+Y6sOa366GcMHjIiQcdg
         fD/QWBXPQhNZgglUUmfTpkRbmnGO8qBPrp4F6BSGe2b3k5Y66yngb1BLsV+T6VNiJ8dg
         xxDrX0s+Q3DvGVrrDBVd0+G4P5fykuSuSIhh/wRJ8Zh7jujw+eMS6VWQKVjUFT8u+41k
         BvuQ==
X-Gm-Message-State: AOAM531DkDrEW6YIVCyRzpWw7UFTyOj1clCYTOpM9zvchQKIsmNeicPX
	wz7WK7kUEuuMcxz+Zfb66Uo=
X-Google-Smtp-Source: ABdhPJy2onD1Lmr58sNiKnZkEmyBz+V1omZ3ZYvfFRfqC5JUmWUtcMxJmeNzuHNT5RBCUvz1xyW+mw==
X-Received: by 2002:adf:f187:0:b0:20a:dfb0:766a with SMTP id h7-20020adff187000000b0020adfb0766amr6959832wro.517.1650991532050;
        Tue, 26 Apr 2022 09:45:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f42:b0:393:edbd:e7a5 with SMTP id
 m2-20020a05600c4f4200b00393edbde7a5ls2755534wmq.3.gmail; Tue, 26 Apr 2022
 09:45:31 -0700 (PDT)
X-Received: by 2002:a05:600c:3d06:b0:38e:d74d:ac4c with SMTP id bh6-20020a05600c3d0600b0038ed74dac4cmr22324922wmb.42.1650991531098;
        Tue, 26 Apr 2022 09:45:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991531; cv=none;
        d=google.com; s=arc-20160816;
        b=mWXPz7PbPcyyV66tkBabXx0OA0neugj/qrfLSDP/oaQILMoTm4TvUBgMQIN7Kg2jyj
         X1m1jwb7vtSvZh+OEdPJNr6Vf064Ec7hdXzJ+562LA3Vgf+cFm0G8LwJKi5b9wlIcPh0
         kb21NwsuaPxrMmidZ5+kO0sdKhwgtVKjv8wmSeJyG862CmCfBjWkcSnR/IWwBPp5/Qsi
         ZtzAvJmbkB56fCnf5Ij8QkFxNtBE+TsIothzWdVFj//F7fIAX8E3RQ666019s4n4ucqP
         TpAnCtxth9RpPCbPgpRk+iel9J7KLi2KBvb0IyXhgijdkpzNGTHYPHMPrK6b001Jqvty
         mSQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=8+FTymzEXuQwrQ48VSTvyp6MK3t+ENPCVe5WmeEaVIc=;
        b=azfrchlWcZEYsej+jqV64IyD5X5EtMa+jDZBoRloP+naK4l3qdcqRg1xJ936OUWUtY
         fQ/MV/1bfzwz8WzIMUQWqKCkRppRNpb3tYzezo7joGPjQ10+9Klzv8ZCDY1OgWeSyJDB
         yvzZ3AwWz032KbgacOTfgj9etp+vBx+n54xyVZGjU1FsAlYlQub2dUdLCCY5BSmAJ2ev
         RMi+TG4+G4yZr5+vaVdKWjlYKMm+rGyNmAeNFSY8YMenF5BRB5C+9uOFp2HVJLWYz/vG
         ZTF2uGtY/a7BH2uQN4L+86gyX3IusKPrJFjJh0QinPFOgLF9fF/IafuUOXifXyh1qhq9
         3uTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fcJ50fxU;
       spf=pass (google.com: domain of 3qifoygykcacnspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3qiFoYgYKCacNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id a11-20020a05600c348b00b0038e70fa4e56si155215wmq.3.2022.04.26.09.45.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qifoygykcacnspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id o8-20020a170906974800b006f3a8be7502so2044018ejy.8
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:31 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a50:eb87:0:b0:425:c3e2:17a9 with SMTP id
 y7-20020a50eb87000000b00425c3e217a9mr22640245edr.109.1650991530577; Tue, 26
 Apr 2022 09:45:30 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:56 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-28-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 27/46] kmsan: instrumentation.h: add instrumentation_begin_with_regs()
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
 header.i=@google.com header.s=20210112 header.b=fcJ50fxU;       spf=pass
 (google.com: domain of 3qifoygykcacnspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3qiFoYgYKCacNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
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

When calling KMSAN-instrumented functions from non-instrumented
functions, function parameters may not be initialized properly, leading
to false positive reports. In particular, this happens all the time when
calling interrupt handlers from `noinstr` IDT entries.

We introduce instrumentation_begin_with_regs(), which calls
instrumentation_begin() and notifies KMSAN about the beginning of the
potentially instrumented region by calling
kmsan_instrumentation_begin(), which:
 - wipes the current KMSAN state at the beginning of the region, ensuring
   that the first call of an instrumented function receives initialized
   parameters (this is a pretty good approximation of having all other
   instrumented functions receive initialized parameters);
 - unpoisons the `struct pt_regs` set up by the non-instrumented assembly
   code.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I0f5e3372e00bd5fe25ddbf286f7260aae9011858
---
 include/linux/instrumentation.h |  6 ++++++
 include/linux/kmsan.h           | 11 +++++++++++
 mm/kmsan/hooks.c                | 16 ++++++++++++++++
 3 files changed, 33 insertions(+)

diff --git a/include/linux/instrumentation.h b/include/linux/instrumentation.h
index 24359b4a96053..3bbce9d556381 100644
--- a/include/linux/instrumentation.h
+++ b/include/linux/instrumentation.h
@@ -15,6 +15,11 @@
 })
 #define instrumentation_begin() __instrumentation_begin(__COUNTER__)
 
+#define instrumentation_begin_with_regs(regs) do {			\
+	__instrumentation_begin(__COUNTER__);				\
+	kmsan_instrumentation_begin(regs);				\
+} while (0)
+
 /*
  * Because instrumentation_{begin,end}() can nest, objtool validation considers
  * _begin() a +1 and _end() a -1 and computes a sum over the instructions.
@@ -55,6 +60,7 @@
 #define instrumentation_end() __instrumentation_end(__COUNTER__)
 #else
 # define instrumentation_begin()	do { } while(0)
+# define instrumentation_begin_with_regs(regs) kmsan_instrumentation_begin(regs)
 # define instrumentation_end()		do { } while(0)
 #endif
 
diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 55f976b721566..209a5a2192e22 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -247,6 +247,13 @@ void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
  */
 void kmsan_handle_urb(const struct urb *urb, bool is_out);
 
+/**
+ * kmsan_instrumentation_begin() - handle instrumentation_begin().
+ * @regs: pointer to struct pt_regs that non-instrumented code passes to
+ *        instrumented code.
+ */
+void kmsan_instrumentation_begin(struct pt_regs *regs);
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -343,6 +350,10 @@ static inline void kmsan_handle_urb(const struct urb *urb, bool is_out)
 {
 }
 
+static inline void kmsan_instrumentation_begin(struct pt_regs *regs)
+{
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 9aecbf2825837..c20d105c143c1 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -366,3 +366,19 @@ void kmsan_check_memory(const void *addr, size_t size)
 					   REASON_ANY);
 }
 EXPORT_SYMBOL(kmsan_check_memory);
+
+void kmsan_instrumentation_begin(struct pt_regs *regs)
+{
+	struct kmsan_context_state *state = &kmsan_get_context()->cstate;
+
+	if (state)
+		__memset(state, 0, sizeof(struct kmsan_context_state));
+	if (!kmsan_enabled || !regs)
+		return;
+	/*
+	 * @regs may reside in cpu_entry_area, for which KMSAN does not allocate
+	 * metadata. Do not force an error in that case.
+	 */
+	kmsan_internal_unpoison_memory(regs, sizeof(*regs), /*checked*/ false);
+}
+EXPORT_SYMBOL(kmsan_instrumentation_begin);
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-28-glider%40google.com.
