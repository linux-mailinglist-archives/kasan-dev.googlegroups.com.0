Return-Path: <kasan-dev+bncBCCMH5WKTMGRBO76RSMQMGQEYXHSTGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 551AC5B9E14
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:33 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id o15-20020a056e02188f00b002f01f1dfebcsf12693216ilu.10
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254332; cv=pass;
        d=google.com; s=arc-20160816;
        b=GmFDEuGD6ETeylHEp8bBCVSO3SumWAKrzyj/3MaeIUmRlkao14SSgNSrGP/BRFbtE9
         6P/sug/OoW+gZute/AIJ+DPf3FGQuf6WdZbgE/xKWjaHG3AtG3CVfcuLy2jGM+VCPTej
         oZy4/M8lkfAXyXnLXcKMogqt+sWcRvfTTjCdYq44OjHMpdjylD+yfxkRLqtAr0icBuJ4
         D+HHZ3CGIo1hm5U5xmZs7K8oZA1Hf1joYexfrp59BQN+ZxpYwEiyC2TSkn237P6BUyn4
         0bnowwqvQUlvlgV7mLHjkrGzyPsnEBZK0z8Kga/Hg86c+8Teu4oNxWw0t7kZBh9hrM/A
         /U9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+fJl2SPVv0Vv/e+Nwer50axQk+VfMz6cOjzJx1r0Uyc=;
        b=Regof60XB+2nPH8tXVBoGwb6pvXC2VB4AbJiv3ukO6tx3vjFzMVbMn7yfPNs4atkiV
         9uBlfYmCupVPq+DaseFyuvsKNj5K2bLd8ejh90MGx7Tt3mVRXlD0RMoBn4xOZGKzBTwU
         wjAzVwMgWvdvDI9PfFI/5T1J28VhyKbZobjYbhp6iEBq/Y7PwNaSa1iMWgmh2aOht8wo
         A6N/NyWdiIBZHtbLZAtQqu4MwZ8KrBr014d6j4Gs/b8jCYVqW52+9bmzvr7bIGFYcnw0
         LGMcZEuLg9N+tM021ddOQmmslVTjXu9TB7eFej4gdKAnb2/ZizwpTLCSVB/ezRVLcX/b
         eT4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NM4axnSh;
       spf=pass (google.com: domain of 3oj8jywykcwujolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Oj8jYwYKCWUJOLGHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=+fJl2SPVv0Vv/e+Nwer50axQk+VfMz6cOjzJx1r0Uyc=;
        b=Y2nlTFPaxDTEfEIjucFjaQnC67lPHPZ2q0BmXsi6a86hzeitK9TiGcd82enTRD9naV
         NFRS6YStIsXS23jv/L/QzSKb5WEjvZE8Dok5l20q/Ae/P0aQkkn/LGPRzsm/yhkA5Xf8
         sEpfRC9ZYwVbiE3I4A+KKFrmlTW2dU6g/NfggwyIuxqb1+8B2flTw3BsUtscL3NmM3kQ
         Geqhne0jBsXH251lhh3n2CUvYmv+dILKHmXhDqnxpmtCYiO2Joqe6A3b006heaiUqBVX
         thIEY6GlMyN1e/uXOeFxyxCHNhzsoIuoKLZXh/5HjU1wZGLmC7fNWXOGyQbykcUy7cwY
         YABg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=+fJl2SPVv0Vv/e+Nwer50axQk+VfMz6cOjzJx1r0Uyc=;
        b=hdTob7vb8S/1SS8POAst8sF4Wrmc20+rQsU8YybyBmRv7YPDKYCUy2sWnY0hUOfTAM
         FPxn86xeZ2WPlQKeAzIyATC0BcK98itnhvtVpny+9j5unhNDi0yhNrU7yepPz6Pnh0MU
         hH40GOVv8ON6MjWoT/4gGV9reGIdDbIaOVxE7T6zQTOHzcZgyQdxWlPU+EiIhfecwphM
         X9DI/HL/ksSi03FVbQVI3Vzvf3d2xBPCIandhqQWIisWS2kgyinXaBSJoswpruCXt/ML
         JBLcv9SQAIwavMtflGw1SbCi9y6PT0cfHv3QqRB7KVIOkI0eSHsNBLsS22PrnHsa7OZK
         Ep+A==
X-Gm-Message-State: ACrzQf1t36qPljLBJJ+RMG2C0QfpIw3cBkSCmUcdkjKQ2WhA3VWPmxlW
	lvE2A+JthyuKkjCugFdlyec=
X-Google-Smtp-Source: AMsMyM7jdG93bH4fhXckDCQ6l05drpwu5wuHoP4m998IjTkjniPKipeqRLqesTT+pr2KxkcbScsM5w==
X-Received: by 2002:a05:6638:379d:b0:35a:41a4:778f with SMTP id w29-20020a056638379d00b0035a41a4778fmr241164jal.102.1663254332005;
        Thu, 15 Sep 2022 08:05:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c7c1:0:b0:2ea:c965:4426 with SMTP id g1-20020a92c7c1000000b002eac9654426ls4162849ilk.1.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:05:31 -0700 (PDT)
X-Received: by 2002:a05:6e02:1749:b0:2eb:84df:e9e1 with SMTP id y9-20020a056e02174900b002eb84dfe9e1mr215412ill.66.1663254331189;
        Thu, 15 Sep 2022 08:05:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254331; cv=none;
        d=google.com; s=arc-20160816;
        b=pVqUd8eNMEykUL+hJziHv/HHjLFb2PMqpFn2UsoQ816MFTOJn8qYSL//MzvCK8MGY0
         Si4QKIi2HAJWEObtTH8Uth+UEEIKZoMMeBfzKllLPf2MeS8JLd6BkrpxcvN82g2mFTto
         +up0LT3TrdwXDTHpOWmuSvav6Zx4f23p5zsBX5P/vZEL9pRusw/8zEYSlvZ4cv2f/KIs
         0cGzOlV5FSpMrRm2mVDILavC9NXEYgSUMRhUZLU8Jg7Y8/Qcnm7uEr27fmtQAkwvT2Zh
         adndHlYZEAogS5jSjiqIIvvdciEt+nMBiAJALlc74WyR2wZibrDS/4lEc+3kPhrXWv56
         oLwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=eGWHmCncvYGtki7dpdJUZ+ZMr1uc51g9yFEsa5ToQ1k=;
        b=d1H5WDcg77IsDcTWcO2axJs3pm7t0i+zSkphEvgFfyHSnX2Z9p9HCzIEPszahmfA0m
         bWKRERqhJMp+okqTjN5mpjl5Bx3LwKwdKqShtPpb6kxSyFGdnSMEPuoz47k3kLWuLWgc
         0x0XziAmMtDoau1rPnJ60f/6EghgexLldjhiMRwJxJN/PLR5BMeyv9EyXobUOtHm+Chc
         6uGZKTTTp1BqHowR2e4H92KNn3UuyKIvLuARFZdfOzvuL3kuAiVJ2FaIRMhWNNH9A636
         LjbMiNyuuNeHpUQOC3uzQgUoiUqwt+K+SUuDEke5o2V2U/Gl6ryl2VFQef0mnmlxtuWA
         JwtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NM4axnSh;
       spf=pass (google.com: domain of 3oj8jywykcwujolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Oj8jYwYKCWUJOLGHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id m7-20020a5e8d07000000b00684e0ad0804si942900ioj.4.2022.09.15.08.05.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oj8jywykcwujolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-3454647ff7dso162076987b3.12
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:31 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a81:46c2:0:b0:341:a26e:9d9b with SMTP id
 t185-20020a8146c2000000b00341a26e9d9bmr209204ywa.336.1663254330722; Thu, 15
 Sep 2022 08:05:30 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:53 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-20-glider@google.com>
Subject: [PATCH v7 19/43] kmsan: add iomap support
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
 header.i=@google.com header.s=20210112 header.b=NM4axnSh;       spf=pass
 (google.com: domain of 3oj8jywykcwujolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Oj8jYwYKCWUJOLGHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--glider.bounces.google.com;
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

Functions from lib/iomap.c interact with hardware, so KMSAN must ensure
that:
 - every read function returns an initialized value
 - every write function checks values before sending them to hardware.

Signed-off-by: Alexander Potapenko <glider@google.com>

---

v4:
  -- switch from __no_sanitize_memory (which now means "no KMSAN
     instrumentation") to __no_kmsan_checks (i.e. "unpoison everything")

Link: https://linux-review.googlesource.com/id/I45527599f09090aca046dfe1a26df453adab100d
---
 lib/iomap.c | 44 ++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 44 insertions(+)

diff --git a/lib/iomap.c b/lib/iomap.c
index fbaa3e8f19d6c..4f8b31baa5752 100644
--- a/lib/iomap.c
+++ b/lib/iomap.c
@@ -6,6 +6,7 @@
  */
 #include <linux/pci.h>
 #include <linux/io.h>
+#include <linux/kmsan-checks.h>
 
 #include <linux/export.h>
 
@@ -70,26 +71,35 @@ static void bad_io_access(unsigned long port, const char *access)
 #define mmio_read64be(addr) swab64(readq(addr))
 #endif
 
+/*
+ * Here and below, we apply __no_kmsan_checks to functions reading data from
+ * hardware, to ensure that KMSAN marks their return values as initialized.
+ */
+__no_kmsan_checks
 unsigned int ioread8(const void __iomem *addr)
 {
 	IO_COND(addr, return inb(port), return readb(addr));
 	return 0xff;
 }
+__no_kmsan_checks
 unsigned int ioread16(const void __iomem *addr)
 {
 	IO_COND(addr, return inw(port), return readw(addr));
 	return 0xffff;
 }
+__no_kmsan_checks
 unsigned int ioread16be(const void __iomem *addr)
 {
 	IO_COND(addr, return pio_read16be(port), return mmio_read16be(addr));
 	return 0xffff;
 }
+__no_kmsan_checks
 unsigned int ioread32(const void __iomem *addr)
 {
 	IO_COND(addr, return inl(port), return readl(addr));
 	return 0xffffffff;
 }
+__no_kmsan_checks
 unsigned int ioread32be(const void __iomem *addr)
 {
 	IO_COND(addr, return pio_read32be(port), return mmio_read32be(addr));
@@ -142,18 +152,21 @@ static u64 pio_read64be_hi_lo(unsigned long port)
 	return lo | (hi << 32);
 }
 
+__no_kmsan_checks
 u64 ioread64_lo_hi(const void __iomem *addr)
 {
 	IO_COND(addr, return pio_read64_lo_hi(port), return readq(addr));
 	return 0xffffffffffffffffULL;
 }
 
+__no_kmsan_checks
 u64 ioread64_hi_lo(const void __iomem *addr)
 {
 	IO_COND(addr, return pio_read64_hi_lo(port), return readq(addr));
 	return 0xffffffffffffffffULL;
 }
 
+__no_kmsan_checks
 u64 ioread64be_lo_hi(const void __iomem *addr)
 {
 	IO_COND(addr, return pio_read64be_lo_hi(port),
@@ -161,6 +174,7 @@ u64 ioread64be_lo_hi(const void __iomem *addr)
 	return 0xffffffffffffffffULL;
 }
 
+__no_kmsan_checks
 u64 ioread64be_hi_lo(const void __iomem *addr)
 {
 	IO_COND(addr, return pio_read64be_hi_lo(port),
@@ -188,22 +202,32 @@ EXPORT_SYMBOL(ioread64be_hi_lo);
 
 void iowrite8(u8 val, void __iomem *addr)
 {
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(&val, sizeof(val));
 	IO_COND(addr, outb(val,port), writeb(val, addr));
 }
 void iowrite16(u16 val, void __iomem *addr)
 {
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(&val, sizeof(val));
 	IO_COND(addr, outw(val,port), writew(val, addr));
 }
 void iowrite16be(u16 val, void __iomem *addr)
 {
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(&val, sizeof(val));
 	IO_COND(addr, pio_write16be(val,port), mmio_write16be(val, addr));
 }
 void iowrite32(u32 val, void __iomem *addr)
 {
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(&val, sizeof(val));
 	IO_COND(addr, outl(val,port), writel(val, addr));
 }
 void iowrite32be(u32 val, void __iomem *addr)
 {
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(&val, sizeof(val));
 	IO_COND(addr, pio_write32be(val,port), mmio_write32be(val, addr));
 }
 EXPORT_SYMBOL(iowrite8);
@@ -239,24 +263,32 @@ static void pio_write64be_hi_lo(u64 val, unsigned long port)
 
 void iowrite64_lo_hi(u64 val, void __iomem *addr)
 {
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(&val, sizeof(val));
 	IO_COND(addr, pio_write64_lo_hi(val, port),
 		writeq(val, addr));
 }
 
 void iowrite64_hi_lo(u64 val, void __iomem *addr)
 {
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(&val, sizeof(val));
 	IO_COND(addr, pio_write64_hi_lo(val, port),
 		writeq(val, addr));
 }
 
 void iowrite64be_lo_hi(u64 val, void __iomem *addr)
 {
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(&val, sizeof(val));
 	IO_COND(addr, pio_write64be_lo_hi(val, port),
 		mmio_write64be(val, addr));
 }
 
 void iowrite64be_hi_lo(u64 val, void __iomem *addr)
 {
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(&val, sizeof(val));
 	IO_COND(addr, pio_write64be_hi_lo(val, port),
 		mmio_write64be(val, addr));
 }
@@ -328,14 +360,20 @@ static inline void mmio_outsl(void __iomem *addr, const u32 *src, int count)
 void ioread8_rep(const void __iomem *addr, void *dst, unsigned long count)
 {
 	IO_COND(addr, insb(port,dst,count), mmio_insb(addr, dst, count));
+	/* KMSAN must treat values read from devices as initialized. */
+	kmsan_unpoison_memory(dst, count);
 }
 void ioread16_rep(const void __iomem *addr, void *dst, unsigned long count)
 {
 	IO_COND(addr, insw(port,dst,count), mmio_insw(addr, dst, count));
+	/* KMSAN must treat values read from devices as initialized. */
+	kmsan_unpoison_memory(dst, count * 2);
 }
 void ioread32_rep(const void __iomem *addr, void *dst, unsigned long count)
 {
 	IO_COND(addr, insl(port,dst,count), mmio_insl(addr, dst, count));
+	/* KMSAN must treat values read from devices as initialized. */
+	kmsan_unpoison_memory(dst, count * 4);
 }
 EXPORT_SYMBOL(ioread8_rep);
 EXPORT_SYMBOL(ioread16_rep);
@@ -343,14 +381,20 @@ EXPORT_SYMBOL(ioread32_rep);
 
 void iowrite8_rep(void __iomem *addr, const void *src, unsigned long count)
 {
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(src, count);
 	IO_COND(addr, outsb(port, src, count), mmio_outsb(addr, src, count));
 }
 void iowrite16_rep(void __iomem *addr, const void *src, unsigned long count)
 {
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(src, count * 2);
 	IO_COND(addr, outsw(port, src, count), mmio_outsw(addr, src, count));
 }
 void iowrite32_rep(void __iomem *addr, const void *src, unsigned long count)
 {
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(src, count * 4);
 	IO_COND(addr, outsl(port, src,count), mmio_outsl(addr, src, count));
 }
 EXPORT_SYMBOL(iowrite8_rep);
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-20-glider%40google.com.
