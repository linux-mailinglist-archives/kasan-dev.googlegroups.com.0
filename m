Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUWV26MAMGQEUDMQSBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 1286F5AD261
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:55 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id q16-20020a1cf310000000b003a626026ed1sf1671179wmq.4
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380754; cv=pass;
        d=google.com; s=arc-20160816;
        b=rRDGITwM+Tpw44ZxlBDNFN/tvVtmr6/zDS+Im2X9U9Z6VhgEmURehUCZf0B60hrE9q
         0trx2xqxM4NPpda+P9y3zsstegJV4UOE8C0Juw+wjv6WGA03H0x5J3DeOjm1VXprtKVq
         WH9HRcLc8Rf3MZaRRyPzXF/rM/KJcCmw+Hx7llcHWH2bdOldVZP4ynot9ZHhzWScyRb4
         Z+1l5O+hRCn1yngNPPZux1t6vHXO5IEp0u83iDsqCkuD7QGh84ImQPuLVd7UVRVAtsiV
         lVLg2qliFppvW98e7G7Wd1cSP4IzeayJriKFp7G2HqN8iW9kwunr/32pdCP3aCTYyM2X
         z6fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ulRv3E6f3ZUcGnU4/QGP8NJ8gwz68v9l3PIpbzCe6z8=;
        b=uJtsDQuepXj4bShpZ1Y9TH2TTDJrLpDEKe41Ch7zR17sdDUMEquVVPMMHf/wEYa/aA
         tzTSnryjMBqN85SWogT/pwlrLWtADrHDmdWXX1ElYkwtbXrEKA7SAVFHawoGnIz5fNM/
         0TeXZjS/gGftqEnl2dEp5ilOEBn4QxgEJLvW+UmBiqpsnMfomvHY8Db3wo4FMYrlJBep
         dPx5KQcBLOk/FU8CgZ9BK5Qs/TEUBA4yUaFW0e9TByf/cuB32iv/o7DeKUdVonGI3M7/
         4rQo6uAUNaFI2izUkZNXoED+cx+ZdzoHyafjw+Qgp1SfhK2OnjFXzPw5MRq6A2UFJjM3
         E3JQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Wp8EteLu;
       spf=pass (google.com: domain of 30oovywykcr09eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=30OoVYwYKCR09EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=ulRv3E6f3ZUcGnU4/QGP8NJ8gwz68v9l3PIpbzCe6z8=;
        b=kixlu4eTGBMf/C6WBLjAk8IJ3L1fp2EUkwy//CGf0ug7rlm5TaPom7+Wql7yDmK4Xv
         r7mcjYc8D8dozZGSq/gcZfU6++xyJ8Z9e7/iT4buMA/O9q0pymWoMm79VNAdESNO4YeC
         NQCyQqeLiLD5CFZtrc5OofuyW5HFEaKJlNdJhS+FpmQNFgV60028XYu7DVIKYhPM7ZN0
         7GTnI5fwiNEby7caPTyT5BMviI5gMQ2mhRP8K8HtC0niXN21tfHImrFgARUsLQrq6vhv
         ceWZ/LXfDnoxqQM6hXUoHb1CPFC4Mll5o3GvbB2jJtqDSDn0XpE51o2kvvPrZqxA+xL6
         3drg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=ulRv3E6f3ZUcGnU4/QGP8NJ8gwz68v9l3PIpbzCe6z8=;
        b=vN8J8ZX/kVSCGd94ZtrQ5QM+cctNF8O48FLTLX9WLwrR8NGSyCpew1y93rOWbN5us1
         aA8rLb5GMMeiOSssdsnqw6MsjSB0jGWZVX4RL+YVJvKtfb+tmyb66dnkNdz3CxATFXPN
         ErxnmAbbEyINrZfu9e15G+zAREsXOWu1D9XSV11wLsQo9eyZPkJ4poOsuq2suXEP8DU9
         qF8kLqEHCUWpY4XGA6BSvQlFUnbuYPNK1AAZsUDiR7klNER7+7CJkxiiYfNjI882rOm3
         UyyxHDjKP0SeZ83nK66++bI4kiUV9VhQne4vNOUq8mKCdAMwoljjnxyf4BS6Uz1Gmniv
         8vaQ==
X-Gm-Message-State: ACgBeo2sbAxsIhQMlKYKTvepGrJ8Zbi9W0ImOgh/w0m0LHFis/spS0yP
	pkLnBQHMklINKO6ANj0e03g=
X-Google-Smtp-Source: AA6agR4cVxP9zcVp1Y/VnBZBdS8eUOHnsumBwFIIIGMpgLiPZxA4ceb1JggBafZaXJFDEw8RIHUtgQ==
X-Received: by 2002:adf:f4cf:0:b0:228:63bd:da33 with SMTP id h15-20020adff4cf000000b0022863bdda33mr4165358wrp.181.1662380754648;
        Mon, 05 Sep 2022 05:25:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:257:b0:228:a25b:134a with SMTP id
 m23-20020a056000025700b00228a25b134als3157031wrz.0.-pod-prod-gmail; Mon, 05
 Sep 2022 05:25:53 -0700 (PDT)
X-Received: by 2002:a05:6000:81b:b0:226:bada:a5 with SMTP id bt27-20020a056000081b00b00226bada00a5mr24381384wrb.539.1662380752941;
        Mon, 05 Sep 2022 05:25:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380752; cv=none;
        d=google.com; s=arc-20160816;
        b=hvOUxcwOLg2+e7mI08wYZk8I8SlRsEsiuUztPgDnYlsp35W8u0VLlTLWldHruHhKj6
         hgOdxz7tlG7y0aEQ42icD1mjhkSwecviT+3xJ4b9ojAOg8q2ly1mqAfYv+d36uB4SI+5
         0CMIvxA362xn2jYkVOnjtnWqhqre9aVBvlm2qHtqyc4AlQuPSrjoMLoZQylOAwBmtEqp
         xkU+DOxpr4Ikr1FsTti8lv24wUizb4AHsj5ywV/2e2HSqH+QzvfjMcS1QgNoY3b3dQ75
         sBrD0MfukUE8IeR4MvOK5T9M2BdzR1FUqGDniUoIAQH+Os7LbMycBpmw3zhfVFi4YZYg
         6+lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=eGWHmCncvYGtki7dpdJUZ+ZMr1uc51g9yFEsa5ToQ1k=;
        b=CQl0pF3p/R9tm++OOa63cfaHc6Vc0VKdAiPFH0jXjMRN+RFx+oYlupJ7/jWUaz6JRv
         Q8jXhq+kCR327hvqbDhQrRchBvrt5jV1fH9t6YUunpoL2jcOt7nMFcqaC+J6R0Rqu6bo
         g/eeMhTC5yVRz4OmBJ8up0/5vMRBESR0jDQpY4opqKsZMtcZgIuH5g+3EAInH1dJ3E6H
         yw4oxD3J7rD0S9IQ4XmUGdKKUzcauurBtAw7X105xWR0AYbJreBTcCwpSiDl1qs2g7zO
         MI2xtiXfLrgrWqeHxFiSrz2msoQfMSoztl26aylVMMhqFeN7b9bwCG3pJBjowVXzQ6KK
         OJ6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Wp8EteLu;
       spf=pass (google.com: domain of 30oovywykcr09eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=30OoVYwYKCR09EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id bp28-20020a5d5a9c000000b00226f006a4eesi411482wrb.7.2022.09.05.05.25.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30oovywykcr09eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hp14-20020a1709073e0e00b00741a2093c4aso2311550ejc.20
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:52 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a05:6402:2549:b0:448:6db8:9d83 with SMTP id
 l9-20020a056402254900b004486db89d83mr30507509edb.194.1662380752652; Mon, 05
 Sep 2022 05:25:52 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:28 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-21-glider@google.com>
Subject: [PATCH v6 20/44] kmsan: add iomap support
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
 header.i=@google.com header.s=20210112 header.b=Wp8EteLu;       spf=pass
 (google.com: domain of 30oovywykcr09eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=30OoVYwYKCR09EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-21-glider%40google.com.
