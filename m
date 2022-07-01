Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDMH7SKQMGQEHUSJ6VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E669D563521
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:13 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id q22-20020a0565123a9600b0047f6b8e1babsf1190492lfu.21
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685453; cv=pass;
        d=google.com; s=arc-20160816;
        b=OizMX4lK1XbHBTxHuVQkTs7xO8Nz8Rh617Xy0zdQggZ+aZ8Iq1K9QvA4eksm9l/wDZ
         WRFhT2ZE4Kw0BYKSzP8nW6TeV5xS5qhakEt6It27j/hd/9qt3TAVC4dwNJ8wyY1thFwN
         FEyzTF1wiV0AXJW/Fvkd5Z2XzN/tem4TpyOx2xK1mII+mudH0Um2eZhyiGNgS63XpidT
         TTj3jH13ftVY3BGUxeuooxu3PbA/BhJAayf0i02JkingcJGyO1IAS9Zq5GXF77N1Akuu
         OLJ+6by8oZzLGRpt8NWw+4LTf8jDy9sVxB9MuwV5MWBXuT4eE9miNfFIkzJyvS9vucFR
         2WpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=wfvAA9o035++apXw2oUFPQFjoI0zWwN2gqTRs1Bk6Fs=;
        b=t4PJU+CT7HDe3hbrfypg7tYAyoOEV+1AOmLSPahJbnZcxZN/+jiGCFWxVLzh0lD4jP
         Koaez2Pl9N/KaACYNsYYdY6FPZdRl0s0er7lhXiENCC235HFA6C79ENTbrkC6XaIJK4/
         rH/lZU0gGV3M6bc+dp2LSpF3w6Brabqeiah0ODR3uAjxKxY43lFNyNWbKpznd2ZeeCO5
         bsf28z02Voc8SDuQmAMVQX7FeQGWu8Fi7vrFeBKeAYh4UvFeMlQASAig5Bc62DS0X6vt
         ZDnC06F44EEsxtSmjWwIpUIjf7Awey5dsLesTI62K6zXgfNYcZ731qcvc93UE69X99G8
         cbXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=foA7zxm3;
       spf=pass (google.com: domain of 3iwo_ygykcaoqvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3iwO_YgYKCaoQVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wfvAA9o035++apXw2oUFPQFjoI0zWwN2gqTRs1Bk6Fs=;
        b=eWEcZ2khO9/D6SxkWyF7whumWu4e90+3Sl/6VSdhjOrzPg7dVQmv1aza1jgAgbg+zX
         SmvFKmqN5NDPeKr1P7SCTdYFY5aoP4RhIUUOtD6aoZfru0LjZ9gzZYrY3Kz5UauVYlZw
         wpfqmWA8eeDxIld8FLizt6G1kYfFcyP9JsOD06Krxo/0QO2f5QfAN5dJ0h9AaJ2xJb2a
         7b8pUn4ln7WHCng0FusmbdoZ8A5J7eLA4Om0B/X42khi9MYJ+XAMCfBga0PdDTNvNtbg
         5Z/KxoHMxD5zkV5vqydiPvcmxLaWb1YiLA0Vm0qU5IwN2tV8BJRnjvYa8rmIoAGKjTSr
         zWdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wfvAA9o035++apXw2oUFPQFjoI0zWwN2gqTRs1Bk6Fs=;
        b=4uCqP1rftXQ8uxEzsYh+Mm51XlnFAdu3muk8oC2fRHdRNEZ2QeVICsnqpxpA/CnAX5
         VYQv650I7MCHV//7cVSuMCjk5ZA4g6O+Tjed/sRQo7bMWhn9i/JRG2kSPPwdeNoFcfgV
         eIk9QthN4aFYDIEKeEnfOO4jKNPdrr7/To7PCn1dDxeocfXVeQG0JGeha5PuCllLbFrv
         7AUZ87ImM8xkSXBjrK4DNZZ9NvMmZ2kjl7akKBWveEYWiWssJJnTsa24q59TSq3WjW8V
         kyeAJ3hkX6kk2MBxsxKaPNHzKwUuhqYHdqToE4zZHncBQXYrD8b5pM6xi9UStnTQipDn
         UJ4w==
X-Gm-Message-State: AJIora+8lXybhzfjYyN6zLIHxrj3tU2SIImObhvtFruU85ns9+NtbxEw
	93qPMvC1Eb8spT3avxmFq7Q=
X-Google-Smtp-Source: AGRyM1vVU1ChkQbkK74hUzm1+Kvnhn0p8em5lJRzxq6w8f/OXbVSKHmbWXKTCxMSThn0ydtrnsQIFQ==
X-Received: by 2002:a05:6512:2399:b0:47f:ad15:886f with SMTP id c25-20020a056512239900b0047fad15886fmr9212108lfv.226.1656685453355;
        Fri, 01 Jul 2022 07:24:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf11:0:b0:24a:fdc1:7af4 with SMTP id c17-20020a2ebf11000000b0024afdc17af4ls7176265ljr.1.gmail;
 Fri, 01 Jul 2022 07:24:12 -0700 (PDT)
X-Received: by 2002:a2e:b712:0:b0:25a:a1ab:2e5d with SMTP id j18-20020a2eb712000000b0025aa1ab2e5dmr8785715ljo.155.1656685452118;
        Fri, 01 Jul 2022 07:24:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685452; cv=none;
        d=google.com; s=arc-20160816;
        b=gxzzWNN+uHxG0R1v8fatbhpgV5X08Vwf/N928/gV+8SchZD9YxXVIQdmrPk4jN5WDR
         mxIq0fJci6+ElO1PqQ0kZxWDfcWLbMYY+u6TDArsQlZZ+KJJ/7h0rTZPf3N5knEpsvT7
         HFxiuPQZUcd/jQRIzfoN5UnlMCg41RKqj1SpV2M9mmKJbuKyWQfSNK/5N6cOWaCMgE2U
         oRI14DKfKOdQG0AyvGDAhptMpBEyS1U6iBpzbwAoUdP94Q4c9R6D1L2EB/e9xLTzdxoB
         aEjz+KTyGFalQWZp3RaCFmCIr4FloyjBgBW6OjSdxDbjn5xaBVFgoYAS87s0ew2qVskn
         YbNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=d5jq2vBXLL0PAqQqIdp+R/eYgdfcHLruJviOlOzbAyw=;
        b=MMUw1Gw+Y4407+0U96yVMWahNrsr4B+4Y9NaPkaHFSzD4UZ7oA+AibGutQjM3iUyJ4
         RYzrBkAq8lWlLo4/w374HYr8w+vvIU1cNaHQYlRGIrTxAUqx9Pqh/lnE1bzKhzBL8vQU
         9IWoxa0jiSdmwNsRDRu3xcCGQgKKnuwiBnHO3pFil0YM5vzhGDuyhadDtih9oqRcZISw
         Xq9dbsK0sYQXj3pxtyadbUri4XNaCoaUpWA7uZy2dzfJHy+M+g5WHnG1iUNFEghO6sYC
         1zm9KkTbB4Fb33Fgt4Wo8gpMHt+DVPTbIlx8+jZWBYKwhrugezEkGE0mvTlmsiqGzRw/
         CLYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=foA7zxm3;
       spf=pass (google.com: domain of 3iwo_ygykcaoqvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3iwO_YgYKCaoQVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id bp20-20020a056512159400b0047f8c989147si914070lfb.3.2022.07.01.07.24.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3iwo_ygykcaoqvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id z7-20020a170906434700b007108b59c212so844375ejm.5
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:12 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:aa7:d5c9:0:b0:435:8099:30e6 with SMTP id
 d9-20020aa7d5c9000000b00435809930e6mr19303788eds.384.1656685451552; Fri, 01
 Jul 2022 07:24:11 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:45 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-21-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 20/45] kmsan: add iomap support
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
 header.i=@google.com header.s=20210112 header.b=foA7zxm3;       spf=pass
 (google.com: domain of 3iwo_ygykcaoqvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3iwO_YgYKCaoQVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-21-glider%40google.com.
