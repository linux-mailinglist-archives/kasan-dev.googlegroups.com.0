Return-Path: <kasan-dev+bncBCCMH5WKTMGRBH6DUCJQMGQEYC6CQII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 15A015103F7
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:20 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id c11-20020a056512104b00b00471f86be758sf4028638lfb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991519; cv=pass;
        d=google.com; s=arc-20160816;
        b=tGjEuGCrYvbj6YzLRgP2TkNU9CPyzrDsO/wcOS52lmmuyrxCGHeGuoAVJ1lNVcExs2
         V+TM253+vIWNcq+bji9fY2kKoVcwPcyGecpeL8amv9KvevrkWi21yCP8ivxMJAbex3t3
         k8nNvShVRk+ELABn7FeUt9FwFaV3u779s0pHXYvYrFAW3nGGMDpJa3NNipK0kbP6UJAc
         1jeQwAzJ3jgSLEf+SeuwgghQSVIx6Qo8EL8ISSdTLYA2TB2f6UTBU1Qgw/Nfyca9Rabj
         a7xgelBovW3iPWMB6k3SwtiQvjdv6rEuh1r+VgcET4Y5Fmx1cPU4+LdmkkXHSDdpZSW6
         EhcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=WN242E/cRJB6OzZ+UiKYT1eAsNvtSyTfOXRoCK23wg0=;
        b=UEuhE0CeLwQ1vARx5OsUnIChmLDodh9TcCmnVEnyMM/fXgYRI3x2jfgcFGCLlcl4ae
         RO2qgyp53xos4rBzLnlF3PHhlrcR4l//c1MmKZVLIr011zlH7WIQva1iBZGIRvShwiXA
         ZO1h/c3WaP2doIpXc8vvw+0W7MzQ930ZWDfRwAOgDRG7qzv625qJP630OFSWnzN6tPb1
         lLJlMk5rUchCDZr3VknqKG74LR4tZQF4UOlbJQ3mpL/MYYLD5QfZKyWv0NOsKz8cYoAK
         zduHV4U74gG4kZ2v/hVUFU4AvE/ESn4syrf10hLwvfZ6397lUY1LGy7r6pMu5OLDZ0Nr
         nzWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EUCnsUCR;
       spf=pass (google.com: domain of 3nsfoygykczoafc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3nSFoYgYKCZoAFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WN242E/cRJB6OzZ+UiKYT1eAsNvtSyTfOXRoCK23wg0=;
        b=bLLJ1e45Ikcsy55KmDXelQ8N/5My8vTElqzRg+3WBgMo3WPKG8kul0E2sTYWDWE1tT
         hlxWw8bdYMGs9X01XVa4yJ/5OTRxv27ufBWVOks6zQGECHqoLiCcx29Qyq8toMKyBhZZ
         Bg5umypMOxvXpxfm4zHdWXUSb2izjweCCjDn4QJGbln/22F1wnVXhgfU/i6mI4Pdn2ML
         8U+iYGv/195r71bjXFD/PrswJcHD5eSUR+0xu/aQXzTrybFmHzMI1lNvDYwvYLpZAHs9
         xCsf0f0dyFQRFCwFYom0vR6MJgYU/XRUjnifhZh8VObPnOtpKhAC4AdZiU9X/Gu7n3be
         FDrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WN242E/cRJB6OzZ+UiKYT1eAsNvtSyTfOXRoCK23wg0=;
        b=sIadgRjjO43kql+n2BXZGd7zexDsnPa8HRmXPIygruDQ9OEExmkf6FX4yGxPqQ0TfY
         ntrJeyd+qAgRXTJNLmYBtwXPae0fVsiHfmp51kkWW5YByRzjQb+zCej+pZX/XpirWknF
         Z9oRZLfoHotWE/0CMwULXUM4kMPInmMpzHy/DxUpTQCb0ASP3gWR6VItXaOs882Objxg
         ZmLP2IyPHvEdWm/HNGxVHZe2flbwj8v7KHLjoAn24Y5wFVOTg7TUaEYjwTeqcJrrMe8P
         D1Pyeo/AxQFLy6wUMVpCaJ5byZmk26WXHLBmbc0EVSd/INZeK1CZRmdMjKFT3fkUEZWB
         XnQg==
X-Gm-Message-State: AOAM531LhywjpxySp0bteqLnNtOW0EkhxrgnJ8qAJnK2A5JEmW0WKgUJ
	sthoFMWMj6YVYqCWthyQ/J0=
X-Google-Smtp-Source: ABdhPJwOn41/itomdQRXr9lgwvClgT+2H1wlGPU8Tds6DfPo+rNxQ7ezrLkl9+3nLwQZUawpQ1B1LA==
X-Received: by 2002:a2e:9d90:0:b0:24f:224:8dfa with SMTP id c16-20020a2e9d90000000b0024f02248dfamr11903582ljj.46.1650991519575;
        Tue, 26 Apr 2022 09:45:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:19a0:b0:24d:b9ac:8a74 with SMTP id
 bx32-20020a05651c19a000b0024db9ac8a74ls2132240ljb.2.gmail; Tue, 26 Apr 2022
 09:45:18 -0700 (PDT)
X-Received: by 2002:a05:651c:23b:b0:24f:1286:c321 with SMTP id z27-20020a05651c023b00b0024f1286c321mr6566825ljn.521.1650991518436;
        Tue, 26 Apr 2022 09:45:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991518; cv=none;
        d=google.com; s=arc-20160816;
        b=KvVN3p/pr4lIeygGft+Fgk1lkjKbcKB2kBnO5xvv1lFke1YDJxt2XOWRe+OoMXPnpn
         bQpNLxvNDl51jx+Va+i50gnrYmLbGe1bkrAOvXKys2fysWX9tvid2gQOL36ft2VXGPeU
         q1j356g0Rl4xuyktObYptpv5xPPu50krC5+GFJ1A0u6VHO5UAx6zloctSlG1HBubP1fu
         Z8Ox8BGPJ+EmSLklzAr3Lnm4goGKR34sW2RyQdGS+65zzwAplELnEBo0DNchQLxyWxmq
         EfuLJuwvtbDmwl/oyHHCMFdz5B0uflyb4LgfqnftLgithT4Gx6auYWn3K6/e1ikfD3qB
         GvMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=8DiARL40b6+V/ufuvO47fdIAJou+WObIc+AUIejVSTY=;
        b=FIdlKV1U7WYLSyrGZldSvEuaSIfHG4Qyry6JCO/IaStyMWq2XV6mCjiSuhYJaFDtxK
         2ejZS4brECd0iaos0mltQHkoHC0/NsS5JZ3Xd7jAyi8q/5gbXwFG0kdrhNvOoEiwI6P8
         NBVSZ5Eny+c3413bEt7lPq4LiiHCMof7ajObyiK70Ju2uhTViv4vqUon1uFi3g3eGHRt
         DvFYUumrJ5OKh66dTLm4/kGmdoGNmOUhwXMZ4VgJNdS6Eqa1i+VtMSaPLmlG6/r1LmAf
         hcL9p+Vz/OS+hLrvfnp2F3VYu/kpUMEFW0/ZZSiw9joHHLuOv7JanvNu7PYsS9R5xR3h
         bx8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EUCnsUCR;
       spf=pass (google.com: domain of 3nsfoygykczoafc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3nSFoYgYKCZoAFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id f26-20020a2e919a000000b0024f0dcb32f8si426275ljg.5.2022.04.26.09.45.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nsfoygykczoafc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id s24-20020a05640217d800b00425e19e7deaso3805178edy.3
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:18 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:aa7:c31a:0:b0:425:df3c:de8e with SMTP id
 l26-20020aa7c31a000000b00425df3cde8emr14404475edq.83.1650991517926; Tue, 26
 Apr 2022 09:45:17 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:51 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-23-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 22/46] kmsan: add iomap support
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
 header.i=@google.com header.s=20210112 header.b=EUCnsUCR;       spf=pass
 (google.com: domain of 3nsfoygykczoafc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3nSFoYgYKCZoAFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
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
Link: https://linux-review.googlesource.com/id/I45527599f09090aca046dfe1a26df453adab100d
---
 lib/iomap.c | 40 ++++++++++++++++++++++++++++++++++++++++
 1 file changed, 40 insertions(+)

diff --git a/lib/iomap.c b/lib/iomap.c
index fbaa3e8f19d6c..bdda1a42771b2 100644
--- a/lib/iomap.c
+++ b/lib/iomap.c
@@ -6,6 +6,7 @@
  */
 #include <linux/pci.h>
 #include <linux/io.h>
+#include <linux/kmsan-checks.h>
 
 #include <linux/export.h>
 
@@ -70,26 +71,31 @@ static void bad_io_access(unsigned long port, const char *access)
 #define mmio_read64be(addr) swab64(readq(addr))
 #endif
 
+__no_sanitize_memory
 unsigned int ioread8(const void __iomem *addr)
 {
 	IO_COND(addr, return inb(port), return readb(addr));
 	return 0xff;
 }
+__no_sanitize_memory
 unsigned int ioread16(const void __iomem *addr)
 {
 	IO_COND(addr, return inw(port), return readw(addr));
 	return 0xffff;
 }
+__no_sanitize_memory
 unsigned int ioread16be(const void __iomem *addr)
 {
 	IO_COND(addr, return pio_read16be(port), return mmio_read16be(addr));
 	return 0xffff;
 }
+__no_sanitize_memory
 unsigned int ioread32(const void __iomem *addr)
 {
 	IO_COND(addr, return inl(port), return readl(addr));
 	return 0xffffffff;
 }
+__no_sanitize_memory
 unsigned int ioread32be(const void __iomem *addr)
 {
 	IO_COND(addr, return pio_read32be(port), return mmio_read32be(addr));
@@ -142,18 +148,21 @@ static u64 pio_read64be_hi_lo(unsigned long port)
 	return lo | (hi << 32);
 }
 
+__no_sanitize_memory
 u64 ioread64_lo_hi(const void __iomem *addr)
 {
 	IO_COND(addr, return pio_read64_lo_hi(port), return readq(addr));
 	return 0xffffffffffffffffULL;
 }
 
+__no_sanitize_memory
 u64 ioread64_hi_lo(const void __iomem *addr)
 {
 	IO_COND(addr, return pio_read64_hi_lo(port), return readq(addr));
 	return 0xffffffffffffffffULL;
 }
 
+__no_sanitize_memory
 u64 ioread64be_lo_hi(const void __iomem *addr)
 {
 	IO_COND(addr, return pio_read64be_lo_hi(port),
@@ -161,6 +170,7 @@ u64 ioread64be_lo_hi(const void __iomem *addr)
 	return 0xffffffffffffffffULL;
 }
 
+__no_sanitize_memory
 u64 ioread64be_hi_lo(const void __iomem *addr)
 {
 	IO_COND(addr, return pio_read64be_hi_lo(port),
@@ -188,22 +198,32 @@ EXPORT_SYMBOL(ioread64be_hi_lo);
 
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
@@ -239,24 +259,32 @@ static void pio_write64be_hi_lo(u64 val, unsigned long port)
 
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
@@ -328,14 +356,20 @@ static inline void mmio_outsl(void __iomem *addr, const u32 *src, int count)
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
@@ -343,14 +377,20 @@ EXPORT_SYMBOL(ioread32_rep);
 
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-23-glider%40google.com.
