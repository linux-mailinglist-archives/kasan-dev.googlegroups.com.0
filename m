Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFOEUOMAMGQEHONYFMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 6719F5A2A6E
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:10 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id qb39-20020a1709077ea700b0073ddc845586sf719255ejc.2
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526550; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hh+QFoeQ54Wl+nySfaXZ6GctUIIGawryijMqY35oHy1YZ/w0j+2s4lskuLEGRvq/s+
         QvEYBUVuFInIM+T4sU5GUgTvr7BW6ZjZWGlDEpIBDbVE7vHF01w+PeJ+Nqwkr1RemgC9
         VKBQyKGeQ2C44E7ZfAWrZzvlTc8PYwbXQKs3uq7hLvjAjTkqCgf6MxaYKnioYl9l6lZF
         b0ZHe8tJlt1p2kdq/4MKhAYmnbZdF/V8ySNdaM7IgLWc0P6VvrVhT1bHZHtg7VZgQbNC
         jjdXuFnCkWoZkMrZWlB54qTSW6WeRMTpLo0LR7xCtBCQ1rTt7IYAYrVzHT0NXIDIawAH
         XdYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=9Ezae8pWIZRMsc2BCkfr93w6wBmMiQsz5YNYJfXHc14=;
        b=wShde7RmYNREgGM4QAbZHgCmsXER0YIR8QCltX394N/KHHFH96pnt9zDl8Ib7J/c8I
         lbuSUpzHgUeD+GBCu3zAu5iB8+1ixUPEwdQIahOd4STwluqYDSniWlUj8C6Jh/3tHv+C
         +LeFdQNIZZSmhQcLLoIcDfYMexBzRbZKQN0xYRsUE6aSPdg3Oyc5HLju537/sZh1hsbG
         GdX0wmnoGhDR8ANJwAxb8O3TL9+VuyTAERkxcb2laHNxCsKCjh737kdEYVWt7kcCv0ul
         PcvtKvs9lY2GfeBhEdRz+D/g4qiUep3IfmUxhspzkrwr/IsDszYn7HbLVOktjQGrq8/i
         u2vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JZiG5Re4;
       spf=pass (google.com: domain of 3foiiywykcrs7c945i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3FOIIYwYKCRs7C945I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=9Ezae8pWIZRMsc2BCkfr93w6wBmMiQsz5YNYJfXHc14=;
        b=hhnl2NPNXftmEIWmuaRqMbxxKMKw+7MeQ62kAIzw3/+4FqGNmnDKSEpUVZj/MwjQTb
         YmCCURioT5DqLxNWKfU0qKGUS/S2821lMEAUyOg/zxLwOW344yXyY571MbYNjscRyZiy
         cwuhxUWU7WEqt758++4Bh4Yj8PrTVm4EHWB5NWNzJs0Z6vWDzQ9XlghqExoXVwcSKhZh
         wZJRwu6QGxbYpn8EYKo5dEOlWv5ar9zSw5Er7lqca7FCNfe+q6WeeglxAvEyvW2N0jNp
         p76te36xgcx1S0NtiNnmGr0m80T/RpfvFP2NiB+RGlMIMZm2UbxD0zqF+c11i7kbtCNH
         NXoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=9Ezae8pWIZRMsc2BCkfr93w6wBmMiQsz5YNYJfXHc14=;
        b=3bviPAId06ao44kFpOrQxqMErGBm22WPF72JpD5x8krpFXD0fJkWZg0ixXECo0S9Wg
         bjsk3BrzKC6qBJKNBpxstNt91RSBSMK9YBhzcp1bftz1aPKNaQlaBOHfh2B46QwCoSoN
         ejv1BRK0D7d1sT+V7wd6k6J058UXLKIB0LLFcfAPoKXZLfeCkGGsvH34oeq/x5W1QOwj
         WaChc4rg8x7uRa5DyjQXee5gkmyyGmpyky4194qQddyBilDwGYORe6CyRTLamg8ViRwc
         AULNWEdGB+Si5oJJr+mMGgqMY4pkuWR2QPXssuEzUPRT48Ig5k+f/BKI4+TCJeu6Z2PT
         coQg==
X-Gm-Message-State: ACgBeo0gc0F6+BYoK0+f/w/+U3d8WSrgdcVH0Cz/jjuNO5RZp9Lz+iK4
	CyPK4zoLCJgu6A7IQ+GBQ7E=
X-Google-Smtp-Source: AA6agR5m00q16x6MYzxuquiDK9OrMsVYV0mqQ0Yq4hkMfuN4C36vN7fAE0YqLg+io2Rm6PBVnRm40w==
X-Received: by 2002:a05:6402:515:b0:447:780c:39d6 with SMTP id m21-20020a056402051500b00447780c39d6mr7246076edv.265.1661526550181;
        Fri, 26 Aug 2022 08:09:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a409:b0:73d:11ed:5035 with SMTP id
 l9-20020a170906a40900b0073d11ed5035ls2167752ejz.0.-pod-prod-gmail; Fri, 26
 Aug 2022 08:09:09 -0700 (PDT)
X-Received: by 2002:a17:906:9b0a:b0:73d:c29e:cc87 with SMTP id eo10-20020a1709069b0a00b0073dc29ecc87mr5685242ejc.118.1661526549076;
        Fri, 26 Aug 2022 08:09:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526549; cv=none;
        d=google.com; s=arc-20160816;
        b=jeGYYpTwwkPMx07v5ghSjnnA7QmXsVjhdVBuhPbkYK1nwUE4dxb7hDLq1gmklFU9I0
         5a4hpXqbWIYPYPvpOcoOOGItKX8ZtfZ3gVze/AOkf1xGORwUUDwl9cEAyIJS2qWdWbff
         7CCfRpoaiyWfsFZPiZMKvsD2/q1lYrSaJE/S2WFNr8HFsksIOrBfpKwbAwZbk2TW9WSD
         9uBlicv2+NiC0dQ0a1vIC2pkrYtyFYyRSaQMluHOAopfHguUdlfWfVjPOaif8av7K61m
         kCJpn8TSFwwMNAToWmOURey6g18+RR12GIWs/RnjoPRm+V78FN25NHvrLY2vmooX6tqV
         CFng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=sAAv4rjcKBcVdRkEmlFE/2pa6fVQ+FymuVP5r3ZkSlI=;
        b=GINj63p4zOWeLMdbA8PH3bvWf2L+Jog+iJOGf8fIQR/AzpiQ7TEM/y11J07K/q3uBP
         dSlOphlNE204MaqaIzWLqwtsp+RA/bChnDNn9iSVBDr9Nq5pYtU4ljMdfSmffxf4FA3k
         VVSwykeSl2i8RfJVCppGm18OXKC0yCICdzxUbaN9UbqkHT4Laq+xHR9ZgiDay3aTpBz0
         8X5fmQDvmJzECpbNVMBYD/OSuV+AKTI4Pkfkyr8rx1zn0FxEil02KOHjLkwyws5m1nzt
         sa+O4x6cw9KwqPjpMRKfHUgdUnNAxWqoukmPB4vRngQ2QBh5pt0B17WzXEnnJGH2S2yg
         ftLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JZiG5Re4;
       spf=pass (google.com: domain of 3foiiywykcrs7c945i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3FOIIYwYKCRs7C945I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id y26-20020a50e61a000000b00443fc51752dsi85001edm.0.2022.08.26.08.09.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3foiiywykcrs7c945i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id f20-20020a05640214d400b004470930f180so1242350edx.10
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:09 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:894:b0:447:fe25:15cf with SMTP id
 e20-20020a056402089400b00447fe2515cfmr1613274edy.404.1661526548777; Fri, 26
 Aug 2022 08:09:08 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:43 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-21-glider@google.com>
Subject: [PATCH v5 20/44] kmsan: add iomap support
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
 header.i=@google.com header.s=20210112 header.b=JZiG5Re4;       spf=pass
 (google.com: domain of 3foiiywykcrs7c945i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3FOIIYwYKCRs7C945I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--glider.bounces.google.com;
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-21-glider%40google.com.
