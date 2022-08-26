Return-Path: <kasan-dev+bncBCCMH5WKTMGRBG6EUOMAMGQEABZTG6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id F40C05A2A70
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:15 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id h133-20020a1c218b000000b003a5fa79008bsf4190202wmh.5
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526555; cv=pass;
        d=google.com; s=arc-20160816;
        b=TzriOGZlhBGH7UZvRZBECc3ll13GJbnDxqLI22/tbyddmGp+ChWliZC/V1vUV+9bI6
         z4H0SZsecFmiym/3S9N1UDkMJ2Kax/yPk0tnFVh0hpG8tXpJHWDkBQvtteZLl7c/50pw
         ZfbmQ9enMQDJd0S/VOATiXA5y4Pd+ATA6g0Z0tYW4JDfh0VAAd4fke7qhETC0XVqsfxt
         PITnVhoEb7zzXgogoUfSrR0QbFTUPm8DpBQt22Fyu/AVLwC49I46SI3901kp3VVTEzkH
         brNGAdCak6o7UNcJMfs8rvwf84ZI7YErpNSbAcmRwh2gkc3i4fs805EFC5oFxDhksuro
         nJ9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=f7HGOqY1HQ6Oc3GLQVX/g/4pplRv5exkJiuEk3FgZKw=;
        b=bgBeyEkAC2qvQSypzpWRFNkvhXHmhFdaYQNttHvMHLfjH4+lPKW0PUILzjWlePdgsq
         VmMk/ihPliChQaL+yY5zK1msBvLmqAAxCkpG2nwUtpZ20RzGSLnKaMrZvSvoJNXyL38t
         q0rIp1a3IgxxXczUunm6aAqSUG38yQR6bowmehZU/06b9ga8x3RJumXQEi77WBjmmVay
         IQ3CJkTO0owKkEVtZV5H/oZgU/QCjs0NzFZbgCVSmqfO/x5d5lKesxkmDcB4L+xRFLR3
         VUVUKrhWHzZLydnUbTdl4mfwXTXplF0RgaBAgeXjyatFn1o5fXuzaGepRmbPfqBX1LvB
         O04Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Ez/lNwvA";
       spf=pass (google.com: domain of 3guiiywykcsedifabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3GuIIYwYKCSEDIFABODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=f7HGOqY1HQ6Oc3GLQVX/g/4pplRv5exkJiuEk3FgZKw=;
        b=n8o8RlCMCnBtlOwnFI5j4M+lLeQ5/fkoGXbVC2AgL9vERJHXuPFDV+XmNBBs7GIGxi
         dcN/YEf2/RkdJQkHatdmKtcKbaO7PTFc7lDV8B0Hjb91ts2Lr5p5LPGI1bx5m6eTP6n4
         7ejpzdyHkf19bhMGlWpgorSe/0HC9MM22CWCtQM+NvwzPhwbdF9kfQwpqon/YQ4C9uMf
         rAzpvUqQNmHbB5sJiWrhzpj7ChxCL47FPFpmf31JOHzQBNZ2Wzbbth6sEA3zcDDBPTPj
         3MTrzWfugQAs0YTBo3fN5eO4pQNquT7hQdoMvGYvdmw9S6mLGaohBjCW3DEGFJO15f9A
         wUmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=f7HGOqY1HQ6Oc3GLQVX/g/4pplRv5exkJiuEk3FgZKw=;
        b=auemqvi/lMDYIWBN+f35YZ1BwijjZCCwb/8TqqhwjzNTH3oagwXcOMMGX6u3qKUG2U
         +CLiptcdkiy5BXIYTJwFGY8ZCQWMEvQZC0jeJAll1GgIzie3jNGP0E1qXx0bsqilCKAx
         UqQv3mRDaRFQgC8pJAJfc5+NvQu1MeRxtw2jLi5mUSxASUqG1I+gzsWPVC6mfnjjm3qs
         b8S9LBD6NiCyMYEtxspaopEVh57Mw0I7n+NqiQoZswawm7yRQkXTxZwVS2E94LWJj1Tf
         PyOoHNsq36xbNoQPaHHC5uTuuNEiQNnqBP8Wdvh4ZYNqLVioaN7ESrCnZZCLG/SJRYAN
         ZiMA==
X-Gm-Message-State: ACgBeo2Qyf2yU1aA861+A8SosRIdFF2Zt0MNocYc+d2i+dqoXz5Ys9G3
	ecwgsIGjkQ6snT1rPCWCNxg=
X-Google-Smtp-Source: AA6agR6N2GFdC25ASzp6p+Y6Fe8nrWV6l70BRRPwt24+/zxvXSeZEd5ZxXR3yzoTwz12D5iCfoOi0A==
X-Received: by 2002:a5d:59a8:0:b0:225:61a0:e603 with SMTP id p8-20020a5d59a8000000b0022561a0e603mr49010wrr.469.1661526555637;
        Fri, 26 Aug 2022 08:09:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e4ce:0:b0:225:6559:3374 with SMTP id v14-20020adfe4ce000000b0022565593374ls87558wrm.2.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:09:14 -0700 (PDT)
X-Received: by 2002:a5d:6483:0:b0:225:7fb7:f163 with SMTP id o3-20020a5d6483000000b002257fb7f163mr50657wri.391.1661526554637;
        Fri, 26 Aug 2022 08:09:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526554; cv=none;
        d=google.com; s=arc-20160816;
        b=GR9cAFg7S3OVtvJY9MZ++KyaBZ5DJ7T1KKevi0qtVuhoHD7PnoRsLaG11Q0oFGhGxx
         O1MsE3Ej+UQkQbA+zY+HzXpENEn2FVHRfZGTVBcL9XVDVFygxUJProZmC9ECLY8dKqKK
         Fm9dC2o0AJEZTLps+JldQu/PaTD4SYTcSaNZSc16EXhpI00MSDvXJu3irvemiv1DRyIi
         aJ3Ajru8zjWSXJ2igJdPcNP9rR1v1iyjIHVog4+Md4rSl6WPJLEHPsLb02VREc7tavkD
         3Tn//eMHJ1c2p1ETNN9rxwpPB1EuDKJcVPZ1mL6u/sRnbDXanWP1yxZ4t+SEYdnq1P8h
         hJYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=76jHGgwozZvM48bVgyafH0ePqqgPygQeeBv9QE8zFSs=;
        b=z9Zy6cCbGXdpMPECV8WJNJkdvBw5UzWYIx07mKb81p6DOCbMTwf7ePB0ijhuIWAJ7m
         WAaAdv/FrOkxCIum2A/+XfstVPMaohADQN9ZP2RmISJJLcjugUK3gZ9XPVtZLIiZ1LMl
         pNdidKtQCFNPG/Wenghd4VNSHz6kcEyNwRK5WysBykpzsAYAyu52L+7tUBkJJpbwYAfx
         Or8tEvmK1mVmpyt6KEPSujc50tLZJchPeY2uBRgEfUEd4xYvWcS2pQSveDlcp7tUf7gB
         A6DnU/4NAg3kAR3itlRec2ThS1IjHHIK4EQw9mb18g2M66+HkzxTjXkaWj0H+AN7PPlj
         fAnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Ez/lNwvA";
       spf=pass (google.com: domain of 3guiiywykcsedifabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3GuIIYwYKCSEDIFABODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id n185-20020a1c27c2000000b003a49e4e7e14si643423wmn.0.2022.08.26.08.09.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3guiiywykcsedifabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id hr32-20020a1709073fa000b00730a39f36ddso715082ejc.5
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:14 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:906:8458:b0:73d:d0e9:4b27 with SMTP id
 e24-20020a170906845800b0073dd0e94b27mr5257444ejy.766.1661526554281; Fri, 26
 Aug 2022 08:09:14 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:45 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-23-glider@google.com>
Subject: [PATCH v5 22/44] dma: kmsan: unpoison DMA mappings
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
 header.i=@google.com header.s=20210112 header.b="Ez/lNwvA";       spf=pass
 (google.com: domain of 3guiiywykcsedifabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3GuIIYwYKCSEDIFABODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--glider.bounces.google.com;
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

KMSAN doesn't know about DMA memory writes performed by devices.
We unpoison such memory when it's mapped to avoid false positive
reports.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- move implementation of kmsan_handle_dma() and kmsan_handle_dma_sg() here

v4:
 -- swap dma: and kmsan: int the subject

v5:
 -- do not export KMSAN hooks that are not called from modules

Link: https://linux-review.googlesource.com/id/Ia162dc4c5a92e74d4686c1be32a4dfeffc5c32cd
---
 include/linux/kmsan.h | 41 ++++++++++++++++++++++++++++++
 kernel/dma/mapping.c  |  9 ++++---
 mm/kmsan/hooks.c      | 59 +++++++++++++++++++++++++++++++++++++++++++
 3 files changed, 106 insertions(+), 3 deletions(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index f056ba8a7a551..c6ae00e327e5e 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -9,6 +9,7 @@
 #ifndef _LINUX_KMSAN_H
 #define _LINUX_KMSAN_H
 
+#include <linux/dma-direction.h>
 #include <linux/gfp.h>
 #include <linux/kmsan-checks.h>
 #include <linux/stackdepot.h>
@@ -17,6 +18,7 @@
 struct page;
 struct kmem_cache;
 struct task_struct;
+struct scatterlist;
 
 #ifdef CONFIG_KMSAN
 
@@ -196,6 +198,35 @@ void kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
  */
 void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
 
+/**
+ * kmsan_handle_dma() - Handle a DMA data transfer.
+ * @page:   first page of the buffer.
+ * @offset: offset of the buffer within the first page.
+ * @size:   buffer size.
+ * @dir:    one of possible dma_data_direction values.
+ *
+ * Depending on @direction, KMSAN:
+ * * checks the buffer, if it is copied to device;
+ * * initializes the buffer, if it is copied from device;
+ * * does both, if this is a DMA_BIDIRECTIONAL transfer.
+ */
+void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+		      enum dma_data_direction dir);
+
+/**
+ * kmsan_handle_dma_sg() - Handle a DMA transfer using scatterlist.
+ * @sg:    scatterlist holding DMA buffers.
+ * @nents: number of scatterlist entries.
+ * @dir:   one of possible dma_data_direction values.
+ *
+ * Depending on @direction, KMSAN:
+ * * checks the buffers in the scatterlist, if they are copied to device;
+ * * initializes the buffers, if they are copied from device;
+ * * does both, if this is a DMA_BIDIRECTIONAL transfer.
+ */
+void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
+			 enum dma_data_direction dir);
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -278,6 +309,16 @@ static inline void kmsan_iounmap_page_range(unsigned long start,
 {
 }
 
+static inline void kmsan_handle_dma(struct page *page, size_t offset,
+				    size_t size, enum dma_data_direction dir)
+{
+}
+
+static inline void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
+				       enum dma_data_direction dir)
+{
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 49cbf3e33de71..48dfd11807be2 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -156,6 +156,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		addr = dma_direct_map_page(dev, page, offset, size, dir, attrs);
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
+	kmsan_handle_dma(page, offset, size, dir);
 	debug_dma_map_page(dev, page, offset, size, dir, addr, attrs);
 
 	return addr;
@@ -194,11 +195,13 @@ static int __dma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
 	else
 		ents = ops->map_sg(dev, sg, nents, dir, attrs);
 
-	if (ents > 0)
+	if (ents > 0) {
+		kmsan_handle_dma_sg(sg, nents, dir);
 		debug_dma_map_sg(dev, sg, nents, ents, dir, attrs);
-	else if (WARN_ON_ONCE(ents != -EINVAL && ents != -ENOMEM &&
-			      ents != -EIO && ents != -EREMOTEIO))
+	} else if (WARN_ON_ONCE(ents != -EINVAL && ents != -ENOMEM &&
+				ents != -EIO && ents != -EREMOTEIO)) {
 		return -EIO;
+	}
 
 	return ents;
 }
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index a8a03f079a8a5..41b6b41e6183a 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -10,9 +10,11 @@
  */
 
 #include <linux/cacheflush.h>
+#include <linux/dma-direction.h>
 #include <linux/gfp.h>
 #include <linux/mm.h>
 #include <linux/mm_types.h>
+#include <linux/scatterlist.h>
 #include <linux/slab.h>
 #include <linux/uaccess.h>
 
@@ -242,6 +244,63 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 }
 EXPORT_SYMBOL(kmsan_copy_to_user);
 
+static void kmsan_handle_dma_page(const void *addr, size_t size,
+				  enum dma_data_direction dir)
+{
+	switch (dir) {
+	case DMA_BIDIRECTIONAL:
+		kmsan_internal_check_memory((void *)addr, size, /*user_addr*/ 0,
+					    REASON_ANY);
+		kmsan_internal_unpoison_memory((void *)addr, size,
+					       /*checked*/ false);
+		break;
+	case DMA_TO_DEVICE:
+		kmsan_internal_check_memory((void *)addr, size, /*user_addr*/ 0,
+					    REASON_ANY);
+		break;
+	case DMA_FROM_DEVICE:
+		kmsan_internal_unpoison_memory((void *)addr, size,
+					       /*checked*/ false);
+		break;
+	case DMA_NONE:
+		break;
+	}
+}
+
+/* Helper function to handle DMA data transfers. */
+void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+		      enum dma_data_direction dir)
+{
+	u64 page_offset, to_go, addr;
+
+	if (PageHighMem(page))
+		return;
+	addr = (u64)page_address(page) + offset;
+	/*
+	 * The kernel may occasionally give us adjacent DMA pages not belonging
+	 * to the same allocation. Process them separately to avoid triggering
+	 * internal KMSAN checks.
+	 */
+	while (size > 0) {
+		page_offset = addr % PAGE_SIZE;
+		to_go = min(PAGE_SIZE - page_offset, (u64)size);
+		kmsan_handle_dma_page((void *)addr, to_go, dir);
+		addr += to_go;
+		size -= to_go;
+	}
+}
+
+void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
+			 enum dma_data_direction dir)
+{
+	struct scatterlist *item;
+	int i;
+
+	for_each_sg(sg, item, nents, i)
+		kmsan_handle_dma(sg_page(item), item->offset, item->length,
+				 dir);
+}
+
 /* Functions from kmsan-checks.h follow. */
 void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
 {
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-23-glider%40google.com.
