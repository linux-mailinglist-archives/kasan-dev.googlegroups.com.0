Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEUH7SKQMGQEXJ26DPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id CAD70563523
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:18 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id g3-20020a2e9cc3000000b00253cc2b5ab5sf503918ljj.19
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685458; cv=pass;
        d=google.com; s=arc-20160816;
        b=YVvYcZCZyxXxPjeJzPBAczGBOS1Ttz6+28ckuihHPJShpOfAD7K3lNpu+YI9t/uPsi
         jDsUyJbSTaMfy5bNaQ4llLpkU6QyES8zbXlBK68ZolcpeNsX0IuZaYD2VSI6OrDfeHoH
         IUt2u9fcvpMfJG7F8HRZ+/hwO9I9/6Fj6Ex+FZpz1HDZpfsCXKaq4DitnI0T/LDjaCBe
         y/6veRnKdoww3qSyn5fss0BMsA5euejq5miYGxt+5Ysr/rXjq9x6M0ziEiDoYkDIWGtt
         7s5fp6Yd4bvGpcJ7k5L5f8pDxw1Oj3wjsssIZaqgIHc6arUhsv/srEXN+XnXaYBvdCgA
         sWrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=zYs5nltVJIBt2y1OqcBQTTRk47mRpwhmN8suxXh/uAc=;
        b=kNpzp8DS1iBGBjPZqNVD9ziNGK7aofxOG0RThNmFPmOPwA0GtBqm0rb7Y+mWmJYozU
         MPb6M2bb77nUeHH7S5QkzvJPVElh9BMCLlqc/3tzhAa7AWBljCy9A6VA/sjdNamvoqga
         HJqkoG1Cn4K8FHP19x7Ft6hDlajA3f8014v2uDafbeBsTa8RoF4PENqMMh5k6kSBAj3I
         UmS6sl8RiEppb7WmsZVylGQfPab2QfaLigZGuZM5sbE3pZq0zKh1GBAzQiupEe2TfOVV
         fhGMKp/7N9dlbehDC6d254XdBm/JTPsqcDF7G9kW9NTJ/JCzNuMYhEuS/8hyJtAb/4ne
         UQ2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="U5LnbAq/";
       spf=pass (google.com: domain of 3kqo_ygykcbawbytuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3kQO_YgYKCbAWbYTUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zYs5nltVJIBt2y1OqcBQTTRk47mRpwhmN8suxXh/uAc=;
        b=sACfMjPU3BKkyse9mSgNcDsK4L8PES4bStRQngoLMRdqo0GdcNZT/MXmtS8ouXYIIr
         bdOQGaJe9bgLEWJPImt0FgoFJsER5oVHv1cxnD7iy3WpnLr7eEtspzHisZdAeEGW4RcB
         jWeBSmZdrclLH1wuO1pQDjolLphTggzu2242KQ9UDh6lZQYDRoXB685pHmgcnafd4CL6
         RjDHbfwMt19HNV0Q0JA30mkrDpoxDsu5Ki7/XlXKoC0Tg/Tv3lT4KzyND/tbKG87RndM
         4CfWEed04VmthOBCLpXemImjb4OCJbcf+aI+lvlS61i/nFT2fqYR3hPATZHEax1uWjgG
         T4Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zYs5nltVJIBt2y1OqcBQTTRk47mRpwhmN8suxXh/uAc=;
        b=JAxEWkmKiTwrPV4qZr7zxPRvV6fePdl0hKB/JLmsYnsOjCUkDQ6bgll8h7i/S+aRsM
         LuiJ2aaaK6ZH72VtUrCZTPkzIT0abgly6m3hCJl+qsenu0beSXfJZkl1hBQJ4hVKDQYw
         TXjU6Ms5UOvNG7p7rNkiIuTzETzpnFcwLL4AVcOIIX3xVd3cMEWxuScDilksSfuCnSDP
         8NwY0EGPR9dZ+/Z3mCG3XKcrPpRaKnaBrXveLk/kCoRvdd6smHLdCXgyGMp/9pEmhA31
         52qX3a/mDqh18lB64Ug0ooNCZNdHlnJcoYLwKhZycBI94nKrIdcGZEqABop80vRzxKsj
         2cFQ==
X-Gm-Message-State: AJIora8DSwsapZ4D8IM+LexrySKDqFe3TzpSJD0+R6m+CpBiZQdfBZ3z
	20tzaj/zrFZCdwnueLmJwus=
X-Google-Smtp-Source: AGRyM1ueOtBI7BQFtUUVqV2WFSLX2tZggKk0hQ7XVPU6/ymTvgsNyN96+ZaijKUJE/Wfmv32IIabBA==
X-Received: by 2002:a2e:bc22:0:b0:25b:c3b6:eb11 with SMTP id b34-20020a2ebc22000000b0025bc3b6eb11mr8666145ljf.122.1656685458406;
        Fri, 01 Jul 2022 07:24:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9e03:0:b0:25b:c694:1134 with SMTP id e3-20020a2e9e03000000b0025bc6941134ls2734019ljk.7.gmail;
 Fri, 01 Jul 2022 07:24:17 -0700 (PDT)
X-Received: by 2002:a2e:a228:0:b0:25a:8e86:ce88 with SMTP id i8-20020a2ea228000000b0025a8e86ce88mr8718470ljm.240.1656685457436;
        Fri, 01 Jul 2022 07:24:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685457; cv=none;
        d=google.com; s=arc-20160816;
        b=VtAqmYgrrcq2td/PbnD4gv4c9oW2V2v+W0j9uXML2ZdeM5s0/kL0GFPqPLpPiakJqc
         ZDEEZwcJxmMcz5BKj1zFNfHnNT7nLEeXllhOr00w5lTKYoHyqgwvzmruUFgj2rS42ZpF
         twltR0WUMC+fJfy2bFfUB1fEcoZziQJKuNjScgKn5X/6QVfPpoKfQjYK+0B5FFnJ9s7n
         KakhQA+O+xB3Hdorp1wNU2JvWUKc2XwN/J41TZTSvGOeRHGT+eFSsp9WXtmLRjHVrtFS
         47C7tI9xiwVcmTGj/VV4sjUGwfq00xswAJA9c7vJ6sokZUp/WEcMQj1McbbhCUpXnZuo
         5szg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=q/n/OecEQokjv5vk7nJWmgO+y+lMcJIuX+yK+Jk36kg=;
        b=bWw40f0ELPFe9lSBxt+v4DPlPMDxYpuE/LvirTp37Zg+YWsy9cmUbL3v3/zg3DhkGS
         RswZm5f9MJLzhaWY3rFhAkyN9qPG3/lC2Av8gCDXdUFkcBQtJNiZrS6LeJmI2Ar4DC0H
         Y1j4ABAtgpzhbGZTj/3ZxVomQ7sM6TH8YNPg7pJAEBfmbgKKuCldQmDDgc3dOOJyanyA
         sb3+HnKiDulWDNb1sQGtH75jbWS6W7wopaL6KxBDFjdjeLO5iwrtbo2qX38c6V2aXInq
         O34oE7hbP5bDAAjE6MICmNJYaDZLaV6TWivfGkKtRBcHbZZXtlCFPgonswLOpLulKZy1
         N8Jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="U5LnbAq/";
       spf=pass (google.com: domain of 3kqo_ygykcbawbytuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3kQO_YgYKCbAWbYTUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id m7-20020a2e9107000000b0025594e68748si982160ljg.4.2022.07.01.07.24.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kqo_ygykcbawbytuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id g7-20020a056402424700b00435ac9c7a8bso1877384edb.14
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:17 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:f1b:b0:436:d3c4:aef2 with SMTP id
 i27-20020a0564020f1b00b00436d3c4aef2mr19579345eda.27.1656685457025; Fri, 01
 Jul 2022 07:24:17 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:47 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-23-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 22/45] dma: kmsan: unpoison DMA mappings
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
 header.i=@google.com header.s=20210112 header.b="U5LnbAq/";       spf=pass
 (google.com: domain of 3kqo_ygykcbawbytuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3kQO_YgYKCbAWbYTUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--glider.bounces.google.com;
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

Link: https://linux-review.googlesource.com/id/Ia162dc4c5a92e74d4686c1be32a4dfeffc5c32cd
---
 include/linux/kmsan.h | 41 +++++++++++++++++++++++++++++
 kernel/dma/mapping.c  |  9 ++++---
 mm/kmsan/hooks.c      | 61 +++++++++++++++++++++++++++++++++++++++++++
 3 files changed, 108 insertions(+), 3 deletions(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 82fd564cc72e7..55fe673ee1e84 100644
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
 
@@ -204,6 +206,35 @@ void kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
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
@@ -286,6 +317,16 @@ static inline void kmsan_iounmap_page_range(unsigned long start,
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
index db7244291b745..5d17d5d62166b 100644
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
-			      ents != -EIO))
+	} else if (WARN_ON_ONCE(ents != -EINVAL && ents != -ENOMEM &&
+				ents != -EIO)) {
 		return -EIO;
+	}
 
 	return ents;
 }
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 1cdb4420977f1..8a6947a2a2f22 100644
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
 
@@ -250,6 +252,65 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
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
+EXPORT_SYMBOL(kmsan_handle_dma);
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
+EXPORT_SYMBOL(kmsan_handle_dma_sg);
+
 /* Functions from kmsan-checks.h follow. */
 void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
 {
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-23-glider%40google.com.
