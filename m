Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQP6RSMQMGQEVGR5W5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id D09F25B9E16
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:37 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id g15-20020adfbc8f000000b0022a4510a491sf4642815wrh.12
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254337; cv=pass;
        d=google.com; s=arc-20160816;
        b=G894WaaeRoEGUsQzNFMk4+m/n+DdL/1+hbWyAR/vWW0joMMFlspauif4EbfVHb2npm
         FvvdhcHzEos+3RMmeoMsi7ZPnH+GcERdkkDrA+hARWrG8k7yFILdsjLqVes2ebLLZu8d
         B2UzfwY+pEeCUk3l9KhpHy19DHd4CrlFp6RJ4KvOeb+YaLd9MZv/cKew/LiOLBxls+r/
         XUCvINa3Dkr2ggOphPFIsXrvvCtprLsg+TTcSTWRHh1FBj8HMTJHjAKLFOdtoT2EL9mm
         vtf6BW1VYTnYAJd825w8oM24BGLI3qzOUYks5lc65PRkMmrIZbDHenSmiRG0rYdDH7cA
         M2FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=N27hawtN4GjIX51CaV7ZvVvGhUDTQJQffGcTG+5U7Ks=;
        b=oNsxl/UoSb8inTQx4nKUWm20vKHs7x2ZQWdMlxVtKIYDzn0RlEH0rbHY+h+tru2x6l
         EZ0ttCJv+CvXumcZoWAXcbyoD8W8ZZiaoTGZh3MDZfkhc0syIE7YrVm/jrvctnO9mryn
         wDKDrmgl497JDO/rAj8zwK9kjIG+cTUOARUkZ9SHE0w4r2I4S0MqsfZIrNYXbWdFK36p
         B+QvUeAKnQpuRQBxmifXmy84JwoZqjlNYhhDso25r7bvNEchTxaMAyBV7NCeAmmD5ru3
         3EtY6gTqqydlpL2NPK3EPOsP18K1xTL3fCh9PCrgpnIuJi9WSFDo5ot6/TJCRdOFQBrY
         SMBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HBcCaYgx;
       spf=pass (google.com: domain of 3pz8jywykcwootqlmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Pz8jYwYKCWoOTQLMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=N27hawtN4GjIX51CaV7ZvVvGhUDTQJQffGcTG+5U7Ks=;
        b=BfKyY4sZbyAu57nPY2SunfN3B9K+LBEPjXn+uLbc0QCFLz7ScxepXziKXA25g4qtnu
         Bth8SB93i4M3WdPC8gEBHgNzhJBGFRgXCcIfAD0/q10up1S7hBAf/dlCFmaMMQTs1apY
         lUIXNVmTKeylKuocp6guocsacKocEB39TGNZ3Z9Ns9LshMkY2lowH7V1VuMLYuMcyyL2
         xEEmPCz0lhadH/1igygQrfoIURLdjGbEsX2+HWRkrUqiNwvIj51SVtGf7GFlDsLOkeFU
         NjDXjjp1cEwT0st3IZhh2nhL8oGoWmp1loV9l3VkIbc54pcmpBUwwCPTiqpYFlCrJje5
         KP2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=N27hawtN4GjIX51CaV7ZvVvGhUDTQJQffGcTG+5U7Ks=;
        b=6xIR62GvvhNh28IX4oV+KBN0hfaIBVi+C2NwNtbMOR+ztvfdB4w1x7DIgo/EZDe4qN
         naC0bN3sSfH8wg50kM2bRSKDbIbESONTX3LakCOONHzOwtUaYnYTS9SAlrFIIyrhAK/m
         ZvZEKF0mgDGe4NQ+5+zJNj4n1jOD0h2k0ARQxHzmpM2W43CmVUHR50mHtbTCSUVenw3Y
         NE65XBtZgSYEsLgeOLNfdF4T5Aet1Z//NysOA4NRUDSyeI5YdEmSB+EroZPLEZFDhJJY
         3QY+5F1SYJPpDqF5I9KHfzXWsFRZ82XF6F81pWeSmJmjX52hPxEOeCFOXkb4Uft1qxEd
         2GRg==
X-Gm-Message-State: ACrzQf3GD11UoTOiY5s76DlJheo/RVbqJccA9+Lihm/Xy6SDuS8ma3C3
	b/H+F4cquoVH76YNRPjaFUQ=
X-Google-Smtp-Source: AMsMyM6Lnqj/Se9KTrGxLB40GbhR1474bVphW8B0v1ZAChjOS2Z4ZbQmNY665QwSSf3HOoy8H9Of1A==
X-Received: by 2002:a5d:5258:0:b0:229:9c2c:3120 with SMTP id k24-20020a5d5258000000b002299c2c3120mr45521wrc.695.1663254337464;
        Thu, 15 Sep 2022 08:05:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7512:0:b0:3a5:22da:8671 with SMTP id o18-20020a1c7512000000b003a522da8671ls7301408wmc.1.-pod-control-gmail;
 Thu, 15 Sep 2022 08:05:36 -0700 (PDT)
X-Received: by 2002:a05:600c:b42:b0:3b4:7580:a995 with SMTP id k2-20020a05600c0b4200b003b47580a995mr7209401wmr.30.1663254336413;
        Thu, 15 Sep 2022 08:05:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254336; cv=none;
        d=google.com; s=arc-20160816;
        b=l6Ovnv3Y157DBNq3iKK2nxC18k32MG4OgHOZQwLyC8vFafZ4HB1e3myHggxwg5LtLb
         IbjvK4zHqy1OFr1ocImYwTTHFqTyYKLqAoa7YP6GbbxsyinjBz7sebKYuaocf14x4gF7
         1ORDKhTO0b4T6vme0PCqOhF28eHTDK3ZVC5JmurHUB3H88ETgSZpQUlXPsnHBogz4l/d
         NM3ZhvIA+qebtvSnVSIzODontkqke1iWDeyk75VmUggmz6yYLF3xKISitd+PK5GbEPfr
         NWWXhdLBb0es5OVVO0DNfYGqb1RASXbipduBZl+6sAOtT6ZOdklR7c3QAnm7QJw7S8S6
         TBVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=oN1DmmB5hIGSextjMwU3Vnw2pm00V4zpd8aSRnyHf0Q=;
        b=HeJ5jsygZZKwRPzHaynvKjoDxjdImCP3lsDbMMN/zYiKrVTeUCMBmOXwC4LW66Qjzs
         W/vJ7ysfnYcnxjARsczXjNvATZIDPrOy1FB9TPoQMSZF4x/p7Em0vSFcW5dzJvCpu/k6
         Bl3JK2lAT+5tJ0Hc+1oikitrNZqEdjpm2K2eDXsBBUP2DwSSL1TUHO9PCs2xJ9vn1tfx
         nnsCUZm/yuUZLydObErkSAGE6Kioy5TNt9RDDmuWIDZ0nRKTGTsMEzFyVkgh8RZ7lJW9
         E0Rn01gnIml0adSTywO/1/DvioKUNlN+OWJUObBnYjFMp5dxhrqOCSN5fWpU+wllYEZg
         fdnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HBcCaYgx;
       spf=pass (google.com: domain of 3pz8jywykcwootqlmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Pz8jYwYKCWoOTQLMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si72296wma.1.2022.09.15.08.05.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pz8jywykcwootqlmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id hs4-20020a1709073e8400b0073d66965277so7605072ejc.6
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:36 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:2694:b0:450:d537:f6d6 with SMTP id
 w20-20020a056402269400b00450d537f6d6mr275499edd.344.1663254335996; Thu, 15
 Sep 2022 08:05:35 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:55 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-22-glider@google.com>
Subject: [PATCH v7 21/43] dma: kmsan: unpoison DMA mappings
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
 header.i=@google.com header.s=20210112 header.b=HBcCaYgx;       spf=pass
 (google.com: domain of 3pz8jywykcwootqlmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Pz8jYwYKCWoOTQLMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--glider.bounces.google.com;
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

v6:
 -- add a missing #include <linux/kmsan.h>

Link: https://linux-review.googlesource.com/id/Ia162dc4c5a92e74d4686c1be32a4dfeffc5c32cd
---
 include/linux/kmsan.h | 41 ++++++++++++++++++++++++++++++
 kernel/dma/mapping.c  | 10 +++++---
 mm/kmsan/hooks.c      | 59 +++++++++++++++++++++++++++++++++++++++++++
 3 files changed, 107 insertions(+), 3 deletions(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index e00de976ee438..dac296da45c55 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -9,6 +9,7 @@
 #ifndef _LINUX_KMSAN_H
 #define _LINUX_KMSAN_H
 
+#include <linux/dma-direction.h>
 #include <linux/gfp.h>
 #include <linux/kmsan-checks.h>
 #include <linux/types.h>
@@ -16,6 +17,7 @@
 struct page;
 struct kmem_cache;
 struct task_struct;
+struct scatterlist;
 
 #ifdef CONFIG_KMSAN
 
@@ -172,6 +174,35 @@ void kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
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
@@ -254,6 +285,16 @@ static inline void kmsan_iounmap_page_range(unsigned long start,
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
index 27f272381cf27..33437d6206445 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -10,6 +10,7 @@
 #include <linux/dma-map-ops.h>
 #include <linux/export.h>
 #include <linux/gfp.h>
+#include <linux/kmsan.h>
 #include <linux/of_device.h>
 #include <linux/slab.h>
 #include <linux/vmalloc.h>
@@ -156,6 +157,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		addr = dma_direct_map_page(dev, page, offset, size, dir, attrs);
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
+	kmsan_handle_dma(page, offset, size, dir);
 	debug_dma_map_page(dev, page, offset, size, dir, addr, attrs);
 
 	return addr;
@@ -194,11 +196,13 @@ static int __dma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
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
index 5c0eb25d984d7..563c09443a37a 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -10,10 +10,12 @@
  */
 
 #include <linux/cacheflush.h>
+#include <linux/dma-direction.h>
 #include <linux/gfp.h>
 #include <linux/kmsan.h>
 #include <linux/mm.h>
 #include <linux/mm_types.h>
+#include <linux/scatterlist.h>
 #include <linux/slab.h>
 #include <linux/uaccess.h>
 
@@ -243,6 +245,63 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-22-glider%40google.com.
