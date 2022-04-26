Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJGDUCJQMGQE7P4UGWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D8215103FA
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:25 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id sg44-20020a170907a42c00b006f3a40146e8sf2521077ejc.19
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991525; cv=pass;
        d=google.com; s=arc-20160816;
        b=y+EjoZNAgaTszHnIF2M3Dsd5fr5vHoDe7qBI41lqlukZlE0LNWDr6Qjz40mFIiwhr4
         DldPVfjPuE1/yHxhrCcmsS0jFmMQbbEKM7h9GgOMPzeLK9Q6DGpfdp5Y9tcqPYdvvk/Q
         7m0o4bZmjoVEPk4aw/v6LGTmHuwMK6DtsRmdfftLxj+I9W0AbjAW6KelVBeVbldI6bTA
         IbatBVgmuCH0rBcSmd+H9Q3p48p+MEBzphyo8i6w1HHn+/rFEwZ4vcquD2jZV8KXkyUA
         UPfljMkOGr5BQwBb63738G3bO6AOpTaB+R6HSLMcrni0Sqpv73gbCFIUjnZ9ERqrh7z/
         opiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Ih2xZUcPeeYVlkNtjdmQSn8qRMd5duaj5kAN2Ew/GTM=;
        b=leayBYa6yChqQtrEQCp/Iuh2PdPRMmqK7XDVpfHDO2mLOk0/8Ljzpa88gGihn71Zqp
         lH78P9AApE+OusboFXA2o85DTg79S7LBMhLbTgE0Ps08mHjwyCz3F+WiVDo9HdejV84G
         ScUvuLvvUfEslRIFTDK4hJfJKeXQIth1e7KZcJrX3MynCLStLswJ64jtqiInpVxpES9t
         D6q0GrPltbuGo/UWiB3LwSSBsTZVGILUQvv8ZFvVOMgO3i7Ks/lAn0zB/n9XPIB4adfD
         uERV1XfvDh1plid/G51D5zNWy4aiycysOwdhVWCuzD3Z+LHGXpDs7Ik+a5PtXUdoSxT5
         VQ+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kru0e6mw;
       spf=pass (google.com: domain of 3oyfoygykcaaglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3oyFoYgYKCaAGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ih2xZUcPeeYVlkNtjdmQSn8qRMd5duaj5kAN2Ew/GTM=;
        b=F6W98KL4QsNH1l21A/Uk/XeAASWFClTKlrCnNyTKJRc1z+qIDWXLfcIeusbGbxaE2e
         m8yqkfyCChxkOAvYYe4fkLaNH2KkJ3NBkNMUeIUINMf6WuOgnenMfPCEeRkrG6/Xf1mC
         B3e/SXvc5wA8npr+XYqLnE6k/lDZJZ88E0AMguNcY3niNogZxf3Q4E3Dtd332k6f4KWe
         HRfk9PZskYaZAysjpcQJeLWll8XABd45sVCM/4UZFI/YbIvQ9FAVT6TsXd3hCULSz/NK
         NmY3fgDIqEjAMXwJogH4YWk+aY0CY5f+BK+g2/VdzqXX4ZRK6+PVsoKl8/exNxBAxv/1
         xz1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ih2xZUcPeeYVlkNtjdmQSn8qRMd5duaj5kAN2Ew/GTM=;
        b=s4ddabjc8vAfn8I9aCkgJbPVVC2mmmBDqxM42By1lhg8FfpJYrgU5TUp1K6OL1GDeB
         ZfGFyy601cKqLkXF6B/ZbaQwkF91cyzT6Et+w1eAzN45HqLQ/6TP0yk7dxbVYQOa/UoO
         Qle/tG++Ds3u3ZqqCV4sKRvfe+1BeRsO3UkyV/c4NJe6pgi2WqL6H3RtEvzaoFX/cfpG
         CD2CE+6cTRwWCGh5k/rqmcmd/evo8fBGemycRiBN1hpbrzk3AvxAp59wrrJjR8g//BBO
         fHoKHXYA3eGHbYu+jzLtsaWAvhMY1xeCTEm8VQrKHNNN0mQZU/ZUZS6J3o3DaI21T8/f
         44tQ==
X-Gm-Message-State: AOAM532XzvOY7nHV9cffhDm6aiIPmVpe9mHP9d4ExrZ0NjdUN9LyqwfA
	6DkVQmIboF3pIGB95wSNWNY=
X-Google-Smtp-Source: ABdhPJxTRyMqmkRIv2z0i2a5G8Ve6WpF5+lP9u5Lh09I5TUquI30GP5aFGACZfNn/7GdFeOXjLVQMg==
X-Received: by 2002:a17:907:3e18:b0:6f3:6abc:a904 with SMTP id hp24-20020a1709073e1800b006f36abca904mr18051361ejc.341.1650991524746;
        Tue, 26 Apr 2022 09:45:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:478d:b0:6e8:95ff:b734 with SMTP id
 cw13-20020a170906478d00b006e895ffb734ls5358641ejc.5.gmail; Tue, 26 Apr 2022
 09:45:23 -0700 (PDT)
X-Received: by 2002:a17:907:1c20:b0:6f3:bf14:7827 with SMTP id nc32-20020a1709071c2000b006f3bf147827mr613403ejc.691.1650991523642;
        Tue, 26 Apr 2022 09:45:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991523; cv=none;
        d=google.com; s=arc-20160816;
        b=MrZAGg7D5J7yAiezedjIQ/5OCqATQHgdnhaqpw/WHwLSMOfqAc+3gk7A2yOB4X0I+n
         fE38H6gjU2ZKnj7/65WfbOedJJnMmxLe+8MTgvDnc5yBFIA1hzTPWj/Ll1TevvnruNv3
         Q5izEXuFgX7TJbguZsIgxHxTrbKHIEjvkstzj1B94RbVkFhiUerIKX0dg4+zMK0N+Bnh
         37HqbjudUPAgTUl6T6mvFIcCjC+SK3tw0uc94tQI2dHO2wPPD5Y74naYnQxU6wGQ5gkR
         cWrkNcWZZw6dx6CEYqXuXQO6CT4iJ0Yda8abemXZDW3fg1qqmice3y+UrXOqp3YMFBBA
         ApzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ae6KBGyLKJoXcxB2yOctfhYiWJk7lyt59+0aGNQoZFE=;
        b=vijTheUszLrIsOC0wuDJD21O8mMvbuo5ri4hiAq1j3l8p8UWNe4cWwBUhAO89bN8bf
         vNCSUjeghq1mXfBWjIXu8o84Z4yGmol+Nj+AmZLArvMPFnqTS3ggQBEgKWqD2pT4oC69
         re/nObhNLLLpejYxOczCOxT/UP/HvYcA3hgSoVry5UiZefHG6SQugogcaNs6emPLpS4c
         U9K+WTDI7YO+qOawY85KYbY783M0JbgKgkM+Y/GPJxZB+On05HBg4JQpudlMvXFziP+Y
         6RmEAUgnkVGlwf5UrO+axB2TEWzPXoFfXdkYw6gTihAV/QV2VX01S64ZJ/Tb47vcTJTB
         qu3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kru0e6mw;
       spf=pass (google.com: domain of 3oyfoygykcaaglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3oyFoYgYKCaAGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id j1-20020a50d001000000b0041b5ea4060asi880392edf.5.2022.04.26.09.45.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oyfoygykcaaglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id mp18-20020a1709071b1200b006e7f314ecb3so9373417ejc.23
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:23 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:274b:b0:423:fe73:95a0 with SMTP id
 z11-20020a056402274b00b00423fe7395a0mr25532792edd.224.1650991523134; Tue, 26
 Apr 2022 09:45:23 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:53 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-25-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 24/46] kmsan: dma: unpoison DMA mappings
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
 header.i=@google.com header.s=20210112 header.b=kru0e6mw;       spf=pass
 (google.com: domain of 3oyfoygykcaaglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3oyFoYgYKCaAGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
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

Link: https://linux-review.googlesource.com/id/Ia162dc4c5a92e74d4686c1be32a4dfeffc5c32cd
---
 include/linux/kmsan.h | 41 +++++++++++++++++++++++++++++
 kernel/dma/mapping.c  |  9 ++++---
 mm/kmsan/hooks.c      | 61 +++++++++++++++++++++++++++++++++++++++++++
 3 files changed, 108 insertions(+), 3 deletions(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index a5767c728a46b..d8667161a10c8 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -9,6 +9,7 @@
 #ifndef _LINUX_KMSAN_H
 #define _LINUX_KMSAN_H
 
+#include <linux/dma-direction.h>
 #include <linux/gfp.h>
 #include <linux/kmsan-checks.h>
 #include <linux/stackdepot.h>
@@ -18,6 +19,7 @@
 struct page;
 struct kmem_cache;
 struct task_struct;
+struct scatterlist;
 
 #ifdef CONFIG_KMSAN
 
@@ -205,6 +207,35 @@ void kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
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
@@ -287,6 +318,16 @@ static inline void kmsan_iounmap_page_range(unsigned long start,
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-25-glider%40google.com.
