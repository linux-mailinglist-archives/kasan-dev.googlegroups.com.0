Return-Path: <kasan-dev+bncBCCMH5WKTMGRBV6V26MAMGQE7WIXGNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id B654D5AD263
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:59 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id sh44-20020a1709076eac00b00741a01e2aafsf2295474ejc.22
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380759; cv=pass;
        d=google.com; s=arc-20160816;
        b=fjAfOEr3avkMwBQ+xHpm1sH/mmxzP9YdWDnOUO1yCIlPKKd03TEPQTReN2eQM7r9no
         CsHxfJw8Xuklg4Q4gZx8xgUn9jx9mFD71juRPZppIh7POooaGPMy9lIR6kNGaIjvUORH
         WhXxfisaKonkcSODIFjI/J0MWuIEuBgGJHd5tZFRW/Z4gwS78mFEUZtMKlrbVGj1q4Rr
         HapwKmaeaIG+eLSuiMLJAW9OXBdujRB2qSY/XbVGWODem3kCnvY5/y35qAxFSJFjk2b8
         DLmtivPJ87pf7kDx5dyXw+aWhSsI7LWi0i6q836RHA84DUaKhioGkb6H7ujdYShNreUB
         QgFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=NST9qxr/M+mg4eTDws9RHHm1b7oa3woLrUrwJ5SZ92c=;
        b=bK19Fjw5jjpSvDeFchmqmlqwatMAdRT/ualTH2UVIjx7M1SDEbvCtpz07yC8Dlz23O
         NDZqhLVuyWZsLiCO4QCQygnM09mGcO9+jgyKpHmplI8u8vRnhONZnmRzitvwMutxt/vg
         URKCQXulyzQ15IPGcMNd75Tk98n6b8JkAkmDIyuhKtuRcomKFXUsbT+Fkux+Txd+gQMh
         PCW8QdZTC1iVe1TKB20Hx8CaSJG4Nr/MprRaT54V7V1DTAXhzmPjEX/rBuOM02n1jabo
         AmgaAeb2mMxzZ66Mgtj60MGmA1D6BwVuoqsuRJZ8eneEehO4P+mFMG/DJOQ8mZS4fXYc
         HbpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HRK55Wdk;
       spf=pass (google.com: domain of 31eovywykcsiejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=31eoVYwYKCSIEJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=NST9qxr/M+mg4eTDws9RHHm1b7oa3woLrUrwJ5SZ92c=;
        b=csz4zMtLSHqLI1pP4DAJWCxpi9ZhniusJFvCB9oIfeLpdrmFz9pptuIsGLdob4P88Y
         xk69R+8Ia2YhkklxCajjvVZgsrVysYQitKLTPr5a5N316vuj5QO2PVejCFlklraUtVAc
         ZqrtU05zqXtwIV6Mfwow5QAlqQqsce7M1UAFG/oFpfIlEXO9mu2EecpQz/pKK9P9n/xc
         Sml8rmEH0eMVoT2X1o5qSfY7oAckvCWSl2Uw4E1FPmisbLZyarnEbCMRnjojvWdlGuxn
         /nSg1bgSOEbYdC3EtEsBwy7DdLKtGHAnZb84YOWYVFc6z/FIIOoWyqt9S5IYDiSqwfaF
         MTpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=NST9qxr/M+mg4eTDws9RHHm1b7oa3woLrUrwJ5SZ92c=;
        b=cJAUDtSZ+p0yc2KULaXU26amX5WABpz+YPUOsI+mSXqmGcRmvK4ET6or368hirW0+f
         M6s3gzAyFnVFb8YBpWGFSV5G667hJiDIIXvibaYMtF3UPBXaruN6WGIP4zLyaCIdtOei
         gjHIC0WacinMpiRO6wPBhpcxE5nUb260IU+4f6/swyqBBmWluTpUZ8/oFu/yep1khvIj
         D8/Fc3NKxTQumFRz+GdWTQ+xJZseyLW8H6i6Px2hKkYrc+sStPMFUooHEgG/2tGKB59d
         G6UFFGETPEqrXgSjdXgO7XWv9/5Y16EYoa9Mn4PrzT5NuD7QQ3jA5/5EMG4TUSBybQNA
         B9Ug==
X-Gm-Message-State: ACgBeo0RoWsdNzEJNqiFsYabSLzDVnsKYgS/Uk83I/F9u1ZzCr27UY6G
	2q/5R3KGXi7yFVpJcpMY4YE=
X-Google-Smtp-Source: AA6agR5cb5Tm4LGotKHMTaKQEEy3f7K13EQ6hZygpbFiZvlmiMf2l/erVuQU4aRaOeu78UH1m0BHQQ==
X-Received: by 2002:a17:907:7d86:b0:730:cd48:e2bc with SMTP id oz6-20020a1709077d8600b00730cd48e2bcmr35379536ejc.167.1662380759348;
        Mon, 05 Sep 2022 05:25:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3994:b0:726:abf9:5f2e with SMTP id
 h20-20020a170906399400b00726abf95f2els3414067eje.9.-pod-prod-gmail; Mon, 05
 Sep 2022 05:25:58 -0700 (PDT)
X-Received: by 2002:a17:907:2bf9:b0:73d:dd00:9ce8 with SMTP id gv57-20020a1709072bf900b0073ddd009ce8mr33497955ejc.151.1662380758274;
        Mon, 05 Sep 2022 05:25:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380758; cv=none;
        d=google.com; s=arc-20160816;
        b=ka0oKkFeRQxi8FLbbhr10hA3FCPW4KpgskdPpkMc/RVyJaPiU2IC7yLnmZ2ZROX0x5
         RBL4YbMtKm90gR2WpMgQ+bW902CwGbH+6h2ugqvL1iUyJaBl6QckuuymZ7DJ3vVrPGjO
         s2QJ9HN9/vqh/OFfFhTZlx2BKxriL17D/pDJd0asMKh60nLW68KhNUmCukNjRvCv8czm
         DzAdGHEQl6YZJNVe03bwW2zQ4hx8vlhc2vBYoD1aImanpQCw3Yl1I8FHzvxM+XzZIXj0
         MdynOYHG8y5TAd1Ni8odgA8mBZvTb2TV0Mjiy8vPp8LJn7Vq89qWgNv/PmoYQ2bKIE7L
         llig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=xU59YLMODhIvgc/g7m6GAFrx2Dkb/0YbdG6iSMMhfg0=;
        b=xYBUWyYrbGoLsFcDP55kXfdVgFI22FMUyfhfH7RkCvX4b3xy8Kk83k5fCf4LmqaPWY
         0WbZCkUsLSslMwkxaA+BywQHoheHetCYPwZUaxzoEjKNJjNULmqOTx2ap2VMphs3yUyE
         34H+ji2EJeE6e3vbNDULt5I6JmBDxRAXPpOE58FKspMSf3nlc361NCnJD/55p+F8Aqe6
         A5Kbz/9b8nTM7NeVaWPaEfjuf99dapE7s/ox5gYQIEYtllha9MDUGabAfXQBQvuw+8UW
         IexZsvnXPAZve6ggJ/8NgW8maS5f6haRp43WPw1/aXPfMO6+1FSXRATD4FF0h7axxHiK
         K0Ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HRK55Wdk;
       spf=pass (google.com: domain of 31eovywykcsiejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=31eoVYwYKCSIEJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id v14-20020aa7d64e000000b0044e9a9c3a73si70303edr.3.2022.09.05.05.25.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31eovywykcsiejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id t13-20020a056402524d00b0043db1fbefdeso5711489edd.2
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:58 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:aa7:d853:0:b0:44e:8a89:52f with SMTP id
 f19-20020aa7d853000000b0044e8a89052fmr3587265eds.293.1662380757922; Mon, 05
 Sep 2022 05:25:57 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:30 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-23-glider@google.com>
Subject: [PATCH v6 22/44] dma: kmsan: unpoison DMA mappings
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
 header.i=@google.com header.s=20210112 header.b=HRK55Wdk;       spf=pass
 (google.com: domain of 31eovywykcsiejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=31eoVYwYKCSIEJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
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
index 49cbf3e33de71..a8400aa9bcd4e 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-23-glider%40google.com.
