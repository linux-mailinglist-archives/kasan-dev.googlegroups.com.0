Return-Path: <kasan-dev+bncBCCMH5WKTMGRBF4H7SKQMGQEHUHW3GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 50E17563525
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:24 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id h125-20020a1c2183000000b003a03a8475c6sf1080222wmh.8
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685464; cv=pass;
        d=google.com; s=arc-20160816;
        b=loaHFOrrIXE24lEKtzmFctEm42u8M33S6L0cv5eNQYpyUs8NpHYyfWkLhnxaAJ3kw+
         6Q1g2J2ptxUz8JoVmDz/EvCwWVXV9S80z5eqerlledLtMKXD4vMZXAYBpfUyZ+1Fimsf
         rUSiDH805UayUqpRX/CV6tWS795woZAovuy99Lyg9eU85Ys6ndv/TL/E6jo3dX9of7r7
         rS5AOcUtCcKYw9xGpi9kQBPKj7iXcjAP/wswtF6LQObcBEETinqPrdZJ36pG/fAdBQJU
         BwVNX4Ejkmu/iWYdxeZfA5B5QFNKbQhMwqqZnlxhKtZbsKmq4vy+7HDJIo5v7AqSsN5M
         N1xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=VCGnbmgNsOkTNeYOCMTXqaOqsdfys7v4sN1YkGHnXoQ=;
        b=rHdnG6+zpqGke9mjMABsQ/hS06gS1eX5mfEZ0T1EiELIw7ysMdbrdR3sNKvJtVRIho
         wO1+dLqla403N2igPd3KIBltuWs+l4RiQHIpXMigfxAb4dEUVZ/En89qQn7tpjjZqWZV
         INfj0K9mjHJw4IXxEU5hcyhVNj7mMChNh3A7lx0ptk1hA+FXG+hoCQ0uiNA3iwSl7R2k
         4g4z4RcCeOv+TwS1a/96S4068l3y7/lBzPuiyX585X54rVux+nB5qXb3qhviTyDbQcdO
         F1gqLQJb2BupnlBhxyhOds8xyN2sh15UC/Z8FvlbWZjc1DimYF8tB3PntJJb0aR0nG7S
         OMYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lkUxcVIU;
       spf=pass (google.com: domain of 3lgo_ygykcbubgdyzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=3lgO_YgYKCbUbgdYZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VCGnbmgNsOkTNeYOCMTXqaOqsdfys7v4sN1YkGHnXoQ=;
        b=TM7QSdUeBKPemIzII0+LvROX/sphAm554veGLShUL1BgT7WX4+jnQHodKdf+WaKzSh
         zVYd6vzxvilR2XbIKpYAw1kwyqlLG7ezSn4Yl4ouyZWCdo2fIwvUpAVfR0MgoLYQyazK
         fIGeTX0t0Ekq+iC9r3MURMzrvBu+6D1JYGNy/f7fRQDLYOuyCOXEd1YYwiwLhXxARSMh
         Sm6nu2VRBXuNvcmSTZ9LIB07K+d06HterhJdX6rcTyTfZmEGcDUd4PjeEPyeUH4z1Qiu
         CUgDk2x0y49CUZOfIhswT9ZH8YqbJteFAL6F6yO+8ZVkdg8PbUs81/ELIaHmjImYqYMP
         WXSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VCGnbmgNsOkTNeYOCMTXqaOqsdfys7v4sN1YkGHnXoQ=;
        b=R4Ud1zs8VE/sfPI0CO62oo7MkBV/R8+EtfeactsN9XIVaC7TFU5JYSEf8o8wuwbaXO
         Z4/QhVJ9FUQt7dAsBzK899z7t4BSzPh3sp2xEdX4aN580KL+sDvoAet4QLP3bp0snX/y
         MIg3+u0Mk+AUCJ1R5CcLodSKzWFgOAv0/BAx8iDa8kpwprSXCMrAvD4X+n6ZtCtbWp8y
         KU1Iw0ObIUqj4guuqo4VA63GRuSqSdlyKL3f6SpgWnRhNpG0jkL/JintI/B5lrZBkhG+
         51o0/vU8eO0x+a4UA5QlVvcyueYF/km/F7KJvJVho9eZEsbg71GkT6QGe4Bdqy4M3lQI
         sAzA==
X-Gm-Message-State: AJIora+TPZYNThuTl+uDrQcNy3g9m5GFEiNPJg4GaBVnZlmO4MSqUE6f
	YFiqlf3XDw1vcBETTOFUxjU=
X-Google-Smtp-Source: AGRyM1sr+Qm27AcCIem1Kyzg9CXieq1PVcts35E+e8hOHgffZlTltJGetIxDVeZvcjE74R7MhpzwtQ==
X-Received: by 2002:a05:600c:4e8e:b0:3a0:4f43:beb6 with SMTP id f14-20020a05600c4e8e00b003a04f43beb6mr18654658wmq.176.1656685464032;
        Fri, 01 Jul 2022 07:24:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:184a:b0:21d:2802:2675 with SMTP id
 c10-20020a056000184a00b0021d28022675ls11355222wri.1.gmail; Fri, 01 Jul 2022
 07:24:23 -0700 (PDT)
X-Received: by 2002:a05:6000:12d0:b0:21b:a248:9a2e with SMTP id l16-20020a05600012d000b0021ba2489a2emr14590916wrx.437.1656685463146;
        Fri, 01 Jul 2022 07:24:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685463; cv=none;
        d=google.com; s=arc-20160816;
        b=Tx8wcXPkJGBotfAGp6ux5nEqt8vp/gb0LBDV74uCnI86+YsPhW/uilVyu3JQ2M7Z1Q
         Yz2H4goN/qHXLbqV6oRh/buIoYzQifiHjM/8u/eIIuUjo/rKO1d0auvhq0rorSAlXNgR
         E9LqSBKFN/6PDBPyPnRO9ttkRyqCBLxUxWsregvEMzFqwDQ2+OHUULrJM5ZSgsKThUsd
         Mm0ITQeYjPfJXa+ti/oa6zpWbomDrsjX9GwMvUGir7F9cuzRQFJZ9DvFSl+Un143IbaI
         fNNhPI5+67YygX//NP+P16TNGUXa8HqClID4GRXwjcYGwGPmFQ4FKh+obKw3luWw+Q/i
         l+JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=zhMMZRuLDF6Pq/3lj4DVrVpRjyIDnZPpkOwtCQdBukQ=;
        b=wmaaQ7d8NT+MphadSiDvIi/IS7hwpLKfH0FOEaMbtMfQrqbgcnN+BEU2EN10kyWxJv
         55oCGKSW62gAgDbRy70lw9qtUO7fKUjUXhSRp5xLx8i2F8gRKIdpD6TKPAWABnEfh9il
         9UQiFuui1y1RWtZlQfIkomoOqxJB66CmqSntb56W/q6ZnD/BPAZ+nxBeelt5u+xqT3nn
         svd/++zXhLlYBVsE6no71jUwcgb3ybZ9TgWisSfvNNKFrdrhqM8BSOe7wrHBfqKoOH2H
         8gXkS3l1gpAfpI87HuUjQDt/ibCMmTw8wHyp5DJemZBwxMurpPPJ+yYwiLgQvazCs2SM
         A36A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lkUxcVIU;
       spf=pass (google.com: domain of 3lgo_ygykcbubgdyzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=3lgO_YgYKCbUbgdYZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x14a.google.com (mail-lf1-x14a.google.com. [2a00:1450:4864:20::14a])
        by gmr-mx.google.com with ESMTPS id ba28-20020a0560001c1c00b0021d2e06d2absi270360wrb.3.2022.07.01.07.24.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lgo_ygykcbubgdyzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) client-ip=2a00:1450:4864:20::14a;
Received: by mail-lf1-x14a.google.com with SMTP id e8-20020ac24e08000000b0047fad5770d2so1183021lfr.17
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:23 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6512:1291:b0:47f:6ece:310e with SMTP id
 u17-20020a056512129100b0047f6ece310emr9097403lfs.389.1656685462649; Fri, 01
 Jul 2022 07:24:22 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:49 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-25-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 24/45] kmsan: handle memory sent to/from USB
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
 header.i=@google.com header.s=20210112 header.b=lkUxcVIU;       spf=pass
 (google.com: domain of 3lgo_ygykcbubgdyzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=3lgO_YgYKCbUbgdYZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--glider.bounces.google.com;
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

Depending on the value of is_out kmsan_handle_urb() KMSAN either
marks the data copied to the kernel from a USB device as initialized,
or checks the data sent to the device for being initialized.

Signed-off-by: Alexander Potapenko <glider@google.com>

---
v2:
 -- move kmsan_handle_urb() implementation to this patch

Link: https://linux-review.googlesource.com/id/Ifa67fb72015d4de14c30e971556f99fc8b2ee506
---
 drivers/usb/core/urb.c |  2 ++
 include/linux/kmsan.h  | 15 +++++++++++++++
 mm/kmsan/hooks.c       | 17 +++++++++++++++++
 3 files changed, 34 insertions(+)

diff --git a/drivers/usb/core/urb.c b/drivers/usb/core/urb.c
index 33d62d7e3929f..1fe3f23205624 100644
--- a/drivers/usb/core/urb.c
+++ b/drivers/usb/core/urb.c
@@ -8,6 +8,7 @@
 #include <linux/bitops.h>
 #include <linux/slab.h>
 #include <linux/log2.h>
+#include <linux/kmsan-checks.h>
 #include <linux/usb.h>
 #include <linux/wait.h>
 #include <linux/usb/hcd.h>
@@ -426,6 +427,7 @@ int usb_submit_urb(struct urb *urb, gfp_t mem_flags)
 			URB_SETUP_MAP_SINGLE | URB_SETUP_MAP_LOCAL |
 			URB_DMA_SG_COMBINED);
 	urb->transfer_flags |= (is_out ? URB_DIR_OUT : URB_DIR_IN);
+	kmsan_handle_urb(urb, is_out);
 
 	if (xfertype != USB_ENDPOINT_XFER_CONTROL &&
 			dev->state < USB_STATE_CONFIGURED)
diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 55fe673ee1e84..e8b5c306c4aa1 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -19,6 +19,7 @@ struct page;
 struct kmem_cache;
 struct task_struct;
 struct scatterlist;
+struct urb;
 
 #ifdef CONFIG_KMSAN
 
@@ -235,6 +236,16 @@ void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
 void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 			 enum dma_data_direction dir);
 
+/**
+ * kmsan_handle_urb() - Handle a USB data transfer.
+ * @urb:    struct urb pointer.
+ * @is_out: data transfer direction (true means output to hardware).
+ *
+ * If @is_out is true, KMSAN checks the transfer buffer of @urb. Otherwise,
+ * KMSAN initializes the transfer buffer.
+ */
+void kmsan_handle_urb(const struct urb *urb, bool is_out);
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -327,6 +338,10 @@ static inline void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 {
 }
 
+static inline void kmsan_handle_urb(const struct urb *urb, bool is_out)
+{
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 8a6947a2a2f22..9aecbf2825837 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -17,6 +17,7 @@
 #include <linux/scatterlist.h>
 #include <linux/slab.h>
 #include <linux/uaccess.h>
+#include <linux/usb.h>
 
 #include "../internal.h"
 #include "../slab.h"
@@ -252,6 +253,22 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 }
 EXPORT_SYMBOL(kmsan_copy_to_user);
 
+/* Helper function to check an URB. */
+void kmsan_handle_urb(const struct urb *urb, bool is_out)
+{
+	if (!urb)
+		return;
+	if (is_out)
+		kmsan_internal_check_memory(urb->transfer_buffer,
+					    urb->transfer_buffer_length,
+					    /*user_addr*/ 0, REASON_SUBMIT_URB);
+	else
+		kmsan_internal_unpoison_memory(urb->transfer_buffer,
+					       urb->transfer_buffer_length,
+					       /*checked*/ false);
+}
+EXPORT_SYMBOL(kmsan_handle_urb);
+
 static void kmsan_handle_dma_page(const void *addr, size_t size,
 				  enum dma_data_direction dir)
 {
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-25-glider%40google.com.
