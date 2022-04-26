Return-Path: <kasan-dev+bncBCCMH5WKTMGRBKODUCJQMGQEP4OSSPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id DD27C5103FC
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:29 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id cz24-20020a0564021cb800b00425dfdd7768sf3907463edb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991529; cv=pass;
        d=google.com; s=arc-20160816;
        b=DEZrI3UM7WtEOzBEpxwJcWf8ls/dYtu3VcihrCkXHKEgH8qm/6eKRGG1nT+mtm2GgG
         QLkXl79+iQxHnWyeGnDciw6I6obKfxcLjBnU6hHRKaaD+sIner7vlvjd8uaFzWET7LKy
         NfIBGoT1kYOU6HXjnoEhQmUsRPjZUkVKvPDFZsp+VlbOA+NFZwKo+dtSGncTFOnhsOGr
         MuEmQLKx5/e7f/scCNHd0Mp5/OQVdJAB13vUOgs7exUKiVy1A8+WV00NqJXPwbyLOynu
         NI8zgR9hKGOYL5TAexBbwrLlrVjEpWilOLDnsxMB9ikHiR4ZHrd/Lg9/7JKQJbGAKapb
         1TPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=a6c9t6whL4WxB4p4NtA2/IzRHrf1JqTyXmBWi5cbktQ=;
        b=s5gzam/jp8SBKPtlxbFeDgptZo7fReSVnEQTLkye1ootcQUcLx0O6kPPWKxryn+Dbv
         /+hrYrlTuxG00XxQnWL+uUD//CZc/p9F9tXcELhO8Vwn8bDeG2UtiOG+RqFAR0AV1OKT
         cADt/qq3KIMiw2QbSziyMUBd8vV/4yZdRCubkQaWQCv4Je+3e0580t8SdGj3fkWSu1XY
         mtU7238Ulx0WHoE9RxSzTOclM26wctpMjrzwWUOS0ukXKwCKdrhmYYFARb5EL/7/GS6G
         Vw4TeO5R7fowG/OdTJa6sFXnAc7esYir666SV9B1xvVMNZ3ae6YIsHKRIBwHVks511bY
         6OtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HKjl4po9;
       spf=pass (google.com: domain of 3qcfoygykcaulqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3qCFoYgYKCaULQNIJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a6c9t6whL4WxB4p4NtA2/IzRHrf1JqTyXmBWi5cbktQ=;
        b=KLU+1AZm+fw7qSvcEkJkoIfkfUIRySaqslnRX3gnCtZMo6BYgbcjpphnWKulDdvjjo
         kZ3Qsbi0FVGcCFp0Bsdi1EQa56TlWIZ5D3a4u5DIgVYnNkw8OhcJ/BAsvMiEGadwhJx3
         9twg34h0mrXEztdYC+6F4St0WwYKve+3VTwmXCTpO3pW3DD6H+HSGHenV91iHieN5MqU
         I6WKMBF0giy4he0dXbXiAHZ4diV5+VMVI6DefQlGMUhPNc/jLJINIb01axgOKC5xYfCp
         kr4RE2CizCH4svBKsorJ/+XLdeIFmFnKqkf3VQH6kEgHJNEfKM1GRafl4vMM8PcEx3TS
         MOIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a6c9t6whL4WxB4p4NtA2/IzRHrf1JqTyXmBWi5cbktQ=;
        b=inJ1Nd64reXdUZuoUgsovM2/sG1i+4JSb79SIhU8bvY1GEyd4u2prOLT+o+FcTDgPc
         f0dPRXLqRqMPgDvWNFZFj0pom+tD/ymWOxZO7bwm81/lsWEnaML6kdAO1V7iSU3CpqI2
         Yw3Yfy9REvyyYEfOa7gs7fz0BvgkdiiNZiDDuABfd0AYAn99KWf5GSlsnvmKfYy8PjDi
         WCOSQoafemcqffUD3fbfRdDuTXtKYSQHElXZNOH7i/Om7+hwazh8BJezQAck70fYQXys
         LnCqOovgPn8Vz7dUg1XO/iSLfL6bqzfuxQoZhSe2sKeXAF6TEXgaY8W4hMP5SzljBh8L
         EVHg==
X-Gm-Message-State: AOAM531EdqaPSICRQ1voF+ZRR51teTrNsbhj1Go/CM8mHXNkqkTD4etz
	GQee4liD5udqdadvVsbXqcQ=
X-Google-Smtp-Source: ABdhPJyKRv2WeWFELLqHgAJj5sZbdqkhDRf6+G9CD3Lthn2v+rnG8wGYJGT5sP4EDUdXLb91vxECLQ==
X-Received: by 2002:a17:906:4fc4:b0:6da:b4c6:fadb with SMTP id i4-20020a1709064fc400b006dab4c6fadbmr22551908ejw.282.1650991529699;
        Tue, 26 Apr 2022 09:45:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:628e:b0:6e8:76c2:5876 with SMTP id
 nd14-20020a170907628e00b006e876c25876ls5354314ejc.7.gmail; Tue, 26 Apr 2022
 09:45:28 -0700 (PDT)
X-Received: by 2002:a17:907:94ca:b0:6da:b785:f067 with SMTP id dn10-20020a17090794ca00b006dab785f067mr22483190ejc.654.1650991528624;
        Tue, 26 Apr 2022 09:45:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991528; cv=none;
        d=google.com; s=arc-20160816;
        b=RluNZEqRhw/m4a3Zdi7WY4r9so+ItxNOjL0Zil24PdXpkLyT8MRJG9gzi0YgjUrDeB
         xWynoXf2qXHSDvPzxNWlFYHZds2aj6r4H/uWk9A4WxbCkEBxgDly9fpoveAetXYCi7ar
         SYSr1WHmr74zm5aD/jnIJKK590ktjpAG2or+Hlmt3DRP+UQiE2xUuizIL70FIkSC1YcJ
         LzyfCn+bhYb1z4uSqacLnfELRL24RgsyPaOHQHJ5jHuR6pr7cOWVK6a07bBPXqmBMn0p
         ANtQKxCz3iDk+nDxxByg6LfRWb4pjD44ruhRpOdjjhDyXrTnqOoK3ONj57nkBMTCLBL6
         vozA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=kXck7gc8vUdG+uIpTKbHiyCLJU3V9DKcF3fYel7nQCw=;
        b=wyOzX2PRj81DpmYGqLQv6FUMGAhZddIKV/skSgvJNi1JUVQkZB/PhJAvJJc+e3ORzJ
         po1Z2ay0v9F2+xVjeptzx6Wc36DVLMLn25wEFiw+BHZPaW01c9DlpfJKK1OZhL36Y8Bt
         29HWS6Kif+vBi8FZej7tjuvjmKJlklrzTHVcereWkQ5RBaeNmI4Dj2KgqF+5Ys9pRLeh
         3zhPdXNE4e+fgnxIPp/3yp+kAsJ/allGfu9qshUxqQAFGVPCF1fVr1/Ve7eHEF0Xa9tv
         keh0TqLSnFTXcwOARLEDnximavg61/x0tixCj5H0nARna+/nQ/+Uik+YH/w61PFp/etv
         VwPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HKjl4po9;
       spf=pass (google.com: domain of 3qcfoygykcaulqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3qCFoYgYKCaULQNIJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id s4-20020a170906354400b006e8421b806dsi865720eja.1.2022.04.26.09.45.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qcfoygykcaulqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id gs30-20020a1709072d1e00b006f00c67c0b0so8987224ejc.11
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:28 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a17:907:1b15:b0:6d7:13bd:dd62 with SMTP id
 mp21-20020a1709071b1500b006d713bddd62mr21844408ejc.673.1650991528244; Tue, 26
 Apr 2022 09:45:28 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:55 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-27-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 26/46] kmsan: handle memory sent to/from USB
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
 header.i=@google.com header.s=20210112 header.b=HKjl4po9;       spf=pass
 (google.com: domain of 3qcfoygykcaulqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3qCFoYgYKCaULQNIJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--glider.bounces.google.com;
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
index d8667161a10c8..55f976b721566 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -20,6 +20,7 @@ struct page;
 struct kmem_cache;
 struct task_struct;
 struct scatterlist;
+struct urb;
 
 #ifdef CONFIG_KMSAN
 
@@ -236,6 +237,16 @@ void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
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
@@ -328,6 +339,10 @@ static inline void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-27-glider%40google.com.
