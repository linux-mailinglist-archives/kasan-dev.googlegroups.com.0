Return-Path: <kasan-dev+bncBCCMH5WKTMGRBRX6RSMQMGQEKYZET2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D98F5B9E1A
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:44 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id b34-20020a2ebc22000000b0026c273ba56dsf2095105ljf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254344; cv=pass;
        d=google.com; s=arc-20160816;
        b=c6kNxe3OJ5c46q15bfzV12SJr/IYQtlg7RfMh/88yhoGMk53TXjtPf5hRoLtCVY5hE
         oXXKClVGHNvTNHedGRJKVqKTgbFUHNo6dgf2cLA/5FMsGyAc/ny+3zsO4mJWviLXJLMT
         1ZiWJ3M8ZNsdDuELj0tMsmAI95XKKITIwxD/+irt/8w3RJm990nQsblt5A5mv4xDr6aM
         S/zanKRvHN5KnqcLFJxhC+wxq7OnTZZQi6eiHQKbi2uhDcdUlO44J399cY5V0dgA7TuF
         +51C2X+JljB/xnPx9+7Yjz0kq+jnY30p7AKeNgUAIO+fUtzIrNu1zxg/DGBi3kzaXoaR
         a/IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=w8sJRS5XMi8PxF/Jf2W2vOq6Qn1zK+kyvDjaD/Vek4w=;
        b=yS52dJJq+6CjOwChUPSBO91u7iTLpetl1hG1CLmdFMP/94QK8pPiQgJtTe6xCUvlDx
         W7hfis/9fYzKDZe20F+Tsw8QeC4XVGRtTv/Xzh7NNFeD6qTwmsvo3NxEu2Vlg96RefqP
         14eBQAGaDyNnOSsd4vgvnR4/sc+UPNSAtx9oRLBeDKKJmCICs3q3d5BdWmyN0sYMgxVD
         ffFzzzW1xSFv/v1Klq7r74nIOWBuXptWrOyb/zRFjxqnDKgBwlw07ucsVNtjAWjwhhR4
         t4IG+AXkZruxO0D8EZ4G+mPXY7e9jSWiUCoQVNwa0PE40A7C5yv1GueOLeBI03lFMX2y
         rxsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fPu7uIFt;
       spf=pass (google.com: domain of 3rt8jywykcxauzwrsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3RT8jYwYKCXAUZWRSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=w8sJRS5XMi8PxF/Jf2W2vOq6Qn1zK+kyvDjaD/Vek4w=;
        b=HhMG/J24qIK1ILNuDDyB1NiSjBz60JBJ298geWV8qoggvICKgxIjCcp6l6WGcgrCCM
         h5KGDbIOlCruwfoZalPFavP1MlPXF1jWYK4uN+7F+0vAK9inoeI9DMjimwk01Zb4ruM2
         9IQlm6b1g8W+ABICtV8ttcVzoiOiEH+xaKb30NgLHa9USe5CD4vdhn4dZ79ggF0RjJJr
         kqfqI6l/CaFcJUXtxm3EcqgFtBJ4AdHDSk9Pb2ZPhOEmDXUcgm3lgdzZ/bG2N9hUH1+Z
         Nbii/zBNA0LEtJJ41tBOLU5DMaaQtPD1vQ0p/USmWf9S0y47/2PNzIarGKDxWydGxfez
         y7AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=w8sJRS5XMi8PxF/Jf2W2vOq6Qn1zK+kyvDjaD/Vek4w=;
        b=1bFiTQ3CmmiuPu39BjT9LVnjPVA6P3Ki+3NpmOgMIwx4LAR3OBK9NOc6CadwCSyCj8
         SdceCoygOYxRsnteol85JP7ydRMeQwI7RhZ4zkV1ijtyJPQgdbiRCZ3yIBLmDr2R1Zp4
         MGZVk7NUER6+SbVq8p9Fw7LgNHzBysqgSR5lGqh76hQSd2Zyl35I8L8KzWUfljHlSZCx
         ACsadkdU1ivbzWJMeOgRW2Bn2HKmaQjwvxP+cYfiLBWhQk/psLeYhZ8BsQx9wtmXNzqD
         SWghQgfWdtB/vnuH+CBVsHW+kyz2d+9OIRBR4sq3v/HwBr+vBLTb2Tdz9L2X/Hbvah1l
         vuxg==
X-Gm-Message-State: ACrzQf1yasZbzcArYWsBcCX4JpE/n7fH+hZJx0cbjE1xCJFBKK97siG+
	U//b5qpucFY2AewO0qy2+y8=
X-Google-Smtp-Source: AMsMyM5F+Eys5rAFpCBh9+vtAclIuV6OzEAjycWMdQsImygjvxMg7JCdbolOMhVczRY163WSA0B8pQ==
X-Received: by 2002:a19:380e:0:b0:497:7968:e789 with SMTP id f14-20020a19380e000000b004977968e789mr121295lfa.242.1663254343044;
        Thu, 15 Sep 2022 08:05:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:5cf:b0:494:6c7d:cf65 with SMTP id
 o15-20020a05651205cf00b004946c7dcf65ls1229319lfo.2.-pod-prod-gmail; Thu, 15
 Sep 2022 08:05:41 -0700 (PDT)
X-Received: by 2002:a05:6512:1284:b0:496:91bc:39cc with SMTP id u4-20020a056512128400b0049691bc39ccmr118784lfs.531.1663254341754;
        Thu, 15 Sep 2022 08:05:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254341; cv=none;
        d=google.com; s=arc-20160816;
        b=KmDQWSPl+S3TEygLzWwFCld1qXS1uLt9lN0KaCUpDMe3WNWcNwdCcW9UsbWVie6DfI
         idiXDg8I+UzdE6kZF4kykzimPP/wOLnro4FAJv2af4J2i7BcjDP6NoSCZrzNoKAs20LI
         aEJ1Hznmv8Mxq3jZ/BD/ToXmjeAK0m6zYNT9qxKJHCY9QU+xWikRedlVcC5BiZbcEs0B
         LFLkO/3VLk0xadWWpcrVylnVglXCIzXJPrV6b//etDLaNGE52lYfl8bCljYXPa+lCfC5
         0NmTcaksDYNpQyf/EsONK0ZDUebkXZ0cAUgDQPrLwMfPiOtshJvr9lNmyTWs6+Nq86+U
         U9Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=2KqHkwy5ct3iw6Sq4tv6KYhLxwZCRI8E9SKEfBphS/w=;
        b=p0GB3FXwXcAzPAut/Ka/Eim5nJFc9yEDXDVD/yRdnKxMgDDj4+11AIG2IEXkbvAg9c
         4ltppBYRM9ObHySTi8KPH2b2jcV0kFWPo34n/mWOemBB2zRI5PU0MXeqxHTvrXHZ4u7Z
         q58TcnzyX/wcA+xP82/5xecMQxKzk1qGyuI4+om57XHYyf6HzjBT3U5L7XezWjPtpSAz
         n4n64KryitXLMnfq5Q8aGj7cX8k3WzTU+AW1yv0u8+b/VWKeCxoc1L/ny1j82Snyfqbe
         4Cej2BznjneUK9TByeHzUnj6N2YdskBTC5dWLJYss72x9xECYaBbgy8HnUyF/Xb66PAI
         hmIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fPu7uIFt;
       spf=pass (google.com: domain of 3rt8jywykcxauzwrsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3RT8jYwYKCXAUZWRSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id z13-20020a056512370d00b00498fd423cbdsi488947lfr.7.2022.09.15.08.05.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rt8jywykcxauzwrsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id sc31-20020a1709078a1f00b0077ef3eec7d7so5441552ejc.16
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:41 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:907:2e0d:b0:77e:999f:dea3 with SMTP id
 ig13-20020a1709072e0d00b0077e999fdea3mr271626ejc.317.1663254341181; Thu, 15
 Sep 2022 08:05:41 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:57 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-24-glider@google.com>
Subject: [PATCH v7 23/43] kmsan: handle memory sent to/from USB
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
 header.i=@google.com header.s=20210112 header.b=fPu7uIFt;       spf=pass
 (google.com: domain of 3rt8jywykcxauzwrsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3RT8jYwYKCXAUZWRSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--glider.bounces.google.com;
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

v5:
 -- do not export KMSAN hooks that are not called from modules

v6:
 -- use <linux/kmsan.h> instead of <linux/kmsan-checks.h>

Link: https://linux-review.googlesource.com/id/Ifa67fb72015d4de14c30e971556f99fc8b2ee506
---
 drivers/usb/core/urb.c |  2 ++
 include/linux/kmsan.h  | 15 +++++++++++++++
 mm/kmsan/hooks.c       | 16 ++++++++++++++++
 3 files changed, 33 insertions(+)

diff --git a/drivers/usb/core/urb.c b/drivers/usb/core/urb.c
index 33d62d7e3929f..9f3c54032556e 100644
--- a/drivers/usb/core/urb.c
+++ b/drivers/usb/core/urb.c
@@ -8,6 +8,7 @@
 #include <linux/bitops.h>
 #include <linux/slab.h>
 #include <linux/log2.h>
+#include <linux/kmsan.h>
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
index dac296da45c55..c473e0e21683c 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -18,6 +18,7 @@ struct page;
 struct kmem_cache;
 struct task_struct;
 struct scatterlist;
+struct urb;
 
 #ifdef CONFIG_KMSAN
 
@@ -203,6 +204,16 @@ void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
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
@@ -295,6 +306,10 @@ static inline void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 {
 }
 
+static inline void kmsan_handle_urb(const struct urb *urb, bool is_out)
+{
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 563c09443a37a..79d7e73e2cfd8 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -18,6 +18,7 @@
 #include <linux/scatterlist.h>
 #include <linux/slab.h>
 #include <linux/uaccess.h>
+#include <linux/usb.h>
 
 #include "../internal.h"
 #include "../slab.h"
@@ -245,6 +246,21 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
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
+
 static void kmsan_handle_dma_page(const void *addr, size_t size,
 				  enum dma_data_direction dir)
 {
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-24-glider%40google.com.
