Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXOV26MAMGQE6YI43UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 033555AD265
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:07 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id x9-20020a056602210900b006897b3869e4sf4939412iox.16
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380765; cv=pass;
        d=google.com; s=arc-20160816;
        b=yittkcyKggIB0yFdzgwAlaEv/AIq2OQaB9gji4SeAIt2VVnxk6afrkkYWry25EMyYX
         87JS+VBETJp9Rr8DKhz19/kXnTGNRn/WX04JpcXw4Tyu3XmW9Ce+gU+zlK8r4uST025w
         8x39NnZ7ThLzx/LJ4JympUaOBNtb4X0lU8NY8Jh7elfphNjZfvi6ju52+QXW4kwoTvfo
         FwAALe6u0v2VEl+RFaDGzYDUAPbaGfbl1rpxLTDlWmIoHd58lLPVHfe+TRvb59+UWx+8
         t96ptWKWdY6X30ZutHyEazgJtPAhjDKNt8oiYWPOHJrN3ywfn78jMsg5wo7H9HkyzjXg
         hsmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=NEbUilJJtBun3mgSh4kU0eMD+hiPhcRUULlbozWXnvQ=;
        b=w1/Lm7rUxrLhiDRKZr8Tea+aYhv0fS09xufp6bldcw6OY5G7DooqIK8r60CgWFN7Cj
         Y0uZzPwM/Np3mRNQfUFZ/o6IzKWIXdEdXfHHD+jab5RPWGo2HGZlvwonlysA/onugVRo
         35pEH6bFejtJCWjlSro/lFgFwaqejZH+R8OBss+3N7NAzoWbi7V5f7TGF10+UMInL1LB
         J5REj0jSqdtaKNwxAVAbhwsfaqjNK8+ih7shHZHea1tvoZmlbft1wnbogPLBbEqeQ7GS
         yq1pHvr1SHrVG+PNG5Mk01TpN8pdi44uIs0n/ZX3COgRUA7sOXeaAR9OimgAwd/XYYqc
         +N9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qNMo5+TE;
       spf=pass (google.com: domain of 32-ovywykcsgkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=32-oVYwYKCSgKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=NEbUilJJtBun3mgSh4kU0eMD+hiPhcRUULlbozWXnvQ=;
        b=tmbHYOqWJBSZHd72gaJ3ngBV9I0W46fViYpN/Y3ki3VAOSrh8a74iKrUVpakpFBlpE
         6hvyKtTqQO5PTG0qfMQijAQ7pa5QXiJniseFl60JwfNqPduYQ2bYjqZtelTwFRDfbd0T
         dWTTmyWU5VklHVU7ckmYA1k/RnIQk84iM6SxXNfHda1BqI+YBv7xaIZOkoeeHMoODLcD
         ujtOIYWnssE6x1DUDSC8P/IE4RojTP84eFLnK/d/WB4FlAEYvFazu9uBkK0ZgvRwkgZd
         8yNpGUDod/DzjEK3VOVqBeKV3N/3m9vAUaAw9JOFyEp1BZUpAu2I31Du5LrfOqMe9Jrn
         5G2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=NEbUilJJtBun3mgSh4kU0eMD+hiPhcRUULlbozWXnvQ=;
        b=fAVgx8aYEzHSpH8gAfqGh7C5zQWmUG+GLT9UZsuOIUPAbJAMozsblIGbuZkIKxJYJ0
         P65kI10o2/B3iR7EPIE9vnfk1f0M8byBRcvxDzimAQvPemGEJtDeNJ8IgwRZR3S7/x4r
         iQRxEIcES3HxxuePjMGLDSByYm9uGyjZZJmXPjHc09elUNREqzMv3JQdY5HZOPXecZai
         lKI0/CumMN8dCKBDSIzvvRhcdObzdAQ8jkwhKF7y6ki4g3Q0wMQo0ayKFTCly1Lq66tH
         8QeT1Fo42qSxlZ2PtMz/aoW4vfQjEIkphv6QRPvkwFO5XTwuAb5lMLNpnnAh80TCvBmh
         rc0w==
X-Gm-Message-State: ACgBeo0qM2kf/NvXzyG0K2kmwq6ihzGFO5zmHToXmGKiizD/mBtEulwb
	1VH8yESsiAN8y9bEnthYUhs=
X-Google-Smtp-Source: AA6agR7tDeSiHjYzNP+Fqjh6rlPEGkN5NWattv0gB5grcletwx2TcD0erfpd7yrpqoxQVH/fGIhzyQ==
X-Received: by 2002:a05:6638:35a8:b0:34a:456:e416 with SMTP id v40-20020a05663835a800b0034a0456e416mr26622694jal.229.1662380765382;
        Mon, 05 Sep 2022 05:26:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:ece:b0:2ea:e378:f7c9 with SMTP id
 i14-20020a056e020ece00b002eae378f7c9ls2417952ilk.5.-pod-prod-gmail; Mon, 05
 Sep 2022 05:26:04 -0700 (PDT)
X-Received: by 2002:a05:6e02:1a6b:b0:2f1:a7c9:ea2e with SMTP id w11-20020a056e021a6b00b002f1a7c9ea2emr292328ilv.176.1662380764079;
        Mon, 05 Sep 2022 05:26:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380764; cv=none;
        d=google.com; s=arc-20160816;
        b=Gy8cRBY7cAS+o+x/p1sADfH1nRQvgLoYKr5e8onikbUiMs3Gi/6cpEiOYRgRd65cR+
         O76tU0t+u3YxIX2CvHuuotD2paFJlPBXDLaHTc/iu61FuN27sdEs3NizAYo7zACQ17VJ
         211DgfuMcDgmzsreDyEB7Ra0T9vLuOkBvmtYRE52uvxohSjUS6tCeckmNIvL3g7lSJT1
         brO5HLQoXXZJvTaPSpP1i3Uni733mnBpJAA5jWpi4l4GE6nE8d6+Em1z79tJMhpcCy94
         JJRq5rYAnruUUYaz0v8s66B8vifgeW5eOF84x6ZnGTc414UOTmuKcRmr/VZ8BgvOH2UG
         /lAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=2KqHkwy5ct3iw6Sq4tv6KYhLxwZCRI8E9SKEfBphS/w=;
        b=aNIXQUhS58QciYEoXoQbxsTAJ24ut6qZNbfCXTnDuZ8hubO7pa4OGHSuigv6+dMdGY
         wzIxn118rHbdDHV3EYlIWMWbxyEFKI5oIv/APSiUHd2OAMoyhwot9x3/dh75x2Na6zjl
         DSUjWX6OppBTYKiVB6EckQTzD4HPsWJlk+1wuP866073dSBvTe2V8XIdgsZC4KFtUHs+
         tIHVgAEvrYS8ePWjC3tvzdi9iIIHbkouL4QXuJd6GLJzCWJuYwH40F6spgggKCX0WDVL
         QBl2ls32kosD3qSrbTk6N9T4lUAO/lBX1U7zKd9MBjgHDP16oUV6H2tbmENN3ADvIyIT
         vgzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qNMo5+TE;
       spf=pass (google.com: domain of 32-ovywykcsgkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=32-oVYwYKCSgKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id e1-20020a02a781000000b0034c1669ea5fsi462120jaj.7.2022.09.05.05.26.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32-ovywykcsgkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id f3-20020a056902038300b00696588a0e87so6615263ybs.3
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:04 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a5b:549:0:b0:677:768b:2784 with SMTP id
 r9-20020a5b0549000000b00677768b2784mr34118519ybp.296.1662380763627; Mon, 05
 Sep 2022 05:26:03 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:32 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-25-glider@google.com>
Subject: [PATCH v6 24/44] kmsan: handle memory sent to/from USB
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
 header.i=@google.com header.s=20210112 header.b=qNMo5+TE;       spf=pass
 (google.com: domain of 32-ovywykcsgkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=32-oVYwYKCSgKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-25-glider%40google.com.
