Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIOEUOMAMGQEWBUVSUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 125715A2A7C
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:22 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id y14-20020a2eb00e000000b00261caee404dsf663226ljk.4
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526561; cv=pass;
        d=google.com; s=arc-20160816;
        b=WaQvT2ebYi1HzQ0bQiqu2HJX5lLw4M+VlzFtSctdvJ6s+qHZQorEcBWtG/oXOW+w+e
         zgxwlw0g+bE/xOTqL+TMiWnHBwQyqlccrUGt2pfTpJ97d7c5XmEBzesoek31dRbs5A/o
         GgBFnnvmH/1WmCtSHH6FEMGmH/Ln6qcuUTWpeHkW9uCaz8r04OzcbELAMxBXCUIFnbCJ
         LN0Q8sMk34qVjrU5GDsHcVAx9EZNp0vob1sarP9tY2WpkeU1ontc5el859B8oxbJPVIP
         ROkpQ+dHgVgJtlaeVoJQ3vNcQHi1X0DL7YFNeQ/W7yS4fy63BkcRo1uyfh/6mzlgF8Sk
         IuKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ifhVuHJDWDfsXQZlAL0HexNiT5CkxF6VmHE297JVN8g=;
        b=QYAiVeBzKNSX1Xg9T+9bru3EM7vFedrqfsMiFO2tqS6IHEEx1TUBFmWicWRI7fzuqI
         /0kebtrNLW9vS59ZHGOIBIs6FEsrsEx4rQp5oeIHGGvPQo5NZLS98JEEA2ZkfLpMAry6
         INlxcviF2VoeUKQaD9Fe4MYaKQkXMYW/xvew3fg1e/4ga2s85p4VArNcpDxrTqKUwUeo
         PXpQgJVXqytDY34/YuYOhzE9nF3ehOjVtjy1taJwq4hQR+6+C6Y9yvORs991PBj0LLNn
         qVbnmfTRWJC4B3aVVqTJebT1cJ0gwFdVT2z+Pe5kbNOua73fq2HNcRa8kITXHMz1vNcP
         9haA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eh86TxxX;
       spf=pass (google.com: domain of 3h-iiywykcsyinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3H-IIYwYKCSYINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=ifhVuHJDWDfsXQZlAL0HexNiT5CkxF6VmHE297JVN8g=;
        b=W1xUVMw/9hGY/mRtYLttpYzlkevf4PCOgj1zaJVYW3FgKyTSJiH+HGWoZVU/xx6hbQ
         4fNvEw8uck9NLF6jI2dFBaxYkNNs4FBOi0BHC6Dp07xokuhlj65TOaANfqxY9cRMeenY
         H4tyGlFH+5w+iGQannl+PRfoIdoPg1eu/Ngl9RZEvzwNJWEk6/Tp2SS2qClokeBkR2Ia
         blYkK8u2kuu1uq7zSbQsS/UYv7arhKTFmlmBI175P1rrY5rO92L4QW/pI1sFKC6P1fPh
         9BpoRWc/rc809g2LdEpwEGKf/YwiwxtK7nKLE0U3k5Si8OZpLoeG394OBHivn0W9fUOD
         zFzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=ifhVuHJDWDfsXQZlAL0HexNiT5CkxF6VmHE297JVN8g=;
        b=Pkw2swKpXki+B/SLZ3bPuJJhgLettXR8k++E+3kjw8fT1HE7OVaN/gTLxYJQUwcWaH
         HSHW4/MkEhxLh7n9xNI9kYxeJvCmIGe8wRjoz7PcoOWlXIc0lD/hnyi30/q20dD97rAd
         o1Eb0Ixq0ZaEXhFWvsSurJtIIzp+PRqxvXDVpFRP6nIRm/UNYYP10X8u+nslrPxjSEfT
         h1pTiO/J1EC2ZHwMezqmTYYNIga5PPfzmZuiiPy9TAvNpEk5gSaEY2d62b8cLvteax8s
         luk9wmJRYxLciS3Fi0WVWgarMU1ckGV8AWXTWfayy+a4FjcPP3lx9rTWWr83kkai5F/5
         kkyw==
X-Gm-Message-State: ACgBeo3zsVONuNO+Nsqq6qjd6exAuDtrwS+YQ/NpZfRsu34NjEBASMAx
	Eval+JyX8mrPNp4XJVNB/M4=
X-Google-Smtp-Source: AA6agR7OLWPmKO35En+ljlkwKb64F3qTe7lqZ9puJAXji3QScEnesF07GPs0kh1WVug7FQePpZ4png==
X-Received: by 2002:a05:6512:1190:b0:48c:bf4e:b64 with SMTP id g16-20020a056512119000b0048cbf4e0b64mr2770800lfr.239.1661526561631;
        Fri, 26 Aug 2022 08:09:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:c98:b0:261:ea54:6c9b with SMTP id
 bz24-20020a05651c0c9800b00261ea546c9bls693020ljb.4.-pod-prod-gmail; Fri, 26
 Aug 2022 08:09:20 -0700 (PDT)
X-Received: by 2002:a2e:a269:0:b0:261:e5b0:2163 with SMTP id k9-20020a2ea269000000b00261e5b02163mr2486462ljm.244.1661526560276;
        Fri, 26 Aug 2022 08:09:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526560; cv=none;
        d=google.com; s=arc-20160816;
        b=mDCl8d9yb75fqIsDzPvW9XhDHIgoo462I4znSt1a/2QZ5onkl/lgF31y/XwDkElMa7
         7VA/wK4BzFgoWLKxZkGbzm0dJrSM87DEpOhbYxWoAKNH9TvheO4gEmyZ+tgL8yfgdE1s
         W876wDArKWjb7drbJYNjB3x6eP58CvXREcg3VVsjaLhbmJ2JxBgZaKgX7ko1MLsuFHjE
         eBIgQ9kwnU/yVf6CxcSrSRE7s6/370j39/1bKiuuu/iwHEPw6VuhTPQJmXaUxkJJYqbz
         jL9yrgXeB1rffrzkyr2sDSuUmkVhpj1iD190CjuEyZKUX2uL2ADCyz/WK+3MglgoiY2e
         ze7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=PLcPoxyp1Xs3M8CttNEhz4gH6ZMFq0yiGHMdwreSHbw=;
        b=pVldoqs4q7xKz4L/1O9WAO7z5xDnR4LoZpvUfYIGcfbviN1jkPbn+KBKnv9DHBmaYd
         X7zQjXiK8ZzP9D4sABab8S0lysMxZ/LNV7dheViwgZI8cODPWZxVjLh+OGpLAwaM6PCX
         xie/8Ap89FeA20mZ38mXXMytLJRF1NBZ6gd07Pmpc/oFHH2kmr7wrGfOcY0FsMjVXhsS
         8KMImbRRNoi3WmQ3eJdgpDTODscE/z55AnvFGdXE/ZLybLrjpcGbNH+wKd+quXgIbnmW
         Q0UPYmUjNIjgZbcXjej6vC0hwwCQrb4ydL4qIgezTEVJJ2QRQtdg6j+UfxznkNTOzCYp
         tV0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eh86TxxX;
       spf=pass (google.com: domain of 3h-iiywykcsyinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3H-IIYwYKCSYINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 2-20020a2eb942000000b0025e576d2a12si86732ljs.0.2022.08.26.08.09.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3h-iiywykcsyinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id c14-20020a05640227ce00b0043e5df12e2cso1236900ede.15
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:20 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:2804:b0:439:83c2:8be2 with SMTP id
 h4-20020a056402280400b0043983c28be2mr7114308ede.292.1661526559748; Fri, 26
 Aug 2022 08:09:19 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:47 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-25-glider@google.com>
Subject: [PATCH v5 24/44] kmsan: handle memory sent to/from USB
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
 header.i=@google.com header.s=20210112 header.b=eh86TxxX;       spf=pass
 (google.com: domain of 3h-iiywykcsyinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3H-IIYwYKCSYINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
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

Link: https://linux-review.googlesource.com/id/Ifa67fb72015d4de14c30e971556f99fc8b2ee506
---
 drivers/usb/core/urb.c |  2 ++
 include/linux/kmsan.h  | 15 +++++++++++++++
 mm/kmsan/hooks.c       | 16 ++++++++++++++++
 3 files changed, 33 insertions(+)

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
index c6ae00e327e5e..84dddf3aa5f8b 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -19,6 +19,7 @@ struct page;
 struct kmem_cache;
 struct task_struct;
 struct scatterlist;
+struct urb;
 
 #ifdef CONFIG_KMSAN
 
@@ -227,6 +228,16 @@ void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
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
@@ -319,6 +330,10 @@ static inline void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 {
 }
 
+static inline void kmsan_handle_urb(const struct urb *urb, bool is_out)
+{
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 41b6b41e6183a..58334fa32ff86 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -17,6 +17,7 @@
 #include <linux/scatterlist.h>
 #include <linux/slab.h>
 #include <linux/uaccess.h>
+#include <linux/usb.h>
 
 #include "../internal.h"
 #include "../slab.h"
@@ -244,6 +245,21 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-25-glider%40google.com.
