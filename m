Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHOEUOMAMGQE65NZL5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C2E65A2A72
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:19 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id l6-20020a544506000000b003455b01ce5dsf725002oil.8
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526557; cv=pass;
        d=google.com; s=arc-20160816;
        b=nAY1JkTb+sHqNFxch+KnjsIQHkPQrXNf3JYLhL8M1tg4r8Q/1ryNocPQ87IhnHWRxv
         Z5wiEPDWoJAPcvsuSwbB7Zu4GNUJozO4wNKG1ejuoaiEx2BxCrE6aF7CycpBoq5vjAb0
         isrl4+PX6lLqybo9TZKn66pwm9x5tZgIBO3rcvRqIOUjIHOtW4mvrnN+kXreHLQ1665q
         h+8AbgyUCP300KrWuYqs50cY/Y6+vVh8pTPm71Y+uoeUc9iXvxcr3bOSXrIRV6usaEuq
         XT3GEJUc5YPhPmja2jekS7vsnC12EtzqVtzMK6GT1sln54cHYOLsPQtst8ypPWRMsqNl
         tLXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=0WBOErl2F+JqUWb6/GBXa947HshzhWqXpC+b1JT8QCU=;
        b=VBzPRIk+NDqzQnU7n+gbz0KVXgH7DFETtd/F8u8WDQ/K2cVYRVkllE8M0kYiCTilQH
         E4w8ojFE8HqY9p2FKOYCSw2k5wrh0V6SvAd6PvMQHD9N1sYBvwhNX53/LG4vokiUZDQI
         ySyPsWRnIZm35QSpAd//Jh3BEvXiiiJ9BnzlUa0ogRBas9SEsqlK+7G9+onybK8Z4P4h
         ishTazFb8s/LZfkCkaTXDWu9JlZjoYJ6ry+wRvne0ByDb/9RsbPnQmG0PEfglPd+V8kT
         22JbU6ingMNk1iED+cRHQWGLWkDr8ZofCBUHCr1td1oYG4cA+nne0PxoLSdi6o9XqCjJ
         Optw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RBRSbeDr;
       spf=pass (google.com: domain of 3hoiiywykcsmfkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3HOIIYwYKCSMFKHCDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=0WBOErl2F+JqUWb6/GBXa947HshzhWqXpC+b1JT8QCU=;
        b=mgCjEtRu7GFNwNUrzh4/YjhE+8ZeAQpmuhY2f439VCvPEWViUPybcKL/yZADnwjro/
         B99dBaiF2qWtGaVVgHnASg3velEILmVPJvWJ8D6tQMVuI07g6WA7UOyJPxgfLCpECeqG
         0V3BVwezXWQc5gqYQWvcLx/cX+8x787a2wFtgtCeG86Mi8S9XG0x3e1czeYF5vKYX1XM
         dEGQANA7VJzmTuZPiPbj8hqrqZdpIN1shuunXhqaJoA/wQh0K/iOoBcKb/4Pkc68omXO
         grTTNti/Zn909xmkhRn3lwFQb8SylYBbpBlMEb4Q35ktcJX9med+46ASziItAsbs7Ed3
         dy4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=0WBOErl2F+JqUWb6/GBXa947HshzhWqXpC+b1JT8QCU=;
        b=uT3Xx0t3jUug1Lj7p6l0SWjwWR1khi00Jb2TiX5TvIjFqnVuIl//scfFNcf9Z6mqH/
         vkI+8lQnwru3Lii6oQTV/cNmwPpxZ0yydOCXBvk6oMA3f5NTDfqnmuoBFcSzik4E08Yf
         GUT+eBi+kSb1qk0RNtZgkcdtKdG2ZBVXrD9XBcG5+b6/x8ekWTzdwX0CsAgcn5iPDUfk
         KjKOpZJTs/pS0dwWwphH0PgWpWVluddWux2YFfJWrWnREuoR6fdGTO5W8S/fz+TrFgBv
         gXCYNngW5r2d2f7y+cHzEfAMGZnMaZ+n5ktMO7URXWZkOtW7Qre2EON1VpC4aV9ZRBfD
         s4wQ==
X-Gm-Message-State: ACgBeo3aYdlCwewrsUi5NgtzWT40j8LfJCoeYeLrzmWnksEJvivP2s69
	oJJ2H3PDT7e7DNX1mWoTxQk=
X-Google-Smtp-Source: AA6agR5oZ99Q+YbLvDocQjy15Ln/dfIbvQJ1P0KzE8ssJ15BA443Bw6GSXnFLLS4rrUR037WhGKCaQ==
X-Received: by 2002:a05:6808:188d:b0:343:4fe6:3b66 with SMTP id bi13-20020a056808188d00b003434fe63b66mr1734055oib.85.1661526557748;
        Fri, 26 Aug 2022 08:09:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:544:0:b0:345:9a88:c799 with SMTP id 65-20020aca0544000000b003459a88c799ls765402oif.5.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:09:17 -0700 (PDT)
X-Received: by 2002:a54:4892:0:b0:344:e0df:df5 with SMTP id r18-20020a544892000000b00344e0df0df5mr1792888oic.234.1661526557374;
        Fri, 26 Aug 2022 08:09:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526557; cv=none;
        d=google.com; s=arc-20160816;
        b=w5PxHM05LX6SHVfQ5y35gnU7x4iZ96DWhyxUUY8Wu/i+GocjkdV/n0dfcVV0Y7gkmn
         bytoSkGAwicii8Yhkmb8uNZKeqZ1JnB2pXJuatPJqm9SVtQC+QPvUI0CPvu2kI0cebpR
         XOqK5hBd5pb+CPH//Y1nFlE0HeS1NT04kwumuccpQ3Vyxm1cjTwgQ+NiZ/nyil6Uer2C
         ItCbfH9ESkpU4EmBWgJieobOZuAc4irdC5E6YygkzRczPrRcXfOHm4hZrAFf6wOAz+IQ
         q8c2JnhE4s0FAcQGWzwfUtnMlQyx2tiRrxceCJCevD4UepoFEMHKi4rrj9vVnz42CrSW
         sBIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=XOIO6yMrJJaBLCVdiKJxecGrRstBRdkXKAU8JD1YObM=;
        b=eDNcO3GqQJVnz8p9+2rHQTFoknBfDvswAn+BbQkXUbVX12QhQU9OMXtbH2E6XI5wHq
         IdefpBcsZWBN7Wz2D+kDt1KFHR5HetGsh0Vnq5aLI2O6ByLId2Q9EYBGf9SBhgke0AUE
         kFwYUCrAqzWGb135O6GDy0ifo+J3m1GVoA5fjQtYrpiH4TQhTL81JAD/QqUlpicsjaEI
         Z7ZxmL/2Ov7VOhYfaPNoCtq3c8SVapUF2FHiQTZmPZDOfdbpzWj6dDOveZE5L2NMzV8d
         VB3EKjBv8RnAGlJTF8y3yL9BRqrxwLoZob9nopbbc7jAn9AfX0vPIagA5YF5lTCO3j7W
         /9Tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RBRSbeDr;
       spf=pass (google.com: domain of 3hoiiywykcsmfkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3HOIIYwYKCSMFKHCDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id l21-20020a056830055500b006371b439b4esi107373otb.5.2022.08.26.08.09.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hoiiywykcsmfkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-33dc390f26cso29442417b3.9
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:17 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a0d:e6cc:0:b0:338:c82b:9520 with SMTP id
 p195-20020a0de6cc000000b00338c82b9520mr151356ywe.66.1661526556996; Fri, 26
 Aug 2022 08:09:16 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:46 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-24-glider@google.com>
Subject: [PATCH v5 23/44] virtio: kmsan: check/unpoison scatterlist in vring_map_one_sg()
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
 header.i=@google.com header.s=20210112 header.b=RBRSbeDr;       spf=pass
 (google.com: domain of 3hoiiywykcsmfkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3HOIIYwYKCSMFKHCDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--glider.bounces.google.com;
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

If vring doesn't use the DMA API, KMSAN is unable to tell whether the
memory is initialized by hardware. Explicitly call kmsan_handle_dma()
from vring_map_one_sg() in this case to prevent false positives.

Signed-off-by: Alexander Potapenko <glider@google.com>
Acked-by: Michael S. Tsirkin <mst@redhat.com>

---
v4:
 -- swap virtio: and kmsan: in the subject

Link: https://linux-review.googlesource.com/id/I211533ecb86a66624e151551f83ddd749536b3af
---
 drivers/virtio/virtio_ring.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/drivers/virtio/virtio_ring.c b/drivers/virtio/virtio_ring.c
index 4620e9d79dde8..a9f06ec5b3c27 100644
--- a/drivers/virtio/virtio_ring.c
+++ b/drivers/virtio/virtio_ring.c
@@ -11,6 +11,7 @@
 #include <linux/module.h>
 #include <linux/hrtimer.h>
 #include <linux/dma-mapping.h>
+#include <linux/kmsan-checks.h>
 #include <linux/spinlock.h>
 #include <xen/xen.h>
 
@@ -352,8 +353,15 @@ static dma_addr_t vring_map_one_sg(const struct vring_virtqueue *vq,
 				   struct scatterlist *sg,
 				   enum dma_data_direction direction)
 {
-	if (!vq->use_dma_api)
+	if (!vq->use_dma_api) {
+		/*
+		 * If DMA is not used, KMSAN doesn't know that the scatterlist
+		 * is initialized by the hardware. Explicitly check/unpoison it
+		 * depending on the direction.
+		 */
+		kmsan_handle_dma(sg_page(sg), sg->offset, sg->length, direction);
 		return (dma_addr_t)sg_phys(sg);
+	}
 
 	/*
 	 * We can't use dma_map_sg, because we don't use scatterlists in
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-24-glider%40google.com.
