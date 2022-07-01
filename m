Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFEH7SKQMGQEADRZEPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D901563524
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:21 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id oz40-20020a1709077da800b00722ef1e93bdsf835631ejc.17
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685461; cv=pass;
        d=google.com; s=arc-20160816;
        b=sptQ15nhTllCuQDANyUdA7H96pLia2rZ6wZWUFrBjx4cmg0jMFMG6UFpgnBzRyH51z
         mIrzbeWkaSPFxEpCFx6ym0L4BfmsR/KQ4GmeGi36/784N2F97sKucQsQl0vnE6MuMEMJ
         kVh1BcN6HCetuDL/fnC5Dc0vshutSaP1ZQQewMlLBE3CAwQJvSPXt6fzONY1LWV2QQmE
         ipwyfKfhdenSadl0rMwhLAYe98XEtENCR7PDWDlTg3kh3g+LXH7WvuQYqe2zKQOjQ+wV
         QWWqcdswppxskY3z2XSMEvttR/NP8hbblTOwM+y/93ZrV5dOEjxYL9dNdiU8flYehtzg
         R0jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=yhh8vz7uDBDH5F50skXUIdKKlgKWjhsqREK4Cf84Yto=;
        b=GA1olttI9W+iZSA/4EpqFUIjN9B9DsqEpjvOfL1dq8LvGWZ3Y0kWF+af77ZDdtfhtl
         QHXvKV9OXJrH3qYzdq28TMBiBJat1Xw4kk+Ew7zZi3tcrF4sAbLjyQpR5fy6jt6wfclg
         2RVeTBqDeBZkEgfFJGV/Wp2HtsAQa9stassCYf4JtntF9KhpyrgNCP3MrYdc7a/xjpie
         /3BUEfUFkGOXFVFsUpVUR20Ub8D0HyglL9aIScmzrt7AZ7g8xMoqCxPeIs697LzFcCY2
         a7kuabpuejvWiU9yD0TO98JXwsrPsH/h6nfTRI7YpZ9d2g2g+DN+DIQp9ri5FkRZzBo+
         7w/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Lp2eEEvz;
       spf=pass (google.com: domain of 3kwo_ygykcbiydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kwO_YgYKCbIYdaVWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yhh8vz7uDBDH5F50skXUIdKKlgKWjhsqREK4Cf84Yto=;
        b=KpBl/t106CFKTghVfDj6AFp00S0jRA4zEY9oy7auW+4jgZJ3Dea8Ac0EW/e0CcHk+k
         diuI9qz5I9Ko+aMZgk475IR5O16s+BKxkXxOw3r3HBZtQSe5OuQQsxMvPdiJdoQcWxeL
         0NuXFMvO83TWqFUrNVfL5GcXN/w8GN9aWV6y6ud0upIlm5UQ6nUWRE+1bsWezuCUQH8z
         WNfMDIRxj1p4kRdXZlZMDOqMzy6+plMmmrdbiju2staSfsJZuOSUdKmRAzXsK4YVHnDw
         Zq2LteTlYBcyo7lDQYX6Pp9+0Jvl/EUvTNs0lP9F3A4hYQ/Y8OCYn3lqo2Wz0ELXKnu8
         R6Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yhh8vz7uDBDH5F50skXUIdKKlgKWjhsqREK4Cf84Yto=;
        b=zEXqBZNn8Ldg8/Lscampzyop8875TFB/aGZjD9oWSMCOAgy7rUzCZqZcLhSHgQgkdW
         hv//6rRnqXGXA5pGtsAM7gxZbbhzmSwV+g5V2wOWwdlTY0OPfBFsnHJ0LpzgHJ3EPNuV
         aHoaWEci1HCBUBB5W5Y9/KaKaH5t3g+rBIQjY0MtHdqzHyMCwbIIKw49KtvKMF9NFQu7
         k1jYKPvqMu9S/lVoxyEvKjYp4TUDKnBBt4CZpRIrvFoQSpTKbPJo4icEP/HpxH5x1X7D
         tim0UPiQ+xSPWzRsHy6oHFW28/EVRRnPo2Setq0P2ChnB+5X0X7Qh8tSONKaNAXS7O20
         HVcg==
X-Gm-Message-State: AJIora+ZZLZ6XoyLPaeO+c6eiaERyR0xbmoxTfvPqRoaNkc3LvOVA3z+
	0X7HuPopAQT5MRUU48iFdwU=
X-Google-Smtp-Source: AGRyM1sq/ytN0gLitLjL33+wY8WabdB8l12Xzi3YxaV8xgxuyZIHyHIjT6MokTX/2/k/+b5KzNilGg==
X-Received: by 2002:a05:6402:3481:b0:435:b12d:a66d with SMTP id v1-20020a056402348100b00435b12da66dmr19481201edc.135.1656685461031;
        Fri, 01 Jul 2022 07:24:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4245:b0:435:dc4b:1bad with SMTP id
 g5-20020a056402424500b00435dc4b1badls369374edb.1.gmail; Fri, 01 Jul 2022
 07:24:20 -0700 (PDT)
X-Received: by 2002:a05:6402:240a:b0:437:d2b6:3dde with SMTP id t10-20020a056402240a00b00437d2b63ddemr19381066eda.62.1656685460080;
        Fri, 01 Jul 2022 07:24:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685460; cv=none;
        d=google.com; s=arc-20160816;
        b=sxDN9TIDgjWwEz1if4JHTUTmtSDQIEoKJKKyQUIskpUEfXvLSTCgtuZuWlhMEDVVWG
         d+aEpE+vfupr070+n9qf+s7TDI5zbwYJJWRlkDonPNqYObu0Hn8OMUoOTzvIBfxtoTMg
         JqnUnEKB2JSikm/naxodf7F80yaBex3B4ck9x5mQveyG4s4ekxG4NrOV/PTbYL8pibxX
         U8Bdcoym37i6azYMQNcJbGQwFOxl3/LG9GOK8xGGmWkPh/1/DAyvGR38XRGcv7Fc3Ore
         xpqpnFBJmPOkCs/EGjiprq/JNOCkJW0jr5L3hMwnSUtNM3AnGW277uEMxRmIGl8mUC0O
         npKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=+K29lQHYx/QboL6+Fy2jFmZJqrUMV6q0RSetNFINlHU=;
        b=wEcyrUS+RnuOrLdWmqPr/NM/9NnmrQWJk1fvSthDBwclInEUPWMyzJRJd3cJyYXHFU
         ybEYT3xocU2VL6lrv1pe3wos9A05VuRr+TL+DxoyiYRDnYu0ftSRteD2tQIN7szwarAZ
         8JtoWM+c7XO5b15jEsl95IFjAT+N8/MsFjaF3PRz2WA+rZm64+nQVsT8aBOZ+KTwVZHe
         lv41VPdMA4z7kpvUvPOGmrIMqusb4DklbA8OQHFoQPQRXa+9DSYs5++RVX/bUz3WLqrl
         fCKnGPpjg19JDajvbkC4fCxtEUSCjbUAi65kRR27mc/d9dH1h3qibnxUymXuHhpG/Igz
         hs7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Lp2eEEvz;
       spf=pass (google.com: domain of 3kwo_ygykcbiydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kwO_YgYKCbIYdaVWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id jx1-20020a170907760100b0072a6696083bsi239262ejc.2.2022.07.01.07.24.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kwo_ygykcbiydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id x21-20020a05640226d500b00435bd7f9367so1885682edd.8
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:20 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:15a:b0:431:71b9:86f3 with SMTP id
 s26-20020a056402015a00b0043171b986f3mr18869662edu.249.1656685459864; Fri, 01
 Jul 2022 07:24:19 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:48 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-24-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 23/45] virtio: kmsan: check/unpoison scatterlist in vring_map_one_sg()
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
 header.i=@google.com header.s=20210112 header.b=Lp2eEEvz;       spf=pass
 (google.com: domain of 3kwo_ygykcbiydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kwO_YgYKCbIYdaVWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--glider.bounces.google.com;
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
index 13a7348cedfff..2d42a4b38e628 100644
--- a/drivers/virtio/virtio_ring.c
+++ b/drivers/virtio/virtio_ring.c
@@ -11,6 +11,7 @@
 #include <linux/module.h>
 #include <linux/hrtimer.h>
 #include <linux/dma-mapping.h>
+#include <linux/kmsan-checks.h>
 #include <linux/spinlock.h>
 #include <xen/xen.h>
 
@@ -329,8 +330,15 @@ static dma_addr_t vring_map_one_sg(const struct vring_virtqueue *vq,
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-24-glider%40google.com.
