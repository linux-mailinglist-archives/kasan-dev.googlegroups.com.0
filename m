Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJWDUCJQMGQEQEHEGNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 515065103FB
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:27 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id eg38-20020a05640228a600b00425d61d0302sf4458556edb.17
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991527; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qo3M1Wrs9K0wXa3UBMdaHIux9Yylta+EjGkmkDH5asaTN9rIdlF4rbYZeQJ/Anaz+P
         7DQRf2+wW/p+ATpPAwuQBrnVqH5r73bEwOUgGLN1wEeRyfHAC9hDzGPtztxT0oiEkDGk
         kIepyu/h0+joM+70bhO2edTES7HoJyXyeq8S81uQZiEwNgLV3mO+oIW95B1OYtnFkFhS
         WJFCWNvR6Qge4OaiGVAXXJSnlKXwjodNI6T7ALKeBoWmhhoWFhAaZFpz2vdIxHlUbsM4
         2tdwPZiA6bhQJYJv9QnjawdOH2v8fM6ihbHeN+W4/3xSQGGJ4rBYaODDLSltxPLpS5Rf
         cNsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=fEv76Ci5m8W9GnXtbHyrZZR8w+jB/DEHQIZoQTVU5Do=;
        b=SkZA3IHia8HpnrWo08Lnq7uN5vWUyjKAhzxVBt1MpsGjG2V+gycW0ywDn1ZcwCi5qc
         i0UnADlUeW/SfvNYVsnSJORs1XrvZaTxPtlyrnVEW39qfooZii4R4m05zYLELrkVxIls
         3udnk3HNo4gl0tLgrxy63dmqn8XpEX2Ara/eTyWypb8eeK1KliHgbqvg3NBxgWvCdp0m
         kZjwAoTzkfc8N12/6+tkt9JnI8bNeIbXpF7FG+oBXg5T/KT+mZ9hEI0suogwvirhgQDN
         s8sus4Iu30yxBec15tYQMcUBhEZmeHtYGSm4SxZ8UeQ6dqHB1s5wGVWgseh1v9Ft2CFD
         QaWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PIyBhpOC;
       spf=pass (google.com: domain of 3psfoygykcaiinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3pSFoYgYKCaIINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fEv76Ci5m8W9GnXtbHyrZZR8w+jB/DEHQIZoQTVU5Do=;
        b=lPyLiatigl7SDb1Q36F/IpIvKmx0JTDVl2kDsJFUO1mF5bGwpN6UFAdrH2Gf+FaFWY
         LuAj0jQGsm4AWb/C63iy9Hg5Qy//JqY7nSHwxogglcoKsHSGex5DwvkTS0yFb87jwgO/
         zeZep+Iglo7HoVe3ESpg/evBv0g3J+XnWwzxxrSEUSyny0qLfzYGGAnPl2A52trS9eV6
         w7rxVJhH47a/n4KbfA8VbUuj5i1w0cdLVItxF+nYpYmHNbHdD9eBSEF7V580XifSmxJH
         MRIzTxHi7erFbWdEfJ6+Se6CETxSlc48dbCVgAY576Aw5bit8ki+iZWs0BR7IakX2QGv
         3pig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fEv76Ci5m8W9GnXtbHyrZZR8w+jB/DEHQIZoQTVU5Do=;
        b=fK2X6pka7Qx3NkSiKFjhKuKUZ+TlsD03LF/9K9I5R8KKQN/FDh+njGZGdDeBjr90XQ
         LcLOAdpxLksFq2w138Yio/QJ7rCLSL68nVTyLtEmC5s4jF/RQv0DPi/RQZiYCsc8xtQx
         GuHRTowHMkkHNHpaIXUfOFsYrUTswSJgfRivtpD916vyEOwsaprb2uFtgoXe6wtraIVH
         moNRX7FwMl5StpgHkzNObFKYUw65cqd/cba+GkUV8FxYRuqkAza6RhpV6xzeuElTPOi7
         zrax11raYEHgS6HwZuxXFXRu6xxDxj0+E9SM90gWBRrFCUkW77iPilW5c9yd3ucZDMn5
         ZaCg==
X-Gm-Message-State: AOAM5303cym52bVc4FLwdap2JGSVEOHyB1foF5JYptskgEUHC0kJYyuy
	9IHjoqdmt3HFBdI/oCYaSMk=
X-Google-Smtp-Source: ABdhPJxtUyzGsmDC9FPd3b5Gibjaw0U3hdGsyzYefYm9jGcXDzRtnZvSPVGRwHR9NwpPHA7IQ1iRGA==
X-Received: by 2002:a17:906:2bd7:b0:6ce:698b:7531 with SMTP id n23-20020a1709062bd700b006ce698b7531mr21486966ejg.146.1650991527084;
        Tue, 26 Apr 2022 09:45:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:478d:b0:6e8:95ff:b734 with SMTP id
 cw13-20020a170906478d00b006e895ffb734ls5358688ejc.5.gmail; Tue, 26 Apr 2022
 09:45:26 -0700 (PDT)
X-Received: by 2002:a17:907:60d3:b0:6e7:fcd6:7fb4 with SMTP id hv19-20020a17090760d300b006e7fcd67fb4mr22898234ejc.302.1650991526124;
        Tue, 26 Apr 2022 09:45:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991526; cv=none;
        d=google.com; s=arc-20160816;
        b=U4bCjgCWj6lwpXrpfUzQed/Vv8b6jYgDwTOffvTMnMIrImq3vbNsm5w4l6pPMctOu2
         3s+rWKkA/XTqrwVnErnAGMbRwppAAo/F+8kXZ56q5ONfsIAbJAs6HIck2O1pb+SpFdT1
         FfGWaEehdPHMNUb+xpFclpMt99HxAHJ1g+VsyGyheVUW01CaP9RcgUYGoIcZVO1dCAs3
         C6NFW6hG+dytKJpbpaelHGXmcHIGiWBAnHpK0UCJRgOvS96/g6TuZiOoUaG7EVuTCEY6
         Y6g2hlo8H/ogSXMbr4dqWLlTBpydgs4utSeWCZG/mVIbnP7z4yKXHXMysd0oCfXxSpmq
         U6Sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=n12oscJoQy25ZeJEgKUppRaHioaFclURl8PsqxmYCmo=;
        b=jx5R5GIHyykKRjIYwJjs2yTQvRji6EiAL3PFF+IDTTzSwJsn6lXCBz4WycuTcdfZqy
         nMJkB2RilY6xIQIi5wB+dt+FFtxJgSpwwv+9KiWqC8nluRMogIXvOkZyocErkB0IO+Nn
         vj5uFKMUB3rJqDz+/ZjTiyo7aaoiTWLIMTDT1ulj2lyGMAAgTaSLEwnk/lEl4vKYCrS4
         vFjhU3L8509c34kPwAM3mqBrZIxu49hwo4/m+Y4hEp9iUMep+qAYvsIqRiR0vG9zIROs
         XfB1s+jc5hIyIXtLaj1hV5FewCEwi5mHhxQAOz5h4L0XcVFI+7oDL79MYTvxQm/0siAu
         Az0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PIyBhpOC;
       spf=pass (google.com: domain of 3psfoygykcaiinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3pSFoYgYKCaIINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id j1-20020a50d001000000b0041b5ea4060asi880450edf.5.2022.04.26.09.45.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3psfoygykcaiinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id dn26-20020a05640222fa00b00425e4b8efa9so3781753edb.1
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:26 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:5210:b0:423:de77:2a4d with SMTP id
 s16-20020a056402521000b00423de772a4dmr25186177edd.295.1650991525861; Tue, 26
 Apr 2022 09:45:25 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:54 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-26-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 25/46] kmsan: virtio: check/unpoison scatterlist in vring_map_one_sg()
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
 header.i=@google.com header.s=20210112 header.b=PIyBhpOC;       spf=pass
 (google.com: domain of 3psfoygykcaiinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3pSFoYgYKCaIINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
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
Link: https://linux-review.googlesource.com/id/I211533ecb86a66624e151551f83ddd749536b3af
---
 drivers/virtio/virtio_ring.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/drivers/virtio/virtio_ring.c b/drivers/virtio/virtio_ring.c
index cfb028ca238eb..faecd9e3d6560 100644
--- a/drivers/virtio/virtio_ring.c
+++ b/drivers/virtio/virtio_ring.c
@@ -11,6 +11,7 @@
 #include <linux/module.h>
 #include <linux/hrtimer.h>
 #include <linux/dma-mapping.h>
+#include <linux/kmsan-checks.h>
 #include <linux/spinlock.h>
 #include <xen/xen.h>
 
@@ -331,8 +332,15 @@ static dma_addr_t vring_map_one_sg(const struct vring_virtqueue *vq,
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-26-glider%40google.com.
