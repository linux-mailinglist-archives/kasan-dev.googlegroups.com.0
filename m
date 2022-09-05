Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWOV26MAMGQETXI35ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 13CE45AD264
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:02 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id qa35-20020a17090786a300b0073d4026a97dsf2256571ejc.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380761; cv=pass;
        d=google.com; s=arc-20160816;
        b=b75eRZxNPTwbRyrhL4CwZmDMWEDOWmYx/mP6GvwIr4ufqIL+BjrZrKljzhS2YpDbMY
         vWtY6KaCtlMu4yudrayZJrX5zzBWB6JWkvkCaLqbxvfiEoVf7i7a/9hCcOlTJrdr4JrC
         CeFLjyQDGvVhyZmXJxd7ISi2EA59xYIpGoa0/WmApZTcl6HzZ0ZmdUqPlazwqroC9Ass
         lC93XsizRuCjLAgJ46eLQcEMQ5ked0hW0r+NuKM3vHMyscTizawaqJCMcvm4jefRHCIq
         qpVxBL+eFy+lZMQjaoi0kjTg6eDzcyKyeg9wT6t1ZWA8hCMT2Bz5OK7DJhQhMspsJByp
         CErQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=T52iKbnqK3pdK5aAyas7cgRkwFWq3GHvZj8YK403V0s=;
        b=dPMiTVwHctY1I5QQiJG0nlxLmaYRcaZQ20zBRAzT8eFwdeumg0D03F6QP7m34eD/nG
         zQ/PEQt2vYHvgNMO27i7Ak/g1Gn93nsM0TFlg1kjtik++dOtPmHbRFNHu3ti/bQGeLtS
         0XeVt8pn81TpLfptEOKeKbEqHLDjLIuSKYbFd19uyfFLPWVmCo/xTNN71hY0F2ShLqt4
         84xWU0yLbNRPLJgiSze6G7yL6MXiNTdfYlOQY2EiXhKjwQSQRk2gYoygHZdIqulI1uER
         lgNz9DnzdUcUpWlQl1M0BlkI5WDUAjPj2Pph3qhRLmjSwOtp8lxN7p8gLXIh7d6gWcTa
         BL5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tTKCC8E0;
       spf=pass (google.com: domain of 32oovywykcsuhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=32OoVYwYKCSUHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=T52iKbnqK3pdK5aAyas7cgRkwFWq3GHvZj8YK403V0s=;
        b=MTg6K5Y6q8CD9dHUdxCH6kx6QeRuSRUCUrgHN4iA9JyuRyeDVYrNjslDmbxpMMWAZz
         ke93HjL/MzUlNS6CFsnKH0mSbybWuwlI1gOHxmO91vU5WwElzuMyEoUPZl2EmDRL9e9C
         /21rnpE04Z8afSGjhDNiLnhl/cpTY5S/sojkHBcEQPfk3PK6OviLDiu/SqQ9iLU0rjom
         pcc0rHv4UZhE7fqXBFI+eYUxjYK+uu9pyGXdFkCI/PY5AMgyfsBtEMxYJcZ107KHFtRa
         0Ns3Zu1llCAGy5OrgrKVHvakWHkM8NKDNLh4tn5n5IQi3zUlQ+hDA5op+xqDx+1HEKpu
         Gg9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=T52iKbnqK3pdK5aAyas7cgRkwFWq3GHvZj8YK403V0s=;
        b=tTlsPDPIRXSTt9QhwRCvaFYEDUP5BA1KBWx/VnuaOrI45+JyEvYp8KZ/CHWON+r/Qn
         ++Uj/uRzippj3q7XHPJrklxSm4bOxbf81V5hj8r1Lbij+aLztRGlz5L1iIE8EpM5hAjH
         NbFCa4d41s2bKuptd95hYWePGLal6bexYj+2Kgi/XxcLl4tE2q8npK7G+G14Fn7BNTrF
         MMEJBatlaAGdcwfTOzqJy9j+lxCZvNqaswHBgzImraOaaouEcHYspPorfTbMmboamJuC
         yE2xNJ8HuVBj7palBHuiA6nZLUgE3fnKIlCBaz4z655qmCJOQjDe8t/lV+skA3KQ8HzO
         KVyA==
X-Gm-Message-State: ACgBeo3+MJez5jEVOgvwvCxrEPTmRfKg32rGc5kfHWuz19MA4KPq68k4
	kjDHIJbjhz/TSeOgQPrgrpE=
X-Google-Smtp-Source: AA6agR6VmyLDB9KbNayAEzaEmwcRJaQKgu6fZyIMkKnIiboALIIzAQqZwUhYnaZlVXLIe70NXxtG1g==
X-Received: by 2002:a17:907:94c7:b0:730:d5bc:14c with SMTP id dn7-20020a17090794c700b00730d5bc014cmr36724391ejc.68.1662380761837;
        Mon, 05 Sep 2022 05:26:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3f87:b0:726:2c39:8546 with SMTP id
 b7-20020a1709063f8700b007262c398546ls3420647ejj.8.-pod-prod-gmail; Mon, 05
 Sep 2022 05:26:00 -0700 (PDT)
X-Received: by 2002:a17:907:7632:b0:73d:c346:de57 with SMTP id jy18-20020a170907763200b0073dc346de57mr36094367ejc.647.1662380760823;
        Mon, 05 Sep 2022 05:26:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380760; cv=none;
        d=google.com; s=arc-20160816;
        b=BOzuLlzomkAW6vqIoXxVXK/RFirrhhD0PZaS2vHOOQ4Q7RtQ2QrILFSjNlnNRdIHvn
         GE8JxsHRWch4V4knD7Bn4xCIK8vAZsEUapDbeaJy3rpwEymJMyVdpaddBZ+nYTpiv6eg
         gauPyYugJrgQyc8zpzuDHGSOkOyRGmh4iPyW2UYBlq0Aanjf65LdnXCDPZMCnxJu/HgK
         BS6BYHhSEJ0A5KhNZeDI1r/Ca/TOWmBwvGHvaKF3Sur3mdmmofDojO77Us2S2e4E6o3p
         mNusLowlKJ+1PSO7za1ljZdzAO9JLE7G6P4xm0F81YJ9qkoOqxeWJphmWXgMlg92Ciw7
         55gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=lOWe2UvDp+lzLw75WkGUXRoANIiWBb139LkOr44Ytus=;
        b=oV4lIo2xh+WigAJ37dHGsAXHXziNHdzqseKuNbaxp5ew231jv0FauvP7z+FvgDdyxH
         zRcyigvGv4n1JYo8qNw2Z6FxvQvvFC+Rl9zLTcleXAauQKr3nK4xdyhD9DEgx8DSXmVp
         qaN7K8PccEuINvHvLtZS9/Na4P3J4mp5++PjFW3NzeIFdnuywrmXs/s2YiF/SnDGnUpg
         nCU7fAqfZmAilJkQiYUvP50MrjlVOjHya51350gQCsnmaISegOg+XoLUzr2Ax6np1EHl
         6/7p0NLoGmgZBCSHFXEy2BEUrI40M1x1rWDiekW0iKYbWiSzUtKpkjlGdetrL3AR2qgw
         tA2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tTKCC8E0;
       spf=pass (google.com: domain of 32oovywykcsuhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=32OoVYwYKCSUHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id v14-20020aa7d64e000000b0044e9a9c3a73si70303edr.3.2022.09.05.05.26.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32oovywykcsuhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id t13-20020a056402524d00b0043db1fbefdeso5711520edd.2
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:00 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a05:6402:320d:b0:448:7cc8:7901 with SMTP id
 g13-20020a056402320d00b004487cc87901mr30728374eda.423.1662380760517; Mon, 05
 Sep 2022 05:26:00 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:31 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-24-glider@google.com>
Subject: [PATCH v6 23/44] virtio: kmsan: check/unpoison scatterlist in vring_map_one_sg()
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
 header.i=@google.com header.s=20210112 header.b=tTKCC8E0;       spf=pass
 (google.com: domain of 32oovywykcsuhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=32OoVYwYKCSUHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
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

v6:
 -- use <linux/kmsan.h> instead of <linux/kmsan-checks.h>

Link: https://linux-review.googlesource.com/id/I211533ecb86a66624e151551f83ddd749536b3af
---
 drivers/virtio/virtio_ring.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/drivers/virtio/virtio_ring.c b/drivers/virtio/virtio_ring.c
index 4620e9d79dde8..8974c34b40fda 100644
--- a/drivers/virtio/virtio_ring.c
+++ b/drivers/virtio/virtio_ring.c
@@ -11,6 +11,7 @@
 #include <linux/module.h>
 #include <linux/hrtimer.h>
 #include <linux/dma-mapping.h>
+#include <linux/kmsan.h>
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-24-glider%40google.com.
