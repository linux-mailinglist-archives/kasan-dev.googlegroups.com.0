Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQ76RSMQMGQENQ5PLYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 64FD15B9E19
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:40 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id f14-20020a1c6a0e000000b003b46dafde71sf5705603wmc.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254340; cv=pass;
        d=google.com; s=arc-20160816;
        b=ciCax8AYkxzLrYSNUXAAKGEonx72ly5T2/DdEFw8vVMVbmERxDagsfBib/fOvM7fr7
         RHtyQKYBDuDhbk3De7CPJ6OM7kolPiTBMb2Ib540l8SVAfreDTpv8pqJRuU2gJRiDtIx
         opE2DEObs0Zd01KbJDGjzm7Rm99RfawmJtXCD42f3Y2b2uIuZyaShzQG/3nYQ1ZX9Uqb
         dxu5cI3r/DVDb9F6BhBOoqqemBSBi/kqkM+VXqduam4xZPaf25T0EPfpzaNWy1wEVe52
         EqQ2lH9Tr5/hcm2l9TRaCKsWlZJP83VQSWt0HPfxaLE0Va6mzWg+/XyCO9sQ3fw6/4Kb
         nMqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=TMzSn/zT2kwfTtCobvq8eQ9msgZzIOpuIz+OcerURPA=;
        b=tzJM/OzQbboLrXReaLC5GTxI4ve2pJeM8sQ3/1eW7YIY4YjBghwLW9WZ87zUNzJ3oo
         3aaba82pc4hUk/VKaDbQs6JBIEo1mYaIhxqLAiLRVEH/4Zq3glNCjf10n0BXLObPyh4r
         GbNpmRs/iIiFLgTIeifnSS/8W4qYv5FGF86XwgUnehCfx9yeQHwb4aHmd2xT6rBDm+Ak
         8c0VSp4HLGZSHAhvkxXiH/jxQ+7jVIuc0h9i4FMCjDy0VaRBib+HYJNTOOP1tnjep0cI
         l27dhsPIhlsiyZkZUqPlkJGPe7BSJ4RkTqpyBir0hndpPEo4dbxQUrKPzAQgZB7gAa7T
         LTdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=r8zwtK7n;
       spf=pass (google.com: domain of 3qj8jywykcw0rwtopcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Qj8jYwYKCW0RWTOPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=TMzSn/zT2kwfTtCobvq8eQ9msgZzIOpuIz+OcerURPA=;
        b=eWKBHxQxCb1nTM2SyMusZN615lQnAUye97ZJSZigV1Q+RMQEStWeDjuIFgIX3L+Nq0
         6afNq0YQbelp6P0ATk23VTXgKMsizMRB1fsDPy23eh7A3EHJkly8tsAa8bLdnrkuO61B
         bm1vfyIffIGN3NX4obP1oxNZ290iyQEWD41VH8S1ieK6a7l1rV3bp+Ijnztg5dbTWYlK
         n71xuTX+p/ozGx6EIRPg7qkUSq/UfsfP2e5Ld3V1TbxkIsfy/SS5/yJ6BgNJSsXkT3QK
         DPdjBW6OkBFM+pq6guIP53zoQTL6go2NL74/n7P3MyfyTQBygVr3X5xQ0e9rRmwE4zTg
         3riQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=TMzSn/zT2kwfTtCobvq8eQ9msgZzIOpuIz+OcerURPA=;
        b=ed5WJDxl5JmuO0Sefgexq2yn5LN0MGxvg3/hdUEG17lS238wCILTH7iF0LMXIhJust
         Z6NIZR6Nso2l3qe9DG6NT8/JcDRbuT1vSd0tqwuw+4a1fFTDCunu0E9+9bzljqTN7sI9
         w5vPsmmPiPlk/aBZweo5JGXEXfMUoZMverSNXreiBp5CKd1NiTX1Qz1WCCCKHKh0qghN
         QpC0Us2LhlJdO2w1zf0LBpbWN873zHfT3a3r+o3oj/4mx4r1IglzSut9s4XTT6xLfAnQ
         MlTlXVKncG9vj28lAl+FjOO+FrfPV6mYvnQKq/OoSzNR6tAdZ2/V09ZZrm8LGHBlkvBO
         R2Rg==
X-Gm-Message-State: ACrzQf3qXKlaQ5IcRjoSSNTvchFGAi+W9inrGKkarWQLW5wL1tcZBGps
	lKZenkhZPRhQeLkgehISzDw=
X-Google-Smtp-Source: AMsMyM5Yl7G8ANwCxRA8c7wwMjHCkCUEeMnNSDGTiMP9lNmlzxh8HRyVUbax1/6QeaLieIMGhGZ2gw==
X-Received: by 2002:a5d:6e88:0:b0:225:3d19:addf with SMTP id k8-20020a5d6e88000000b002253d19addfmr67746wrz.600.1663254340079;
        Thu, 15 Sep 2022 08:05:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:256:b0:228:a25b:134a with SMTP id
 m22-20020a056000025600b00228a25b134als3202049wrz.0.-pod-prod-gmail; Thu, 15
 Sep 2022 08:05:39 -0700 (PDT)
X-Received: by 2002:a5d:5010:0:b0:22a:4247:3be4 with SMTP id e16-20020a5d5010000000b0022a42473be4mr82727wrt.270.1663254339053;
        Thu, 15 Sep 2022 08:05:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254339; cv=none;
        d=google.com; s=arc-20160816;
        b=NfeZ1LS3xC/7NNZ/+POjRzTHZSrfwtTdV2K7Uh/6fCoeK3nGyPgeGUQ7IMZe++xSgd
         fGQXz+fmZ4E1ikVpVHTKHM15HBlY+AxGJsri8fSudn2VYJ1I7NgmX7WByGv0fFjJnzmJ
         FPSpfvOY2YcHrvoKzWBhKge0nz4xfhZNRI1HJi/gwxWDH8ryEQOdR0oEGG7STVWoqkcp
         8j6d4kK5JIWS3INVWq538uKjxCGDRQU/d50J9jwylTp/8wsW1gQDMTtRiHRmqsnHH6hz
         zVUyw/Ubs7xTiE/fjRphJOdQsNmWQeEfQAGEw9Bvc4QLzJeo2guumSluV+r46wWTTL8u
         fr3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=lOWe2UvDp+lzLw75WkGUXRoANIiWBb139LkOr44Ytus=;
        b=ICKvMq2zjthAfZ84fwCjUxzWv6rokrB42lJL/PEq0SIF6IniZ0y9rh9H0lnNtCnSv2
         JUzy6k6qp/VNodgQKJyrXfpf8lCg5wZ8z50V6Avdot16OpT45BxC8vWxxA+Ylav37ghY
         bMiwNSCVYhnDqb07Hud1egdunU+ybZcuFNQTStx5qgUc34k6SjOGUCTYSPm1ekt6Aox9
         MkyRhzFE0mEpIc1j3vh2PS/QU5ujytZLkDHtEvqT+4owm2weFF90lnE+yn/w2078CEgu
         E5bp5lZMPB4pEUsnox5qb96z/hIns69lnT3bsEYTvz/IZ+3s59NS2gWgBDlKMBGKQLXC
         AkQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=r8zwtK7n;
       spf=pass (google.com: domain of 3qj8jywykcw0rwtopcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Qj8jYwYKCW0RWTOPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si72301wma.1.2022.09.15.08.05.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qj8jywykcw0rwtopcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id q32-20020a05640224a000b004462f105fa9so13076414eda.4
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:39 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:906:58c8:b0:6fe:91d5:18d2 with SMTP id
 e8-20020a17090658c800b006fe91d518d2mr326676ejs.190.1663254338524; Thu, 15 Sep
 2022 08:05:38 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:56 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-23-glider@google.com>
Subject: [PATCH v7 22/43] virtio: kmsan: check/unpoison scatterlist in vring_map_one_sg()
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
 header.i=@google.com header.s=20210112 header.b=r8zwtK7n;       spf=pass
 (google.com: domain of 3qj8jywykcw0rwtopcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Qj8jYwYKCW0RWTOPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-23-glider%40google.com.
