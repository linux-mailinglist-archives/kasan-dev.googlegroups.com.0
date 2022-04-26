Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDGDUCJQMGQEBC5THGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CC1D5103F0
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:01 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id hr35-20020a1709073fa300b006f3647cd980sf5653420ejc.5
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991501; cv=pass;
        d=google.com; s=arc-20160816;
        b=TKZWG/rGYp+/nlsrscAuZQtHA8YrsBl2WRQKnJ5j2E2XuFunVOsuDtlAbi9MRrFO8H
         tzVX5/D62W7cCD7l9obLVADGrUZ6LhezNma0mUYKHRoIYD6hAngDQJrQTgeLfjvrT2RC
         4jQB6XGFu/nj5rKhJPOfqXxwH+kxq4Rfqw+8dbk83q9AbPNPneTL+tVX8BWjPylgJloP
         uHURYl/N6AJMdGCJNmRhqxp5QOX9rTu/tq2NekNJZgSXPfPsANPEy78KwvzMIXwjVqnI
         yubu3t1hx4Esq5VPqXimecSQaUden5AKm3/rOm1+P4vr+VCudfAUgMd4CZoRKFLSQs65
         g4VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=kGc4LQUYn8IU+/gcWi4FpDrzaeZG57ClDcVDqoGd/5w=;
        b=0TubMuEkGSXfjloBlKOo1u14gM7GlJM4OY880EdGWOgVNrbvSLN/x0TEmqmCaxFmTe
         OlZIbL0xhBw13zeBPGIfJzd8vM/TyfgXwdPBbitJx5OfMUfEx4CB4GNTbXdpV0POJX60
         k31gbqjff4/ESlJd2WUIv3G6K0fJsan5Gxj+4ryTwDnkR3WjWZO9EG0qcsEPlKAE/T3t
         UXY/Gzq5GpWLjwUvDQ/iPmjoOkiyX6KX0j6zv6wte7kCFOgJtj5+qvz9uD/Qxg/7lAh7
         TgWZbpftxri4hxRlUPbId6tqHagnpPCSBBm6MlgqzmD9AeNCVH30LwQyADPcAZNgUVbe
         XIHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="AH6wl3/h";
       spf=pass (google.com: domain of 3iyfoygykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3iyFoYgYKCYgsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kGc4LQUYn8IU+/gcWi4FpDrzaeZG57ClDcVDqoGd/5w=;
        b=aoVB6xPhlDdXQd5PGiIbqDYovPrKW+2TBGlhZK99o8on+RQQTIzTuqmPnXytL4etZl
         VJolCKNs5S18uB/zynPtGFE2W7WKVHdJVpKuCum2OJzj2Dfu/16ZEJ65BjfDv6VlFsbG
         TPrC8K9yOa8TxTBFkkSKEBP8tEwl5fQLHQ7mSoPe86ycBti8sXx2O5fKY+qgIX3glMsD
         4XhHYEi77wZUNoGteB2A85FGznjZsnKZvSHV5nqjjyWChcCSgCTUB3PdsNT270qm9ZoC
         hGp59LcCgLIQPE37Bvpbsdy/7wxhlMFwcEOlbL0eCCtneFCpl9+ovjxhpbnqgvA2k9jQ
         CKCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kGc4LQUYn8IU+/gcWi4FpDrzaeZG57ClDcVDqoGd/5w=;
        b=zHEfrzVCH1jKmDxYhyzL1RleYtJD4WEpW3sQIT6Pb0C+AfLPpXHx+q9L++QSeOkpES
         ZN/AJeQ27MIez4F1X/jvVe5RlGEsdu2XdjHTWsIFlSQ6GU3/00W9OyL+UPRVIpfjZoCx
         nDIFrnYJ4BY5TP/HklB2yj+pQqGiu01MnbE0ZQRYzwNF/AQk4MkZapRHfKEWtIq6M6MS
         vhMIHEJizwkZ/dRmMx3SYHpx+BZl7A0KiwR64N4+9kl9jLhGYPJkL7komusFPIjVqPSo
         47uZhHoM8k6z0AgE2xGPnpFAbX5u15XVLaXPyCSf7+JiURYOPbxWIW7awPotPtxOFBfu
         yAQw==
X-Gm-Message-State: AOAM532NeloDqFYfhnuU1sy/Fsy68Cv7BRCh0i3QJWNG9Z+nElNsPTlz
	z6likhhgy51AQ1D327Y6Tjo=
X-Google-Smtp-Source: ABdhPJxvMysJVitM2ySH1uxuihHMWN4UeC4AOAkyu29sEwcfTXExLpsrIxTmkvdfQt19yFnFU2DJKw==
X-Received: by 2002:a17:906:b286:b0:6f3:b3e4:5f67 with SMTP id q6-20020a170906b28600b006f3b3e45f67mr3399472ejz.148.1650991501216;
        Tue, 26 Apr 2022 09:45:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c10c:b0:6f3:a080:9f50 with SMTP id
 do12-20020a170906c10c00b006f3a0809f50ls718981ejc.10.gmail; Tue, 26 Apr 2022
 09:45:00 -0700 (PDT)
X-Received: by 2002:a17:907:1c9b:b0:6f3:833c:2816 with SMTP id nb27-20020a1709071c9b00b006f3833c2816mr14549267ejc.601.1650991500100;
        Tue, 26 Apr 2022 09:45:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991500; cv=none;
        d=google.com; s=arc-20160816;
        b=Te5+qlJRbgX155ukTGREm6F30/6hR2FIlSy09is+w+cwmT35DyJgM6yko3SpVDgShS
         uYgGeVO2QNpTcTk149FA4KqK0DvuFbhvQYugBuyC9a+zDzetgiAOHftBTpPM9c1hNtwD
         a1WFyDYYuou8L7KcsZnJ9amVd+ssysbw80BYxEe3Do6L+gLaN4B6DqZKIxDH4ODD6pm+
         NRoCs+mabuQ2JmS503CNfxueYuowo6yTDmRPwNCfdLKH8INjhXaCRzsbtuY2tQAJ4S23
         1wWhpfDaFzGyLMCd1/xlAu3d/QT4tYiBLWGnZo10in6yocMP/IN6s4apOlZx4aqIy0bQ
         7GHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=eiEr+2P23HBOM4McbqvmLa2JAqZ5nkaX8a1H8WzeBdc=;
        b=JDGILdaNir1OY87p1sJu111GgmzFf53sfboMM/epuDL8ym9GQ8lnBSOiO+uTW9Vz0l
         MtbPOJKTjulAFsfkmo8ut6oMsJqmfTet+3vqo0WeDTZPuJKi4SdltIJyXbWimNqruSxZ
         8ScTbATJ4nIQy+mksx/bKtK/Ge0Tyz0K9aGPdiESjfr9FbjcyqW+qg0B1APIeE+U4JHH
         8t7Z9RTCyiDpsMjiCtSHWrKH40frKMaMbfTcP0qTycsYydS/UFHY8TivPRqP3fkJJXNP
         SgV8ub6Lz6p7odEFW8VE+CiglSXIB4hDiFynpYoGiSdFwNOey7o0EgQZLmxL1aefzS+/
         TyHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="AH6wl3/h";
       spf=pass (google.com: domain of 3iyfoygykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3iyFoYgYKCYgsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id j1-20020a50d001000000b0041b5ea4060asi880392edf.5.2022.04.26.09.45.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3iyfoygykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id mp18-20020a1709071b1200b006e7f314ecb3so9373417ejc.23
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:00 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:11cd:b0:425:ee49:58cb with SMTP id
 j13-20020a05640211cd00b00425ee4958cbmr10117861edw.157.1650991499654; Tue, 26
 Apr 2022 09:44:59 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:44 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-16-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 15/46] MAINTAINERS: add entry for KMSAN
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
 header.i=@google.com header.s=20210112 header.b="AH6wl3/h";       spf=pass
 (google.com: domain of 3iyfoygykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3iyFoYgYKCYgsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
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

Add entry for KMSAN maintainers/reviewers.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/Ic5836c2bceb6b63f71a60d3327d18af3aa3dab77
---
 MAINTAINERS | 12 ++++++++++++
 1 file changed, 12 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 5e8c2f6117661..dc73b124971f1 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -10937,6 +10937,18 @@ F:	kernel/kmod.c
 F:	lib/test_kmod.c
 F:	tools/testing/selftests/kmod/
 
+KMSAN
+M:	Alexander Potapenko <glider@google.com>
+R:	Marco Elver <elver@google.com>
+R:	Dmitry Vyukov <dvyukov@google.com>
+L:	kasan-dev@googlegroups.com
+S:	Maintained
+F:	Documentation/dev-tools/kmsan.rst
+F:	include/linux/kmsan*.h
+F:	lib/Kconfig.kmsan
+F:	mm/kmsan/
+F:	scripts/Makefile.kmsan
+
 KPROBES
 M:	Naveen N. Rao <naveen.n.rao@linux.ibm.com>
 M:	Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-16-glider%40google.com.
