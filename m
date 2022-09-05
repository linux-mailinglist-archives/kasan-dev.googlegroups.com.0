Return-Path: <kasan-dev+bncBCCMH5WKTMGRB66V26MAMGQE3W2QKLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id A82385AD271
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:40 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id v15-20020adf8b4f000000b002285ec61b3asf746900wra.6
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380795; cv=pass;
        d=google.com; s=arc-20160816;
        b=vDfCXckAs4ovu/9v9o7uU2pig6G3C2j0AglFSFzeTUotDe88RRxHQRsYMEIFgQz7Sj
         B8DLd67prlXjyc10GS7jS9nzRh0iv/63frKMq5VY+j0Uvt/CMrttCItyUcrIFH3xfZad
         yHX6xEhxCkLstdy03PJiJPyPU54XuYGmpDNmnZDu0RYlKUH2R1pjoIPGpyfoiYL+E4p+
         aKnec4vcSUvCBuHwyb7GyPyG0ClWQ+MrUbKySBRDCiHGtnjdPe2pcBhw4cqLnZUecLOn
         Fhvn3ah18IQG6CF/J5mXaLc1bQ70LsoSprWe0tko1WMfw163HyFuLihYySgO0xWDbtnm
         xKyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SIqZ2xjgg1bSoHE8qlFse6ADw6yMGuIhNd9XozvGbfI=;
        b=W1ni2kagaiROVXKLUpAydm9wPvhtybmMZLU3ouMW9dNakk5C5zahi36bODCNJlEvrw
         C7LEctSGoi4DsX6A1JBLoNOAt1WOaDOtMPyvNTj5lFzFAEJww9dvZZ8tLQXEazATYOKh
         Krp0LghDegX4rEUyDALsQfHsU1m58Cf/TSjUg1k37jnvCRsIuXqPdNGbg4VXffVQcU34
         mDrDCFgmabtDzzkV0TZaagFOVY8n243ja2mxfLAHBzQKfy07aIzAQde9SUCglJpXApK5
         p9K5OjmmUvfVIORVz7TCNilp4UtvumWJ2hJs0ywihsZPOCSyBx5yr9UwLlH+ZyeTdCP0
         lCVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fAxph5Y6;
       spf=pass (google.com: domain of 3-eovywykcuyotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-eoVYwYKCUYotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=SIqZ2xjgg1bSoHE8qlFse6ADw6yMGuIhNd9XozvGbfI=;
        b=eSREqc5qxkKCvcoWKP+wpfjhKIO5lX4DYXasUNX046HAzOKzZwzTAIl/yAm6QyzllQ
         hCSpQwJConGei2/Eo2QIhzn8oNQ2fxuAvZaT/sYkumYyP4Ez6To8WpX2o+VJPNHHjDIP
         /hOLYXteey/FGPuXqTPW7MgROm3O76osRhUlPpnp7s7kVhMAp7Y/2kfckbo9NrtX6x73
         2KlhWSoUsGWMI5PlL/cKyVzBolVl5NNJCSC5lQxl1cRsbHHWSY/7jTTdzKmC2AeXX6Wq
         C+qkWOEc2kMlNYjidftmc+oOmqghnJ6+LDSRMVYMpaDbwlcgy7ee31Q1nUCfwqhzO96J
         wuxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=SIqZ2xjgg1bSoHE8qlFse6ADw6yMGuIhNd9XozvGbfI=;
        b=q1megWX21pPLeq5IAq9aCb9yKEqoDugOLQ62WWlIg+tA56KHaez44r2jDDHFprtO/M
         XZYMFUUMI6YA2TaTamRQ65CNNlLsqGICj3NWEgSlBghX18cxoEtXHYoxQ6LbzLUmjqev
         aWfbIp6DtLKTIKMRqXUtr0W4s+L6xqS0tBwKATB+V/13F4rPRnDYfYlEy+j/CnragONO
         GTgwgizNpNJYitlWL43MEBtRD8A/3y+wV1+l5rToxnrNLFd00sbxdLJDYyhE6qJIUUE/
         nJYc9cpCiPFUfzl/EV1jM2sfstamXOXZAjt3uCHH6G/fmWxvpiortXyx64HSmzo5CiA3
         Q2Gw==
X-Gm-Message-State: ACgBeo12ld0VEpNMLTlrI3SmW1scx1/SI6HwmU6f1mmlGSU2TwmQCZvo
	roH+BlQzSn/uY3+TvGomf3U=
X-Google-Smtp-Source: AA6agR4Gg5AFkYAe8NwLI0FWMA7ZhtoWYAY077YajXZ7OCtpv51SfHWwlGTc2g09hlL1A8rarVBhCQ==
X-Received: by 2002:a05:600c:1d12:b0:3a5:eb79:edc3 with SMTP id l18-20020a05600c1d1200b003a5eb79edc3mr10675950wms.136.1662380795319;
        Mon, 05 Sep 2022 05:26:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3784:b0:3a5:1ad:8654 with SMTP id
 o4-20020a05600c378400b003a501ad8654ls3812203wmr.2.-pod-control-gmail; Mon, 05
 Sep 2022 05:26:34 -0700 (PDT)
X-Received: by 2002:a05:600c:384e:b0:3a9:6f5a:b6aa with SMTP id s14-20020a05600c384e00b003a96f5ab6aamr10787488wmr.131.1662380793992;
        Mon, 05 Sep 2022 05:26:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380793; cv=none;
        d=google.com; s=arc-20160816;
        b=mm4ZPG1y2Pr4FdtQ8jwyLEDl9FgS3OgvvqaiJZzkYDt3vb1yKGwOeu+oLb3pb45Umb
         FqPsJAO+lYNJIyl/mWbkWhAD1Vxkp2GUOsnJyzxrElmR/GJ3Dw8NbQkkNs8pcudxSJhU
         SCesBTiSohfJj+tVubroOxeWNL462qoD+V6HQQd7255juUWDKBHitr8b8V+3NmYYcG0g
         Muh1G/A+NcfrckfdgKykQeAmAU5DdxOXleJqgfdjYYXvwuxYxm3VQDHGLpaaemG6TapW
         JGJ+EM60Gg8Qg8rt7sJywXygocCRi4FUvsBWU3419GAVZDQvhCKkbaCEETx9/uoe6KAo
         lg3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=yflFKH40jmwCCGQluWMEQ//gU/gWIMkmRe3xdXByGVQ=;
        b=iEOZn6DQ/1AyuIKZOKP3gpPd26nIisO5jtE2Zntw/wwBz5LM2VPDHY34IsTU9C7RVE
         jbVmUFaFHNFBF3AmBikrs35xz73iKIjT8Xc7VcoW3Ic2yIgX9pJdm/7ZddhS5lhnIkfg
         gJP7CxXGHMZbd2wg75EYTQCVjoW6YgNpefGS1S2AjkQDNUwNJw3tYKkZhZ349TEzV4Jr
         wIiySvD7uwpdXIoHJsQs4+nNtgxTtKgi2Z3JWmv6zMLjwsy7fYj/2qhyGlY/w3RrbPzR
         WcQ6b6lWdoCG4JGYx0E7AHIiVqPu/hNliSGQxjiJQfv8OEYHIgAve1HfQy2wfdQZ9/b1
         hyJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fAxph5Y6;
       spf=pass (google.com: domain of 3-eovywykcuyotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-eoVYwYKCUYotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id bp1-20020a5d5a81000000b0021f15aa1a8esi301320wrb.8.2022.09.05.05.26.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-eovywykcuyotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id gs35-20020a1709072d2300b00730e14fd76eso2277246ejc.15
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:33 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:907:2722:b0:731:2aeb:7942 with SMTP id
 d2-20020a170907272200b007312aeb7942mr35645383ejl.734.1662380793723; Mon, 05
 Sep 2022 05:26:33 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:43 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-36-glider@google.com>
Subject: [PATCH v6 35/44] x86: kmsan: handle open-coded assembly in lib/iomem.c
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
 header.i=@google.com header.s=20210112 header.b=fAxph5Y6;       spf=pass
 (google.com: domain of 3-eovywykcuyotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-eoVYwYKCUYotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com;
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

KMSAN cannot intercept memory accesses within asm() statements.
That's why we add kmsan_unpoison_memory() and kmsan_check_memory() to
hint it how to handle memory copied from/to I/O memory.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/Icb16bf17269087e475debf07a7fe7d4bebc3df23
---
 arch/x86/lib/iomem.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/arch/x86/lib/iomem.c b/arch/x86/lib/iomem.c
index 3e2f33fc33de2..e0411a3774d49 100644
--- a/arch/x86/lib/iomem.c
+++ b/arch/x86/lib/iomem.c
@@ -1,6 +1,7 @@
 #include <linux/string.h>
 #include <linux/module.h>
 #include <linux/io.h>
+#include <linux/kmsan-checks.h>
 
 #define movs(type,to,from) \
 	asm volatile("movs" type:"=&D" (to), "=&S" (from):"0" (to), "1" (from):"memory")
@@ -37,6 +38,8 @@ static void string_memcpy_fromio(void *to, const volatile void __iomem *from, si
 		n-=2;
 	}
 	rep_movs(to, (const void *)from, n);
+	/* KMSAN must treat values read from devices as initialized. */
+	kmsan_unpoison_memory(to, n);
 }
 
 static void string_memcpy_toio(volatile void __iomem *to, const void *from, size_t n)
@@ -44,6 +47,8 @@ static void string_memcpy_toio(volatile void __iomem *to, const void *from, size
 	if (unlikely(!n))
 		return;
 
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(from, n);
 	/* Align any unaligned destination IO */
 	if (unlikely(1 & (unsigned long)to)) {
 		movs("b", to, from);
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-36-glider%40google.com.
