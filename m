Return-Path: <kasan-dev+bncBCCMH5WKTMGRBP6EUOMAMGQEQXX2YPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BD605A2A8D
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:52 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id k13-20020a2ea28d000000b00261d461fad4sf661575lja.23
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526592; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZCluKplPvGSACiKpQ8knnJdewj1Lm2Kg6xin+0+1+bH2tVQAFfpQDa+C8nCODT+k94
         JC7xM8mpEfMMvW0Rcm9i9cgtOxKuahTIYnYqbEJOhf7TcE+N60D7NDMD1X0B9fsw3t8A
         Dn8EcWEg1hdp9BwtjzyOTFciH8yVj2mmVY6wR8+T8YOZCQ4RbRNRroHv5wwD+fbzr5F1
         XMn8tX+5G9xe+H4GTHAZ+LKhLhdkznmDbbnmIPqGd/ynqH+nmApvGSFzdwJgHKkqLV1n
         DWexXVHgMrkVA2r3PLHH4X5W+YU9l0/EzCX+UUXS+3Us3rV2OjjoZPRT/uO+YmWBav5v
         uPBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ni2s7P3P81jsh4VQGXVLLFX8Y6H/s6wqxkfncnaemF0=;
        b=O4keRZUgzRKb+ZMWtdu9TIay1uix81tHFx/f+ke+hUEDTwWdFgzz+lWq98tNglHzC5
         QRfXFqe/vgxwCfVwgT7ThYeQrPE72oll0NN6jRB9MC9eLv8Qz61Svq9N4m18PnbvjIxL
         UX4Y/DkbEP+QnnlUPCbSbbBzbU3+wz3W8J7lJTBdck52C4Yq8eHRyU5f3LYa551e3/Nz
         wpt6eAzeVhP+7/hCxiHQP4nYIH/8bhPak+F5VKjuEU927SEwAxJjLOLzOJLPyE/aJQfN
         MCtoN8X+B4bxyaM+4n/xV05gYlTDz92P4optAuwpZAIw3IBbrnrer3U9uHq0DX6Y0zU1
         qtjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Z6njr41s;
       spf=pass (google.com: domain of 3puiiywykcuunspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3PuIIYwYKCUUnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=ni2s7P3P81jsh4VQGXVLLFX8Y6H/s6wqxkfncnaemF0=;
        b=S7NLnZkJxVhOFVJ2Te3fXvNELFn+rTb1D7bkBTn0Zr53wUa658j8zoAuAo1S8IcPXL
         h0KLMrwx4RkUntPb1KWinWvVTSLZXH5Oj2KnJRl6puY3EaU0MjPPEp9Hd05E8hSfToWB
         /gcMUFSz+5zwmecyCfpR15/RoTZVLBARjd84Y4EpavZtRO97hBsDUY77C4ytEbbrgNel
         E2GQ5wm4B7YlswOaDs90cVJ9DfsUbxWFlmiLcTB82HSkNppTs5NmgrqH8IbwR64GSDPB
         cOMWeebHjKm1qvZ6tukCn0+01Q3o0RsvAoz3iAxeA1zQYJR0H/CUBhYShbAHiDMNvVA3
         jYpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=ni2s7P3P81jsh4VQGXVLLFX8Y6H/s6wqxkfncnaemF0=;
        b=07nUXpiBOjWxHQ7wlYzz/+V1yMwNSNYuGQY3c/fCdhs6ZDQPrhX+4KUh/7ibqzleuN
         JreMusvJJ0DnbXWXb2ZrEJBeRRdads5mZQoVJLQtomhNjtVty/CJvbJlBNMZDPKbfBYj
         OFmuXG25g0sECTa7T5HuDzbb24l/haH1lBv+jDWOwtba1gux4ALVe0s+o3e2FuzcHqd5
         q1As+eFBOl7W+byaLS/bGSWQ+sWjcX3SIDzJ5nD5SA4KZXwmtFKv8zLgbX3D4gPXh98P
         fUD9SUmL95VKQmWb95gJNUZofGEuhNtlWo44M/Xuh5mRjXsiJDsGE+YYLZsCOULf3HE3
         ZWlw==
X-Gm-Message-State: ACgBeo1YQ8jTFjsIKX77f5q/dJXDmwGYpAZcsildss3LzNyGaR8h2NEG
	z4zpvgjZ2x3HHrXvo3jDVG8=
X-Google-Smtp-Source: AA6agR5u8G9gMa5YNwXu16qO2FAaYfy8muRCXkIB87fSe77K5hGMPt+Gt+Y/OgybjeFXx1JJRAm6wA==
X-Received: by 2002:a2e:a44d:0:b0:261:cb9c:6891 with SMTP id v13-20020a2ea44d000000b00261cb9c6891mr2597978ljn.136.1661526592171;
        Fri, 26 Aug 2022 08:09:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:238d:b0:25d:9c9e:d165 with SMTP id
 bk13-20020a05651c238d00b0025d9c9ed165ls710840ljb.7.-pod-prod-gmail; Fri, 26
 Aug 2022 08:09:51 -0700 (PDT)
X-Received: by 2002:a2e:2f03:0:b0:261:cb0e:c329 with SMTP id v3-20020a2e2f03000000b00261cb0ec329mr2298069ljv.106.1661526591124;
        Fri, 26 Aug 2022 08:09:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526591; cv=none;
        d=google.com; s=arc-20160816;
        b=igEuLH70eSfGxDUXS7yucKcPlTnGGmjMkTGa+HhAOnHQddfzbTmw3hsEIZCzT74CrV
         UGslj7AyHvQW5rQnZw2nk+9xLQfZFFTEUVbQrZZ/dNchhdc4cEfcwXtJvDZK37HoyFTq
         eIQ1LeNYogrADmEeut8KRWE11CaDvgGKr2LIekZDuCOrGs1esixdQDiYopODR/7nGZ6U
         c2fgwFcnh1g007HSU9YOcEb3qsEZpoYQYj92UIFpW0oz7cn11rC14xEnFqA9QyUCCk8d
         kiK8QUpFZxDH3wX4zVpu3IUpVXQp6AzJJKcf5XED/6r83LEl5usldZaimUT2QXkcj6qK
         rAIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=+OT6SjVSfWjyqzxbCZyABchDUcmsVpvJACt5vGUex24=;
        b=f9qgoY+SoXmkA8skFGKhuV8QIXnT7KusIqyiEyWwCgwPJUN6noQhCWZ59la11xjGH9
         Cex867FUrCBlazHeiSw05BM0yUeJSBtcTXZIqHg5k5oCZs7z5rwhkqQhajhj55B91Goo
         07WrFaiaC6I3Gc6g0z2xk6SCMZw4IWb5SiOTaDbKkZru+R9KDK0BtD3wtKmp9BmRjm6Z
         Vh+xE1Mj7Z97VcwiYmWc1aFsQR/mqltEY3+0U6SEQrewA2hKTF41Kvv1SX5acWKfwIcL
         zITgS+J9yl6esqFh+FTuctOKD7TipwikLoXp4ni/MrGGv9Tc8fvFPWSibliUQjTSj6Uq
         IbkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Z6njr41s;
       spf=pass (google.com: domain of 3puiiywykcuunspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3PuIIYwYKCUUnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id p5-20020a2eb985000000b0025e5351aa9bsi74221ljp.7.2022.08.26.08.09.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3puiiywykcuunspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id r20-20020a05640251d400b00446e3eee8a1so1243082edd.21
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:51 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:43c6:b0:43d:79a6:4e32 with SMTP id
 p6-20020a05640243c600b0043d79a64e32mr6871771edc.281.1661526590665; Fri, 26
 Aug 2022 08:09:50 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:58 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-36-glider@google.com>
Subject: [PATCH v5 35/44] x86: kmsan: handle open-coded assembly in lib/iomem.c
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
 header.i=@google.com header.s=20210112 header.b=Z6njr41s;       spf=pass
 (google.com: domain of 3puiiywykcuunspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3PuIIYwYKCUUnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-36-glider%40google.com.
