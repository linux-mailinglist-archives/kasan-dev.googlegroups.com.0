Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZH6RSMQMGQE7KO45KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 762805B9E2C
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:13 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id q11-20020a0568080a8b00b0034fbbc585f3sf999972oij.4
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254372; cv=pass;
        d=google.com; s=arc-20160816;
        b=y7gUopsczAhR8mH6/LaVf61r/bD2pCdg/xT2s6pwPbZxuwNQxAExkQwIaG3H5gUNrx
         Mpvb0LBUM+hNa7ui4U5UjCJ2fOm4wrPTaf1sw9+SZX0/K6xhYb1tMIFp2ZZ214MQmr9s
         iY4ZwTSFFNDmtJPBiVR+FZ4lcl7Ra8W4siQB3nlmCBr+V32n3WFUvVY+dc8rCRCVzxHO
         zHEHhSx5iIlSmH4jP81IriMwPf8qnGyb+yTDzOm54S8T2kAzJXkgIEG1s1w6b//3vWc/
         uxPTz1Gd0dztqiruYdDV7EPhqSERKoLaoJcxresF6Ky2UxNkUuHneKISYdxED7Et3cr1
         O8OA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=p810DfwAKaQ2c8kkjjPZuOlOAlUan4GhCQ0uspZQMnY=;
        b=yM0RulINfpVtk8HaghUTp/oV1a4iuI2wR/KDhZGVAdSIYBQ+CEmT8/SgbkK8gS3myj
         3CmZUHjocCUsag5FIiE1ntgQFGDEPtL91daperpOn+pqz6HzNbnY8PG3Y0Tqg2ZTvH2g
         ir4TVm+3l6lkVK2xe5rLARBT0BTfc+9Xymc33qw/eI24HYXzUEOXJJK+EdvqqSEJdyoG
         DrUfuSmLT5YB6pA7T6kyYJ8BX/ad9OXo5dDtBKryrdWGCigT7xx0Dq39o7TFrOmMmVEy
         d1wuPe9N6Ahe2r2Hu/PrtUqteCBMnt+d+xCMbbtBj5kwzAR6034jiX4Im3M+mXMthkfI
         uFIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nHAQ6SAQ;
       spf=pass (google.com: domain of 3yz8jywykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Yz8jYwYKCY4y30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=p810DfwAKaQ2c8kkjjPZuOlOAlUan4GhCQ0uspZQMnY=;
        b=YeAgubGgI5EjrX8fmH4jw2wpMbUarueLm0LkCLXleHVEUergwngF0nccmUKQwhRyG2
         VYD27GdHkgiTUAXepyzkXPaVGkk1LJoHx6nRt6POJpIRk9nlHo7lk8tpCmTGzpN+vrHA
         qYvxjNOH26WdZlU3J4cr8ec1mWkmztSes2CqsR+0uv342hRRzBeiGIaUFbg6wCTxBAHE
         nHYWTR7EAdXkGG9fxeLbf2/MsLTjMIbZQ3Ip0YmsO0JLSBWL2OSjSWICx5MFu767y29i
         6sXpi3JQ73bfL0IanEQ9Fl6ElmgKKN71OygnexfGcdv+XjHRRstFYgaOI42IE9s+uy1K
         /z5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=p810DfwAKaQ2c8kkjjPZuOlOAlUan4GhCQ0uspZQMnY=;
        b=sRDw/lkWWBaA1DUSeL0iI8kfxE32t/oekcqTHEfAmJfKrCak1YUzn6MEB+QAHey0ff
         FQ8oPr+nXsTBcYz5yi01ot6WehwwBBQyUTjrLq+AhQk30Z6s7UlPn6R3D7bYz2nWcm/j
         2URmnkHISkLfqizeILKOOEYSORsToJag0OLeiA7qxMZ6R9UwrPsVIDNM45Ka5eBtk8YP
         62NqykxnxzRXnNfDS+NECa94X5eqrcOrwf3mGQ57wSjCaJ/eNaxWIInb11HH4JzdcELH
         /+yLwFe/wEsn1CuwKRiFJ6AhKERSapi5WozCRlA1sVm9qr0iDWto/efr78TmG48/NP3p
         bV2Q==
X-Gm-Message-State: ACrzQf1Ob1zvEHvBQO/3jbYUrxTeFIGbx658XBiWjjV/PDMf2NY/TtHk
	jtwkKhwUfqldaofJdbJH+7M=
X-Google-Smtp-Source: AMsMyM5H/u+30QPnihjZklxKBDTXN2CG/QCNY3enzUuNfdfmUTam3Mmkf/pn3D8fAxHdL3YqgtY0vw==
X-Received: by 2002:a05:6830:6612:b0:655:de94:6130 with SMTP id cp18-20020a056830661200b00655de946130mr49077otb.374.1663254372118;
        Thu, 15 Sep 2022 08:06:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b1d1:b0:127:7af0:8da5 with SMTP id
 x17-20020a056870b1d100b001277af08da5ls8458791oak.2.-pod-prod-gmail; Thu, 15
 Sep 2022 08:06:11 -0700 (PDT)
X-Received: by 2002:a05:6870:6027:b0:101:696e:d594 with SMTP id t39-20020a056870602700b00101696ed594mr5817282oaa.245.1663254371505;
        Thu, 15 Sep 2022 08:06:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254371; cv=none;
        d=google.com; s=arc-20160816;
        b=HiyXSP9kJzv9Jq3eNurt+2sGbLLC+tbAOUlqHLlWl/1OZRIqNaEprdevTNuv3lVGFj
         PyiefhwNuZcrd6zihqk21i4vTuMH5Ai78MVsxGLw10aExpcJ7OzIoOGKNNTKvKxNPqrD
         DA67nBg4j3DfX8glgcL6wWrW8TJgvpsgMp7uKNK7OSGUnWOaYy97TUkyeM8n3fMba/DX
         CoOEaNytFrssvs+yaLJFvlscwXfmuN5kf0Pfy7Tr9kYY/MQUYUPuOXFx7haNJ4kaf/Aq
         lBcscq4wN+yyZypwQ/VWGjD5nTQXMFacs63WYt5vzyFtwQkq2NJflueMVEkgm7zBuQkO
         AWhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=yflFKH40jmwCCGQluWMEQ//gU/gWIMkmRe3xdXByGVQ=;
        b=z+Dujd6sDFwqm18l59bVqca6lfurmNBX6fwBv3M5Ob+cFXB0RThSR48Cu0k5crazpl
         6BIFVnSeSzJUgZZKLEYtboL4IAc6gdDCrfE9bm+KAlhqP8s26e2iKLd4Wsk6xYiUzTg8
         AwzmAJfDnKIEBCaNyf5KacGKPnnhnkxzrsOU1SPdzaLj7Q3Ggoj7+32NS+LwKuNbl9y/
         7nkKOKnh7L5uEFWObY7Cf960aEjxcqD7fEmR8l6nwP60slgNcgWJuSmu5ffrNTBYoArl
         h+I/vfgbRlru8ZYbJdILxVH+b71lfGRFwTUxdg6fq6R51pvystgT3RCzmzfPMqfM1gwg
         QnKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nHAQ6SAQ;
       spf=pass (google.com: domain of 3yz8jywykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Yz8jYwYKCY4y30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id z3-20020a056870d68300b00110b77f4e1csi296599oap.0.2022.09.15.08.06.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yz8jywykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-33d9f6f4656so163214097b3.21
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:11 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a25:9d0d:0:b0:69b:6626:6915 with SMTP id
 i13-20020a259d0d000000b0069b66266915mr228697ybp.294.1663254371078; Thu, 15
 Sep 2022 08:06:11 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:08 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-35-glider@google.com>
Subject: [PATCH v7 34/43] x86: kmsan: handle open-coded assembly in lib/iomem.c
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
 header.i=@google.com header.s=20210112 header.b=nHAQ6SAQ;       spf=pass
 (google.com: domain of 3yz8jywykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Yz8jYwYKCY4y30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-35-glider%40google.com.
