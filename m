Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCUH7SKQMGQEK7R5PMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 42AEF563520
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:11 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id p7-20020a2e9a87000000b0025a99d8c2dcsf501656lji.18
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685450; cv=pass;
        d=google.com; s=arc-20160816;
        b=QYZ+zsiYqjquozpqAUC47FeUAiiyu9uvvdQ1qbUpfg9Ylqm8V6JHCHkf8wOujZ4yKs
         GXoALzdzeX7gx7WkjbpL51te8/PB9eJMHpLRpWzcjtTiWW5BJXFC4/+w6EaoUF47nvb3
         jTn9dIpa1/nCB8wAIWBjasdXswdcDYoZ0Z10ekuNz7hWKRdNx8kR72qqoQ55sm18t5/+
         p3zz+DeDHM7QbAmn8VdG5sQt4TNwlzVBtBjwNpCPauU4f13R/LBe4rqcO+YTDjkH9V87
         C0GF8vr3sl+hSSnsbaTssBJ+EQ+F4iidesYtdq4A5dNLCswfEQb53tzgKzlIjREW0zWn
         ON8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=/pqRRO8O01FHzksUvkkg26aCOx8rUPnOt50AWsyqOjs=;
        b=XYY8PYFqRTT6mvc0pQJw+AUzwPPbGuIByXZOk4kuGmC0EANiZHtVTO2ybeohQnkhAc
         /3rpb24QyXkHZvRS0ING8jTf1UD/cekAUSHAV3EBGmDsOWV5M1QbC5Cid6E+X+GyRNES
         Wa5xPdoGlhlrVULrgNbkcxNcCaoeByEgIXRifD972WE06YyXW/uduvruK9ILpoSe2S25
         tNzm61iYH6RurLfae7CmRLZkG0Fa3C2N+bUR3Z2IKRWN7plBpOfwFLcputZ6wGV5sVMS
         FAZ6jvcDkSY8HeO+T+1lnkki6IZbEYKH1Om8bIIUCX6Xe73ZnUGZ7tuR4yRjcUo63Fgu
         xn4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sYf9Flp9;
       spf=pass (google.com: domain of 3iao_ygykcacnspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3iAO_YgYKCacNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/pqRRO8O01FHzksUvkkg26aCOx8rUPnOt50AWsyqOjs=;
        b=lZn9Mw5eRTFD24M1y7lHFgTHcFKQRuThvPWi0ive5yIKJv797KQ1rwZ+d76iu07fAb
         gebt/RfTN2XtHlxrmk33anv41dU43i19acfW+SclddzliUmFcahOK8lqWjbs5QiGLaXM
         cIZD5DGdaDYaAUwfv9niePCOfcUPd7EewHZttEI52E8NwNecvSJcyowrmpotN1FUS/Mk
         qJBeCADbkqa5KdPbHvP/+pcJ8EMJdHZJJ2f+hgVwZOfPzLeyMJ7eBzETfyRu3KOibJuc
         M09vCHLxjWws+VtKwKjb9IUdGtp3Ak7uPgy+QfSmffELLy3u+k4Zrd+liyLqg5t60R0e
         434g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/pqRRO8O01FHzksUvkkg26aCOx8rUPnOt50AWsyqOjs=;
        b=jeZMvuKtu3kV+aZh01GjRF/RCmq/P6iwOgRP86uc79pGXm0Ppb7klgqC8vketdMa67
         B1+R3f3AWBSkXBDqx/R3ciRtRz/Umx1xYTlHD1r4VVCgG8aU4Stz7dcS9iDFpDAw+gqK
         qON+OxR5wpOYQr08vT6fBD/7iQZEasgL/qB9+f9b99CcsGjR3hHNpizlI2JPMPoWECmk
         2i8qGgZ6cGnHTBaEWOCkBBv1yfjm23inhopBh4mutYiVFKP2ILEoZRoGKMfNkbos9cD/
         ThyYSWUST0R+PyJpr/Avy4J+bUXjmqXfeuyrK13c0JCSEKNY663GkCTskUTKCAF/cTlw
         awqw==
X-Gm-Message-State: AJIora+aAvIme8oVMuFLuox9QrC7mBSxtlM+dwDhk1KfLk/XYjYl0iRU
	yI/ZQvgQ7Q0M7WBtD1Z/WyE=
X-Google-Smtp-Source: AGRyM1sXyFKway2G3mKk0mIOtkhv5BmSpr5gJR4EEVqTKdyO2xXfb2vNCwje7utoNN2odDJVIgzJaQ==
X-Received: by 2002:a05:6512:114e:b0:47f:5f76:22bb with SMTP id m14-20020a056512114e00b0047f5f7622bbmr9823620lfg.648.1656685450849;
        Fri, 01 Jul 2022 07:24:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls87416lfb.1.gmail; Fri, 01 Jul 2022
 07:24:09 -0700 (PDT)
X-Received: by 2002:a05:6512:33ca:b0:47f:acc5:6c8b with SMTP id d10-20020a05651233ca00b0047facc56c8bmr10151937lfg.612.1656685449128;
        Fri, 01 Jul 2022 07:24:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685449; cv=none;
        d=google.com; s=arc-20160816;
        b=uEyqKidXt11Rkm1Bmp+LPNiuTk6T1KYFV0HG6G3dItlx1U/4370c60qNO33MPzheh/
         hvs4euP/cxwF9gm0sJDbnK/zmYI6RCkEJACDsFCDZvrBLGq6XqK2tFtslAFvMT4ELx6G
         pZpFwZALPpM5ZaRBoTakKmfbyc9WqvkQbcO7iwuZLdoIr9psnfXMCbOETAzMsb9Lbzpm
         FcDSqbW/G+yHJaZeRRAAMmZsfQASaHwAxCYgxJdfFWSM4GMUicfXrMhI7DUXhiVqT/A/
         f7a9+CxT6Dz//LNofaLtFOAhSxTYfLF7LbuBwRCp5bBECDgiMbSLEsJSIjLtRKPB4ga4
         Y+DA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=GNX0et0VeFDbRNtievhe/rlGdldiDAHSzzvJvy6PdeY=;
        b=zVqRx5u1/bRFd4FTtaaPenrc/js2tf6E3yrqwawTAKlmv9gJYVVHaVDfycEABIJpJx
         dJkOWDvjEPaPWP3sE7DTN2WkN3PHL+gDwG+KQstwlLqnajgcXBxPWrYCXxqA1JE2+Ifi
         lnUp85La0PTRwz96Mson3uVvHe/DD9zifvb2D332fpozV9F1lW9aaExDKiFVJXySspVC
         yAU6ExNCDbrt7d0AttU7RT/XhbC4SuUWVxLsFNywvZ65zs2QH0eW9PsmVvW71NTm77qA
         g4RyEUUTZ+H718e/3MxfSNjxOwUti1rd9tj/9Epxb96f9m7vHJSbsrHfJvSyZ7Hbt+dM
         e+rA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sYf9Flp9;
       spf=pass (google.com: domain of 3iao_ygykcacnspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3iAO_YgYKCacNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id i2-20020a056512340200b004793442a7f0si1008054lfr.6.2022.07.01.07.24.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3iao_ygykcacnspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id x8-20020a056402414800b0042d8498f50aso1886211eda.23
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:09 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:2985:b0:439:651b:c1f4 with SMTP id
 eq5-20020a056402298500b00439651bc1f4mr8429220edb.276.1656685448889; Fri, 01
 Jul 2022 07:24:08 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:44 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-20-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 19/45] kmsan: unpoison @tlb in arch_tlb_gather_mmu()
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
 header.i=@google.com header.s=20210112 header.b=sYf9Flp9;       spf=pass
 (google.com: domain of 3iao_ygykcacnspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3iAO_YgYKCacNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
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

This is a hack to reduce stackdepot pressure.

struct mmu_gather contains 7 1-bit fields packed into a 32-bit unsigned
int value. The remaining 25 bits remain uninitialized and are never used,
but KMSAN updates the origin for them in zap_pXX_range() in mm/memory.c,
thus creating very long origin chains. This is technically correct, but
consumes too much memory.

Unpoisoning the whole structure will prevent creating such chains.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I76abee411b8323acfdbc29bc3a60dca8cff2de77
---
 mm/mmu_gather.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/mm/mmu_gather.c b/mm/mmu_gather.c
index a71924bd38c0d..add4244e5790d 100644
--- a/mm/mmu_gather.c
+++ b/mm/mmu_gather.c
@@ -1,6 +1,7 @@
 #include <linux/gfp.h>
 #include <linux/highmem.h>
 #include <linux/kernel.h>
+#include <linux/kmsan-checks.h>
 #include <linux/mmdebug.h>
 #include <linux/mm_types.h>
 #include <linux/mm_inline.h>
@@ -265,6 +266,15 @@ void tlb_flush_mmu(struct mmu_gather *tlb)
 static void __tlb_gather_mmu(struct mmu_gather *tlb, struct mm_struct *mm,
 			     bool fullmm)
 {
+	/*
+	 * struct mmu_gather contains 7 1-bit fields packed into a 32-bit
+	 * unsigned int value. The remaining 25 bits remain uninitialized
+	 * and are never used, but KMSAN updates the origin for them in
+	 * zap_pXX_range() in mm/memory.c, thus creating very long origin
+	 * chains. This is technically correct, but consumes too much memory.
+	 * Unpoisoning the whole structure will prevent creating such chains.
+	 */
+	kmsan_unpoison_memory(tlb, sizeof(*tlb));
 	tlb->mm = mm;
 	tlb->fullmm = fullmm;
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-20-glider%40google.com.
