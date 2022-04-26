Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHODUCJQMGQEKWGYZ3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CAF8B5103F6
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:18 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id v13-20020a056512096d00b004487e1503d0sf7882790lft.4
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991518; cv=pass;
        d=google.com; s=arc-20160816;
        b=N9PFMA58fhnxtvp3ncGj2pHVre5P3WveiuD+MFoD4+QUjn4wdbn2bkACP6sGMDcO2i
         PDJXM0ehp6cGDzIJ5msGmJL0dByfURBfeM6wZ8hi3sjUK5sgAbeFzBIzSbt4ZlxPmfdi
         q5cDHR107sThHL3NFEuCWsTZQGcGFnsEKOdrXI6Kon20Fl3THoP3AzInf3V/a45oVzF4
         0GNMX64313rGhQWM/AiqOs6JpOvNMI5+4CS+T+z+0eogM70IfJbUElQyRuA91wLWKO3o
         lvT7iGDwRLTAopfNl8cw5Qd5UhDau62TSCfd4fPCclqvtwwQo+l1WiLIVbXiddMEX5D/
         xHag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3yUsXI1BAeF1iuRPpowoDJQgz0kzBN0YhrJklOeuByE=;
        b=edPVEuasjZulNMqACDehMTx5YoENTG+L+xX0JxALOTEZJkKv1u9ktqTnfgLh9UAkUm
         fy5jRuwyDYBmV365mC0SCIfpHAU9aKNUTj/rjOz2cftnd0OJ9IRmcJq2jSjY2jw6G9l8
         xC5NHWnA4MlYMWd+aihU3CvwK2P8lshN4CxI3jkV95iqBGuZ/7mLMRLclrKsyjaDevGJ
         ATmaY5ndb4JX8ipyoewe+ABaPTXi3fLfigZB3B/NSZPPaIkzSGUL691oYreMAaWUsV4O
         oFBobpuDNZRiL7NYYXRWLIVf/M+wp5wNolhMur5uFWU9Nv/Xt+NnwAKP3rmffbp8wPWG
         8EZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="eaD4tCJ/";
       spf=pass (google.com: domain of 3myfoygykczg8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3myFoYgYKCZg8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3yUsXI1BAeF1iuRPpowoDJQgz0kzBN0YhrJklOeuByE=;
        b=mx3B/zT9lgCnVcitYa/3QYF1SZa7zWIuJv4Ek65sw7bCr6o3dvplpTzLdysuMSHhWk
         dKdbYN65WxjrjTiswaQuZEhFHDVG800NsgSDlYrhtB0NJrlINbMtx+xOMp3TT+PJrtVw
         Iok7Q2udMdSzYXLtf+hb376B2XSCLraUfG1MhxoapO/1Sdss4/LielJn+nDC/waKNXxu
         pi2CsGtaCh9pnQnLwuA1oCW55fEzztc24Q/F+gveHojRLZz+SbBIBQXCefFWu7sNy1dX
         UlUSedpbvwCIEsk/W3+xIRuM7w/eGd+S7w2znMKr8X4Wz9sHm/ZtC3AuaF7NJGQYF16x
         090w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3yUsXI1BAeF1iuRPpowoDJQgz0kzBN0YhrJklOeuByE=;
        b=EsDF1tsg1pu5UmywJl9P8CaZUsN06X3PLgjwrHqT/9FaX4TcwVEAxhHRr3HXOFby6b
         VY/ou0SbgL0/pHI/9KaCXlJl9Aro3+E1zBkfF651AmvIipixRU8URyZspoqezlSFr/ws
         gdiqRBia+zaqqwx/savMZjuxXf/c0sVKDC8t6BMW52eyYvEYW+lS5Z11YKJMDZ1ZaxB2
         DWx1yLaml+/Lk3UaJJHkBySnOTBhcy1lhsDvo/DB4/bfDqfBCsAosYJ4SbDw3pxP21uC
         Ottsnx0uggInNdQrAhGIXd3pYXd9/4R4uOHF3nnod/SZo5lmTU/tmFIvOySEz9yHAaOX
         9MQA==
X-Gm-Message-State: AOAM533A5Whf9IYrELMp4c/i0h0HO0uo1k9RpFm4SyZDcI0dh6uUlSQc
	HyxgE3wUdh6WcKc/ifbSIEY=
X-Google-Smtp-Source: ABdhPJwK2cWYXpard/71aFXrZwJiE11N/pqvbohLIXDeTJ23ClJQXcWVsBmsAZ83U7moZDqskzefjQ==
X-Received: by 2002:ac2:5101:0:b0:471:fdd7:4c9c with SMTP id q1-20020ac25101000000b00471fdd74c9cmr10884656lfb.49.1650991517712;
        Tue, 26 Apr 2022 09:45:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf11:0:b0:24a:fdc1:7af4 with SMTP id c17-20020a2ebf11000000b0024afdc17af4ls2132907ljr.1.gmail;
 Tue, 26 Apr 2022 09:45:16 -0700 (PDT)
X-Received: by 2002:a05:651c:1988:b0:24d:b60b:c20d with SMTP id bx8-20020a05651c198800b0024db60bc20dmr14886215ljb.410.1650991516064;
        Tue, 26 Apr 2022 09:45:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991516; cv=none;
        d=google.com; s=arc-20160816;
        b=oKw6bIOo4uru8deXEGuXbBkvn/3hcWMBgTJymYdpCZh1ztMGpVdM2dlv4YUSM8BdpT
         RtXc/JAQTVUkOztL5r6mVApeBXsCDoO2aiy6xGC0InQVUQFG7AnLHBvThGr59dqXDCEV
         inmq087TmDCbRAHqVC94T1699R5H450aAKPqd8NWYuN/D1iSi9D3qmAVxEkSFYBQd9eU
         xBaRjBv+aYf/9Qn6yY6dYDQUYDtn72ps9a397FDdHTaiuX0YBsC32ABhsNkmy/MBXk0z
         7FHGLD27XBF2Joiy5Y50Bk2oPstqsheP+RoUgJyOwPOs/6V0ZVkB/bEJujSu/1wzhTmK
         yGjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=vFqZ9iNZJAVQIjd7MnY5jhYV4PJ/+WpYoNR2VRSWpiM=;
        b=k508mLBO0/0O8dIxnRNtz8Zc4K7fgBU1ZWD6TB6nsp8eaUSJDEW4Vg/r7JS8dYszKT
         rGbuAlGQtshN3T3sEJOI4qn1cAlwNcQmCszbJTVVpNwNPO4n5tkMzQEZBv+18SJvOOxi
         T+v8AKNR5U9/LqjGM4yJ4DzKXszjVhi04I576xdTG3g0913dZ3G/pTIZWqRxC79zsX+m
         +yEOKOmBj9L4wqGgKSRtyhpjVSUflag7/yh/kg7pfbknI5Vk8lUs+S7GVWkyjpYtDvMB
         x4/5Fc2KKqPbeqacUzj0MFEp1xoz+PqXz9vt8Lt81vltVjZUk4tjNqljNa0R9il10OZm
         tplA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="eaD4tCJ/";
       spf=pass (google.com: domain of 3myfoygykczg8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3myFoYgYKCZg8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id bx6-20020a05651c198600b0024d9eb39428si780292ljb.7.2022.04.26.09.45.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3myfoygykczg8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id x2-20020a1709065ac200b006d9b316257fso9386773ejs.12
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:15 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a17:906:3e05:b0:6f3:a14a:fd3f with SMTP id
 k5-20020a1709063e0500b006f3a14afd3fmr7558438eji.640.1650991515225; Tue, 26
 Apr 2022 09:45:15 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:50 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-22-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 21/46] kmsan: unpoison @tlb in arch_tlb_gather_mmu()
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
 header.i=@google.com header.s=20210112 header.b="eaD4tCJ/";       spf=pass
 (google.com: domain of 3myfoygykczg8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3myFoYgYKCZg8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
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
index afb7185ffdc45..2f3821268b311 100644
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
@@ -253,6 +254,15 @@ void tlb_flush_mmu(struct mmu_gather *tlb)
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-22-glider%40google.com.
