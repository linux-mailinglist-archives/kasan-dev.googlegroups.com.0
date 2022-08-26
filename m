Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAWEUOMAMGQEWJL6S6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E74C15A2A67
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:50 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id g23-20020ac25397000000b00492e52a1dadsf292029lfh.21
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526530; cv=pass;
        d=google.com; s=arc-20160816;
        b=ELo2P3RvVYjdtYtd0lRWv4vmWAgXkkvm76xKjLDc/lcBz2nPrpiYfXlAN1GqKgZB3B
         uO9CGgXfEauDDovrcrEWFJBk52AZpXihjBv1arxyHcIo+DNL4JnOUdprz24VZh57i1cv
         Im9DZjYxOfRL1Apw1c3nKZj6XflIoynHtNUp5DPMfvYvQPjj6oPqDr7GyReyDTQ0h6Xh
         lOIPo5wvKMKfgotOiDzgoXRX/hkYYdmqvMKeUzj5RC7bl6Ctb+sLSGAHSmzkHmFRD8el
         iEcPWrHJR01inWpoAk/oBWy8JQe2rhshxIxF2JvJYb5oOXj5x9cM/SFF6deUx0yxvdQY
         S6gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=16wDsFyM8yh1vWb5eFJtjUtifLg4Q3A97QZLP8T7wis=;
        b=HpS0LBe6N67Ri3s5QhGL0qm2qpEWfQ/RAuLfNQltCnpQ80qSINfZDiYytYYFQVSStq
         T4rA+TB9LsywbO5XMPE1gnC5kgkG3HzSqAcpYd1OxUe1uWONZCb9Y5G6eli20B3sa5GQ
         swSCw4BeQrdE0XEjat5ycV4S6L1gePtGYziw5INWDcP45L6IW4b5dMwt8JWeHruPDFAp
         4nlbVa+JdR43BVKEWmeGftuBSqdp8RsZgOt6A0BdBDq4juxVqLJViVAJPmEvMdjcx7e8
         zhS79AGQMbvuz70caSPqb935XZrwEQYxYte3TCiMNbDejm4zHzKfSYc+KRI4giHxR9Uk
         EsqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YJO4Xg0+;
       spf=pass (google.com: domain of 3aoiiywykcqcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3AOIIYwYKCQcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=16wDsFyM8yh1vWb5eFJtjUtifLg4Q3A97QZLP8T7wis=;
        b=gfvFNEe0lrkrRg/XQ9tcwi4I3Zu3yJlQJPX1n73jqV/iZoigtlcshgidePzFS38/5K
         ZRbCNoFIio3Hfz3mV50FVHP3/oreZE8Ifr4GtTQbGXlpYq/niKfLz0xuJxoc7D2mH+Hs
         JK3kOASxBZsk7zORMNI7rlJCEot5DZcrxnWSEXZKVKSw4YiHZWrf0MY/pD1O3OpaI67i
         6ov1NAK7p0GPSQyqFcP8Cwr6nunhVlUAZAykrcSDwdvPVQgzg2BUFSxE2FYyGRoEpoO2
         gg1hSzZ05FgGyaBrAHzxRVTzp0bYJ+vL2J1o9GMrZwA/9yMB81SxQtTODKlzL70rMkws
         iMpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=16wDsFyM8yh1vWb5eFJtjUtifLg4Q3A97QZLP8T7wis=;
        b=lv83qTdluhcd1tgzLVoC8ZxBPYY6tyUXoCUzwQXQ0vOcAjSPe0jtYCIy+X7Tr9TWNN
         2/V3UUYnFsUpbaWxTLhmF+9rut12sJFQn26cBIIEbYOFEfNhUm5309rO0syBOg6RPORp
         mLUcSz3srH+BFS5Q/3GHsA3Am0Wo8tEwoXwjnbdfi7Xmidwmz7DKknQxLxSCHwPfyPN5
         /FzH3g3268UkloA9LEwWo/icRjp7FwMgh+yM0jSvstnE6+4eN55bu4ebNAJTxg7BPAl0
         jOPW5TcncVTIWvjc2HlfLWA02mVFCSJD+paTr+o1tmFqszcVdmYZ7lQ7iQGygkNy/6VW
         nLaw==
X-Gm-Message-State: ACgBeo1Qpe/W6gVlvyU1S7k4GLte4Q/oiytP0x5qtz5SVCRoDXo4HlPu
	Ldnabhhpku0UfPuZqGd8MaI=
X-Google-Smtp-Source: AA6agR4Vx+XLb2tNr/EScUqdCoxl2F0z/oOA28ONzeWVFCu5Oblij1gV/yyltcqdY5L24oyWETDXFw==
X-Received: by 2002:a2e:9d0a:0:b0:261:85c6:efa8 with SMTP id t10-20020a2e9d0a000000b0026185c6efa8mr2697455lji.477.1661526530462;
        Fri, 26 Aug 2022 08:08:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3588:b0:48b:3a68:3b0 with SMTP id
 m8-20020a056512358800b0048b3a6803b0ls1138921lfr.0.-pod-prod-gmail; Fri, 26
 Aug 2022 08:08:49 -0700 (PDT)
X-Received: by 2002:a05:6512:33c5:b0:48b:9c2f:938a with SMTP id d5-20020a05651233c500b0048b9c2f938amr2712687lfg.557.1661526529340;
        Fri, 26 Aug 2022 08:08:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526529; cv=none;
        d=google.com; s=arc-20160816;
        b=r3JRApzkNsgiZqbmWoXGA8Bhjf2QJ+LicFw3AZPmQZmnMWeEyakPKCO08maM+y7vjL
         VZeWo+M4BD0VkjeVt2zfnvv3ifAtFV4YspXi/hi71q1ml1KbvXWc54ZS3KM0lpyxpQ/M
         QvFto890CoAmIctZ416oQjewIQiQyuMWuFkR+JsDL7N/g1jkKbPd6NI4w5cyJ+MMVW2x
         QNBHeUflfHOsR22B5EFdQttGlS08W403GsecaI8xUOtvYSq9EAYuXtyAVVHvxFswBe15
         TkxuHBmvysQTH7UrNVzOvE6SRLiAiQfUU7sG4DTSdxOf3kjFoicPRZDzVfVv53pknCwO
         4g4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=PmohPhKomZXd1zOAWK/EQjp0UhZ3tSbnWnyq8ud/fAU=;
        b=vxFK9r1njT2xtPJg/Akkzf0f3sEf+1XC/Ex3v7xdtXKQ93DQ05+6ESlpiNcz5D7H4l
         vWlNguBPGFabL1erKv5k0Evyrh4Jf0h/yfLRJ60AdDfQv8/Ipp7/NhpMZgJO2s4jnPZX
         +4YPWAXIlDXAewsXrP6HHSwhD7xI3OuLbdqs/lgMklyjetxohtTm75cxjIad9uoLfTV8
         tyqV1HQPqLMOSzY1EsrpCcgziHzo2sXJhmYWqIZO+ahqDMw5oZ79bVhoJ4LyAi5yDfDB
         7Zqh2a+lCYsEVbhsm+yT2qT5gFIPXZwnjJ0o8bfoH/28NJ96WPn8hN2uZaOpxItx2J3n
         b7aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YJO4Xg0+;
       spf=pass (google.com: domain of 3aoiiywykcqcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3AOIIYwYKCQcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id n23-20020a05651203f700b0048b2a291222si62514lfq.6.2022.08.26.08.08.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3aoiiywykcqcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id y11-20020a056402270b00b00446a7e4f1bcso1254329edd.1
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:49 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:907:2cd0:b0:73d:d80c:b51f with SMTP id
 hg16-20020a1709072cd000b0073dd80cb51fmr4282876ejc.619.1661526528970; Fri, 26
 Aug 2022 08:08:48 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:36 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-14-glider@google.com>
Subject: [PATCH v5 13/44] MAINTAINERS: add entry for KMSAN
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
 header.i=@google.com header.s=20210112 header.b=YJO4Xg0+;       spf=pass
 (google.com: domain of 3aoiiywykcqcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3AOIIYwYKCQcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
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

v5:
 -- add arch/*/include/asm/kmsan.h

Link: https://linux-review.googlesource.com/id/Ic5836c2bceb6b63f71a60d3327d18af3aa3dab77
---
 MAINTAINERS | 13 +++++++++++++
 1 file changed, 13 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 9d7f64dc0efe8..3bae9c4c2b73d 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -11369,6 +11369,19 @@ F:	kernel/kmod.c
 F:	lib/test_kmod.c
 F:	tools/testing/selftests/kmod/
 
+KMSAN
+M:	Alexander Potapenko <glider@google.com>
+R:	Marco Elver <elver@google.com>
+R:	Dmitry Vyukov <dvyukov@google.com>
+L:	kasan-dev@googlegroups.com
+S:	Maintained
+F:	Documentation/dev-tools/kmsan.rst
+F:	arch/*/include/asm/kmsan.h
+F:	include/linux/kmsan*.h
+F:	lib/Kconfig.kmsan
+F:	mm/kmsan/
+F:	scripts/Makefile.kmsan
+
 KPROBES
 M:	Naveen N. Rao <naveen.n.rao@linux.ibm.com>
 M:	Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-14-glider%40google.com.
