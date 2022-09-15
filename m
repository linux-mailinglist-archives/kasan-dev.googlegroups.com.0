Return-Path: <kasan-dev+bncBCCMH5WKTMGRBK76RSMQMGQEKWWFXOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id EABE55B9E0A
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:15 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id y15-20020a1c4b0f000000b003b47578405asf5580783wma.5
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254315; cv=pass;
        d=google.com; s=arc-20160816;
        b=GzsF6rNMyE6VlskQJF8QYys+msmh7ZPzlQmzNyBL9Q6u2mt9P+a1v7LPuUUDVX/V5v
         HFYpVY1qojDFag/n+I/3WFwWE7QEsaltWcuJYYcSnQNLGBB2tcxNpgV9CkRIu78Xrb5B
         mdKOcQr597mDWXMrlvdQh2CxnMsEEmOMMh+C2hY5e4X4Aw4ooid+N2I+8ryakper7tM1
         3XEg8usqhnu1Fr4J3a+rFf8HQghOASFoUVmN6Hx2nDPImd/QeIdkwk7NEjo5whKwKJBT
         M2SXb0BL6/u2OBImHqhpIdKSgumpDOHyx4W8ACHmWPqvhEcfVnWciAK12KewfwThRzgY
         i5aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=0lfjatTREDc6axfGseBto8vIJAxJVTFWCLGn82ARu1Q=;
        b=qsoIJj8cvM1m/eJzd/YkBTI6nZ2q8dn2OI7IV5fR9fgRmnFsmkXTM0RvQr8DvRH80m
         2jKgfdg5luwbcgaGILCXhRU3+kwfkT0Jrt5IpB6DxImqVIlJITdSKuftsNwkBY1V8UXh
         wy//KYjfK+WaKxm5gPJSnIuWnauuZsVWx6mrb4XkBAIQAHblnS4dIz3nvH+V0Nw365u5
         Z3Z/lNjorvSrnlVkzITQvaP/PjZTmT85CMA5Pj3ErA9Dfx1JywSqA2wrhmyBQt3Kts6R
         xe9AolemCTcBR2LG0NU8l9vS1IlX7mxQwm94uC7MVqRfJBKA9Fr6x7u9EXQi1+Xt/9wU
         wo7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pMDlMog1;
       spf=pass (google.com: domain of 3kj8jywykcvu38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Kj8jYwYKCVU38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=0lfjatTREDc6axfGseBto8vIJAxJVTFWCLGn82ARu1Q=;
        b=t7+0ZIf3p+OOJg6/bXJaI5tAKW86DL1J1vAQWAk+hzFJGMambFT7KT2pWwBA6lfzT2
         Bkrkf3aBjH/2XSwY+LWU6Y1LpNT30RTq+2f+LIzyZScPO1mIBSE2SlIADBH+WAU536+s
         kPrutCh1xrMxbx2r/MsSnI5xCuGyehFQzGsVB+zRhog+rcJWf/CBCJ84BOTUQ10sG6Ns
         +SpObfj7Szs1UeL3FztZhvYERawlv2gJs6rUVPbjhlh0v/vU0SOah7dP7sDpCZGI0M8i
         8ljEKtlaQ0aGX1QES8THApeX4y63N84mS9MZpHLDbQNtf3TvoqYXjkqFpwA+w1XBBVOs
         y+MA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=0lfjatTREDc6axfGseBto8vIJAxJVTFWCLGn82ARu1Q=;
        b=hQxmlmUKfFfCLV9o+/9PmbPUrE49Njt7SIoIH+t8GZDcpxoKuxAGoYCPu3NiEh7844
         AKiUH9qeVvPEHpusejh4JIO+ZCW61T/1yKAJrh6pmRyQbKnIXLF8k3MDMoSVmcuIlW+i
         NTDsCCdr3mHZVLfnSX2piL96Z8UzMSMRV7KsAXDbTSqpM8m+gycfWpV/fb9LaoEjYn9K
         ETyLcVO37cnYq0BpU29z0jKPX3eePRTH97Q7TMwvavVV2zoBazrjJkqeLBGX8moctzdI
         1Jedv+ElB7VVQ20OAet/Xes0XKlmdONC1ppIUexHleEZroM1+QFbmu8VJLPogE+VPoKs
         uaYA==
X-Gm-Message-State: ACrzQf05zxdqf6cBQ57RDfBxfHdSFAgI62uvc61XfszEM3NAKR0Piwz1
	TTD8bjVsYAM+DV9aueGLnkI=
X-Google-Smtp-Source: AMsMyM4YcL5i++T45ZhIVQZ5AHNTiYShGUjrwTrjzp8mlWZOjM7gHMWmUDlLQ+5FSikZy2ECped1vw==
X-Received: by 2002:adf:eb10:0:b0:225:70d5:e994 with SMTP id s16-20020adfeb10000000b0022570d5e994mr49777wrn.425.1663254315649;
        Thu, 15 Sep 2022 08:05:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6187:0:b0:228:c8fc:9de8 with SMTP id j7-20020a5d6187000000b00228c8fc9de8ls3197813wru.1.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:05:14 -0700 (PDT)
X-Received: by 2002:adf:fe06:0:b0:228:db6f:41ae with SMTP id n6-20020adffe06000000b00228db6f41aemr48078wrr.577.1663254314668;
        Thu, 15 Sep 2022 08:05:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254314; cv=none;
        d=google.com; s=arc-20160816;
        b=AuXpSDQeQdRF2xy2QACe5AcV0SvHQYUP6IiyAyirvaeZEj7Vy7ZEp782iDfYU+HZaS
         lIAFfeS0hLzD8yuwNcDI5PIO7Sm3Dv1CX0Af05POfTFb8pltVRMk4667AOpyaWEfL8df
         NLdrR95MzCPW7Y+DpYSdaEZLVU1geLEUXRk5Q7kRgiLVPaPjkk/7cs1LepWqs5778v6B
         dYEN4TqGyf9dl80WxMcxc7LW5Dlux6xRsk29y/lfBKqWsBNQ7EAbfUSh1aY49UZFx+Z4
         cfoL8y2mhObjZTQo8u2KNn1DapemSO1xQK9EwzV/aH17WEfEl36uqK4E/reWja1+NW3d
         p6qA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DrXJVgAnGikXdoBfgSCi3xOinuzD72ruDjEjRoFoD7o=;
        b=K7maU8610voI312BYmpT9cLxIWhiuit4F3UOz5fm8zafQLrcmzkjsTPn4JRCVLnv3F
         V14WQv5AHQQm5hx65AwNRZpVbKX+uAi+ESgGD1C1S5yGyoNIKNWLZv4q8R6WRUllvSY/
         DHPL1XxLtE2osmJc4U7ymr3ZvQUPT6OoPsppgYUuOau+rCeIJyWyNxQTYarIjmsdYHGP
         2oElP8IXhvC4DANgerVMmSkzpq/B9xSf8e9ONDFpry1/BrvlYuiujiFAhZvf80pcc83w
         IRwW1kCWU0w6RCO1jUKpXenCem4S30EQeg+FpCh4ANkk48+GHEF2rOJRwls7GVlgYDfD
         C5aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pMDlMog1;
       spf=pass (google.com: domain of 3kj8jywykcvu38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Kj8jYwYKCVU38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id n24-20020a7bcbd8000000b003a5ce2af2c7si77168wmi.1.2022.09.15.08.05.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kj8jywykcvu38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id z9-20020a05640235c900b0044f0575e9ddso13210233edc.1
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:14 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:907:7f1c:b0:77d:248:c1c3 with SMTP id
 qf28-20020a1709077f1c00b0077d0248c1c3mr291412ejc.416.1663254314212; Thu, 15
 Sep 2022 08:05:14 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:47 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-14-glider@google.com>
Subject: [PATCH v7 13/43] MAINTAINERS: add entry for KMSAN
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
 header.i=@google.com header.s=20210112 header.b=pMDlMog1;       spf=pass
 (google.com: domain of 3kj8jywykcvu38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Kj8jYwYKCVU38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
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
index 936490dcc97b6..517e71ea02156 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -11373,6 +11373,19 @@ F:	kernel/kmod.c
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-14-glider%40google.com.
