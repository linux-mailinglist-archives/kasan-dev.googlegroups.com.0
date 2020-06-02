Return-Path: <kasan-dev+bncBCV5TUXXRUIBBPE33L3AKGQEMBAHQJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E5811EC102
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 19:34:53 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id d63sf1007758oig.18
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 10:34:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591119292; cv=pass;
        d=google.com; s=arc-20160816;
        b=beOO8fnAQzno5n+sr0bFkKKLq1dUJqeUSjrXmksVIXVLY8D6deAWuYGMWCS3uMNowv
         xzKvJRodloKglmW89dYbFfRv0jT+4pXbFl4NRjlSbC5EJ+6nLMIAHBQnac7TlxeARLmy
         muW2iGs+XN0cVuczyPUPuCrfPCK+p2xRwoWJnjht8td8zeq9NpeZMxa2/GlINSP9ygQV
         rqXKa8fFUCENlQnzekE+WmLph72Uhlq5mG2+KVqC4v0mNnraBY0LEWewVKpdR/xHPC+G
         yEIX4rQvEraBefi0jHQc5NpEF1e79aePnL5Q4Q90BeW5ZdRAinqKZLGU2fY6TKrAyB/s
         EqvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=zXy3wuFbIk++EgCuch3HNd0/U1NLzL42sEa3+ecWREQ=;
        b=uztACjaFCXCJzPnGoqDiB1fyNOCVLp0FA3xRcCk2FBv5FFrhIUn4/KOfTPLIZ6KcPC
         pV7jxqnq+nSLDjJITbnXKmsTRz8MvD60szLCYP+1uyS1xlTNynM1AyX/bGIRBf4L9mDC
         4qkER3rH9PaA0qloMeeldfJpd/OK90oatoh6Nh/6/m/3sVdaxwyGekK+WH0b4ppcgMkJ
         fK+MS3rpRps0UiKU1aVyuVx4SYZL0fWKYrkEVURS6ETlIDKMfip3V3+VrFJnTYGwxp8c
         AIPahY+gyn1OJo1ybxcMYWAvnxhIa2iGOHMN87HG4oPXo2WLdKcXCLVR+CS06pDpPKWZ
         f/rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=temperror (dns failure for signature) header.i=@infradead.org header.s=bombadil.20170209 header.b=m6Don+I+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zXy3wuFbIk++EgCuch3HNd0/U1NLzL42sEa3+ecWREQ=;
        b=pAUk7l5VRV8H5xlPEqqidOrwv5qICjReu78eUcomoA/w8pkUso/nIPNxDPQ5TkPUAS
         f8mdGTrBx5U1uYDjwQSUXu2whtM9NgSDT0pY/8b7UCZ19o5ZIJ43C7xOtvWZNsX3BLFY
         secns40ZFKrOljLyocOSEdSjeVBuVqw3N9x/iY4qwm896b1nnpKHTQ4SxoK73WXXshOT
         icOxBNiNNKg9KPEMV8XuDquoXzocKWESMOo1s+by7iW0r+5oSusZlLQsHe5ivJ7qmFX6
         0DJTawOAZbWTPStzy6LxK/tkaolyf2otwV9nw+PTWqF58RVa0NitJp6Pwe6XjVbkrik4
         mUdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zXy3wuFbIk++EgCuch3HNd0/U1NLzL42sEa3+ecWREQ=;
        b=Y8NxYCP8r05oHqYM86FM8zBo3YgI5LAzZrWfWVZ8P7zwhTESVae/2wWVxhq2BVLcna
         xdJ0UVZK2ojQLNfx2mS2siqbBstHs+s+zZ9Uuu0tjV+7LsVpUoHPnzrXpcA6RDO9ba8K
         BSoKBX3rscVjmhNSkB3Mc3BH10PaSUZpTU4wqw31HRMTFJ9y6T96VCuzNXUEAM7f2SB3
         XYi02RRLW0+XXyW0EM7dOuF8GzAF7U+9Rt0i9yDee9LkhqO3L1sEEufrhbyK0B+NRSZc
         iG2orpWJfuvH6hSPkdnMv12MGddEJ/PEHr8MVkdp9AM5NR2aaZZGj0Em5nUGxRMr3EFT
         +D2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5301krP4Swc5ZTbmAU/eHlm1I76ATYzNOvLZIWq5vR9P6i161dxZ
	78j1aN7xn5AdHagyXG2kYrE=
X-Google-Smtp-Source: ABdhPJyWETCcv7JT0SDq5kJGj3tAyy2hDTplJtKt7YL2SuaMyXgFjzp+kI1KYaeVV1wof8m+0yBtWQ==
X-Received: by 2002:aca:be41:: with SMTP id o62mr3766514oif.133.1591119292528;
        Tue, 02 Jun 2020 10:34:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6a1a:: with SMTP id g26ls3903946otn.0.gmail; Tue, 02 Jun
 2020 10:34:52 -0700 (PDT)
X-Received: by 2002:a05:6830:1e74:: with SMTP id m20mr293993otr.370.1591119292174;
        Tue, 02 Jun 2020 10:34:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591119292; cv=none;
        d=google.com; s=arc-20160816;
        b=f+YPyBHHc8CtUesWxb95S186HoPrpPymn8cdQfyIf1Sx6oec4vQyKg4MDEfeinjVkD
         UBQyG/4OvwOVtjJkTDk+cDaxZ33UVgHzkhO5uaNuraGs6hqSWh9L2OTw3HYVNG4l0kMu
         R0UOVQl2kq1aXGtHfaxHlmip+TFwtwWJUlYQTnhpyp9kzQSJAdsglfxuVSw50jblmQF0
         nvDyWZfSyChdmXxXvJDuNiojv9JuZIrf/L6KbDYIzVQehNTwKdvgp0LcbnaAswLO6pho
         /hnNUzFpyYPsrYfKLi0rCEuuuMWbquinuxHbDpzqjGfAcNEpQDMnVjGlzhT/o2hpiEiN
         g2fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=4xLbMzeVbeH3u0A7zApTQ56UOcpBzDKP0lu5oB5vj54=;
        b=TlliSVKhSzaFGHgCM3dqVJRViLWQKGmsFyJZojDltSpQ3JMXAAFfOvOazF9OPIwfeo
         CggLvq0yFNV07xb8bRQjyr97NMB1aheoeraX6FaatPEylKnLbhQBr8eYoXNlPfNwTwhV
         GhNu63DKXoZtvzd7x9U4dXUgDwnzHN9nH9KOkjuZFgFY/n+DEcYN+8ejjoruORJnPrdy
         /Vn5DGzK4KVov/MKQMBWQUgkbzwT4sCNTQWERE6HMvgQj6EgSL8ao7ijnvlY/sqDfZCZ
         uSOITX37o/du7TqlYeCzNd0iUQlNsp00q2AQywfEOnLwRq9+hig7iAXnJmFQV5my+l+l
         iTTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=temperror (dns failure for signature) header.i=@infradead.org header.s=bombadil.20170209 header.b=m6Don+I+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id e23si414011oti.4.2020.06.02.10.34.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Jun 2020 10:34:43 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgAoC-0007Aq-7S; Tue, 02 Jun 2020 17:34:40 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2D287302753;
	Tue,  2 Jun 2020 19:34:38 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 053AD202436F2; Tue,  2 Jun 2020 19:34:37 +0200 (CEST)
Message-ID: <20200602173348.343967487@infradead.org>
User-Agent: quilt/0.66
Date: Tue, 02 Jun 2020 19:31:04 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org
Subject: [PATCH 1/3] x86, kcsan: Remove __no_kcsan_or_inline usage
References: <20200602173103.931412766@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=temperror
 (dns failure for signature) header.i=@infradead.org header.s=bombadil.20170209
 header.b=m6Don+I+;       spf=pass (google.com: best guess record for domain
 of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

Now that KCSAN relies on -tsan-distinguish-volatile we no longer need
the annotation for constant_test_bit(). Remove it.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/include/asm/bitops.h |    6 +-----
 1 file changed, 1 insertion(+), 5 deletions(-)

--- a/arch/x86/include/asm/bitops.h
+++ b/arch/x86/include/asm/bitops.h
@@ -201,12 +201,8 @@ arch_test_and_change_bit(long nr, volati
 	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btc), *addr, c, "Ir", nr);
 }
 
-static __no_kcsan_or_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
+static __always_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
 {
-	/*
-	 * Because this is a plain access, we need to disable KCSAN here to
-	 * avoid double instrumentation via instrumented bitops.
-	 */
 	return ((1UL << (nr & (BITS_PER_LONG-1))) &
 		(addr[nr >> _BITOPS_LONG_SHIFT])) != 0;
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602173348.343967487%40infradead.org.
