Return-Path: <kasan-dev+bncBCV5TUXXRUIBBCMY4P3AKGQEAG57UFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id DAF131EE25A
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 12:25:13 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id u11sf1822609wmc.7
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591266313; cv=pass;
        d=google.com; s=arc-20160816;
        b=NMfF/747bAY58oD+6dwcH4jcDwWlKMpGKNSCz+rXm+/LpHFVMEQnJP+EwkoOMWC+he
         9tQvPQqlZ7WN9Ae9I7WDnqhvpJqfyiSDHxn7OxUx570pda0im2ya/ypXKj4B1NAjlW0R
         9bgDsTUqPCk/IFcSs8xEPW1I/OjZEUyvFH2vtE2vzFL/IZ56k3ujCKQCpfcnazMK1cMi
         3kEYOmwivzIipT85t+hZov5B5RyogZHeA1jV5MLi4qwcC1lSU/WGpkbjvZEhaCwTyDZr
         5fpj9ZxzmMcnASJ4N3FYXUOt0hTDByHKeB+7h5dAgvx18Ljy9JSYRoOdiuNBh2gC8+yL
         pRhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=4XBbDZcJQvbJqG/ze2QjSoundu2zVHpilvIcNBbqOa8=;
        b=appf398Lq2CKatmvVWqgaxQBOaXPsjTSDcqiceM07THdJ/ApoA/UZzDruaoAyu9AVg
         piSKTNjQ3eHwUgvlnS92FTwD8Va3/wdDPc5h8W6+0mbu+fg4KaHENDcOh8G1NHRC0oTA
         UZR61EPj6fu4xgjoiz9i2LN4ykNVbZa3o2Zqr/z8EU+LCxcN3MuboiQ3CYa4Abcsr26K
         oSWgdqWy3JDFqhkC9EwItvPfpfPt7dPmpB9NcZQittgQAPDxtwQhtJJJgMg/OSwOUo33
         jf+e0mr/gvMUeYaNiMwrCiytU3wbeVm2WFwqaqNFX+pS0by9SuliU7aeUY7HnIPrYYRz
         4pZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="Z5o/s2Yq";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4XBbDZcJQvbJqG/ze2QjSoundu2zVHpilvIcNBbqOa8=;
        b=azAO2wMHhUIUUcpd1hWKGCRbzFM9zEUy807RK1RKbcHQm8/F0xikhopkp2sbx6SQp3
         fA0SX3mnYM5SlbOrCddaJgwDUtNjECx962NnQLZeFvnKslLaRzFw6KqC/s4kc3OC28H5
         u8dHsM6MlNGIScNT1Zkud20TufnHC61N2k3R8MPfcJ0Vvl8OKPO7JtqAAn281Yg1NCVU
         m0Rr1WWOZ8magquN7mvb4ZzvqbCxaeKznCEWARCm2jA9cjb9YcKgFH0MBA8+30KtD67k
         c+/VnykD9IImbjHD9SbyC3BqT1+ztySg/aZjE7hUOOasoNcoh087NHZsWnfdcgTF41LP
         g6Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4XBbDZcJQvbJqG/ze2QjSoundu2zVHpilvIcNBbqOa8=;
        b=OS+ILxRnCRvu+1m3iBDoDrh7GXrTOrzvelBRU+X6IQhqnhr5DbChInuaXXXol8GOYD
         /CzW3eId7S2+Nzv7fdLrNxWq290bioE8OnTrY9l0U6rX10zBPRPyDMnoJle+WF0/aVfc
         aZzM8LsPyYolJR7Mds+GYwr77U7DgWJbMPWDW5POSNz+OyeG+0m144muopdQ4CTm8qQ1
         dCWofRL8TOl/NQv6V3CbsdXpqItMduYGqT88TT0vi8rCJg6a2zC36OLmQlFxcxSaaUu5
         hGUtziOkMcfngcKbeF4re8Tb2jDJLo3n/6twBhlFrePvbcWWUov/QzgpPCnox6/DNs6D
         shwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531J+bdxYA8DJNSf1JWCA4UNU5xAh/FDbLWpgBZmK/cPm4ei/bR5
	8TjLqiV4qCq0nUqI50RygO0=
X-Google-Smtp-Source: ABdhPJy07QJoI/z1AtmrQ9liWiOlzra8M4msv7FSdNTA7HZ+f6ce/YsjpdPqexAk+X7h/blRPNT/xg==
X-Received: by 2002:a1c:bd86:: with SMTP id n128mr3590180wmf.5.1591266313664;
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e510:: with SMTP id j16ls6182274wrm.2.gmail; Thu, 04 Jun
 2020 03:25:13 -0700 (PDT)
X-Received: by 2002:a5d:46d0:: with SMTP id g16mr4050431wrs.229.1591266313135;
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591266313; cv=none;
        d=google.com; s=arc-20160816;
        b=KGxhjlvisWzaYpIYMcUw/lLMRGckRlY065p4CTl/3hjR1SkXu9vu5kgRtlXsKHnh3y
         hHPymj6DAXwOQcNQqPzmQXwmlwNXROghz0Zrq0Ub8NJHg1LYF8xqOex9oIxKn735Yv2e
         +2w1927VhTGSzsVArfYQ4PsguLS3jPs/6DnC6IAAnD8/bmD24IwGYu2b7aiVHpozZlzc
         hIG/cDiNJZL4i0pCO6aUCaeEg2dZ6QLygzmZE7hr+0PMt6EM56J8E1wSMdrntcgnDgZe
         qSigKAHDriNmU7FwVRypJvw0JGQLeEwx5cMy0zBwBY9jDGLORs0y0WKL75o1Brzi8+Cp
         Nnuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=4xLbMzeVbeH3u0A7zApTQ56UOcpBzDKP0lu5oB5vj54=;
        b=VaP0la7tn6+KlVXIj5XaidVhY/a1ruAMuEQkLa87Hormw9x763wpf75kQSkSsniTMF
         8vqoCOILuqpP1crx7J92SCRzvVJM5M0A0B45r/o9JyV6DsDWiXY0KFMuqqTQtkH328x+
         43mVf2oCbQGbkhQnCFRvcKq5dnnFzA7LXkTloozGyTs/J1Db9Zqi1uzlfdMJ+QSMZtt1
         cOtV+f92nD0I3vSKq5lq97pPB6k0nnb3Bk3/9+kYQy/43N6AW295ssAZ+EXFaPPNHyI6
         qPKG8Ju9WrxQt6b1EJYoGibhOwUsSvKtkElFQLCG/3SHQpyflc9HuQf0JNXHa69KTcsJ
         jSfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="Z5o/s2Yq";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id m20si299632wmc.0.2020.06.04.03.25.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgn3d-0003tZ-4T; Thu, 04 Jun 2020 10:25:09 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id EAF0830280D;
	Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id D64912007CDE8; Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Message-ID: <20200604102427.963062528@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 04 Jun 2020 12:22:42 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com
Subject: [PATCH 1/8] x86, kcsan: Remove __no_kcsan_or_inline usage
References: <20200604102241.466509982@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b="Z5o/s2Yq";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604102427.963062528%40infradead.org.
