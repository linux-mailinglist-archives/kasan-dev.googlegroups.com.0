Return-Path: <kasan-dev+bncBC6OLHHDVUOBBI66ZD4QKGQE6BENZHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0289424160A
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 07:39:48 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id 3sf885577vsx.13
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 22:39:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597124387; cv=pass;
        d=google.com; s=arc-20160816;
        b=VuA8DzTrZ8NgUIFyGd4XPGy1mlezWQMsdqfuYAztY74tru1jRGTYnoEOporPJaNh+e
         /AKgN7TjsEkRg5pTyWV5E8fC+5+/uJEi9vRT5ynl7Y8WBVb/XhbiCRXkg3Jwju1xhGd5
         L33FEZU4DBzKRNFUo1F8OFzKS3EXCyUk6QAA/ym5CByFnjTfmZ4W74WTyFXz6R0CDMLU
         y0pNl/3GcAsDjhP4YPCMcyEyvlN6v4OP1tlmSy/l0hRISx0xLeoi0+fSaOQNn4D3OYl5
         jWXTNIBzZ1cmJz0IxQAt5ubRmS5AWQGaVpwlXZkXLuO5TB+F6G/8kYykaQNM4M+Yznde
         7vdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=6Vs7lpyV6VsmD6HusSBDSMFgqJcsYg6bTGUEU72KkvE=;
        b=JMj+ycdmc9A9XjYhZGS8um8N/QXLdHdVhFlJsm6995OIkcScL8WfW83ZJ0uPX74lnb
         18y9qrLOXYpQeDw+HeYoQlwSx/aBeDFpI85uJSEvhvCwW2hZtj30J3RVLKxaDCNFq75Y
         3yz6TinXK5VQ7mS0A7U/16HrFlZ8hgLyboWaySyhIObSoJ7xVSwFdq/Hv58f3nL6JTBn
         8Yg67UxgsOp44r4D4OHpXZyiRq7Ty8jLzEiJn9Slun0//2kywkwVTN3z/nXVqZLe8iwV
         IgbDztgPdu0TRkW3QORB3t9NNo/oT8CjY9a6SwoL918BWqQU1JebR1Eg1iQ1fvf8BdJm
         SivQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tHAO4iJN;
       spf=pass (google.com: domain of 3ii8yxwgkcukol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Ii8yXwgKCUkol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6Vs7lpyV6VsmD6HusSBDSMFgqJcsYg6bTGUEU72KkvE=;
        b=FU8MS7Bh1YdspozSVDnCj3L55Sf8oJEa5kbIU9ehKZSAiK1u3CROOwTOdgJd1EnQZK
         SSI54MPsEQUTIukozs8ybUyC4r8fZnLhXCHy5ko6xI7FVYy6U2o8E+l/dy5IXTbafFZ8
         hewgfMEuXAEhp8GEQ0wlHwod+eQpSk0BTocL/znWgR7YBp3ZxTg1Bo2hnbjz0jD+B74B
         V5dKHplYN+ReeBnIHnf3G4Dcp2IFPQSWmSmDrB6PM2+thE4AXW9DbXhPWLR3IcaLnnvW
         URMhcz3LDX8YR1VRRIvl/8+YiSYQRejlUc+Sry8YfFOnV8b7LjTI+rAqtf5bP+t1CDZR
         C6gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6Vs7lpyV6VsmD6HusSBDSMFgqJcsYg6bTGUEU72KkvE=;
        b=pvQG1KBwyE9XP0WBQXJZBu2waD9J+Ly6nGvZWMBazj07mWRzbqR8WpYRxzNsyGHvZj
         BWWwhqAwBiLu0blvCv31LmxFjxx1oGOfvA0UoIoi6f71shKZJpnLwiHBDLGJ65XoL3OF
         +sYKrT2166sNSHwyvmDr8yaXME3AE7ED8i6rdwsBTrEFdEqr5mXuo4pOinrE/OS8dEps
         tXLhxGV5c8p2Rx600xFoQdfb+PAVr8Fzx2YwzcP0n9KwLbFUuCbSEtDy7tCHhC1nP/Xq
         xAIR5zJgJaKxbPoUXiHKjRp1EjdqArTjrWXWF1yV/q/WvcZtxUse+7KiwXZIxcmwuq01
         23gA==
X-Gm-Message-State: AOAM531oo39c/Xer2schIc3f5bLl8sYuSrPn21LscIqrXp2nd4YHJHZ9
	u1lt2+AFZCoh6bPMSJ/ASw0=
X-Google-Smtp-Source: ABdhPJxFXiwGI8cZvqliTMxpfG7+96EWI6IEFoaLEm63eBNf67571wjzeyAm5r6s+KpWvSDhMmV1xA==
X-Received: by 2002:ab0:1002:: with SMTP id f2mr21848126uab.39.1597124387080;
        Mon, 10 Aug 2020 22:39:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fc0c:: with SMTP id o12ls1773598vsq.9.gmail; Mon, 10 Aug
 2020 22:39:46 -0700 (PDT)
X-Received: by 2002:a67:7782:: with SMTP id s124mr22840579vsc.112.1597124386687;
        Mon, 10 Aug 2020 22:39:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597124386; cv=none;
        d=google.com; s=arc-20160816;
        b=KWUAZP1KSNTuJwIx6j4E+wU+V3S73z+d/3Zd8zGGgg9nOu798hR3wFPoU75OAENeXW
         gHi/5Y+GYgy4wvWT9VDdP7i0Cgz/m7KU1BYZjLX9/Df5jxwNUsnKFZum1JaqSU72b5ri
         COAvwhFSbkSTkz4UyV3p639fpB01xC9CZiSA9OvAv8Nyt31dl/18sCBMjW0P8ljkrvBX
         kSNKg95kN5j/RhQVtLbD1Qy5I4AfkXGh1vxu83c+ROsepDD95QRNFX/TxyJpd4Zw+a3f
         OMcBuEctb4yKh3Z0PEaqY3E8kQV7ym7UQEKxS5n0RTIVXBHjmmC62+g3aESKO+lD+qB6
         mlBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=z+/W2Lb1k0h/CCYiwDe5JijUnwa2JcEcWzU8gpWcUfw=;
        b=mQNmhZnRTVDdTGuVal74g4xaM9+eMoiy7BdmKz+Dh9jzVzeNw0wa1dHtmZzYBWCJOp
         PDm8w/C5MMwVhBg45RH2Wa2AGqXTQpA0eDUMaTTSEAUMjVCpRPujpONDFUOTIJPv3tXI
         O4iewLrH2vlj7Nt0Ae0TQns/ZB8KXUP2ZUP9Hqbg161rs7tQiknjbNrkfXYX+q1hu7+A
         O8RpT3+Yhzvn+93yM+CsWDDgwnEYWImCrU8uO1z/cSviO9rDlu/0fUAG7ApH/o+1vx2u
         Cx5pQfCoMrQXs8GpmPpEu2QCv/N7G524AqQpUMKCu1rvmcjTjchJQ8FaeUweRA4bfOEv
         fpSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tHAO4iJN;
       spf=pass (google.com: domain of 3ii8yxwgkcukol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Ii8yXwgKCUkol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id p197si1318935vkp.0.2020.08.10.22.39.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 22:39:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ii8yxwgkcukol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id y9so14357569ybp.8
        for <kasan-dev@googlegroups.com>; Mon, 10 Aug 2020 22:39:46 -0700 (PDT)
X-Received: by 2002:a5b:308:: with SMTP id j8mr41696962ybp.185.1597124386219;
 Mon, 10 Aug 2020 22:39:46 -0700 (PDT)
Date: Mon, 10 Aug 2020 22:39:15 -0700
In-Reply-To: <20200811053914.652710-1-davidgow@google.com>
Message-Id: <20200811053914.652710-7-davidgow@google.com>
Mime-Version: 1.0
References: <20200811053914.652710-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.236.gb10cc79966-goog
Subject: [PATCH v12 6/6] mm: kasan: Do not panic if both panic_on_warn and
 kasan_multishot set
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org, akpm@linux-foundation.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tHAO4iJN;       spf=pass
 (google.com: domain of 3ii8yxwgkcukol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Ii8yXwgKCUkol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

KASAN errors will currently trigger a panic when panic_on_warn is set.
This renders kasan_multishot useless, as further KASAN errors won't be
reported if the kernel has already paniced. By making kasan_multishot
disable this behaviour for KASAN errors, we can still have the benefits
of panic_on_warn for non-KASAN warnings, yet be able to use
kasan_multishot.

This is particularly important when running KASAN tests, which need to
trigger multiple KASAN errors: previously these would panic the system
if panic_on_warn was set, now they can run (and will panic the system
should non-KASAN warnings show up).

Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e2c14b10bc81..00a53f1355ae 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -95,7 +95,7 @@ static void end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn) {
+	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) {
 		/*
 		 * This thread may hit another WARN() in the panic path.
 		 * Resetting this prevents additional WARN() from panicking the
-- 
2.28.0.236.gb10cc79966-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200811053914.652710-7-davidgow%40google.com.
