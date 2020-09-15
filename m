Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVO6QT5QKGQEO6ZNQ5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id B968C26AF5E
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:10 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id h23sf2034474oof.6
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204629; cv=pass;
        d=google.com; s=arc-20160816;
        b=lVmmmuBsLTI4PFWQ8/Yo+B3nb8qRdWfbZq0wwy+z0uFdrTZHgS/qp8kf9MTOKBvnGb
         ASZevtlxouqrvNx9cCGmnw7VQQfAuOlMQcLa1wbXWDjNNcu1M5omo9uuTU0tPhWA+lhs
         ULn6AYWczVy5+z+Xjp0KMgq6eIi1I+4FYS3mYBF5Ex1ublkWvabP5Tobd2F1LgxfhGzi
         BYIW2xA/pW93k0AYgcLQFCjgscq/Ll1urnUcS00K5Ku911UKfJBb1R87HFGjS/TlMqeB
         ZDb24S1xuT0AX30QyosNbPDqdqaf/4RFlgME9jpvt30h51TRVtfWxzxZ2ckaHp/MKq6N
         RPTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=LLyrKnAgBZBqpaeFWC3Vitk2LUItGfod141GAJDrWPo=;
        b=owawr/AZE8ZmUFs0OzCqFUzJOLcP8dCE59Ypos4xUJ7FnflU+omS50lLDY+8kCcx1W
         uQ8YuTNAHde2ZNsVsYSrn/lYbB20WDL5KDFVibtHTL1TKi6BDgux+mVbiVfC7mI7SMEK
         s92zTh2kp7bnWmzqNv8sMybSDh+cdduVWrIt2YYYDcLoJUm4hybD79N7zojEZms+gEW+
         KI7mBa/fsApabcmEh/7S2o0FVWH1kvbWOICsKPA9LS6U0Y4P9rSMHAPfZkvTXezpi1ek
         NWpgaLdGcNgyP7avC7JZdCU+vgDa7QKF1Y+8a9mcPls2L27BnYgvh4o2cwtl6x5j4ipY
         FqPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ETreXfWq;
       spf=pass (google.com: domain of 3vc9hxwokctkviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3VC9hXwoKCTkViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LLyrKnAgBZBqpaeFWC3Vitk2LUItGfod141GAJDrWPo=;
        b=AS232xrf7TGTCJJ4bnAmMpPTAXcQvJ/1Y2EcMJkUab/OLWKuf5Z7FsVnCP2FL0fPJ3
         JCvIS8mzYSSHTGCgI3qb+6pMEbC3mQP52feR/1GIxxjgqe1CWwoErtK4VyEGf9tEtZXF
         h1pNkYQjPBrWhMv7CqaefLzP7nEYVZo3xJ1cMmxmlkBj6EQcw1Fhi4dslJBS+eRugqpR
         ikZU+jjF+V3k1E/ToB9JqKsVrDHIp2YQgyJcY82o24u5UYbPeo/WwuAzs7HJB+f6XEcr
         IXdT8ZBXAa26rKkTnmjs2pjGSRgST/JeWfk3E8ju/DLmV1LyOQrueGWCggmbOiuIkQ6M
         ct+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LLyrKnAgBZBqpaeFWC3Vitk2LUItGfod141GAJDrWPo=;
        b=UuO2Zths9iyYY/R+hG1aKXRQbC28zCz6vYIwi8Aue0p85qxbuzPPYpEeGwAbEKdgcv
         9Lzj2j0NXbOw2YpuA/SZSWc+AOrdXGOPuh9meZdxzBQ3WeTXnup444OCV5qjJZEagp99
         yJG+18pCUy76+BbcdLytN6M3Zr42ZED2x7SiyiawVmaijw/FhR7r/2DfpAvpn4CfX7ZW
         Z773Qr1ydOaRp4aQmnw2/w/ACkzo0wVqiVAF8iH4ape685Hv4qjEOx/z38EsjjFMV3Il
         d+wmq0q53cQITfSl3VtIDegKQj5Iy51HVwapcLRV7Zlf+TNYbAoQEN7gxjuAKvMSbgNo
         YiXA==
X-Gm-Message-State: AOAM531IbDD9lgpuLENOJITOIEBVD6ZvdGoDlEiCOq1qQQgrEN+kBolM
	95NEbQUtmVV/7wbiicFb7K0=
X-Google-Smtp-Source: ABdhPJxldBKfdBzvjzsZ+fchbD3GHh2tamqC1drYDkKg/2FeHZM7N9TYxiq7Ai7W8t5QNtqXJkapsQ==
X-Received: by 2002:a05:6808:3ac:: with SMTP id n12mr904566oie.73.1600204629573;
        Tue, 15 Sep 2020 14:17:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e547:: with SMTP id s7ls2504oot.11.gmail; Tue, 15 Sep
 2020 14:17:09 -0700 (PDT)
X-Received: by 2002:a4a:1a44:: with SMTP id 65mr15939485oof.30.1600204629264;
        Tue, 15 Sep 2020 14:17:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204629; cv=none;
        d=google.com; s=arc-20160816;
        b=Oq1BPbe3tst0dta2h/ZuUGolVGuU5SHeSWm7oKLxON//vQeQwCP31GBr194wqEp5h/
         MLMS+xeHrjNShoAB/x8UnSRsLNoYeS1JFOwguU5r7HDM5wEabM9j4VyKJBmTLWzbIj7p
         7i8OJ18lt0+9GsWUAIbO3zMxGlOXbob0T95YT+65zLs7d5dcEN0DtPQHS8QurUXyaUZx
         n/HbdkPZRhtw/5ANfWAH+MHdeuciUNZYmvWXJSPxV64nRjARua/+uJCUo4itDKsPvs6r
         rILpwkL0jTx28qz8dTub6q0q4gB1zI5ERoFGjg7A8osBM8xO1Hpj9DZJrvvQhV2EOAEQ
         T24Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=mh8O150eeMuxxMH0jStzmqkyZ8vLujB12mmwVNwjeBw=;
        b=f3px8auuGEq919SotuLUZTHGSYA8zNu2UH12nCE4+HEvlUMDJY8gJNNXbYSRfXDNPm
         eP3aql2igAn5s9oToeyuJtTG0ArV/SQtYyaD+pdsFQWr4CGQ9CMJpXd8cHTB5JBZkf42
         wawuWdp8rUpRXWb2/gsNGbVjoGgjxURv6lj9d+llOMnb95N90ZDUwINjvOWAFiO+Uqyp
         Yk/w4wGQ0tjWGS1ZwaRdvhfhpgklo35Nr259MZJohUUrxB6OJWunZ8CsJZkeaMzfTkLH
         jagAypCJrUmYxir6ghlVbq6V6f2w49Yeg9RsLF8HuLQiN9W8OvhENdyy0pz0k/LKqGNw
         H0yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ETreXfWq;
       spf=pass (google.com: domain of 3vc9hxwokctkviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3VC9hXwoKCTkViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id b12si462493ots.3.2020.09.15.14.17.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vc9hxwokctkviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id a2so4072331qkg.19
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:09 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f2c1:: with SMTP id
 c1mr11709701qvm.30.1600204628690; Tue, 15 Sep 2020 14:17:08 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:01 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <42f25c11d97aa8497ee3851ee3531b379d6a922e.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 19/37] kasan: don't allow SW_TAGS with ARM64_MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ETreXfWq;       spf=pass
 (google.com: domain of 3vc9hxwokctkviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3VC9hXwoKCTkViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Software tag-based KASAN provides its own tag checking machinery that
can conflict with MTE. Don't allow enabling software tag-based KASAN
when MTE is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: Icd29bd0c6b1d3d7a0ee3d50c20490f404d34fc97
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index e7450fbd0aa7..e875db8e1c86 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -131,7 +131,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
-	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/42f25c11d97aa8497ee3851ee3531b379d6a922e.1600204505.git.andreyknvl%40google.com.
