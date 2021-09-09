Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ6N46EQMGQEKWDDTGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 621064048B3
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Sep 2021 12:49:40 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 192-20020a2e05c90000b02901b91e6a0ebasf570365ljf.13
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 03:49:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631184579; cv=pass;
        d=google.com; s=arc-20160816;
        b=tIO2rqoPGllKwogLGvOHk3eANIpemvpC+xxl2fp1y9pUuB2mCd0uQ5ubvJ950B+RpB
         i1y9yzJFQ4w8lEm85nxKkinnFNBijlUnItKSPRuqItEZM+y2oe7+HlTPco4dPERzGFQT
         B7bYf5WzCo+GZfZnBWrTzcBtTO69j7eVVYlEHCfC5Gfb5nYOL2nhvlN5UMSkvHSV+ZN8
         Qs8ToyIshRd4thKzBZPSXa9s4iHoaOq37tcUSXSQXf9eF/ZXBP8sf2tMLJuMDjhtP3Up
         R8lLXvZMjlSvMyN7pVUAyi2xDt8TacQRGgfpKL4NKdzvDI2RJieKJhR2jraQEDPNENwA
         N7Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=au9P4jyvx4lSvI8Qiy9F3Nr+Q2iZBeCNNvaw42C/Uew=;
        b=xqIgfXd58Woeq6hbY3aFOyAfCmKXTRNf5XK/20+XD+8ii0sOuKxXseYGHqYMNBMfKG
         bjs17zYw7paQ9GxHc7u2ROe6Xx27eMOweLaTUUTHZxmepDeb/8+R8Eya0JIiXM122sTH
         skR1kmk2WIVh9XyWcTe9t0oJT8GKRjbleR9/B9Ih9TS190uGmTC2vQqoPJpbW9vRw+Zk
         EC0ZuDGoWKhTF8RTwbr884KXAj0fpBFOpt+x4DJ4KCFP0qO4LnnuLsBzt2lculnREWB4
         5sHwfK7ZMNoQtF6VxJLSf81Ms6qOEPMkiQjSnTf45+vMuU6IvgDhiCtY5MkVyK4dbnEt
         /heg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oVBgZSF0;
       spf=pass (google.com: domain of 3wey5yqukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3weY5YQUKCYYov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=au9P4jyvx4lSvI8Qiy9F3Nr+Q2iZBeCNNvaw42C/Uew=;
        b=DeVscWnrog+DtVX5AfuSuvuMhrjUtyZ5BJb5d/6BFpVFQScPBqCZNw2E7AIfEJJcDs
         fRUGj+t9Ca8G78qQDxhXSn+sfdVKlyPnyzKvboJyTvJk2oqdA5UiZ3oa8oWpwMfxnTMM
         hcr2m/QAKTPuOLOpIiP0JWgU32U90aKx/jPZrOk6QWia9zP7/NAFntAnGQjMXMXr/5HP
         32gGdRL5xfLhgMAc3gV52H/WeoOgLWEg/McWEqkJmcl/T+p+P/OLC2O8Kqu6IMhkX6Cl
         Burqqe2Dlo9LqS8dNKka4FGU+p/FmZGDpQ1xJmpSfBQ9NHv/K7Lb6ICr66qztdfuy1k/
         xe2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=au9P4jyvx4lSvI8Qiy9F3Nr+Q2iZBeCNNvaw42C/Uew=;
        b=3eENIlKui8NradE94yr7UGkn9gITQXedYrivp7JJwQouhGXRZ4xTe1j0rQZMFhj+q0
         Rr4maECeBRXtPC56xo7IMl1yeGaOc67iyeGAoZ6rxLVI2teoKnecbEff5/aR0pysqMNc
         9fMdqbq0GtulvLQcIcEWGKOSRhIENNQQ+NjXX9rqJd+JYm456jTQMTCkQCRALCLaHo/l
         V/pivymufZrfbHdRLlUcyS1bTp79E8RLsxnc3L6NwVZb1CybVjgvvvxfjUITojgSjPFz
         H6w3R8oKWXbdeChmpo0QR9D4Vd16RmCwmsOkYvKR/t+V3O+L9ZGGwhahGCl2RpCXuoMu
         Y50g==
X-Gm-Message-State: AOAM531pzRJARqgkKkNZK3OqMSjK8CiiJhTU+q2CsWBHHF+/04rkkvr2
	ILATRNH9cMPFFz+LX/70cdY=
X-Google-Smtp-Source: ABdhPJyF5yjFztwEs9Jxr7h7mG+Ba2WU2joNwgo0E9hxv/oVARgvnHQRePgZKpEayCTHuoLRDEkc5w==
X-Received: by 2002:a05:6512:12d5:: with SMTP id p21mr1908978lfg.304.1631184579729;
        Thu, 09 Sep 2021 03:49:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4146:: with SMTP id c6ls1341943lfi.2.gmail; Thu, 09 Sep
 2021 03:49:38 -0700 (PDT)
X-Received: by 2002:a05:6512:1112:: with SMTP id l18mr1814990lfg.402.1631184578648;
        Thu, 09 Sep 2021 03:49:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631184578; cv=none;
        d=google.com; s=arc-20160816;
        b=zxPN9EDf1vZqCCSiXZm+2ClSSGjvWjptfEAj517hyOzuklRNlRkhKoD66MZ4yXnrp9
         3xLCiIOJF/xcuCQz8iGqrTAWrY5nRSFGDFLky2SlTfKIzR5vIjiuWSi6m/v+ZI3bkKqH
         jrxN5Nr9oZwbl3uUEWdjx0SOHL4bthy1y3iUDPOd8lo5R0I6O+Gf7POeheos/kxf4KZQ
         K9XjXTeh7dSMvjqtZCCSRRfKSZ2E0hd6ISe6CrgOjIxqQaM8AWXjJ85YkD1JNeZByBqM
         FLRi0QbcaC1QVaxYI3Bm1VLiEtDy8jtLGDs7Zc30VJHM9ulz81PBDkOnIWdr39crQoq0
         soBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=JKG2Csw+REpqX6pYLoajkSbStNWY+2P13qnXNLcGPTo=;
        b=rXnD2Ty3sTjpkXa7+xuVV/+ockZl9fy9y6m2xcQC0oyMZ+ySv6fRnPzh3BFtoJ9CtO
         loNPQ5jjs9DBedLeSO1C7Wnrrz3IG9T2X8rl/1+vySLOPGHnQRJO6VihkHhMeQFV2tSV
         TN1lanDQmU2I/nxTjEubVH66qfDXSwXyd6j3/8wc7r05EivSO6V3HBTQmUWMXHh9FgrF
         39jUYSMKHH+qV0zroA3Vc0XdLYQ0Fe9N8M2ExfKOnrNCWsWtfNJeRYiXnFGBP915FjAt
         Wv36qTRg2dbKqV6HJ1jz1uBi1PyzUuWQWixB6KoApMK5TIWHjyKKxJ8Zz3MCIOfj/TVX
         hB0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oVBgZSF0;
       spf=pass (google.com: domain of 3wey5yqukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3weY5YQUKCYYov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id z4si94439lfr.2.2021.09.09.03.49.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Sep 2021 03:49:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wey5yqukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id c203-20020a1c9ad4000000b002f8cba155ccso689468wme.4
        for <kasan-dev@googlegroups.com>; Thu, 09 Sep 2021 03:49:37 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:98f9:2b1c:26b6:bc81])
 (user=elver job=sendgmr) by 2002:a05:600c:b4e:: with SMTP id
 k14mr2206453wmr.151.1631184577256; Thu, 09 Sep 2021 03:49:37 -0700 (PDT)
Date: Thu,  9 Sep 2021 12:49:25 +0200
Message-Id: <20210909104925.809674-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.153.gba50c8fa24-goog
Subject: [PATCH] kasan: double -Wframe-larger-than threshold if KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Arnd Bergmann <arnd@kernel.org>, Christoph Hellwig <hch@infradead.org>, Guenter Roeck <linux@roeck-us.net>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Taras Madan <tarasmadan@google.com>, linux-mm@kvack.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=oVBgZSF0;       spf=pass
 (google.com: domain of 3wey5yqukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3weY5YQUKCYYov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

All architectures at least double stack size when using one of the KASAN
software modes that rely on compiler instrumentation.

Until now, warnings emitted by -Wframe-larger-than could easily be
ignored, as we would still get a working kernel.

However, with the introduction of -Werror (CONFIG_WERROR=y), it makes
sense to at least double the -Wframe-larger-than threshold for
software-based KASAN modes to reflect the already increased stack sizes
when building a kernel with KASAN enabled.

Link: https://lkml.kernel.org/r/YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain
Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.debug | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index ed4a31e34098..2055bbb6724a 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -345,6 +345,8 @@ endif # DEBUG_INFO
 config FRAME_WARN
 	int "Warn for stack frames larger than"
 	range 0 8192
+	default 4096 if 64BIT && (KASAN_GENERIC || KASAN_SW_TAGS)
+	default 2048 if !64BIT && (KASAN_GENERIC || KASAN_SW_TAGS)
 	default 2048 if GCC_PLUGIN_LATENT_ENTROPY
 	default 1536 if (!64BIT && PARISC)
 	default 1024 if (!64BIT && !PARISC)
-- 
2.33.0.153.gba50c8fa24-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210909104925.809674-1-elver%40google.com.
