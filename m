Return-Path: <kasan-dev+bncBDX4HWEMTEBRBONVSD4QKGQEHJX3DOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 644532346BA
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 15:20:58 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id z10sf8815889oto.11
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:20:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596201657; cv=pass;
        d=google.com; s=arc-20160816;
        b=H4PrJni+Pd02rMnUNq8gptlyoyMCSMl86X3hOaNwRYro8BdZLucjaFiZj4RBhEf1IN
         F2YaYvUvMsjJBojHa/IixKjHykE2elEu0JflXBoZO5BLBR7qLE3mCIGg8zkUcqWUmocl
         TNy4qu6P4s9kPs36y78OEtj+Y/yRYgARkI+KXIFvP0M9/bWfoHb9i36H7ly4f1M/dFf9
         Kyw67g/VwjnbTAHMVqNjsvwO/CZee5fGBQUuB3I153aVl220xKDR1+R8k04Jjb5TG5WC
         3gBQd89+FIveMASZhAV7VOPZZdxXByrzxTcPQnRVOtPNoi4soZjZjZc053IzYnwKC9jZ
         ftmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=T2l/tq0NBhzWEPuwTYJZyAathZG98BzDlXMaUrgjzEc=;
        b=unPf8rpvv9+eAOgL0dawtS7TlCRfPOfWxvBJn6EYhJ/ojJSEq08pml2d0W7Q1+ja0Z
         MJ10cfJ/sNaSpVZ0vGeyWTavIt8YQfkwXDaQN+J2vaebBNJMmXnfCjXNzjYoSUCoBqXS
         Nd/YprmPFm4pSnuOJqDQpIgl2ngwG/owjW3Nn2Evnz5esK/NTYmykK57QF02H+yTA9AQ
         C1qRuUzEnqtjKtaFWWMzXt2RNFEbidD+cfJLmpCde2u9vsuacX3T9NQTLCD5gWVVDZOP
         hlawqOZ+mDjId1MAVppMFi9A7rCiLgURtFWPV/Ek1eAdpF6EH6JpLvCplLN65A3MaSrz
         KSvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TTB8YFCf;
       spf=pass (google.com: domain of 3ubokxwokcx0boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3uBokXwoKCX0boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T2l/tq0NBhzWEPuwTYJZyAathZG98BzDlXMaUrgjzEc=;
        b=mnHb/R8escnckmq8ArARsnCgjA5I0uM/MVm/G2rTvdJt+6MIqRQyhnxBiHWY7MDXB9
         W3pYWJVj5JXWb630U1oRYsWS/rDVQ0qWM9FXDfb8G0R5Wxg7hjerJXDPcp1hRJk9OwrQ
         E7XkYtBUztdJge2ZAqpBuPz5LD0miSm5Q4DJk/l5B4Q52OWb2eeNPiRe331dEToT9Nwv
         DAoGUoMJBruLWXknUnSfRI8+A9rpGZXplqo3L7+UfHTFAE1TRsTPNBqwXH+rAorhgt/6
         2TM7ubSdCiSXiF5yEZmJCCnZI9tJBUAXaYRlxtLqrvMjRVcoVKlRVvq2TdEy59qJtJ/X
         +xAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T2l/tq0NBhzWEPuwTYJZyAathZG98BzDlXMaUrgjzEc=;
        b=GAwPKvRDkDQub7yYKhylXK5zm7/HbVsTCjHU0VPBbfhCp3thYLyLVFY8OvlLyEpWSI
         bv3I88wchxUxTTA25OkA5EgZxw1wfpUm370LOKtlVCHDyMtn2mP5CIRpQtIQ9P8m+KXB
         dkIjGUGF3SI8Yt530q6pQ58D+2su8/4MfJKc/U0LhE2H4/erQHeZJ0mWLrSPTKDJTMfE
         oBwALUQP9Z5F83WJ7WB2+t41C2qaBNXR84ZmgcwGiqTkXvhX80yKaqHZBZL9Ryd3D914
         fG2s4I6HEHYc7i21yhuzPEbXdC/M3p7dc8hvv1Ko9vOBLXSpYUz6np99YuHTIC41ADhc
         n19A==
X-Gm-Message-State: AOAM533iCVESKtKH0n7B9RyRKoOX3PTcE9J8JO1Y0nLkANej1fw1cWAJ
	pZniuf/ik4bZIBQLeU7eBuM=
X-Google-Smtp-Source: ABdhPJwZLZSbTpDJwCWfESrs3TFOFEK6+6gl5CB0NTIxUeChfg2bgEpRSseuXx+s5wbafq+EkRu+yw==
X-Received: by 2002:a9d:639a:: with SMTP id w26mr1066856otk.140.1596201657114;
        Fri, 31 Jul 2020 06:20:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:56c3:: with SMTP id k186ls1555828oib.5.gmail; Fri, 31
 Jul 2020 06:20:56 -0700 (PDT)
X-Received: by 2002:a54:4f1a:: with SMTP id e26mr2976350oiy.171.1596201656839;
        Fri, 31 Jul 2020 06:20:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596201656; cv=none;
        d=google.com; s=arc-20160816;
        b=HSvbsQn86oMsUbjN66C1hRfbiKWeorvQxi22rXE+sfAz9djBGP8z6aWixC0h0sYaoh
         VznFvsc5gRVbtwGz/2Rw8MpuhTkPvcRfDDWytkBmOPEdA5D6/t8lCdd63F/s/taokbBC
         LTyAJSB5GH/GmHAPKhmNls+ZroAUvxVb0LyaS57jwX4QEr/4Hihf+Oikjl827aPC71Vt
         CULFyciAIKyrUKRh2/e4E0VSKGAUqU5DypqQHjF0JpUdzN8cnKQjyfIh0Ji1hAdZOIcN
         amu+OszrlG2hYdx95CC84vuz5rllwFQYKovTscCdhbEh2x4O+Vh/Z7C3WPo+HKE3f9mv
         WLBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=r3AVQip2xq9L4iLlC84/aNvGhdtcJ5cWyH3sWORBbtc=;
        b=lZv1pvrgG6CSRNdySXu+tTXcr2EzqmmT6wq3d7lo7VRPA8obSMv2XwZ3kMy7VR6Z/C
         6INJJQLTcpeRqBnVxUOovFptMM9otfylMgbJS+Yk9FntuNcE2nNHaoK29wP0k3HFtv/J
         TiQYiFPhgYN6ofdk9g0vYk2iVOHFkA9iz3RhteB+uiN0RkvetKO4tgkmb10RRJ72eT2k
         mXJWA56SRf257r5NKgIaS2XmsiizHLx4rUVq/BTzHLacLnPybqcmhM8dgOJybYI4Ran3
         iFVs3SbgMv2GqMJHec3ip+pIoL5+1Ada6e3no55k57Ctj+kzVBZR80uJ+ox7/suVMCfV
         plfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TTB8YFCf;
       spf=pass (google.com: domain of 3ubokxwokcx0boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3uBokXwoKCX0boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id r64si371243oor.2.2020.07.31.06.20.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Jul 2020 06:20:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ubokxwokcx0boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id v20so20355880qvt.15
        for <kasan-dev@googlegroups.com>; Fri, 31 Jul 2020 06:20:56 -0700 (PDT)
X-Received: by 2002:a0c:99c6:: with SMTP id y6mr4112285qve.86.1596201656301;
 Fri, 31 Jul 2020 06:20:56 -0700 (PDT)
Date: Fri, 31 Jul 2020 15:20:40 +0200
In-Reply-To: <cover.1596199677.git.andreyknvl@google.com>
Message-Id: <e7febb907b539c3730780df587ce0b38dc558c3d.1596199677.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1596199677.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH 3/4] kasan: allow enabling stack tagging for tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Walter Wu <walter-zh.wu@mediatek.com>, Elena Petrova <lenaptr@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TTB8YFCf;       spf=pass
 (google.com: domain of 3ubokxwokcx0boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3uBokXwoKCX0boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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

Use CONFIG_KASAN_STACK to enable stack tagging.

Note, that HWASAN short granules [1] are disabled. Supporting those will
require more kernel changes.

[1] https://clang.llvm.org/docs/HardwareAssistedAddressSanitizerDesign.html

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 scripts/Makefile.kasan | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 03757cc60e06..f4beee1b0013 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -44,7 +44,8 @@ else
 endif
 
 CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
-		-mllvm -hwasan-instrument-stack=0 \
+		-mllvm -hwasan-instrument-stack=$(CONFIG_KASAN_STACK) \
+		-mllvm -hwasan-use-short-granules=0 \
 		$(instrumentation_flags)
 
 endif # CONFIG_KASAN_SW_TAGS
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e7febb907b539c3730780df587ce0b38dc558c3d.1596199677.git.andreyknvl%40google.com.
