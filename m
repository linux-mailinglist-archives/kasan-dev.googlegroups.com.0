Return-Path: <kasan-dev+bncBDOILZ6ZXABBB76RVD7AKGQEHVSXKAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 83B7C2CEDE9
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 13:18:08 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id m16sf1987986ljj.16
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 04:18:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607084288; cv=pass;
        d=google.com; s=arc-20160816;
        b=nY+4WJ7CaSzr6F1z27U3QXBsanArjfBI1Jt4vpHt+JWIYM1AtVyjyeA2vg9F2Hv9o6
         n1JN6aHyAeEhFZT2oloJXpzODDs2d8ct7N8BGf7t5GDpgp0SmU1pPuTcLyZAUrGBofTz
         HKpyr0pYl/w2/URMS3wgijawheRU3DkwiJN5iiBB+rjzDt4ghmQmdEdbFZdiF+exPFOz
         m6rMBF/4PIxR6h0snaMF/AX6QboZlfhnqbieb1bJroi2a0Qvk9js5gl/wmGJaxwBP7GS
         nfUxsmKnf0rzASVgviHzniQo/zosdjV9pl+pGk0ijS4FfXEaUJ6y88QS423CMrkuihhh
         0SmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=gS+mT65CawbHc9IdpzTmGIMgDW3cTG4NrkBH2+/POM0=;
        b=sLnRYfAN9IbfvEQIT9Sq54ixmT0EmvkqgZDJ0N1QyyfWRsAcxxEg/PwquHWEeHR3BG
         PZ++t81EFPNPToZiTaa/8cXgtRN+4VcCEBm1NcUl9Knlj6sVkzsrXc+yWnc6tqO1qUHL
         6RT+00DwG4cUgVAXR0nyAbS0NCepu1vsC7j7oBwa386eZYU8RAS9XMfApjr8jfx2KnEk
         EzNV7gS35BVumDGFg0tt67fn2h4jNddMZwEkqsFVpu16/gRnbAaH9BofT1DDKjlXS8VW
         goJfBpwU5t7621+cIctR8xrIxwOtD4NTJNuzAgkleyTH3zubk2ZKMkLs5URa9a3n55ah
         nhCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=pZu9FxSW;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gS+mT65CawbHc9IdpzTmGIMgDW3cTG4NrkBH2+/POM0=;
        b=JEN1yJyW4yr0ti9Fvib3vqM+EPy1qINY899b9IJTloDlvBi8uwBORfDtjjuWPcFSfX
         CIOTsed21tcuTa4UthXsquYmkOfqbAH+tnpmg3TYh1ztnqiWCksOciYwlkRC4Vh/OepS
         TwVBEH49XYC261bZZ3VgXkF99amf6mazMMjlIHgHxAsg6GQWozkNUQ1HKXkMhvdXK86i
         NL3D+ZN6AWNlNXzB9R4hd21pAo1Fs7y9ykaJSAWp62l658E9cCVhyWCmitdbr577ntD5
         ZAaZr8cYZtgj5U+LY2PGYfHDz3VTmfS77VTh2rDMhfAuH3s1VAyJiWP1xsBoQGkM7J/Y
         qdxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gS+mT65CawbHc9IdpzTmGIMgDW3cTG4NrkBH2+/POM0=;
        b=M6R/JljV7CcKZPnGjcMDtGMguvA3k9IOuTMKmFZMtU05uh2BmMbUgrYhFbBxrXTU1f
         YzMm/qZeTs6UWkdCPZ2o2fboSGFUuBU03gDkdYnusIYDIKDfYFQaRNGJF1MdrkDfBWY1
         na23W49tiQ1/5KPUrEzyQfVHD4J0V9eMAXDWb+1fKVXBl0KM7RBsfslwNGbKa2WQQNBx
         pgtfYKV17vm2KJnBGDBBlU6oST13V4I6nEDe8Yrg8K3hxBtYPdvM0iwvmdY4O/EDR2vY
         PNDOJHt8tPI52yV4EMe7Fb62fk95rAMDiaDH+BoBmpWUuHitwzLx3iLtdvLmasv920uL
         DPVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532S/jKA/bbPc7e0Niuq2Cd+ocONq7LqPN3TGIgXzqNBJJTGTx+Q
	+MMw9EmJFjTvpnvwRfkCOKU=
X-Google-Smtp-Source: ABdhPJxLsk1I5avjKVaym10CFz2zqPlh3wqwozZ7gsI+ZS7Zcc0ExxavtwpwUPioEjXfJNm25wEbRA==
X-Received: by 2002:a05:6512:144:: with SMTP id m4mr3076825lfo.247.1607084288051;
        Fri, 04 Dec 2020 04:18:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:d0e:: with SMTP id 14ls2624912lfn.0.gmail; Fri, 04 Dec
 2020 04:18:07 -0800 (PST)
X-Received: by 2002:ac2:5939:: with SMTP id v25mr3083149lfi.490.1607084287034;
        Fri, 04 Dec 2020 04:18:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607084287; cv=none;
        d=google.com; s=arc-20160816;
        b=BXuhvgV5QUGmUFNfLJNtBiDMXOLF3MMAtsDhZwZjN0ChcfjwAADvSa7lJrS1UNS4MR
         7/DfgoKL94IYgyWUGea82qBosuUwd8Jy1Esf3mLCeOqc3yBsxFVV19wtu6DlLmK1IXQv
         tRfqfWD6jIkuv4D5Ger4wVCmS35MSM15/3xeGyLUaFMfPAXl0PldNsAuKajbix7cPKjB
         971CueKUognJKnDlmFYEcCqC4odYUzXjJF5XqyMH4AEVcyM9xhr9wlKBgx6f7YpbmC35
         kiqmlC/2jWql8GZ1MhM0Dik+y5eZ5HIdGKWy810iwAJy1hd2nbkZvaZOc+VTcLcXxWeO
         1SNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=QKh+BEm0Z2hwqewzzroWyDAofQUgJdQkZ+JXiUwPDEU=;
        b=AVGyN2beQFqfWSpEdU4FpNrPoSoVCLFdomenIHefLZHsP7V4vQUf2U5RJMJNP9Cms2
         aJ33VDdumytI5ACsTM6r2OO67KV8BhHKFsuyJR3MWSCBvZMJgH6Ok4y6FKKTXkaTvoH9
         kwVR+V7mSta1TX+w8Y8W2itU+Tf6w7C/4cw7Y4Ppu7TriA+r8qZ+15RLdga8IyRDcatu
         fGsq5QOTYg+bAFXHtK3ETbzxmFTI3V3bmMBid93scSUkmMQDtLB+Qa6sYfjg8962gXun
         vYlUBhfh9SLQgzlFRe7DIFZwglUlgooQ7xxEtdjb+WDsyc8x8z2ps4yj1CBsJxuq1iVy
         c2Eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=pZu9FxSW;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x142.google.com (mail-lf1-x142.google.com. [2a00:1450:4864:20::142])
        by gmr-mx.google.com with ESMTPS id i12si165789lfl.0.2020.12.04.04.18.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 04:18:06 -0800 (PST)
Received-SPF: pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) client-ip=2a00:1450:4864:20::142;
Received: by mail-lf1-x142.google.com with SMTP id v14so7363259lfo.3
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 04:18:06 -0800 (PST)
X-Received: by 2002:ac2:41ca:: with SMTP id d10mr3218682lfi.419.1607084286559;
        Fri, 04 Dec 2020 04:18:06 -0800 (PST)
Received: from localhost (c-9b28e555.07-21-73746f28.bbcust.telenor.se. [85.229.40.155])
        by smtp.gmail.com with ESMTPSA id c8sm597731lja.103.2020.12.04.04.18.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Dec 2020 04:18:06 -0800 (PST)
From: Anders Roxell <anders.roxell@linaro.org>
To: akpm@linux-foundation.org,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	catalin.marinas@arm.com,
	will@kernel.org
Cc: kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Anders Roxell <anders.roxell@linaro.org>
Subject: [PATCH] kfence: fix implicit function declaration
Date: Fri,  4 Dec 2020 13:18:04 +0100
Message-Id: <20201204121804.1532849-1-anders.roxell@linaro.org>
X-Mailer: git-send-email 2.29.2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: anders.roxell@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=pZu9FxSW;       spf=pass
 (google.com: domain of anders.roxell@linaro.org designates
 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

When building kfence the following error shows up:

In file included from mm/kfence/report.c:13:
arch/arm64/include/asm/kfence.h: In function =E2=80=98kfence_protect_page=
=E2=80=99:
arch/arm64/include/asm/kfence.h:12:2: error: implicit declaration of functi=
on =E2=80=98set_memory_valid=E2=80=99 [-Werror=3Dimplicit-function-declarat=
ion]
   12 |  set_memory_valid(addr, 1, !protect);
      |  ^~~~~~~~~~~~~~~~

Use the correct include both
f2b7c491916d ("set_memory: allow querying whether set_direct_map_*() is act=
ually enabled")
and 4c4c75881536 ("arm64, kfence: enable KFENCE for ARM64") went in the
same day via different trees.

Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
---

I got this build error in todays next-20201204.
Andrew, since both patches are in your -mm tree, I think this can be
folded into 4c4c75881536 ("arm64, kfence: enable KFENCE for ARM64")

 arch/arm64/include/asm/kfence.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfenc=
e.h
index 6c0afeeab635..c44bb368a810 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -3,7 +3,7 @@
 #ifndef __ASM_KFENCE_H
 #define __ASM_KFENCE_H
=20
-#include <asm/cacheflush.h>
+#include <asm/set_memory.h>
=20
 static inline bool arch_kfence_init_pool(void) { return true; }
=20
--=20
2.29.2

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201204121804.1532849-1-anders.roxell%40linaro.org.
