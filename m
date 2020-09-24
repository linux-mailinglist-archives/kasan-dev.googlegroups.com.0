Return-Path: <kasan-dev+bncBDX4HWEMTEBRB76FWT5QKGQE4ZURFMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A887277BDF
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:44 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id l17sf286769wrw.11
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987904; cv=pass;
        d=google.com; s=arc-20160816;
        b=IT7qTZsZX7SdThN1WTxVLOtYJNRNE+4Ch7DGUas9ZLlvlmA5dIxNHNDVArphaU4E8g
         ME69R9wa4jblkLte8ZJV38lwjGj9zhEOVHUStVKguQDQesZ+2Pu9iBuzvcytixmWUT6I
         M2QFBqKrAXNOg/t3/UcT4pcxoiUF6hK3mhd/XW6ykOZuGdEYGUmVNCUvhSFbSkKN312z
         OdIINocujAdgpS2WEG/0FnW7asCL359ervxcdzSn/6j89/MJhCPIRGLHZx6gDUWviRbw
         xmpnpSOVsy3V618ytVnfuU5fljOps5pC1HZDKi7CiOG7sYWKupC+IXiXz8kph2lKKXGv
         Lt/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=oYMqAOop/dHmvFl2Na1+ge6FYFG+b/zr2CtxzrWWT+I=;
        b=FrKAhkgKi3fw1Ro3RxQHS5WibPjwQ4mhLEAAkIGa0PSRoxH2lfhPSOL7JEXhE3FQLU
         ilrleD3MFFSTzo+f3jWsAxUKnp9lBdHx2ApAdIVMpsP6FRxLF5OqIdJAR6VMDBavbZ6h
         MJLnp4mbOFGpja2sJbHXdHX3S510FBBR5k4QrCcqBWxwTsvNVjKmqjDJNnhZjF4CRC4f
         cGCmuj2O8QskiUYe0OGiae9dG4z5JjhH2LmiHEbNYlmrwZzLDhygbAvMpyk0YetulMHF
         T5KPiSpZfqAbX8hMqbJYKT7inVXmuZ0ui4MlerqhTpPnhy2R0XXXH7nRsbVywXBzxP3n
         DpLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZQQPPgDS;
       spf=pass (google.com: domain of 3_ijtxwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3_iJtXwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oYMqAOop/dHmvFl2Na1+ge6FYFG+b/zr2CtxzrWWT+I=;
        b=lIQ15zRauTRX9v9C33UMBc5jpD/oCCWjYtXeuhnbQktXi/M4738LxD9IkJumh2QVmq
         t/EXiNjVpkx+kA5k+7j717Mdanzt3tADHurfpRVwH3wtUx67jKOifUjDOSHsk2LdGwka
         OlpVsCyChYp2XNIbUG9wGNH79CtmKXrsG16cbKeBy1ABIohtE+E7EvQCudjD3PbCkVGa
         91bjqVb0cKGn5YY12fxKfPVDYlx904+/M2jGiUVaShwbC0/PigVJz+8XeXJ6wjhmaC/a
         +ZJo6UEtNOCjlc8dWSqbofJIiCLEcKJkqSK0pQdZLrcyV1+1dFluvK83nz8jh1dtH/R/
         +BYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oYMqAOop/dHmvFl2Na1+ge6FYFG+b/zr2CtxzrWWT+I=;
        b=rREgLznp6m+tuISZlLKVMo8Q2EhySFs5RHqHTom0sjtqS1kC72xgtiOobUIfYSplZL
         /maCnFEHt6Z/jMuIflFU9Mite79QCG2jCBJw5ZV6nOlgu1vZslQnW161MEUfKp9sybfV
         lJMgBJ2eTKeBT/FZNO3wQKavzdEW0dnVksKK4OPMYNwm9oBDAedB7xrN5PCkmmUitAcf
         5BsYCOId4jtmhb0SxBOGg8/Yp6j6y0nY8ubTMOzYFVFnr1i+JwSYHBTrMovSEna2geCi
         dKKm4cqcGrf5BmQh6IhGZ3sVP4I0QODiVq/wRglpHYMkQHLEERT7tcYLyDGc+R8WCbOV
         63Wg==
X-Gm-Message-State: AOAM532qMLQqVSeHq5WklMmy88aWlBsMgCSOiO9Erkz6P2T1Abi8S2Nl
	GdHE5M15//jKyQqcbJukADo=
X-Google-Smtp-Source: ABdhPJz5aRa8JS/9UtZS5JJyhBZwhY5COTEkX+ityPAZMVBmkYRW4qpXvhUJ5W2Mx/7628RHZuTu/g==
X-Received: by 2002:adf:e7c8:: with SMTP id e8mr1239259wrn.358.1600987903952;
        Thu, 24 Sep 2020 15:51:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:8:: with SMTP id h8ls1028625wrx.3.gmail; Thu, 24
 Sep 2020 15:51:43 -0700 (PDT)
X-Received: by 2002:a05:6000:12c3:: with SMTP id l3mr1270352wrx.164.1600987903135;
        Thu, 24 Sep 2020 15:51:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987903; cv=none;
        d=google.com; s=arc-20160816;
        b=k5qaIwV8PXc9ZeHj3eDWEwqAgAOLc88EH2P/9LkXOj+l4P2o2l8KOyAqWLQEZMKDrz
         RGIm93WQRi9NqBCbw5Lzb69SjzDLiGHH24Z1KDrZVhtxeAg9o5jB4B34b71JcktxVuzh
         z/S6dD8nCXYYTbHv75r36ToaJKS6x7qk6+K+/pa2frbU9XqIeuJKU/DJ9kFB9dc0sW4s
         og2NInINe+5Jjx7vUN2Bc6KSz235by4B3eSiNtiOWCTJzDD0NUuLEFRv+2FUvkN7dowW
         zsz4yKEC86+/LfB4AK9YJcrN23Ui6rjWtnh5Dwdr3zIWgn6WT+wZupscWexaF453/LH5
         qNWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=jdvdUBTX2W2BS/6LXn98shgk2aR72XHwNTl4Sjd6ky0=;
        b=pZXRC/1RnhmhRa+I6w23/jc46QazJCcNmcrDkLKVCG/qR1v4J056TkRM0vJQ/E0GH7
         wDe3m8CePKuQukT9BQD2FXPajIidNTEZcscF7DoLxJtvZ6Ar9ONEFlFFM5oDdYPUGjAY
         v289Jl4RB776Sn7EyQ52YFmOI+3OmN79Cwk5Vwup6sBz0xI4PCVd0JHGMEdfnJIwsbPJ
         UyPDLa3jqRPk5Ynw4H5NaXIv9/eNI3SVwNshiXwY8LS3Chl4Wz/99pV7FxSu1oLMTsBp
         RIgll4z9Kshvjk5Z00xM892gL3MDHcrcpax7wP0h+ZvFSNV0H4ivgveY06mIa21Yw+M/
         oWyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZQQPPgDS;
       spf=pass (google.com: domain of 3_ijtxwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3_iJtXwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id o13si28902wme.3.2020.09.24.15.51.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_ijtxwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id m125so318223wmm.7
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:43 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4d0c:: with SMTP id
 o12mr169wmh.0.1600987902272; Thu, 24 Sep 2020 15:51:42 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:28 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <d00f21f69ba7cb4809e850cf322247d48dae75ce.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 21/39] kasan: don't allow SW_TAGS with ARM64_MTE
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
 header.i=@google.com header.s=20161025 header.b=ZQQPPgDS;       spf=pass
 (google.com: domain of 3_ijtxwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3_iJtXwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d00f21f69ba7cb4809e850cf322247d48dae75ce.1600987622.git.andreyknvl%40google.com.
