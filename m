Return-Path: <kasan-dev+bncBDX4HWEMTEBRB766QT5QKGQEEGPPUCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 09AF026AF6F
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:52 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id i23sf1803907edr.14
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204671; cv=pass;
        d=google.com; s=arc-20160816;
        b=JjUfUyCIb5U/ZjDsLruxSo852IlpD0hZ0lcDaJLyeQhRq7c6B79/f9tIXidsi/qIzw
         fktxfkAJEkigYUC4Kj9EcoBxUXin+zljR30HgL/stZkonlcsER+CYvu7V+MPz8TxICpY
         eldOkP+ltLXoxRSdA7Nb29BfP46wc7L6Udo2IbVWKHtYsnm1PzeVmMvr9vF2x8BBeDxC
         BhyPRLTVpW2cfERpcu47NnL/tR4pXCXZ+TZQZaz+CG8HYiBuv5p3IhVgWiBG+ex6Fvsv
         SMAwZw8eMd7SYedMgbO8sTTSXM//Ivc4L4lO5cwjUpZpyebB+bEz1FbJE/1bacinZYHv
         nGYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=sKqKMn3A2C8ZveAN+gSAysrwdpf0dgwXJxAcu1jbv0k=;
        b=vDh6RL+dWIvZKtbx1b6qL3dCVQ0Oui5MNoFyvRWtSE07f75fPFa91ZaSTmt7aIN/qm
         p4mXJ5L7dMH/D1sFahF6jfTtLAuEUtrY6PPn5kGjM7Ynl60Qmtc+z/HP8Lw9GtdmGAWa
         5hY4eVLtcoJb2hMkrsGzUEOIsq93YxxPPCsPjXvKSwN7T9K5wSMr12AHRDn9XiTGkDvS
         f2DBTp0kN+bRICS98NDmYNvqdKZbnVBRtvQBVeT06vxnVzqCcOseYQ3/Raek+epIXJc2
         PP8S+NpuX1Yadm5DuB6DLVKuevrjsjEg/XR3l4t9QFZ2vBOsbmlTRLF7YfQVCuMlMiEe
         02oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vpddWMvo;
       spf=pass (google.com: domain of 3fi9hxwokcwmboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3fi9hXwoKCWMBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sKqKMn3A2C8ZveAN+gSAysrwdpf0dgwXJxAcu1jbv0k=;
        b=d7LGjHLpeExe+ucKmihpLVSbhT8HmNE2k8yHiM9mBJDD+ga7VFC/UErKBAWvlopgjO
         TeowmmI1Qb9WAuu1uPXZn8NcbcGgzv+fYNJbq4dhZ8eZ1gACMTY1aJXqAukggKvWY0N3
         pCBHUGotQa96yvr0E7/FwMenPWgHUL4SSxJyGvAyua+zzpOnVxfK+puvxr7GiEGxNaES
         /mkyeTEHTDHUTXM0KXRv1xjWzDbiy5H1PksqwW9WWEhXf1n3uKMRS5lLHfVVYvOQEn9S
         yL9/KOGzltEO9oQPoQvovKSQr3Z/oxN273NTmI7JtgRoSaBLE0NBpNMWFh2sELUsI+AS
         Eixg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sKqKMn3A2C8ZveAN+gSAysrwdpf0dgwXJxAcu1jbv0k=;
        b=qHqOLpfNCoNS+Wdvl/eI2tcTHU2HfxGc9hxU+SYflbGXCmD4JrpJmcBLNdWRVWDn0j
         xkdrv7amMzjN83kMfcPOgjohozwK57jMQSP4vQM6u0HBrNp88rzghdG/Krr0C0MpxxlU
         mJRAkr3AnwcAelinDNL0CKWwGm8eruXokQw7eV0SFs/g8yliFU+QczqvO1Sg+UNavyTZ
         yHJVF9h5kSzZ2OJheLslzYpkkdrtevU4U/OwJRlsVTIvVbR5KDCerKzfAZsHr0nf/cdf
         ld/dD0bP+HtnXDEbabTnUuXnQWQ+0v8xOhBy2wFX6nhh5TOVMO8O7ZvVaT7PKTxQtdGN
         To3A==
X-Gm-Message-State: AOAM53008hjf9eQQ/yGx7INKDJ77xgFyBtXUolxE6nndfp/VgHZ1YKz7
	e6y/C/iJesu0BO9BxnsCnKA=
X-Google-Smtp-Source: ABdhPJweuZjm+Hp4CidxfwUXXObq5Bc/eR0DNn0UvYH6thF1bmmfeSTYPTgxGG0GlJGqhSemeNpmWA==
X-Received: by 2002:aa7:cf96:: with SMTP id z22mr25183511edx.120.1600204671754;
        Tue, 15 Sep 2020 14:17:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:40ce:: with SMTP id a14ls70591ejk.1.gmail; Tue, 15
 Sep 2020 14:17:50 -0700 (PDT)
X-Received: by 2002:a17:906:f0cb:: with SMTP id dk11mr11788050ejb.457.1600204670936;
        Tue, 15 Sep 2020 14:17:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204670; cv=none;
        d=google.com; s=arc-20160816;
        b=zXdgyY/41QwO1lhS64XPwu6DODR16hyvgPzWoNC5gHHlbHVzlSoalLOfjMPJSmQut8
         iS5zpbAEjHx2E18Kui5LWrCMNLLKuXTDDoA8O/LMgYd5U2cMFnpz8hL3n8glKnbLGoxX
         U6heGBNtZMx/X81O4If1NDKklAh/7mhWH4mAqceZXctgc+kXgZKqADUgt3LUfci4iMqX
         S9mpPImmHZiPEJBVYkQyPLIpCNDlsj2pp+Z8UzX6QZbtmfmikKgE/DRyUHwleADHkI8t
         sAy9YDSA22rFOk8jdGcl8nJ+8fdQyyqV8OoLOyBBpBhxzbsSaivp1IGMXbDhJsdAdvZg
         wOHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=t8rdfVrdLyxTAYdMt/4LR6Ye4IfbP7qoWzC6FDGTZkw=;
        b=y7rkQvL/eJQswuxD/n4jDqg+7hMPqpRY77Zyirqb5omDqDrZlfO0/8CBQQWpJTZQG+
         u6/B8E9WClykEJZ2YJOx1hiXrxSOQXcNUg087jNoHx3JitOxVkPTkwc1fA8hSLJuxsAH
         d/0Z7oHbDXO2OWSzIB2CLezna2FxJkDSHRH75LDTTywOWpG+t0dQpr1qcBmPuiZSb8Ke
         uyi+UUpmFybCaPhFv0awQR5a6ZwnNvHLUac8GfxV5b2nVd+W/5T26HdvP0w9s7U1SUMx
         sbVhwJzr4KF6LhN+jRF+ZS0IO/ejGPZWUFpMC8ned+uA7BPf01oQJWN0tyLgGj4gKHnJ
         ehhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vpddWMvo;
       spf=pass (google.com: domain of 3fi9hxwokcwmboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3fi9hXwoKCWMBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id r5si403592eda.1.2020.09.15.14.17.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fi9hxwokcwmboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id gt18so1827382ejb.16
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:50 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:60d5:: with SMTP id
 f21mr21975308ejk.94.1600204670609; Tue, 15 Sep 2020 14:17:50 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:18 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <d5705790ba42513fdc302f679bf420cf86fbadb6.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 36/37] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=vpddWMvo;       spf=pass
 (google.com: domain of 3fi9hxwokcwmboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3fi9hXwoKCWMBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN is now ready, enable the configuration option.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I6eb1eea770e6b61ad71c701231b8d815a7ccc853
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index c8e45870e993..afeb5dde437d 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -132,6 +132,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
+	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d5705790ba42513fdc302f679bf420cf86fbadb6.1600204505.git.andreyknvl%40google.com.
