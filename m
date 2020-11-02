Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2W4QD6QKGQEYVZRQSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8342C2A2F2D
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:06:03 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id f5sf4608257pfa.18
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:06:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333162; cv=pass;
        d=google.com; s=arc-20160816;
        b=s4uLzwFe+0QICAdPzc03dUhABZIDGLq+W7fhvj/wnNCzVlqVKwJmf+boo4hyYzqbW7
         YBXRPC+PodBeTGAjaIVP360npp4ZtI9eaG614/aT4lG9SK4gSZatKRK0N/YGnrzt3Z3A
         RJRwdpdyQRWEX2hINytAey89VNV+CTo319hIlP38+YIdWe+6TzZWfd3gRBiwIW98bGu3
         70Vif4b+daCkivaQi2IXyFbi4WKnsLLhow1bmiexXt8nuwt9I/fCC9tl4jiPWI50rAgG
         pijG87SaKoekwXLqt4tZ33fSSdHy63znWmUZc5LEKt7ikTu2b0ZkEA0/gLuJJvCbZS3H
         Oimw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=O0DR31eazlfvzRou9f114RyD/mkbCwUwBL0A63n0SWA=;
        b=0b4vx3F0Abl09kW3rNIO95o01BdMfGlYcMF08Z1AYtbE8k2iOT6a9HSN/t10UdWW2w
         YsReqPHpUlauJDcDI9BhHhAD/yFDaRyG9HbrUOXTCSBNdrsu4t9rhNCf+J8JqxNkGQKZ
         NW9mKpQOqrW18K+JFeP5yvzdu7I0s8j69N1vde5Z7c25x2M7dZWxkNFORKhKrdT9edrB
         PQs+FL8goVrj/Dngg0I+I0bMREbEIHFUJdpnQcDnVYW6HUlDePbUdLLyq5KHKzX1I0OH
         8LxuFf45YShl+UKIggpQfIw/B1oqvAnLlfz5YjZ0I8w5WeGXQz53Sm5DiddA9MxqiEWF
         CTUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lP+3S3PA;
       spf=pass (google.com: domain of 3ac6gxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3aC6gXwoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=O0DR31eazlfvzRou9f114RyD/mkbCwUwBL0A63n0SWA=;
        b=UNf//wGpRI7oBKEkgjw2qKQ0Zt96QgAxMO1IqkNE47ndK+D9IGrL+bBVXr/46bHPIs
         8nWHoqh1ppd1VEgYac0Y39J3pnS4bhKbX0LNzmJSwFU6be9L8qYeW36Hm8V9lenuDlDy
         IxDQvEcea8aGk/DToYox51+vzb5Gw0ZxhCKvbkAIGuzhX+sbrni1XRISRpmJRbP0eHuU
         dqSg9hoMWMTkQS9VsMz0Ck/qr6DkmhyiGyMre5dLzzA353LMBuwbnsnuKKoPcaiCXKBS
         j41On0hfwDuQdFTlNB3tSCicZDTWkJib1/W2DEI6fihcHuu4MgwpMfwYZmC5JQwBmnXb
         FhQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O0DR31eazlfvzRou9f114RyD/mkbCwUwBL0A63n0SWA=;
        b=BBwuAoWWg70m1u4/TZFqhDeR24xaRcnBymEqCL43DAN/btzb48S/a98mTBzVa6wPQ7
         Z4oZkRc/tNVBg3DVsrMCaz8Xs5wZzqgePourFIKYWP2rqK6rjxFCtlgzv6ulHl88eNLD
         KfV4EgpXrGsw/eG1CnXn/yGfShZqH2ISUrb0lOFCEHnLPX+CS60prPSruAJWLOBWmvOX
         1gSBGIJG5uN++unJn9iRz3z5m0lNpKCTaZbuO0/Q+Dz+px8fqqfpokyFyPD8VzAavNnH
         IglAwTlMQHbAL1UmNyMWUpIAOS1kbr9UeCJJ/uMS/LmYiD8Dbsga2Of182FTzb/+dF3z
         zcXw==
X-Gm-Message-State: AOAM532b3vuFMKTfrJ8hcrTkXY3N8KgnAMR+yt54xu5uq4WhK6g/JmhS
	Std0OUpMVIIheuZwllE1o9Q=
X-Google-Smtp-Source: ABdhPJyCh/PkuuYRb9CbF15IqTAfmZrnvIH01WxBBfg/i6ap4Vt+J46yAvfSbcrW8AvD5NpQ+fZ89w==
X-Received: by 2002:a17:90a:5e4d:: with SMTP id u13mr11490917pji.171.1604333162294;
        Mon, 02 Nov 2020 08:06:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:451d:: with SMTP id s29ls2823780pga.5.gmail; Mon, 02 Nov
 2020 08:06:01 -0800 (PST)
X-Received: by 2002:a62:1991:0:b029:155:f476:2462 with SMTP id 139-20020a6219910000b0290155f4762462mr22767495pfz.43.1604333161776;
        Mon, 02 Nov 2020 08:06:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333161; cv=none;
        d=google.com; s=arc-20160816;
        b=Q5oMRz6VYrMp4JoemAzXMet1mFwWu61HCxFNQPAT4rWNJ+1MwGSCQhoEhQuXLViELd
         juf8zKPuKBEctZTrMSWUGoRC7yt4y6VJso8U5amvf/KNYo7JDHcYT4kxNq3vxWTQ8LLV
         ESHqar56/QPp2beXVmNVc0qMTdAAHREhHk/hk1Ug6qNyqzIoecfw9/byjQuzRYh9MEI4
         F1r2ySAWupwHMPAIFnrrdpwX5cCSyJH6saDYByWQdLlBld7HwcSvqPYSvDQmUgmEMSzU
         ya8eR2UJ6CzJKrJn5FjOx6II9EEL7XTVlZv2x9ht+7X593ve6o6gE2nGQmrHzf237iRs
         4NZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hKqfeGmJU17yqcBnh9EcbhWo2RSZMPrdWdsmZezW6Y0=;
        b=Hv6iYCDbBi1wvZOdWvZQLJWBIcWMgxRPu6MpBW+7FIpd/b0v50jc7rLpQHKPRqjxWS
         4i2LedGh1dfE4CTIFb2fP9PZhHQharlnpOLTB53iF7TlHb5omL/j0iKTuhaFmNuLPEQV
         q+zvKJkNX2DkbP3i2SHgjhT3UKjLNnKwWxLPau7dez5IFV4G7awOQxdKTUz0RUaXQKVu
         MTWu5vSIDruqw7ec3wraP9zCtqL7N/r3qvTzqcvDCbHhmLX4orTeVcyvEavDX+yzKHGI
         BQP0k0me2gh5YVkB2mDq72MVHglhHlHeEw3+2l8m81z8MqX8vpEOnLcgH85daamkMTrB
         v+og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lP+3S3PA;
       spf=pass (google.com: domain of 3ac6gxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3aC6gXwoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id i5si28070pjz.1.2020.11.02.08.06.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:06:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ac6gxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id eh4so8451087qvb.12
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:06:01 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:cdc2:: with SMTP id
 a2mr6570448qvn.16.1604333160936; Mon, 02 Nov 2020 08:06:00 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:19 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <4cd13fcf68a4b69ccdef7d8bf8e483a9a9abe244.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 39/41] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lP+3S3PA;       spf=pass
 (google.com: domain of 3ac6gxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3aC6gXwoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I6eb1eea770e6b61ad71c701231b8d815a7ccc853
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 43702780f28c..0996b5d75046 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -135,6 +135,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
+	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4cd13fcf68a4b69ccdef7d8bf8e483a9a9abe244.1604333009.git.andreyknvl%40google.com.
