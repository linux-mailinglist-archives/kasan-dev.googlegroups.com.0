Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFPXTCBAMGQEZQLHX3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id E591933117E
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 15:58:30 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id q11sf3332829plx.22
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 06:58:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615215509; cv=pass;
        d=google.com; s=arc-20160816;
        b=kDGwPo1BH3oFrliF9gc66ncmB+zs4bL5orQHzyjN32/SaDf13XxJRnwd5/v3OspW1N
         wkBf9pQMNHrtGGFVWQv8AUTC1rJ8Kba4uHiv6oFQMR4FlDtSagCNI7OHuePEkUrx6M94
         psXAV+ohabCSEbpet8KvvU/F3ihUcH1otizBO/TAExFVfeRIVJzZNhkS4Yzq4hRhXhQ5
         AbtvMYCa9AMe7hGH5fz35F3Qw5ZRDUJEST4XCgxOmv6S4tYpcj3N3A9p5pl250t2laf4
         7eLbqei5q/pXGjtdSmRZi01Fyykwzgzanz15cK/61foPaSeK7oa5VlzBKG2MFSyXxJC+
         FGLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=8wGqsQtxGO5vTxZGFv1GR99GIUCd1BAu2A2ZkZlb6zI=;
        b=I81DX8AsFG08yG7dB/31+BJkCIdgBIXGI/CAszivEB7w7UmoEQsI835dc/8vk1sPvG
         jtI00fcUOevq6oMuRNWJSMRXcQm+tgrKaGDMGFleZbtnzcKPgKuj4afoBViPlUOb0YE2
         h1FYEN0kdCetrEybba96RIcCrF2IUbuVGtYJ1Tlqu+VaDzYvwMgAcKzNcLJoPBzPuswa
         rTVmhzLUvgmb1QSMektqQYztFCPu7xiUQZ4W5KQDrF5VRtypkl7sl8/+xUKofgHbHw0U
         OFSEScNJDcFKjFVYt3avxgG3qibADx8zUbFSxvzVN98BE5z1o6yqrqBIw7pJD6sY9Zcf
         FfoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CY88Hxf2;
       spf=pass (google.com: domain of 3ldtgyaokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3lDtGYAoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8wGqsQtxGO5vTxZGFv1GR99GIUCd1BAu2A2ZkZlb6zI=;
        b=NR86wB6j1S+jT89dbTxCpGOYeQ1HisorYpZkz3jcmZSsfutnINh9GGzc8NQ5nREYOs
         +CSS4Ar8t++nvVO3FSU0oEy7DUmg3maEpBGlCCET9leg5uGd2wxveMUHzLKbBUnOgxM7
         muTkEKch5mb01Km6HYcLVVSP/JOjUnVQekfW5IfQ3Wb3EdUQuMfZS01jQxwvZKtVQUdX
         Y50hdC4AhQjC7IEacpxd954pgPlhRu1ae3wxyI/mLE5sEnM3hJILd6Co+c2JHsVED52a
         9h92UHWy16zkJjq/eRdld+6FxqNdIfVRt5NaZxMmco6uyCs9SIoHuubv35MJEzVA+0ax
         99ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8wGqsQtxGO5vTxZGFv1GR99GIUCd1BAu2A2ZkZlb6zI=;
        b=mhWv9Gn3wdPPB8DUUuGb8bAEVLGuwVyJnKHwje4AoiuvJtR5rMzXGSn3vvMRLazY/G
         FVvlqTACKm8EprFvFuZcCESM0octg8H8BvWc4dZQQvg7JDA5aiK8JyDpuMojdf4v2sTN
         mQh6mb8YbwkP5iTFeenx2czX7Q6im9sd9TZbAnuYr4OrYO0K4rLXiSfr9pZfyPfjzc2r
         iN5WEB+FQUm+KfvzoPgQ2wrKNZVIG9sFH9IK5Yl/gpwWr5BJ0rxRYEM+frExWIAmy5Vn
         CpNk2ntzaLxYJ55FpadvkSf3oWwAd0IpbYuPOiLanp/7kC434mt6J2AYFBD3LHZXMkwQ
         NHZg==
X-Gm-Message-State: AOAM533aZlr56Nbfk9h5ipIkBK4iyewfbmBCyhpZ3+0HS0uDJgWkkM8D
	C5c0d5fVgCjrEe+MRfirEiY=
X-Google-Smtp-Source: ABdhPJx9+1SGptkx+2+I9wRJl4AN5HWe3bzxWcd1Dv1G9LxU/waXVJzFH0V3T7ADV/zg6Uy+Hhts4Q==
X-Received: by 2002:a17:902:9e81:b029:e4:a69:2f92 with SMTP id e1-20020a1709029e81b02900e40a692f92mr21268728plq.83.1615215509578;
        Mon, 08 Mar 2021 06:58:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:9549:: with SMTP id t9ls2531286pgn.3.gmail; Mon, 08 Mar
 2021 06:58:29 -0800 (PST)
X-Received: by 2002:a63:eb53:: with SMTP id b19mr4023042pgk.383.1615215508993;
        Mon, 08 Mar 2021 06:58:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615215508; cv=none;
        d=google.com; s=arc-20160816;
        b=gbqqghAP5KsznZkUSkumoXivSWPLkuSAHtgC+WeGS2J2Y8kbqNpsQ5nn5S+GkyJINW
         v+lQ0D1i2VDDlfZ8V+jj8u5aN0kU+nD32zEtwrB9FWv5+YVMkFDB4nQWapj1tIopKufl
         v4eValof8ZRcuZMGGq3TsOFV76SQFUQ5eNRe7SWlDkDFrGxwO2UE/d8qDxJtbPM7RsQ2
         2aBlqCxiKfqXO8bbw+uH91xuj47YzKGOHaARNgTzjGJI+UP/gAlxcrYz+KkfTV3pjzPt
         HUtIXR1tNXttSHQurG8g0DqSfLNDDi6bZC5uILGEQc+wkHcsZ/z4SArD3LE/Jn07VgqJ
         cDYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=BxhzP0W+qvkeGdKa9mCwOIPGRH/6WApGqekyUBkmdsU=;
        b=RKskMWfKfD6y+i1WgPxNYT5MkYGUgS17C5cQmcFSbhSUz/1ne9BRfVtKzbheC08hLh
         P4p9EoI02LskMuUibTQQatHfTO1evJzxinyUt6RqrouyjnL9MmPcduq1SxDR9Ak2KCXs
         Oy1qrF1D7+SV0l+W5NF3d5RhZV6sjgW0eReT0OMvvPfnw9AdeLr6O1HnN4cs5ELUBBjy
         a3m6mzLJPM0C4vrGCkPNhyakg107TFCEZZRjfns94+XPhbxkaq9xkl8N0TeM/cwqUO8H
         FCWfL6pwON1034fBF3vKqg10quL9/Cjjtguh9QKoZZ3s8JlnvmU2StSBDAr65VFfnikk
         Z47Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CY88Hxf2;
       spf=pass (google.com: domain of 3ldtgyaokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3lDtGYAoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id x3si1107651pjo.1.2021.03.08.06.58.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 06:58:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ldtgyaokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id h12so7834069qvm.9
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 06:58:28 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:85fb:aac9:69ed:e574])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b418:: with SMTP id
 u24mr20842991qve.20.1615215508348; Mon, 08 Mar 2021 06:58:28 -0800 (PST)
Date: Mon,  8 Mar 2021 15:58:21 +0100
Message-Id: <59e75426241dbb5611277758c8d4d6f5f9298dac.1615215441.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH] kasan: fix KASAN_STACK dependency for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CY88Hxf2;       spf=pass
 (google.com: domain of 3ldtgyaokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3lDtGYAoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
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

There's a runtime failure when running HW_TAGS-enabled kernel built with
GCC on hardware that doesn't support MTE. GCC-built kernels always have
CONFIG_KASAN_STACK enabled, even though stack instrumentation isn't
supported by HW_TAGS. Having that config enabled causes KASAN to issue
MTE-only instructions to unpoison kernel stacks, which causes the failure.

Fix the issue by disallowing CONFIG_KASAN_STACK when HW_TAGS is used.

(The commit that introduced CONFIG_KASAN_HW_TAGS specified proper
 dependency for CONFIG_KASAN_STACK_ENABLE but not for CONFIG_KASAN_STACK.)

Fixes: 6a63a63ff1ac ("kasan: introduce CONFIG_KASAN_HW_TAGS")
Cc: stable@vger.kernel.org
Reported-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/Kconfig.kasan | 1 +
 1 file changed, 1 insertion(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 624ae1df7984..fba9909e31b7 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -156,6 +156,7 @@ config KASAN_STACK_ENABLE
 
 config KASAN_STACK
 	int
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
 	default 0
 
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/59e75426241dbb5611277758c8d4d6f5f9298dac.1615215441.git.andreyknvl%40google.com.
