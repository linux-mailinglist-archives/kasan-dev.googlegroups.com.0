Return-Path: <kasan-dev+bncBCCJX7VWUANBBHXWY77QKGQEZHEL3SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C7F52E8D7D
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Jan 2021 18:13:04 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id q10sf13209658pjg.1
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Jan 2021 09:13:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609693983; cv=pass;
        d=google.com; s=arc-20160816;
        b=V7TbA3HCLJlvfxaknkeK6lIqQJJBbpIOAziCpmrbSTVcxWodT0KKbDeNNExGJLtKeU
         lA+olxmSmsRb7BpBaBXpLdr9FJXyuwqjeA5kaIGynTMvsNCih6q6ZR1heLV1CILMjhsI
         bfpkD41ncjYf579u84djV/Uh38/xuAIyU10yqdCq23jHfVp2y+ttXb+840WxqMoMA3qI
         30Qz98cS05qbXzhYfsNQkD3EqyhpnFSpbbnI47ZB1WHGHJn/nS1HpciWEGnepLiK1iI/
         gCwOJj9FRrRLYurvUIjlWUKlTHNsbjLOZbiPt2R0VSwtToCywjsCyTVOrUXEA9VpeRZr
         9auA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=HoInl9H2E/CDOKKbfUdfmyAb1MJVMeHI44Tj4q3j7qI=;
        b=Tdkqh+Dc4xJOqzAQsqU0SdCfZ2bf6YlU5Jo9aVXt9l4Ae9vNECgM2bQCkIm+vxPLYc
         zOGB0zf4LQZV2JjQSDsHflqPMtYRslwbZ7ph4EG4dpbV2s8x8VVjldwMdTJzNlaTA62J
         +7YwRQWq0UlaTa84HATg5QCIabd21a5dUnpxyTC2uZAQihDZ8Q4/SLcTCzb8Yc49fz7f
         79zrcd/6tgq6Svm5ejwPlDG0z/P4HfPsJIY/m8XR6WQfJNoLgLNirCwo17eZTfmzplnY
         GQVPa2uC1/rSC4kX9xGL/FWLhyAbFVWYiF7pGfdWJ/wP5LoCRZr6vGmXZSrYR8ayeIhH
         n2tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="GJ5A/1au";
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HoInl9H2E/CDOKKbfUdfmyAb1MJVMeHI44Tj4q3j7qI=;
        b=rUnHLkdZMy36A4nMIBnsvekgfpsMvtIGyB+Lvi6rvTqnw1iffsx8weFiKHxTjFzp4u
         GkWtMZzQy8JXRQyGMavagoU2Gm4LODOWfxYzwsCmejcBFY+8OB4sjG6oTYRXoHNQv4/x
         rqSGwiIMVJDCC45t9QtSp/MaQR3Hb5vsrfOoy7SZFB2UaeJw8T9R/KpPogCwtHRpSoMd
         J578KahNzaVo7x5XKwtc+NhqHMEI0YO3yO57A8ZgjO3bj/QnCPzztCUrQq7Bvf0XoLBn
         +vQM0QNZg/7l+7MI/Qqft7DjVcGjPzN/50zVJ7srr7rudx4qJDSjrzdEP1v1M6ovjL+k
         VRZQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HoInl9H2E/CDOKKbfUdfmyAb1MJVMeHI44Tj4q3j7qI=;
        b=ciXLL1pbTTNNAYmcp097or0Kzzi1EFqfBg4Ua6t6D/elPqapw5fXl+Smh1YB7m7GBZ
         C3+EcSHvW5xCfZNWycmyuPez8vFU3JOL5b+4LVxfQv+9spJ/T4+jASO5paeEpDr3jGGo
         p7s0UfmzHa3cTayckfKlhd0mlJAoTQc/KfA4vk4MqK2pvWYyb4VmnIc14j6adDI1eC0V
         9BPrSzu4WgxzAn+pqCMvTEQu/P6JNKKZPmbq7MDVhU5sa+u9lpZV9H28Uc8v7zZqAc+Y
         WuTLN5KyEz7Q6JdQ2f9x2ORmdxBIn5IOIjADsSLGQk8r3oTw2QehS8nDwZTgqkhIaBXX
         goCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HoInl9H2E/CDOKKbfUdfmyAb1MJVMeHI44Tj4q3j7qI=;
        b=EXBjyS9KfZW+8WJgFcuJTgXHlVPtzQpDpnK9Cnq1ZJzYCYu+d+04ViX8873R8KHboD
         F+tWjiOpaNvcnTOuGHA+uYyrnqQnegsnsJd+V3CSBHCm+b2GB9DbBP1MylzSVYMDmmEb
         gMdOUH2dzI55hXQ3b3NCIiki/FdqUxNdo+WTPl50f2pcV+KRdjCo1uPpC/fIdZp525R3
         7KZmZu25MeTFhUmwptTPYXJH95PhiSKMAxUatKqs+zWxosXMLLvwvTFawkZUcwZoU73J
         fb/lvtFJCqweLC3Z7D1ADyvyQyuEKNsDDYIaGws5aAUwXbSaiJVQwdBiKiaQCBWYUIH+
         oOFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HolupsJ+OiDcNcicmetDUxV8RhqXozSXxQUwf/cB0BOnBSJdQ
	OlBMZ1/Wm8C2PYu4Izy1uW0=
X-Google-Smtp-Source: ABdhPJyVLLq4ivzb79fraqtEqIb2I7DJqsiZhLqYRThjBmGhsrnZoiaIxK0hLKMjE2NODVIcpPM5nA==
X-Received: by 2002:a62:b410:0:b029:1a4:7868:7e4e with SMTP id h16-20020a62b4100000b02901a478687e4emr64338989pfn.62.1609693982978;
        Sun, 03 Jan 2021 09:13:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5c85:: with SMTP id q127ls8727558pfb.11.gmail; Sun, 03
 Jan 2021 09:13:02 -0800 (PST)
X-Received: by 2002:a65:48c9:: with SMTP id o9mr67690378pgs.156.1609693982391;
        Sun, 03 Jan 2021 09:13:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609693982; cv=none;
        d=google.com; s=arc-20160816;
        b=l9E5O10zjv0tuYzdXJRCjXK2JPi27N/l9whXJ/qsJXEr3boiHvVgxPu8bi94Vl9fVa
         KQlnRKsWypp8soNF1wfie18k9+Z8LqaN5Dxa3a86NznzDbgvC7bVlq8dayvSsdVIetzx
         qp4BbqCqdZiriJ05SLuoO346rNJPNBU8la7rfNrJvZcUrKG0BguD9hPQkrdl/KC6Ei3Z
         6UNsOPoys+Tim0R6KzfVhTWni8X1ob6626sKllXLs8b0C+MIVMH7eqpSdT286PR8oBTc
         nFN5ovqkEuAs6+mAk+MDpD1ZDdDovnjhsUwarPW5LjR4qEdtgEZD8JQIkGGgHjXtiuSe
         gvaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DJN/Pu+8mLKZ+B4Z+Om7De+VUDyUCro4rXn59AnfrE4=;
        b=0ah3BBqWCGx3mQvJsFHshu/8eiLpx4MNXEui33LF2nLECKR83YbTizP2I9/nwBwOBh
         Pt1RbB76UfgqUEUrmIIDPgoohq9rKmnHWpbz4oaY3/dYyxokwqSK6OLQI94XESZR9ypc
         zAFxG2Sijf7VA5g7xu5FAWyAAMgq8nSEQPmDQWZH+Itn1hypbRFlDA6tpySIY6UYD+fp
         1qT4K1x85vo4Byrq846sLzmAVkuuHwHlL3mp07IDwWbF4ZyDZtseEi+4oZjvhiDc4fRd
         An0AtP5H/ke+QRstibHqa+8e4Q8+s6kJ2U+JJ1n7Z+1P51Sid1rNsiCljoSM5tcKbwWP
         wBgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="GJ5A/1au";
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id lp7si1033397pjb.0.2021.01.03.09.13.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Jan 2021 09:13:02 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id w6so14922692pfu.1
        for <kasan-dev@googlegroups.com>; Sun, 03 Jan 2021 09:13:02 -0800 (PST)
X-Received: by 2002:aa7:86d5:0:b029:1a3:61b6:9c1 with SMTP id h21-20020aa786d50000b02901a361b609c1mr61911995pfo.55.1609693982185;
        Sun, 03 Jan 2021 09:13:02 -0800 (PST)
Received: from localhost.localdomain (61-230-37-4.dynamic-ip.hinet.net. [61.230.37.4])
        by smtp.gmail.com with ESMTPSA id y3sm19771657pjb.18.2021.01.03.09.12.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 03 Jan 2021 09:13:01 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org
Cc: dan.j.williams@intel.com,
	aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org,
	yj.chiang@mediatek.com,
	will@kernel.org,
	catalin.marinas@arm.com,
	Lecopzer Chen <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH 3/3] arm64: Kconfig: support CONFIG_KASAN_VMALLOC
Date: Mon,  4 Jan 2021 01:11:37 +0800
Message-Id: <20210103171137.153834-4-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210103171137.153834-1-lecopzer@gmail.com>
References: <20210103171137.153834-1-lecopzer@gmail.com>
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="GJ5A/1au";       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::42f
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Content-Type: text/plain; charset="UTF-8"
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

Now I have no device to test for HW_TAG, so keep it not selected
until someone can test this.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 05e17351e4f3..29ab35aab59e 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -136,6 +136,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
+	select HAVE_ARCH_KASAN_VMALLOC if (HAVE_ARCH_KASAN && !KASAN_HW_TAGS)
 	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KGDB
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210103171137.153834-4-lecopzer%40gmail.com.
