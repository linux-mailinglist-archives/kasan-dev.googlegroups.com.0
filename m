Return-Path: <kasan-dev+bncBDTZTRGMXIFBBQ4FT7WAKGQEIZEO35I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 335E7BA407
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2019 20:51:49 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id a31sf510910pgm.20
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2019 11:51:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569178307; cv=pass;
        d=google.com; s=arc-20160816;
        b=r5xiGvEmq6PgarLewhQjfj6siCfdFNljHTyvwDz6Vt2ux9crA7A+ko7aIPzRUVShp5
         UkfB6s6ADYxOH8czkU5kAcRzsM2Ukg9xD3rmuSer7psuX8EkgBSREYSO1ts+C3blL55p
         IU3Xzg3Xew4DT+FnJJShJE05/wuI7vNxaS9eUu+Q7mCzn6aamvJAdkE/NWLq+z4dCqHv
         cu/L1VbUW5yEnfHC4h2cDE7pWH64QZXYRzltr2tulsASxkoUJjjG3sjWk5rPSg1cuCSY
         U6baf0F+8kltm3Rp/PVsOA630OEcHqXcZ1pQY1A/+7SM21+q3hawQAFeFYDLnW9nsBYO
         umyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WkniCDgpXv4lhDh9vcJgEx7efg2KhoCF3NoBNAn55co=;
        b=F6KvQ5JY27KbgNu6qNLyFLaev0GUAUZDlDcQmbgYQFSmZHT4J6cx7w1McRyACV39UG
         nselryumiGO7GAg1u//+/qyV41RIHiUbY1544z7IyvPmj/nnQ8EhK3i7Jsr4cG1Oa6na
         pBG0H1sA7d7KYbTWzXU3oStN+mexzP7ZVqX3paeX8YiT0KJhPbq4XntR7b53EDYZa0s8
         a85XkRTrHyPomMyuoBrElKMc+UGh8Y//Fq8eJMecn8vlnZ+T255rsYt+0SWVN6ie9f10
         ZVlPbVgkCyuJBCCzns1jFS+xZ7Ir3dlnxIQU+/CFLBQgNk8pV20haArsHGprzhjHR/bw
         ZkrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=AETwH0Wm;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WkniCDgpXv4lhDh9vcJgEx7efg2KhoCF3NoBNAn55co=;
        b=QRdt0xP10Rsk0HCqC6iQacdskUTLQBYd55wAzgYf+BXy5xP2D6slFnzH0bT4WrbeAT
         kU2/k9pUICIbinkTjX6CpRHw7TgS87HjuCgmSAdGzA8CZDVaujuDJ1EFIQeEsNPOVcCp
         jU8pOgdv5i9NZ1HhS9cKMGw2n89UNiYS91tTm4vTYGjmH96PppNgmvfsr1CNOyUrTHU6
         bAa5OpB1wAL97PQhVQz+W7j8NT7DRtGpX2kK5y++/T0vYF/CU1C9eTazJgvqjddd/IEC
         zcT3/XXHOIXnSQ42mONDvaa4jK9tX5/n80sJ0YzdnI2YvHtkji7wofLNqeMfR8KQFYnO
         bcFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WkniCDgpXv4lhDh9vcJgEx7efg2KhoCF3NoBNAn55co=;
        b=pg4jV9iSwde91dIy4OVVsHQ88t7DIHOWHMdfurBjz6bbNXjIEbnAquihyfu9C0dPu7
         aBDGybPWGeY944OS7ugvabeT8Wub0TfUbCR4Ou+pqx9JtTAGFTSkZN3Kzk8ehDSlmYn2
         ChfYh8uWeJpnqT5xKcDSLPn9RU7pshKeew9Gre9cUzCmOkv1cZWs3t+1MzVpuElrfiOQ
         /RWcKE2KwXjKduoCImJZ72ws71v0/CtoZfbUqKX8A+YaqUwkvV4LiLo8gHEB3JTPTaxU
         QoB1ZJS3s3PqS3UKMCMZuoG+e63oHpNwLzEkVYylTNDTehgdmrv4mRul3DOZNNJRmTsC
         R+SQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVw/57UlhUGGbt1Rs8C7u0ucIU+XxTEGGbma8Ty8AKGSn+iV3EO
	Zuqvez8TCHa8o2sOfXEgREA=
X-Google-Smtp-Source: APXvYqyyb9Rgu4kohFqn07xLvtMtRCm3vAtwANGDM2c50V/WlCwzYnW0eaCJK9c0ezT96fHaNKePZw==
X-Received: by 2002:a17:90b:f15:: with SMTP id br21mr17115623pjb.101.1569178307425;
        Sun, 22 Sep 2019 11:51:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a8c:: with SMTP id x12ls1993879pjn.5.gmail; Sun, 22
 Sep 2019 11:51:47 -0700 (PDT)
X-Received: by 2002:a17:902:ac98:: with SMTP id h24mr29072616plr.64.1569178307105;
        Sun, 22 Sep 2019 11:51:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569178307; cv=none;
        d=google.com; s=arc-20160816;
        b=MFg8IlwjfeC1TtcoCVKj7qUYKn+LEFIa10gj5VZV1LADdQTLLSc3Tn5mCMjZncnUtD
         XwC0B/yt/a0VwLuuJgcXG70VT9ywUr14JmxAyAOp0PYJl+bhOD3OyPmDGFmj8wj89t8f
         J5+8YRmd55QfKS1EO/veTvBBaQnwnX+/Ai5qaiNbKQCUUyRT0MneSmIQw3YapV2diraV
         OV78DwZ4Ti69dFXMURhunOOhreMtOWTGe/F6sWZglFAFwSEg6oarG7dOYWN9G5TjodSy
         GMZvsAA0gbdf5fSq2LtmnyZ/2GH3PTKml/m4Z0j6xUfqiIT4eHRdHDjFW6AstTJDTarA
         xsgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3htRQl954QmBuJyLQwasHk4KigwbFor2wr91rI3ejzQ=;
        b=AUdTsVaA5Y+l2pGddMZ4JUOn4rNIp+IE5VkdLyWWPH6QUVDovoB3v+DH94TJdGuPWd
         hBo/gwuDhIIEivTRDiPVF4NEsWNGA53PYhi7qjnbG3wskA2moS3D8cb5rIJi7HtJCuCM
         l2hNyWKY9DhQjjq8sULhATlCn+D00tz4cIZtKkAlrT2hLxh3j4/BWfLym26v+tuivHhu
         KOPme28bkVLLLBSMIkNMWi2ieMSYHVIptNSKRbqFbyrbygG73mU/nMkekVDkzenMz/Oq
         qO70G/owRL54BXGJY82XhBMC5piI1LygQHpoYS3VGyDJRuFstENTKQfKJyaCZBZ/XhS5
         INpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=AETwH0Wm;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m44si413756pjb.0.2019.09.22.11.51.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 22 Sep 2019 11:51:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from sasha-vm.mshome.net (c-73-47-72-35.hsd1.nh.comcast.net [73.47.72.35])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D59192190F;
	Sun, 22 Sep 2019 18:51:45 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Mark Rutland <mark.rutland@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Will Deacon <will@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org
Subject: [PATCH AUTOSEL 5.2 077/185] kasan/arm64: fix CONFIG_KASAN_SW_TAGS && KASAN_INLINE
Date: Sun, 22 Sep 2019 14:47:35 -0400
Message-Id: <20190922184924.32534-77-sashal@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190922184924.32534-1-sashal@kernel.org>
References: <20190922184924.32534-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=AETwH0Wm;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Mark Rutland <mark.rutland@arm.com>

[ Upstream commit 34b5560db40d2941cfbe82eca1641353d5aed1a9 ]

The generic Makefile.kasan propagates CONFIG_KASAN_SHADOW_OFFSET into
KASAN_SHADOW_OFFSET, but only does so for CONFIG_KASAN_GENERIC.

Since commit:

  6bd1d0be0e97936d ("arm64: kasan: Switch to using KASAN_SHADOW_OFFSET")

... arm64 defines CONFIG_KASAN_SHADOW_OFFSET in Kconfig rather than
defining KASAN_SHADOW_OFFSET in a Makefile. Thus, if
CONFIG_KASAN_SW_TAGS && KASAN_INLINE are selected, we get build time
splats due to KASAN_SHADOW_OFFSET not being set:

| [mark@lakrids:~/src/linux]% usellvm 8.0.1 usekorg 8.1.0  make ARCH=arm64 CROSS_COMPILE=aarch64-linux- CC=clang
| scripts/kconfig/conf  --syncconfig Kconfig
|   CC      scripts/mod/empty.o
| clang (LLVM option parsing): for the -hwasan-mapping-offset option: '' value invalid for uint argument!
| scripts/Makefile.build:273: recipe for target 'scripts/mod/empty.o' failed
| make[1]: *** [scripts/mod/empty.o] Error 1
| Makefile:1123: recipe for target 'prepare0' failed
| make: *** [prepare0] Error 2

Let's fix this by always propagating CONFIG_KASAN_SHADOW_OFFSET into
KASAN_SHADOW_OFFSET if CONFIG_KASAN is selected, moving the existing
common definition of +CFLAGS_KASAN_NOSANITIZE to the top of
Makefile.kasan.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Mark Rutland <mark.rutland@arm.com>
Acked-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Tested-by Steve Capper <steve.capper@arm.com>
Signed-off-by: Will Deacon <will@kernel.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 scripts/Makefile.kasan | 11 +++++------
 1 file changed, 5 insertions(+), 6 deletions(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 6410bd22fe387..03757cc60e06c 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -1,4 +1,9 @@
 # SPDX-License-Identifier: GPL-2.0
+ifdef CONFIG_KASAN
+CFLAGS_KASAN_NOSANITIZE := -fno-builtin
+KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
+endif
+
 ifdef CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_INLINE
@@ -7,8 +12,6 @@ else
 	call_threshold := 0
 endif
 
-KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
-
 CFLAGS_KASAN_MINIMAL := -fsanitize=kernel-address
 
 cc-param = $(call cc-option, -mllvm -$(1), $(call cc-option, --param $(1)))
@@ -45,7 +48,3 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
 		$(instrumentation_flags)
 
 endif # CONFIG_KASAN_SW_TAGS
-
-ifdef CONFIG_KASAN
-CFLAGS_KASAN_NOSANITIZE := -fno-builtin
-endif
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190922184924.32534-77-sashal%40kernel.org.
