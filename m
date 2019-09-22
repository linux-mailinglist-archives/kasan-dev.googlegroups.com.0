Return-Path: <kasan-dev+bncBDTZTRGMXIFBBDEDT7WAKGQEYPNGYJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 36539BA3F1
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2019 20:46:38 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id b204sf5673522vkb.11
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2019 11:46:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569177997; cv=pass;
        d=google.com; s=arc-20160816;
        b=EOVEh2bK1/hjt9EWjCxWz1DkTbptOQCD2L223vKgXrO3vPhElFeUjIthqvuISo93p1
         TNmYbngk8S0EckvBUS7AToBiCb/xRD8kNHXFRWXhDCAocRuyJrpx87CG0cfy62P2TwmN
         R8jkJFwpLuzxlvTA8A4a5w6+0DS4aIfOb+KIOI3o0k0MR3QUk02swZME/P3bPwHsNaYx
         yzvUYtEI/vANF26BMWBDX24j++g/Vjy2g5gbG3Lz/vNQWNkGnhQrGs3f942xa5Y1PpZr
         7aAsyzqxpjmg7OH3gxuGVCkS92evGFRJ1QjA0y8+DJetW2kqZWukhj5wxYLSxXA8PtSx
         3Qrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jRRGoRXMb3r488/bJrdGZ9Ef2w5+wrsx32x6ZGdjCpc=;
        b=N0ic3XyG72UhVUICQ+SknGT4DLwRCliNBPW6kFPf97+LJCb2zSrBqVxVcDxgkIGI9+
         JiAjbssA5VAImF/NspnC5zf3Yg0327L8f7HtUgElrRI3gOX344ibIZi0O1u0KxiwUTpS
         2ygyVQ/v4pjTzySSSirbH37f+qKBsTHsGdWBOFncXBcPht8FsYXqTD4JSDWO7Dp+wPmk
         hZ+/0eQsv3pLhEGDsLJEsDFfNIoMC5I7dV7JAbuPlXwIUTKXWOShkKg42wheMER0d1ft
         zGZ/ce7eaEQXeG0q7XqMkFikuMIi3AI2vqj584CX1fCf/tHGZmoaWGGbes3wEug+I/6k
         FLlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fkk5uMMk;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jRRGoRXMb3r488/bJrdGZ9Ef2w5+wrsx32x6ZGdjCpc=;
        b=ivegBE/+JBAQ2AgolieZ0xxgQeRQ7azBWB4nibWYROoUD0f5vueFdshj5p6fINzw5X
         J9BNu0ln4Mm8MOvIllxHJ02d6gE4CbWB4ujqSdrK2mM+q0uVZbJ1wW3KbqPcolUs8A0A
         iYJwR8TsLzzCNHrC9KL7eN2zhT3H2Pu8Y7yIYEP1YPyRvotQlGlkem31qf9atslCBj5s
         Jr6n8Xc2gtr1A1qUSTHo/UgFGa64Y6YN1zVpNYTvVYX6Ytnv6sMnvLydQZX8zzmOcW5/
         IyTscpw1XmOXBqG+UiJB+NaHGQzlaBxRerTmgagOHNsUd9A7fW6SKmxO85J9RbnMJ+le
         MDTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jRRGoRXMb3r488/bJrdGZ9Ef2w5+wrsx32x6ZGdjCpc=;
        b=ildS6TNQ8eMvsY5FHHeYQPhK1YoxfIrw1q3kA4fMwgGgXydATyXwBP2rq3wfjvepTy
         WROqijq1jqrfiP/ZyE2K/zmYhWnceJ07Qv279094V5qprI2K3Mtp/L/IXqtHDWwH315K
         MxmjcmuD30cZw7C56+3ZGD2t7Er6JNUlLWf4Y/snEhdPyxtSjTd7UlIleTKm+CjVoS/m
         Vr3V1XUm3t6YTh7iDRTCuxQiXe0p85CsmJhN1dvdP5vm7/cQBYvX2Kf3eC2jpVV3g5yJ
         1Ykp/MromKrWoks9QvJ6Zc6tprqxwCmw60KSckHP/A8W9omydvNL9V3lK+Fw7Twqs6s8
         4/iA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVkiVl10xqNuApSVgc9tOzb3ttMFcTgagCNSQpN6UqL0RQcVVti
	CHUax6cKK1kgaJa+IlS6EP0=
X-Google-Smtp-Source: APXvYqwjAVkVq1RyzaOEyeP89lf3iEIkfhwt+tBZ35yDD3Fc3xR/GwefYc7iO6WGs2N9In3gRdgE6A==
X-Received: by 2002:ab0:164a:: with SMTP id l10mr5376877uae.56.1569177996870;
        Sun, 22 Sep 2019 11:46:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c28e:: with SMTP id k14ls1249586vsj.3.gmail; Sun, 22 Sep
 2019 11:46:36 -0700 (PDT)
X-Received: by 2002:a67:cd87:: with SMTP id r7mr8489583vsl.59.1569177996634;
        Sun, 22 Sep 2019 11:46:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569177996; cv=none;
        d=google.com; s=arc-20160816;
        b=jOT36uQLIFV0sJydrC5IT9piA0BWlWBYCnqS6cQ5IUp8sLr+Z5FvQaXhgwpYpOf2WA
         zkIrT84RBylMvsxRt3EK286L621GL1fTx5Yzrf1Lyk0YQeOmKj/aadG5FvbZyV+6+4Z3
         rYtY8QL210eZI6rwr1X0LSWkqYAgrXOOQFC8LcIJLKT39H1CNocV6ROS7D21DeuaqTQ9
         vjnsxAT5/AO822WaFtI9SOW+MwtzSW5ZHvj0zmAsaIAlKmtImtCyGn7snmZHmwBy//MS
         fNS93QhTsNRBW4jyAIf1Hc+AvToTJV2tRugyjtnhtPFdsSPcMIyjxDD1X6y48YrLBvA/
         0Qkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3htRQl954QmBuJyLQwasHk4KigwbFor2wr91rI3ejzQ=;
        b=E3IywJCzSUTAte67BB5jMSF9gngwnvaYb9jl/YKek+eh30Xv+Dh44LvAW+e9CEqVdd
         PLpxGp6uZ+9gNuv8yXP1GspOTBKJZJq/lVQ+han6iZNF8GyElRlDcfvDZAUueIrlrsKd
         dWE6+BXOMQMZXAEmAv5gawEKyb8S1Dfig4pq/XaAiMKrYqUFbp5wn+4Ax+v8oAAW/BrE
         eq/GMWJ4jG+jkiVIbJS4hTKaB7+RT/jheurTp+3MhGPwn22xc9Z+8tsIIFj45rzcVgyP
         z8Ssosavfs96vI/J0TaIN0I8sufk9Zxn6D+CB9QaFvDsNfdHX1zgeBQbW/5URlXMDUZQ
         APlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fkk5uMMk;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k13si249981vkd.1.2019.09.22.11.46.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 22 Sep 2019 11:46:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from sasha-vm.mshome.net (c-73-47-72-35.hsd1.nh.comcast.net [73.47.72.35])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 88E3320882;
	Sun, 22 Sep 2019 18:46:34 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Mark Rutland <mark.rutland@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Will Deacon <will@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.3 086/203] kasan/arm64: fix CONFIG_KASAN_SW_TAGS && KASAN_INLINE
Date: Sun, 22 Sep 2019 14:41:52 -0400
Message-Id: <20190922184350.30563-86-sashal@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190922184350.30563-1-sashal@kernel.org>
References: <20190922184350.30563-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=fkk5uMMk;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190922184350.30563-86-sashal%40kernel.org.
