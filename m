Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEGE3H5QKGQE7HT23FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id CAF1E280AFD
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:12 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 140sf53921lfk.16
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593872; cv=pass;
        d=google.com; s=arc-20160816;
        b=wWodtNAsI+YCuueejCja5S27vwJXbWOAG6JpgaIdR506KirL8pgWU6G/0Bi6t4dAE1
         ANhh3vwkOv1Ixu5Zh65lZHyt5XhxaYAYYog6D6MEn+HbSUQIxgrmBHxgfoJTFmOPlzOF
         V467ZYtH2Wq69BBrgM4PtvMg1rQoFI+q8aOu7poVjeokWW0kcBdODSfHE2bvnwAnyxUx
         fhBvWlfniT5qydjH8UYiypcBxreAZnqq/Mia6m8Sh4uVXrmumJf3H3VuV1xQHQ9uGLaR
         wmuSfG183mJqXc5JL5vGSeN2aDxHUcIsdofBzZdCKNYUAEhVK3p9ELwO9lBVSmYtcj3b
         ERnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=O0ZSB6YEo6nhRmapkTv7dMUR/vy9xt1jBcOIeG+jgJ8=;
        b=W+PAdHKa2zvmcqXYq4op0k0KUOc49JHFEE8fjlHC9mSatslwMpnvMl9moarmztHxjG
         y7O/2v/kUGG5Wv+BqZnBXFGldag9VwlpXpy8VSKoU1CHHXa3jRA/qD59HwY3QQpqaCXv
         Qsx+i2sgMe6vGqJV005ArWKaLKmQSclbi2YELnyP4JLbiT2yVI+m7ymzuNmDYrnFjTZP
         Y26yN0pShSjPO2u7u12SrZbznHpJex9UkCB7fdEKMKcG/X+noQK0u/AIJw7GS9Xmxopj
         HFzLgsa/KM5hTrM4B0k10bzMgDV9tpQZItzLWfOKvQpfWCmxWD1O+VJnMvXGAjP5iulg
         uYFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KR9aH6cO;
       spf=pass (google.com: domain of 3dmj2xwokca0naqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3DmJ2XwoKCa0NaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=O0ZSB6YEo6nhRmapkTv7dMUR/vy9xt1jBcOIeG+jgJ8=;
        b=FnLxMkcY5IFKfUPvYs+NgwsteCQNBQ4x05JS8dFmJyt3Xc01VDaXPlR5QZnSCMkQ4M
         NJ6ko1TFgPWygE/coQqrEb9zf43xyfz0YACflVOTrn9Y6zNnQu8ZNNvD02D4zpReDcd1
         oJmUWiBM97fQ8aFQibATmqzHW7lV2AiwZpVyrao5MaMDfxUZNv2nn+907oGHM4YdT/lp
         C0Ng/0xYwhGePOrP7PwStxcTnmcE6VlKjSsSbi/XKfoSPFCabPrb+HJ97Az4pUAenAaV
         y0GuJmdY3/EPLP8njoh7xYaqbVFDfCm5pb/Hgpq5EfzEanhqbkUPILjKUmq1v4IoC8ao
         mXNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O0ZSB6YEo6nhRmapkTv7dMUR/vy9xt1jBcOIeG+jgJ8=;
        b=s8UG5PovJ8hTNXb3/T6NHzJ/4oS8Y8vERV481MQxMKIvCTcK/UmHlPZSJxL53oaUkx
         Z7JlXuzJY0d6V1zUNBaJuXMUu8f/c+Xoh6ZCoUzy9a61SIiJFyfVd1XTMcOJN68z2hA3
         m9BHHI5IFL4rPzwK+EW4WGDW0WV3k1Nsr/rcJR79Zkv7ANHho0LJGY35cj1gWJb08/d3
         L1TwD4OcqOSwqGfI1mgv0vDs/Sk4NMufoYe6qB81/7hDJ59Fg+u0rMnBJ9yoP+emn/Sk
         t76wZS5i54L7FG0AX9gCx0aBsXJZ2H2FtO5gTqTV+t/ulgqV1+njftoiY42o+Ilo9INo
         3yQg==
X-Gm-Message-State: AOAM532n/z0ITM66bUnM6gG1ISIaj7yewAtYPgh5xkZn+Va89k9dRIbS
	PTE3o4msP+ENmZ+GnFCp+wc=
X-Google-Smtp-Source: ABdhPJxuaipCcFIQvrRHUiWIVxIc9QER0EXuNo4PG0a9o21OUw+HClMDf0UopwjNyWKk4Bu7vTd0qA==
X-Received: by 2002:a2e:9cd5:: with SMTP id g21mr3113419ljj.27.1601593872380;
        Thu, 01 Oct 2020 16:11:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7c08:: with SMTP id x8ls1069355ljc.6.gmail; Thu, 01 Oct
 2020 16:11:11 -0700 (PDT)
X-Received: by 2002:a2e:a41b:: with SMTP id p27mr3224514ljn.75.1601593871314;
        Thu, 01 Oct 2020 16:11:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593871; cv=none;
        d=google.com; s=arc-20160816;
        b=fs74TV5tZLVLe/hL073Ueeh/zdvccLGSBnYhplwewP1rIpg++VCgz8P9R93XZrDLzd
         JXGTcpwL7ri/aKxomVHYRd13eO8xbaYoyR+mvwbQ1FHm7P/0VczwdZ7kE4gXjwSNpKic
         E9DxM/FWoFRXMK1Q7ktOcWaDK3+9nnYL+d8PmPMin7CchlgTQvzUZx9d4qW27TmsY+7V
         aCTc8DnO5fS+EDxYJksuLDaQItBYYJKcV+8WpE5JBE5G0wM6kD95BVec/1a1dPI4jJwa
         Ken3gBbPE7C4wnQhnqaTFSFuWtMOs2AhD+dmCdcfKdgNWuoIstN9LvVMgo8Dz1kfkKqL
         xH6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=BiBwOA300QhxWc80ZJY9u1KximGsgeGOJ7BXhwr4DYI=;
        b=DNok0XeLVF1Yok4WGK37dDp9v/txmfBqrrj93v2WkVL1NDcbkgMeOdTrsCD8A9wcfS
         k93M1fbRJg6x55No3InwqtT01XsSUnUAebm9DGjFAenGDqouWXIlZ2KKlQuthX0Kq+UK
         Ca4Wg3zcC7C8///9cAuH5qDBBBuM8dqTNRglkNIbYVpaL2C8X7Yc2c9+yjRR9E565ul8
         eJMZTqxjK8ge8kFKGN5UdvQ+huBtbUVxyQQWLywSI1AsU2qZEgpTsV0LaSJeBKZ1Y2gI
         DXJd+vBDYxfj6Z+NiHhGxSrlqN7+PxjXLhIrl8ubeapbh1dORTqKn08ksKBT/zk22GfD
         2kzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KR9aH6cO;
       spf=pass (google.com: domain of 3dmj2xwokca0naqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3DmJ2XwoKCa0NaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f12si206138lfs.1.2020.10.01.16.11.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dmj2xwokca0naqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id d13so110762wrr.23
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:11 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:f009:: with SMTP id
 a9mr2285015wmb.158.1601593870620; Thu, 01 Oct 2020 16:11:10 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:12 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <9bc9adc49d90831aad292b1927cac60570380d2a.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 11/39] kasan: don't duplicate config dependencies
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
 header.i=@google.com header.s=20161025 header.b=KR9aH6cO;       spf=pass
 (google.com: domain of 3dmj2xwokca0naqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3DmJ2XwoKCa0NaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
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

Both KASAN_GENERIC and KASAN_SW_TAGS have common dependencies, move
those to KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I77e475802e8f1750b9154fe4a6e6da4456054fcd
---
 lib/Kconfig.kasan | 8 ++------
 1 file changed, 2 insertions(+), 6 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index e1d55331b618..f73d5979575a 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -24,6 +24,8 @@ menuconfig KASAN
 		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
+	select CONSTRUCTORS
+	select STACKDEPOT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
 	  designed to find out-of-bounds accesses and use-after-free bugs.
@@ -46,10 +48,7 @@ choice
 config KASAN_GENERIC
 	bool "Generic mode"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables generic KASAN mode.
 
@@ -70,10 +69,7 @@ config KASAN_GENERIC
 config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables software tag-based KASAN mode.
 
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9bc9adc49d90831aad292b1927cac60570380d2a.1601593784.git.andreyknvl%40google.com.
