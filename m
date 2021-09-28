Return-Path: <kasan-dev+bncBC5JXFXXVEGRBHO5ZKFAMGQE2Q5JRSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id C5B5B41A78A
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Sep 2021 07:56:46 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id e5-20020a656885000000b0027e0068121fsf15041753pgt.16
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Sep 2021 22:56:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632808605; cv=pass;
        d=google.com; s=arc-20160816;
        b=BaYwGndWGgIduMuRFEHJy9BRW4KsdNlWxZlUDiHGjQ5/V3ExFZoKcpUtvHJg+5Osh6
         kopAydvqd5GDeplFS0DQckQ1HoBJRaLextZ9IfCYiHZo1GWiScTHy1e+gVKCFc3Qi6M7
         KlFdK3o6ce0kEsoBPQhdcwyowOxyzkY9LAe73AapKu5ca2uVl66YLQqcW1WQa6tjVwKg
         CVq1GEeTRNV+w8alZsDHpeOKy886+XNfzMhC05wj0ojZRUN5DVLbEq1l4W0TfouNCED+
         +j9MFfDfdkeM3t/3CRH6//x1C6SgSDxKwWk/MCsfELarMNlLOxhapXYkLnVc3bXPggyY
         ACRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NP8d8h9n84H19g6Cy3tjWiFhp0H0Tr9/iDIUrWVgOs0=;
        b=fL9STPwbcXfvwaVZ0p17nRNJ77ipaPaDSe/2EVFwew8Mg3Ec/R2oWKsm2o4scQ8erk
         71dQRcN0QOppg7zj5XZe//FLRwYCWa4AR3RcYNy8IsiDxiSo3Hlho38LQIC07hy4yznQ
         4lRnmK42haCCAue53uPvkyStM0Hn8rlxkVzCEhcZLlMyclv5iW+oZ686ZHevE5bzJWfk
         ES/fH4fZfm76seovK5Vh2o6sdckzrvCAzSuRkXmBIkCPIe9RGwtOvsrQ7ThYpmw6Y2k9
         EwBEEjCoNjt84hOmzPg142XMkKDRr+OsoMxukjKi7Q9+WR6toBvEKzTO8V+B5BaLpi55
         mr0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IDbTbR77;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NP8d8h9n84H19g6Cy3tjWiFhp0H0Tr9/iDIUrWVgOs0=;
        b=Wo0j8itVQxm0lMe2KVeGnStLcUmqYjSRAVW3P4yvnrx6FThAwXwVv4+wgbONgT6L1a
         M3Y5XyLcGsAqVNAuRvoZCGX6JYfJfl7sLiLPcpbvZpzCp6rw/o3W/gd54ao1Ae3H4T2g
         wQcjts5dcL4bnTvBtpXErH3UqRWzApwUCMBNgy9UJ53axTRyA6QNyLyGgWHm2AyQJmZe
         WoYJUYwYNPs3LpraXpfgmF6C+zRcn66SRQIpeX8A00TAAA/c4tvRoce7ljieVGd/Gdb0
         sHxupXgC6Pqrn0K3mzwz4Hlx2K1WRbVRm4H7HlZLKg4ANOXEu+3gTZd32qHhARB5xsBx
         Crog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NP8d8h9n84H19g6Cy3tjWiFhp0H0Tr9/iDIUrWVgOs0=;
        b=ELy4nsAo76fir0PQj87B+Fnsz6J5OaLP0iDR79nbB/EN+sUSosJmoqQuLTJF+XXq3T
         Qt9ifCoN3S+n338xxhXOpIzVB3XcY1gBJV96qkO+QqWCANTQnrta7ubCMFfYeCcDyubp
         L5ZZxjYkV/EPSIsmeyue27YpQTzpEBYVLaWfekf3xv2GbUu57wW4U876N0ntTMa/LSfi
         V1MmB0HGJG6U2g2gWKo10lqALD6Yv/9uSd/LcnrdJQR83Q4Bco0LDA39W3TZoJefoSki
         THnBEqD4Auhlo1GUiAwaEqtws2xs7fxJhmD51zc97H5RP72jL4qVlmTBffztEcS5kocR
         zc7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PyhUA1JVTvtyGGGZXBgdIoeifl9YVNVFvXx2tvYSO6+IPx+jQ
	MQoyt78qiNa1py4G36eIjdc=
X-Google-Smtp-Source: ABdhPJz5hberdqw335zmN7Kx5D4GW8njGxVb0MLX3tLD/vjtEmm+ykcu0rzsSph0jNzK5/hBR3pLkg==
X-Received: by 2002:a17:902:7c17:b0:13e:2dd5:e5c4 with SMTP id x23-20020a1709027c1700b0013e2dd5e5c4mr3626206pll.68.1632808605127;
        Mon, 27 Sep 2021 22:56:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2e8b:: with SMTP id r11ls1075219pjd.3.gmail; Mon, 27
 Sep 2021 22:56:44 -0700 (PDT)
X-Received: by 2002:a17:90b:d89:: with SMTP id bg9mr101281pjb.165.1632808604487;
        Mon, 27 Sep 2021 22:56:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632808604; cv=none;
        d=google.com; s=arc-20160816;
        b=RbEM0DIvp9ZOhqcNxHu5P20kU96WLypSvEnG7yuTnQ3KLgIy/vdspih/BayfRKsXDg
         hujaWRF1vXlU5NykmyKtfEKLPTSb1Gjn9aq1pnrWZms65jnOLOJNTQE8NghhzA48pOGp
         UtsFnyKqKmpPMMRgxYnaFaoegLgW5FbMQFHWikwaXCMSvXpO2B7arZnA1+eCoQtkeQ9+
         jOVL0UENlOsVFPOSTK/zl8Lt9vcBONwcVmkj/fjfiTanh4CdalZyD10ezcVzHGj49Hil
         JgjJtchp2iEFU4CrOUADXNCu+CH/eICL3MMAwdXR3NtxLOGK2FlDtKSkm0iF3wiKzRZW
         Ak2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AZzpyU8epQ30RViwQOicHU3v01xLOM44w+JvTXvxA0M=;
        b=B9MdmhD1GixUF/DmO5+yuPdAsDV89JP2UQMz6oIlgY1B9cUZHkiRENUk3WbM9Zaz9k
         luqBIFZUqTwbehJ0TldOnRLJWqeXSFdSO9DIejIrWm/j5wZO7Cws2VdYHDCiJRv0KemD
         QpMcT90pG8UY3RqnzF7cvwuF8/XWVr0cQ3L8NpJWzbT5+dc5ekwfcswJIdhMOQ7ox1uk
         V08K2w55jFvN2403WgZTPhO9PJH9fY7eJrB4vwr7bNFeV3LB7nDq325nUhn5rl01iBe5
         8j2VRVqBx1Ci0dyvTzPWnqY27tRIF/LlSADvvJ8umfWewvPblxOCHBdgZ5nF6LWujCc/
         9HNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IDbTbR77;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id pg5si343715pjb.0.2021.09.27.22.56.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Sep 2021 22:56:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 1997461266;
	Tue, 28 Sep 2021 05:56:44 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Nathan Chancellor <nathan@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	masahiroy@kernel.org,
	michal.lkml@markovi.net,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH AUTOSEL 5.14 40/40] kasan: always respect CONFIG_KASAN_STACK
Date: Tue, 28 Sep 2021 01:55:24 -0400
Message-Id: <20210928055524.172051-40-sashal@kernel.org>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20210928055524.172051-1-sashal@kernel.org>
References: <20210928055524.172051-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IDbTbR77;       spf=pass
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

From: Nathan Chancellor <nathan@kernel.org>

[ Upstream commit 19532869feb9b0a97d17ddc14609d1e53a5b60db ]

Currently, the asan-stack parameter is only passed along if
CFLAGS_KASAN_SHADOW is not empty, which requires KASAN_SHADOW_OFFSET to
be defined in Kconfig so that the value can be checked.  In RISC-V's
case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means that
asan-stack does not get disabled with clang even when CONFIG_KASAN_STACK
is disabled, resulting in large stack warnings with allmodconfig:

  drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q02.c:117:12: error: stack frame size (14400) exceeds limit (2048) in function 'lb035q02_connect' [-Werror,-Wframe-larger-than]
  static int lb035q02_connect(struct omap_dss_device *dssdev)
             ^
  1 error generated.

Ensure that the value of CONFIG_KASAN_STACK is always passed along to
the compiler so that these warnings do not happen when
CONFIG_KASAN_STACK is disabled.

Link: https://github.com/ClangBuiltLinux/linux/issues/1453
References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-8 and earlier")
Link: https://lkml.kernel.org/r/20210922205525.570068-1-nathan@kernel.org
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Nick Desaulniers <ndesaulniers@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 scripts/Makefile.kasan | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 801c415bac59..b9e94c5e7097 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -33,10 +33,11 @@ else
 	CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
 	 $(call cc-param,asan-globals=1) \
 	 $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
-	 $(call cc-param,asan-stack=$(stack_enable)) \
 	 $(call cc-param,asan-instrument-allocas=1)
 endif
 
+CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
+
 endif # CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_SW_TAGS
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210928055524.172051-40-sashal%40kernel.org.
