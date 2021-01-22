Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBW6GVOAAMGQE7RBTSSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 76C353005A0
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:38:20 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id l21sf2612133ooh.8
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:38:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611326299; cv=pass;
        d=google.com; s=arc-20160816;
        b=hX+MO2dAFtx7OpHsIHiQdMLcyr54sGGjIB7gAtPI0QTFfplkzClMo5y0zC/d96kI8w
         qsLLIgdYsJkEhfGhXBCDKkyg+nWTGA/UQSA58wvTrzUnaILJMn4jVXKHZ6GHLE1P1u/q
         MjGBKs6cDvaC6X3yHnb2T+80rTMkxLTcoNiZBqfe66ndWgJJ8lnznYBmtNi4Dp0VyWmA
         db1+ShCVit2CrbZ6atXPFC/ibUh3oIt0zCLCgyntJoRwnKiRwxces6R2E/rwbXlCkkXj
         UkIXtc820B95pue6yU18g4xONAErPi3x7V/wa906LRFrT26jR53iKJabAH153Mj4OUAA
         7O/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LKLanHQKb9eF/nZp4LMpfECgnejXYsCfInjBSl1vPeM=;
        b=vGZ/VYciw4fLSXY2Nu3YWdXYgayJ79Tgr762j/wEoIZZn/dDrQxnZlWD+VM4Rq77Im
         grBJOIQzMLk0Mq7d3R0wpQwH9VcEQUBRCOXcA2WS1HHIIdnFoYhdrv6WaaGB6a2ik6Ci
         SYBTvZY5yexH+14+sGpa8ZqljzeI8IJBmbgfv7acSqR6bLE3aQ1tJMr+F60AXoHZI8Jj
         vM7RmuUukq+RcstvKY+ySZfTcsiwmaEFz/MfCtz+lR6vyHLOd6quMgpvUpmei23BiD5g
         KdH+jK9Mrn0IxZbvSTjl5jOVztyvOrSj76sYJJL8ulBsQhS85zuDi6gSPgqKosJKVCkU
         8qXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LKLanHQKb9eF/nZp4LMpfECgnejXYsCfInjBSl1vPeM=;
        b=ln4RXSk4Al7C6Mu4rGBHCRUT9ZKFJZQkcgqF4ZI108q/I6DoFWmjn6FHrM0HPJro8r
         Mm8waYv6BN+VYSSM5NrSruOAJ/kc7bx9axnoOEd259d8V9IynqTeK2mc96Y/9jsS6fYc
         mDlbBJpV+cCFaACy+8KpB1z8qLL5uq/hkkxycVb1WRczNfp75qdBLvDIG6tPF9KBQA3X
         AhrioN1zzmijGmF7Dw8DUn9TI4nNWUUjCFM3IOKUK7IOrYsoa9n7xc5Enkj2NsDycZBL
         v4rEOVzBCIDlDQvTfxyr/CEvamN38qH5vsupcLwX2RMjkX0XefdM8WXaV9LSYLhtJgLL
         bdGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LKLanHQKb9eF/nZp4LMpfECgnejXYsCfInjBSl1vPeM=;
        b=YM31Hi2z2Grwv5aViqD1lJ8wb6587GfrkmetmG61Eq4w020ZeHt0pgEJXD9wwzHtxC
         743IcaU/4N8ydjjlYP0YBnz+FoMsP5aH8BvOA2OAyfsKB0F+ZrBRDXGycXtQEeJ/hcXf
         rAtZQ9D8bJTXPNYhB66/iGtrstJm1YYEUgf8xMlA6QAnLz2lhr4ltpTXKw4awNd4frhw
         W+9+gW4akQUunt6ohMgrvTYTcPlG91cVp8lUHDt2XCGsAolR9lPFZR1ru2K0SGZIREtv
         tD9+nab0/wt+NEAv/Dwtt+VugcAqyAP1qvzHdJMJn/ByniLwM48PY/jjqhTFEOTGGqIs
         lSfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530rRoz0VclB2RNr3gAuOW7TXKGK5vEFy+8dHhOwO434yOy7qiOa
	0v/bQ19k18UoOClQOfvNdDw=
X-Google-Smtp-Source: ABdhPJzLqB4E2n2RZCmlYD80ruopzj7XiEn3u/R/zdlJrwsYiyBL1VCt7Np9ueJOMG+eWqXto91OLg==
X-Received: by 2002:a05:6830:2376:: with SMTP id r22mr3557003oth.274.1611326299239;
        Fri, 22 Jan 2021 06:38:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cc51:: with SMTP id c78ls1534284oig.5.gmail; Fri, 22 Jan
 2021 06:38:18 -0800 (PST)
X-Received: by 2002:aca:db8b:: with SMTP id s133mr3387712oig.27.1611326298929;
        Fri, 22 Jan 2021 06:38:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611326298; cv=none;
        d=google.com; s=arc-20160816;
        b=JOlohbIemEF44cfVM/i3CM1hL4OQSq33dgpSY2Gb5ilbd3FUMp4BsxD1pc+f0C2F6X
         9ehscI78j2jIA+0bcXwpkVVDL95qoaRyzUaWxD1cA5i/CW2flp1M7rgfNzQfJavWCLA2
         9MoY8EWwAyLI9mP8CssEmzxswPuRdDQ0chWgF2NIU0+JvBlAuAPCohErPMC2A7VPB/uV
         fSpRu5Oyep6J/5nI8lufpYV33gicnVWcsWiUtp8uMsaf0tpM+ZEjWbi75arvFUFogsbW
         P9IK163O6/K3s0gv337mCi/GJ7BVO/WJizRFAEKMx9ulRXrljHnXWTIfAlq5Z+pZwqXb
         ChVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=91vGtqoWM3+RA37FGock0tG4dsCPUxVlWzSDrNe+0Y4=;
        b=FvpDOWKiEI6V0YOXk19ig0IGhegkBuJSE3Vl1r4lvABCxW5kavSf9l09ReCq/7etpn
         9M7gNDnTJWYyw3Oz/icB66o4xmlKYhdtu+tdmaDwUtadjI1eYqwX/hNrBfGcGVslIKTv
         CosqGyUvj0KTXjLCfoRj1bnc3tChdIro5WK5dW8JZmHt5uXw1HaR7HGxaAuA3TwDk+x6
         8xVDX7O8cJuA9lfyz0AMvGR/xiWh13dKo3zuOdKbGU3dfy6b2O0KZwW5F+TvmTSfQ0E6
         cLBDPWh4RSR8I1d6bPRdyI2mdwmq3BJ5ckNURW5RURJE+3e6YDViKDbInZ4+GMystqj9
         m+FQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m7si537516otq.5.2021.01.22.06.38.18
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:38:18 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B61081509;
	Fri, 22 Jan 2021 06:38:18 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EDDC73F66E;
	Fri, 22 Jan 2021 06:38:16 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: [PATCH v3 1/2] arm64: Improve kernel address detection of __is_lm_address()
Date: Fri, 22 Jan 2021 14:37:47 +0000
Message-Id: <20210122143748.50089-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122143748.50089-1-vincenzo.frascino@arm.com>
References: <20210122143748.50089-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Currently, the __is_lm_address() check just masks out the top 12 bits
of the address, but if they are 0, it still yields a true result.
This has as a side effect that virt_addr_valid() returns true even for
invalid virtual addresses (e.g. 0x0).

Improve the detection checking that it's actually a kernel address
starting at PAGE_OFFSET.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h | 6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 18fce223b67b..99d7e1494aaa 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -247,9 +247,11 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 
 
 /*
- * The linear kernel range starts at the bottom of the virtual address space.
+ * Check whether an arbitrary address is within the linear map, which
+ * lives in the [PAGE_OFFSET, PAGE_END) interval at the bottom of the
+ * kernel's TTBR1 address range.
  */
-#define __is_lm_address(addr)	(((u64)(addr) & ~PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
+#define __is_lm_address(addr)	(((u64)(addr) ^ PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
 
 #define __lm_to_phys(addr)	(((addr) & ~PAGE_OFFSET) + PHYS_OFFSET)
 #define __kimg_to_phys(addr)	((addr) - kimage_voffset)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122143748.50089-2-vincenzo.frascino%40arm.com.
