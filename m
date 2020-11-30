Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB5GJST7AKGQEPQ2BLPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id D367B2C8A20
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 17:59:33 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id s135sf4442515oos.3
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 08:59:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606755572; cv=pass;
        d=google.com; s=arc-20160816;
        b=HnI6tD6TBpFejp/Z7SRxWhw74T/PTnY3xKa6WWMYmnhBAYboi5HJVP+1zg053VHEDs
         gAjSDNt/GWVVTnyTpfMRpyW6TpY0lSm/gF9O71APkeCQHm4rBRtrZTdJZxNbM+ec4alA
         H51swQDiiY3hGTdWg9s9jTtI6mqhRw7lPHkO4IRyaF+eLFaotpQnwM76YjULq9p2/b56
         sUGTfhlziOjDh352+ROOFgc+Gp5elTBBnRiXSHvhTx/cnJPmWcanof0u96htdtAiZt6Q
         b5Vb4Vh5W1bRyg+OTrMdhjqsLPtKKsCjnZmavWQpxOLpvzKDt90VbTH2n+BkArhk+eCp
         SEEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=w8vCRUewND6LByErS/A4Bniw4EkqQhi4esyYzwn+UbY=;
        b=qXjD67eOSarrbIGB5dkWrP6RMl4ehFkeN6UWqqZRfuIdP/vrLoDS/jYNQyn8tHuWEd
         mk+cOn0g6XCxY8FBobGO86k6nvNpFFD39fGftMZ+0NbTHbCLBndxJFejFgP2FwCajuqf
         6AYY+JRZs1ZX7D8qlKrGBMxvM/O8t3ukbzenSkCKSiQkjVSQmnUg05dLxrg7L2OdDJZa
         xexFSJTE5WuYe+EEhbHzxn5fB3yZIQWWOBPp/vHg9B4WRB8X9mxLZ6N967vBt3rYtwtE
         vtRaZWnvLbCJh1CrCwl53VcAW/FtHA4tRdWxnv4lygDPkWoe8BF16WPTEjH1ujWZ7drT
         m/kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w8vCRUewND6LByErS/A4Bniw4EkqQhi4esyYzwn+UbY=;
        b=IYHJg2jb7fZUX+nfGgccR2coOYIKAYK0rf+pve/yAcVBIcDUJJzfl2x4WiYw1UsFzM
         SV2SDb6AeGW5NEhDBy8RR7bdURHV7gVzPZgV9Ajsc3MCg/O902O0IP2DHbycw00J/XpY
         Wghv/A/im4EgV7Lk4p2N5mUSlqw1ilmkMYK/l3vUDucxBA5JZlnf5ZGarjKDxUQVpc+E
         EehS3mslMYb4TjYSDr13F3wQd3XaIlOPXyMaFszQKkoDiDiADNWSYfvkHU07usMa4foM
         4QmsBx99CtuM32NJ7fPTagbd36GURE4EI1BNBiJxkJTRXYRa2dnY5acXotAXQlatvy4+
         r8bQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=w8vCRUewND6LByErS/A4Bniw4EkqQhi4esyYzwn+UbY=;
        b=KlXToJ8K4gj7tmtP6GO6ub27AqvqysiuivsZzTBXc74E5x1+FpBI/4qHZvkJjedMto
         DNI4LwN6HYp+fQBGLfpMPWzZSm18sG+rf6XAaxVyeo5y8EaUmVWpfCTpcAXU/zOUcxl8
         iPClDk42dUvLpu80Fj0YtjrMo6WEJgtgLky1yLlPk0b2ZNgWdo0n5VxvBvnzsIrpOYXi
         lF2KL/3/nOYZLHaXtIW3vagKM82nBoBzQgLiXg8IDQ2d3U8AFCREwQ9DN5WdCBqe3qGo
         /deJ//HhuFPj0XSrlC3B4X00SVxlZaeen8EZDqoZeHWg6VWUl98TY8VmUniknJbHkFyF
         3U2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530eolhM7foLTtWHK31ZhpK9SpOWUQtpcJsevYUvEGBT/knMkRh3
	j41kblzZGiA/CiwiX6vfb98=
X-Google-Smtp-Source: ABdhPJwVv0m2mhysiBQdKTpXkWk5t10QOQohfootkn4KoQOaMAvGZaaDziTgcL1P1ZDij1Mq8kUIpg==
X-Received: by 2002:a05:6830:2143:: with SMTP id r3mr17417711otd.189.1606755572642;
        Mon, 30 Nov 2020 08:59:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4fd0:: with SMTP id d199ls3061230oib.5.gmail; Mon, 30
 Nov 2020 08:59:32 -0800 (PST)
X-Received: by 2002:aca:919:: with SMTP id 25mr15019241oij.95.1606755572325;
        Mon, 30 Nov 2020 08:59:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606755572; cv=none;
        d=google.com; s=arc-20160816;
        b=PMh1TkFdFnCmwVGH3SiLamwLKbjx1FaIlkuTqJ10ssuN8deS3SWoZNRgMsQPxBkwKs
         t4vrceX6QXCymvBOS1mVBY9W9Ay1dmGwKQ74U3phdcOdvLd8Mulf3taZUolmwyspqpZs
         YaSF8urDzOdJulmfu59uUL2hERgFF5MEiCtOspJXbUyWlgMEgXSj1Rqt3ooxrezwdl9F
         5o+YLN3Ie8ffoT26k1fVjxfHMmwwo0Gd6NYCyr7cx8kZsS4JRgMSrpfhQsy6lfKlaxbT
         suUgNUVyDVFJubgDpyTtnIA23WaegdfT4mre+N/QpBNPv7Nn+qua+YAez8DuDacxx5K5
         grfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=HNNA4SW8dGTQX+Ujy8nKp6lHw/GHIIqM7lZMr2HBMrY=;
        b=UvWdj+rLQI5YBQtxkPFGpih3XlBAoOflvzW4yuFOdUfYK40KvEYQ6pa6YjVPBy7LoF
         qkPQX+lL44bVxEbt2uKv+fPMJidgoN9x4S3hbaISGuHwvzJ40QeyyVuCqfK1b+6DxNHn
         dCDmrpsAL3iewIYSHabkn21gvRHbQ3ilF8Uh+qM8AHnAbJXkknCdL4wrPtv2it1eTkm7
         0qVBrGH/OrC8qwtpC657GFEkjFi/tmZvRPJ+XyWuxd/uJdIUgRs8SbXtFqaESJv2ux5S
         eFIpU0Sr6mkmY/CBIHY+oRE7iYLReiisLTNINhvhsJjTGf/BRsCZn7L0vHga+JTkIdGd
         JqzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m13si1205066otn.1.2020.11.30.08.59.32
        for <kasan-dev@googlegroups.com>;
        Mon, 30 Nov 2020 08:59:32 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 08B971042;
	Mon, 30 Nov 2020 08:59:32 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2325C3F718;
	Mon, 30 Nov 2020 08:59:31 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>
Subject: [PATCH] arm64: mte: Fix typo in macro definition
Date: Mon, 30 Nov 2020 16:59:22 +0000
Message-Id: <20201130165922.17993-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.29.2
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

UL in the definition of SYS_TFSR_EL1_TF1 was misspelled causing
compilation issues when trying to implement in kernel MTE async
mode.

Fix the macro correcting the typo.

Note: MTE async mode will be introduced with a future series.

Fixes: c058b1c4a5ea ("arm64: mte: system register definitions")
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/sysreg.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/sysreg.h b/arch/arm64/include/asm/sysreg.h
index e2ef4c2edf06..16454a18a320 100644
--- a/arch/arm64/include/asm/sysreg.h
+++ b/arch/arm64/include/asm/sysreg.h
@@ -987,7 +987,7 @@
 #define SYS_TFSR_EL1_TF0_SHIFT	0
 #define SYS_TFSR_EL1_TF1_SHIFT	1
 #define SYS_TFSR_EL1_TF0	(UL(1) << SYS_TFSR_EL1_TF0_SHIFT)
-#define SYS_TFSR_EL1_TF1	(UK(2) << SYS_TFSR_EL1_TF1_SHIFT)
+#define SYS_TFSR_EL1_TF1	(UL(2) << SYS_TFSR_EL1_TF1_SHIFT)
 
 /* Safe value for MPIDR_EL1: Bit31:RES1, Bit30:U:0, Bit24:MT:0 */
 #define SYS_MPIDR_SAFE_VAL	(BIT(31))
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201130165922.17993-1-vincenzo.frascino%40arm.com.
