Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBVHLW2BQMGQEIRIX5HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 5226A356D67
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Apr 2021 15:38:30 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id y22sf479884pjn.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Apr 2021 06:38:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617802708; cv=pass;
        d=google.com; s=arc-20160816;
        b=l6BqSBbTdtgo/pu1/SF21zMR2+gtGfTuSMpTHM1j5sMDQMlT5Yna1e8bl2GMlQrqRU
         U6nQQ+Bqg1yRszQoE8RgVpTzdW0nc10hEJ/yPwSm8pyCZEWraAhe9ZG88Qa0xvJcdoO1
         y9b7yg57RhCWtSZbr9c6SZjGKFzpkzNN2+chclmekWuH+H4jwjC3uJqcRa0dxkXv/akz
         oQAtGb0lvUkavSzPW9YH1CKbe+/rsx/fqB1v+iin+opf6LLWPXmwPoDWMaQXSHPQ+3XD
         2RoD2EQ1ajYVWm2vG35Bfymx9b00RXCFwjmg2mGqyFm9tJ7q7Pyq8g3BJ1uL4jGKj9lZ
         gHBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=HLKdTMzqeLz0di/M2uuUsM/6rxR6MwwZhntacUcEiyg=;
        b=mjkGTQZdK5L+x5sernlt4gGfj8ica5wyTkvrPrplxAKXwpig7VcqBXbin+Agk4/pa1
         nhCPtUwwHogo1UOvCDMllhQum0DWpIrIvh+Zn+uiR1HO9PiUn1sm30FFhEpMAPY6+Od+
         apSaEaWKzqSAVCTWszlinKm1IqYZ02V+zXy7XP5tbEOgvaqmAa6ScIPeqjVs5MSAV4A7
         I15qRFUtblwoHggkfhOFX4WfOQZ9RFxZmj6KNZR/X8DrM0Ajpx+nRZ+n908X6D4a2naJ
         EgktVvigiAX47XFptoajX7/l6P5rKCkKUzZVf70NCZOMI/dmF9JeiEcPF6GxpbaeVuk2
         O3Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HLKdTMzqeLz0di/M2uuUsM/6rxR6MwwZhntacUcEiyg=;
        b=fH968hx4eO8xguoz89tgF84kLk9EZOS6D8QUX8rwFlG48JTiTktgABXachL+A3xLa4
         PLnoFkL+GmGTLoRV0sE1Iy0AxyTp87DRbviF+tW/bqc6XsOwzoJKrQQ5F3OiAufXZ2SH
         dhJkt+wG5jcUaPfbA0ds4Jhr7llwlDNWjuo3QCeN3jlQwWHdZyw++/UDe02LJdm/sAj/
         kEoK3FzB2MvfQU55+LECk4FWj4zW7DW8Rq3/R4cuSPEqcnxrdeRW3lxXMmi1Q0hRDXXu
         XiKQi7P1NPwKkixOUlx419iJKmADKbMw0sFXqBCXMusXxdMSaXCz65QCbgo82XtOO0h0
         5bmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HLKdTMzqeLz0di/M2uuUsM/6rxR6MwwZhntacUcEiyg=;
        b=CuGzgz5QSmy8/kdjMEOHRGAvbfmFg0W+mz27MeGjQpRpwOM6Wx3SG/EhiO9WxDv9/u
         6Culw/6bgqeFmq8GK3VZhp9yGrWVnaa0Hg2AXyH7ONrf3PPtO0meo+IJbPWWzGxWMPjY
         cA2xIC4oxLBlHKnCc2DGs64S+OragCN26yfFGvEmBtOgs7KZDDLQZo0RvAQjZ/HAo1GI
         DIFs1KcZ+r1wqExc/IqMQbUfz47Z8QaP3jhXR2dLY8LALuykEnRm2NByVl+hKVB6Dwt6
         B2mR14z5riV3DiWmmKFXSgqouWJQgCQLhOdVuD+aJHiNjtq1lftoMKNZ4wdBbUYp2iAa
         wXMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Gg0MzTGrPxMi0GEvc+MQxl6AbSusJLJMLyKrxux6VOmfDqM4G
	QyHXSDmEoHrsLQK/Pj/5Dd8=
X-Google-Smtp-Source: ABdhPJxDZ8bmKVCHgQWX+S2VaIyEigqAm0JUDFHA9Zeg3xcBUmm3J/3QbPtveKOIgGAjjgJlhErFTQ==
X-Received: by 2002:a17:902:b201:b029:e8:bf9e:990a with SMTP id t1-20020a170902b201b02900e8bf9e990amr3055739plr.56.1617802708628;
        Wed, 07 Apr 2021 06:38:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ac09:: with SMTP id v9ls821462pfe.2.gmail; Wed, 07 Apr
 2021 06:38:28 -0700 (PDT)
X-Received: by 2002:aa7:95b5:0:b029:1ef:272f:920c with SMTP id a21-20020aa795b50000b02901ef272f920cmr2974283pfk.21.1617802707952;
        Wed, 07 Apr 2021 06:38:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617802707; cv=none;
        d=google.com; s=arc-20160816;
        b=jwQCgcfVX5hHO9V27eS4R4pdVBbZr/Iq8Nhfl+eMsVI6b0o6LO5Xb7fPlBItfeyxVf
         N9oq9axOdDv9Mw8Ot4TM4Luxx0VAN71YGj9+yDvFEVkcRUW0d6Ck6xQ5a6XO+6ROTh85
         AJ65yJ+HIGW33cu/F7mM4WH2mGSnkZ3c4RDkfYxgjHuGBr8LHoXqtXfGJeNbFMTaFcox
         Ksl/Mp7RgoYDuc9ACvsUnJgOktdgF7oAeDjkZjqT/ZAAsm8KMHIXdysnDbeXjWJqKeR0
         uGL8tvZlC8/GPgcOkCJEwRBXBOCugFF2Ag1T5hADtf2FIujkzHxFDMr1hmKIGcANNs70
         jAow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=uG6HYueMizjwnFf/sQv6XRKKcDP2ifnsvWTzXEQoZfs=;
        b=gvm1pPpAJYv9Zb9OKWXVSkL63APC245b69jUR3S0T680Rq94qJhfes56Kx3ZU2nRWO
         vMZI9EuiezQNVOSaFRrABmxWG/5mvTDUKGR4lEUKECLNcve7TdW5kiudlkdgv0Kpvj6I
         isXjyk6z8UWM3jOwLl/kqKnU6rnjriwm4t2zIvWRZDRepmIVHGULkjsUbLBzqf0ilDP1
         I8IAIv1v4oa5yk4J5p8LkfaaErj7MsCSDtOyvTdSF7I2mCQftbXgilKeTKdmNZKA41y0
         eFsfmhyA1DBih3cwF7FfK/UiNKiWPu0eNwM7UJrQkRlUIbL8Qc/nWy9mqz8EGHOocL8e
         iLXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r141si662028pgr.5.2021.04.07.06.38.27
        for <kasan-dev@googlegroups.com>;
        Wed, 07 Apr 2021 06:38:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D58911063;
	Wed,  7 Apr 2021 06:38:26 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D35933F792;
	Wed,  7 Apr 2021 06:38:25 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Derrick McKee <derrick.mckee@gmail.com>
Subject: [PATCH] arm64: mte: Remove unused mte_assign_mem_tag_range()
Date: Wed,  7 Apr 2021 14:38:17 +0100
Message-Id: <20210407133817.23053-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.2
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

mte_assign_mem_tag_range() was added in commit 85f49cae4dfc
("arm64: mte: add in-kernel MTE helpers") in 5.11 but moved out of
mte.S by commit 2cb34276427a ("arm64: kasan: simplify and inline
MTE functions") in 5.12 and renamed to mte_set_mem_tag_range().
2cb34276427a did not delete the old function prototypes in mte.h.

Remove the unused prototype from mte.h.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Reported-by: Derrick McKee <derrick.mckee@gmail.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h | 6 ------
 1 file changed, 6 deletions(-)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 9b557a457f24..387279540139 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -47,8 +47,6 @@ long get_mte_ctrl(struct task_struct *task);
 int mte_ptrace_copy_tags(struct task_struct *child, long request,
 			 unsigned long addr, unsigned long data);
 
-void mte_assign_mem_tag_range(void *addr, size_t size);
-
 #else /* CONFIG_ARM64_MTE */
 
 /* unused if !CONFIG_ARM64_MTE, silence the compiler */
@@ -84,10 +82,6 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
 	return -EIO;
 }
 
-static inline void mte_assign_mem_tag_range(void *addr, size_t size)
-{
-}
-
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210407133817.23053-1-vincenzo.frascino%40arm.com.
