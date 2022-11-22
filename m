Return-Path: <kasan-dev+bncBCJMBM5G5UCRBHFY6CNQMGQEN4G6AYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 44D0363318D
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 01:47:26 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id u6-20020a170903124600b00188cd4769bcsf10391609plh.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 16:47:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669078045; cv=pass;
        d=google.com; s=arc-20160816;
        b=QRVwBs6IOD/H4Olr7pWEyw7pKuC8BBy0gDlESBOxSTQqMEocoJpz7bq/4M89CYaLVv
         DVF2vqv+hQljWohQDxjn1OhXEwTnu5PGmG7uys5/1P6K2esrG3yg/R80sC4ZKrDT10ha
         BZFiSa87DGtudydG6aHvwRWg3axPr3WstBENPauzgGQTBzLj+ohNZ/x7KhH8q9099Uar
         ViCiqqcfbIdWfWTkBIVEe3CT4WtAEocnYxw+e41sCEJzEDLEyoaMCnk9aqjcVRWW9mnf
         9sUkxdt4I3VHaEMe9lbY1zdQ8LkazjBbXb6XcF716OdqHCbVxmIDuapAyCHACB2qAMid
         j4BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=hqN0ABjgMT6BZksY5KCPV9qRLKgY1hBqzqsJTfah93M=;
        b=aUmFx/gVx3+S9gitW1VOsTx4bAjEDtiOKip5xUgIPytjd2zETzNnn/7/VO2uS3ZozQ
         zxlg1RKvAF5pvKHzS7A4gV58P4ZftqRsGIUy/Vxldrxiy6RJLO8ib0OmO7LNt7FlqdHs
         jdTmATXn1vRfhFh6JynTjWsgMbEnN2hO9eRZpxBRrH0sKWkETXwhdYhgkNPgkrb1NR6+
         xD+9QHdt8YWWpCxBsdsUCL7Fgn7O85HH55J5qC7fTw2Rn+IxS7DjWvZf8jrBdEXQH2xQ
         Dw1K88fzxFvT9/hKiteYi1lRpfH5TbDbCttZAI78vC5AScJxbNyLgOG48UUI7Cq3jpYh
         Lc2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=Hc4s4CJ4;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=HepofYBE;
       spf=pass (google.com: domain of 010101849ccdcb6a-1bdab0ba-24ad-4002-8614-e6c50862bea2-000000@us-west-2.amazonses.com designates 54.240.27.21 as permitted sender) smtp.mailfrom=010101849ccdcb6a-1bdab0ba-24ad-4002-8614-e6c50862bea2-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hqN0ABjgMT6BZksY5KCPV9qRLKgY1hBqzqsJTfah93M=;
        b=XoZMq2bjDebu8vmKc9fjgXi40SgQD6ikT/vOtwtHFPIpqHpVHQ6RtHfD0849vhqmoj
         Tv0JkxPCE/IRokJkQa5zVGapckxMWNMG22Mp17aj8tksz1kFb+v1+i9GlhEjfYzbFGKS
         66exRG66SIVqE9Nadx/QxFayHci/tSU46uy2+HbVpB5RlHbV5+yNESLVuARHPCEOGLd4
         3XBOraHfkefpotbcj5/WSKBvA4a/FdKYholsl1nQ086Hkc03AvmJoAJdO7x0nHurSEJU
         gf7jsK4YOgVEjfVtXnQippUhnMkaadcmH6IautjwP3aaS6gOVoXZfEoZUScSSsTmnbW/
         VWXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=hqN0ABjgMT6BZksY5KCPV9qRLKgY1hBqzqsJTfah93M=;
        b=KB1cljsEi+YJVZ6iiZJ5wpYJtiadi6z/QHzMQwlTSJzsP9WJG+3YM12iRGsfbfuNVz
         70Zra8Mhdr7kLF9gsff0M7pmtcHlzMwxsM7idN/pcorTw/IIp4QwX4K9x+O32pc1SXNY
         x8rvAiryNLgJKFJ7BmzZoIbsMVdCeWOH9f6B/9wN9i3uhKX30m4vBQbiRye+C7OHdM0J
         QOOuqBFXjm8oOv98waRY5bevPxiOJ/RbVhUCU52pW4VOvQESMOoz4XefBXy6IPjkTwUt
         0z/nDyhxwnQI9c/qauVGrYhKFNpqH6VgubcX+5KI0sB8VTkdMT/sew+ZpQ3rNbeYM45F
         FUlg==
X-Gm-Message-State: ANoB5plHSTi+AWrK71GAv0ZN6dAGNGIPB129YiCprk3WUuzTjzT84v8q
	ShuUtdx8zD2Utr+lbVVAAGk=
X-Google-Smtp-Source: AA0mqf4b4RGopvdpPxKXZPyN0ZOLfCuC1gIH3FnYRNXrH2NB+gcu9GtggTmQmzdGK75MHAA4sqjO3w==
X-Received: by 2002:a62:1b4a:0:b0:573:20a7:d with SMTP id b71-20020a621b4a000000b0057320a7000dmr5465090pfb.65.1669078044833;
        Mon, 21 Nov 2022 16:47:24 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:158d:0:b0:572:5d4d:81c2 with SMTP id 135-20020a62158d000000b005725d4d81c2ls6618188pfv.3.-pod-prod-gmail;
 Mon, 21 Nov 2022 16:47:24 -0800 (PST)
X-Received: by 2002:a62:6083:0:b0:56d:3180:c7fc with SMTP id u125-20020a626083000000b0056d3180c7fcmr4366547pfb.41.1669078044135;
        Mon, 21 Nov 2022 16:47:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669078044; cv=none;
        d=google.com; s=arc-20160816;
        b=nNj/H+qcwQAEBfa8jSsNN3onYYVyWVpMIH/rdNX1LT2p098IGp+LkvA0ggi3LqpV1g
         C9FzF1j8AdrBnNwC+SFiL0cyslkMpetEyoNAK81RK3soC6byRMo2n68gC1KK7UVK4Nfv
         X6nyPZ3uP/dvVRauD+w+Y+9g642YqudxY9cdDxkLUOHTs4F1tODQwPyWDCzTHdmUxN0e
         KQVsIV4vf4ICBKnG97unDv+WBwNe+Uqeg9wi+afUvLNjQcCPL+gq+UokJcqsYl19EiDq
         UGXTW5j8YWdz914qIu2IsC3DjtvSC9mcdw4ai8vmq/yLwBkiC/ntSyhbcqomxpVYWubi
         AGyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=nNMejm08STPSduLlyJuBjNKuiRWiYmDTW/IG0Tnt3/Q=;
        b=lUzV30wAAf5PxCPllWS5hKwoL2jU20w2uJudaD8SblROXM2ogfxsLl61mOoAhQhs9F
         dMSal0f+uSLRccsDtZEt8S9xnwSQB8TwTteVWWpRtGO9r1yvN9APrx6424huY/RXGS5p
         tY/7Ix831gAkxv83BC093vigS6fQg+88fNJq7hTe0KvA1/CHliWcjjxeLOnlXCRGxMWB
         DeTN8gGd7W0HM99pXRW/VqofzqgnBhBuUnhQXH3PdeRLn3uoYz9bKR/tg6WYPDXeunGP
         iFG8KArKF4XZuPwyGNrnoyyYXfGKbU9KTUqG1lHBp15hZNBP9XHlMU9SC7HIU7msSa4r
         jAIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=Hc4s4CJ4;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=HepofYBE;
       spf=pass (google.com: domain of 010101849ccdcb6a-1bdab0ba-24ad-4002-8614-e6c50862bea2-000000@us-west-2.amazonses.com designates 54.240.27.21 as permitted sender) smtp.mailfrom=010101849ccdcb6a-1bdab0ba-24ad-4002-8614-e6c50862bea2-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-21.smtp-out.us-west-2.amazonses.com (a27-21.smtp-out.us-west-2.amazonses.com. [54.240.27.21])
        by gmr-mx.google.com with ESMTPS id m3-20020a170902db0300b00186850a4ecbsi777594plx.10.2022.11.21.16.47.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 16:47:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 010101849ccdcb6a-1bdab0ba-24ad-4002-8614-e6c50862bea2-000000@us-west-2.amazonses.com designates 54.240.27.21 as permitted sender) client-ip=54.240.27.21;
Date: Tue, 22 Nov 2022 00:47:23 +0000
Message-ID: <010101849ccdcb6a-1bdab0ba-24ad-4002-8614-e6c50862bea2-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Andrey@localhost, Ryabinin@localhost, aryabinin@virtuozzo.com,
        Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3224913: commit edbd95fdfafc6fcde6f24ba0eaea9fde9f5e5580
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.22-54.240.27.21
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=Hc4s4CJ4;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=HepofYBE;       spf=pass
 (google.com: domain of 010101849ccdcb6a-1bdab0ba-24ad-4002-8614-e6c50862bea2-000000@us-west-2.amazonses.com
 designates 54.240.27.21 as permitted sender) smtp.mailfrom=010101849ccdcb6a-1bdab0ba-24ad-4002-8614-e6c50862bea2-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
X-Original-From: no-reply@roku.com (Automation Account)
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

Change 3224913 by automation@vsergiienko-flipday-internal-rtd1395-nemo on 2022/11/22 00:40:33

	commit edbd95fdfafc6fcde6f24ba0eaea9fde9f5e5580
	Author: Linus Walleij <linus.walleij@linaro.org>
	Date:   Sun Oct 25 23:56:18 2020 +0100
	
	    ARM: 9017/2: Enable KASan for ARM
	    
	    This patch enables the kernel address sanitizer for ARM. XIP_KERNEL
	    has not been tested and is therefore not allowed for now.
	    
	    Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
	    Cc: Alexander Potapenko <glider@google.com>
	    Cc: Dmitry Vyukov <dvyukov@google.com>
	    Cc: kasan-dev@googlegroups.com
	    Acked-by: Dmitry Vyukov <dvyukov@google.com>
	    Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
	    Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
	    Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
	    Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
	    Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
	    Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
	    Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
	    Signed-off-by: Russell King <rmk+kernel@armlinux.org.uk>

Affected files ...

.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/Documentation/dev-tools/kasan.rst#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/Documentation/features/debug/KASAN/arch-support.txt#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/Kconfig#3 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/Documentation/dev-tools/kasan.rst#2 (text) ====

@@ -12,7 +12,7 @@
 therefore you will need a GCC version 4.9.2 or later. GCC 5.0 or later is
 required for detection of out-of-bounds accesses to stack or global variables.
 
-Currently KASAN is supported only for the x86_64 and arm64 architectures.
+Currently KASAN is supported only for the x86_64, arm and arm64 architectures.
 
 Usage
 -----

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/Documentation/features/debug/KASAN/arch-support.txt#2 (text) ====

@@ -8,7 +8,7 @@
     -----------------------
     |       alpha: | TODO |
     |         arc: | TODO |
-    |         arm: | TODO |
+    |         arm: |  ok  |
     |       arm64: |  ok  |
     |       avr32: | TODO |
     |    blackfin: | TODO |

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/Kconfig#3 (text) ====

@@ -38,6 +38,7 @@
 	select HAVE_ARCH_HARDENED_USERCOPY
 	select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL && !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
+	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_SECCOMP_FILTER if (AEABI && !OABI_COMPAT)
 	select HAVE_ARCH_TRACEHOOK

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010101849ccdcb6a-1bdab0ba-24ad-4002-8614-e6c50862bea2-000000%40us-west-2.amazonses.com.
