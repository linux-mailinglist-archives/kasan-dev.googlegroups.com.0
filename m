Return-Path: <kasan-dev+bncBCJMBM5G5UCRBYGZSWOAMGQEA6RCLMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E08B63B7C4
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Nov 2022 03:22:26 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id be1-20020a056808218100b0035b89bf17f6sf4473306oib.17
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 18:22:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669688545; cv=pass;
        d=google.com; s=arc-20160816;
        b=oym3fxc/EcA8d6jSIqz1tVlePXXv9GXAJ0h7Z7ulO8AARvThblH0ORVZQpXNbjxYWY
         wHqb7+zwRd77pExvcaNNm8PEFeOJWBSYnX3Oc7lHHHjIv25yDQaiiepPS+DrSQU2ll6G
         b2G+fL/K3Y0zxjWwvHe0S8p4zEIaXDnpmbgxFIoCJzf72pDdoSYd7CauZSZJotp4O+GC
         Vy0031f6wit+KnZ4xbX8HYSXTOwJnBOoNDdQ5Vbx3xDlWcBtTgqjzOjd7xEDQBzCd94Z
         Z9lFZqGI4VulUOKkCThgl9CRQfmFSo1XP5izn43A2nTzJUFuW3KyuBxCCH2YTO2g5JqR
         Y8Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=5T3lYOdnEscpX9xQeWJldE++DU8g1YQTwJ0UktwmUIw=;
        b=ReDLX7Q4GkMKERHtAz6gP1007CuTBsVT0aWtb0hMW9pi9cHvPE4P3G39+ao82+uxeP
         4+ZPeL1eGvss4d0JN9s94GCLJNPMCST+Oea9eKt0XWg6BAUjTiwt6TKZHFxyVaCNoApr
         W/hjpyEbcg8klJ6xZ5kWpTDNkgSnv50PE3rJXfKp77rLTAXp5IGYHeNmsX2UdHnXPiMT
         JolfYrYFuv5/wZySj9Ua6r1Gft/I80F47PgCInYatPxKoV2x4KljGIaSQdt9+RRX3q7g
         JmMJJMuS5JmEGYZ8xg1Cm2r+pKz/N2V2itu3lBGnkY+R6QagSf0v1uU2yPdNmHh8JkyQ
         NDmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b="C84QWr/I";
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=IJnEXmyV;
       spf=pass (google.com: domain of 01010184c13148e6-d78a8616-4544-47e0-b0fb-4dc780299fc9-000000@us-west-2.amazonses.com designates 54.240.27.55 as permitted sender) smtp.mailfrom=01010184c13148e6-d78a8616-4544-47e0-b0fb-4dc780299fc9-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5T3lYOdnEscpX9xQeWJldE++DU8g1YQTwJ0UktwmUIw=;
        b=tFsRpS10amMAtaV1aHyrxJvaUJwGvc2ffiJSAtDUWNufLxyayQriV7k1yI54cst4/X
         1qUs9fKkkusJeNM9XX/zF9Y2wOlr/WJDZgfkX5RfXscv/slXIM8pLn5H8cg23BIew415
         RinkqqMVpWKwXmUCBRUDKGip8AOrw8zxDf+PcxMd3H6dKdGvBJoj8hg5xyA3xX/brqVu
         vcAM1u8PWHCTj/+Fge8v0v9HLfiIKlS/1xgg2tqTCbAwnQJDODV45do2bJ8AF+2pvwAe
         sIn/ewv4ByQ55Xi4tl6Mt/vIvUQw1PoVSDa2lJPZ7QZyn0t8GkwP1/o/A8q6CjLl+msp
         gR/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=5T3lYOdnEscpX9xQeWJldE++DU8g1YQTwJ0UktwmUIw=;
        b=LrcCyQipsWC8n7bPHhcIeTCFpAbpJt6mC1ZyWOU+XaiNzjHS/PRu4eFzdHoAq+64eU
         qqOoGHkD0AjlMgR2VOAxE9TOcXAYLFkuOEDrwyqhEKQcnJR9kn6iKmVPFgXThaczJFGB
         KI6AYBMnV7MiET+59dX4YuknZ/Zp8TrWReFyQ731ub3mHd0tq1dpDNir5SzPsj8nT4dO
         5Aa4Zzqd1tayQLcJ2EzgBtpGPajBxelqrvrvPXFtwa7117hZMeht/mNVrIw5YzksmAHl
         DhundfEEwaup2brtzuOZ+9TNVBuQFjdq6BKl8uIucVm4cud31fxjQ2SU+mK71ndFtirV
         XdZQ==
X-Gm-Message-State: ANoB5plqoO1BtY7c48QNoomHZ/um/Cfs1J1bLmqQD7k/yhxg2kb8RgPC
	ch5HDdGf7StE7eIQi0+GqsU=
X-Google-Smtp-Source: AA0mqf6fIvY+4TwIUj6agp6Ceqbya3wxU/N5etQdceG2WhJCCpusLeUGBPpY+SMx3dgkj1sGSE4GBA==
X-Received: by 2002:a05:6870:bf03:b0:13b:55d:8ddc with SMTP id qh3-20020a056870bf0300b0013b055d8ddcmr34079081oab.296.1669688545095;
        Mon, 28 Nov 2022 18:22:25 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:93d5:b0:13d:173c:e583 with SMTP id
 c21-20020a05687093d500b0013d173ce583ls4488498oal.0.-pod-prod-gmail; Mon, 28
 Nov 2022 18:22:24 -0800 (PST)
X-Received: by 2002:a05:6870:609d:b0:13b:d2a2:829 with SMTP id t29-20020a056870609d00b0013bd2a20829mr23623223oae.178.1669688544644;
        Mon, 28 Nov 2022 18:22:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669688544; cv=none;
        d=google.com; s=arc-20160816;
        b=WxcGVDkvtcDucgaFQ67Xn1pb5CYbdoXFtxEYSoBs1OCK5/ME/MtR6+t9a5B0NONuFw
         5IUwWkKsPUNVo+wqfCW2oKLuvGtM8Rz8rjRKGcjXjrFvR5wzMMR19KlQc0yEL9YOLx0m
         dnxLGeX3ws9UaERAPkvayRTDepeCQIzGBgum9e2+pChOg+rKkPRr95nrz/CcGUzc5uQ/
         UKHfEchgs5PtYFm+iEmADK8/qNQZQOr/21Jd+wf58k0DHxW4wt7j2hyMpLtK9NfDfqJp
         CTBIXPNzwXrSjEVreheM6RFhSgkAoISrh+mUoF8wz7rZ2wOFVJ2rH0mziCvS/D/XSIcO
         UnOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=6g7pc0CXFpXcaJLSODZB6GWhqScJL+ZlJctnD/J1wH4=;
        b=B4ihHnvOAjvXwl6CcfCyvFuMezsPGTsya8hlbS9JxclXuvXwnXCapW00fwX1obq32k
         54pJNWhDCyotL3FFk5rJvn0y6Eq3xWDSh/Y3mw4sIAWYhody5Lf176yMj0lmvVfKUdkd
         bDeufhFu3Ac/7dZOCVykhLGKQUfK4vInm6eYOxOg1CbBdQS0G2Rtomq5KDej6KZXGgkf
         OnUM/OdVLV6E3zdnPC1lkvY5U9kxjVIr8cZeiIkHYE6VwoczKg+0zKQhhBNTTsz9eey+
         DAop81ZtjVPT8++aeOp/DRhP/P31bcjD010HkuJh21TSxqhD2lBbLc2qDUb6ub1L1sLz
         xijg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b="C84QWr/I";
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=IJnEXmyV;
       spf=pass (google.com: domain of 01010184c13148e6-d78a8616-4544-47e0-b0fb-4dc780299fc9-000000@us-west-2.amazonses.com designates 54.240.27.55 as permitted sender) smtp.mailfrom=01010184c13148e6-d78a8616-4544-47e0-b0fb-4dc780299fc9-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-55.smtp-out.us-west-2.amazonses.com (a27-55.smtp-out.us-west-2.amazonses.com. [54.240.27.55])
        by gmr-mx.google.com with ESMTPS id c17-20020a4ae251000000b00476ba3a3008si694048oot.1.2022.11.28.18.22.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 28 Nov 2022 18:22:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 01010184c13148e6-d78a8616-4544-47e0-b0fb-4dc780299fc9-000000@us-west-2.amazonses.com designates 54.240.27.55 as permitted sender) client-ip=54.240.27.55;
Date: Tue, 29 Nov 2022 02:22:23 +0000
Message-ID: <01010184c13148e6-d78a8616-4544-47e0-b0fb-4dc780299fc9-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Andrey@localhost, Ryabinin@localhost, aryabinin@virtuozzo.com,
        Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3225580: commit 59c06ebc91f7dd6b93697cf25ec09d9499e13094
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.29-54.240.27.55
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b="C84QWr/I";       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=IJnEXmyV;       spf=pass
 (google.com: domain of 01010184c13148e6-d78a8616-4544-47e0-b0fb-4dc780299fc9-000000@us-west-2.amazonses.com
 designates 54.240.27.55 as permitted sender) smtp.mailfrom=01010184c13148e6-d78a8616-4544-47e0-b0fb-4dc780299fc9-000000@us-west-2.amazonses.com;
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

Change 3225580 by automation@source_control_dishonor on 2022/11/29 02:19:51

	commit 59c06ebc91f7dd6b93697cf25ec09d9499e13094
	Author: Linus Walleij <linus.walleij@linaro.org>
	Date:   Sun Oct 25 23:50:09 2020 +0100
	
	    ARM: 9013/2: Disable KASan instrumentation for some code
	    
	    Disable instrumentation for arch/arm/boot/compressed/*
	    since that code is executed before the kernel has even
	    set up its mappings and definately out of scope for
	    KASan.
	    
	    Disable instrumentation of arch/arm/vdso/* because that code
	    is not linked with the kernel image, so the KASan management
	    code would fail to link.
	    
	    Disable instrumentation of arch/arm/mm/physaddr.c. See commit
	    ec6d06efb0ba ("arm64: Add support for CONFIG_DEBUG_VIRTUAL")
	    for more details.
	    
	    Disable kasan check in the function unwind_pop_register because
	    it does not matter that kasan checks failed when unwind_pop_register()
	    reads the stack memory of a task.
	    
	    Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
	    Cc: Alexander Potapenko <glider@google.com>
	    Cc: Dmitry Vyukov <dvyukov@google.com>
	    Cc: kasan-dev@googlegroups.com
	    Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
	    Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
	    Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
	    Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
	    Reported-by: Florian Fainelli <f.fainelli@gmail.com>
	    Reported-by: Marc Zyngier <marc.zyngier@arm.com>
	    Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
	    Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
	    Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
	    Signed-off-by: Russell King <rmk+kernel@armlinux.org.uk>

Affected files ...

.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/boot/compressed/Makefile#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/kernel/unwind.c#3 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/mm/Makefile#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/vdso/Makefile#2 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/boot/compressed/Makefile#2 (text) ====

@@ -23,6 +23,7 @@
 endif
 
 GCOV_PROFILE		:= n
+KASAN_SANITIZE		:= n
 
 GCC_PLUGINS		:= n
 

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/kernel/unwind.c#3 (text) ====

@@ -249,7 +249,11 @@
 		if (*vsp >= (unsigned long *)ctrl->sp_high)
 			return -URC_FAILURE;
 
-	ctrl->vrs[reg] = *(*vsp)++;
+	/* Use READ_ONCE_NOCHECK here to avoid this memory access
+	 * from being tracked by KASAN.
+	 */
+	ctrl->vrs[reg] = READ_ONCE_NOCHECK(*(*vsp));
+	(*vsp)++;
 	return URC_OK;
 }
 

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/mm/Makefile#2 (text) ====

@@ -7,6 +7,7 @@
 
 obj-$(CONFIG_MMU)		+= fault-armv.o flush.o idmap.o ioremap.o \
 				   mmap.o pgd.o mmu.o pageattr.o
+KASAN_SANITIZE_mmu.o		:= n
 
 ifneq ($(CONFIG_MMU),y)
 obj-y				+= nommu.o

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/vdso/Makefile#2 (text) ====

@@ -29,6 +29,8 @@
 # Disable gcov profiling for VDSO code
 GCOV_PROFILE := n
 
+KASAN_SANITIZE := n
+
 # Force dependency
 $(obj)/vdso.o : $(obj)/vdso.so
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01010184c13148e6-d78a8616-4544-47e0-b0fb-4dc780299fc9-000000%40us-west-2.amazonses.com.
