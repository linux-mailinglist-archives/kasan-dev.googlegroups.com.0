Return-Path: <kasan-dev+bncBCJMBM5G5UCRBRWA6CNQMGQESEA56DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DA6A6331D4
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 02:05:12 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id t10-20020aa7946a000000b0057193a6891esf8343955pfq.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 17:05:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669079110; cv=pass;
        d=google.com; s=arc-20160816;
        b=qhB1xzULgCoNs58Stt2PjiHXUnRPuDzhLgGPnI2jOwErRPJY2xPUi+WVsgHdNJS7+T
         7iEIA8OsIHnaVu0j7Lt20Xi8n4vqGAS9DuzJi+48bgOLQNinN7XoOvXQ/1QzYxuTIwMl
         vnco7zpw8EZ6mCuc3F9K9pmCdCTxVmX7k9r6GPD+qfRw4ubyqIouiFBOJZoQz+4gEZ09
         1VBtM02EVkNXpBMqHN71uu3S4HtKoVVXJVYrIWObppBs4Lwrd3bCW6hFCnh7aO7dFnsw
         HIoLU7sO0jYu+IOT2QPHGvdKA6K4y84gIdcpyQfTno0RyclvSMBBqQi8fnjb4NliA1rq
         oujA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=Z7AjqbCGxXVv+bkgoBUhqfenqNJ0w0FoX4gwCtHcppQ=;
        b=KBEk4lN8xbGtEc7t7cUNZwKgB9bsud9AKlGsY4ohzMGGVg3F0aNzDHksN4nP9kLotd
         JAKKdgUPYuIF0c8YwlOMTe0mxBde0P7H+6YcneD0OXBvuqUlHVdVrRQqrVqtWdEKQw8y
         IV3hUuIGfplUwAGAE/vwJ4riX6N9pCktKd2L7sR58YT8AXTGTZzVw80fPbYgSmzSapQH
         d25JH67GyK/QXITgA1fQRwYcY+InNSod9Dm7WYANEE/QnLbF8XanjL9TCmQ5FO0Z+hHK
         v3tof23MW1V3aqg5jEQSxtf7eGuFaORfffB93wiapjj7vA1lqU9x0Xq6Wp2y0vu0XgFm
         cOWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=i5HD5iKu;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=MJhwvuX0;
       spf=pass (google.com: domain of 010101849cde0dd0-ec51d65f-d827-43cc-818c-9c0fbf21c79e-000000@us-west-2.amazonses.com designates 54.240.27.10 as permitted sender) smtp.mailfrom=010101849cde0dd0-ec51d65f-d827-43cc-818c-9c0fbf21c79e-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z7AjqbCGxXVv+bkgoBUhqfenqNJ0w0FoX4gwCtHcppQ=;
        b=gXYg1ee242/qv3Cjc3ceu1xxTGA9JnJjLYvRNZm1ep3P7S+B8z3HaTaXkU77RqDauv
         GQLrnVn9Qxqq4ct6b5kbNJvCbmvMBMAqtrSHpGi3a4N1zVzBJGlbsycfMhxZkcgjCdCH
         2VPLaHVXCWWdcxK2LsT4IQ0Dz8IRrkP+prnlO5fAFb5frjc4yzu8hTX0m6C4PUc8wE28
         JNN3W4cxqF5/GMgHInIjRasN+A4tvlzDh+ZIYYvZVZVlyTP6Stpy4F9wkt0DmXC8EEiE
         phXS8QU5zFgmAfCuC6xUJHUSOzYPxsxcnbrED2HSR29S5DX2knsIuPTgtHoKi4ew1m4U
         HVfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Z7AjqbCGxXVv+bkgoBUhqfenqNJ0w0FoX4gwCtHcppQ=;
        b=h5xfOn56blJ3i4saaqLA8rubTdrruHhLvE8ffv0VrOXhA9dZ5gpzJdq6fXA8B6gKlt
         sg+txvML0WFnuX9/4ReeEzGe6jXr7yr0yuxuYmlCjJAzBhNhZAyp2rsMbGH8BAaWV0kW
         03EORTMonl6Mwl5jbagztopSqaHi71XZeT36EIEA7EKqNIqM5gNMJ+/RkJSWAf8YulK9
         1qYwlQ0g0/wsgQ2txY5X7HAi76Onsq9QOHM2sXMAM877QGz9bfoESp/F22Izv1YojkDC
         gT3GJH5J/b1ZoEj0RciHI/CldeF9i6Oly1BApGtCKFn/FDZxgElNCr81KWMCDo0glvhc
         dBRw==
X-Gm-Message-State: ANoB5pmmJCRZbvR86S1GOMVRtWBAI1PcR3DaL7Wxm4G6fr2IY9K6DLBH
	DUmFFxwFlcveZvFgtjbXNaU=
X-Google-Smtp-Source: AA0mqf6YAWxKVfWt5PB8caOXQJIASBr5/gXYZTMuttfzHl4ifMmm73+Cj+UvzDNFywp95UG2cANKdw==
X-Received: by 2002:a17:902:e0ca:b0:176:d217:7e6e with SMTP id e10-20020a170902e0ca00b00176d2177e6emr1241103pla.82.1669079110451;
        Mon, 21 Nov 2022 17:05:10 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6c48:0:b0:44c:c693:aec0 with SMTP id h69-20020a636c48000000b0044cc693aec0ls6764355pgc.0.-pod-prod-gmail;
 Mon, 21 Nov 2022 17:05:09 -0800 (PST)
X-Received: by 2002:aa7:9192:0:b0:563:1ae2:6daf with SMTP id x18-20020aa79192000000b005631ae26dafmr6505947pfa.71.1669079109684;
        Mon, 21 Nov 2022 17:05:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669079109; cv=none;
        d=google.com; s=arc-20160816;
        b=Z4hUYErrzx3EN2B5RSX/YaB55jIEPVSRJJMtXs9wyUkoOkDl8qMuYidzsoim+VXxA+
         d+68mASDiLIOd9aHzhhrPKSlPbybGMif1khE7NZiIWUHFGm+iNndKRdmrbAQo/tGFABl
         vLNUD58zGFqf457Oog0iOIR7eyJPfZAIPxxMkF92fsx//cVdxz4BztFM9voxTpzorOhF
         MLaoeKr0CVSBl7n1BspYWfKeeDdfxqNDnGEftMf4hOJPTTeJ9+bL6G9rsYdMkGxsZXY2
         K6Fjriu09il+qhhk6otTA/TUD+KeYFkvyoSDg1uuKtUdNAK/dTxXooE4L1MfwSRObWx+
         jKdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=hhjqbAPTvQbo7UzgQvdr7t1s89YATVZW0YB917ZMjzs=;
        b=KLN4hiNH7fy64+ew+mPZ6Z4lvvckinkw8e3bGAEwcJzgYfBpA50+I3OwdAc7ZLwVeq
         XMpNzMaEqF8zYRVGBfq2JsKauC3QxhberCVJCOv78EIZhZbTbjDVNLA58gakYyK51stq
         QVFMuRogAbGrdAh5WvYeG5eXML3Pppj3r4NY5wASmX67ZNZE7I2034Vs8thTdUiu9xG2
         k6bDWRjLjvINgUDaK5HZvOfNW2cu/9kyZJP/HvBFMZC7Zn/jVZtOfifxykGC2oX8MmY+
         ahvYGT/nMEoDJqS9TYYTx5u0XDxHHhmWyqDqUX398lg+BleaRXhvENuYR8vwUer0K65F
         ckMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=i5HD5iKu;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=MJhwvuX0;
       spf=pass (google.com: domain of 010101849cde0dd0-ec51d65f-d827-43cc-818c-9c0fbf21c79e-000000@us-west-2.amazonses.com designates 54.240.27.10 as permitted sender) smtp.mailfrom=010101849cde0dd0-ec51d65f-d827-43cc-818c-9c0fbf21c79e-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-10.smtp-out.us-west-2.amazonses.com (a27-10.smtp-out.us-west-2.amazonses.com. [54.240.27.10])
        by gmr-mx.google.com with ESMTPS id j1-20020a633c01000000b0046f3dfb889esi681339pga.3.2022.11.21.17.05.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 17:05:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 010101849cde0dd0-ec51d65f-d827-43cc-818c-9c0fbf21c79e-000000@us-west-2.amazonses.com designates 54.240.27.10 as permitted sender) client-ip=54.240.27.10;
Date: Tue, 22 Nov 2022 01:05:09 +0000
Message-ID: <010101849cde0dd0-ec51d65f-d827-43cc-818c-9c0fbf21c79e-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Andrey@localhost, Ryabinin@localhost, aryabinin@virtuozzo.com,
        Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3224925: commit c8357c2fd6dd04b4644dd74fa20fa76617131049
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.22-54.240.27.10
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=i5HD5iKu;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=MJhwvuX0;       spf=pass
 (google.com: domain of 010101849cde0dd0-ec51d65f-d827-43cc-818c-9c0fbf21c79e-000000@us-west-2.amazonses.com
 designates 54.240.27.10 as permitted sender) smtp.mailfrom=010101849cde0dd0-ec51d65f-d827-43cc-818c-9c0fbf21c79e-000000@us-west-2.amazonses.com;
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

Change 3224925 by automation@source_control_dishonor on 2022/11/22 01:02:03

	commit c8357c2fd6dd04b4644dd74fa20fa76617131049
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

.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/boot/compressed/Makefile#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/kernel/unwind.c#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/mm/Makefile#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/vdso/Makefile#2 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/boot/compressed/Makefile#2 (text) ====

@@ -23,6 +23,7 @@
 endif
 
 GCOV_PROFILE		:= n
+KASAN_SANITIZE		:= n
 
 GCC_PLUGINS		:= n
 

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/kernel/unwind.c#2 (text) ====

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
 

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/mm/Makefile#2 (text) ====

@@ -7,6 +7,7 @@
 
 obj-$(CONFIG_MMU)		+= fault-armv.o flush.o idmap.o ioremap.o \
 				   mmap.o pgd.o mmu.o pageattr.o
+KASAN_SANITIZE_mmu.o		:= n
 
 ifneq ($(CONFIG_MMU),y)
 obj-y				+= nommu.o

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/vdso/Makefile#2 (text) ====

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010101849cde0dd0-ec51d65f-d827-43cc-818c-9c0fbf21c79e-000000%40us-west-2.amazonses.com.
