Return-Path: <kasan-dev+bncBCJMBM5G5UCRB6WC6CNQMGQERZ6BD5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 11DA16331FC
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 02:10:20 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id k3-20020a92c243000000b0030201475a6bsf9644167ilo.9
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 17:10:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669079418; cv=pass;
        d=google.com; s=arc-20160816;
        b=tyRNCjVu6/B+gq3ln33P61YdZOzatAXVRHZwPhyU4BXexRIVuCFsT1qWz3sC3D3uEF
         AMqkPLNVpWFhsiYXj+t+Saz1ZoQFsdkq+qA9xomyu8DFXsHk/NjXkBpVfTklRnYU5vTg
         L5B9rjjN8pudRKt2wbDy2fp0J0igBYc/Wvda+KUUqfkdPIrif83N6M8yGNOE04254Rbb
         v/FAfx+qcEB/AXwizI5zoE+1B3kwp+ccwK08oDNFLoKWwho0ubOC/j3ZZ8X/0LwujpQV
         Vo+1SqA4IH7HbKG3RgjgTFPzhJpgMA0413ARiDCUepWaz1WjfnMebgEMVJFR1HlQb3lS
         amfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=xdLKH9TpFVi9PQqrVahFL8zEQEnOkjMl8AueWqyY/Ek=;
        b=qdefJdRCyDTPCt9V7u57n02PAdaij+H/JJ9xlb03+tVBtHyPyKkhpk5BhbM2SqMhhm
         s9ueoxyrDJdGjHx+MRTvvn/2e8TREd1wMiVL/nsTcNE7HrgNoH9CCa1gEg8rhcYpAEi9
         jegET5R9MNwcvtz/0IMTVb1ETTntnC+7ATV8oWnSUcg6GV3JFtaB2Frk6HXKW/rvtU/u
         KZkVvLPsKoni7AYdTmoFapcNPSbh4qNmBZDQ2NrReXE/i4BU46DxkvFIHrOWZSbxujA+
         ykGjZDuQ6Rddh5qSFuojkXCvSn7QDbf8FFEf2QXg4OttKX9PHPeEC2k7kcj04RE3AGa/
         gdbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=OXYhE2rl;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=abdIp8Xy;
       spf=pass (google.com: domain of 010101849ce2bf0e-29a97289-86ec-4c5e-8e69-b67bcb0c8ba8-000000@us-west-2.amazonses.com designates 54.240.27.21 as permitted sender) smtp.mailfrom=010101849ce2bf0e-29a97289-86ec-4c5e-8e69-b67bcb0c8ba8-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xdLKH9TpFVi9PQqrVahFL8zEQEnOkjMl8AueWqyY/Ek=;
        b=kgtMi/aJbctyQxnTy1fS7aYCdR8u1PjBlD7F4VH/iaVa+TVSc1VspIPBblTo17XGlq
         er4diT7xasSGom4gqH0Qk46DhbBj7Zzz22IRMabzBn184sNxTZZYWigKXRtIe51EQSIc
         Fvj0ouUxmkMfGbalRq4DewMxw1Uq48DwbcMjO++jbjFPvrk3xywKk7iMuplLFw9LE+SB
         RNwEIuZINh44aehHNtYn0AehMB966NUb0PO4VOeY/N024gT3JO/drOfMzAVOcPobN9Nl
         wyX72i+wmcTRymieaABNVIxr+JnpfqKyYBLMeOKDizoU2O+ApPGiWZW3OeyyuUIZM0rL
         3ZXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=xdLKH9TpFVi9PQqrVahFL8zEQEnOkjMl8AueWqyY/Ek=;
        b=4aEEy5o0Y+wMR5pG6GGaawcjoxsF4BfVMcnOLFLbdH42GeacQjo5iBQv1u7niQDOpx
         TTxq9RdZT1hrFH8nKJqAyX1pbiMI9GHFexVqumOiPOI4KElylrRyr606P+cU6KqEHca4
         AIxOUGPDnNXChOPHic1OQ229FWMSXXxLYTYlNNYsEIzlDoMX2+FxbP2X7re+yItIKAnu
         tplKbBD7IDosPNDDoPSwKusVxbQw39pezlq2pGt8QPCfdK7bbeR8PyH1PhqeKK47B9bQ
         P0/TaqTinKnTL8h6YsHLnMO+HvgaFMeqpyHBXYQ36T6cbW8fxgunKC9Nrr3H213Tw5l4
         7XAg==
X-Gm-Message-State: ANoB5pmMYTaHk2Na9igjlWUVG5Xq9rtRivl9IP8T7PgK6v8zwFiqSaxU
	gO/Av+U56blizwU8iBy7JQ4=
X-Google-Smtp-Source: AA0mqf7mw9shd2CavNuw80xTKTE8ZhVBl7RmQsDV/5Chado6aW3kpudBIW/AXphhc6R0mux3xFOuYg==
X-Received: by 2002:a02:715a:0:b0:375:260d:56ad with SMTP id n26-20020a02715a000000b00375260d56admr9640927jaf.302.1669079418353;
        Mon, 21 Nov 2022 17:10:18 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:368b:b0:6bc:c593:b6b3 with SMTP id
 bf11-20020a056602368b00b006bcc593b6b3ls1388084iob.6.-pod-prod-gmail; Mon, 21
 Nov 2022 17:10:17 -0800 (PST)
X-Received: by 2002:a05:6602:3793:b0:6dd:cb01:28e1 with SMTP id be19-20020a056602379300b006ddcb0128e1mr598574iob.143.1669079417763;
        Mon, 21 Nov 2022 17:10:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669079417; cv=none;
        d=google.com; s=arc-20160816;
        b=esOUZs7JUTjedI9yTiaU9mikUbN8EmiXwgxbIRBqY9W5WS6ZroGbUaLtUOru9TPPIE
         0vBZILBQ0JCxgz/+tAsLpPwpmIduwSV6Q5q5GLTVJca5d6gDT989O3ToKRfGrNjZEQZm
         sXvDp0LUfKzV+MWNCdYABt4nyR+E37HMQWTzc5oA9dPa1TOuT3PRGl2NbGyJZaKHouaE
         FGp3OD/AE5ECSV6b+c90OwrUCc5LjtBBuoSiCs6dgQXjeCXVA3L7Cb9grtUNV11StElp
         Bcy4YUxacfKU5ptSTZSGJoQKF8RwkXa3c16TLSKUr9lLbvwumPJ22rM5F0NKYj8vDMSU
         8uEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=mWfplSyQuOQzLufcBt98OE1wcAoCjkpMAC/xW8Za5Fk=;
        b=gK4ifxpmkOkFh3HHFizBfCo6vHEdLjHcnfYg9tWn9AvEaLcU1FqmmFSxoDNYMshBjw
         P6nDZwvpaIKPFYdx+M9iCF9cz6QROzorYtRj5qvjzhLvK8KGMyOvKIE7D/rTZqyoUAah
         8qqtsRTEfrt4w4Ssdwa2r8We8IfwbYgQ4jLSCLJdPYXnw5iBsiYV6HtepzxUBuQyxAOg
         /R2nwquFH+XCAe8pdpInwC7upRJHvnrZXunqO4RDpK9FaXqw4hUns8bpd0RSAn96JrTa
         Tu3zNpeyhLIM/7Uxrds6Lx3ZDIhSzgOPTQsS1IoghKMZ+84DNh8CGIdOQ0cbb1Mdf8G0
         15Aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=OXYhE2rl;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=abdIp8Xy;
       spf=pass (google.com: domain of 010101849ce2bf0e-29a97289-86ec-4c5e-8e69-b67bcb0c8ba8-000000@us-west-2.amazonses.com designates 54.240.27.21 as permitted sender) smtp.mailfrom=010101849ce2bf0e-29a97289-86ec-4c5e-8e69-b67bcb0c8ba8-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-21.smtp-out.us-west-2.amazonses.com (a27-21.smtp-out.us-west-2.amazonses.com. [54.240.27.21])
        by gmr-mx.google.com with ESMTPS id z12-20020a921a4c000000b002e8ece90ea6si539776ill.1.2022.11.21.17.10.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 17:10:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 010101849ce2bf0e-29a97289-86ec-4c5e-8e69-b67bcb0c8ba8-000000@us-west-2.amazonses.com designates 54.240.27.21 as permitted sender) client-ip=54.240.27.21;
Date: Tue, 22 Nov 2022 01:10:16 +0000
Message-ID: <010101849ce2bf0e-29a97289-86ec-4c5e-8e69-b67bcb0c8ba8-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Andrey@localhost, Ryabinin@localhost, aryabinin@virtuozzo.com,
        Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3224929: commit d8387e1ef5b8ddba0a416ad8536c05289cdba7e3
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.22-54.240.27.21
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=OXYhE2rl;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=abdIp8Xy;       spf=pass
 (google.com: domain of 010101849ce2bf0e-29a97289-86ec-4c5e-8e69-b67bcb0c8ba8-000000@us-west-2.amazonses.com
 designates 54.240.27.21 as permitted sender) smtp.mailfrom=010101849ce2bf0e-29a97289-86ec-4c5e-8e69-b67bcb0c8ba8-000000@us-west-2.amazonses.com;
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

Change 3224929 by automation@source_control_dishonor on 2022/11/22 01:03:07

	commit d8387e1ef5b8ddba0a416ad8536c05289cdba7e3
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

.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/Documentation/dev-tools/kasan.rst#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/Documentation/features/debug/KASAN/arch-support.txt#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/Kconfig#3 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/Documentation/dev-tools/kasan.rst#2 (text) ====

@@ -12,7 +12,7 @@
 therefore you will need a GCC version 4.9.2 or later. GCC 5.0 or later is
 required for detection of out-of-bounds accesses to stack or global variables.
 
-Currently KASAN is supported only for the x86_64 and arm64 architectures.
+Currently KASAN is supported only for the x86_64, arm and arm64 architectures.
 
 Usage
 -----

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/Documentation/features/debug/KASAN/arch-support.txt#2 (text) ====

@@ -8,7 +8,7 @@
     -----------------------
     |       alpha: | TODO |
     |         arc: | TODO |
-    |         arm: | TODO |
+    |         arm: |  ok  |
     |       arm64: |  ok  |
     |       avr32: | TODO |
     |    blackfin: | TODO |

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/Kconfig#3 (text) ====

@@ -39,6 +39,7 @@
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010101849ce2bf0e-29a97289-86ec-4c5e-8e69-b67bcb0c8ba8-000000%40us-west-2.amazonses.com.
