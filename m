Return-Path: <kasan-dev+bncBCJMBM5G5UCRBUO4SWOAMGQEK4DOFFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EE1363B7D2
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Nov 2022 03:28:35 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id d130-20020a1f9b88000000b003b87d0db0d9sf5541079vke.15
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 18:28:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669688913; cv=pass;
        d=google.com; s=arc-20160816;
        b=lP0bW6MtCghAEi3Zh7rd1e8VIq2Ls8tnTD5PgEvS4TAJvBxssdXixt4bOT6J2lOq2p
         a5yxmtDlTCcItPRvzTLpPsaK7vRaelirG6Uso6y9nlgmScygL/SJSNtVP+7Tv/5ECBnS
         UzSpA9Zks12PppG8D0hE+RT5J9fKU0hDExBUGmkiHMo6xMib9qA7MR7ai4KpT14WF0f5
         lW39IdJnFu4toDyi73L6toeCnNWvjR/dPIJLnMZonnkac5vvZ2pR7MNJmClo7SWedF33
         5YZPNLjAuGZgtKP9SIiOsnQi3VJT+uVoYM7IXNrDlTmFKd7RzoEfolaqdYb8pm0Eq1tB
         rtDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=ZfH7WmtKDOpCS2yKDHaQFRGCVheG1+sqwPqEibzdaL8=;
        b=Q0+5O493WzTBd/m4vbCaybx+v4fH5uNHDNUBPUoUMrsQHPLjYHxkp8BmYf9NeEl9q0
         pKNhF3FNdnJgZBjVHQNh5cz6Yyw713XAMZjeGDsG6gzCxm8To0cMfnF6QTYB2GyCbRWw
         SQXyiBVtaQFAuobsOBD649T7LZQXYj8tPjm35Q5PsBYB+vQgRjuFiehUdDZhm8T4fXrb
         Z/GFhwpddeKRfq0BabCVckxOCl8NA0RndABNUD8t25nEnHuJZmNSNc83Uo5GptYTsnQl
         52FSnFh2Hebq+Ekg5S+SntWy6IOwiSxOrWnMAF6XJIsnurF48Mss4dPvG3sCyflBqQ/t
         HJ7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=G0cp5LY3;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=BhoicpMx;
       spf=pass (google.com: domain of 01010184c136e7be-adf24c58-e3dd-4430-a7bb-5156b58c148d-000000@us-west-2.amazonses.com designates 54.240.27.185 as permitted sender) smtp.mailfrom=01010184c136e7be-adf24c58-e3dd-4430-a7bb-5156b58c148d-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZfH7WmtKDOpCS2yKDHaQFRGCVheG1+sqwPqEibzdaL8=;
        b=X1T5mkvG3MnV9DvszoedWXM4s+/J/tmjzCCxCaMSe9PRO0pRoFd/aTAW3x5tN7I/SI
         xkxuDtyl4hspx1hxhcXqGRLHpz0Qein+Sc4usxOSgHIvJgcLj+ZL2QAq4Ujhnh2K7h9K
         iGVhXCIhLPgHj4P8NS3/NlYL8YvUuAmyj1EA2+ZfAPNH7rqtOW2eazn8uKSDlnTTZZr7
         bRW+vYdLCe74uA7JPe37mWquzcWH+eYcdk0IlBFqnMK5wasTSOQFNzrYIGgHb2Oy3S/w
         a07bK1Eff/8TnXPR30dVqdxVXTq79aDjsZB9lUn2Ikb8KU5rWVTZ5lxRi4++UXdigmEr
         1xDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ZfH7WmtKDOpCS2yKDHaQFRGCVheG1+sqwPqEibzdaL8=;
        b=ii3pSSBvnVWKJ2U5DZ76PHKvJLcH+VJU701bJRMD0rB8LKHkF7aZJH2kbTZUSvjoj+
         Rxa2oyCthTvLc1MR0ePAImSrHhCux4lQtyZRak1lMNI/SQyIKmc85Cb2LrGG1b93opbM
         PTOVv4KBGBMctUWuZd4U9flZnF5izQEluuaJNkBBvdQrP2ZfEndxO87IuBUdZd6DynBO
         UniPzjNczXlC3lNPsUDhIHwfY+2BVuotgNj/F3EDEwRH5vDoe38TaA7u1DlSNsvuFxwZ
         8x92mE/H1pdEE37HxKYcJ09at+qlDKw//c5ZTZhciGAhzaP7SutI0AAxL/4sTuWmtqYO
         8FXQ==
X-Gm-Message-State: ANoB5pmXlsbYpItjTFGajgZPu4v5oz1OBws3FlTckpd8pAiKpWkYK5JW
	JAw2h0t22uQ8040VssBrS9U=
X-Google-Smtp-Source: AA0mqf4bLLpe3vUOUIYyoVaMHEcdywZzjGjx7eUiJOm6NTTv7ZGORmFdqk25dl1xyTnhvdXzOTzopg==
X-Received: by 2002:a67:ff05:0:b0:3aa:2443:df10 with SMTP id v5-20020a67ff05000000b003aa2443df10mr17945533vsp.80.1669688913722;
        Mon, 28 Nov 2022 18:28:33 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c114:0:b0:3aa:190a:9431 with SMTP id d20-20020a67c114000000b003aa190a9431ls2183337vsj.4.-pod-prod-gmail;
 Mon, 28 Nov 2022 18:28:33 -0800 (PST)
X-Received: by 2002:a67:73c1:0:b0:3aa:1fd3:129a with SMTP id o184-20020a6773c1000000b003aa1fd3129amr22413305vsc.47.1669688913141;
        Mon, 28 Nov 2022 18:28:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669688913; cv=none;
        d=google.com; s=arc-20160816;
        b=ORLxZ1n14ENjdCkt9wxdcHRuw4gcNXyMfPenmyyImkpVmoWzBN7s7JdBLX9d0jfaEs
         DR4CGYJCs0ZQGLcpZAQxNKf4R1W++Ha931hRfnTR5BDv032GuDzLHU4jbg+AYHUiAfbP
         nh2oRIFyBs1gLHPI+dKA0xCfIu2Llm2Yw8JR77Ojr3DDen5WwaTaYar7J2VzNz7APloP
         F7NXOcWnwCVbqpNFYH4B8DmHXUtKkxmedsMdkmf91o3H/H2o4uglrI/YdxURu36wlrPw
         JBTOVLv7IbOkbvTmZeGs7+lhxGv7lPpgV02sH6DJr5guthR1asgPjRWAxENeH3LsONlE
         DX6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=47xfIPxm9HcRIfDuN9ti/yAWpXbjE6vBgXMp0AgTy7Q=;
        b=X9V0wHt7I/3u5eqOYRDMXiutoXsoyrafxEPd8TvHslkMhoHIkx51pYcJE1AYbtlKI9
         uw90yWZahU3wFK+yqcYKzAWor+DEwWsgnzd0PElnDN1bnqvNgti6NeQ/4ZZ0S2+DI9GL
         Bp9VrEbg5OBngsmb9W9wbEcyGVnlFKCVkF1OtgojATlSorxcqeEUHSNjEEJ/AD0W8KRw
         fXFvbDkY0qMEO3yzjpxdIrYIYVTiJh9i1fM3X5RRr6vvW36qMS7kPbnQGherg7yJPrLJ
         i0RdVNzgPYG8AftusJUmgCkJOJKFpo2Y3u5lH12U7XhxtwyeIDXpIy2OX03Xck0G2Phs
         eBEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=G0cp5LY3;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=BhoicpMx;
       spf=pass (google.com: domain of 01010184c136e7be-adf24c58-e3dd-4430-a7bb-5156b58c148d-000000@us-west-2.amazonses.com designates 54.240.27.185 as permitted sender) smtp.mailfrom=01010184c136e7be-adf24c58-e3dd-4430-a7bb-5156b58c148d-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-185.smtp-out.us-west-2.amazonses.com (a27-185.smtp-out.us-west-2.amazonses.com. [54.240.27.185])
        by gmr-mx.google.com with ESMTPS id p143-20020a1f2995000000b003b87d0d4e7bsi719724vkp.1.2022.11.28.18.28.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 28 Nov 2022 18:28:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 01010184c136e7be-adf24c58-e3dd-4430-a7bb-5156b58c148d-000000@us-west-2.amazonses.com designates 54.240.27.185 as permitted sender) client-ip=54.240.27.185;
Date: Tue, 29 Nov 2022 02:28:31 +0000
Message-ID: <01010184c136e7be-adf24c58-e3dd-4430-a7bb-5156b58c148d-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Andrey@localhost, Ryabinin@localhost, aryabinin@virtuozzo.com,
        Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3225584: commit 5187f2bb74a5046e1cf9f8c3a6ade89f17ea894c
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.29-54.240.27.185
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=G0cp5LY3;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=BhoicpMx;       spf=pass
 (google.com: domain of 01010184c136e7be-adf24c58-e3dd-4430-a7bb-5156b58c148d-000000@us-west-2.amazonses.com
 designates 54.240.27.185 as permitted sender) smtp.mailfrom=01010184c136e7be-adf24c58-e3dd-4430-a7bb-5156b58c148d-000000@us-west-2.amazonses.com;
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

Change 3225584 by automation@source_control_dishonor on 2022/11/29 02:20:59

	commit 5187f2bb74a5046e1cf9f8c3a6ade89f17ea894c
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

.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/Documentation/dev-tools/kasan.rst#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/Documentation/features/debug/KASAN/arch-support.txt#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/Kconfig#4 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/Documentation/dev-tools/kasan.rst#2 (text) ====

@@ -12,7 +12,7 @@
 therefore you will need a GCC version 4.9.2 or later. GCC 5.0 or later is
 required for detection of out-of-bounds accesses to stack or global variables.
 
-Currently KASAN is supported only for the x86_64 and arm64 architectures.
+Currently KASAN is supported only for the x86_64, arm and arm64 architectures.
 
 Usage
 -----

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/Documentation/features/debug/KASAN/arch-support.txt#2 (text) ====

@@ -8,7 +8,7 @@
     -----------------------
     |       alpha: | TODO |
     |         arc: | TODO |
-    |         arm: | TODO |
+    |         arm: |  ok  |
     |       arm64: |  ok  |
     |       avr32: | TODO |
     |    blackfin: | TODO |

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/Kconfig#4 (text) ====

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01010184c136e7be-adf24c58-e3dd-4430-a7bb-5156b58c148d-000000%40us-west-2.amazonses.com.
