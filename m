Return-Path: <kasan-dev+bncBCJMBM5G5UCRBLNV6CNQMGQEFQ7HJQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 68E5663317A
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 01:41:19 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id z9-20020a17090ab10900b00218c5bdfd55sf1324227pjq.9
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 16:41:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669077677; cv=pass;
        d=google.com; s=arc-20160816;
        b=odCN0UiYohSMMk5Z+1nl4q8vgaP6liUXxf+MnG0fzBmnwaQtzE/RGcep2DV/IwyEtN
         JjGTo7CBkKQmAoQwJpzjVRU3293fzURFFvZAx+SU6c5HUA2nsuD6w3bVZXMJMG3wcAuH
         +Ly00/p2VDY6ZacNxq4HhI44+DrmqA9wciONia2j12P6EiA75CsHis9Zs8SmHcHnxMjW
         fYCziRXxI9tndJQ9/No1zLADyOFqX0w0L+4hfQ2pjH2NR89Tk76qNMd0M/h0Zp8s4Cy3
         BY0AzLE2KMbYLfwZerCiAsCebZb1114B8dnu94tRLMh+4qZfNGLcuW8/zPZIzmYI5TTf
         QmNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=bS4Nn2HP/q1YYk1CSDtsX+YyZIIlYXALta5xdLA/YJI=;
        b=oL5IC3MTzMRva/dljuKxLDqTVG300gJlV2lA3TCz5BuhUcoLqBNdKzE1965oMJ8gK6
         Fg1k2wvaLE5JtFeCXeW+9XNKaa8lwjLe9oMGGu6Eb2VKYWKSeQvtPReWEnB+xZwiiiJA
         yFA3McYNtFng+J0xKA5/vBHVt6nK/y6YuR+v8IvDdN69HrFyLAhbiXnSYRF1oAaaEkoV
         lv2sQB+3d3ncuVE2V8MWWGyj29yFGmlaz23ICNBroq6nNN7dStHqDSWV0+MHgcUiZstA
         9S68lE2jgCn0x87rRsd7FC0mOk5ZY/RsDctNOT+WNqPm0/lAjOZBQWMwp7MWQMnKiDKY
         6vwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=p2f8aXJd;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=Lk+Ja891;
       spf=pass (google.com: domain of 010101849cc82f87-b1a35720-6592-4cfd-a01e-e79966110126-000000@us-west-2.amazonses.com designates 54.240.27.56 as permitted sender) smtp.mailfrom=010101849cc82f87-b1a35720-6592-4cfd-a01e-e79966110126-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bS4Nn2HP/q1YYk1CSDtsX+YyZIIlYXALta5xdLA/YJI=;
        b=BASKPpqE/DgKMcR2+XIw3n9D/ZmQGrlrf2toTzgkEkfQATMXRcAf95aPxOSZSK2mBY
         v/gdyWJ3KyzGG/Pe2z0GEww8lz0iz0h/v2flbcY8chtdDFWcmW31XMnqg19rwqD6rWvQ
         o7F3Opmf1bsYeFjypX02L/Xq73LQNe+aJU1TvNgxQ5H7LAAyU2VXycXbQefpnqoUeAl7
         LG+gR3w+lX6hWzrvAfPj2RmZXvYxKr4kR+NQDscBFniBXtI1CchDjEwudGrAsPLBfZDM
         S8a8qmlClDMKMj+anqTukwgQJgBxrUizxt9ktP0HEt0dMQ0rEcw28tYzUTLc6qsx5k3l
         DybQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=bS4Nn2HP/q1YYk1CSDtsX+YyZIIlYXALta5xdLA/YJI=;
        b=OrMNzBu/g432BSy1PuAPjV9JleDCto2LKCWnKa5nsSgddOK469qiRdArQk3ZD96CM3
         LO1d1h126Uwa94iiXKulhHTYdzGN1sWh9oxTCcOc26fqBdtqRrB5NQa4/scdsavMwnSN
         92wDtN8htIzTx5J4NHM1JGV9HUuZU1HYFGhIEx49EpdHOIbGBLriRgcte3L/nHsXHf+1
         Ew8Tqy4zHdDfk8JrcxcVkqzSx1+AApMY99D1kI1ZeWLs0Hp0TVAudWzDiv+YbGVoPfT9
         CpHVTgiuPlVSdvM/AeeOgo+jK5iu+UzEomteZMjvAVqJeXqW8Y0EhzRIeSzggVbhDU3d
         Im1Q==
X-Gm-Message-State: ANoB5pm0pMUwx2E/y3ekh7MpPM4N6KqJUjbQiHKYzO+takqokgsaKsUk
	05WLKGBf0P2T+Ua5b3lQXPk=
X-Google-Smtp-Source: AA0mqf4ZkP7/JzO2ONdcPRS+HmbxZ3ysWC5Mv2gov1aJOKI/5yeLhtXEbgWyjRAQ7U/u0TwkZopDpw==
X-Received: by 2002:a17:902:e9cd:b0:178:2989:e2fb with SMTP id 13-20020a170902e9cd00b001782989e2fbmr1963697plk.81.1669077677409;
        Mon, 21 Nov 2022 16:41:17 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2014:b0:186:9fc5:6c01 with SMTP id
 s20-20020a170903201400b001869fc56c01ls6526028pla.6.-pod-prod-gmail; Mon, 21
 Nov 2022 16:41:16 -0800 (PST)
X-Received: by 2002:a17:902:bb84:b0:184:e4db:e3e with SMTP id m4-20020a170902bb8400b00184e4db0e3emr5593566pls.47.1669077676672;
        Mon, 21 Nov 2022 16:41:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669077676; cv=none;
        d=google.com; s=arc-20160816;
        b=av8Ends9+TAousC/NRk7rEmHEuxhWmMPi6JiL3yTURLDV2UipsHbDGP9nJu5k06zaR
         U+3YXXfRqtCSCf9aQe7JZcBmP9EAb4qVHi72mPP9VRKqDadfo2180GRgxh0qVk5Les9m
         mwyJp+HZrpW+ggHlLA+xSw7KSlFpEQYCWBjWzjxorDLUt/kTECWFHCLjVqa4SBH/L2IT
         J0OvEXNSXTSAfFomQVXqIq8SHqTFDImZcuta9cJyzG181yUE7hwyHe0Tdnct98z5t4gn
         K+idixzQwR62a06l3KyFDy+c7fko5UWjmBGAg6pTKUnOWPCYjD++Rq9vxt4RnO6ILSu2
         brXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=ZyxbjJMbyFuHS+SuS+4ESbIt8KVdSGhYiX5smy1QNag=;
        b=gg7QOutuMZ7nLgf5tN/ru5jbWtTtheHnx3e2GK/BNEHghknSkL4Ylqe2eIXNhL6/Fw
         ssObV/pszwijyebk0zhasA7ldtJl1zSk949zF3o9ZIw63PEohG1/FsC+iCSYISzI71Zt
         47jUJ/FkQi+JjIR2UqO4jE4N9YqgHZd8x1NftX7/IqvKav1Z949Im6YvtDO7UJ1taMf6
         7GYwcDwNGC3fLJ8CUROJc9fyiX1N+MZHBlWAlIdZCZGRP6v2Pq6aJ1WKiGH+uc8c2+UD
         ZHRfMmYrte2NnwKImb9g8gUdYSANWL/VHDlvUqY7BdCtYXCxelF0npGfUhjKzjL2zYzT
         TcDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=p2f8aXJd;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=Lk+Ja891;
       spf=pass (google.com: domain of 010101849cc82f87-b1a35720-6592-4cfd-a01e-e79966110126-000000@us-west-2.amazonses.com designates 54.240.27.56 as permitted sender) smtp.mailfrom=010101849cc82f87-b1a35720-6592-4cfd-a01e-e79966110126-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-56.smtp-out.us-west-2.amazonses.com (a27-56.smtp-out.us-west-2.amazonses.com. [54.240.27.56])
        by gmr-mx.google.com with ESMTPS id k17-20020a170902c41100b00189348ab16fsi2918plk.13.2022.11.21.16.41.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 16:41:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 010101849cc82f87-b1a35720-6592-4cfd-a01e-e79966110126-000000@us-west-2.amazonses.com designates 54.240.27.56 as permitted sender) client-ip=54.240.27.56;
Date: Tue, 22 Nov 2022 00:41:15 +0000
Message-ID: <010101849cc82f87-b1a35720-6592-4cfd-a01e-e79966110126-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Andrey@localhost, Ryabinin@localhost, aryabinin@virtuozzo.com,
        Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3224909: commit 13d2dc778e425788fdb3d5f16264fd51c883c71d
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.22-54.240.27.56
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=p2f8aXJd;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=Lk+Ja891;       spf=pass
 (google.com: domain of 010101849cc82f87-b1a35720-6592-4cfd-a01e-e79966110126-000000@us-west-2.amazonses.com
 designates 54.240.27.56 as permitted sender) smtp.mailfrom=010101849cc82f87-b1a35720-6592-4cfd-a01e-e79966110126-000000@us-west-2.amazonses.com;
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

Change 3224909 by automation@vsergiienko-flipday-internal-rtd1395-nemo on 2022/11/22 00:39:43

	commit 13d2dc778e425788fdb3d5f16264fd51c883c71d
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

.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/boot/compressed/Makefile#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/kernel/unwind.c#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/mm/Makefile#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/vdso/Makefile#2 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/boot/compressed/Makefile#2 (text) ====

@@ -23,6 +23,7 @@
 endif
 
 GCOV_PROFILE		:= n
+KASAN_SANITIZE		:= n
 
 GCC_PLUGINS		:= n
 

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/kernel/unwind.c#2 (text) ====

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
 

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/mm/Makefile#2 (text) ====

@@ -7,6 +7,7 @@
 
 obj-$(CONFIG_MMU)		+= fault-armv.o flush.o idmap.o ioremap.o \
 				   mmap.o pgd.o mmu.o pageattr.o
+KASAN_SANITIZE_mmu.o		:= n
 
 ifneq ($(CONFIG_MMU),y)
 obj-y				+= nommu.o

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/vdso/Makefile#2 (text) ====

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010101849cc82f87-b1a35720-6592-4cfd-a01e-e79966110126-000000%40us-west-2.amazonses.com.
