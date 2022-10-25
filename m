Return-Path: <kasan-dev+bncBDBK55H2UQKRBHHX32NAMGQEILWQY3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 897CF60CA2A
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Oct 2022 12:34:05 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id e21-20020adfa455000000b002365c221b59sf3400351wra.22
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Oct 2022 03:34:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666694045; cv=pass;
        d=google.com; s=arc-20160816;
        b=vl/OuFdT+mv98y33HmfvAT5CT6tODEx8nfUnp80InFF3hgWCcSBEPzKmcpFt2bF1zk
         PiWkUpB1jaaKHuZvKQS3+oKCP4b30kYgGGfpRyBU+Ct/sSJgdGJWgWfdCKGhvJvZbpRM
         GcyngBtp0U966TU04NnnrPRs7V6qdJ8u6Lt2ohmc71TrvfBzCkPBicJgkkYb+YZnNh8F
         rwRyZNTPwE+Sn/XirUR0v47XaPfxK9yzaAwnqX2q9kVAPqI+NtUVm3zD+lb+B11VzqOK
         xU2ueunMcS+xppqTgYmMKS0j2uBrN3RDE2ETcri59cNDDSkUogWyGkEwQyrMMPwR161Z
         DNZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tHPXMTcV/HMbY4gr77TIm1ObliWKfu+2QN8J5g6/8ug=;
        b=HI0rDCnm3gLFuWml5jqo1tXS1ql5H96G1su2mnSWWN1RGBmrHLvUSh6YOjYpynGeAs
         u8Zai96Ox+CWbcZ16ToGTo7qudeOcEhxOmBKgqrZkd+Sq5PMb9gFhBb04NI7tch1yBYB
         0/NluuGJua5fXSLebDMD5c8swwLeqHlnCIX1JW1PVUEx0EsmjWdor37+qeKyn7JVbmhH
         S6nLseFLkZAMKuMmdLJ2qoX/zcRmRb4gxPbRuFasS4DopAV6YF59offrvxVMwYnL+UCg
         WdSutw/PAoEXxibVtkUJrfvZjGekdjc3Bc5EX802T4RGjD1dA0Gg5spZzmDwiuUc2s7P
         nu0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=pwDgHKGN;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tHPXMTcV/HMbY4gr77TIm1ObliWKfu+2QN8J5g6/8ug=;
        b=lliQFH70AuEojDXJ5QtI4fkUBUUIm0hLDgDke4Axy8SPckKMYueknM5MRJgjHd8XLM
         4jA883x+82+6xIu8JdOnWifST70eALEAgot722Ppqps0bLQ7kOtJSN0gOX14kHlwVE/a
         e7mySE1nrK5ue7oXQSk4nGOW5GLrRaQyHjGOyHpZB6DRkgrEcNkzHPpzM0PzONEyuFY1
         mHjNBq6C9g2PEJipEObdgpre4HyGw5tsuCOs9rE5Y+yICIFhoFOQljSaWPqRiSy7w8Ak
         7nolSvJE+0eppI9i+rvbafKVeaKB2Ze4OJpdJ2Z5TGO3kHwgbrxydtY/eGdzimyqkud0
         Dtpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tHPXMTcV/HMbY4gr77TIm1ObliWKfu+2QN8J5g6/8ug=;
        b=fZMxcFw/9ZV69qt8oFEpsFczjzy+JaR72L0vete74JSvU1RYmgTJAxVxskVqtNkTl3
         UozUEej2Fzvj8ZZ2rDzxcj4jiBEu1BW8XmhREfgtWePVw+hKUwfx9XvXldGJ7nmzY2Sn
         cGFUwDdqdGsCjhimKWuXdzEECRcybNzD5aTl0tkS2crx48sbyPx7928spiG3sNjl2J6B
         xovGTKoPCl3l/Jnuwc2EHqiNVqS9v03FXb2WQvSwzYsQz+r7o/vRREuVx0z4yRnIg8g/
         Rp6UYJem+IgeGxkO5UdM3QgrZxA4Zz1v3Ad3ly2iJaiHnr8TSs6hHsXFs8xFMLMs4GWj
         4AtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1aHvqQ9L88MX6MZE3Wsa7jDexRrwXaUSxtJhA0ba5hh9UdVWXV
	zBpqU8ujlGciaurNrOOGixk=
X-Google-Smtp-Source: AMsMyM7jzO6Kx2ybCMmtD7RxFixnJFINhiBjN53FmeRV76PxrLDPJrMwWjCMv2sJOBXzBpo/ZjixSg==
X-Received: by 2002:a05:6000:1882:b0:230:9595:4131 with SMTP id a2-20020a056000188200b0023095954131mr25421347wri.17.1666694044985;
        Tue, 25 Oct 2022 03:34:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:222:b0:22c:d34e:768c with SMTP id
 l2-20020a056000022200b0022cd34e768cls3851989wrz.0.-pod-prod-gmail; Tue, 25
 Oct 2022 03:34:03 -0700 (PDT)
X-Received: by 2002:adf:e196:0:b0:236:740f:f234 with SMTP id az22-20020adfe196000000b00236740ff234mr5758097wrb.518.1666694043795;
        Tue, 25 Oct 2022 03:34:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666694043; cv=none;
        d=google.com; s=arc-20160816;
        b=ZEL5/DgpAl0BUOGTsy/49K2g2PzUW7oq9txjvtGnCCcdLaxklFsr2piVYYbonbmz+9
         It5ptv0SmYNsuHRT3W38YENXkdZTEOELIL+9aep3jmuElLbRVpFi+xET1k6hwo0iijyA
         9AM6k/5tmGEhf5zGwQFBMdGD+usGar4y51pEaZwR3DXWg4bPbU0fGxAQQjn2LDXvNYVp
         Ws8tnaMXQ24PjgS1LN/2XDinS4r3jxqgz0g4PHBvP5Q3Qt/QclJInuBgPvIZz3l2nW4R
         JCf+vp2+oKrvHEDVWkttECuYlGEpDza18rNFiO+e3jui6yfm4L2FGEMF82I68QE6yKoX
         plCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=w7jyh7t+HSd8ls+5K8wYXg67ORftlivpSuWpTIAA1Ec=;
        b=y3olT00KyE3f2LuxRNuUpLKH1H4W9BXVYQ73Os24FftA2R4H7VjUiCgthnG8Bx1Oou
         C89iIUro4BJly807RQcKIDfsuVrYpgdcP3LeaZ/R5B3z/S/7RPy+g8pNXtU86I3bilPO
         FLxC2yqaWYs3Gn7Alqi8/qiHZPmAaPhUMkAWUA4OBCnbg6mzG04AKievDkWrKdOhENjL
         CoylKtoQ/qMjR1v9bwTY4o+iVdqVu8tvqlHgw7rDqk+nuHp/jplQ9YYG3z6dthevAqX5
         U9IvaTHL3VmJd9tNOJBLCiGZ82EZ6jiAThdzrldKWaATPLhqiPcemQmu+WymL2CwkCq5
         nS9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=pwDgHKGN;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id cc8-20020a5d5c08000000b00236845a6242si26862wrb.2.2022.10.25.03.34.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Oct 2022 03:34:03 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1onHFr-006I9L-Aw; Tue, 25 Oct 2022 10:33:55 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id BF151300169;
	Tue, 25 Oct 2022 12:33:54 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id A028B2C431FAA; Tue, 25 Oct 2022 12:33:54 +0200 (CEST)
Date: Tue, 25 Oct 2022 12:33:54 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: kernel test robot <yujie.liu@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Seth Jenkins <sethjenkins@google.com>,
	Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org,
	x86@kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, "Yin, Fengwei" <fengwei.yin@intel.com>
Subject: Re: [tip:x86/mm] [x86/mm] 1248fb6a82:
 Kernel_panic-not_syncing:kasan_populate_pmd:Failed_to_allocate_page
Message-ID: <Y1e7kgKweck6S954@hirez.programming.kicks-ass.net>
References: <202210241508.2e203c3d-yujie.liu@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202210241508.2e203c3d-yujie.liu@intel.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=pwDgHKGN;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Oct 25, 2022 at 12:54:40PM +0800, kernel test robot wrote:
> Hi Peter,
> 
> We noticed that below commit changed the value of
> CPU_ENTRY_AREA_MAP_SIZE. Seems KASAN uses this value to allocate memory,
> and failed during initialization after this change, so we send this
> mail and Cc KASAN folks. Please kindly check below report for more
> details. Thanks.
> 
> 
> Greeting,
> 
> FYI, we noticed Kernel_panic-not_syncing:kasan_populate_pmd:Failed_to_allocate_page due to commit (built with gcc-11):
> 
> commit: 1248fb6a8201ddac1c86a202f05a0a1765efbfce ("x86/mm: Randomize per-cpu entry area")
> https://git.kernel.org/cgit/linux/kernel/git/tip/tip.git x86/mm
> 
> in testcase: boot
> 
> on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
> 
> caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> 
> 
> [    7.114808][    T0] Kernel panic - not syncing: kasan_populate_pmd+0x142/0x1d2: Failed to allocate page, nid=0 from=1000000
> [    7.119742][    T0] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc1-00001-g1248fb6a8201 #1
> [    7.122122][    T0] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-4 04/01/2014
> [    7.124976][    T0] Call Trace:
> [    7.125849][    T0]  <TASK>
> [    7.126642][    T0]  ? dump_stack_lvl+0x45/0x5d
> [    7.127908][    T0]  ? panic+0x21e/0x46a
> [    7.129009][    T0]  ? panic_print_sys_info+0x77/0x77
> [    7.130618][    T0]  ? memblock_alloc_try_nid_raw+0x106/0x106
> [    7.132224][    T0]  ? memblock_alloc_try_nid+0xd9/0x118
> [    7.133717][    T0]  ? memblock_alloc_try_nid_raw+0x106/0x106
> [    7.135252][    T0]  ? kasan_populate_pmd+0x142/0x1d2
> [    7.136655][    T0]  ? early_alloc+0x95/0x9d
> [    7.137738][    T0]  ? kasan_populate_pmd+0x142/0x1d2
> [    7.138936][    T0]  ? kasan_populate_pud+0x182/0x19f
> [    7.140335][    T0]  ? kasan_populate_shadow+0x1e0/0x233
> [    7.141759][    T0]  ? kasan_init+0x3be/0x57f
> [    7.142942][    T0]  ? setup_arch+0x101d/0x11f0
> [    7.144229][    T0]  ? start_kernel+0x6f/0x3d0
> [    7.145449][    T0]  ? secondary_startup_64_no_verify+0xe0/0xeb
> [    7.147051][    T0]  </TASK>
> [    7.147868][    T0] ---[ end Kernel panic - not syncing: kasan_populate_pmd+0x142/0x1d2: Failed to allocate page, nid=0 from=1000000 ]---

Ufff, no idea about what KASAN wants here; Andrey, you have clue?

Are you trying to allocate backing space for .5T of vspace and failing
that because the kvm thing doesn't have enough memory?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y1e7kgKweck6S954%40hirez.programming.kicks-ass.net.
