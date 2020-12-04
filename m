Return-Path: <kasan-dev+bncBCT6537ZTEKRBQH4VH7AKGQEPTI5Z7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 406E52CF3E3
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 19:21:53 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id h3sf2320127ljk.11
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 10:21:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607106112; cv=pass;
        d=google.com; s=arc-20160816;
        b=pIQ2+SdkVr77WHJie0/Lv4B/J6yR8lTwpR8Zwx0vIZh3JVtJj1czwjDMhlX3eJDZfQ
         1uOBlRWcK7E6ova1zkjbDnfxOjBLcVisC+c/Rivd3Yd7VWmoGwp5N82BcaMCppM6FLzv
         0m0LGaIGXd7mB7bN9VuNkW2VJqfL57QNYqpuIO+j0KeqNp8bqR9qDam3raCmL7uwZLHE
         EQSuuY020gEORgCeJHc6pXubHKuvGq3JJzEUYLq8UZIWXSkXbFrSbXmk2vH8yBUgpSJK
         uwHU2Xcbt8qThIOeiolonXXrD8FoItgK5Ca9ts+znOdj5eWApbRFpTQfLe1HAlgiBjiD
         Yx0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=MslnNDUhngP+ia00rbA6zb0u6kjMp4gS7xrhp+QkfJY=;
        b=T7GiULJDLk7qNQB7Qx37LBbM+OGNsc406ZlXUHjGCRO7fCKfsczBu4ZVmZzd7eOUSB
         A/UPi5EhsxqlMP4Y8ohKH42PiOpkfvpuqmmSNMOXcAVHQT1YApm4kSKeTZuDnCdnOgDg
         WI6OzWT3GNbhzgtYuitkpZjERc7jlP66ujw8h8DOhq54OU2/PLRWdmRJSoJNJBnPjaWg
         /g1/W6HhiNkO+1CRB5/m4/rTK1jzzS4H/uscPpL9PZG4R3oVmAs1+d0pTYZiJwr8bTDU
         Owjy/+0oh0mADdhZ0pdxSxut7l6QgSfULSNHgqOiM5D2gRbn2Ua1GKuKobulcNk+nwYD
         aKAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=EL5y9hBp;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MslnNDUhngP+ia00rbA6zb0u6kjMp4gS7xrhp+QkfJY=;
        b=sp9sb/jNZFu+M/ofnFR9+dOgeJhOoPCsdEHjflEZ0m0lzPFN28BwmUnepjhrHCd+mf
         M73jqSHDp2+vQ4lSDUnNKCIYY8oTGQP3S52Y9GgcDsDHiQbK5NH2wUIHFHRvQfiA4tB6
         3Cn9loo/7OU3xfFMDqH/BB9pSZYkkh14He5yikYBvd2SiXNs5MGFE09uJeYgP/0+wjQ3
         bZchjBLR3nlLL/7SOiy2gMnC1YsnHu7drRb83+TohCPzhhrFe8wQ2PuyBfEQ2gXIsf66
         Sr1AG1Bvi6vKiuf9wtPNl5zulYY5fS+XyXsJpBhblm0Nq7XCOjJKbAcI8ooCyU+h7kL6
         R49w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MslnNDUhngP+ia00rbA6zb0u6kjMp4gS7xrhp+QkfJY=;
        b=BztvOaAGrCiz/blfS+HwBgMWHhS7ZgnKlybYGni3ibhUng20B1kldVffQMdoLaaXY7
         HLdUP+GkOynm6dyfRu2cRkSRoYlmjablV+ov3G1ryXeEENX6Lke226qMbeOYK5KPyBmy
         5rIA0zwwMNDXNN/VXi8u5tCzSXikP4HUoyqWL5QUIwjsgL8mCWVIhnWQoiOZRph1zAeu
         o3HmUpERXQY3vkrGO8DRFYq3hi4UfsQDaJBZ7Tj0wX9guJyXUeMBnGwWPseEEa7x6+Rm
         PkhrEYEctTaQyJ41nZknbmH5MpFA2fReCVBVJ1nLUx2AZXtHUObaG8NSm2rH7eKwcrh3
         rPig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531aDUNMeDJUbfxf8bpQQ/3YNBuZRtYSHL8axZVXF/AbUJb3M1Al
	OYxagLbRaku19ZXOz2RFce8=
X-Google-Smtp-Source: ABdhPJwKs3WAMG2CXjE4ALNpht7aoR2LiJ/oxumBiYKMiU7BPNW+yGXtfQPO1hNspbxaR8wVNae3fA==
X-Received: by 2002:a05:6512:3054:: with SMTP id b20mr3686403lfb.45.1607106112726;
        Fri, 04 Dec 2020 10:21:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1114:: with SMTP id d20ls1809549ljo.11.gmail; Fri,
 04 Dec 2020 10:21:51 -0800 (PST)
X-Received: by 2002:a2e:6a11:: with SMTP id f17mr300958ljc.202.1607106111648;
        Fri, 04 Dec 2020 10:21:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607106111; cv=none;
        d=google.com; s=arc-20160816;
        b=mYukgxteaqGoSzMr13p3CWGyA9Fim/Z5ljKDFRAaQgwMLV+29Ez/3z+/4CmuWXNpIq
         CIjQwNXVpY2bzVgKsRIJgYEM/XYDsvWTJrcLz0OEVQdCcHraZUVSrWJ14JVbr7SWs1WF
         sIdE/dCVbKKjlQk0A0loSsZDHINiJym6s5FYBcgkyyd+S4x0bTe1MgFj7JH+NJobyTkv
         UDEsYOChA/76345H1WoYm8eH8wPv7CVYhVCJ22OM2NRTkUN0En0DYLfzcbS1nm4Upizq
         FqGNNS/pD0dD6nabs0fUmwH9vZ9+grMToQmmFf6oMoBKE433BsRz/6Qy7m/K5DNqdcVT
         k6Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=ZRVh9nEjQvUMIF508xcL3n/raN8xu3HvHHn5B7tzkG0=;
        b=KLLNGKFx+xfGChWntdG8u6YZ7waG+I5xuauomIGP78EfXat9pMT4ZQDQDTGA7wSFTF
         xauRsESCvPykCu7kMfeI+KUKkVJf6llLOVXvbonwvTZUjVHMNXs1tF9SlI3GyPsVCKZM
         ttg+tSjoMVSg8Kcrg4uVeNElPZFSzJ4lHMs9MIdk2L/oRLqORhpnBfB58XLDb1D1eWAE
         iC8y5j8GpPj3qf8Egq//ZMlTPO5SWA5CSbuWwhRQ3p3eDkiFWmGwS3WyXVGkbosZ7+FG
         oPTjzeRSypOVSJz+HmUvZr3r4KsMCTjsIICQ88aajK1iDeiJ8B4NcqC1H+FVAEfxo0xU
         0Zgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=EL5y9hBp;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id q189si166661ljb.1.2020.12.04.10.21.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 10:21:51 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id b2so6809258edm.3
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 10:21:51 -0800 (PST)
X-Received: by 2002:aa7:da8f:: with SMTP id q15mr8747868eds.239.1607106110881;
 Fri, 04 Dec 2020 10:21:50 -0800 (PST)
MIME-Version: 1.0
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Fri, 4 Dec 2020 23:51:39 +0530
Message-ID: <CA+G9fYuJF-L+qHJ3ufqD+M2w20LgeqMC0rhqv7oZagOA7iJMDg@mail.gmail.com>
Subject: BUG: KCSAN: data-race in mutex_spin_on_owner+0xef/0x1b0
To: open list <linux-kernel@vger.kernel.org>, linux-usb@vger.kernel.org, 
	lkft-triage@lists.linaro.org, rcu@vger.kernel.org, 
	kasan-dev <kasan-dev@googlegroups.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will@kernel.org>, Lee Jones <lee.jones@linaro.org>, 
	Thierry Reding <treding@nvidia.com>, mathias.nyman@linux.intel.com, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=EL5y9hBp;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

LKFT started testing KCSAN enabled kernel from the linux next tree.
Here we have found BUG: KCSAN: data-race in mutex_spin_on_owner
and several more KCSAN BUGs.

This report is from an x86_64 machine clang-11 linux next 20201201.
Since we are running for the first time we do not call this regression.

[    4.745161] usbcore: registered new interface driver cdc_ether
[    4.751281] ==================================================================
[    4.756653] usbcore: registered new interface driver net1080
[    4.752139] BUG: KCSAN: data-race in mutex_spin_on_owner+0xef/0x1b0
[    4.752139]
[    4.752139] race at unknown origin, with read to 0xffff90a80098b034
of 4 bytes by task 252 on cpu 1:
[    4.769781] usbcore: registered new interface driver cdc_subset
[    4.752139]  mutex_spin_on_owner+0xef/0x1b0
[    4.752139]  __mutex_lock+0x69d/0x820
[    4.752139]  __mutex_lock_slowpath+0x13/0x20
[    4.781657] usbcore: registered new interface driver zaurus
[    4.752139]  mutex_lock+0x9d/0xb0
[    4.752139]  ata_eh_acquire+0x2e/0x80
[    4.752139]  ata_msleep+0x91/0xa0
[    4.792317] usbcore: registered new interface driver cdc_ncm
[    4.752139]  sata_link_debounce+0x1ad/0x2f0
[    4.752139]  sata_link_resume+0x32f/0x4a0
[    4.752139]  sata_link_hardreset+0x456/0x640
[    4.802369] usbcore: registered new interface driver r8153_ecm
[    4.752139]  ahci_do_hardreset+0x177/0x230
[    4.752139]  ahci_hardreset+0x23/0x40
[    4.752139]  ata_eh_reset+0x91e/0x1bb0
[    4.810641] ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
[    4.810482]  ata_eh_recover+0x79b/0x2bd0
[    4.810482]  sata_pmp_error_handler+0x7d1/0x1340
[    4.810482]  ahci_error_handler+0x7c/0xc0
[    4.819247] ehci-pci: EHCI PCI platform driver
[    4.810482]  ata_scsi_port_error_handler+0x708/0xd30
[    4.810482]  ata_scsi_error+0x128/0x160
[    4.826321] ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver
[    4.810482]  scsi_error_handler+0x26d/0x700
[    4.810482]  kthread+0x20b/0x220
[    4.836069] ohci-pci: OHCI PCI platform driver
[    4.810482]  ret_from_fork+0x22/0x30
[    4.810482]
[    4.844397] uhci_hcd: USB Universal Host Controller Interface driver
[    4.810482] Reported by Kernel Concurrency Sanitizer on:
[    4.810482] CPU: 1 PID: 252 Comm: scsi_eh_1 Not tainted
5.10.0-rc6-next-20201201 #2
[    4.810482] Hardware name: Supermicro SYS-5019S-ML/X11SSH-F, BIOS
2.2 05/23/2018
[    4.855343] xhci_hcd 0000:00:14.0: xHCI Host Controller
[    4.810482] ==================================================================

metadata:
    git_repo: https://gitlab.com/aroxell/lkft-linux-next
    target_arch: x86
    toolchain: clang-11
    git_describe: next-20201201
    kernel_version: 5.10.0-rc6
    download_url: https://builds.tuxbuild.com/1l8eiWgGMi6W4aDobjAAlOleFVl/

full test log link,
https://lkft.validation.linaro.org/scheduler/job/2002643#L831

-- 
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYuJF-L%2BqHJ3ufqD%2BM2w20LgeqMC0rhqv7oZagOA7iJMDg%40mail.gmail.com.
