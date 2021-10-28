Return-Path: <kasan-dev+bncBC24VNFHTMIBBB7O5OFQMGQET6RIEGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F0DA43E8EC
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 21:16:24 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id o6-20020a92a806000000b002590430fa32sf4567961ilh.17
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 12:16:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635448583; cv=pass;
        d=google.com; s=arc-20160816;
        b=r4LGyebOXbdD4HjBR8ehJaO2IaR6oEa0g7c+LaNOLeCEK8URZl0aCMUxxytChr066u
         S0LDHVm359IMKuwy2w5qLRLWYmU2/Bru3rq7fXIvaElst5LWLLRxh8WREOESN1uYaExb
         uAYU+c1fkkHkf1+knkLRhzG69zxLWZLSkKdfUm+/l6olSm/WPODs0RDUI+bF1F13lcJS
         jMj5WqTAsXEv7Rpx3/e7lvlwZnByBvwtyB2dym1KDmty4nMeciCBiuNXeNnsWGUBRuXQ
         DPMA5AD/kSUZFZ5Rbi+5U2yAAfqFmIQ4h0VALug7Xzr/V3MDEX/PumuzLpzAobVZzV6u
         xsfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=RxQPpib5XUY+0OSJpyB50U2/2t7IvoAG3auNZMdDQ0s=;
        b=OEHk4DOANPSUZ6XcbfuHLD4KgkA1oxsYXQB6RgFrt2EY3wTdEWTuBEyd55MPfN66d0
         OLyiiKsBC3nHFuofQM2hXdjbVuyNfE4dTgX567gaFfmkxJzc9gQtgfVh3flhVpz+j8xV
         jQZTvnvZNFPRNaCpDHxjI5kdMGcSyAfBvsL9EWOESlvYLxPLXMvddcWACEpnEzHPrpX+
         VKq8guPhE4QY0WMhF0AbRg/MeAwZ0btnRQpYGU9dh3jjK2zOg/cXGS4dET3l2yyh00HU
         axXkJQuWqexfhHg9qAdm3QBHpmuprwQ30XJciuzHnKcaNFSRqQJJRoCIbHLVRpMdiRVI
         HSig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DhpYdxUm;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RxQPpib5XUY+0OSJpyB50U2/2t7IvoAG3auNZMdDQ0s=;
        b=PbyuxGUZtLN2llWlTg/82WqiV2eb1vfTarNiVO3caF6qrJh4g3d645tBL7icmEWVWO
         PrApnyAY0lNjhBx9iQYW9XtYS7/IF/2MOfMl4L6mSFK6ZzE2db0RpEMq6cAfKSisGPlQ
         srvdqjj+0rQM4Bkx2r8z8wNrxwELyy7zB28o4LM9v6sIDukZB9LwoZ8gmSUMdzDqQ5r1
         YisuwQcawKtBof4XDM/UUAaGuqPi0xEwm+p9Igaop8Zz1OaHC3r96U2fY7eEmTGXKhPy
         +KUdAXlpxWBu0LuVQzLxXu24WQUFzUsaRPUU0onPd+8Y6lyz2LLcZxuqC7oE9g7INsGM
         /new==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RxQPpib5XUY+0OSJpyB50U2/2t7IvoAG3auNZMdDQ0s=;
        b=rP7EdCggTNeZy6aWmxlorXjXAsIgOO+wxHgc3Zff53vR2VqgXzwQ+NUnW0jVfNlbf1
         Co+QxTxv8JJq4joLs0zb2cVhZaOS9ku+7SW4CRGqQdrkYE7n+hTqpvaqK7G96IVe1Eb1
         rf4eq1iRMP/VxH2AMW1LyXgMTzipZC/x4wK1OJSOySlNIFTZWMmk8B0/wevzkGSzVdEY
         J2OcFdkkFyXR97nrd8AQ27EhrnkO8tvp3zBERgd8XuxkTnN8MDD+C37RATns3miiFHvD
         ndjzgh8HHFF6GwXTJLL0xhm4yn+nbElr5N6tQa4WDzBjYe2PVBBraB2+X2ZeZVfkNuey
         9c3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+akmuPeUAQwDkeSHl53WBt2FRotjBXWOJ5jJGp6o65qCIW16C
	Ot4tN3gPmafQawtYP5e2Pic=
X-Google-Smtp-Source: ABdhPJwPwg4PPbU9HUfwMEWEt5N5YlZzyd2Xa/b00pu7s4G/b/zbPbP2s2b0Kr61jVi9ZZH99TX/ew==
X-Received: by 2002:a05:6638:1612:: with SMTP id x18mr4739772jas.25.1635448583259;
        Thu, 28 Oct 2021 12:16:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:14c7:: with SMTP id b7ls782224iow.7.gmail; Thu, 28
 Oct 2021 12:16:22 -0700 (PDT)
X-Received: by 2002:a5e:8803:: with SMTP id l3mr4483520ioj.217.1635448582927;
        Thu, 28 Oct 2021 12:16:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635448582; cv=none;
        d=google.com; s=arc-20160816;
        b=YYno9SgK1AYNKQ2CoY85DXwkmxqkpe1igl2l1Z96SvNspFbQ7spi4N/08tRUEGpDga
         IawNGrnomBi821huFE8slWgUg33QOHUPVESiwfoooUzDtFtxO7/cHWj8J6H0+sD1MgZP
         BvnPyu/cbqfDHwEdKRE9kM2mVBc6VcOl3czpMmYIaohC42ntYaKRJ1pblIJnPejFjvU5
         +eGO4p3JuVjbTNmSZzymrWTL5uqyf3y3ABhIzn9G5fdlULmQNV7sdLeBM77Sxo9XbxgO
         MPD72Wn8t0hGy+G5jZ+o8vgzQagtQYepYRCf4OOkshonUWWOMhWEkaxgqBqcoUIPyhqO
         qC3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=HKVMsXNvnHz2OjdMotS7mp+3giUn0tthAcsyfTeef/s=;
        b=SrzfGJ/DH0fMcvZKLhAGyUzaMaHaCYoNZgOECbdkFPe15betpaS+AlQ82OGiD4Eny+
         iUVNxYSzyiZYFJFRUxPWPb/Lpc1imxAMEVDzQ/j2Wf5edWWNDUdYQx2h9rhA2NB24RZ8
         QVZmTjQsq+gWmLywlmot6RfHshb/91kU1SlgNz1NsrTQBcEoxWQK9VuA2ijnMaI16f27
         I3tetfmt/gUpCaZC+rXkIKEP99BP4W7KHWfIl1zENaUVMLXDhbU63ciYbkcgjb+sEtTG
         QoYzl0Hip2TA+U2Of7WZeA7vaFeZonjIpg3lfLfLJ7cLg7IH1yHgF+3SIgQU+H9g9UIj
         BFtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DhpYdxUm;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l9si274798iow.4.2021.10.28.12.16.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Oct 2021 12:16:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 1776C61100
	for <kasan-dev@googlegroups.com>; Thu, 28 Oct 2021 19:16:22 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 0AAFA60FC0; Thu, 28 Oct 2021 19:16:22 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214861] UBSAN_OBJECT_SIZE=y results in a non-booting kernel (32
 bit, i686)
Date: Thu, 28 Oct 2021 19:16:21 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: attachments.created
Message-ID: <bug-214861-199747-cZN74sW12O@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214861-199747@https.bugzilla.kernel.org/>
References: <bug-214861-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DhpYdxUm;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=214861

--- Comment #1 from Erhard F. (erhard_f@mailbox.org) ---
Created attachment 299355
  --> https://bugzilla.kernel.org/attachment.cgi?id=299355&action=edit
kernel dmesg (kernel 5.15-rc7 without CONFIG_UBSAN_OBJECT_SIZE, Shuttle XPC
FS51, Pentium 4)

 # lspci 
00:00.0 Host bridge: Silicon Integrated Systems [SiS] 651 Host (rev 02)
00:01.0 PCI bridge: Silicon Integrated Systems [SiS] AGP Port (virtual
PCI-to-PCI bridge)
00:02.0 ISA bridge: Silicon Integrated Systems [SiS] SiS962 [MuTIOL Media IO]
LPC Controller (rev 14)
00:02.1 SMBus: Silicon Integrated Systems [SiS] SiS961/2/3 SMBus controller
00:02.5 IDE interface: Silicon Integrated Systems [SiS] 5513 IDE Controller
00:02.7 Multimedia audio controller: Silicon Integrated Systems [SiS] SiS7012
AC'97 Sound Controller (rev a0)
00:03.0 USB controller: Silicon Integrated Systems [SiS] USB 1.1 Controller
(rev 0f)
00:03.1 USB controller: Silicon Integrated Systems [SiS] USB 1.1 Controller
(rev 0f)
00:03.2 USB controller: Silicon Integrated Systems [SiS] USB 1.1 Controller
(rev 0f)
00:03.3 USB controller: Silicon Integrated Systems [SiS] USB 2.0 Controller
00:0a.0 Network controller: Ralink corp. RT2500 Wireless 802.11bg (rev 01)
00:0f.0 Ethernet controller: Realtek Semiconductor Co., Ltd.
RTL-8100/8101L/8139 PCI Fast Ethernet Adapter (rev 10)
00:10.0 FireWire (IEEE 1394): VIA Technologies, Inc. VT6306/7/8 [Fire II(M)]
IEEE 1394 OHCI Controller (rev 46)
01:00.0 VGA compatible controller: Advanced Micro Devices, Inc. [AMD/ATI] RV350
[Radeon 9550/9600/X1050 Series]
01:00.1 Display controller: Advanced Micro Devices, Inc. [AMD/ATI] RV350
[Radeon 9550/9600/X1050 Series] (Secondary)


 # lscpu 
Architecture:           i686
  CPU op-mode(s):       32-bit
  Address sizes:        36 bits physical, 32 bits virtual
  Byte Order:           Little Endian
CPU(s):                 2
  On-line CPU(s) list:  0,1
Vendor ID:              GenuineIntel
  Model name:           Intel(R) Pentium(R) 4 CPU 3.06GHz
    CPU family:         15
    Model:              2
    Thread(s) per core: 2
    Core(s) per socket: 1
    Socket(s):          1
    Stepping:           7
    BogoMIPS:           6149.42
    Flags:              fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge
mca cmov pat pse36 clflush 
                        dts acpi mmx fxsr sse sse2 ss ht tm pbe pebs bts cpuid
cid xtpr
Vulnerabilities:        
  Itlb multihit:        Processor vulnerable
  L1tf:                 Vulnerable
  Mds:                  Vulnerable: Clear CPU buffers attempted, no microcode;
SMT vulnerable
  Meltdown:             Vulnerable
  Spec store bypass:    Vulnerable
  Spectre v1:           Mitigation; usercopy/swapgs barriers and __user pointer
sanitization
  Spectre v2:           Mitigation; Full generic retpoline, STIBP disabled, RSB
filling
  Srbds:                Not affected
  Tsx async abort:      Not affected

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214861-199747-cZN74sW12O%40https.bugzilla.kernel.org/.
