Return-Path: <kasan-dev+bncBC24VNFHTMIBBLUUU33QKGQE3ULJJTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 20D6F1FC489
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 05:12:48 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id o34sf660256pgm.18
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 20:12:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592363566; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZbWOb47CAZqRoGlPKiHJduMEAclIumunfkOb15F7+dhd7mgPKcnI7CQsaXpdzdK0+m
         YRz5aE+cksDGRRlTipuiIcuytmhJQ7nWbClh54kA/UYu1A4NXSWF9C9ploMNXUOBK+S2
         Y0dwExRCDIH8Q5S36l2wFlrwWPs63gtyp/o/Z8uzvwZUFvICKs4RRqiriyL3X0blhuwe
         YoIxMd2JyH5pEQ1p0auPk7O76nWSw+7FaCm2aQmlxKBYnzvhw0roFmlfxdLpxWEg0WSi
         c7n2QQoXYEFRg+GfxhTlIVsVqrvx/f+iG7HPkIqjSJS3B0/fMSLIrZymJMHDTzvEA1/K
         6Bow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=35J1V0ydf+G8vez01TxEqbYE2dcaEMIAISWTi57sRI4=;
        b=dvBPd3K+UUsz02GSjr7Yftz//jxxSTbcyUUtkYAG4ZWUkfybtPH2/fjIUfSUltXI/E
         KASjI6Fg0X59BgDakwB2PbRZtZCD0byiktQHR79WumBZAhBR8jQat1d5PK0J7/JiAcOP
         jRmguDakszAw8s3hM/6kRq2VCTu805R4+HCVbn7z+PRYxgMNlS6h8OZdXlCE5OFqiWC8
         B+5Bb/B9cmCY9XaBrA3CEcZprePzjYoBwNWRhuMMv41RgXAxH7uJ5AlLAD2W7WMqxM4y
         mPgvBTKqFdsGs6IcZDGIhWmmg3MR2GUCQzxGjscdEKF/CzrL5uyfLrkXleK/Vy0hdDzy
         jBVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZyJL=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=35J1V0ydf+G8vez01TxEqbYE2dcaEMIAISWTi57sRI4=;
        b=CJDv+7TZdPVZ5s1KRXJ46tt81BfWUAkKiNxHHXOtq7fg1Ou6fhEZh+VAvhpvsxCK8U
         8mjdP5d3WYEjBD6Yj+gWxD4S//CZj7medChsK4iShOLOXndQrt9au9MN6AR5AEwFBsHK
         Qhc9stOgjrhENePHMMmoPvA+XUeA6RBQ9ClrWWlPtxNO3YYJRcRJw+Xj8tOuOzv/uHKN
         ihZMnnO+gSsPMl41elCm4HHyP12HybuH+tpOWBcaNM1saXqnGwbONf3qOmcuWqOUXbZy
         QOYXZ3uox+zr0RsAvE/6rNG2iBJ0cPzzsF9oEusA1+8wHfjDvcH0pqtn0W8paL5VGDG1
         1kkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=35J1V0ydf+G8vez01TxEqbYE2dcaEMIAISWTi57sRI4=;
        b=mlodh8lThuefHSKaB2uwxHAkNpsBwXSv4+ewyyIZk+j0+Dg3EFIODmqt+NOjFqo0pJ
         vijJ0e1U0dqsUFT2ZL0uCL/ryYdXQ1GLhdlAoIb7Cm2W7oVpeTgLBpi39xLkVTaWHWq4
         RdEb34UxJGgt+ws2V9M9ZlNmvS9ZeY6uXn2az5yEGOW9nTREHD0cUMUF6L5/n4o3bqab
         QNrEL6ftyJqxYONgR9FTd2PAhRaIYJIu6iCF/2mK6twnr5k0y8G6zQjxUaMP59pgnned
         cBI1gY3p1hcYnJX1nFsT+zVjpDEpHOW7Xzc8RiRi3HQGu/a2/jJJ79079s6I4CsRf3ZL
         jjjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531O7vx2sPtg4NfVeGr+ZBov4b5YEwiOD1IbO9Iu9tbu0g9jCge+
	Akpxcc3Tzray6yVvI5Y1dIo=
X-Google-Smtp-Source: ABdhPJyUqyX0/ZAZQmIebxIkFxQp2S5b3NZPV/dLAMM5o2OJWgbOt8zaTwrhcc+PEYTSWIXy/G8bkg==
X-Received: by 2002:a63:482:: with SMTP id 124mr4537386pge.169.1592363566481;
        Tue, 16 Jun 2020 20:12:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9a84:: with SMTP id w4ls314130pfi.7.gmail; Tue, 16 Jun
 2020 20:12:46 -0700 (PDT)
X-Received: by 2002:a62:685:: with SMTP id 127mr3015960pfg.316.1592363566085;
        Tue, 16 Jun 2020 20:12:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592363566; cv=none;
        d=google.com; s=arc-20160816;
        b=PQibZgjBTZPBOfbla6DCu+8hw5VxGjaJuGAjNtX2LUYA6Er3QoyhDiTpbnu8N5PeY9
         ausKs5FF5AsjwMoocvw4klRJKBvXjgO0aPKww9ZeTle1/VbusbdgB5SZAxslgNvCJaUR
         wM+qmDekfC/ArpHBGPUixNEXR94ocgPaYjKyCJc9Hv2lnOl9hDRwWLjivFaA8tXNGIIE
         qNObNkTvIBbB5GnZj0ohbULqtnAThznrrFJI152fQ8KoIdOOQ4KKdBtuCDUtbPCb/JwV
         i+qMB4bUZv7HQUuoGuNTo1IDUa9UW6NhObSO0j26k4yRekWTKc7nuiwm28vxOMO2N/FL
         ScoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=5fAc1Hu+zo/3ZDi7l76JAB4m5+1LSF+E5LbYlQe5Rlw=;
        b=o2eVgNXqLtoADLkam/XvOC1eJ7D9RXL3ZcAyaRKye1s/VDFegqS7aOi8mGIzbmBmy8
         z8DD5eLzTbxdlaIdv4icjApBEXEE21r2CtG+8PfN+gVjh5G7bfdV6YxlT+mz5TziwDpl
         YDNrBLTiwnZlgUUka8jHJG+lRkjAEv/S8O3x20Yjet5RLr7IuOuReL3jD95IpIQFlrIl
         V65WGkBGUZN2zkRnx0zcwRjn9nVA3aFOPItkWrAzj2fGH4IYEMHbw7cI3EAiW2TbjhEN
         7wj2UyyDmGZEInZsh91gQLaOeOJ21OL0sz8HdY8zyrwDKz4jlZm5GoDBKNgOWxsvlY0J
         Dszw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZyJL=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id gv9si154584pjb.3.2020.06.16.20.12.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 20:12:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Wed, 17 Jun 2020 03:12:45 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-BIKcsmPPew@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=zyjl=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZyJL=76=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #5 from Walter Wu (walter-zh.wu@mediatek.com) ---
Agree, It makes sense that kernel and user have the same instrumentation.

I try to trace code and reproduce this issue after only modify untagging kernel
stack, I found below code need to untag the sp?

--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -2575,7 +2576,7 @@ SYSCALL_DEFINE5(clone, unsigned long, clone_flags,
unsigned long, newsp,
                .child_tid      = child_tidptr,
                .parent_tid     = parent_tidptr,
                .exit_signal    = (clone_flags & CSIGNAL),
-               .stack          = newsp,
+               .stack          = kasan_reset_tag(newsp),
                .tls            = tls,
        };


After apply your and my patch, it always trigger the following one report
during boot. I will see why it always is triggered.

==================================================================
[    0.002285] BUG: KASAN: invalid-access in format_decode+0x90/0x10fc
[    0.002306] Read of size 8 at addr 74ff900015447a00 by task swapper/0
[    0.002324] Pointer tag: [74], memory tag: [08]
[    0.002347]
[    0.002375] CPU: 0 PID: 0 Comm: swapper Not tainted
5.6.0-next-20200408-dirty #4
[    0.002395] Hardware name: linux,dummy-virt (DT)
[    0.002412] Call trace:
[    0.002430]  dump_backtrace+0x0/0x578
[    0.002447]  show_stack+0x14/0x1c
[    0.002464]  dump_stack+0x188/0x260
[    0.002481]  print_address_description+0x8c/0x398
[    0.002498]  __kasan_report+0x14c/0x1dc
[    0.002515]  kasan_report+0x3c/0x58
[    0.002533]  check_memory_region+0x98/0xa0
[    0.002551]  __hwasan_loadN_noabort+0x14/0x1c
[    0.002568]  format_decode+0x90/0x10fc
[    0.002585]  vsnprintf+0x184/0x31e4
[    0.002602]  vscnprintf+0x80/0xd4
[    0.002619]  vprintk_store+0x98/0x93c
[    0.002636]  vprintk_emit+0x168/0x79c
[    0.002653]  vprintk_default+0x78/0xa8
[    0.002670]  vprintk_func+0x918/0x9a0
[    0.002687]  printk+0xb8/0xf0
[    0.002704]  kasan_init+0x2b8/0x2d8
[    0.002721]  setup_arch+0x460/0xbc8
[    0.002738]  start_kernel+0xe4/0xb88
[    0.002755]
[    0.002771]
[    0.002789] Memory state around the buggy address:
[    0.002807]  ffff900015447800: 00 00 00 ff ff ff ff ff ff ff ff ff ff ff ff
ff
[    0.002826]  ffff900015447900: ff ff ff ff ff 08 ff ff ff ff ff ff ff ff ff
ff
[    0.002844] >ffff900015447a00: 08 ff ff ff ff ff ff ff e4 e4 ff ff ff ff ff
ff
[    0.002861]                    ^
[    0.002879]  ffff900015447b00: ff 14 14 ff ff ff ff ff ff ff ff ff a4 a4 ff
ff
[    0.002898]  ffff900015447c00: ff ff ff ff ff d4 d4 ff ff ff ff ff ff 94 94
d4
[    0.002916]
==================================================================

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-BIKcsmPPew%40https.bugzilla.kernel.org/.
