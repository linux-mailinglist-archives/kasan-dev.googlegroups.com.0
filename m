Return-Path: <kasan-dev+bncBC24VNFHTMIBBWF2ZLVAKGQE4FF3MZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 053E68B687
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2019 13:22:02 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d6sf62724926pls.17
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2019 04:22:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565695320; cv=pass;
        d=google.com; s=arc-20160816;
        b=hTnxJZqCx3mX3OVdVKl5gjd0C/Gs3UhYVudh7aB35cTSgdd3jvIr/IcK16ma5gBHe4
         o7VbU7FuH7VCSX0CcCkJdRZGptn5+ju1/HVrPY6TJ+fysnHys2ZId/+H2rSI/imiFWlQ
         de9kv7oMU9KcU9ExPYkM+hmZFIRIpP7Q2NhZZUWi0/e+hoXo/2mxGLMxLpNkk9gpkhPL
         FWVYSBKDXhdb+j2hgFxaAoieXIa18LVzaSadcdW17grysGRVm5LfJHqDFGB3ufmLeHgm
         KMz2hAuscn36ZdGQtQdxOUr6T2LqReTmrUFUR9ZLKse0aLwk1JoSVwDKhlz//b+fDfZc
         no4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=g3k7uSY6LaTPcgd6C+5sSUy+eF6sRW7yHJKfR07LfRs=;
        b=PAp/3Y4zTHdDelZhikfLwBJB1enHXsZ3e2JPHgaxI5Hsxn7FFrqJGfETrYPRjYXdlW
         vUuyVpgFUe1sQsA9AnQGBPClGAzDiy3lNmCospjr8BMedk0zT7Ti6xsmgmyMpiSVyNOt
         un8fW0DL1/l9Li5AAJXEuD/70SjZT4zI5m2mZKZcycAlWOVrZH+idzIwPopPZSVT7iz5
         YAam4YQptug1FIpmjyq7nLd8HOYkoM1Sl0Umh8wjoPxBho5vj+C/3lsWqPZR3Wbq2gXM
         Iq9Fc7+WhSK09sSD4dDfF8FYh6gEtpwDd51soeAUlOAUEMqpsF5iUUxu0KzggL2QT+9r
         hetA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=g3k7uSY6LaTPcgd6C+5sSUy+eF6sRW7yHJKfR07LfRs=;
        b=KQ9LQyy4z3fcTzmWEaV2RaiQtMMKePAVZYr7rFXkN5D0a2hgrf50FY+cF/YWbyWOUo
         gDw7agXLNGTLg6h/UNzZWAOUPv0tmXAj6Vbf4Ro6Jo0loPEL/x+RtYvw2WAFig0d/aKl
         HTA8QeMchkQ18/lDSnRKzsHS48aMWRa4ytipnQvsxXccIF48UtXl1WewljS5Uhws9epP
         CK86CSnEi54qKL41xf4+8/v2t69LHGWX9ckxYb5Glr4X8DtXSXxaPMRlzThdJSO2KnvM
         YPPSzUtT+d50ypzzdTYa4+2jsiej1AT2jATEp4ISKTJM0BDNCKkbeujRKnY9xt/To7ZI
         U9zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=g3k7uSY6LaTPcgd6C+5sSUy+eF6sRW7yHJKfR07LfRs=;
        b=P/dKfjrqOx8k+IPTPvXwP9X3/JXqpR0JFjjVTxQpKrOIGNu7+/f09ehfhUbcYKBUYS
         nIqj578+UUoCoZoV9xINnlPEgDIx1Wqh4k0q2xnEKv9Ikq1WdrSTjr9WkQpyi6+XVQmt
         1M+P0aC8xjy6K5ejaWzV4Dl3Aqwgz5JuznHVrlC2SStXxcqMNfmOjlYYnLdCQrVX8Aip
         6kX9ekUD0dtnbb2Ozzl3WNd1TXXr4vwLxKPGXDEaLkNi7m7fWgur3L0rYzs6SB+aYne9
         GHmzzNnD85wvzNg02k5X26KoLxxPFwjD035KqhuioPj4ubAO+KewmAN6k8mHY7N5kxj2
         nqeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVIYlo9MO4Xm5WWqct1rjY6OcogmgAPcTw1axBqsJ9r1EGRpAZp
	t3eLtwWurCO2cq7LHRduNUo=
X-Google-Smtp-Source: APXvYqzsDtR+NPNeWecz8VH5apBPRMHYlnuOoB82Zxro3vO0tZ2GMhRJJv/x9LhCfDvA0H4yutHLpg==
X-Received: by 2002:a17:902:820c:: with SMTP id x12mr37941401pln.216.1565695320590;
        Tue, 13 Aug 2019 04:22:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9e81:: with SMTP id p1ls1171127pfq.2.gmail; Tue, 13 Aug
 2019 04:22:00 -0700 (PDT)
X-Received: by 2002:a62:7d93:: with SMTP id y141mr17199035pfc.164.1565695320232;
        Tue, 13 Aug 2019 04:22:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565695320; cv=none;
        d=google.com; s=arc-20160816;
        b=BjmcXGtiYKxXJKUO6gv1aIVGxgHp1djB1Cq7bdm96t5q3TtNqkLnMvspisHIXELGxZ
         PYFA6gX/x1WFclgpVLNyjh6Yv5b4KbLvFJGi5G1PMHiLCxHCfG4YPxRJrgRnVQiId1sm
         Xg9K31YHFnvvQHP96UZxYZgUEa14D2soTRASds5SIc16SzdU0eJzDMmmF/zkfHxFe/jP
         bdqRsA6y0tyMlLAnlgL8iX/pWRXDkbLbV+fGYtUmgv5k7vOD1ZKYlg+lapDMC7XKhXpH
         5Xtx5ko/rhV8qqBbE128G6J2vu3iLWbpzkaSi+c55yq8soiqQ4F0A1pKe0uTPUGlxz4B
         gS4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=5DIVnjWJQZAg3nyWNGfFNAj3IaTaDBJn/d7ZYOWQvBE=;
        b=krsfqV3FnVBICuSnpyc/6Qb+s+ORr6fv5DB0dZOyd62LvUFumggDofFwHCYIxpFQap
         vgaPtqi78jWcpXKxtdtaSB3aCa/NpVRKdSI4BCd+ra+GZcXawbkFuRsLx0CRm4BrUu37
         n3Fdjw1tHKt1yRoWj63C73StcANxVgEkfIoTljmIoyawQ/x2HFdUrzLsm/MBbAwpMDed
         Xo4FF9/xyvnJZvV4NZ6pUa1IjzgQ+eB+gu+NHPMNW+DDsGetXC/igEDF7KmdxtaUEQFV
         sAxE8SNg+NQrRRUf5osEOPV66ZeP0Ap3O7/WQ9iurEw+NWfP3v5hkFgj1hHQ2pNZanZv
         Sfxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id i184si4013826pge.5.2019.08.13.04.22.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 13 Aug 2019 04:22:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id E2254285F0
	for <kasan-dev@googlegroups.com>; Tue, 13 Aug 2019 11:21:59 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id D642528617; Tue, 13 Aug 2019 11:21:59 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Tue, 13 Aug 2019 11:21:57 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-204479-199747-nqaXwTB8zW@https.bugzilla.kernel.org/>
In-Reply-To: <bug-204479-199747@https.bugzilla.kernel.org/>
References: <bug-204479-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=204479

--- Comment #20 from Erhard F. (erhard_f@mailbox.org) ---
(In reply to Christophe Leroy from comment #18)
> Two possibilities, either the value in .rodata.cst16 is wrong or the stack
> gets corrupted.
> 
> Maybe you could try disabling KASAN in lib/raid6/Makefile for altivec8.o ?
> Or maybe for the entire lib/raid6/ directory, just to see what happens ?
Disabled KASAN with KASAN_SANITIZE := n in lib/raid6/Makefile. As you can see
in my latest dmesg, the G4 continues booting without further issues.

If btrfs gets loaded it still fails with KASAN (will update bug #204397).

Another funny issue. Mounting my nfs share works via:
modprobe nfs
mount /media/distanthome

If I mount it without modprobing nfs beforehand I get:
[...]
[   66.271748]
==================================================================
[   66.272076] BUG: KASAN: global-out-of-bounds in _copy_to_iter+0x3d4/0x5a8
[   66.272331] Write of size 4096 at addr f1c27000 by task modprobe/312

[   66.272598] CPU: 0 PID: 312 Comm: modprobe Tainted: G        W        
5.3.0-rc4+ #1
[   66.272883] Call Trace:
[   66.272964] [e100b848] [c075026c] dump_stack+0xb0/0x10c (unreliable)
[   66.273211] [e100b878] [c02334a8] print_address_description+0x80/0x45c
[   66.273456] [e100b908] [c0233128] __kasan_report+0x140/0x188
[   66.273667] [e100b948] [c0233fbc] check_memory_region+0x28/0x184
[   66.273889] [e100b958] [c023206c] memcpy+0x48/0x74
[   66.274061] [e100b978] [c044342c] _copy_to_iter+0x3d4/0x5a8
[   66.274265] [e100baa8] [c04437a8] copy_page_to_iter+0x90/0x550
[   66.274482] [e100bb08] [c01b6898] generic_file_read_iter+0x5c8/0x7bc
[   66.274720] [e100bb78] [c0249034] __vfs_read+0x1b0/0x1f4
[   66.274912] [e100bca8] [c0249134] vfs_read+0xbc/0x124
[   66.275094] [e100bcd8] [c02491f0] kernel_read+0x54/0x70
[   66.275284] [e100bd08] [c02535c8] kernel_read_file+0x240/0x358
[   66.275499] [e100bdb8] [c02537cc] kernel_read_file_from_fd+0x54/0x74
[   66.275737] [e100bdf8] [c01068ac] sys_finit_module+0xd8/0x140
[   66.275949] [e100bf38] [c001a274] ret_from_syscall+0x0/0x34
[   66.276152] --- interrupt: c01 at 0xa602c4
                   LR = 0xbe87c4


[   66.276417] Memory state around the buggy address:
[   66.276588]  f1c27a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[   66.276824]  f1c27a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[   66.277060] >f1c27b00: 00 00 00 00 00 00 00 00 05 fa fa fa fa fa fa fa
[   66.277293]                                    ^
[   66.277453]  f1c27b80: 07 fa fa fa fa fa fa fa 00 03 fa fa fa fa fa fa
[   66.277688]  f1c27c00: 04 fa fa fa fa fa fa fa 00 06 fa fa fa fa fa fa
[   66.277920]
==================================================================
[   66.428224] RPC: Registered named UNIX socket transport module.
[   66.428484] RPC: Registered udp transport module.
[   66.428647] RPC: Registered tcp transport module.
[   66.428809] RPC: Registered tcp NFSv4.1 backchannel transport module.
[   66.741275] Key type dns_resolver registered
[   67.974192] NFS: Registering the id_resolver key type
[   67.974534] Key type id_resolver registered
[   67.974681] Key type id_legacy registered


But maybe it's better to not open too many ppc32 KASAN related bugs for now. ;)
It probably can wait until you patches are in some later 5.3-rc I guess.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-nqaXwTB8zW%40https.bugzilla.kernel.org/.
