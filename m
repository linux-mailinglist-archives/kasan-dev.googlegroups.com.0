Return-Path: <kasan-dev+bncBAABBZ7OQGJAMGQEL4YFPOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id F39D94E8826
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:40:40 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id w3-20020a4a3543000000b003247262c123sf7601087oog.12
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:40:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648392040; cv=pass;
        d=google.com; s=arc-20160816;
        b=LdKvAgxRNsZJthdwjQPKriAWpeNXW4HbKLB+pDpHyzNuWc2xG6LNLpishBi/FQJq4F
         1WrN5UjtoEfj9pjnYa4ma2f/c+LfMdCh7b+C+dzOdln8Cza4tdTkkdjbgDMiETB56Qch
         v5DeN2vl3k+M/YHNKiFtK1SadEX54nREpqZ8Sryp7jxy69gYyAywItOB7dQ8poCjg4Qy
         NuJMsIUbU55dxHRq3UBuE/FbQFuluCtl7+wgtjPkNhD6oOAvxbsdLxzJls8ChYgNgnJ9
         wqIujkXLWh5LsYbK6jtBVcV4TQxZZTYgN7olcwMqvfR36A8RZyizbGkK3cZHhCST0fIr
         Gp0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=6iOnHEyvdSRBiqJgXViYKq5UgsU5j6gCb3dhv72utEs=;
        b=LtkgbEWDTQNb7t2Wa0YKIujnh9GQVlyVhOK750fdsd9t0L00Y2SbgVkWYkn704NGkG
         L2utRXxIZ3GFVt27EccMMsIShpNbpkyI3GHCBN5kkuH7h17dvP7SBMT6JoC9ZfWakLRd
         Lhj93sRPbwakx80Kh3qaof1fAlvj986ThrJinktBaRP4BL9FMLDxyBnLpf2ZfWJmY4/l
         NXl3/mxQG1wjAh8vPL/2+qYv4f37GW74QPRhZ62impTPXco/Tqd3NtGwcct1AWCm3yyw
         ulVaBHwl8dZdyGNdUSoqu7o0wzLvrWPgGNGimryyBe0VBQUfz/jQFSPxBHXRxORd2kEc
         eArg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bMvYSgfA;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6iOnHEyvdSRBiqJgXViYKq5UgsU5j6gCb3dhv72utEs=;
        b=qOz1Bdt8uEzojqLTQMw3aDI/+qIUfb17b4lgNncKdw3L4YZ/G4NiW6yN7ndBPL5Na9
         gBFAJL3FNtTXbd3RLfL+Sj00+bri8gLYo4a88nz6wqgyV8CZjRILsuRuXmjXr6I4OyL9
         6Jop9O8YKohGitVhTX08R/RNNQZqidj1KsJsFrZCDJiJpBGv48t7/z6JRGz03OPQyuZ0
         zFDNHL5APUhdeter02ZoqVtxeokiSfVtoFkkSH+WXdkz3jIP0TM4Mi9NfuHJyS5Bvnf7
         ZIo0A8eNao0lw2haQKbKjbJbWuJAscUdqhTrNCMXe5+bTJ2pjD9MOzV1yDBCnZeC81oX
         DCrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6iOnHEyvdSRBiqJgXViYKq5UgsU5j6gCb3dhv72utEs=;
        b=7F/PEzj/zTaBfFWppQClPnitApm3XVCKLh699QnN+88Z+x7PLAgxuagY8KZoST0nUL
         fM/nBv6i+qhpMpysZDwR6qPYvP7I7OJTPwrRxFoLvGPO1T8Yk7bO67snk/WZVx1gzet8
         +vvjKzWW2D4NHHW1f2AzT2Cg/p2dHy+O0VZ4/KysB7mOsoO6Viy/k+BcIUf2zwE5CKSC
         4sRPm/J2ssxh938Ik8oWk1fBc08dXzwr5IFFVTHS2rL7w36bGhJ7DF1SncbjJsjKRk6Q
         rUSv6Xhn9Zyqok2xtldhD/5qXHONEIsdRv749qrWS7q+D1Fz7idSfNa8e8cuLnPxtjlJ
         /N7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533qehlNDWYJAENrvj5a8HJXVk/UCfl7Dbh3Zphg7w13POBO51K3
	WeTMq/skzFs/W8rtdO71mcU=
X-Google-Smtp-Source: ABdhPJzx+ydzrshWXZCFp+N9uDHsmv2jRrpDCE7dfDsABIGaxxK+57UTcPhqFfEhyOnNVqHetZ91tQ==
X-Received: by 2002:aca:914:0:b0:2ec:f440:e07b with SMTP id 20-20020aca0914000000b002ecf440e07bmr9881584oij.241.1648392039992;
        Sun, 27 Mar 2022 07:40:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1b0a:b0:2ec:ce85:cc5a with SMTP id
 bx10-20020a0568081b0a00b002ecce85cc5als4208328oib.6.gmail; Sun, 27 Mar 2022
 07:40:39 -0700 (PDT)
X-Received: by 2002:a54:488d:0:b0:2ec:f566:db6c with SMTP id r13-20020a54488d000000b002ecf566db6cmr10128856oic.109.1648392039694;
        Sun, 27 Mar 2022 07:40:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648392039; cv=none;
        d=google.com; s=arc-20160816;
        b=ems8NTVH6EPgaOTc4POvhlu9n+imMMKxPlptj2n59eAzunKsx2MqAW3sDLWEnGJX9Z
         ITI5cPRB8O75BDlRDot8Bex3BVoReYDd+qPquF1ZrQ3qTX47CmVp8OPmbjVh6uvctKdq
         BG8+thkLIfQt5Iep2cEH8iftVA/2rug0rNpY6XdOc8N5eV0THK9Bny+h/oMtMtXAfjYD
         AGIu0mdl3tqPdU2847Ebngu9AzuDsRQdpZUC3z46HVpeNUP4oj/ccTcoQG4OetC5nbyu
         WEGgzy+A7Hky+N+xrRI2QfIASfDfMu7xXnCq6n9YkBdEUKa4RSkbXY6/GtUErdnI39t5
         6xcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=7rAP86jZBL/82dM+0K1VE3BBNJlADa+0/WggoTp7SUw=;
        b=OGHyBF9fo4MgsveN0ph7S7Ro382jm5zfV7kPYwiCmKIwfdTODOduIef4/tM2ra4o3q
         QnRKAHXq2eORZakA4Ru0/11BrgZdg6XnzTNagbxVzX84s6VVN5hy+HlePw7fgwpoCZx2
         RbqBwt2yQPmj2cwzxFn1CsaZmuJzG1iMZ97o+sedBNP3D4LSRe0qOlxAjASeoQ52tgsH
         KJFez9UA6P1deOYKbuAmN+vBhwAfvavNrDiMv4ngSeageA3n9ZdlxpOAPIrob/PPnPaY
         yUv0ftMP+vAprVOuX4ovqOZfNS+TEGAJSHJ9/4SYJLlRJBAo/4HIkmzafsTSDyPhqcCN
         q6vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bMvYSgfA;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id k8-20020a4ab288000000b0031c361dd941si426531ooo.0.2022.03.27.07.40.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:40:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 6488A61029
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:40:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C7855C34100
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:40:38 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id A3D2FC05FD4; Sun, 27 Mar 2022 14:40:38 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215753] New: KASAN (tags): investigate tagging executable
 vmalloc allocations
Date: Sun, 27 Mar 2022 14:40:38 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-215753-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bMvYSgfA;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=215753

            Bug ID: 215753
           Summary: KASAN (tags): investigate tagging executable vmalloc
                    allocations
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Currently, executable vmalloc allocations are not tagged with the SW/HW_TAGS
modes, as the kernel does not tolerate having the PC register tagged.

Investigate, whether it is possible to tag these allocations. Or at least tag
the memory without the pointers.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215753-199747%40https.bugzilla.kernel.org/.
