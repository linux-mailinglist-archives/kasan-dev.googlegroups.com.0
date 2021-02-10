Return-Path: <kasan-dev+bncBC24VNFHTMIBBFO4R6AQMGQELXOT5RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C4E931692A
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 15:30:47 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id t196sf1717674pgb.20
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 06:30:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612967445; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y/8fvOrs6XA1/DESaQMmVz7eXiIas/CD9m54g0lInE6f/eCokSM2bDO9HhvHKHVMd1
         REnOjGB2jZi0NK2tSV/LVFAQ+JGd85G3vMdPpldmra3aArmkdlRg/8DwE6bepPqrS5YY
         5GmptTbyOlJcHRAvPO9K/c3W6JHW7kt3VmsXEV4aqqB3QQnaEVd03tIvisrWQiSB6RAt
         S4C5LARsixw9XT+iQFrtBY194JfO3U1GZDCxx3F3GPNydde4L1i7NC7hfhYp0w7j0xMC
         OAOqViNy/hITs67k8ns2od+/KOWfuRDPSmON50Gy7zMpH1iQTXxmQoAN6kJ77hfyRKFl
         g05g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=B/Ef9ZSDe4QCkSu83/jCvL6JVEknME+XLoEE7Ac5OS4=;
        b=NqUpDDCB5jRUr77cIZQom+efvBrNinI/X60zjm5aKhM4hR+TQ4/BEzOYmnwGRsJ0Q+
         BnPShhfLs1Ms9FZXLrW9rg5nlAM97U7OeHdIomiPJYwODfwnqb3ScAUNrEnUKrDqGpfa
         UF9ugxrHh/Ak8pD/aJAoiOpB7kH1NoP6RIvEwvbfyuHekmpkvLUCvcac5AMyEBXXyuIz
         zbPDtRZ64BOT2psQgDhI51iTrZddlB4uuveFxMT9XQOaGSme1kezaiQP7iwOsqUgSAsP
         BAqcu95TRJ12yLu7IC4BpXQT4KuB6OYe3EVqAwR2D4w4DyYoAvOJuvs1KyBdoFBnipFd
         vKiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tiJgkx9Z;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=B/Ef9ZSDe4QCkSu83/jCvL6JVEknME+XLoEE7Ac5OS4=;
        b=p0Dqoo+LcjIAevDmr/WFHVJsx6HAjm5EP5aB5oDrIi1V5mYuzrGcLnKetszZlCA1tS
         QbvJK82PE0FXP4aqAH6qPPZPLdWGygx7tod8J67/69kaQW2rBUJTM/UGWymFvMsRqM7+
         AhvjfLostQeAnwEEl59JADRSgHCpYEOAcoQeF/Kdita+eAKTCxLSTUUm8HS9099F39Qh
         GufFYeRUTQgQEZohY6+HFoSIgeMfmgCVgiDbe+n1JDHJZxIUsbbn90BIni4ujMjKZ677
         CaL3QRIaNqjwRRb49N5cZQQ8h6UHc7Bt+OTBKnsQytAoyElrqZ0gHNGKEFy7gfq0De7C
         4mng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=B/Ef9ZSDe4QCkSu83/jCvL6JVEknME+XLoEE7Ac5OS4=;
        b=lQdGDZVV5mM6x8i5fODxi7zlAFDbtUmFoFYb12zek8xh5nXlnYBjYK1CWl/tho9vb3
         dRqRAjocxWeIibvxY+6mDw2v+LAjwpzR/Sgpeu3xaSrmX8lAlnGKXuskHu7hJp0oKsve
         dJXehyFROp3iqSC6L+4KppH0oTXE65jz42FHHo5AW3gqA+atEYrSDnmomJ3x0XtSyg41
         SS6cFtCC16IPkljLLtiFTPAlgx0ViPHRxiFSLgjtpS4i1iEUYNG2GQXTmSBr4D0thR2K
         p4QfPLYa3g1Yv32sUM+yor2olMkc4XLE6cSesXD9yCj27SCRlNtV0l7oHi0myH2nbbXw
         Kdgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320h+QGaF8sKf4YO6hbfQ8l3D+wZ6Dx8HKc7b99pe9jUUFrbDTy
	PRmZxbLyalxZ3neAAIn1x84=
X-Google-Smtp-Source: ABdhPJxX8vVHm/eM1r86O4qsmYf6tAwD++d25ZU9aB1e8E5rxkyCsvinfeqgGgK8dkI1BNJpDfWwiw==
X-Received: by 2002:a17:90a:420c:: with SMTP id o12mr3417354pjg.193.1612967445569;
        Wed, 10 Feb 2021 06:30:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:31c7:: with SMTP id v7ls1117401ple.2.gmail; Wed, 10
 Feb 2021 06:30:44 -0800 (PST)
X-Received: by 2002:a17:902:e551:b029:de:8dba:84a3 with SMTP id n17-20020a170902e551b02900de8dba84a3mr3211357plf.8.1612967444794;
        Wed, 10 Feb 2021 06:30:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612967444; cv=none;
        d=google.com; s=arc-20160816;
        b=QWFMQrHeTwZSgis9dBHO8Q1B/obJNd7pjLVq0dkQ1SVEOUO7so0ju48ZMK6ijRTXIS
         ACzcCkjZwx8C2hRtII4MBusxPbksZZH/dYs4K2T6Vl1Ch1F7Oh6ojZcabtD8Mk4GLS96
         TyAD6f9dkVYmU8diuhiP3afJb/eTyU8z7dB3iBStNjmtgMQTw2jaQqYhWZrqecgG4U5O
         mT35RJQPeXGCeal8hGIAnhatg8wQWpJoWDtoNzGlHiykHkDGxQpgbz+tSRjILxQBhp69
         ofSTLYunkFriu2a80hDxV5liqetqVfhoEBSTAI+kIMV/Omro7zj9zcOZSBw5ITazrVk4
         gpbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=w8E5tTBlUVmKppmrBmsUrq04aPi9EKu56+ClISJ2hPQ=;
        b=kd8xuAHUo5Y7wOvDP3HiobV0VaWq+M2cTQGRfZpz5H8Fz7XsHalKEHPD3XqsVnm03B
         mHaIQeq4smqRS9sCL4mUjgDHVfY9NaIvz7pvZZPlhzQg/3J2aGIeXs64un6VjHglGsa8
         xSmLrV5M8ncYb5epap/3aUH7D2gG3rnvhexIvFrbvsuUV4HlabhL4gmN4KOaKE8fI+aK
         CANYX3pRdxk608ns6ef2kGJ0tr+my+Y+i5H4SPlxQhK11+gXfg/ebQ5zHpZ1qTr23ELH
         K5LUA3V2Clee6q4Uw6kYkjWzunCIy6dwjQ7FpitnCnOd62fvUjulwdFRLBAPLTP7HUt6
         xCXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tiJgkx9Z;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n2si131036pjp.2.2021.02.10.06.30.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Feb 2021 06:30:44 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 6C30064DC3
	for <kasan-dev@googlegroups.com>; Wed, 10 Feb 2021 14:30:44 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 5FD5861479; Wed, 10 Feb 2021 14:30:44 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211675] mac802154_hwsim: support net namespaces and phy flags
Date: Wed, 10 Feb 2021 14:30:44 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: priority assigned_to
Message-ID: <bug-211675-199747-0M2fci8fpy@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211675-199747@https.bugzilla.kernel.org/>
References: <bug-211675-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tiJgkx9Z;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211675

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
           Priority|P1                          |P3
           Assignee|mm_sanitizers@kernel-bugs.k |dvyukov@google.com
                   |ernel.org                   |

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211675-199747-0M2fci8fpy%40https.bugzilla.kernel.org/.
