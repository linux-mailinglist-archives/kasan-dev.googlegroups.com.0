Return-Path: <kasan-dev+bncBAABBJ7CQGJAMGQESIGJ3MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D0F3F4E87FF
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:14:00 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id n18-20020a4a6112000000b00324ce634918sf3921579ooc.13
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:14:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648390439; cv=pass;
        d=google.com; s=arc-20160816;
        b=CQmyJ1MCnSeHsAP2QU4Z9jR+8vfh3uDJM6CVdp98sFHgi1Y3e+zQCmIWhPTF460P/B
         leDCPrX+Zt+9nvvCKzBMC66sUTGJbha1V9Qhb9g5/A2TMc2/kaP9QLhB/a3j4W0vursT
         jAthEDxIP/xO3UxVHFb4RhLNtEaorR0iec6+BAI0P82PoSVXakuVVCyFY2+jjEfajVmq
         qjvEUaOHefSRyNx3W5zVwCtKt6soNJpwJowZRUjt+weR/Rze5hxt9nTinZs1Wrg06Djr
         GjfLTRqtSLgU9xUILPtIm3PSs2fjo9bucor+wPanYvuugICCHTiA6+2RoUDRklhJWq93
         p8ZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=S6vYDAzhpKxCwEoOZATTLYZxfZkRVDvUil+eN892D4w=;
        b=GL909mKAgzpUqxQVHRYrM2sWacVfU4kenDc/cFQrNjxz4VtKl0kqiJ3co/DIQvJ0lN
         Eayfok8bFJAwp6c2i/nENw1Z6xrc/xSSWhtzzle2rd7pJXEp4m4yhm7H3lj/I86sskCG
         uEm6RgQqFj2tw/VFj3NxHw/1Ynw/f/dHUmZSgSV+pNpD6cAS2ug2T4dNDIBmxlov9URT
         JzouJmTwuaNlZwZd2q4+s+C0/UU4E91ADYg9ttNHGlM/2/O1ezMgSa9HxcXEqG/1iaHz
         Y9o92OGlFMKd8p4ExVSrF6p8vZ0pKlwkL88ynY+zUV13zM1q3dBcrQp/Y7D0tMeSkXcO
         tdEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lEvLXW1e;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S6vYDAzhpKxCwEoOZATTLYZxfZkRVDvUil+eN892D4w=;
        b=fADgvJ1en2WCcM6Lnky7Fo51gsV+Ge3DuBHXpq4nX+UHEYTem1ZC5Z87lOVJ09YpIk
         3OK2ercw5paiur6PwH2+/dqFdqzaw8IY++F7/EQoK0YkFCMGCJISOm8pAFv4LwQqyeBv
         YLGgdmB+jBr1RUU0NKCg1EPCIL8fthpU+8C2kZkZOgP89LbzZIrabWUkAMy74C1J5sWI
         5AUc7dhmVnsr0n5kUP+PCJ5rWkoaVjG7aKizuEVEDrP1fUYIzdmOblJmytpPBSPN200m
         rkEQGzmDAPeqSxa//aOf2lfWyZ0pn4Z3ku3fYLn2HCWHNDutlZgwTY8xyHcG6084pTTf
         plaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=S6vYDAzhpKxCwEoOZATTLYZxfZkRVDvUil+eN892D4w=;
        b=I68A/PNh1Stawswi11CpiZgRj0a0Tv8HJjpRtDeKX3iH1mscurf2p1p9IkmWFNlMFs
         bMaWw8E4B/Ld4HfQm95Qzq1BlR+p1CFD3RmAI1n6HEbi92Ao+4bnxxVifwIbA6CnAQ0l
         yezmlhZjfvxgged+IpNW0paoFC6g4Zck9A9m/WEA2EJF51okX6AZGMWsOdSMHFYErXmV
         BEuS7onEVoUCA4bNlU5G5CIqWi9Xy8h9emnF1vzGTIzTT4f+Dopw0fxNbdGkscPdCoBx
         EPoGsOgyhfphQP81FqFLwCFPV3hN9ZyYqPhobESOLbXESG3iC7H9mu9v0uVs60Wt/v8w
         sprw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Au1OiHtK+8C1pBLY0G6avA8OFMPxFrTP7qjAO0EAWq4W9ANvn
	iIoH5fK3x4Z6gSiKrTsm7jM=
X-Google-Smtp-Source: ABdhPJxnKUFSza7clAb8OjBDi2SKTRVu9ZDFDIjj7vXxz+q/FbfwLJ0McYxEVvtfMWy2Ho44P1PAFw==
X-Received: by 2002:aca:230d:0:b0:2ec:a4c1:e112 with SMTP id e13-20020aca230d000000b002eca4c1e112mr9634082oie.220.1648390439592;
        Sun, 27 Mar 2022 07:13:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:787:b0:d2:9f85:b3d5 with SMTP id
 o7-20020a056871078700b000d29f85b3d5ls3812695oap.11.gmail; Sun, 27 Mar 2022
 07:13:59 -0700 (PDT)
X-Received: by 2002:a05:6870:b487:b0:dd:c79d:18ab with SMTP id y7-20020a056870b48700b000ddc79d18abmr13084963oap.205.1648390439263;
        Sun, 27 Mar 2022 07:13:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648390439; cv=none;
        d=google.com; s=arc-20160816;
        b=DfCv/QkSwnzjkLnOZq16g9sDB6RnafjV5U5E7+/kjomRQ39TnjCThMAd6rVY+ofNZy
         LriYZOGD+IcbCffYoB6bsUBT0wXjT1djlJ+g9MAz997Q8WwW9X4gJ1lUfv4MOs27NjV3
         DlrGSZGK0Ys+YixhMW8J+tqpRCgPo4d3aFhQyfeSQcNtAQVD2C4i/JB6dcNkcMCAVYom
         jSnZnH2jvESrxxPU6EpVvn9h5p4V/OusESYaW5PrhwCV5iFIIGOfjOpy/G5nyA5msADG
         jjN5ASzdDYKwRb8y35tZBM440tYklzpVXHGU2I/ZBJuk0H4ldQtR/gKsVU6eHTEBsVTb
         RNWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=GMXz4jTq8ljI+o3/tODErWruey1zoUHcQ3+V9XE3tK0=;
        b=ZQRkECxFIbt07X6xZ3ChwzLv7qC4hxPfOuVhK+zu63sD6ETd18kHINSTTEzJZzjp7Q
         93QU2eTwoWT/WT7oNTPZ2kX1zQ8ArK2JhgVpVODrrbjf4dp68nQ9oMTpZZv1Ez/LAetX
         mOvAWUe19WMtrkNT78ovA/izmqFy3CB2gRQ9IEQ4RO0jcIp3Ynx47KaZ0tf0QHx5i7s2
         KDGDAjQAlYEZwyqWVafXGtpcKGhUH/07xV0E1+rSkIAn81LP1VKErS+SGRQVVIiYUNnm
         V9HiskwstOZKUg7A4GORVH/JUwToCcwEgTfrC/e8VdY+L9bxYD4Ov6coh161/xzrBgTi
         bt2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lEvLXW1e;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id y24-20020a056830071800b005af3a0effdfsi815555ots.0.2022.03.27.07.13.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:13:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 164C661019
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:13:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 775A4C34100
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:13:58 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 5C153C05FCE; Sun, 27 Mar 2022 14:13:58 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212209] KASAN: clean up multi_shot implementation
Date: Sun, 27 Mar 2022 14:13:58 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-212209-199747-pRhfGkWZXs@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212209-199747@https.bugzilla.kernel.org/>
References: <bug-212209-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lEvLXW1e;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212209

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved with [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=80207910cd71b4e0e87140d165d82b5d3ff69e53

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212209-199747-pRhfGkWZXs%40https.bugzilla.kernel.org/.
