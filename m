Return-Path: <kasan-dev+bncBC24VNFHTMIBBOXTTWBAMGQECVXRPKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 95661332743
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:35:56 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id o27sf7626117pgb.14
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:35:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615296955; cv=pass;
        d=google.com; s=arc-20160816;
        b=YTN3qE7SJwkRHEHkmbISzIc8HQh3RTEeQBLnnN6LAKfzbmDQLfx5yqwfNcgRIBNOpg
         SV7T+f114p9GuURSd0TlC47WEGse5AToKJMKRtSBYxJOE4q8rShF7/4WA+jKs+U2SNWt
         2J+POy0/F7evk/oeLXeWm3swkbyOA8fz431GdZNCM5hGXmYsyiCy2Ppzq2Es+qrd4QnV
         X6cVTVZqoA/CIYPz0oAaT4FdR4v2S/Mhjf8mhhawOHoBhXrkccMO7PnV76sUvfS6HmcZ
         EWX0vthdk4kjui5TqvjO7u2ISqz/lXIHsnrGpjGcIkbYcfPWnA6C9YklOBN1dLXqRKH8
         c5dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=y6S0sjerZB1KYqxyDp/H9VdVFPp9C8u54xrerQ39c/w=;
        b=0bqcSiC3TepounC6IkH36RODyiqUDrkfAe1JvFHTrWMhkhnLQUNoS3WBa3tFiKMvpD
         SLdb5zJU0xQw/SxWVzF4Pbr99UyP3amCyQjuicudQUKgYq9GJgRO/W91rlUV81+ysBqw
         CP9vj42okBkeMGi1FR/eXwfPf/XA9wtAFCy6r+eULcvOFYx4vKpTyzGddLxtpLa2id76
         JvA51QcHpBdRxzBU9xNlqiYEBUnpgrlgZF797HhYOxInDBxq9TqZMHbz/XZhFiorJf/N
         ytZttCboF9mPKUOQWI4gleDQtJgnNdFF3hwg8cv/au6GZp9yYySwB184JoMsOIHIw/G/
         Jm4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UaxXobNM;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y6S0sjerZB1KYqxyDp/H9VdVFPp9C8u54xrerQ39c/w=;
        b=JUyymMmeld6nfPVm4jlZN4o0kMkFVwSM+QAKN6NUd4+tAiiHU7ca2ZyUnQrZxxUej0
         TQj6wIxV2RjsbXOXiCFso/RxuBgb/uFZd/sZtrUY24EpBkrXJjnhKMjJacqzCNFe/fOB
         W4baWQ7/jc5xs4ZJ/vtYvofKkt4jy0v10+itcs4agLxRWeIuo2MGcpq73u9812tP4Iqz
         c1RDvPuVOnmP7d1nyI8IlRZ0qa9QvvwbJvS1cSKmrLOvnVDNxWko2s9BGmD2gEoE1VbT
         e3rDDdP+ocM6vT1yDuGnBVszECFTI1Qzq1ugrHBxY2eaxZNtLvPKjAqKuOJGw2BFNfOS
         XL5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y6S0sjerZB1KYqxyDp/H9VdVFPp9C8u54xrerQ39c/w=;
        b=VjwQKEKiBruOP1p0ggMGOXJ6Au9WRZY9T99xEw022kjbbmn2tPPS3EJpFwtROwEqpA
         bVkSefpN53Vvm+aE2T3G6+4MoP1O0WWw/5O2ZwEpiqCudHPSgDgixjbSYi47PprUmKYm
         KSiQbrWQKI6LKy/46Ni35bJMx8pek4b6mCQMpZ4WtSkF38Y9Y7C2GbUfbj/NGMzEUdms
         Twg7K6symJBPDjgaDdyQe8j1YO0fDRcEsua2GnBc7CtEbb2F5lKgY28i6ckYFSoKGvnq
         M9WiMv1CxgUijayYNJLHBZqlGkYuuaRqhk/aCwxHgzJ8idlIMp7lVj20nw+INTh8pRAv
         c7Qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/ItqK/sk9wmVZVon4sKLeijfo+r0/NzBKZxchVf1sGkoPHqUY
	RbH6OyWnJRmRcfzzezwXTSs=
X-Google-Smtp-Source: ABdhPJxauGM/vgCYaB+LFvP+XKTOj65pHUKmbPzSzmH3e17HxP2IFVbKOBhMrDqwatxh72165k4b6w==
X-Received: by 2002:a62:7c0b:0:b029:1fb:6b7e:8bc6 with SMTP id x11-20020a627c0b0000b02901fb6b7e8bc6mr1123245pfc.0.1615296954991;
        Tue, 09 Mar 2021 05:35:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4108:: with SMTP id w8ls1042808pgp.7.gmail; Tue, 09 Mar
 2021 05:35:54 -0800 (PST)
X-Received: by 2002:a65:5c44:: with SMTP id v4mr24297190pgr.362.1615296954508;
        Tue, 09 Mar 2021 05:35:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615296954; cv=none;
        d=google.com; s=arc-20160816;
        b=SZUk5VCQ1/J0kJuo6bp/ipky9DGDbYItA6ImzLUsnBgNkdb19McUTLu8ldVU100Ta1
         5sTqnLsJ7I9P2UjOz4mgTWQWLaZiqDIa6shtW53bXAybcwF/63h5OO7wRksKKPTsoFQ/
         MMdSbuIkuhK7okUeOP1xhciC8T2Zob4n+eBg3q1AgQ+g5MtJEvzkFLN9PPXMLwnYUexI
         ZHCETMLuy91FuAX+3ZyGtgL7BrYt+yFzZh3Zlr6c6U8wIsSfoibSL5Bk9KFlXIgjQfZ9
         6PDYVzean20IA2xpqFs7i0MM/7StG5sBQP6MXhG8Rue4J/8KEpQWSdjiKlVP5o7D/9Ww
         pqDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=YUa/WbZIt/hr0CbUXui2XnP9fVfmeAaEz3G4k9xKspA=;
        b=JTKQeoGL+hIxi3syImFxl08LGTXqlPSm1ci9Bx3CRR0DSNq9tzdbW0s72PDwcJUNK8
         iEzmVWavaIoDWshbn0VRCamkIlrFYjq2IWXE8u2NWGmKkWRDEQ58e9C5X9El1zuatmZt
         7LPseCbLQcUwjWiNAGTFvXFNsCKBCMaL3PGj01xSzZAv07IFSpjZw1+7wqfPS9Ly61FX
         h3f9P1jEe5BtMy/jRPaxXDu5m7wUNaqOrKIHb8ofSCrq/FDT9mbhbXUCWJ+jZcgqfMy7
         5VM9oRFO8pFQXGrEG9jiCt82yCHdhlNbvgFC4/jGJvL3IFlQo19eIjO0LjMqlq4CrIpZ
         NLQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UaxXobNM;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i24si812816pgm.3.2021.03.09.05.35.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:35:54 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 0D78E650ED
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 13:35:54 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id F0BBA65368; Tue,  9 Mar 2021 13:35:53 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212161] New: KASAN (hw-tags): support SLAB allocator
Date: Tue, 09 Mar 2021 13:35:53 +0000
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
Message-ID: <bug-212161-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UaxXobNM;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212161

            Bug ID: 212161
           Summary: KASAN (hw-tags): support SLAB allocator
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

Currently, HW_TAGS KASAN only supports SLUB.

The main change needed for SLAB support is marking metadata accesses in
mm/slab.c with kasan_reset_tag() (or page_kasan_tag_reset()).

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212161-199747%40https.bugzilla.kernel.org/.
