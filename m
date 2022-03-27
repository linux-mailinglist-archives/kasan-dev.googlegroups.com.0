Return-Path: <kasan-dev+bncBAABBKHRQGJAMGQEOMRKRIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 10E074E883B
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:46:01 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 133-20020a2e098b000000b00249b89dadfbsf2415457ljj.9
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:46:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648392360; cv=pass;
        d=google.com; s=arc-20160816;
        b=UefKcyg8OsC58/wnXWpbEXACeIE0QPm5voSrfsOXH0a6iQ2yrrS7PLGrN9sGMVyhuP
         S3SHwWfG99hc8RXAFiiHrs9AOqTF8PB8dNgi33FIvs23HJyWhI2jdpTCjlmSVHzFK6Is
         NPjrb97cCXysP1YQ4sypfjI7xFjK7e2ewAte9rffzxsvAAyznupoYcpbr6oAQTw70xk7
         zGBvq2b/qPQqvHRitsOoQI+q18k6Y/YlaQwmmtXtvzY17CiCBUWXEnzHlRcp0kScBhrS
         0vIEGY7un/U+ylCwhgC/sT4htshj5DbVCV5celOMUkavB8TubWnXTDt8OpyDxnavuRJ3
         UoOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Xb061O/sf1gREMCgY56pRfg2DVfYjGhESAf6aDs+PCc=;
        b=LEQ4u7qvQLRi6v94uYaMzt0f3WYMCaCLZFjWC7V9VhUEplPi0xFxRgnRdzvMaDktJo
         nptVKyLkktKqepcU3T0ALcN+ENUNcICXp4ouZD9cYPKu8tTOBwyZqzSK5jKFAcU4o/Nh
         zZgHbYKtclNiEgcqsEVerBDM+iDKzqimUO8+c+GX6mBJQlHKu9t1adfj0LKkTwOLaj69
         p4k48cSDs3+XBZhRX2GETWgMCCrV2XAlmX6zHQo+PQwutO0sBgB/ASFC7sB2YHNfTrH1
         nD7lzWflP9Qz07uXDnvpSHfr0oOr+8/aUoePWYim2j/f1iagNvdpdAh4nO8z60t59dBi
         mt1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z5A9zP2r;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xb061O/sf1gREMCgY56pRfg2DVfYjGhESAf6aDs+PCc=;
        b=DhzWkmd3srvfuW/FbmMXbVWCjJnozMeZglo076T2IHqhAu7bYsscpboXWL05DVPgFx
         WUqasqCyBkz34C9GL893ASN3BDmcdFPTn0V+hHrJ2ivLys5EnbIFJZUpCpuCehuay8Zq
         fQiynXOsWJU9jcBCn7/RmnAbwIi4RBxh0QS2sGLsehrUDYqB/3NSGaS1+L1wQ4dG5VTl
         /yZXBt3wIdYfcf5KANMLPpbqQ8LmuBN3PQBepOjsSTTufarfQh8hnhAdMKv4aJriRtFB
         tioITccQI7hS7+8eNyaAnn9ARAqNmLPVWP3BWnVuM+n/CbITEbp8GidXWQU09Xkojdus
         MmkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xb061O/sf1gREMCgY56pRfg2DVfYjGhESAf6aDs+PCc=;
        b=Tx2d+YPEpkB7gpCpxTglEuHmzFtTNKw4UMpyPkL4jyq6c/t/M6UbVihdsBGbQtp9QC
         zexC+j54xmR1wxvxlKGWUfKrA9WBSH2XGq22md0+LJ0jIZ/RUgFoy7K/KrHCk1q3/PyB
         lsvPkIbTCnNgRLjc2K0np5px4wfG81rlrpSb7Bgo/aic3cJSrRgMyB0Di0Hr3PTKeNDx
         u3QZj+pgDjHVv72A+nfCkH51pvHGf552HgFWLwGbZzoJ8XVYocRQkWs4wEwlRR0hMrFH
         ODZs42HwPYxJHwKP3wVnz2nfGUOGbLaThdB7SNb/L4Lh7EqPq4122y1amszTeG8gWIyD
         2+AA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531VsgUNw9cpSq6ULjoEl7C8OVeXks2893/7pZQ5DSKeIDplMQ/z
	uaxM0fV+hQhtDBZOQLgYqwg=
X-Google-Smtp-Source: ABdhPJyeuCQFqxjS4x8BxxrtafhbOpqsq+rxNNU/cJUba7sAq+uNrAf/IXcwVy0ZBJTtPHc2p6KZiQ==
X-Received: by 2002:a05:6512:c0a:b0:44a:3766:5904 with SMTP id z10-20020a0565120c0a00b0044a37665904mr15612476lfu.544.1648392360609;
        Sun, 27 Mar 2022 07:46:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5285:0:b0:44a:94d2:1d8f with SMTP id q5-20020ac25285000000b0044a94d21d8fls394234lfm.0.gmail;
 Sun, 27 Mar 2022 07:45:59 -0700 (PDT)
X-Received: by 2002:a05:6512:ad3:b0:44a:614e:9d4d with SMTP id n19-20020a0565120ad300b0044a614e9d4dmr14175701lfu.557.1648392359776;
        Sun, 27 Mar 2022 07:45:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648392359; cv=none;
        d=google.com; s=arc-20160816;
        b=lClSMqzZP8LD8Ts6rFhCU8CNravzawAhQ35VE7jQed1DTJZ0IE2sIZCxlSWJE9J4rk
         Qo7AxMZjfsgYUqeWAHrnBz4ibHUTFsY46ohjd6QW3/pYJMgJisFKLBSLuvLtqhARoI1r
         j60BUc+1DCbSXdMNRrBthFPJR51kP72XOe8YuC5E7P4+2R3kztRBNDN9hJB7EYfwj7q5
         xH26e4SSreDapS3JJiBMENNsz5pyL2+fd8oDsZXEhjGLl5bVJiX9EWzSyZ3mZxOFfT5+
         PWBePVdvYjcXz5M1yYBItJd/ESVookCr/LFYw3w8VLDsdQe17nEXV3YeaPG39Kvf3a0p
         4Nwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=yD3h1gj+7fvgWX0/S0Jt7JOJGbujzaB5PTQIJHs6LR8=;
        b=QuVvQGHMPzsXZ7r7JTaWoj/Hc+kfC4BwqXwnNZimVMCS9mBwttDFMeY10OggXs9tLr
         eFl5boQJyKCa5IkGR+o8HvKhDvc6mLTvnk+zSQ/0LqybeY3/2eNKYLBNue2IciClCFjL
         H+27JHLE5X4iSQgLMTvt1C/UARroId9NO22f784Wc/1l2qTtC52fq31TGwda6cCm9Q47
         Hm1Zmv9TYalt9Ttx/m22l94j6U3o7Lmm1TtLOMSYM8Qa+RxK4Mp8inxJZzDRDGahvSuh
         vr+pCar1rJsyK1YvbSfUI++pcu7WH3eUHp6GQtBN+tGrWGRt8G7f3NQB6tI7LkJXEpPN
         FzOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z5A9zP2r;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id b19-20020a2ebc13000000b00249b9662730si290952ljf.3.2022.03.27.07.45.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:45:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 1AB40B80BEC
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:45:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id BA9FDC340EE
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:45:57 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id A8057C05FCE; Sun, 27 Mar 2022 14:45:57 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215755] New: KASAN (hw-tags): investigate tagging pointers to
 vmapped stacks
Date: Sun, 27 Mar 2022 14:45:57 +0000
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
Message-ID: <bug-215755-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Z5A9zP2r;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=215755

            Bug ID: 215755
           Summary: KASAN (hw-tags): investigate tagging pointers to
                    vmapped stacks
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

Currently, pointers to vmapped stacks are not tagged with the HW_TAG mode. (The
memory itself is tagged.)

Evaluate the impact of having a tagged SP register in production, and possibly
tag the pointers.

Optionally do this as a part of adding stack variables tagging support [1].

[1] https://bugzilla.kernel.org/show_bug.cgi?id=211779

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215755-199747%40https.bugzilla.kernel.org/.
