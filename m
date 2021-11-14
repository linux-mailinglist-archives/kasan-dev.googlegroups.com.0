Return-Path: <kasan-dev+bncBC24VNFHTMIBBXPYYWGAMGQEUA3WZ6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id F08A444FBBE
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 22:15:10 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id t75-20020a63784e000000b002993a9284b0sf8103662pgc.11
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 13:15:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636924509; cv=pass;
        d=google.com; s=arc-20160816;
        b=D9VvRaU9ZdzmHAvFjIPruwhlXpdAcMekpybKYIZAxrrmalAUQy4nWJlhEcOqJ6wEyx
         YtIMgfQ5daD1paSMpgzdhpVvVQXNnEYkFQB2RerpQuNm0Yu/jEdf1r4QAW79FtudIoEW
         oc5bND2/SfppS9T+bZ3s9vh71Wn9uQAtOUgBSV8XWyn6EWBkhwr4zKCedor1/xTkcZYw
         67JbEJFwPbOjknYYsucPGLovAdrIurLYhWPBht7+/QKSN6weEYQ1urtnvTHWO6IDLy5d
         l8YuNP+9gQHvN8YosnKYHmMw5Le9TqBvLR5NBIMF5x0QEoCpySlCx68lhAfoICGEWiUw
         DZfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=N1dZur3fboQGP1tsHB/2by3obQ/TqmhGtbC8fa0dnTo=;
        b=CLRo81BrKffEhnHhLNoXKwgIOM3OFlqxJsG1r+wwbTcBaCiLKnlVob6qDh7V/rYH5L
         iZ8OKNEOk2P18wVP0+f8m8cNykJEmzam+CxgENaKAgoHi56KD4qmlu2M8jvXmXA0vfkE
         2LrectnYE1Oszyoq3npgBAdrBXFh6QMywMOOqcb6HXgjxW0rxL957T1Qzr5tiiAGBYWP
         ZtmAazmLV7yrN+zrrr+l9Fs1BlfU1Fm8IgkCSUAW+m1P5b+cRwvnLRUIUOemALbPhZRK
         V4FSW86vS677j9wagp/9+6yUIYplj4RUiJmVwkaRJyQcbScMP+sEjoU2NbT80z+2V6J5
         SYLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="jP/FGvHp";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N1dZur3fboQGP1tsHB/2by3obQ/TqmhGtbC8fa0dnTo=;
        b=f75CBzPJ3uCrLw5KslyEDijRWPUDbWJetzhXyjeMdM4eneXpb9jUJgOSaHIx0whEFR
         Ybom7PQFANh5nySh/vyGtZT93V5CsHcU0ZjAYbB5GOwXnFswGb/nSpY7LYRjql/EDvhs
         mAsX+qNVYtdvaOeHqyksgzvS5rkkqRuA683JhJvPu14gaHP+n2+gJReMz3/7gKhfGX4w
         F89xPYnnKwudUws+seRstwgfDrlqhdqqBk4IN7t14NiTNTLh0K5WtLvfPELpZetYEOxK
         C8emMMPRTu5icCakRklc+QYLm7TR5yikvVAOTEsPK4MLCddTNpiMMZriYAfieHM1Jlbj
         CyAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N1dZur3fboQGP1tsHB/2by3obQ/TqmhGtbC8fa0dnTo=;
        b=ouVQAC3EY3J37hFBpDq8+Z4I53q8De07Q/8FOPYo9bz0WoOhKQLqdEam7ldxKx1O8o
         t2Wh1wxIdivxxkp6c9GgW/XYv9Ar/fnIBy2nwWEfuZXHiPMdD3/4yp5fk6cCANDFA2Fi
         7xOarxCnjLBTXlBhuC5+uOa2VLZfQuA2H8dZvUaQ2ySWrK2AK99RcIElF1YPgYpAmmPk
         7OXVsDdF6H7SzN52+G4oDGOYBJyyUHBMcxv1KB0lSiBH5BXwYZ59I0kwoXpwMeG07ELz
         wkw/lXUeRrvGLh+TOV/R6h5JGgbhD5Czpbs5KYWZxPAIFM6xvoxRz370Gy9f4bzXWi99
         h//g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533E3V1IZ8cxoyOuWgt98EAhkH0pytFZ/oWpMUjbf1FbPPP8yk4C
	KxhiJ010aJsN2FrT8rRL8yE=
X-Google-Smtp-Source: ABdhPJw76LgGNsmiYe25He80IQANTZdhZHxvrh08eRfpKhCQN4Cld0mEw6j/ok0JeAxN8xrioG6LoQ==
X-Received: by 2002:a17:902:b909:b0:13a:2d8e:12bc with SMTP id bf9-20020a170902b90900b0013a2d8e12bcmr29179476plb.6.1636924509317;
        Sun, 14 Nov 2021 13:15:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3ece:: with SMTP id rm14ls9449153pjb.2.canary-gmail;
 Sun, 14 Nov 2021 13:15:08 -0800 (PST)
X-Received: by 2002:a17:903:41ca:b0:142:1dff:1cb7 with SMTP id u10-20020a17090341ca00b001421dff1cb7mr29118838ple.37.1636924508787;
        Sun, 14 Nov 2021 13:15:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636924508; cv=none;
        d=google.com; s=arc-20160816;
        b=O8794O9/S14J05kuP6jMYFVUD+2pv9MV2SGaNnj+RB6z0GbXesBMgIJeiK3f216dID
         6ChKk6E7UZoZK+rPqEXfyXxWk5x2agLEbTDgACaFEmDLcXCvB0Mh6oLxmUmdHhq6Kfcs
         5WTU2cxyPp3QbxU1+rRqP5jkUSjn3GVJmi/6B4rshxi4UUPjjfV58eAkJ+GxZHZGGm6K
         L3Zf8RjO3BPJxlk5L2NKl/icft6FxGXH0qOzzrqlKNpxOleiBkOSVwuzi6/q4I7RlGh0
         PbSzOkYtTxwXmEPg6qCgHND8atmmWgS/zLLb3NhuRpN0coUcFoORGsCXmbJ3OnAKWC2J
         A7rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=kEFwpxAcjN8x5OaVDJ/RZDuGnlWz+PyM8neRiMopcXo=;
        b=PPAn3xaor6cNrIkm+6xipzTqTX5C7cxigJzG9uuY9YduUg2xzWyWQ2oUZVO030y7FH
         I9hBbji1pZ5DFe7JT7NxiqxIcDd8gc89Trfgmm4VbvMxHeOrEu2wSlMDfFE+5fLpq98A
         /9HqQzDBJefX+f1q+ktQMB71ksWlcS97gie/jT2Htd6nJYQBC48rG24IUwxjp6HHXTpB
         zHgB7URhoIsp0A+9jeaVCCFRuWHTrBQpFnsFjFJTKDopiqe0eT8eRYZbMtVC0F3olS68
         XCXF6MU2Te8w7XYvE18nUcR1OhdumuRgfSU5HhDNfJZlvqSeUsuPYNgfxxVBDDpqLaFT
         osdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="jP/FGvHp";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g12si889358pjp.0.2021.11.14.13.15.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Nov 2021 13:15:08 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 79FBE61073
	for <kasan-dev@googlegroups.com>; Sun, 14 Nov 2021 21:15:08 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 6DD6C60F51; Sun, 14 Nov 2021 21:15:08 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215019] New: KASAN: sanitize per-cpu allocations
Date: Sun, 14 Nov 2021 21:15:08 +0000
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
Message-ID: <bug-215019-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="jP/FGvHp";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=215019

            Bug ID: 215019
           Summary: KASAN: sanitize per-cpu allocations
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

Per-CPU allocator (mm/percpu.c) is missing any kind of KASAN annotations. This
likely means that KASAN can't detect overflows between per-CPU variables or
__alloc_percpu() allocations. This needs to be investigated, and appropriate
annotations need to be added.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215019-199747%40https.bugzilla.kernel.org/.
