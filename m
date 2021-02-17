Return-Path: <kasan-dev+bncBC24VNFHTMIBBBUJW2AQMGQEHID6PNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7155731E0FB
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Feb 2021 22:03:03 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id f127sf32053ybf.12
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Feb 2021 13:03:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613595782; cv=pass;
        d=google.com; s=arc-20160816;
        b=dXXm1I8MkdO90smV/7tJQ7ZLlNRSnOK7xafu4smgWc57/QzGIFazsdwyAAw4Uz+elv
         I8lOLqUsRNQzbIauHDDESSVNkp+u0sNGclfM6AtT8rb3OfLXYssUGoqR4JOmgvA2P8gu
         ThJauVd44LdpZsugOsVBckvh2O2oyQDBo4Z0pEbypSpaRwb6NK6HYbvjYBfS3iz3jt1U
         q26+ZMp/g3ZHOJ3GmLnGrhzHLCT3spT8I+t/SYSgC+crjo4Ly7LRHWeyJqhNl3BbM2zA
         +Phr1RhHNS+pEOmkami2OQgdXnkyOG5W2fPYbGb06IpZjikHSaZ4mc3Yg0EDADjD/X3g
         cGZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=q9OiB2KhCQrzNT1dN9s+GZO1LDrEBW/yBhCmYsebgak=;
        b=a00VaGQjm5sznIKaTkiwl49eH0iom4wjRRH1H5P2KyT/mQvGpmZF3SBAWoC4ZVE3mS
         SRivaL3DX4TGjenFo0koUzQcq4WCdf9npEg3JZVb+BDwsQOsTayUscrTEftoU5VqGYlC
         Gfzi2hzATgALAwfNUNFObvt8UdsVhjpV9Ep/WsTacdA2ck+ZPJAt+vyu6D+SqmZtQCvr
         oqhKZBsyTvxA7O6r5R782lO34VFriGw5SN/yqjok2xExGWek1bMOIFrNIoI3DYDpE2xT
         DUCag8MOhHOH+PCmTMWVbez4U92FPgOXHJvSYPzvDzrIGi1oaPKmGlu/XLb734uVVJeU
         HJBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fNTLy6T3;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q9OiB2KhCQrzNT1dN9s+GZO1LDrEBW/yBhCmYsebgak=;
        b=gAwSfvnFGkKTz/5/0CHD+AuS+dQGlcCh7cGcMPiaiSbgQ3ueydgCGDZHLDoWZdBA29
         7g9lPntjS7uYOZgyjucFe5ca6cNU7oIOfpldasoG6Mr+N89XCS8E/vSXnpE5zo8Sj+r8
         OIWFNKg8HV9iJZgNRnslgl2VxDdU4J1Bv6GJFvr6Pqt5pE8Va1Q5SuldsmqWSzKjTjG3
         4OTbZubR4U61pGANWHU2wLHUIqSdaVLhamdCxE1g224KCV/O/cGZxBXduMdrw/UK0o1r
         ZhUWn36f618zQziRpElMniGA/AEpbUE8qJXv1ixpkLpPcZhVPYzCyHdrsP/QCwWt++dN
         7v/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q9OiB2KhCQrzNT1dN9s+GZO1LDrEBW/yBhCmYsebgak=;
        b=fFVwFXY1Elw8Mr4lStd2q1obYdjU6Ml2M20J6eRA7PytVh0M6CfezrfLPBaxaxem69
         ykANy8srVY7HjNucXREelBQSxe/48erBaVmZ8AeM2wOmC0ETuvTJbno888I+BzLifj5W
         9FNsTum3cQ3Rc7GrB3RmN7/EVec8lpftCWg8JfUi8XlMNzwvwg6qUtcZAWMsMSBlfd4L
         htejxH8YMAvNR+BU8GkfDNOo/+BvCLoriCtyLWz1Vo9URPNq/jWPq7dY2buZBZLcYOsd
         XlmO+C7PSdMafgBIhAjasOtfJUL5eaAgu0uc+e1Th1vcww5JxFqa4jbSTNgJAhPhTWkI
         ypdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5324hZU2tm+jpkQO89AUz0gX96ad5BLZ5/jRy5ayuZtJJRE1gPUm
	fMxQSLD9W95edb0CIwj84wg=
X-Google-Smtp-Source: ABdhPJzVLGAkn7vhC8utmjVcHblyjAQoDR0N9aFFgB/uzMNcNVuKbb5mpIzAenozDjvN67A/xcmPNA==
X-Received: by 2002:a25:a241:: with SMTP id b59mr1970141ybi.289.1613595782293;
        Wed, 17 Feb 2021 13:03:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:68d4:: with SMTP id d203ls1806753ybc.9.gmail; Wed, 17
 Feb 2021 13:03:01 -0800 (PST)
X-Received: by 2002:a25:d94b:: with SMTP id q72mr1764445ybg.135.1613595781939;
        Wed, 17 Feb 2021 13:03:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613595781; cv=none;
        d=google.com; s=arc-20160816;
        b=t1FhPQ1HAoUyeqsIuNE6sW64qarFCXWLkAHKbdlItR3ZHMo3mW7xUgYDGlc/iRui5H
         bhM2wbVF9syZj/sF/4uwbpaW0Hc1ViCCalWjRl8anL14SCdWnxaCeVNxx7qYU87vrSee
         ejwPPTQtZee6eXhO0R+5h/lHyEWkVdCT/pn0/DG3ozYMe3Vgu/64LOEjbgBnbG9bPStV
         Dhy9r7CqkFls95oZLQJ2h4gdBvx5XvLelhkYYkKr86k0PZWz5g/GPuqzO+D1tPktgv7S
         4uAuVr3loO4zoZOn70CD8tJerJAXstZ61yFS6uGLqGcZMPovwZErufiAegF+paMbg2HE
         /SsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=wFwMZhgxaqONbm2Z4s9B988DeLeaZFNjNv4vnR+C9+c=;
        b=ifvoabeNwwUF5M5Ai5/szYp7Azvv0xjXcO9wpuuoK5hieE4yI6YIjmMzT68YqNNKJ/
         LcyEF4TrVfzm+y4oQ+ysfojro+Q3zgrwYaVRYXshp/4A85AMGfymaMkV7FlOom73qCUz
         kE085vIWWOw9usElkh0fAa9B3l1ybD5fOsBkJDFwzcnJIxAV1oezg2dNQAgdBj9tHCgJ
         XJxox/ZrJXVpgfcCtNq8nH0fZrxnQ+w80fpUbmVXmzULBrnkWIQjLEW4x6wF0GsGI23S
         qsGkULC+VZoE193KMuyp0rluQ6ZlHhdVBPWUWLV7nIRQWwNKs/UI7wusrXuS8GcP+EYa
         wQLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fNTLy6T3;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k6si147679ybt.4.2021.02.17.13.03.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Feb 2021 13:03:01 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id E835B64DFF
	for <kasan-dev@googlegroups.com>; Wed, 17 Feb 2021 21:03:00 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id D6AAD653C5; Wed, 17 Feb 2021 21:03:00 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211817] New: KASAN (hw-tags): optimize setting tags for large
 allocations
Date: Wed, 17 Feb 2021 21:03:00 +0000
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
Message-ID: <bug-211817-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fNTLy6T3;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211817

            Bug ID: 211817
           Summary: KASAN (hw-tags): optimize setting tags for large
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

HW_TAGS KASAN currently uses the STG instruction to set memory tags for all
allocations. Using STGM when possible (e.g. when a whole page is being
poisoned) should be faster.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211817-199747%40https.bugzilla.kernel.org/.
