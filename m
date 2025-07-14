Return-Path: <kasan-dev+bncBAABB6VO2TBQMGQEV77JPTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id AB399B0420A
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Jul 2025 16:43:10 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-60f3442c58csf3103662eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jul 2025 07:43:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752504186; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dc5TIaE4s5/YGL6MHvfHZeSHv2bVyl3pTuJASS+/yVn8lcAMyfZvAD2VmKHuwR/CVw
         bcEJsNt7BMn5c5/+GkUHzy4+CoeyPqqeLgv7T0Am+d4j2VdEve1d5wz4AKAjl1H3r3gZ
         +CjC5w4ssNOByHP+2W2TuHmP9NT5qpsRteNrjkxcnfi690xIFdmIkbnnFfMGBnU8HftQ
         KA2Z5+JpoBdTkSRgrK1zFm1MZ89Tesg87+dSCyzOm7LlMSdk9I7/Vu44D0CVB+6xEEAt
         hOyNGgsmKQJui93Y3PrPHCuhCStvJmhJM4wwGZqKTsNi6cbbSfwmG135bUa/as/VSlWG
         lbQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:message-id:date:subject:to:from:dkim-signature;
        bh=GkVpBkQHScbafAHj/iG7+qLaZQdqoV5/y/ClfuphsYs=;
        fh=SMZQ7D8vpVRBhveiY+NC1CJX8vnEaDxkCju85iDeOgc=;
        b=HDSzPdq3N8+HH8E1TVbqMDCNKI0/X26Jd3Tjtpuggg9Tt3e0cXUfrAlWykfEYE85a0
         ReaafOxf+EER3C+gXl607MUiDPmeO/ZkE32IQeG4IJgkuMwkDg4PCpgjHxsS5Fpxc+yi
         GkqBr2nc/enShcjMmeF9dXOWL9Q4lBeoNnZyM1XLVDZki4cIsSZrMXE8Wq1DxhkkYMtG
         G1uBadGqIKPro2WqBnk5oTqusMdhlv+Rz+pwlByPGPsr2iycwlakwKDHQUjhb2w0YPWC
         Qt36kWAZM2T+9NW1hHvxZZrFNjCI11xedDRtEH+e2Bq9fWUodUvaW2gf4RC+zMKacS0o
         jN9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kJdI5FvH;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752504186; x=1753108986; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=GkVpBkQHScbafAHj/iG7+qLaZQdqoV5/y/ClfuphsYs=;
        b=U7/LRynEoG2H1x6MNde6uQHVe8qnp9vR1vMhr46dUv9YN6EQ6gmnclHrPkGWQCcHeS
         W06JR/A2/QKBY9tkDuXtOARogwoPydfg9+Zc49T5Id0XukwTfvqcaVYVnMzw5wI6wsWE
         ar9UevKa76eAPpM1us/HYFtYqZ8q4boDkIy5UtPxwjUx7XfF+Vtz3TwFvi318zG5HRu0
         7pbEojftSsLugV61TTn7ndX52K89XZC0WCQ06Xt7g4b/+NirGu268m80SmE11l6IH94T
         pZ11VNmFKQew05an3BhFRgDmi6dcNyxodk9dICuX34JRs3X4m6upHd7K3v3dNbkx6M8Z
         U+vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752504186; x=1753108986;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=GkVpBkQHScbafAHj/iG7+qLaZQdqoV5/y/ClfuphsYs=;
        b=gPGc9puuUgjNTuKb0SPP95mZwJmXNF/YU86ZqQumaaNpFYVrehKXIsVpM5tEViOFM8
         Nj0BMCbZ9HmliyObWP6u1CBa1VK9cP2zFlwEUkTVwSt4tWh5CptcMIcAa6Wix9AziOQc
         yMH+Zcm5usxh+MOrDJJfeF8vMeFDPMz599XdoVRRqzHs0y69TR8yZZVr7P9Fm7tPkPDC
         OwrXq/8m+sI1l5bOUiMaDCL7mXRuzSa9yV97s1Yq+PMmdTfOsU3eoroijiVMPsuRl0RM
         Lzif/FrEX2b3SEXwtZVD/U+LfIt12d28E/frGkTh/R0TohzRc2G5baaPn1eglZOc1aXu
         grnQ==
X-Forwarded-Encrypted: i=2; AJvYcCUNZhLmWssQu6IobVb/W2NQGgAgJlWM7qoMJhJpwPagkgt+aC2tzlrOmCble4qh2Jd7nZYCPw==@lfdr.de
X-Gm-Message-State: AOJu0YzD5qIak4FpyQFPhdS97JhUsLDNNeV9//4dSAiS6e3FNGQqLONV
	Qpan2O5I6qlcZYFK9SABfJhdE5pM1F45t9eS9rBEeZwnpdL1TLAQ2WQ7
X-Google-Smtp-Source: AGHT+IEkSulm98XwOVy07FTJcdfG1iNi1jAK61pdvEErO1gP6oeuNmMuj24Jc/26XkeKJzwZ4FvSWQ==
X-Received: by 2002:a05:6820:2785:b0:611:e31c:5d23 with SMTP id 006d021491bc7-613e5fff653mr9303584eaf.4.1752504186683;
        Mon, 14 Jul 2025 07:43:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcwqv6pxOmL7XYoI44e+9DfwuVNtEDmTWgH4z+JhxoXug==
Received: by 2002:a05:6820:4df7:b0:611:7896:558b with SMTP id
 006d021491bc7-613d7ab8387ls2226915eaf.0.-pod-prod-08-us; Mon, 14 Jul 2025
 07:43:05 -0700 (PDT)
X-Received: by 2002:a05:6808:16a3:b0:406:6671:6d11 with SMTP id 5614622812f47-41537b53a66mr7869813b6e.15.1752504185748;
        Mon, 14 Jul 2025 07:43:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752504185; cv=none;
        d=google.com; s=arc-20240605;
        b=KzP1TWrapafqpRxwT6hCYSoWpNR4HQpAZHuqBNPjTIQmVl1sGh0b5XqKj3/URYsRIN
         knZNQ1Avr/npGYPefenzfsQBHLumQ5F6YtaFNHLT3a7mC/09cxK7G66ixeqCN5LVymE0
         qceV2Amwwf/kYOVDnGPckyJrgllyUNh3MeG5jEd07216OO/ceIWT+bOPqOWoacHBU+Aj
         FVedXVWzTCYH9gW8niAFqidrBGYlHhhKl1ogwIgFXy23p4cTA2gS1k1ep4FZI3Mi69ju
         +fHtLqyf2EvTuLHVxmoTRNlmPgL5Y7iK2J+Z+f6hr+Y3y1RcsYd1irjL8J1Y5ELQefPz
         epIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=0ppoLGLJGmlwetg5z2BMySALrcWMCvY03DG+r8/sQdM=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=YEB+KoVCFsza03C06EsFIR74lzpNTEAlr+h0LEqBARVe+L4WnrOcKLwCspT1B7odAS
         wXFvj0RmxA3cHG8KBr2mCk50tGSaEjqMgFMahVEay7A1ybf+l4Zvfulid6beQVQLQI1V
         APS6L6DsSw2cle2JHXKpUIZpzGRIL0R+gJMa0z9gK7q1VhvUp9E9qUZJyvWcRTzrGOcH
         wNryLx12pxtR7FjVkRpglJ6bpDvHJG98TLImSb/bJqe85NBdNxyYWzyncjuM7y24SkEh
         Vgi2TnYzMEEWXieP3o1NgP/AorcfXQ5+VcaFbDEbOJ6cBjCboWe6j48R/Wio7gpur7MZ
         iOxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kJdI5FvH;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-414161e2600si404528b6e.0.2025.07.14.07.43.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Jul 2025 07:43:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id ED802434FF
	for <kasan-dev@googlegroups.com>; Mon, 14 Jul 2025 14:43:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id CFABFC4CEF4
	for <kasan-dev@googlegroups.com>; Mon, 14 Jul 2025 14:43:04 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id C4295C3279F; Mon, 14 Jul 2025 14:43:04 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220338] New: KASAN: restore printing info about vmalloc
 mappings
Date: Mon, 14 Jul 2025 14:43:04 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-220338-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kJdI5FvH;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=220338

            Bug ID: 220338
           Summary: KASAN: restore printing info about vmalloc mappings
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

A recent patch [1] removed KASAN's functionality to print the information about
 vmalloc mappings in reports due to the possibility of deadlocks; see the
discussion for more details [2].

As this information is sometimes useful, it would be great figure out how to
workaround the deadlocks and restore printing it.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6ee9b3d84775944fb8c8a447961cd01274ac671c
[2]
https://lore.kernel.org/linux-mm/20250703181018.580833-1-yeoreum.yun@arm.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220338-199747%40https.bugzilla.kernel.org/.
