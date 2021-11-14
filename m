Return-Path: <kasan-dev+bncBC24VNFHTMIBB3M7Y2GAMGQEMFLO3LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 756FF44FC4C
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 23:38:38 +0100 (CET)
Received: by mail-ua1-x93c.google.com with SMTP id q12-20020a9f2b4c000000b002ddac466f76sf524924uaj.12
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 14:38:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636929517; cv=pass;
        d=google.com; s=arc-20160816;
        b=NSb73MCR+tTsqQNZLJqiJJOAVV6ommu2E9gp81zshJZgG5eGMMYqqKu5ZEF4RhVtoS
         jhGBY5SpMUqhqybiulX+1iPfCtfMJrGE39mNG3a7C8GtPsgz5Z3PzJ99APi5VR5LRXhC
         yP4j9IJSq0zBTxn1YXrh0ZG4ggS1+8XBMyjB9rtkhwXXWPLWCXyKoK8MCC7fO9z3Sr5U
         dgNwurcuA4v+OFjgN4eOBGUZD4XpRomYgvpX76jEu7kUoYsyAsWBlwnDlIoajGvAuEUl
         NlnvrYy/yT6oDFvy2dU3X93WNgmy+7biE+1HHkVLUOSG4fANbMfUtJa2z4pmRPdUToEK
         xeTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=wrJN/TZL7F4m0/BCl4EfuLusqpod28HaByNuJcLtnyM=;
        b=L1sY+Cra2vLhqvA/6kl980b1aMrD8/K8wHOrq2JO3qoalJ5KeE+qImLGt8yfznWerf
         MVw1BzJCbocn3zkuYgEANaQcDSOHGRsSTHOMfKap2f7t9bn+0tKMEb0wkJUOGq/3pOvG
         tTyOTqV8B7dxiMOttdrUcydyBeg5B09+TbN0+UCGDTWNNYLYpFLHW65e06tiaB1ti/hR
         Iao7RvjEQ3v/ZJc92rziMI14PlKurBsD422chOdhOjg48PCG0zbJazXTWC+oV6Faw/3y
         keDZtwmjDhwe+j53K5eNUo/JMbJlOm34aoxgm54Re/Z+wGQYlYFJxngcQ+G6THCiBNqY
         PZ4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mXiZ6uy3;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wrJN/TZL7F4m0/BCl4EfuLusqpod28HaByNuJcLtnyM=;
        b=PtQZxOgq/dcTCc2xOP5PI98AKB3V+XQHWwq35Re71ZGuv5b+sfTQkN9Vn7gokkC30P
         HrNSazJs2UeQab5CnaVzjnQ6qIqW6xfgzSDmEY2I6XnF4i+e+q7jkpZbSrNdQa9cWn74
         nKUjB1lSFHuVMQpQV0Gpvnrk2DuGEoW67CulbHkNDOqfri+3C57CO0YTgULcb6wpKEHr
         Zdl5NKIg6idGJ8C9DjDFKVFbGM4xtif62Da/R/Sgsi/lqgcitvDXVIeyVjkwCkfo5jnQ
         zFz+pv8ol+17d8pUwNwtMMf7CYFx/vjq/VnSJcw0JyxUfEGYV9C/UeuTnAAFJjwEkKBc
         Qtrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wrJN/TZL7F4m0/BCl4EfuLusqpod28HaByNuJcLtnyM=;
        b=D0QO6QOo64C/R6Y2LVm3ZNg7AyjywsgmvHv8EzUxnlFWkDy7SIijlxuMa/dpqTpzA/
         GDLZnvjHAzVgOqLwVUwFW4AG1hHxlq/e2UK10TGvt0X6N6IF0+NWxa9BV4r/2hT1OpK4
         0f4FmeT7pDus/bfQpDow/Lfv0qkSv6+lH98JHYz6PIEqLYI9ztgOsp/o6Z3h/v9aHZOy
         8b8H+pX1b0J3nYt2KSKvd+UOz5ehz1iYeJfVixX4VbS8jk5agb6W+Jh3RaZYn00mEUId
         5NMdMGlqqhB7Z482rH9kyd6IpaV8JVGUBgN2GI5WitDXj15lyu7nDLW6U6v3iriNbNPb
         +F4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5316EbeUygox6VhXtCz3/WsshIgpnnVMepBDk+euMyvQzi9WqzvH
	SCw3oUh3Ia/ZreiT6sGYJ6k=
X-Google-Smtp-Source: ABdhPJzc+uBbiUDrgZhyVdy/3H6xX6FIEo5RiGwGmUYmGVtldcfgQ3XkRj74BDWjwAHPB+e0Jn2oGw==
X-Received: by 2002:a05:6122:997:: with SMTP id g23mr51751678vkd.15.1636929517489;
        Sun, 14 Nov 2021 14:38:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2386:: with SMTP id v6ls4260405vsr.5.gmail; Sun, 14
 Nov 2021 14:38:37 -0800 (PST)
X-Received: by 2002:a05:6102:b0c:: with SMTP id b12mr35955339vst.27.1636929516931;
        Sun, 14 Nov 2021 14:38:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636929516; cv=none;
        d=google.com; s=arc-20160816;
        b=iEf4nf/cmk7TBBCnZIeTczqlL8sLLBE1lu+bCrT+p2piQI3t3WQ6yyI4diVyTwtyOh
         Z/klZKlqVMVdBdyS/Lk2jwdxPTanQSqOOAD8ztxJojfi597bzyr/vUmf5KumSEqVPM+N
         81Y8BiioCaIMfZIS3LDX43qDAU68yF1/T66D8VIVbHMocZt6UFgTao8s+d9LQ8C4rUCT
         4+xWrXDzhKS7Q+3OIhbzR3ThQDXJK9OnIQZVhWTbPTu00ucrW1vBKBA062Jc2VkY8ter
         jaNG1N3quGiSIem8dym15MMp4MiU2oFsNTNpBLdmuUPIL/tGsbGZDjc+asE5YuOGGlyj
         UIAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=SNImNu+ljYgarbAtyH96aO+xqqxyrI8QUhrogNzSVTI=;
        b=UE7DBv0HUVY1iYWs1FsInOQbc1VrpdX0vaJxFk6vyp0r1BiHiqPhvSx8hojKtbtXMW
         SPdBzVHMb5z3tc99jcKv8FAQ8ZEMESi4fki/gGRXVjf00KuwyOV4xcZibsaYAdD7BkRU
         VMi9zqOonCZJxdRUyjVOUIq871W0boY63TQlFGNDgIPZ28u7v3OO7J8Ffhts3+Li890O
         U7MoQIpIVg0/jIx8bz+Bd/Ud2r9U99McNuFo2W8rA8ePPZhxD80gd2j7GKHsjWpzB9kq
         arsEr2VKJSG2FrjnGJCOwuyHEBC+q9IbaWm9G/tUGtJsYlkLQXVYky8m6pCwfBJnK1f1
         XPlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mXiZ6uy3;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i3si1036591vsp.2.2021.11.14.14.38.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Nov 2021 14:38:36 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id EC4E361073
	for <kasan-dev@googlegroups.com>; Sun, 14 Nov 2021 22:38:35 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id E0CCF60F51; Sun, 14 Nov 2021 22:38:35 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215023] New: KASAN: redzones for vmap block allocations
Date: Sun, 14 Nov 2021 22:38:35 +0000
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
Message-ID: <bug-215023-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mXiZ6uy3;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=215023

            Bug ID: 215023
           Summary: KASAN: redzones for vmap block allocations
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

Multiple memory objects can share the same vmap_area when allocated via
vm_map_ram()->vb_alloc(). [Generic] KASAN won't be able to detect
buffer-overflows between such objects without redzones.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215023-199747%40https.bugzilla.kernel.org/.
