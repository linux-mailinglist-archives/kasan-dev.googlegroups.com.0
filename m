Return-Path: <kasan-dev+bncBC24VNFHTMIBBMWMVX3QKGQE34U2M3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 886211FF294
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jun 2020 15:03:47 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id a4sf3983000ilq.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jun 2020 06:03:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592485426; cv=pass;
        d=google.com; s=arc-20160816;
        b=xhIQyXgho2pp17Gt5S+ua4FalHoge04QlG+BJsin9wGq80onARgT6gm6kVbsYmcl7E
         sVAg5K/rLqvz+5onPzlmaKomdcifY2UD2OrygqrMITAIZ+YZVzXZOFD74CSGbdY6U0SP
         3E2IQiJS7eviwNrubDJjRr0PdYpLlTWVhrNRWhg0rXB7+AZI+Dt1P8lsuQwsgqcWutgn
         UWXLYDB3todFtPyCGOhCZTsA1Ao88ZlmXCnqrLfRnFkbS3zRCzcs0DgQlk5dkhVbPZIz
         gn+ea2hU0UB9bVDvtUFBRT07w1JEYRE2MVTnrW9GJv+U9lvkI9jJ+/0Ry2QHKBLXzCS0
         iexw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=vFQgrx9JH99M2BsaEB+cbnfSl37tUnglCTvEUzeniU0=;
        b=QJ0gVkohZgiMIX5N/1Ls36/RLuCXcTORtCIqHWtU8mXKHxvRr8mQzqYCM7L6ZBC0o6
         D0vsPRp+qCxLpasVeS+9n/b2SvtJ6tbItJSzI1iRqxdq8c97aRFCMqIBTFPX0n1SvXMX
         1IqjDwVkrKu8TT2CoQ8IDv4j2dvF+5CPgsdwXn/VXDiaCgYyLOx119k5vY2Mfj40Ripe
         yYAXGe8JElM6d3o8/oY7nQ0urLa9IfTArYqhHLsaRy6SYn5ouc0f6wIwSPfZZ1aqKEhu
         mcZB+LYsMlkvYjNYkFZzQx+EMQFAcn6b3H9kJTVDhR7pnWmiHpRxbbRy6SRwBoUOA/UF
         srqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zslz=77=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zSLz=77=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vFQgrx9JH99M2BsaEB+cbnfSl37tUnglCTvEUzeniU0=;
        b=nS7oASynhIRvJSaRN6rK3HNiFrNWW3458GOzPnnRTjEgcxsT7+yEtkU9Gu45reXIo8
         E+AdJEuk41gmC1CRQNtj3UlncTigOo81kvzyaMsfzV7IVnSpqIm+0Tjqz6juVc09tgyv
         1B7jZvcdJrlBv313OYtgzEs51Ujjn0hX4zEGC/J/jC7l4Na918ytHDcHXcf06KlqzRX8
         BUdENMpdenlGbaT6tlWhz9lXaKZdyOBsT1vseXTs+Ba3QTUVslQ/aE0PLxMnF5VCsdWH
         JIqt3BLEQBCJTzzgd/g3pszfkg4d3557J9kxUSMpuekRxZgFKDcrKoXjk3XVsW6fXPvX
         GBFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vFQgrx9JH99M2BsaEB+cbnfSl37tUnglCTvEUzeniU0=;
        b=U5Jd06BNfA3dICMRXVwWnezLRdJUDZwDMyJlXgKC4v7T5Na0yZGQ8K7Ae3SD2Jrl5S
         IdLtfgzG2ybgZVgQALMVqYCcDTM9/KxyRk0x98RmvzHYa99/wHR4Bn32wT5Iyya/OttF
         DusmjExkOadu95ik2jkJA3iqS8AGsl/bh7s3h6EYzQXFfjyrVrNAMX6ZkNnZzGfuQJzh
         Q2tUbWSxbcQ9G3zd4/40857d7GaI6I/WIwhm5z6FAGi7BnO8yoTdLVfvCMJDhPBVZayX
         +MDV5qtyBrmRKFMWNptk9RC6+29A//TIlqwYj76ngZKRdTRB1yqGR6jCvxwGUy/yjzw/
         10LQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530B/MXfzHY6fZCoTKD8ctD9eP+V4DZfUIXOzK8HP4d5KpncSVJo
	BPGG+WLmBUvvdRN+gvz0Zh4=
X-Google-Smtp-Source: ABdhPJwpe6ayifGVQRcday/hNlRLkscHeBKclKQaBJfrQmlOy8fA4LW8ZhnaJ9md5iGjSnSLXQ2F2g==
X-Received: by 2002:a92:48cf:: with SMTP id j76mr3971444ilg.270.1592485426379;
        Thu, 18 Jun 2020 06:03:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:9505:: with SMTP id r5ls1170040ioj.10.gmail; Thu, 18 Jun
 2020 06:03:45 -0700 (PDT)
X-Received: by 2002:a5d:9819:: with SMTP id a25mr4641988iol.85.1592485425120;
        Thu, 18 Jun 2020 06:03:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592485425; cv=none;
        d=google.com; s=arc-20160816;
        b=MF2MQtROnNDeEtMWohJ8HPC0w5DjmYaQ742jPGSAGWrUAmD5FEmK2eF405A6U4nbdF
         T/Doe3ThFuP5ggrzH70D558fo86073wrf4BF4URbdmJsWeaNx6J3oJy+FBFxlqOwUh96
         jrJt8mpvr6Da9p1UZVpuW39PUW6EoNx7bNTVrF8ISxzzCN97iXbUQ2JRpWEakusEmWjP
         64QwbnOQhCGpuzsZTkZk/MZlbgxCl6cabC/owi0Vy2TzI7N7R0sfWbc9I40+KTxTXBTJ
         qBtustN+v8EdV3g8j8fuxJ8nmo70+YOnrXEJ4sl0KTqtmaBF4156LcVBXUIqPuBsLYC1
         TJwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=R3WPXNQjIltnIqR3XXpl4esP+sRGXGVwHmUqVZpJRgA=;
        b=QNnxqGZqVq09gvgYOQcw0M0RCQWBoD35MDi44Zre0QB2mPg2f5dvlpUmlAJinLJ/ow
         PA99xM5GbXPz7C3p5P2K8+zbIX+jgCIJwIlGl8pYJWbgsyNgSv/QJzLPtTPvo52uzmRd
         UouuqlxGuDiKxQsP9TN037GwA/3qg6+t8OUA2oKSikRSyT7MGKRpvZAKxZe7bIeS3qTd
         NgDqUT5DcNTiiiWUrxHhvBYUbyN0f6O7dd5RHKh99u5Li5ZSryDEN5u4FBf7fbW2GvtZ
         N/CB0h5VIVyuw3lkqsuBPht/niwmLW8wST/2wDIyQ0Ka4QCb+tJt5JusAay87j/b1SI5
         O/zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zslz=77=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zSLz=77=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z11si108193ilq.5.2020.06.18.06.03.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Jun 2020 06:03:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zslz=77=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Thu, 18 Jun 2020 13:03:44 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-EPqVqg9RWf@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=zslz=77=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zSLz=77=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #9 from Walter Wu (walter-zh.wu@mediatek.com) ---
==================================================================
[    0.000000] BUG: KASAN: invalid-access in start_kernel+0x718/0xb88
[    0.000000] Read of size 8 at addr 74ff900015447f70 by task swapper/0
[    0.000000] Pointer tag: [74], memory tag: [ff]
[    0.000000]
[    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted
5.6.0-next-20200408-dirty #4
[    0.000000] Hardware name: linux,dummy-virt (DT)
[    0.000000] Call trace:
[    0.000000]  dump_backtrace+0x0/0x578
[    0.000000]  show_stack+0x14/0x1c
[    0.000000]  dump_stack+0x188/0x260
[    0.000000]  print_address_description+0x8c/0x398
[    0.000000]  __kasan_report+0x14c/0x1dc
[    0.000000]  kasan_report+0x3c/0x58
[    0.000000]  kasan_handler+0x88/0x22c
[    0.000000]  early_brk64+0x1c/0x38
[    0.000000]  do_debug_exception+0x4c4/0x814
[    0.000000]  el1_sync_handler+0x40/0x244
[    0.000000]  el1_sync+0x7c/0x100
[    0.000000]  start_kernel+0x718/0xb88
[    0.000000]
---
It looks like that the KASAN report is triggered by start_kernel(), as I 
remember that process 0 execute start_kernel(), the process 0 should be
init_task, the tag of init_task.stack should be 0xff?


below is init_task structure.

struct task_struct init_task
#ifdef CONFIG_ARCH_TASK_STRUCT_ON_STACK
    __init_task_data
#endif
= {
...
    .stack      = init_stack,

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-EPqVqg9RWf%40https.bugzilla.kernel.org/.
