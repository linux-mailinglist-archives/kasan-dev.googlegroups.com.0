Return-Path: <kasan-dev+bncBAABBYE6WTAAMGQEEQ2KREY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 30353A9DC50
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Apr 2025 18:52:51 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-b115fb801bcsf3898094a12.3
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Apr 2025 09:52:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745686369; cv=pass;
        d=google.com; s=arc-20240605;
        b=IAAQemdbFm/lJ6FSWE4trqL8AnL178sy/7XtzN66flDI8uns1jk4PwgYlX+UqsGAjF
         00HYX+KaDdnZfOS58CCxsJV45FrQQyKQdkGN9JDhhrYAofWfmRfokGfapPggo4NToLtV
         EceghHaKc1FCoiZ4cCqWd2kYudGCUFPVNPUqU4dXxl7JgucKyU3Y4slnCn07pHjnNfxU
         LUo+71h7GvjzW1zVV2w/TyamU3xlrtT99RQh5B55ljzzdcLpsrJXvXg0ub7A6iz0h1jW
         bs3SwruQfRvaJmAoL856T5aZHzw+ChxUn4KbT8crDfggovLQiG7EDie6S7sIyI7DqQq9
         Lh1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=yvI1FW1SuK3YKuQmXmLTYvskn9IY4tLupU5i2QnEn3o=;
        fh=i6p9+X0WQj/7HbejYmjihx3TBupqJowXrpE74KZ4GT4=;
        b=XvMjxWPslW1QHpmJVyF+TiUEBbfddl+wq72bwkqQLDFzNU4ZbQsXCuDkwtYrbf7TV0
         1QUP/VQGHLCJWMFktAUX5ZYF44Ta8JakFhe+YHw8VojlDKm/f7UxBpl9jw9HiqCTu78U
         ePu4U11FxyreYGFw4L+R7O6Vjgh5sedFZqnIJt7gnteHfw8Qeri8zQgDq1dx2vWB9AaL
         5f9SyTNCAjyf/E+hINFMmb4ERTye/dLBWYbC+6G2jA2qaji2K1NSy0LTn/HWlmvUgYmj
         V0EnuZO0k3oF931LTv0sBz7jXcdbenAMxxrYamykMxmR69/Td49zIKN/BJdb8ILrBrWG
         DQbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=szpXsVJl;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745686369; x=1746291169; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=yvI1FW1SuK3YKuQmXmLTYvskn9IY4tLupU5i2QnEn3o=;
        b=mPoi+isO8oi8HVSvQ+d8FJTHn+VCYlpT/yyr5/iDHeKZSM4h2PlAntxR9xh/wJtfI3
         J2UOTnn7kbCarib+y9ndOBo8RaCOSJnz/wRM91lHsHcUpfEIpgtUcTPgbqsSX5WOYwio
         DhtNR229sFQD/1gFI8TDt9Q6RVvp6I9G2Px1jcFJH4N+3dLlW7X8sLaQJJHPEkz3dalp
         KC++eJUCZKkbBQ7yLWGTWUOh4tI3ILJFMHWTx8t6HfRsZKclQF9uwtoxnOzNexhTHxtf
         Jj4hbY8t55FNx8nzKtTVLo5ft5/UxEilx3onSaB6wEqAW70Av2C6zjhe0bLfsjB8F0Oq
         vs8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745686369; x=1746291169;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yvI1FW1SuK3YKuQmXmLTYvskn9IY4tLupU5i2QnEn3o=;
        b=YcrpOXnR36lxYdMZUEAl8LmxbAsB6Cs7a5yZJBdLj6m+7F5hDBGphh8Rv4AXX4e0qn
         3xxe7eaxx2ZCpBtnTviAVu+zbUAZPu8Q1vQJvU5O25YNKJZXvFB2dHn9u5GNnKht0xXp
         GASTFsE2MyN0ts+y44eElHK5NJT6bLRSPTqY2P5s15GitjSUNhDBK7o933FJOiLTniY2
         8YIPgBwpT3T0Bw8GxkwWCxXDqXxv5KtQNvZPPoASARE5treY1B9cU1QTLq/5Sym6G8fT
         iM/Wz29+lbX9/XDGqU5ew8NkVHU/aMqihz9wbX9tbatr9HpUtXLojeObkL7MN7+rJPmw
         2CMw==
X-Forwarded-Encrypted: i=2; AJvYcCUG13aT+g7bh4zUBFwtmJlh6IwB8sXhez2DONT0ZDbaetA5FfgfZf6fRp4rf8ZhCs2PSCwkFQ==@lfdr.de
X-Gm-Message-State: AOJu0YyPwgT/bcmkubCB8d4ME+kXBKR5Zw4gW+1e6Jp3V2USTKyUVP0z
	L3GQmzDtM1RdQyoECZmdwcO1lmf+xdGyZok6QevFQwZhM+O+fj7V
X-Google-Smtp-Source: AGHT+IGDH98N9MCvgadyqyA1a3XJfppBu/ARcCUehWtt9GMZbCJUYci60wJp6P/6h/TqWjO/EFoSUg==
X-Received: by 2002:a05:6a20:1581:b0:1f5:67c2:e3eb with SMTP id adf61e73a8af0-2045b9f26b8mr8368236637.41.1745686368863;
        Sat, 26 Apr 2025 09:52:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEqmh+uPnh1aLG6DjqTlRX03N9UvydXZ8VNR+2N6+TZpQ==
Received: by 2002:a05:6a00:399e:b0:730:8472:3054 with SMTP id
 d2e1a72fcca58-73e21be413als3873552b3a.1.-pod-prod-03-us; Sat, 26 Apr 2025
 09:52:48 -0700 (PDT)
X-Received: by 2002:a05:6a00:4fd0:b0:736:a8db:93b8 with SMTP id d2e1a72fcca58-73fd69f8e08mr9643529b3a.3.1745686367772;
        Sat, 26 Apr 2025 09:52:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745686367; cv=none;
        d=google.com; s=arc-20240605;
        b=Rs//WNEUjEamlR0oZn6klb6uuRRxD6/N2hTfPevFk9FJGVBG28nI65Nkw45B3baWZZ
         I/WBhh9B03DfXQHGPVJRJKuNsoScE9vHNzJQPkSMJlb7PVEyYePPrVaWZbu1fqe5vDnN
         cms0iklrbOBTpVsIJ+XEfuQiAVEr5FQlwTDi7bYTw72HpCoSkQPbkpRyG4bBYIQ24iLO
         6X5Jcu+bTfqCQP3iHvMMUb0DwO1fV/7jZ+56ZG1vZa+nO5GX9wBetxNCPuyEGJOAgHG/
         s4neAEb+hXilZVS+b3LB8A5migDJxGwyeDmBBz4v5Pt9ITpU8k6hfYuf4s97m5IDA0P8
         0qIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=2kqNWMbnx5TxJnGifW0ceAlyWNDSjAGodHIxbj0uZD0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Fn8/iXYgeI3JP403aQzG8BlwK3i7DTDGZs+fPomMDkLB2T65MXaD8FYf9CfRuZAx7t
         BV721YWftm+lcTzi9tAsFDM7bCFE2YAMgfdKsFdz5tquLsqyf6jNwDDeDDZl5NIoW+Yl
         2X32E9bcLHOgphX0PDSYbVrE3OT3ezmC9GBdP3qfjk9Nadve2u0NYxgZD+1qB9tjD8CF
         DXHtD4LUIzwYVLm1oD8A3dJdtBYNm4tEqcPQbhaGzlKFsAh0YUvkKofCMaeT3xxYh09J
         CNuDoVQM6NNx0RzJnVH6FP78E+M14uaHF6ncH845QJplLqYpTeptFGGu991kyud9E4eN
         oVoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=szpXsVJl;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-73e2536466csi264903b3a.4.2025.04.26.09.52.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Apr 2025 09:52:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 86CD049E55
	for <kasan-dev@googlegroups.com>; Sat, 26 Apr 2025 16:52:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 35BBFC4CEEB
	for <kasan-dev@googlegroups.com>; Sat, 26 Apr 2025 16:52:47 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 239B4C4160E; Sat, 26 Apr 2025 16:52:47 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 219800] KASAN (hw-tags): set KASAN_TAG_WIDTH to 4
Date: Sat, 26 Apr 2025 16:52:46 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: trintaeoitogc@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-219800-199747-s4DePUarTz@https.bugzilla.kernel.org/>
In-Reply-To: <bug-219800-199747@https.bugzilla.kernel.org/>
References: <bug-219800-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=szpXsVJl;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=219800

--- Comment #3 from Guilherme (trintaeoitogc@gmail.com) ---
I runed the `./tools/testing/kunit/kunit.py run --arch=arm64     --make_options
LLVM=1     --kconfig_add "CONFIG_ARM64_MTE=y"     --kconfig_add
"CONFIG_KASAN=y"     --kconfig_add "CONFIG_KASAN_HW_TAGS=y"    
--qemu_args="-machine virt,mte=on -cpu max"` command for test my change. 
And I can see that the test_clobber_zone test is fail. This test seems for me
that is a test for slab_errors value change through the registers value changes
(I can be wrong)... 

If I make a restore on my change, this test failued yet. So , it seems for me
that this test failued is not because my change.. 

The test failued is on 
list/tests/slub_kunit.c : test_clobber_zone()

---- 

well, I maked any tests for check if KASAN_TAG_WIDTH is changed with
preprocessor command, and this work for me. 


I will send a patch

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-219800-199747-s4DePUarTz%40https.bugzilla.kernel.org/.
