Return-Path: <kasan-dev+bncBC24VNFHTMIBB7PQ6P6QKGQEXPJHNZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D6742C2567
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 13:11:43 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id x17sf13495600pll.8
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 04:11:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606219902; cv=pass;
        d=google.com; s=arc-20160816;
        b=nBrM7Z0neDnpXbCbPhiKSXxVkixspMt7i4mREJ4t7X492nWdGUa6C3JgOEv9vd+n/t
         mWFTyayV3BrK1qwwGf4OyhvfwUvJEGhfZmK3mNp2KxZjxgmFVSNKk51z7f2yQdCiddr4
         B5KBNzXT/Udj+pMd1LqVAHctoiLdJvWlXAYMkjES2bUDxmdj/awBYWL43sULHFAv+hZe
         w2qSuqDhcGmzvsa6pV+dhSWzf46JWGsMJJdIxqDwcLmJpSOgPLhxTgzVFbBNPHFFvxQ0
         QH+m7155UfH662bkvBGxrZ3bHIinWusax2fVdl2fQZ/iMIWkur0WnREiOgKXFpehng7u
         q2/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=c1fcsRvD+GRaE01GnTOsCIhUIInIwxR9stPEnqYUeAI=;
        b=M75s2xalsyWBkZyrs8uX7qXC9MXXnF6hIK3mHWvpYPpVEHbC+Cm/egYDlFMWxbOvXu
         /buxojq8idDAavctl7gXqpSIIolt3mBauc6tOvVrtQUVqJu428t6Vh92tScrGGPNmPWP
         AWVZVwg3jTe4RdZhO32aMx5RJ+M3TVdBH+Vn0c+Flxjefifywv4wlHBq0Sw5wdlaWubC
         /pxqN6A+GoL1t/Gdg+1/1Te1ec9msIaFvWDTT+KlchkrNoOwxqm3FCi6iqbjzoHma3Uz
         JE2OYzfbWIo76rqKpRO1aicwisCILmyVv9sw93NXT7xyJJ7UL2bNEwQ7IxD8UmdmdT7T
         O9CA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=c1fcsRvD+GRaE01GnTOsCIhUIInIwxR9stPEnqYUeAI=;
        b=hbV3+1B6LXXayNXnOR/jnAmbsU3ADayFI/qwGrsPHtCMJoZcaKQxpJixSKRX2VsxmO
         plnv0rJ9qCM/XQfE/dkLIKCPmqzU79NqJd6Xfr28naJUuP1Cm9p1am9l4iLzPqL7epaV
         D9eY20YI5fufO/M9tilABWsnvtz3MTJTvD84OXZuYNd+kGTygqpSAgZdW7cqdlZhXALB
         uHMSUj61fPMJG+U3nhMN/vIDKDgBN39dc7szhxZK62JAv0mqC142C8OtbZxiR4nzJKps
         eJ4FWNTJ4WZmWe44IBaWUxjAI0hmbotbRdQKLwdZ6B8unHOF03WsMliCvrEFT8IG2+CC
         9z7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=c1fcsRvD+GRaE01GnTOsCIhUIInIwxR9stPEnqYUeAI=;
        b=rMcbTVek5ylLCChFJiybVSPZmw020qO9qhk6tAtvARPXV508s0GyesmTNAUCGIiKIc
         ljEk+CeCkxjqY4KefxMup2fvtL+uOjpj4iba1A08qRmNjWMTOMzLUnRRzTRPM4NNGV/0
         1mxWSO2mNtc/am0KgR5y2apzQqLUb8JS7amzV1EU3Lcj6mxxlr73OdCSuCzX1p7jN4EG
         a+iczGADSX1+fJbOxsdkC6DgSUak0IBBaAFxOTS7lSF59fBku9wByJ40S9agewP9G+v7
         rLMXc4bSbicYWS88NlxlFknvBM42yfrU8zMO0ivkjNBHSugR4w+NVAGZnM9glfm3gIpV
         zPcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53231/reFbVtc0adydECCFwIPhXcHBl1yPH7Z8U7I2dGReVf6QMr
	D9dNgofLMz4lkbpf5bnmdj4=
X-Google-Smtp-Source: ABdhPJwgdvpTlCWJz8L/UDAgn1bbtV7SXSDFouzsyjZuiQ8UZ4VN9pfCBQfkDFYY61UGuY0+SL5s5g==
X-Received: by 2002:a17:90b:1b52:: with SMTP id nv18mr4769038pjb.172.1606219901896;
        Tue, 24 Nov 2020 04:11:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:34b:: with SMTP id fh11ls1856954pjb.1.gmail; Tue, 24
 Nov 2020 04:11:41 -0800 (PST)
X-Received: by 2002:a17:90b:396:: with SMTP id ga22mr4782403pjb.194.1606219901437;
        Tue, 24 Nov 2020 04:11:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606219901; cv=none;
        d=google.com; s=arc-20160816;
        b=CZVbavd0HI2AFXvtG5D+biMNQ+pqKWvtwR+a6jMhsuP7M1fQvQM9F2+YFJQa4TrLUD
         30qbKy1mI4hJpD5romKHp5e93lPlOdVE68ZGEAH5ETLd6MkTnYu471ZkKcaYeE8SQKOZ
         FXRDaCe6LGp4tGUf6wUuteqB1rzYAEC4SvDN8FT9M1ASaNC5nCYitfdl98KE6RzRBtVO
         YX/BV1DvApgHTThts7MBtAolywaZwrYq3FXFgEQc0XxiBof9TmuuBsEIW3THqr4tk1/d
         INg5zs9gh7mfaK7exjYrIboi1U1u2XJz0E6svPErKD+68VEM19tbpcYg6k/RIBe7ZvpS
         hWrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=jTKcJs0WVqllhxnezv+oOGp/pWi6ZvxuZjI2jqhO7Fk=;
        b=j6T2T+oOMeHrU+VNCHJ8TFWxAES1M7gBUrXm8grfLUpoXveAdGmFeq2kv2iYgwXtqK
         cU8N4GZoxCb+p86V0Nk3o5sDzghlklzgRgHGUO7BbypBVKwFPGE1dRwmCAVA1T/8Uimw
         YaWNTo46PRvD1AbpYgw6iTDfjEhj6caHI2TiWVQfniuvnW7xeLsoEzyjKfTS1P0bHXmx
         Fq1+ypuBJlmRrsFy+CCgRcw5//QzO/Iep+JQseyEqWAvsBERxw84XGDax8Um5J6rfcMQ
         hh9MUkle5SsOqF9Yg1xhsowRvUzHahnxpbubEOnwESt8tBYzRGHEhQ7vQ4In38aP1Bqw
         Aijw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id gg20si233528pjb.3.2020.11.24.04.11.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Nov 2020 04:11:41 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Tue, 24 Nov 2020 12:11:40 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: high
X-Bugzilla-Who: vtolkm@googlemail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: drivers_network@kernel-bugs.osdl.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc component product
Message-ID: <bug-210293-199747-BLaIigOvCZ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210293-199747@https.bugzilla.kernel.org/>
References: <bug-210293-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210293

vtolkm@googlemail.com changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |kasan-dev@googlegroups.com
          Component|Network                     |Sanitizers
            Product|Drivers                     |Memory Management

--- Comment #3 from vtolkm@googlemail.com ---
There is also other userland being reported as leaks:


unreferenced object 0xc8127e00 (size 512):
  comm "chronyd", pid 2163, jiffies 4294911429 (age 2020.946s)
  hex dump (first 32 bytes):
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  backtrace:
    [<84fa39b4>] alloc_skb_with_frags+0x38/0x198
    [<13675628>] sock_alloc_send_pskb+0x144/0x160
    [<cd6aa92e>] sock_alloc_send_skb+0x24/0x2c
    [<5d38c9a6>] __ip6_append_data+0xb44/0xf64
    [<2d8d0578>] ip6_make_skb+0x10c/0x19c
    [<668928cf>] udpv6_sendmsg+0xa98/0xc98
    [<77b8fd3f>] sock_sendmsg+0x34/0x44
    [<d30db77c>] ____sys_sendmsg+0x23c/0x260
    [<8f2ab41e>] ___sys_sendmsg+0xa8/0xe0
    [<13e9eba2>] sys_sendmsg+0x54/0x9c
    [<fd52ea9a>] ret_fast_syscall+0x0/0x58
    [<b882c797>] 0xbee4a3d0

____

I would not know how to decipher any of printouts, only thing noticeable:

[<fd52ea9a>] ret_fast_syscall+0x0/0x58

it is showing in each leak report

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-BLaIigOvCZ%40https.bugzilla.kernel.org/.
