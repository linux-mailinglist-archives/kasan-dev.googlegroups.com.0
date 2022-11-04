Return-Path: <kasan-dev+bncBAABBFFHSWNQMGQE2IIG4NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id D8DC3619F61
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 19:01:56 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id e21-20020adfa455000000b002365c221b59sf1484458wra.22
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Nov 2022 11:01:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667584916; cv=pass;
        d=google.com; s=arc-20160816;
        b=lesaB9HUTYQCBdZOTBYvHNhDtN60PecXaMFkMBa+/nk/nWxBklOVgDDmmHVA0VHCPG
         8KrTTEu13ZwrOV9LxOC3n6V30aFjlQDj1iV+7r92MYFarPEuGnh9hsWWmCNMgci96yqq
         wAHo0a5rmtY+7NpT1cUZ3/HBwCT3I4ydmBBYJi3rNZ9/ewcYDGOhDLiBWofWpISC8nDv
         yoUQOQo+RQleAMf0OkCIag59QmPn+hwGFQ27+YFhWscj+MmukECQvjBgi6tFKqAhXn4u
         dSR6/5kc3MLBWmz8gbF+18oVcRc7AwVqPLuKid8UKznxQeCXtQkza99kF5JLqaXlz4wn
         q0wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=zwmvM2HieIrQ4Eq//lolU4GUl07V9ClCccjhvx4+xsY=;
        b=BgWYGWlnABSSEwtM+h+4yxyqMp6WusSckOxQVkeyzYLtIVQfXHhUai11CfOYUsbAhk
         RgrWGSyUZ4CjqzJIAsdxq35DJA4UCzSDF6t2SZXQ+C5yUm74vJDm1VAqzgQxQA3sPnms
         I9Ht+apQoEZ99hAZ9ZODO1fvzGt3HXV8iLBCe3UgxUEeHhse8RqAXAq3sL2zrW2YPzqs
         vbU4TNLP64eOhvQd7SYn0L8SLOoY0M5N30iMvEpSH7S/CCDm+y0mjcaY1M4yJkylXNPf
         yOwZa0vLJUY3FGADpDXh3SZtpbpOJ8YFa7oefyb6ii+Kpx52m+nVxEcXhWSBFD9MYBkV
         eXRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BnAx7wKA;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zwmvM2HieIrQ4Eq//lolU4GUl07V9ClCccjhvx4+xsY=;
        b=NFKEJM8MV3jJO8ClASZH0jFTNzKTGNdDblYpkTG0D9oztMBRrzYhL7hoORPOP2Y8JT
         7y7HQoYNZh6iQKtr4Y87XZUuMtdXVG8QqbOHyN+xOFWONdFQjG1GAT7qyYSypiACvyfl
         9D+8/CtRHkDbfh8kkUqcBYLHmdA85riWL7+k11yC6J6xeu0uvip+xnDdCUZP3ApZrwRv
         v8JkYL4c0CXZtiQfQHWX0pF1Mzp9DYS2/5AMu8BLaTBzsFkqom1VcWzupbS4e6D3r1Ai
         czGlK4Fgp5LtmiSXOGmcCDPvFkfaVtUfq5QexCjtsmllmeGgqBbsJB72c+1b/kpFrnpJ
         iQVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zwmvM2HieIrQ4Eq//lolU4GUl07V9ClCccjhvx4+xsY=;
        b=A2vJqNvdd3JL7wQNhfi4J5hJBsb00yO3BadfWVA7E40Xog5llsxS30/I3gfFBOnpNC
         xH6BpV71vHj//hksQsLfi7E87CKFXPwKc9CJBXxy52qwcOnqRBVhT0bskIGU5anDE57q
         4veVT7QDlEGKyW1UuLrxlkiLayh/xMeAb5PkNBIyie1wcv7e682c179VeRFtilcMQzG2
         gTwGItl+0HeiSdApCjVXcE61viQ2X/JpxJ1lPDkIjOy/q1nUGOu2rSgUOSZ7t7xZzK9Q
         Ztll5il4HLgv9YvSEHmczBPUqtE4C0i+h/8VR/BgA4AGrNm7odBmiIVQos3s7B7smkIF
         Xrqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2Y9Jc1waVKdhA0VjBbNiCmqZOE20jlrWYEKkmFWgG9qHx1SdfO
	+CN09AMnugAtBYJKrVaTcpQ=
X-Google-Smtp-Source: AMsMyM5/wZ6Q14nWRIxj6C6FP/J9Cr+iyOK4LjPRxaQPGCCOM+llE4DxufWH/V1TpyLO4+1rEtAFmw==
X-Received: by 2002:a1c:7512:0:b0:3cf:8896:e1c7 with SMTP id o18-20020a1c7512000000b003cf8896e1c7mr10721558wmc.187.1667584916201;
        Fri, 04 Nov 2022 11:01:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f07:b0:236:8fa4:71d1 with SMTP id
 bv7-20020a0560001f0700b002368fa471d1ls6379116wrb.1.-pod-prod-gmail; Fri, 04
 Nov 2022 11:01:55 -0700 (PDT)
X-Received: by 2002:a5d:5b18:0:b0:236:c174:e99c with SMTP id bx24-20020a5d5b18000000b00236c174e99cmr20175781wrb.10.1667584915462;
        Fri, 04 Nov 2022 11:01:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667584915; cv=none;
        d=google.com; s=arc-20160816;
        b=nxf5kSJfvVZ/Ll7jerMeOLRby/H9wgbE/oT1EuwSzf0TAUb5CJh2J52QcxLw9fHqXQ
         AQeGAZG1T9CJPPRwHh/udSp/a6kj8TtcBfinfmbIP1QFz8dfy6l8aHJEiiJqUAVVQuwj
         LdHXLF+kC3UwdNcoIB8mM3pMUtWOYLm+Ennde1C+hjl1osRdhUIF0n3F6xvitLnzGrIP
         j8gxWixY+03ez5uQ+4sllcqeM2Of18jZc8fiBmB2BwhBStCZqJDk41YKtJQj9PYZImoF
         m9N22Xo0+HcSgbqjS7DLvt66L179oGRBq7rp6bhjZ2e+GWGxWYCkXhZrUFiATe3M/aM8
         RhXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=HK/QOJG9yi3Z8qv9ApH8QKe9aPxExjm4WgMovCvquNM=;
        b=Qm32xG1KvU/nGyqjRkrrx2jzpJo9dnc0MUFnor+l5S3KNmBjAuKn5qK6kXykyivJiL
         +xA2WsU50VDLjexph1viBil6Cj+EGTZZDYGyZ8nVnuhk6hC1SNjtx2yPfjGl8bzRG+op
         ME+vIcTDhxNjcdkyP77MGAXJs6NuZ7WShxG4oxxZYVpFnI/jyJW59CxEUbts+BcL7Rzg
         O1Xhfw+Rs0KyeaUHtFs0u6oXu4j/AQqJg6sRJlROQL7+d+KRhKfiOBQLoV+bjQDAEnUV
         RRONY0fqlzmyQiginfUruLCxnFzwu1R7v/Q0YS43nvk1u5ZYsoVck7aeonR8gul5kNN/
         3ZEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BnAx7wKA;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id n23-20020a7bc5d7000000b003cf1536d24dsi6845wmk.0.2022.11.04.11.01.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Nov 2022 11:01:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 1FD0CB82C9B
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 18:01:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C1FB6C433D6
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 18:01:53 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id AA4F1C433E6; Fri,  4 Nov 2022 18:01:53 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216662] New: KASAN: detect use-after-return bugs
Date: Fri, 04 Nov 2022 18:01:53 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-216662-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BnAx7wKA;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=216662

            Bug ID: 216662
           Summary: KASAN: detect use-after-return bugs
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

User-space ASAN can detect use-after-return (UAR) bugs by using fake stack
frames, and poisoning and quarantining them on return.

KASAN does not support this yet.
Some kernel structures are frequently allocated on the stack and shared between
threads, e.g. completion. C may be also be more amenable to UARs due raw struct
copies (no RAII, no copy ctors, etc).

Implementing UAR support may be trickier in the kernel since it will need to
work in IRQ/NMI contexts. But perhaps we could do something in best-effort
manner and fallback to the real frames on the stack if fake frame allocation
fails/cannot be done in the current context. ASAN instrumentation may already
support fallback to real frames since UAR detection can be turned off at
runtime.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216662-199747%40https.bugzilla.kernel.org/.
