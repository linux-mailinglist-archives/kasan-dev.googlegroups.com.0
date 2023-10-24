Return-Path: <kasan-dev+bncBAABB6EG4GUQMGQE5OFWMFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id CC6A17D5DFE
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Oct 2023 00:21:46 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-27d0a173c7bsf4069368a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:21:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698186105; cv=pass;
        d=google.com; s=arc-20160816;
        b=pq4tHpsnvLNjqgO+97+sbsgvVTZ71KdxOHMSovLQchT3giHNFBq7xuPF0SwgBghZ3a
         ItZx8Zaa13sIU2MqNH3T2rWVOb8m3NY1l88LGWMHgDF8QCbqWC2GeAWCLcjSkzxx9h0o
         DA93qho85mWGnWpAmMmTxwl9PtKLPKL4+tfcRAmEXIc9WQERPg2atkQeIbVvdNnTvJFp
         Eq5d8sYoO9oNMZPApWfhVbNxEUCKSzo0nHmTnn0c8JK/kR1MTaRu4gbcxjughK1Urrpk
         R6lOu/BnDSduxb26Kb4nratj5+Rr8B0Akn67iV4CnqCee73hW1Zit2xlHVnO7V5NGzul
         5N7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Bbao+klE54ptNYvPXpWdn6WkBP16Ga3v8flnZD/5OSw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=ug5GCmSMmCLgZ301xvU4XlYXLpjFW8IwRsfuBVQz3CDkWKNC8CtKQ3CBrMJQkVzt+z
         YCTimXRd+uIDTpz2otI6+5LLOdMgXO0elPfla+dFfD3k4FOXWboO3S2UC8PCoC8vfrSG
         leXWrbWQUTxsdya4WppfAT21Sz9otvQX4Vq6aX2/2NXRkYBAczpFjApNgLd6WsHZjJn0
         gQy/ZZgc8qa743Fh8hBzT6HiL19dkeCGJz2aB0RshDtZf98RSePZ7mx9ktInz4C8F+TA
         7KIUwg0UIBB1zDU6WUt8/lHlYGIQcCli2e6Z3tibPB/D6VJlaNiTtWDPp5+E4yDrMRQ9
         yZYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CGjcEela;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698186105; x=1698790905; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Bbao+klE54ptNYvPXpWdn6WkBP16Ga3v8flnZD/5OSw=;
        b=MCpF5fJdJppU0/7F4X1i8Hzo88KH/8MdgTNBMoGpu1VQXBMUbVwwhcU0UVKsEznf2Y
         eQwWD4dxZZ10Wqiz9ydcew9PmLSpHsoQ2y0undA3IStvX5alqYTK0DKdKmQU6598x5hD
         i0bYIQOhS1P38nbEbnOFCKdWYiZdpTOEXKbB9KqjEDbGlrvX+pcGi0qyWgGiKU7SB36v
         2rTHGw/CiLyINKfy+S8w/nmnZblgmBEa9SNN55QWM2RNc4PCPc5k+c28iMgJbUcC8vbg
         pBZkFIxIwFX6kdgA0Eetl9qw357TncOLMFabIO0wHeZWJ0xPtqDgQPZarKwsHFAq0nPw
         vnrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698186105; x=1698790905;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bbao+klE54ptNYvPXpWdn6WkBP16Ga3v8flnZD/5OSw=;
        b=bIiG/PhtmCOwB74yBpGXelVnoehAu0TxLomHT9GNhz8ArVZekh7rw6FTwKXG+TJyL5
         mlYGB99V8cdkRYcZF/QHce+y5fEh8U36G95n8DDa7XqWrvjJddl5WOkDPM9F1+FTg7pk
         wS3wXYlZxbfCNrZ1T2zwQmkjqoAgU30VtfniDaMwXbcT3d9HcP0Snc4yHK4w+zbe42Ix
         idN/PxmvbfWQ/+JmgpgShH9KFSdNTFxrW2AQb3RkGe2qcmCmNH2o0M7lq1fvlxYSrvs8
         sXdr75t7ILLio+HcAxDQQzxBS+GXkO9M/9hevMjGwy6Brh0DIzJZcAWadd9WfLUAyTkm
         XXCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzEhzbd6XKv5sAvlvMioFMC2quWqlMl58amUzLyn721C1w0JnVs
	WPOPh9kwZO9QQMa+M/92NAE=
X-Google-Smtp-Source: AGHT+IEworfEju4dVxLhiQgKehGN9oDlPdPCUYYu2L2N+HTCH92vOzWqSfZLdNUOcn+YvzFGU/VRkA==
X-Received: by 2002:a17:90a:357:b0:27c:f315:8b14 with SMTP id 23-20020a17090a035700b0027cf3158b14mr10214105pjf.33.1698186105163;
        Tue, 24 Oct 2023 15:21:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4d83:b0:277:4d73:721c with SMTP id
 oj3-20020a17090b4d8300b002774d73721cls3218831pjb.1.-pod-prod-01-us; Tue, 24
 Oct 2023 15:21:44 -0700 (PDT)
X-Received: by 2002:a17:90a:7e87:b0:268:5575:93d9 with SMTP id j7-20020a17090a7e8700b00268557593d9mr11601508pjl.10.1698186104243;
        Tue, 24 Oct 2023 15:21:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698186104; cv=none;
        d=google.com; s=arc-20160816;
        b=Fhi3Dl5UH+kFJr2BQCVim2RlUkLlHIJoZAdN/k+5axhFqSgaSE6jktGDZAdmDGu/0i
         aef6g0EK/5ba0jz98dXy5pjLDixAUDZTDJRH1jo41yBDgE99RuXMmz08MhhfiYquYTsD
         C2RmPZ8i0b+/yRrUEybAxm8P1NqmUuddM+o2T3ojKNFgL8bCwVbPX/D6TQDoKyIXz0Su
         maTcSMpDRmtWSKUVlgPjuaPjpaRC5vw5IFGre//wWxHz9H+UYbUY3yuaoYy0Yv/K0NSj
         YGN5eCBBlCkUMJXVaMKB/2blN/HfKSRu3mvnk4L3dDwgxTyoaOCMFFN7mOtB2n5GtaWG
         nVXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=mKBoOu3Cc0IKotjjU4GzF5VrFkLK6t+d2rypQcKR3K0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=f6XLOvBRM8Tmbkn04AwRb9R/zthaLsE1p2szqFuBBh1VTUq35IjqwR+TnSjRHtR7GN
         ma6ObjyK0L5Sq3TATLir7xs1l+r/yU7bwR+Jld5YxgKovytIp4o0TlwrkNYJadl4Qdpu
         KWmj4WcZZNGv8gLmYmyt2x/26FeSWxPQtPiqWgybYFhmxanO3jXdUItnVss1BEGKyIDg
         4uYHRnyL7X9/J06AeSm7BygximTuZuMpOe2VNRrWiCFHXqGlEXxjAqY4nTdXZr50c1Fx
         C/R3s0pwdXXUAX406DjaW0hchIIKsuGBORTA33sGSq2YusLRyOaFQpdMHECsK/xwVGij
         s6sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CGjcEela;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id gl21-20020a17090b121500b0027ddcc6164esi97027pjb.0.2023.10.24.15.21.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Oct 2023 15:21:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 831E261BE7
	for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 22:21:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 1B2D8C433C8
	for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 22:21:42 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 02368C53BC6; Tue, 24 Oct 2023 22:21:42 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218043] New: KASAN (sw-tags): Clang incorrectly calculates
 shadow memory address
Date: Tue, 24 Oct 2023 22:21:41 +0000
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
Message-ID: <bug-218043-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CGjcEela;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218043

            Bug ID: 218043
           Summary: KASAN (sw-tags): Clang incorrectly calculates shadow
                    memory address
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

Software Tag-Based KASAN calculates the shadow memory address based on the
following formula:

shadow_addr = (addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET,

where the bit shift operates on an unsigned value.

With CONFIG_KASAN_SW_TAGS + CONFIG_KASAN_INLINE, Clang generates the following
code to load a value from the shadow memory:

ffff8000800143f0 <__hwasan_check_x0_67043376>:
ffff8000800143f0:       9344dc10        sbfx    x16, x0, #4, #52
ffff8000800143f4:       38706930        ldrb    w16, [x9, x16]

Here, x0 is addr, x16 is supposed to be (addr >> KASAN_SHADOW_SCALE_SHIFT), and
x9 is KASAN_SHADOW_OFFSET.

However, sbfx (Signed Bit Field Extract) sign extends the value. As a result,
the shadow address is calculated incorrectly:

x0:  42fffb80aaaaaaaa
x9:  efff800000000000
x16: ffffffb80aaaaaaa

x9 + x16 = 0xefff800000000000 + 0xffffffb80aaaaaaa = 0xefff7fb80aaaaaaa
(0x1efff7fb80aaaaaaa fit to 64 bits)

Instead, Clang should not sign extend the value when calculating x16:

x0:  42fffb80aaaaaaaa
x9:  efff800000000000
x16: 0fffffb80aaaaaaa

x9 + x16 = 0xefff800000000000 + 0x0fffffb80aaaaaaa = 0xffff7fb80aaaaaaa

So far this has gone unnoticed, as only the top byte of the shadow address is
miscalculated and Software Tag-Based KASAN requires TBI (Top Byte Ignore) to be
enabled.

This issue doesn't affect other mode/compiler combinations.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218043-199747%40https.bugzilla.kernel.org/.
