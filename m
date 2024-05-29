Return-Path: <kasan-dev+bncBAABBWXA32ZAMGQE6VPWMJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 116C38D4183
	for <lists+kasan-dev@lfdr.de>; Thu, 30 May 2024 00:46:52 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1f44b42fb5fsf3463665ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 15:46:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717022810; cv=pass;
        d=google.com; s=arc-20160816;
        b=syN9VjbvmnX9A/4eplpLOJGDTAdo9XKOS5jsKAi923GHPeSbPAF+HcQFzfg6XWS2B4
         YANfA5rbTBpxy9cZzufouCNPviu196QcApdB5+wHNTMzbN6amjy5IDH8oWM1L8iLrqGg
         AE5JxtEzmjjjceAKaMF8pR3I2YnYU3WuUpBPZt+QtAmRMCpcrfznZ5YaX8ZSTfSEbv2E
         lI6ZnggHuO4h4Gu/Xkc4V3wBxd3C962P4CXrwZICO+k0xc0NvTbb0CQHhOhu0v8qTInv
         mkaK0n4+N4/UsAWSky9HApjzsBArzjogB8NosZustd7JepTnnzc4IpOUP2ukSJQFCs6h
         IHuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=h5+OwgTCrdzMcnuY77iFGFWAHVJOA5NcQx489zQi/MU=;
        fh=xwzsB6aItKSNBFgLGRZ7wBq+gr2T4X5yxAdZYmOBDeI=;
        b=FiGRPgajkjfaFoWLupLXhBywYaTEiUmR/uGn8qQ5EHfXkKrqPwg8BgAelGfhF3ZgsI
         pvbw1x0NJX+3bZDheJHtwCE3J9rzpFsZCWUSU/RHXJgmAzdM33CJH4VkX9t5HeEnjMui
         P0xCLezem5eMb96jG+s4AlLLcKPWc9AFv+a0ZFpI4Zz0oqjswLbbpyIr/BTdyuHtl6Dn
         u4XJHiJuT5FKlTKexijT58rgLQIi0YERbBcB6a7iHYWF/XIVeA+/HrPWxnu0AvXYdAec
         LwNAgL4Q0vj0NdDxzY2G9oWNYppqnLoTdnLzsnlVmsRsvkgf7mPgtgqtNdAFaEfK0nQE
         5IFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IESq+zUB;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717022810; x=1717627610; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=h5+OwgTCrdzMcnuY77iFGFWAHVJOA5NcQx489zQi/MU=;
        b=gYmD/3QQHR8a3Xqs8bkhl+5+/QkhamHx6ZXE6Cuud8ml3IIwXH1bUalmAXePyFsf5g
         lMARmLEj2mKzaV9OE/43KhBt5eroNaRU59LgZPnWSxeEGNdHfVbklnCrtCWepgrqUkKy
         yxreU1IIuMVqUQsooEQ9t0b0kZyx/59+maCSdvtsbbbMYxPu0nWwiDVrQFBfSQsHlKub
         0lD9JMX16axj4WMgSXIaIXmSMjTsQQ1bUVeBeu5g/aLFwyr9/TAq4hXeHtJr3UgSIrnu
         jO0+7Il/Z4yO8uFQAizoOZic05h/740EfaNYBfwZF6/2MzUTlG4iacsgUh+12Da3fgWJ
         QWRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717022810; x=1717627610;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h5+OwgTCrdzMcnuY77iFGFWAHVJOA5NcQx489zQi/MU=;
        b=Zcgoy8dpEFxFwPYFodhICpDtYkJGdpAvsRyCc1LloiwPI4fOf7sBO6hABlfnm8P80a
         vXSez2UJeFflWkw5kSHMPSiC+d1L0xYNkkjnEZcYNU8PvWUi4l49fFGKwOOzL2HoNg9T
         0appPRN8KgxtJAyuxWmFkI8cpjLEP3kp8/0/VocrZ4DzwdVyR42Uf6BF+pXpYS0NnGKC
         FOW0UkL+ggZzETIu3dhaSBDJRRpWiYkEPQ6dmluq3oGfbH4kaxtbm8q6MBCJ3TEjgNJN
         cKVsHEpFsH+edhRJxiwHnhFOStoOKGH8JWcdkBrYBORopHv9wwCSkETa88n9vg8n2UPe
         zXoQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXgZDNEX/AJKTCcjHU7ua2WK58iHlDwATZ/iFuwtMbsEE0dLQ8JMLd6x/NXMCopW8HBwkEhWwhhlXhFsKy11m80ikrFO5g3Q==
X-Gm-Message-State: AOJu0YxSMt3Q/ZtfRr+QV5QpdJ8WsnjQKvWlpsDFq7lf/NGwVK1VhbwM
	pOZmOZelSbTy9XBumZrBYyuOjaU1a7IvKlQowElWkj8It1fFNdZT
X-Google-Smtp-Source: AGHT+IE/ZX7YU1STiVLITv1a1hdjWn+IZ3MCu0wGXnwWr9fQwsxYYP0Z2s9tlFB/PZNSOoIsZAsoxg==
X-Received: by 2002:a17:902:ec87:b0:1f4:466f:8ca4 with SMTP id d9443c01a7336-1f619209d85mr4368975ad.0.1717022810233;
        Wed, 29 May 2024 15:46:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dac8:b0:1f3:555:b718 with SMTP id
 d9443c01a7336-1f616f8b7ecls1766525ad.0.-pod-prod-02-us; Wed, 29 May 2024
 15:46:49 -0700 (PDT)
X-Received: by 2002:a05:6a21:338e:b0:1b2:3998:404 with SMTP id adf61e73a8af0-1b26451e2ddmr504840637.4.1717022809175;
        Wed, 29 May 2024 15:46:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717022809; cv=none;
        d=google.com; s=arc-20160816;
        b=ZK4OyCW9hzJga714UFJhmZXx0BajeHJJPxHSCUQisg4tER0acxXYki2h6jUZ666HO+
         C92ncXPA/YJi8K+d0jYWQoUjni/hDs+/ZnnJ7MmOmoK1dgBX88bmab+lvxH+4f2A4jms
         hGBIVA5ubLy+aD1qjm3r8n68Fs9VMaQolWOBEGMh7vTiiG8l9w8zbQVJrumsQL3u1mCI
         QorZUvKLtGfAOJ4j85XyAW8CUMd7pZLk41Qv8o7MoUsofg4PxWQ1EyX/lYdp2yHQiRfr
         NBjzUTOJp+0hccWZrgb9d9jfY2c5QdqpUWa+fTa3yAVE6VHd92uW53B7XGo8rWKAIVTd
         NiJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Royj4OLZzy1o7KYDum6Ix2AGBbQAGvLnRYe/SlxZ99c=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=HQPOo4HdO4+s3ngPqABFB0IxlHzD3gqYOd44e82uUFJYg1kMxTEAP/bDOCxTwUNdLf
         xDeD9TsXMwzoaC9d6KZkkas1xJFz1hpvwPtIzsj2EAUNWol6VZyWPW4sB42NXgCvWcAg
         5Wpgtm12yKUg/SuCUu/V4IJy+cfhiFnYNNPFCELHa0MJ9nHpzc6f+fB13RsxNtnqMcMQ
         nJFbrTeZEE931yKrLMntXi1P1toQ0EzvPncRYtew1KzYoXk/cLWLSwo8ocxWsP9dG9AM
         pqO4YUfJLJhXbvn/FOPlal2A6ddj5jC+gXZDrHoJVdJqHRriMLz3hQ4wJKEGcsVKzxEF
         JJKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IESq+zUB;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c030fc9973si369114a91.1.2024.05.29.15.46.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 May 2024 15:46:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 6BB9A61FFB
	for <kasan-dev@googlegroups.com>; Wed, 29 May 2024 22:46:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 19A66C4AF09
	for <kasan-dev@googlegroups.com>; Wed, 29 May 2024 22:46:48 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 0C371C53BB7; Wed, 29 May 2024 22:46:48 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218887] RISCV kernel build fails with CONFIG_KASAN_INLINE=y
Date: Wed, 29 May 2024 22:46:47 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
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
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-218887-199747-yIwbqcYdH0@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218887-199747@https.bugzilla.kernel.org/>
References: <bug-218887-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IESq+zUB;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218887

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@gmail.com

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Awesome, thank you for posting an update!

If everything is working as expected with the patch applied, please consider
closing the issue.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218887-199747-yIwbqcYdH0%40https.bugzilla.kernel.org/.
