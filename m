Return-Path: <kasan-dev+bncBAABBCES7CWAMGQE3DPRSFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BD3082929C
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 04:03:43 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4299130ad10sf214051cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 19:03:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704855817; cv=pass;
        d=google.com; s=arc-20160816;
        b=qVjx3Vs4Wiob2pv5RZefyGkTBN6xbEFChSDMGTw9fxzwpFFxoJGs+jkpyT8MnKsMMr
         6Xi9vVbtsqUrumXwYzDaGMt7TXkjDQoS4cXfyTnZBw7lXKOwQYXmlCx7UCC6aPxEGg0H
         JSKRDEDEeKhx5iMmetlmyMHKIrQwJsGlfzkW1Z72tFzxPNl64/d6aSdtvr9bMq+suNQN
         GsD2BXUi0RfxPjxH62+VJ8ZQcflupt8DDnxN01ehs8D2S4FYlkj0GsoZ+gjzpnqNGPW0
         h4u7iVkpVONx8OKC6vqy9pWMeWjThFS59NfSMEo/r5nTT6LWjV3v69gq+DgoFERw668r
         CYKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=dCm4qAxZnq/R6bkZIfZV+ezyuQFDkx2cEXbcefG3VdE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Roq8QxHH27VfUXwwRgBIrImPOJchF7GDWpruO4o+uD9yEOazggTzSTKrVaWo9TAkWY
         8EQAUQXKPkpj4WYibDRYGEJAGBgDtkNDwFTii4xWr5nT8SADrd0+Bh+jpdvuhHCA9jiE
         igZ2ausacuzGcCcMQozHSLoKT8MoiUyA2leTYeTFbX+ZE5Ia19FtCySGS/ZXps39CsS0
         dTR5+lH3yjXkjvNyonk4QSFGsO82e1o2g7iJNh1B1QHZUXOuvCNDJefM+PCuwOvzaZhT
         3ZG39phPPdbfymuP4/UrQoBQoPequ271eA2gQBjBd9KUSyQhK22LgjjQDgljydeSDqAw
         2rrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PMwS6ErE;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704855817; x=1705460617; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dCm4qAxZnq/R6bkZIfZV+ezyuQFDkx2cEXbcefG3VdE=;
        b=wTtvNhz1J0CrLxOloEjoyLvLzHuZ9Q96hHtp763p5yuYf8qVi08+WHsCz5yNBdo9Ij
         dWYr2H8gDbpgE0XxE3DxnVkTYLPlww1QqxaSFWMyr6Hl3/Csggz/60xdMN4NSwHRHaHS
         UIkGcDk5OGsdi59AY6SrbTIIjpJS309YLa6P1CSIgl7LB6j7fSNvsxZQi/ia7fppNDxb
         J6Vz/+OmK+lXa6MGBi9Um7Ohd4lJz+IgCJqLCbAuaiA1meJ3+b47Sndx1t3jEdNF56YG
         Dqvx3K6db+5feK/Hg1Vsyh0SgXe1Kt5dhu5qtPZTSb/9vxPzfHBMKHtZgkI0JzX7kl0o
         P1Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704855817; x=1705460617;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dCm4qAxZnq/R6bkZIfZV+ezyuQFDkx2cEXbcefG3VdE=;
        b=gfR1ds++LPUCQ368ymVAClfFrIsgTPEY0ySexqrFajJCdPF0o1j0m7foqRg8W9im/d
         Kkvpc7wj15fxsxZvGVF6cFvsLBdr9J+L4BBGhZbW8rkJAyCh4YKXg+fn70I4ZQKyvED8
         QrMbRkaT3nKlUpV/fZDPf220BYwfDAEOjCMKj/FTh3Rbvu6EUVG8MFqMrPyVPbqc33Tn
         4aBqWvBnm1mqW5rb3RuffNbHYE59HykMP3uLgPlx3tQVPPTLC/HW3u0DyxQkxhchcGXq
         wUW9oAz2wEsnpk4UgS0ui7YK8n6Kly75VMCHVTA+Dx8Ydq9AFNJL4linwE2cDLnU3krR
         ufBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwLTV9rK+G2CG23nv/RiqbP8UA2zM6PA6Y6Wq7/nHEespEczKfT
	0CE+xzT3w1QFBtrtftmfHTU=
X-Google-Smtp-Source: AGHT+IGSWTyjSmFH58Qhqs/WqRjiTgYPpM6KNqtM5omE47TI07JcZZ2WzBYH4x3Z7tTLjwmHPYCn0Q==
X-Received: by 2002:a05:622a:1494:b0:429:9d3d:1766 with SMTP id t20-20020a05622a149400b004299d3d1766mr212380qtx.28.1704855817072;
        Tue, 09 Jan 2024 19:03:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5007:b0:680:c838:efbf with SMTP id
 jo7-20020a056214500700b00680c838efbfls248943qvb.0.-pod-prod-06-us; Tue, 09
 Jan 2024 19:03:36 -0800 (PST)
X-Received: by 2002:a05:6102:390a:b0:467:ed7d:7644 with SMTP id e10-20020a056102390a00b00467ed7d7644mr274097vsu.20.1704855816319;
        Tue, 09 Jan 2024 19:03:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704855816; cv=none;
        d=google.com; s=arc-20160816;
        b=wuLWYmjVS1r57A/01Y9f9rholc2Qz8HR/4HDBChWS/8JlSVz31AFwavpAK6fee/X03
         3jwZnOjSutllMhlHUX8aZZguPsCR+klp27phtlRfKP1x2BkZhGkOYzxyecISqex7n9SP
         PRa4X3hrQS0wi2oscG6fQOr6QzJIwzwJG+5FEl6axtxD+oxnk0CDuVlAC3IOqWgQTIjV
         AvO1WAczDi7u8gWdkBFQrWJ7pcSIwuCr+2sivbYHEJV1gKcCpDPIBf9J3aiuZL4YwPeA
         mlzVhyC1NPcghoCAG7lnF1Rz0jJ7tFYuVFBLs7TH227NJgUFWMMA2BaRTEY2xdyzWhIs
         Yo4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=qs46L82sGOeRgY4edHzhvVD2RJVK6nBIZVaJEGszcDw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=fyyAotJAqL+Hp182wuwMyj+1zZWeWnJhlhY+kFREHXzWJd/AIKcd/wV4QHLapy8KVI
         UsFthO+ci2A3Bm1HBw+w+pMTjl0Fq/BvtPpfl0bJDp1ArP6e4er4xbsp3sR/cPokFCkS
         XzKsMtl7kUZENKEpFp4OWsI/jUEulkrAn+OALzH4m/+OnvqWblSjuc46hYErBHl+f6/I
         WL4GwY1SwmogoHHYpSidpgGhX74abGU6zAaGytBYB9wYVBD3oetrNclkVYK7v+hx3fL8
         4/HvLWQDTS77bay+kkZEjzmW10gDKT1+nLJ49BYEN/u2iCMvfrm5dp6x6bKPfgBhZC8e
         Fq0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PMwS6ErE;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id g13-20020a056102158d00b00467d4dbee05si588675vsv.0.2024.01.09.19.03.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Jan 2024 19:03:36 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id B3D5CCE0E69
	for <kasan-dev@googlegroups.com>; Wed, 10 Jan 2024 03:03:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id EED42C433F1
	for <kasan-dev@googlegroups.com>; Wed, 10 Jan 2024 03:03:32 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id D48B7C53BCD; Wed, 10 Jan 2024 03:03:32 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218358] KASAN (hw-tags): respect page_alloc sampling for large
 kmalloc
Date: Wed, 10 Jan 2024 03:03:32 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218358-199747-fA7MDSstLU@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218358-199747@https.bugzilla.kernel.org/>
References: <bug-218358-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PMwS6ErE;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218358

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
This becomes obsolete if https://bugzilla.kernel.org/show_bug.cgi?id=218322 is
implemented.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218358-199747-fA7MDSstLU%40https.bugzilla.kernel.org/.
