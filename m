Return-Path: <kasan-dev+bncBAABBON3Y63QMGQEZ2QNADI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 48317983919
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 23:29:31 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-39f4e119c57sf48319285ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 14:29:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727126969; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vl8JnGEnXRBAM/wZNtnCoFHbfcq5kBLj97sLjbRa7PZZdslOIsaXMJt0NCMrJ0amZs
         oSjmnDNpranj2nUcoUQ8pM8JcOwf8s1xMTZO/AZ7rrBf1Q1f7e42upUK7QkLANvgsKVM
         PoKp3ABZ1mG7FTY4ujKzQe4PREi85JX0oE38d0g7f8VBsnTnDPid16Z+u7C9m+R9qZ21
         fhk1PTz6fOalA+uv3CcfN5gxbqeAeBjS1DQ5N7qgUQLiN5PjG97ILxWLd343vcKrAWCP
         99KF0HAeyLz6cVt6yLNrgDf8jo/CnID/W9UtH3D8pxvOLmMWKyF05tupFno8Bu98VTGR
         413Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=Qu26ObZ5sfw6wlBMykicFCKgcbBoGCL+AIJqvSPk79Q=;
        fh=AScRQm+JcZuRlX0gikRBORLzEUc0IhDpYXNbhkOSjcI=;
        b=PyxIfnL8F8jFmXgzBpB3Ad0aXOSKTCWGhpLA9m0FYl/iPNyV5UKbUPuYL0lT12Ir5Y
         ezpt6mH+YK4bLtUimvjEbNABhjPjGbpC6QTpr63uaTTsleANUX4QnWKLZ1sI4On9cFTI
         TxV05LpFjTrmduTNWSuH+/8qGNm04gy3YhCtATP4KofFeX0do28nFC7c7kerlbGEBSzr
         cfu/ol4qfp9dGxsDNa1fxHEsyCJytIYLU7iAvMZYEvVsRTvYPIHpO0x2TqqaWDxG5Ccq
         5F2YUENTn/zEvbpeV1lUd/NiP535JBwIO5+puquQSLEW6H2uB/DTbhJDNmM2y9g5hF+9
         lsIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fOAeEX16;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727126969; x=1727731769; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=Qu26ObZ5sfw6wlBMykicFCKgcbBoGCL+AIJqvSPk79Q=;
        b=oHyvjj7VDhAzrBNUzyz1E/tWTKClXMNYR5OmhVl2HRQqGRXnWseMbUzlW2jGr5TsnO
         aaRPyGHIVUL+sV2/fNDlL2746pSsMQcwGCM3PwpTJxMNi2vOapR2pjD4/jXYVWaJjj8Y
         Phm5WboeK+Uftg5KxmiQIiOb1Lvz1SMRyXpeeOF0gPJB5FryB1AnwysaageW4/j29JaS
         FQ6tr6O1YzEqM0mGtvBSZGnMnPjN7sjbkBPQ9eWxwmv6/v+jZBpzra4cwVFfuoNuvaOT
         5LP5VIpwqk7F89y31aLFCCeMqL9XMn2VbNgygC90Geb6PYPW2W5H04xVa3l3RFwiAnQM
         8/DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727126969; x=1727731769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Qu26ObZ5sfw6wlBMykicFCKgcbBoGCL+AIJqvSPk79Q=;
        b=EbKInwJrBIM8EVEO/voQ2TzcYmMKaLqT+MWeazbS/EJoRExeId/iT03zS4ooeniajW
         7qk44EVdYPNy6vMjs7TSTv79uxzbz98+o4OF3kgTpX0rPfxKGvBKV+aL0qItrPVAFM60
         Ded3sIy1e9MopifIKRry3LrFjKRm7b5WWb1FOeFxyZNlZGF2b9XE9GZsez9+8Q+AFxt5
         oMrDs/WDVj00uh0Me0gm4W2oRrhiLnx6tclZlXWNbNOC7DmPXKv5NUl+hlOIm7df4FGn
         XnVWf/vttnrIM26+Ag+p8IOiv4h2ZWZP8iOWc6sOS47fXJOdel1ltXtQVzMtyFRwzgzh
         Bw9Q==
X-Forwarded-Encrypted: i=2; AJvYcCU1e5RuqrykISfGVM91f7EIFzyaffzWw3S1zE4ps5hY2jVvRIxXl7Q6iCHhpDWkItoD9xKFrA==@lfdr.de
X-Gm-Message-State: AOJu0Yw+pVDLB0qsIzb4E8lMqwZRlsy7dE3mHB2c55ZVaHdqF3IrDkn/
	5mF8OxVu2glbLkh3RD6OzIleK8H8lLvcy6KtWfXjbui7MPBy4zG+
X-Google-Smtp-Source: AGHT+IHYp3idFXRWDs4+oPRw2mWYRnoEgsVsz4catFPSyfX11Cb3bu2GnUf29RDvB4sXNOOqXKNYFQ==
X-Received: by 2002:a05:6e02:1648:b0:39f:7a06:2a62 with SMTP id e9e14a558f8ab-3a0c8c5d451mr117213545ab.5.1727126969635;
        Mon, 23 Sep 2024 14:29:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1945:b0:375:a4ed:3509 with SMTP id
 e9e14a558f8ab-3a0bf168165ls20823995ab.2.-pod-prod-03-us; Mon, 23 Sep 2024
 14:29:29 -0700 (PDT)
X-Received: by 2002:a05:6602:6c11:b0:82c:fd13:271c with SMTP id ca18e2360f4ac-83209d04881mr1045057539f.4.1727126968816;
        Mon, 23 Sep 2024 14:29:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727126968; cv=none;
        d=google.com; s=arc-20240605;
        b=OguN+ZKerUHo8NzQu2UV+hM7C9AeHSq/kOWdnTLMeayCGD6xtLjHesbC6oXlkRgpe1
         0qjObjZe5vDEATIWftGwZPahR9ma8KwsmO72yVtzBPZN8DC4xyKKDUjmXKLin9HIvdJI
         yFCA2vIz5o0af7UEStjxCS+AMfLFHweOwOnd8E3Iyj5DGKwSH88UIxqszS5VfvezZ0bb
         E9aMvahhJCUBtBncF2H+DmhqDBlokXU6UNM40DendEnQpGAaGbaPQ3G7WXXgFp6TEpgz
         hxbNAWnQKHmLxBj79/PdDa+56yClvfPPde0S244nB9IIRjrql2AqxU+TTpKj1OWloZ0u
         rZvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Y50bs5dg9BGuI0s9UH/eqbqNST8r32C2NearEXlAir4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=EItRFS9MX7A1Dvz2bC2l7mlmuHKJW5k/xw5x6K1aYFbnY7mOnB+p96HKj10SuObxH6
         8s9UMEwTOF8p+dWSwYc8IWXfqglAIlR8WgA7Z1xLBCCwf0lQXN6TKUqq6jxhUDN8ihMf
         rcXZ7DaZCSriZinA+8cwZnSmt15QwGoUVaeJXIKckG66GIYcPLaLjldnfICSFogRGboj
         DWgwF2lmcg0DGCt2byUscW3Ev4qE/rv1NYW6vD90NV117gbWvhClUUsLzxxw+3xMhxH5
         5WMEtBu/1PTvy4DpafZdhYvWfamFqlEJQvk0MFgCaasDmIJKOr6AtOUAyeAg9tulNxrX
         YbJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fOAeEX16;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4d40f152a43si9997173.1.2024.09.23.14.29.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Sep 2024 14:29:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7E6675C44C3
	for <kasan-dev@googlegroups.com>; Mon, 23 Sep 2024 21:29:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 14142C4CECE
	for <kasan-dev@googlegroups.com>; Mon, 23 Sep 2024 21:29:28 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id EC36CC53BB8; Mon, 23 Sep 2024 21:29:27 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 198661] KASAN: add checks to DMA transfers
Date: Mon, 23 Sep 2024 21:29:27 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: arnd@arndb.de
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198661-199747-9WQ0q49m5l@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198661-199747@https.bugzilla.kernel.org/>
References: <bug-198661-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fOAeEX16;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=198661

--- Comment #5 from Arnd Bergmann (arnd@arndb.de) ---
Right, this is annoying, so it can't be done in the top level of the interface
but has to be done separately based on the implementation (direct or iommu). On
most architectures this means dma_direct_sync_single_for_{device,cpu}() and
iommu_dma_sync_single_for_{device,cpu}(), which convert the DMA address into a
physical address in different ways.

On a couple of architectures (alpha, arm, mips, parisc, powerpc, sparc and
x86), there are additional custom dma_map_ops, but most of these don't do KASAN
or (for s390 and um) don't support the dma_mapping interface.

To try things out, it's probably sufficient to ignore the custom operations.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198661-199747-9WQ0q49m5l%40https.bugzilla.kernel.org/.
