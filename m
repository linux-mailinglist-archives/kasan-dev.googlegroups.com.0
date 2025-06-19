Return-Path: <kasan-dev+bncBAABB66N2DBAMGQEM7E5E4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A915AE0997
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Jun 2025 17:04:29 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4a6ef72a544sf18396451cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Jun 2025 08:04:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750345468; cv=pass;
        d=google.com; s=arc-20240605;
        b=PSD1v4MucOzfm6Ac4nLQ0wdU57Ec4wMAz7bsnUzSXvdIQyzp3YVQ5URY2dRqdM5gan
         L6RvvZb2U4rePvrKrD5U8aByAqKO8gxPEAGs9B6AaUSpRNofbeyLyeCo2mgp4gMwNf8K
         mi7gocRRgRCOjIJFzPECdyfH3zwICMMf0iDVX5sua/opuFQ/5XD+0I0UDj+123sdN9FK
         W//Xb177RGnT4OxT/ENKiu4aW6qF9PASztijVuqG4Dhin0yaG6koxgy/wqArzOdtNrNJ
         /bLxrbatynFnDC5A9Z5Dc5wzLcfeqANk3HQEXDZ7/dU4FfyVmKRkBFANAor+9UOa1AQe
         Bf5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=iUamj2Uq9EBSrizGeLuKf8LHO1EdLV5wjkXMrxfVBn0=;
        fh=OHg5N9o4Osh1zvOsRo0LE/+Ltoad5HoHXqDcVwLa22I=;
        b=BU/O8Umx2aZ31YkgoUtF0yYjimpNttlhNwsSwaQtT13+8j1NeBEY/PqirMDWfkyphW
         K41tr9XU1rLcEB8yHn14K0+6aEQUlahfm9aWxSb/DcDxBFv9c8kBdUl/NODO2BmF4KXd
         ArWoea0hty6qlWlF+E6hthgOa/+sMKtAIxOGHeFY5FTfa2Nu3Qub5WM4eiIjZJuCPUg7
         4jre+5P7IrF+BjR87KS24DNl7Uagk8u2hkePenU/BzpelMTvWIxQ+uPuUwDDetZfqXMR
         T23RoXfaNvmM5YDix19Ad9OYAgpxQsi+gBde97viAT/KWfQM3miYO9OwyIPYmTIt3pjl
         cTDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="C4yR5B8/";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750345468; x=1750950268; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=iUamj2Uq9EBSrizGeLuKf8LHO1EdLV5wjkXMrxfVBn0=;
        b=KxvoTb1n+XVOIIb1VZw26kj8zFvTbqcuoqRU4rhqpiUFLN+QRuLdjLaBdEkxontt6F
         oKZ4K1lW9Cok/s24KeyMMPseZgyJxp5HDObf6aL+PLIRd/trY6RHtRj/Af6AXYtar10k
         Lme2WLA5P7kuSU6Cq6Kl2Azo/IQI+rJ3YHfmXSN5z/tRJ5kfCARD9zCmfxMmf8ATcz1/
         sv0xoMnx4uVmY3gY40vQFak/09MEk26XxejhETmhtCQgHUoOs2dJdw4AccYlIbMv5cNv
         ucaSaMxjq52ymT1j2C7uyovuD6J05bSr1AoZFqQXNeRLxmqY2mNbQw6J0S1BbP6USX1Z
         XV7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750345468; x=1750950268;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iUamj2Uq9EBSrizGeLuKf8LHO1EdLV5wjkXMrxfVBn0=;
        b=QX6qDFv1ktp2/U66ps9+rZhzKGa5UKqpovJV6XWhPLrmkNSuScKTVzdokmRdgENolk
         EvG8j+og+qpSmMgdAClFYD8MXMy+P+r2iaRod6XsBtNpHLif+h0rSp5zmY484oqFiuDC
         xYNdtwVwtwVvkxxCGJWGH/7/1YvQzEwklSSAWciQujf9CugsjcqYZbo+0VkyydydM9FP
         MDRuystnHaWCotMINvpFtJxz7W5jGMqhO1RTJ4ekXZ20AiTyeh66vKbgtUREg1UqTLp5
         lGhactdAulU6nEJCwI2mYVBLsXEeCc/VVKsxBB/GZ9ly8JLJGJiiXy8f8aO4X5pY11VY
         LAxQ==
X-Forwarded-Encrypted: i=2; AJvYcCWt2PMTlWHKMZGeRHD0HObRpWJqKaz4HFKqgzxtM+jnURniOrVIh0yEAPZQF1GxFq/J90lksg==@lfdr.de
X-Gm-Message-State: AOJu0YzPwctLkDrvfCThYbKbm4W++jCtYx2QQcjGNy+pAYngdFiipCtq
	LASTYLxm8lGmr1l8hXUHw/UycJYlmlUw9O6zKpjrTDQ0RAJ6r5iHND0E
X-Google-Smtp-Source: AGHT+IH9aNIDZIMzcUKG1NNXywj9ca49fhMwpWU8ujUccBUEQCYRswqGRH5ihy6Vv+jbKyqyA8NHXA==
X-Received: by 2002:a05:622a:1456:b0:4a4:2e99:3a91 with SMTP id d75a77b69052e-4a73c51f9ccmr353650241cf.11.1750345467713;
        Thu, 19 Jun 2025 08:04:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcOHuIk6CJhzgKqpWlIA1brRXBvCBElFEFLzWdV/jJ5vg==
Received: by 2002:ac8:5cc7:0:b0:4a6:f717:1df3 with SMTP id d75a77b69052e-4a76f1bb39als10420701cf.0.-pod-prod-07-us;
 Thu, 19 Jun 2025 08:04:27 -0700 (PDT)
X-Received: by 2002:ac8:5d8f:0:b0:476:95dd:520e with SMTP id d75a77b69052e-4a73c55b94amr349549861cf.16.1750345467076;
        Thu, 19 Jun 2025 08:04:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750345467; cv=none;
        d=google.com; s=arc-20240605;
        b=DxVyx/LMWXcYTKAdjsrG4AsfwqWvJD0ShWXTsvaCNyatoqmgyBfBLGa729yVIhuIUb
         AUe1VOpsoQsZ4pgIHYBg+0xrw/dzqiPrrP+Xj5U8XR6AqnkJgR4jQIiljiyzOzKyC9rU
         noKoryEZlHBhE9APZpkDcu8rfI3UgpBBcXA1KyYagyHERs9DAF9gOBZc50OqarKNlWJD
         a6O+Sx56gioW5tv4KXV4X8J77xq3oe5ZsADsgOmJCeNWEey/VA/Y1xQqggC3fCngl9s9
         g6dqh17t+Oy4xdLKwT9HnB2YyzFWISDB0l03dxglkSFB6KXncw91fr7o+96ATlgmuYO9
         vHbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=pBkiWFTgsAoVzyoWKuaCpN9z3MWxpncjiSrbLA9QUH0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=kaAdnPeg4esmCVJF8cnShjREWK8346DnheK9sfts7Glb0QwLdToN9UzGnHQWByFkj9
         6RBqsAxJ1zKreRlwfsWZLlxZWqmtZzsVU6U87qSuQAA20cVRWqjhhDFshrCI6DO1OWqv
         2GcnHGOXdiBy9g0W3TmPf+J6Rxvi0aXQcYl0262pwEWtPsAL1PkdgiygD6LvlWo9eSKt
         n/0TTwA1ZojrjARNoUYqqVADyOfK9FdhUzTZkTLX+zepDw/siTkpa2qztvPSEEVTGcwx
         a8x5BGsDw51U1S353WwAiCROFCg0WvFBGAhYJQCAR4/n2HQg7NM1nybZTFxhd4F/SuAx
         noCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="C4yR5B8/";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4a7785b291csi8711cf.5.2025.06.19.08.04.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Jun 2025 08:04:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id BBDC6A54638
	for <kasan-dev@googlegroups.com>; Thu, 19 Jun 2025 15:04:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 67C69C4CEF0
	for <kasan-dev@googlegroups.com>; Thu, 19 Jun 2025 15:04:26 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 596C9C53BBF; Thu, 19 Jun 2025 15:04:26 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 219800] KASAN (hw-tags): set KASAN_TAG_WIDTH to 4
Date: Thu, 19 Jun 2025 15:04:26 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: snovitoll@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-219800-199747-yMppwyXx7Z@https.bugzilla.kernel.org/>
In-Reply-To: <bug-219800-199747@https.bugzilla.kernel.org/>
References: <bug-219800-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="C4yR5B8/";       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

Sabyrzhan Tasbolatov (snovitoll@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |snovitoll@gmail.com

--- Comment #6 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
The patch has been applied in v6.16-rc2.
https://github.com/torvalds/linux/commit/69eadd6a05409ca3725cabf8d60ccf6c8f87e193

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-219800-199747-yMppwyXx7Z%40https.bugzilla.kernel.org/.
