Return-Path: <kasan-dev+bncBAABBM6GX63QMGQEKL4632I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 13A8E97E0B8
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 11:28:21 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6c3580b7cf5sf51597806d6.3
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 02:28:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726997300; cv=pass;
        d=google.com; s=arc-20240605;
        b=IaSujOMM2NsKxOB54Howqj/acvFwrPatpuW1sjug5+H8AKP8Fo78pd4pFp9NXJDa2Y
         JeRTrXVSv+BnMsys7kzmYG+YpUDB3CK1CsJq2pKKUYqQ3M9f0b41fsFeIPQ3UJ6XA40z
         mioH+w5zYZyiIjzDuP7BsOtJsPc9wRpA7XMcFTwgeM2JXnCfRtC8ElA+ORzICOQEEUjc
         mp54XJbj+bJOQ25rnbXE+MKU6ZOuu6jUat3psFemMi02a6Ldwk47qKCfZL35GVd/hbc/
         W/c5479aUCZBIKesDyQt3Sm8JBBTHU+y0jiNAH+u3NNNfBgWdbkSdR4FJi7TejHoyLsN
         TfwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=uz2x5haxWSVv3ocCFmlUhEKfNs4qBRLJWUSoxvODHAQ=;
        fh=Ai/YpVczDA/jUURIeMGl4bhEL2vYLvP+GxVOq6A4kbU=;
        b=YmmeHzOZRfZXI+CpNF2vZq+bb+E1xggxnt6phBj5qCQI2ykA9Mbx0VPEcFLhhHeSLg
         V8/MlGmXSyQ/2SQmsVjiohqHlLs30028PM8QAHAPz894sQfbKHpsZlrU4yE46aimi5Ks
         8HDTwO6L1gmTet3PX6XXRcfGu9XgTCnc5/01FgRgCEaVk5jQj2dr0XR05uLXN8Ptpmv1
         ABOhazQYj80+uqrcz5mFm8JlY1NkmkgT3xg8dkeUuQyymouuc9BBlnte3i/Dkjf7Hqmw
         iCSMN8E+YiXaRpcQOW3r5qZ3lwuRNaTAbi2tRdVUl6uzITg5MMU6sh5NotnDQ7dEkyxn
         3hnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jE+T2+hD;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726997300; x=1727602100; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=uz2x5haxWSVv3ocCFmlUhEKfNs4qBRLJWUSoxvODHAQ=;
        b=aMqgh/GjrQe/jAuOMnzbTGJi3o0J7B0rFUO5qj85UnvX4SDozWsjPOVlj9yflkpZL7
         gnmIHTzza+4rIVLdeHPi+fWdNmx4kIeNVgRJhVbifRrNsHFroxva/4UNHuV6PnCec+Iy
         SE/NmBT1keMWDT0J3cW8HUgroV7rezIAZ2Iv+q04lc5Eo/Ck7+MJwrpuC0wsrd4cjgRC
         V6TQKGZcrGB1kXlV7D9BHh40c7SgWe8dCJjtA+U4x2b3xJ/iGCIgB/73aV01iQ6GP4YU
         RTfPFeZ7V+80At8JMpYxK6BWJ7eRcZoau07lthVB2vsDbpf8hBiYrZuJbRbQYFpWGZAr
         O88A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726997300; x=1727602100;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uz2x5haxWSVv3ocCFmlUhEKfNs4qBRLJWUSoxvODHAQ=;
        b=PEckZPp2ILLvKxz3JoHLBNKvNF5x7FPPdDav8I/1KYnM9dYh4vH+qjx74Ne4MgTP91
         nSApn+xtq4jD7gCFOSKy12NXFZIGjzm06tgfadsfYTPfVoyoijAHcmwIT7xSmjPzC1of
         2M6rH41jnEhm1DHohanrDbCmuIDsCuBCTW3qF58IQMMa/erVBhj0eX95xUhoWgiM04Bt
         N0HHbGbw5KZDPGfJqsY1FVWYqVkkfCDhGIyYfU8ZrVrKVDSt/xLwCoG4hRS7+wS4tXbC
         LACTxGEr6MX+DlRhicLPfJcdWzbGAZwUYMvvXXWAWW8x8ZVjwXqQMfLdbY3mEnMhWpOa
         Ls1Q==
X-Forwarded-Encrypted: i=2; AJvYcCWDQWvtNpsMv9vfiD1FvS9a06V5KQ9QmPTFRqif/O1dcTlgvvjAuivvLYqcVVYcnG8Wn/28ww==@lfdr.de
X-Gm-Message-State: AOJu0YwD6PPnU42E8fr03dBZVC1iHzT6ruWBjD3K3plCXxidfu+5Lqgq
	7zDvoDLKmWBfY6dvsdBFjNKNskdSa1JbhayUOksAqbaNu5ocFHes
X-Google-Smtp-Source: AGHT+IGNeNtmSlVGC9yZqGnFkMibK8ANzx8dEgDv8d287G83AMmv4blJNh5MVTA9QszE8BAjs1kO8w==
X-Received: by 2002:a05:6214:4886:b0:6c5:aab1:4f04 with SMTP id 6a1803df08f44-6c7bc71f0ddmr153816516d6.28.1726997299643;
        Sun, 22 Sep 2024 02:28:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2303:b0:6c3:5462:e5df with SMTP id
 6a1803df08f44-6c6823b56ddls61086026d6.0.-pod-prod-05-us; Sun, 22 Sep 2024
 02:28:19 -0700 (PDT)
X-Received: by 2002:a05:620a:24c8:b0:7a9:bdac:6405 with SMTP id af79cd13be357-7acb80aabbfmr1531383685a.17.1726997299069;
        Sun, 22 Sep 2024 02:28:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726997299; cv=none;
        d=google.com; s=arc-20240605;
        b=DFHUKHJrJj3V1/uwvWAWcb7u59Q66dFVjL7uaNB1MGgaWMITSh3tSch2nIeUlYm8oF
         rYDKA7YDeNil7KP9IrbGYr627ABAvn71ykNSwTgLiLMWA+mph3HNCaOCodwdNxWVJBfd
         loRMb/i0i1+ADNXsFEfeemWLN8M/57TYqgpgpWk79+HE+hfV9JUxUes8FZltOx+npe2k
         sePCMc3foUakPTN8XtLM5tJLtcYMf2l0hBYbPmpcPUagvpokyMgtSQ5qLmSSkS/XKQb7
         LnAYbNt/O41dkimJriK1poccCJeNLOECFLPkqW/AY99YUwodMm9+dnyMSxAyKv1c+aNp
         k6TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=CPiRAsrboPF+Sn8bY8kIW2mal3+WxxF7hHf3r/egCJg=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=eMgUN3Q6R2qMJYVTD4SV/Gxw/jabDFzZhCxSl8wJs27iO24gf8tuXD5grZooqqBV41
         hUgTgfP2egRZi8Rpb0LBj0xonaKs9C9lB0TrErCl/gj4JRxLm3lMetSiBrLX0OyDgSpj
         XAIb6qFSCrVx1jczYFSNoqLzi8t2pKhyK1LBuFMdLvMq84vvQLyIpETnmVM9/i4TFap/
         M4KsfM+0K6SLTrPUD7jbnaLun+ShIjBzpHRqwzsOa/CbbPRxFk6rqU0TB11d3zdK/RrA
         81LlhdNMgtqgKOcBKPL2xuxQ+Wp1Vyk1zVlP2TFuWRk0brLzP6Sh24lgIXy7Q/Epy081
         YJ/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jE+T2+hD;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7acb06f65ecsi27778685a.0.2024.09.22.02.28.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 22 Sep 2024 02:28:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 90933A40D52
	for <kasan-dev@googlegroups.com>; Sun, 22 Sep 2024 09:28:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 452A1C4CEC4
	for <kasan-dev@googlegroups.com>; Sun, 22 Sep 2024 09:28:18 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 37EA7C53BC8; Sun, 22 Sep 2024 09:28:18 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 198661] KASAN: add checks to DMA transfers
Date: Sun, 22 Sep 2024 09:28:17 +0000
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
Message-ID: <bug-198661-199747-bP7Aftjedq@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198661-199747@https.bugzilla.kernel.org/>
References: <bug-198661-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jE+T2+hD;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

--- Comment #3 from Arnd Bergmann (arnd@arndb.de) ---
The functions that need an annotation are the eight "streaming mapping" ones in
kernel/dma/mapping.c:

dma_map_page_attrs()
dma_unmap_page_attrs()
__dma_map_sg_attrs()
dma_unmap_sg_attrs()
dma_sync_single_for_cpu()
dma_sync_single_for_device()
dma_sync_sg_for_cpu()
dma_sync_sg_for_device()

In all cases, the "map" and "_for_device" functions transfer ownership to the
device and would poison the memory, while the "unmap" and "for_cpu" functions
transfer buffer ownership back und need to unpoison the buffers. Any access
from the CPU to the data between the calls is a bug, and so is leaving them
unpaired.

It appears that we already have kmsan hooks in there from 7ade4f10779c ("dma:
kmsan: unpoison DMA mappings"), but I suspect these are wrong because they mix
up the "direction" bits with the ownership and only unpoison but not poison the
buffers.

The size of the poison area should *probably* extend to full cache lines for
short buffers, rounding down the address to ARCH_DMA_MINALIGN and rounding up
size to the next ARCH_DMA_MINALIGN boundary. While unpoisoning, the area should
only cover the actual buffer that the DMA was written to in the DMA_FROM_DEVICE
and DMA_BIDIRECTIONAL cases, any unaligned data around that buffer are
technically undefined after the DMA has completed, so it makes sense to treat
them as still poisoned. For DMA_TO_DEVICE transfers, the partial cache lines
around the buffer remain valid after the transfer, but writing to those while
DMA is ongoing corrupts the data inside the buffer as seen by the device.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198661-199747-bP7Aftjedq%40https.bugzilla.kernel.org/.
