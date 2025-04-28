Return-Path: <kasan-dev+bncBAABBTE4X7AAMGQE3LT4LUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A728A9F8DD
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 20:51:59 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-b1c122308dcsf2249172a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 11:51:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745866317; cv=pass;
        d=google.com; s=arc-20240605;
        b=b4Dr/oxIhJSI4dZTM/91ywsskc5UFN3QL/19i4EL2Sr2dQVbUV1AeU08fiz3bYJLso
         YhlDJxSH6kxoATTh9I0jW/HJZRGlI9QlOPyx3ZF52hXJtxKcDPE43KQEFpaaii0kUgFV
         +LOJaMjQu6tx2TpBCUrc01OYNP5qgSy31fQp9PtQ0P/Yc5VDRS+XIscVpSvokciglNWw
         ORTlefB9fm401lriFKEP68a/gGZgvSbA+yI+u4ygmUsa+0v8YRcZLnehp0LR0GUpLmnc
         c9Bv0OKV5MyOO37lWOqIf2ZlhchKkfJqf6qugKUDvjnUIWC9wgJ4aq6B9VyxxiIwVVAd
         2V6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=HBzOpMhqwhvYuiiqs5kixR4fLx7zgR3GKNfli5LgEMc=;
        fh=Q/fPgmh5Ic7hKggWMQT2o3lYRZtYoPd/4ORuJ+tr7hI=;
        b=gT3ml5mAB7YTMaT+oV3Vo9MbRRBoDo90qCbM2L+t96kCurltEH74su2yhv+VbuUOl0
         N+9zxxes2C8VH05opkgaWNYnauPWK+3cPivXv/i/CT1TYzr88UGFzQp2LKifKYL90sRK
         Z3sPYITY+gyazIh6TJdbNi8tNMmIr49HSGDBITFnnmCx3UjEERz3Tb0ldKhB2djLVOOC
         OESF7jlTOW4Wg0BfSTY5jcTclFJNryBIW3/u+zFYewF70NDKt07TBheDIKn3vm5ph9G4
         UQvTEHmZnQ4knzUHQPD7AITh4ZIOq1spUZX7pKLfbPCWRmz97QILu1ee/f8eEXMADX09
         ZIvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ruGMCm7s;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745866317; x=1746471117; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=HBzOpMhqwhvYuiiqs5kixR4fLx7zgR3GKNfli5LgEMc=;
        b=IBawuR8cVU5QNXUfR1n83XlNmQBgMEhhT7vLNPE47U6ZtO/JV9DerwzjlJ2I4FeaOa
         S22cqTLrX5KmVxhoiGEZdNXBbUOO10vzwBL97PDrPjnu4u5dbVgNU0lQzrDypPMmo9Pn
         6ky7PwD7eJvHBvC465MIK0Np8lPOYTxmUr6nOhVpQwT70hTGDnHQyRSs5vc8gjm2qerL
         G8BBuMcHzmErgfJLY15BsfDK8qFlvTVQ3DHEsp+le4KT5EbW1qJIGH0PHxwO65LRdYT9
         ESFEx1GQH1VLKJUswNO6XhLwLP9+iugmAA9ROcxUDO3NqtJAzW0y3PFs2yQd+pZYr8qQ
         kxQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745866317; x=1746471117;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HBzOpMhqwhvYuiiqs5kixR4fLx7zgR3GKNfli5LgEMc=;
        b=NWYgwkGH7+LiwuRhLj6f/QNqU3UV4eADcom/rqekmG+bctBNXOhneKEHj8f/r4Hcma
         27n6bMthNpp4Kf3ZPpjpOEYIqnvv+QDbXArQh5lM+bI4YwmHTG96tOwySno6DkG4CALI
         vsaAYHeam+rTfl7CIHbyp+HFVNaksge5Zz6J8zGF2vyFrbx+Ql30GqQOdX+t8V34WWBM
         ZYME+gFb8QymLODfqjGTB7TrcoAqY5/XG32AsQqxaLtRQgffe5GZSbzvnD8XOZ9j1bdK
         VbbxjJ3xzEE4tDR/Bb1C+vEaq1n9pS5rI2cufRKI3zUF7jjmJm5NYgEYJ3qLr8znfH5d
         XSRg==
X-Forwarded-Encrypted: i=2; AJvYcCWbo+Al4D4LEim11qXumpdEqeKYdKvogupRA7SLhRzT8zpYC1pMHZJxFOgcEFko7hmzUC2epA==@lfdr.de
X-Gm-Message-State: AOJu0Yz3vb1AkKSRhhQSa6U0eX3/kQ0Lic3pt6RWDsUSvmXoI56jhzr8
	t0VdBhlarASvYoygpgYFQxAn9heCpbw4jaU0bBlMps7jmlpgl2ah
X-Google-Smtp-Source: AGHT+IEQkt+6XumvoX7bZw7cUTnZUlYBxhuQko9k7hrL8TqnwYocKX29+D6X74WnwQ6lhi1MJ8UqIQ==
X-Received: by 2002:a17:90b:5826:b0:2ff:693a:7590 with SMTP id 98e67ed59e1d1-30a21597ae5mr1466521a91.33.1745866316889;
        Mon, 28 Apr 2025 11:51:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEtmGY0oxqmkROgZ5t9Euk8BDovD0/sIEmJfQACVxYvCQ==
Received: by 2002:a17:90b:2549:b0:2ff:4f04:3973 with SMTP id
 98e67ed59e1d1-309ebe09e1cls803443a91.2.-pod-prod-08-us; Mon, 28 Apr 2025
 11:51:56 -0700 (PDT)
X-Received: by 2002:a17:90b:5185:b0:2ff:6fc3:79c3 with SMTP id 98e67ed59e1d1-30a21552a93mr1547252a91.9.1745866315967;
        Mon, 28 Apr 2025 11:51:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745866315; cv=none;
        d=google.com; s=arc-20240605;
        b=R9+bNUy2P/4YqaVZqSRg9iYIZk4PQaZvAULWTYrv1fcZtb+6LcnFGifBHBRT2SZXvq
         7AGLyW+ivj5RKBAPrO9rDgttkPxuZAzIAOS7/UaNy5+p8aFnQ/raet4BWJA2GvvS+EDS
         3SusdXdFnRhMjV28Rd1KckwP1yU1yiNoGblwrIo4t6ganEv8Er7k3xvkSqv7aihmw5Tp
         EmBgB89xzNne/Guhx4JuUPwkdwOt/maLwDgayf08ZmxGPCrYEle1nt51YOfQfolJ/Qng
         DoHpMnaLjMj+VxTv7vXVNwmXgFWCq4qPurchNx7xKwMxxORHycflRDvm6KYHm7QrhoOF
         6g6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=lY2embzjVoTHn1/KNFLigFbQGhFzwK/pKZJAw1sXR1s=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Qc6PGnJxWXlFHU2tN2tw39O1qMBwkXxNy5xZmaN5dEiUbEprIn55yOtS1IVT5G41og
         70+mL+paYIBafqXjHwiI6RrMpTSSCVDNYb8hjmRQZB6Ec6lAA+F3EBICriXDXSGfX13K
         B2ywIg7vXBplb0xUovEOjUpa6yLRSCJE9gzs/he+gAN+xUHq9TDZYujARriEQTntK0Gp
         V6+8bdVAYHFXqQt9bOU3MMFQOX48aZ29e8pT9sd/g9a5f1GE/0N7nCWE0DvhSVfzuQ1l
         lLf2SnNkcou3ztSOpMx9PMfQy6/DBGusWTb6YgmMMkjDTMg240L/S7Bsjo0vtqwZABku
         tf1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ruGMCm7s;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-309d3bd5db9si1160914a91.1.2025.04.28.11.51.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Apr 2025 11:51:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id CE081614B1
	for <kasan-dev@googlegroups.com>; Mon, 28 Apr 2025 18:51:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A05ABC4CEF5
	for <kasan-dev@googlegroups.com>; Mon, 28 Apr 2025 18:51:54 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 9694FC41614; Mon, 28 Apr 2025 18:51:54 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 199055] KASAN: poison skb linear data tail
Date: Mon, 28 Apr 2025 18:51:54 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: kubakici@wp.pl
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-199055-199747-X1q04Hvr6z@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199055-199747@https.bugzilla.kernel.org/>
References: <bug-199055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ruGMCm7s;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as
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

https://bugzilla.kernel.org/show_bug.cgi?id=199055

Jakub Kicinski (kubakici@wp.pl) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |kubakici@wp.pl

--- Comment #4 from Jakub Kicinski (kubakici@wp.pl) ---
Hi! The initial target for FAIL_SKB_REALLOC was slightly different. The bug of
interest was:

  struct hdr *hdr = skb->data;

  if (pskb_may_pull(skb, sizeof(*hdr)))
    drop;

  use(hdr->field);

the use() is UAF, because pskb_may_pull() can reallocate the underlying buffer.

You're saying basically make pskb_may_pull() do the opposite of what it
normally does, and "truncate" the head strictly to only what was requested? Or
just make it limit the skb buffer "rounding up" logic?

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-199055-199747-X1q04Hvr6z%40https.bugzilla.kernel.org/.
