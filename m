Return-Path: <kasan-dev+bncBAABBHGNYLAAMGQENRSEWBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 94DC0AA0845
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 12:14:54 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-309f0d465bdsf7755309a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 03:14:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745921693; cv=pass;
        d=google.com; s=arc-20240605;
        b=clKEJntCzPPKn9uWyHkmDTCU2LeBknXpMAJDRDP5M8cdu0t0t6jJjQfz7T69EmSsvW
         G9XDbt3NJ7Pfvbvf2Ls4w9nvKildWspFS9Oe0IVt1Y0+z2FXWK8DqAogZGCjegkW7w2H
         5vZNFoF7ibrbaKhw1gDH0Ty3/ESShn0XeCRDuZF2hIzatIVcFmrvE0bgSTFh3ctafP4c
         Jz/Ck35h1OFCOVjDcNbThH2+ZBZxXQVCg5bA0S3CvrKbZygTLUbpJYmRkgc67YPz+ZU1
         6UtBU3xalpFnaC1rn9UIcnLnxIHxwh8nxjVs8cNOUeY8OjLvYMxTFiu1zm2DOzuaLwDH
         z0FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=Bdot2411XOs7FJrDgz2qk6nos+383a3sxhWGr4NL7P8=;
        fh=tuEudRNjUt19iMfMwaNpMSSgBK8HNAVkc04QRoqmfW8=;
        b=ZCrOQTXlF1H40QXdrflO8pUcX1QFPHs3ZFZPPzJbeApNXKls9RL3iJw7zkrsWwFUrr
         rI+SnQRtElYYr20p4J1STDdArFHYM74MOalP07od8yx8lnldM1kHxrFEf0CacSZqhUub
         tHbx3J3obfCnLDHF5u/gmUcEzhp4GV6NQwaWaBcgN4sJ4YpKd3zP4ChhIG9nPRjsudOn
         Odcc+3y+WoeggKPjRXvuuyGbTVKzRvN9yzYfBjuesvqR5+l/oKQsYkwFzik8Q5I+7w+s
         uA2dcx6cUcLE5LihJcVFCmYlraPi6I0kOBI6FvLEqWTb3DNlzHCNIZgxm2MANixosFky
         dHiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ju5KViYK;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745921693; x=1746526493; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=Bdot2411XOs7FJrDgz2qk6nos+383a3sxhWGr4NL7P8=;
        b=M+7Dr8mfClkwNTV5WRbgnsXlLwjWRmjFsjXDVdAAtF8D2hiB5JnA2QXKr8M1wjmRro
         g7pDITlwPNcSJ4v3IjmnSgZT9Qjtqjwd0RDsYmiNawVw40yRghzVPp2YH2M2c8vBpV2r
         N4f7I/Pw5a+xkyA3+hvPac4GEI22zn7tsPXPVVbQPNzwkv/fiJVXpk5oY1p+j255nWdg
         OTi4G1UsdK9HHrYLMRZaWIhoo9vcLbuMk/eaMXlYHF0uvvXFNSsbkDy0qMi9ipAbvDKa
         pUSg/4AV9CpBLdrz2pYbnMtImabfNwOdTCM6eHx+VPbI+hxUlVsQ1QtLGCvNiVpz+VJN
         VXYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745921693; x=1746526493;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Bdot2411XOs7FJrDgz2qk6nos+383a3sxhWGr4NL7P8=;
        b=hV/DED76QAYeG7drBrteo13J/nqBKKIL09L9LwdNZpSuof2N6moC8THowFP+pWrqxM
         2X/b7hVe6qEgBn6i0DWzLtg037jZ+mMtpd4TojlSdP9e43gfulynXGNQP2qWqNd8g4vt
         64HhKAIbpclQ70WYpraDLUS6SeSvLq1KvzbxNEvGE4JTVDVhml4xfIDnTiwy3MTJ7zC+
         Nm1phyOYeZDt37EVScXh3XOkoDXtgfWHhsXvUMpK9w5/dXy1taYneVNtUFv69VulJz9d
         5874xNpltAjp/XtDJ7WvA2SxNe25mBMVAz3kM8kRaCkGbD069amGGm3mWqvLeG0/Dnmk
         CrNw==
X-Forwarded-Encrypted: i=2; AJvYcCVs+YN68AS1Qra8S54dv4L4e+GxXFFZdsD+PW+xiOlkMPBBWQwNMVfppMSJXxifdy14AZZ1gg==@lfdr.de
X-Gm-Message-State: AOJu0YxVmVypQHoaU+T6kEEse3lyStYlwtwq2ThMan9uYvREno2NTeJm
	j3JBWdyzhEvC0vaZSI82q3bCgIOggdmsbyqYsM86W/Mw0TdAdEo2
X-Google-Smtp-Source: AGHT+IGXXguw9xTqKld6sU6QXP/73zePMiOMSd+7PpGZoEzW58E2uEzhFNbuS+0Vxz4lAMdOCi8WvA==
X-Received: by 2002:a17:90b:5826:b0:2ff:693a:7590 with SMTP id 98e67ed59e1d1-30a21597ae5mr5294229a91.33.1745921692721;
        Tue, 29 Apr 2025 03:14:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHg+TxWMiTe/qrGYozeZKoTb4uuLcN0IFTmt48XQRVwOA==
Received: by 2002:a17:90b:2549:b0:2ff:4f04:3973 with SMTP id
 98e67ed59e1d1-309ebe09e1cls1415208a91.2.-pod-prod-08-us; Tue, 29 Apr 2025
 03:14:52 -0700 (PDT)
X-Received: by 2002:a17:90b:4984:b0:2f2:a664:df1a with SMTP id 98e67ed59e1d1-30a21546c8amr4589057a91.2.1745921691799;
        Tue, 29 Apr 2025 03:14:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745921691; cv=none;
        d=google.com; s=arc-20240605;
        b=aS7p16Vurtm7cwnIHpWKQfh6vdNYqQA9AMiHLLAzDf8QCMI6rbsVX/hb2Ttx9QpS5o
         rjhY4QkLEOq7jcu/InA1lV0Wi8e7yQteC6PoN6l0OWU8QiGcVq7N05KId6docIAezmOF
         hXe/9r96xfFofbEZ3bYecdSfuE4RviB0IIdxs6IlfQ6Z8DHiyB6FiYBP/WE3ZyVysPqa
         0Vg1htUqx4dAgMcCCkQpD6cpd3EKbo9Xcg4CokqHRIQ1CIBDhopRykKTb5FBmrJ50Bhx
         47MH2iiUiA44VSIz+6lE2R/ETcKVFSgCjoAgHfIJSQpTww10uRJUCy5l2ohJILcNHTR4
         a4og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=E1QHoLPU2HV8ZgiPJAfW/jVdDKAVXjGdA+NntU3keLs=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=JBUj9KYoXSKMcKUCu/4v7BaCJAUU3uCTg+azEsubCrCW0twSH9jlaVIoC/wlf6DSr3
         j93po4BRxLrV3HRxPlPGaVOxBUaCHF2OeTBHuhy9wV6B7pYRWy4gjL/+5w3ok40nMHac
         LDBetGMkteyy4j0BePAGp4VdhHX1Zx1qGTtxprCi0bfXPvJJXevwzS1whAE9WbLfOVxD
         eibYQkP0Z3P7OmHN3qKhfwidw2/XoTFl89n4DhhUr7q9ceRVb0N+T1iIbKg5TDGSUU0R
         4iZrNrXgEhQ6KN518EX0gncjt7x/WCugFvFbuFrLFQYqRnxbh9riNlXrYH400jnTD5H8
         hU1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ju5KViYK;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-309ef0df342si417499a91.2.2025.04.29.03.14.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Apr 2025 03:14:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 50D6D4A2D7
	for <kasan-dev@googlegroups.com>; Tue, 29 Apr 2025 10:14:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 49E21C4CEF6
	for <kasan-dev@googlegroups.com>; Tue, 29 Apr 2025 10:14:51 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 43A78C433E1; Tue, 29 Apr 2025 10:14:51 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 199055] KASAN: poison skb linear data tail
Date: Tue, 29 Apr 2025 10:14:50 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-199055-199747-BmwrZ9SnQG@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199055-199747@https.bugzilla.kernel.org/>
References: <bug-199055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ju5KViYK;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=199055

--- Comment #5 from Dmitry Vyukov (dvyukov@google.com) ---
> You're saying basically make pskb_may_pull() do the opposite of what it
> normally does, and "truncate" the head strictly to only what was requested?
> Or just make it limit the skb buffer "rounding up" logic?

By "truncate" do you mean some logical limit within skb, or limit passed to
kmalloc?
KASAN does not know about the internal limit within sbk, so it won't detect
violations against it. KASAN has annotations to mark/unmark regions of memory
as "poisoned" manually. But I am not sure how messy these annotations will be
for skb (wrong annotations will lead to both false positives and false
negatives).

So I was thinking about just asking for exact size from kmalloc on "fault
injection".

I am not sure how expensive it will be to do this always when KASAN is enabled
(both reallocation and exact size). KASAN already slows down execution by 2x,
so it may be reasonable, and it should be a very useful mode for networking
testing.

What do you think about a separate CONFIG that would enable this?

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-199055-199747-BmwrZ9SnQG%40https.bugzilla.kernel.org/.
