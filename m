Return-Path: <kasan-dev+bncBAABBXGRX2WQMGQE5IRUI3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F20B838DFE
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jan 2024 12:54:06 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3610073a306sf35633145ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jan 2024 03:54:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706010845; cv=pass;
        d=google.com; s=arc-20160816;
        b=R84MlihUNF7MWdqkjanUvyItaaVXiMsPFnV2phDgGOmaDO95IyVOAtXuU+jbyhZHV0
         F/YYuHN7MHuQXr5c7gxqrCnydZvXOv+7pdqTYi1lL4aUsLQc1UgQjW8jG+7cJba5vCkN
         sn9I5kzL8QmtQfEYr5+Eif7so5XSavjcqZRRRSS6L7TTVHVYGveWFwYEhzJI9cotOJpC
         DpsgOaLStd4om25eLVkPanpnSK6HL31Vfk1kJ1o3JmmkE9JwuHM/TTR3OjWv/GpvYFfq
         U7Xi7R5yzWSFRqm+TcTJur3aXlvgv1pA0/LPuH5koX0Xq00fCarxCh33ZTxmLlA6COe7
         UOYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=//N/43WCMUsHU5+rn0Lr+zbBVh03WFfyO+LvSxQewlY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=sBQyFYRBfZVMF2L2KYO96CBplcdcEXuM28kLKR6ccgPdAJEXgqdQDj8yd1dqraXxY/
         tta+c0nZtPrxzApr0gCIqdXT5h8WChpvC6EOSuLzmymTw8vwc7f3nsQXro98x5tw9vg3
         waCUo31Cw7p686Dd81lGTQftaCZrVcUffyKD/8f0ntRf0nBTY0EqRFychAguzpAH/5gg
         cWUxnsZlR6Tetr1+phRQB6soKtouuBDX1hheEBWp5Z6jxDIc9IficCPCWVHMOQdC3+qn
         ECFC7/BfWZoc7QW0d+fmBIyQ14wgvDbdV62mJlB9F+9yPEoJwwk/niJo0NlKjuVOpJX8
         NTPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Ypz1CVl/";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706010845; x=1706615645; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=//N/43WCMUsHU5+rn0Lr+zbBVh03WFfyO+LvSxQewlY=;
        b=rF879hdNOjKpHXjtcAkrKyUgbJyREUAOtfK1ugBUQ1kV4BITzgzVaDH4v3GS6JJz6C
         4rJL3boFIzBT4Xa03ou+tpnMX1YecOVmEk7Ogok59mWpS7dHanDk7pyvv7Ap571n9E+G
         9pEG3RL1H2cDrJQ8CWwaORX2dU8ybzfJMXfLqi69wfYB2rWiXhBqoEy/1Lz3M4PMJX25
         GNcUuHHDej3uuyKPnjtnM7zcds1ZMlCO3q8EML4u2uKb6uM+x9TGvIMGKH8S2HC+286h
         Byq0qpoYKtGaPWjfC3ssuDVXgOCPl2JGQJKaISSB7d7/7W2vEXx9/fTeOFo+X2hPi423
         76uA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706010845; x=1706615645;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=//N/43WCMUsHU5+rn0Lr+zbBVh03WFfyO+LvSxQewlY=;
        b=t/sUnyxUGoh7RDIs88Ktt7PI5bzNnISL2C8vEhsgtiMWnrapQUIaqJEtokS3n85N2w
         10kP35le40baqOHBWOVKawyqZfjQ0qPLEvrVORfLfeoBV5bTnGh/e3ycCebfxapuH2yh
         0ts6yEUkHAKD4eS+6i61z2JGRq0sQ+AmUg3b+oqcbFzQZ+2KympixwMKEKsn3IHhSOqs
         ubs4AERIe/0nbykIRShCH30/YazsXYbEVzkzncAz56hT3NweX+Ctev5Oh/Mllw7XQp0c
         HYumwVJI8F46Lv6YsBoZF1fDWY3Tk7OEG5+Sh4JV5FUxHbctq0cNQJIyH/8kpqqZ4Tsa
         VOoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwAf+3khnGB4dvBM9Dm5t0jGP2Bsb3Bw9VR4BP5lWRVm1NPKI3s
	DDrWugc7QV/dLHuKMDIFZw9uK/NtA5plrmsWk/Af37BdSO9IBKwB
X-Google-Smtp-Source: AGHT+IHs5xSBpPlHoEf3uxxfoh7gAUHSAi9gBp5z9rPhDcWrYwysUJeF6dilB4y9n5qN/DnIEaL8Ow==
X-Received: by 2002:a05:6e02:1106:b0:361:acf6:5dc0 with SMTP id u6-20020a056e02110600b00361acf65dc0mr7713902ilk.11.1706010844976;
        Tue, 23 Jan 2024 03:54:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:6b0e:0:b0:35f:fd04:f60d with SMTP id g14-20020a926b0e000000b0035ffd04f60dls1343745ilc.0.-pod-prod-01-us;
 Tue, 23 Jan 2024 03:54:04 -0800 (PST)
X-Received: by 2002:a92:d591:0:b0:360:61fc:3d06 with SMTP id a17-20020a92d591000000b0036061fc3d06mr7825338iln.16.1706010844329;
        Tue, 23 Jan 2024 03:54:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706010844; cv=none;
        d=google.com; s=arc-20160816;
        b=Ckb2NKMLmElP17diBJNulUQtGWHy1xKDGOVhn5Uj8U2K1s3Y0A8JPzemOyEbNyJk/w
         DOXupvo4+npuA5ItlOgfvatYAd5RlRN8TGgEZu+igj/Ip7Sv8bHgDyX6BMPjPI6t+tP3
         mfrjqxl1UzOtFp2bugioPx7f62Pkw6423KSpY/dh+b0Ms139fmvWGS9H0Q/yuUudyvQ7
         My42d9aqfVMMl+bvbPPTSwxrABswqQyIk9CZeuEj2xMlDGvrY6ox/QriFO/+pUMwsD/3
         8TAfW9XCEcsJiHDmOI5dtjpUvDf+e1pWqAwOoxuETSqEsBLu5/sqfLLTCYnIWJS/Q5PP
         o+RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=1M1BB0/Y+4LrrMiCVjEbsiIgYkNJLoezGWIs0Jl1dVg=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Cr67/vf0L0l3SCUHJpVHQFNmXklN0xN69ujXVy8CHHjeauiH6yZ6xfScQPykZZhlcT
         i2K+Njutd5JrCshsLxlPAuqqvlUvudJDoff3buMq9iizDpVLwJNgf1mFiMHacZv7BRxU
         naaqOdbgcvkqVJu2tvZd2HUwo3HPy6/T/vasZIvtreGVJZCptcMNuDh9nU92iJsmUAAy
         McozH2i51my7rdeSnh133naAypYHEaLA/0cqih4r7eljDXh+PlDnM7BB15JLiqTEmql/
         GKTkSfVROuVHR+Y+jubVBsxb5LqpoFw3CkZ72TUz9kzNi32qZg7TxR7baAAXyIVpu8Eu
         SNjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Ypz1CVl/";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id v127-20020a632f85000000b005ce01d5b09esi935238pgv.5.2024.01.23.03.54.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Jan 2024 03:54:04 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B66FD61BA2
	for <kasan-dev@googlegroups.com>; Tue, 23 Jan 2024 11:54:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 66171C433F1
	for <kasan-dev@googlegroups.com>; Tue, 23 Jan 2024 11:54:03 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 528D5C53BD1; Tue, 23 Jan 2024 11:54:03 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218313] stackdepot: reduce memory usage for storing stack
 traces
Date: Tue, 23 Jan 2024 11:54:03 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: melver@kernel.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218313-199747-Tj4udckrLV@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218313-199747@https.bugzilla.kernel.org/>
References: <bug-218313-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Ypz1CVl/";       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218313

--- Comment #5 from Marco Elver (melver@kernel.org) ---
For generic mode I think it makes most sense to just revert evictions once we
have variable-sized records to again save 4+ MiB:
https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/25002

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218313-199747-Tj4udckrLV%40https.bugzilla.kernel.org/.
