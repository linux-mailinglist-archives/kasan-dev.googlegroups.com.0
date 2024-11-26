Return-Path: <kasan-dev+bncBAABB7N2S65AMGQEHRDJVHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id E34A39D99C2
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2024 15:38:55 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2ea50590a43sf6628432a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2024 06:38:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732631934; cv=pass;
        d=google.com; s=arc-20240605;
        b=SHTp7SALBZZizXGtQqEX6NJ4o7yDd4HjYRCTiZStk8N7Y01Tz3vUAm793e9ndkv20l
         MXLDA4Xhv4Q+DgTenvVHD81OmPw75xiWWNbtK5m1PRdXCvhybNSGxoVHjWpFM5Ij8ebi
         DtywL8UQeMxuk7RrAadKuFiyyijzYYUaqNAMJ6qvP4ZZIXGgwUazXhShgrJwPxN/61bb
         3cgC3xp8GBfyv6Co+EwYROv1F9J1rtnxUGZ2hkewcP+I5AW6yKgtOK1lFyROMP635WF9
         fqWWxBwtqe4tvvyjxF9AB5dlaRZKDLGlpma3Za8QJR04pehsHj8ny5eyZhb7vA4nvmJB
         LQgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=48bTtCBDI4yUBaqh4/MaTZNqmSXnV0ECIMLGLoolAyY=;
        fh=mO2ELl54kwZvUwN1tv5uSra7wh3mf85U3fy7TTl3XPc=;
        b=LmvL3EvXKskhjEFFT4LmahPNkoQH75hIuoPG7dhiaUItl4RPe49zPaMPIH9mPdJ6Ot
         OlzeN487SMX39/kSYQ2qH5moIgABDVmEJgoqAkd9lUe2iYWEaknddidF4EJAbQntOnTS
         aUFdcop24QJAbWLbcfg5hugbuYAvTRknzf4+yfCOhkW0HdlIHeeB/FDfqWQFsHZPQnRw
         6+nBwBYWzxFvj9d7hB6vrbG99B8bm1VUIal8gOI+gmY+2mVjB+3tr2EnydMLfFhOTuZI
         RJrdOJ5k9tF5LhayOyyFtpvpo/z9GGbjEXAqksw/DKVlHgpMgw+cUmcVALLHJftqVYKp
         JZ0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PMmqM+0O;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732631934; x=1733236734; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=48bTtCBDI4yUBaqh4/MaTZNqmSXnV0ECIMLGLoolAyY=;
        b=RXrm92phLBNWIrCTFaWBaMs2DM+zjTvyyVCZzcXOcvTR0m9vixdTi8jPgRXp6xwOzJ
         5rJ09EWbusIMx/y5WBNQGRW8JjpPr2z9y7wlPcx+fy/rVfL9p/cWQTEyjzIPJyiO13aM
         17AlXlqBaf87/A/mWTUK55yc2A2qE1w4y3EI9Wt/RPspNplXATxxqNyzZb8h5KwezUu7
         V7Aj5sEiU+FT3fsn1/jBOjwu05zM7PSQxRx7wgZdDjnHfeGt6wK2lvIL5P8waTYFspYU
         oYC0uAfMJNRMgcre9syIoBgVf+QxeXftWLN86ebksWWDZQVU1+ApLpVHxCV1hKJbrFFx
         nSBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732631934; x=1733236734;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=48bTtCBDI4yUBaqh4/MaTZNqmSXnV0ECIMLGLoolAyY=;
        b=AbBusG1IRZmo2qWoJ3NuSPGmY+FKOvoYHgqWuBW6Q5+Hdt1dRK7DieorjwJXuJ+PtW
         KMUfANEt0Se/BVZpNItd7cDlSXggiactokHmONseeDri88CBtYOFzvV4NQFehgPDtwjy
         bcRdXL69VTmJAAeJB+LrFpCZ6ItN3u3uUXKCaiXTBOn5IwWeoxh2V7lSttV9edPn1lXg
         9KXtIHOQjSINK70OONQ7vKgTlnM1D4J1qx4Vy4pqrikGCH9xEHXKqBeuTPmGsd5tEWZW
         FscEVefTqRtQBSUrq9z/LPQg8witGcse59as/enkft36XWmAC8uPshc0KpG5ZJBFwwoO
         i/0A==
X-Forwarded-Encrypted: i=2; AJvYcCVcS1Boa3VxOl/UkEdqJICkvfKfgvtEVTwEFuXR9kKJQxjHCmFQ0zQ4bwcEoMX+YcLX5J2t2w==@lfdr.de
X-Gm-Message-State: AOJu0YwDwhWFrHhLFMmAuVB0H7sXk1yHedLCnJVOU8KmnprAN3W6008t
	NzZTlp5XcfHzE6FYfblBsZQ6hUl0Wt4ParytSXEhL81mc1WPAQem
X-Google-Smtp-Source: AGHT+IGo4BrWCBItLZLXVURs3NII2sPZ9utViUArDkY1rnA7IsG35ubwcXPqC+t1G1fdojP64Z2iiA==
X-Received: by 2002:a17:90b:2784:b0:2ea:5c01:c1ba with SMTP id 98e67ed59e1d1-2eb0e869fa0mr19624357a91.23.1732631934047;
        Tue, 26 Nov 2024 06:38:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:380d:b0:2ea:377d:5c8e with SMTP id
 98e67ed59e1d1-2eaebc20713ls454284a91.1.-pod-prod-08-us; Tue, 26 Nov 2024
 06:38:53 -0800 (PST)
X-Received: by 2002:a17:903:244c:b0:212:5eb7:9cb3 with SMTP id d9443c01a7336-2129fd804f2mr232267825ad.56.1732631932921;
        Tue, 26 Nov 2024 06:38:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732631932; cv=none;
        d=google.com; s=arc-20240605;
        b=Z4JHiCdQ4US6al9hMKE9QFmipI1OIlXf0pcZqE0HWs2JpMQqllm1lfn0Hq6Y4NsRXd
         csoI4aF0xGXA6m65pljhMfAMg7jqRR4rw7iXwzgnLCXGgxjuBwm1jHx7DHmKbf8DAwrQ
         KcYBQSNn61gufVvavLasYzFt9n/+ZUbCQLpLB01cu4CtQAVngFniv14sKMKcZluhmk2V
         Sg4YAQJ0R2kQnXlpoByJcQldFOvE7tCVeHqxb87Ryk9t98RFt1c2thuB5LfoPxcaluro
         l21W3tW+ntIbFjiuI1aNNiVvKrINSPcCuKB7NjnqQtJG86NerzSvbqG11j0yNEB7n8W2
         351A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=e+K/iUQEK6vL0EvyueR3dibiYvRIhzt30PJNClQYuXc=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=JqWPO5KVCFUm+7tbe2CI3BKvGEAeASBdfYXxZqkWhQbROw5IijDBVuvbPtFMdf4GLi
         vVFi/nxgzZ+Lc4VSu3+M1Kx2GFEUZhJC4O/KsgwArTVeA8/0jli0MVI3sKOcmk0Kqhx4
         +mtSWEBvIkTnDJMow4qXvi4yh09HPM7oHjwhWSSvPh0VYBAbOMgt1rm/Pkvz9NO20pck
         1tuhRWGXQt1CbOA1u4Jh/rm94Sa59ZdHl76yQ7I0sRIHTyLbA1kweeoWu53hiD+O0g5A
         JzM09Kl9CNYZCBAzq3shhn52/OzDmiDBS+uvLgZU8f++5q+p/KC7bjkPdcCqTM/rOwFT
         dDpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PMmqM+0O;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-724faae0dd0si290100b3a.4.2024.11.26.06.38.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Nov 2024 06:38:52 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CBCC25C24E1
	for <kasan-dev@googlegroups.com>; Tue, 26 Nov 2024 14:38:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E7AB0C4CECF
	for <kasan-dev@googlegroups.com>; Tue, 26 Nov 2024 14:38:51 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id DCD2BC53BC9; Tue, 26 Nov 2024 14:38:51 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 201177] KCOV: intercept strcmp/memcmp operands
Date: Tue, 26 Nov 2024 14:38:51 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: cvam0000@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-201177-199747-9zDUUuqPuS@https.bugzilla.kernel.org/>
In-Reply-To: <bug-201177-199747@https.bugzilla.kernel.org/>
References: <bug-201177-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PMmqM+0O;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=201177

cvam (cvam0000@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |cvam0000@gmail.com

--- Comment #1 from cvam (cvam0000@gmail.com) ---
(In reply to Dmitry Vyukov from comment #0)
> CONFIG_KCOV_ENABLE_COMPARISONS allows to intercept scalar operands of
> comparisons using compiler instrumentation. This is used in syzkaller
> fuzzer. It would be useful to also intercept strcmp/memcmp operands and
> expose them to userspace. SELinux uses memcmp to verify policy header, file
> systems use strcmp for option matching, some file systems probably use
> memcmp for image verification too.
> KCOV export format has header with some flags, so we could add MEM/STR flags
> there. Length of intercepted blocks should be limited to something small
> (e.g. no more than 64 bytes or something).

Do we still need effort on this Dmitry ?

-- Shivam

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-201177-199747-9zDUUuqPuS%40https.bugzilla.kernel.org/.
