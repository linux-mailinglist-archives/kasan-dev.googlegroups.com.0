Return-Path: <kasan-dev+bncBAABBQWD5G3QMGQE6DJFQQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id E33D9989CCA
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 10:30:59 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4584d6cb55esf98609721cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 01:30:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727685058; cv=pass;
        d=google.com; s=arc-20240605;
        b=WXaGphKYkwNuKzwdyfctW4Sh5bMTyyMBTyKkR2zhsMkvM9yROvESYd+jRDM4toCNdl
         V3mSLrpu2V8CNqzyDtxtalLLClZhKIzq33hx1KNeFZ0/xY95cJ2/2WbKCV2Fq4y+NxkN
         Bkhgj+FevgPd8RfDChPmecloJwGKR+gttr3WzflUpRo8aM+gJz182HiPKbD2yjXW4Jy3
         wIbsdCUuhCKDkqHxiD2hccqBs8gheDPW8JyXwYG6kOu6SU+oXwthSSVs7RbuHXNlbJaf
         MO2CAYLI3Mkdhym4Gi+vJ881kjsxzuPCWaxgTRwUR214+emxzuRLnfYLt4d7KEMc/I/K
         dUMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=NMwG7tcL4gYVRYzD6psgOMhm7tElp579tluuUpk8VSk=;
        fh=8RWfpZtQKJeQYmAKbtVXaWwa/3NskLnfXpKvnirExEI=;
        b=e8/gkC3+izp6s/Xt+qhyX3c35L9lhNXFTqU5XzjeKpI2VHgDJArkk9VUMAv/nHzfct
         5Wgp853pYNZpqgdvCLXchr2vZOcROTF6TsQnW2SSYxfb7Xkof0vnp9AmiyFZIM0J1oll
         djaTc1TqkRoN00R9amtB9QdwUVqvQqd+bX5BMS0/oxCzBenvxgtjFUf369HNVrEuXBI8
         JbvcVO7KHq7pxJzgNmKPeo7mGC8+eOWv/YwQgg5D80nBiR7d7RvyxhRmYeY9j9xcTPAI
         7pSITTwjTvg/Fa2+pfjl9EORMvTuKan1iF6WdribVm7O2+LjWM5iP9+GkNwnN6t9317U
         oAKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Y1ooNVUd;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727685058; x=1728289858; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=NMwG7tcL4gYVRYzD6psgOMhm7tElp579tluuUpk8VSk=;
        b=pI5lR4HHcihoUJSwsmSHccPKBllY1JIl0V1zP/fjPaaahC/eU541Bnb7VV33rPkeEF
         WrenukolGNTl0ZpALN4OceN0eAdyaSWA6syUOnFOz+AdW8c5X0qIpGac4Tv1gOCHdGui
         9w44uV86GnAyPfqEjgh28ORgqGDzw8LNYifFr8lMnNe0I8Icjc7wI3vYzBzp/ROBnvuu
         wA8NCjAhDzE11+Xnoj8FSc4YxehM+wg5PCQwgAYE+ekCGKZ/2vImbCCpI3fktDXfaaIk
         GS2j2AO6b3Ay86zvUoytWqKTqRBqgfl7yDmroJakKxYWUY1LTz4t6XV0Y3tEZIu7ew08
         RmiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727685058; x=1728289858;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NMwG7tcL4gYVRYzD6psgOMhm7tElp579tluuUpk8VSk=;
        b=wNRW4F51JjbMr0jYDhM/e/ek9j7sJvuw9VBeQ/v4AYl6/1WCZWR6P/npAcozDTxQNS
         ivOFs8HMRBPuJZn4xRrxUVuTPyUj65jEQXWzMxv2z5I+XC7L60xEcbBPSYCkfqCqrdQG
         QM01TMswL+HpooG0L5Cf+zrqvhelMdZmicEd/uvwMzRD0g0eh/c7iTE60nWcDBaazWM4
         fUzjyhzUde0u50avmVlXmPqM0RDhOoIMHELE1nKY0sbBhrzVoLymLdrIoiuMMnrfRrxD
         DX4uzo8sKZkKVS9I0/X6B5so3ylHk79yxfgoxPRWIb54uVwCBCNiI0AsPv3yEWa0Dxh2
         Rcsw==
X-Forwarded-Encrypted: i=2; AJvYcCX+L4AGWJM700SxdiaWW2AsO/cvfn9fgfWolFbESSuZd6f+tXLWQahWEEgydXmwZy+/us5Isw==@lfdr.de
X-Gm-Message-State: AOJu0Yx29djnL8Ve4kKnd193Tm8JrO9S0IS4pBDo3BycwvlrWunCgEhP
	pJo/9VAYYAQ/5Eze8Rr6KTbNzRMO4W0yyhgvBkJxMqyskzKdEKpl
X-Google-Smtp-Source: AGHT+IHGhHXpb/6Pn8RayXzWE1qP2nqr6WrvMMUgLP9CgFpEsGeSfuwQ88sT5WpGfkjB4c/a1WtoAA==
X-Received: by 2002:a05:622a:1347:b0:457:cab4:6e4a with SMTP id d75a77b69052e-45c9f28610fmr148928911cf.37.1727685058559;
        Mon, 30 Sep 2024 01:30:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1ba1:b0:458:403a:4ea4 with SMTP id
 d75a77b69052e-45c94ae4687ls20849621cf.2.-pod-prod-02-us; Mon, 30 Sep 2024
 01:30:57 -0700 (PDT)
X-Received: by 2002:a05:620a:4693:b0:7a9:b3ef:7d93 with SMTP id af79cd13be357-7ae3783b6c6mr1911552185a.17.1727685057129;
        Mon, 30 Sep 2024 01:30:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727685057; cv=none;
        d=google.com; s=arc-20240605;
        b=BobsL1ABpeyOv4s2nElOBISwAAQzQIAtJAV8EDm1zIHXVXxbTOBO6QaMj3nKt0tXL3
         5YD7Q+Z4CtWcIclf8bHIAeQRoa/alK7nwIniIvMXx7RCgo7dr9SZxEPx3+nbP3aeMqDf
         ml8lwLtSENngzuo4BWSbpPwo63icdN3pnAD11iruMcjr92nuo18z8LNFePTOoSSCHSrK
         Dez9OL6mmvQPTLuNjRfpfpI67ZyjohZ9cs95I4oT4vOlc0bX+ha4CnwJgyeZq1CZT2IN
         uQxlKG48jYhbS583w/5Tld6klQ9OjPNLpMgMRfYx0exEXtLf+9Kbcox8xtZ537Lyzx/I
         Uc5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=FaMAFCJXb/UZDuPqzZEDHl07K7v8bCz2PZej9/o7SEU=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Eha1C1Nrq/fkq5lVIxHBBzGeBdVq6KOLHeaqx26DrpbFo1LVzwmF3JZ1o6yP/ni4XJ
         SLXGjj5FSTRL/+3tUrngUUhUw2Aw+LNLE34MSOzUz3wbEJVd3587GC+/WDMqsg1pBQuf
         7MFh8ZTT4Rf33yoybivZ3rsJafrFQk5ZLkst9Kf5A3wDTFZI9l73/5DvBtRPLjHrrUFk
         RwyJ81FoRalPmyDrN2Ay/JBAkqvz8akgNpHdf03jck//S2/YKdmzjoMVewNN/snxf4mB
         A4+lrC05kLSRRz+HfyqtW6EGgc7WBAjfxXekv/tgmVi5sR2/pkvFQHtYAW3EMpmI36GJ
         A8fA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Y1ooNVUd;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ae3783d2a6si30065785a.5.2024.09.30.01.30.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Sep 2024 01:30:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 6D902A41688
	for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2024 08:30:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 678D7C4CED1
	for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2024 08:30:56 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 5AC08C53BC9; Mon, 30 Sep 2024 08:30:56 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 210505] KASAN: handle copy_from/to_kernel_nofault
Date: Mon, 30 Sep 2024 08:30:56 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-210505-199747-XDJYIezl1Z@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210505-199747@https.bugzilla.kernel.org/>
References: <bug-210505-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Y1ooNVUd;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210505

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |dvyukov@google.com

--- Comment #3 from Dmitry Vyukov (dvyukov@google.com) ---
Are you sure we need to check both arguments?
I suspect it may lead to false positives.

As far as I see, kernel code uses copy_from_kernel_nofault mostly to copy from
"random" pointers (in the sense they are valid at some point before the
operation starts, but may become invalid while it runs, up to the point that
the memory may become unmapped, thus "nofailt", however, the result is later
re-validated):

https://elixir.bootlin.com/linux/v6.11/source/mm/slub.c#L544
https://elixir.bootlin.com/linux/v6.11/source/fs/d_path.c#L50
https://elixir.bootlin.com/linux/v6.11/source/arch/x86/kernel/ftrace.c#L92

If the source pointer is random, it may as well point to an unrelated
KASAN-protected memory (which is actually likely b/c if it's heap memory and it
was freed, it's likely to be in the quarantine).

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210505-199747-XDJYIezl1Z%40https.bugzilla.kernel.org/.
