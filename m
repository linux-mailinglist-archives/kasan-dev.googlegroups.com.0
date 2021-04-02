Return-Path: <kasan-dev+bncBC24VNFHTMIBBE4RT2BQMGQEFP35NDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 97CB935309B
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Apr 2021 23:11:48 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 131sf10623945ybp.16
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Apr 2021 14:11:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617397907; cv=pass;
        d=google.com; s=arc-20160816;
        b=HOoVPi5t8vaRi+WCg20ixFCKQH6xDXh9QD3WMxmilEW2z7ROJQ1iJtI49UTvBuKXuF
         PZcC2atLmsmTty6h22a9jMAh016QZz0/vK8t1e1J0mTRzrgXsrPi+VgrXLWYrgS2qC1s
         ri2UKFq1TDTDWPX7RXl2mPzXywuokW4FcCpgjmD7H2Z1rslYMlH4lKdZWLaacNk/VGcq
         igakEMTQL533rp889whUIjjtWySiXC4tboIaGqa6jsgh5H3f4B8AJxmwjrIfWa0y/lmu
         RgQTl3UmTf3uV17oNzckNtWqzyIz68yBiMjBTunwu7AnuqmFqgcgGuhu6jBApsTdnf2G
         zybw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=USpa/1g4CVFhONeFrEY5R5Xn8H2Z28ibaYiSKEXgwj0=;
        b=LepDG9OYnDzruZGQX05frcl5ciIajP6pPMxFfRm6vfVD9RpGa9eix76hckou0tcpXU
         182ROEF4HVzj/Fux6UZmwvWSchE70DN/3gddxMUvvsWdx+FEdmZ3ZIFxPlaFJQK/yA7a
         hJc6DTB4c9zC3f0RzufVL9ea4HBj1lup34YtB25043cvz2T6XVz4qjO65Fk3vipGpzMB
         laI3nqfx4KYFRjdTAs42c6La3Z8NGvTHfP0g0Rb1GlOmTzqJEk35lmnvpSArVqHHAs5K
         Eo01o9X/QPCG3M9Q9RRHAwXGQyONzYozs9l/Ei7oRKLn7iyPW7QG7w7PjsXRcnZdMj3y
         K4Bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=I7d5NKl7;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=USpa/1g4CVFhONeFrEY5R5Xn8H2Z28ibaYiSKEXgwj0=;
        b=E+6H3F8nMFkQxTAmQbepktYANsR8RGQgGiozYbL2z9IthJTPHR+REkIwstG5Z5bn7O
         4tdQcrw5JHbV2mp1q8u9sohzZB7jTLSbt8vnFxy07crX5bv89UjMxnKtH4xI+WoKqlck
         Tz00CC5zYZZYNetISnu9GapUh9LepMeEExMWowMew4D5b2gM+ii9pApERML6kY4LIjp6
         m44anfDrZMPvvypZz6b9pGv03j9P3vtCvj5z5LsRH05C6MFzDaoHQwblQ0XEwX0l9gXz
         +wkQ362JC3VUIccwWjYHEla5CKHApF3Rv0uEUYwjGD4tohMimdlf4jjDwIaVFPuEY3G+
         oLyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=USpa/1g4CVFhONeFrEY5R5Xn8H2Z28ibaYiSKEXgwj0=;
        b=OUCBZKfRnkSOAddwPu/6towKDUVThnN19mX4HlLxYoJAcd3knUUmh3IZzua4geevIa
         SqZIpyljeWmyMrNUm+wB19jwF9atmv5dj67ngOJtZDsLajVS6hHY8n2Gsw7NTRwl4FnH
         bEN4SkLF3xAeVhRsh+yOifNJwkgGg9eoXHcLRNHde97zw+4vsPIlR3zwfA47c1jA/i2Y
         eWn9M6eWWb56fxzoLapu9O1CwNja+cc4QnZFyMj4XGPVRxwRsRDh2lenqiOKhRvCHOT+
         V9gwZHKJPVd38ydp0H3vTP1+DjVT8dCG7xoLtX+o+MdIgY4pGpEWLD2L1olzF1mBCKvZ
         AjtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RFnaz9VRkhHyps1UHguqQyBvgUEeQsp3xD206Ti5HOseg/6+D
	GreJjqzzVhR7ucjeC6mmNdU=
X-Google-Smtp-Source: ABdhPJxfteZqBaigVE5M3tC09DQIxeGuF5lVfc88AKGzyI1SKwjZcZQD5N43Qw5qHkPyMG1MEWRz/g==
X-Received: by 2002:a25:af90:: with SMTP id g16mr20587586ybh.223.1617397907423;
        Fri, 02 Apr 2021 14:11:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ec02:: with SMTP id j2ls4694724ybh.2.gmail; Fri, 02 Apr
 2021 14:11:46 -0700 (PDT)
X-Received: by 2002:a25:d151:: with SMTP id i78mr14036744ybg.293.1617397906851;
        Fri, 02 Apr 2021 14:11:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617397906; cv=none;
        d=google.com; s=arc-20160816;
        b=qFL1neKI06hqEuRD0GWC/NOWL9lnRi+93QXKKlejcMIyGxJza2jHgfxUYMyuVNR4mp
         l9nJcu5mUOvGnCWwebVme0VV33a1hEeKs/v3AQToCQh6418BN82siDuclFmTprNph4cm
         2cXvQDNjRYghDNSaVqBJkPjS2S/fCmuuNx4yL0lNbjAlog2ZY4d1iNRkQvGIf5XP38Si
         Viu7LuEruSbA/xiIRPybc9CDIOChIpxfjYQHYD+MmMXlja2xvgETfGpCa+k7ZLZK34cA
         SkHj4PD0Ygr94xZZqWWCTd63J74X7fQyzwy8uj3EydJfAdYp6EsuVTEOCX60IPd7ZYhi
         W8Xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=DdXeVC5Y/ZCaBBZ+bRsBQ3HnLSCr3AKV+V21Fg7KWcQ=;
        b=f+hiEzBrI9VAyMNbk2xg+Wuh5xKl5eWO1xYQ8FE+x6faohCwSicSL3XGvBuu4qJ4WO
         ddYEivKkkeQxKYRS8t9MDLPqWhxZubLGbiCyPC/YS1JYHHDg2msGeKVcWxB9UJHOaE1W
         rYTBXTDFS3LLrICVkWLiY1XLE+tmn8nOV1m7FyJaeSfMMkGvndkBEzOVYDiIYQ2g+8xl
         Bizii9k8ofrnhLpb1AODMQ6TvHYW113RHuZm3xCjvavvrzPA9OVLsM318vDPvrXCeUZf
         Z9+msyGBGrE8p09skTBNGQnEEFJuFYJ6ZVH5FfrODzqKseEtfBaO2MNmF5xavB7CbmNX
         h4+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=I7d5NKl7;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s192si629588ybc.1.2021.04.02.14.11.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 02 Apr 2021 14:11:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id C21D56115B
	for <kasan-dev@googlegroups.com>; Fri,  2 Apr 2021 21:11:45 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id B6A0661055; Fri,  2 Apr 2021 21:11:45 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212513] KASAN (hw-tags): annotate no_sanitize_address functions
Date: Fri, 02 Apr 2021 21:11:45 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: elver@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-212513-199747-ymAFX7IOYe@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212513-199747@https.bugzilla.kernel.org/>
References: <bug-212513-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=I7d5NKl7;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212513

--- Comment #5 from Marco Elver (elver@google.com) ---
Re __attribute__((cleanup)): "allowed" under very restricted circumstances. I'd
rather say it's "tolerated" :-)

For KCSAN I decided to use it because the abstraction it's hidden behind is not
explicitly about resource management, but a special assertion. Furthermore, we
know that all compilers that support KCSAN support the cleanup attribute
(although these days, with the kernel requiring at least GCC 4.9 and Clang 10,
this isn't a problem either). Last but not least, nobody really objected I
believe because KCSAN is a debugging tool that is usually off and nobody would
notice.

My guess is that any attempts to diversify the kernel's resource management
strategies (e.g. vs normal "goto out" or some such) with
__attribute__((cleanup)) will be frowned upon and be rejected -- which I'd also
agree with because it'd create inconsistencies and in some cases also makes it
hard to reason about what is executed on function return vs. a simple "goto
out" (at least that's one argument I recall hearing somewhere), which can be
quite crucial in certain contexts (e.g. see all the 'noinstr' functions
restrictions).

So, my guess is that if the usecase is closer to KCSAN's usecase, then it
should be fine, i.e. it's hidden behind some abstraction that is for
KASAN_HW_TAGS only, and not about resource management explicitly.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212513-199747-ymAFX7IOYe%40https.bugzilla.kernel.org/.
