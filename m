Return-Path: <kasan-dev+bncBAABBHP4V2ZAMGQE6JAB2JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 92DCB8CA3C4
	for <lists+kasan-dev@lfdr.de>; Mon, 20 May 2024 23:18:22 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-61c9675ae5asf204801737b3.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 May 2024 14:18:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716239901; cv=pass;
        d=google.com; s=arc-20160816;
        b=BCdeNV8Bb61pUpkkx81BjRQScMUE7OfKkkFv4zzkFPz1XlURRgyP8XOypm4sOcwo36
         r86BG3r1hMVY8I5Fjos4P77U5sX9G8Kl1jlBX5grfFs8jg9knnS89rF8IpD0jyH8Qc6J
         wwu20qlCHAX5avWZD88wFBPaQyjPZOjSxmfmTuesCjEHV/0T5pOfb/ZjZRgeMYrgpo7y
         c5J3HPuvYZYnOU7VTkXMifU7mNbC6ZOduuw8EzG7U39j8T1YGnztZ3SsHVH9Osq2J6Kb
         5ZOjlL8XpD9vU9D4nu0twKd2KGWL+WQmZULjE033Yj9SgJPqv9FtQYMYBOQNdyFFc/Bl
         mV7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=YWWYjG5cIsjBVKvrhi/W//KLyFCbqjxNtieGK6uG/Co=;
        fh=dkLrQgtg66zpsTYsyPSlFEqo7v50Skeeyhwra5D910w=;
        b=mc2e7eNRUpF1162Y6NXULU7dbrjSoAVCfMvTQsEP6iNhSjELCqNss4Q5QFdxynZJT9
         9xCEal81mNforZso64BoOhYEjdcbLve6ftnC2TZEoUIF9GnBCFw8d/HBhg8Sa3J3TEae
         jmt83pkKnZqPTzLKqzEbaidOdgaJ6vLL/4G7g2zjguWvDWL4Kd7kibK45qwM3p5BqRTU
         qUq6RxFUWULQGq9BkWrWaLpJzoV5yhe7+lxfYC81KL/BTb1lKvukq7dQeFOLED1ooAcb
         Ro1AB+XnHhLV6Bii6uIwxwL3BxRxwM/L6ogehqfTtU8SJXqdnvXv8zIQiDK82JpCsoV9
         N73Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VX+DQ8st;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716239901; x=1716844701; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YWWYjG5cIsjBVKvrhi/W//KLyFCbqjxNtieGK6uG/Co=;
        b=iRqhqMUZ/eETWUHTo620h5tSsVHa4IO10T92NpW+7tDItGFz6mQ6/ZXw0VUxSlbcgT
         qR/aJUYHVvrQxqnnVf1Cwz3XWUm7Xvl1508wjMZvWJ157sGQAAkLJhKHpxfXxr99pgqM
         MdCuAvqICi9eF6WVt4mbV+JJjPBMTrydfA5oDo7aqQI8MuETJRP5uvPTikoDiIvPbw1i
         TLYe/vHvUbU+/4LCnpOSGjKKoQ+DWjHm6Pba4NTXKLADkZkTIjB1tcDGwjSKCaxR3wRs
         shajFYQ0mN+w4ksWHMO8hpzExbj5OKyaJl6Wtk3xbMk8WUuTeU32cPV/2iwjKcuDQCOY
         3SKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716239901; x=1716844701;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YWWYjG5cIsjBVKvrhi/W//KLyFCbqjxNtieGK6uG/Co=;
        b=t058Kucg8tQirlmv5Q+C4ImGWp3H0M8+d+02A7VX/wE8Ogy188OQLn2rA4HIJnzlWd
         E/LDjVUjl/XY1+4I514TFzE9mxNx+34A4Ys0+hzMnrZpectda0VX3Ae8IbEb/bWcftuD
         VcbatwLoqBAWzctcx/3IB7R8cOLGhY4uGZTXmEOHRHIelXlyYTdWl2jv/9ALeUaZ+hsL
         WLkZqAoT6bTp1g0x1weX8KwvJh1Y6f/me/6CARdPWi4W3qSKO/BoN4ccxgfBvFN7Inid
         S6+7477iqlEmSfXlvrTtYXW8bTmpYE+POFSwBm/Fm0IRrBsI1Y4jN4/Rs6UKielMgV6v
         Wtxw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVIkSJze9gKzY3/xV4Mp58bTrySaNyADmmGJT7YA65Pze/Llv00WplI0jeZnVm9uyqFjL42Jf/z4hmdzmO2QXotdd9nquoJ9w==
X-Gm-Message-State: AOJu0Yw3260bwSMleL+Civ+cvLOsodNmHTFL/TLc8brrg3jxrJRSO9Bd
	yaVLfjR/FqCgL08Jhd0MP/vRDVD2BjjmnKo/Wd3M59ETrnLMREEf
X-Google-Smtp-Source: AGHT+IHMI7lLqJ+OLrr9rlZvOAXC+Za0d1WNHg0AbH7noG26vqwgEl+zAkf9cp34pb54d9sZNuQ2Jg==
X-Received: by 2002:a05:6902:604:b0:dd1:40cf:942b with SMTP id 3f1490d57ef6-dee4f3709b4mr27910624276.48.1716239901279;
        Mon, 20 May 2024 14:18:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e0d3:0:b0:de5:a004:beb with SMTP id 3f1490d57ef6-debd0877ae2ls856689276.1.-pod-prod-01-us;
 Mon, 20 May 2024 14:18:20 -0700 (PDT)
X-Received: by 2002:a05:690c:f83:b0:61b:3356:d16d with SMTP id 00721157ae682-622aff902aemr333238687b3.19.1716239900654;
        Mon, 20 May 2024 14:18:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716239900; cv=none;
        d=google.com; s=arc-20160816;
        b=zdQiGv0Dk6zWY3jZZtuOQMv0vjUGIfFaQDTbw5+FsaGkka5WnpxycOogyvCCF5uU9S
         yPRmlrJ2bMpwDq2Jysng8Alqc0CRF6oHaLBnhyqEpDRYqBag/zsJHYgLjOBssheWnEs9
         53O4DTrcTrbl1LU7GGwDW19hR5Y3qaTJ+1VxiEWyjCJLsm8wGmp4oL+cB0ZOoZt0r7Ih
         geFj3VyqXRPgX3hpDhQURsc9brQhV95BkzrfOyY0+yC34o/Gv7KjGzXqc+d1MRs/tiRO
         whjbGfXsxs0ok3hJMxkTvjhSwV8ckCoVsZH/J0ggoEQVC+cwLjdHre0XLaBW30T/P/wS
         H9LA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=imDsh/oUUqJ1CK5Hr+AKKcUvsrgXlGhwdC3OdJFys0M=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=S2Iwnfh6UkXVfzBIz9IPNIbefbrcBo/4rsuqpz8YOcdrIY6vhhXvSxzpPA17bU6J10
         EMGz0Y8Yw8egSMTej9TrlttUxahDjMxjWuWb9qeUL8ZM4vdsgKVj2ztMbt8D6JleOodr
         Q+KK6mMgxyi6raqGDJaXj7unO1gODJYdqtYVkBnQf+WV9JD8YEiWUcn9yGOVG46LEUzB
         dPzkuNkE6bRg4h7dXk9Fi+mKUYTdpOQqIumLet6jMjB9RM3pnN+wlWp6Igcf9HT6KhEI
         g6V9lgZYtXlnJtIe78cNpC+F6Gi6yFEEaOX7yehaHPzD5i+j+1iCHY1fF68US4C9pbRC
         UTFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VX+DQ8st;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6209e349f4dsi16914287b3.2.2024.05.20.14.18.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 May 2024 14:18:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 48D0061E9A
	for <kasan-dev@googlegroups.com>; Mon, 20 May 2024 21:18:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id F1A43C2BD10
	for <kasan-dev@googlegroups.com>; Mon, 20 May 2024 21:18:19 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id EB347C53BB8; Mon, 20 May 2024 21:18:19 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210337] KCOV: allow nested remote coverage sections
Date: Mon, 20 May 2024 21:18:19 +0000
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
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-210337-199747-VmV2OCi6RZ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210337-199747@https.bugzilla.kernel.org/>
References: <bug-210337-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VX+DQ8st;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=210337

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|KCOV: allow nested remote   |KCOV: allow nested remote
                   |coverage sections in task   |coverage sections
                   |context                     |

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210337-199747-VmV2OCi6RZ%40https.bugzilla.kernel.org/.
