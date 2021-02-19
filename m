Return-Path: <kasan-dev+bncBC24VNFHTMIBBVE2X6AQMGQE2WQCNUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 92F0531FB08
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Feb 2021 15:38:13 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id k20sf2836157ooa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Feb 2021 06:38:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613745492; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qh8FKCMYlQpZ6ZXvXeaQSkuNYFCOF3IJo9FX1ypSSFg2wLSnZk3lod+UgXRz4parV0
         VqEPn0pmKwxW8dZ3lLjp8Zzs2E7EuufrPjsNdD6uF5oL6uSRzxYV7qW0zctqbCKV8UYu
         8h/5GWnxhO9mAVTQ0JItWTNimwcJxZR0HNY3+z1eFGP9puDTkk84Zh6/KJndBI8btB/Y
         3l4IBbAHhGNAX+7RhVrK3aBESTfnJrM1u7MD3L2JSLHY5mDrKUYjtp27Xavk2okhOx1c
         FlMVa1FCQeurACPmawQ3BGUv6QYXh5MO1+8/yp6mf7IfcqdoTy44GVAwL5oP5rIN79o6
         v3RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=8uB2msU4lmI1uuXiTOTtgxF5sGZB/eQOQjDE2ApUVpk=;
        b=x+OzUjCzei/3yqRURikoUQN19f23enZhjWRnXgJJqsUyJelwt9Aa4MEdgHteElzBES
         Mje+i4qxFoNyrWEBx79orZL+LdEIdrGXDCZCFRgss7Dx7xaQY6YN3igRN+BhiwDNmV86
         XybKkotwSOzZG6yKgoAKPoNlUD2e9dOG6xZ8KB+pGuNzcVwedFknulltohTWxthBkch1
         oz0tCKFya64msyq6oJjqjz7b3chfmwuXy8CDik6Ung2rqFttWmYjlwGAA2TU/xHc8C9B
         F4YzwKdpwphmsmEmzjyfWWQGLMq1GE18LGf3VBKeffUMDGHHNtIRBY6Bb5l3H8eH7Oak
         ofEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=A1YqAyaN;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8uB2msU4lmI1uuXiTOTtgxF5sGZB/eQOQjDE2ApUVpk=;
        b=TdCuAoPej9u1NLkbqhw5iLAMHSPhaOkLUYMeykY6VfdGepI73jSSYE5+q8jl9L2n34
         NWl00/v/95ZJjkM0+1wDwqLP/NowtXmlfwGCZ094gKvG7I9uMqWZASzG48gPUBK+mE6U
         HHxh6zrTfkHpvAWBWGBLluwda1aYym6M1qOhmLIjgDKKDhxb4UDJTCT7euukGgtCB0kO
         IXBh957ojPBwPz9ZpSfgHDZYP9XluFKC+Fojx3LIwEd+PRi9v3nG/KyqxvHhto2i0umP
         JmckkP+vc1UDfPbjeYFdRdF17C5RJ2rQs9Uc5HcgwbLhh25DYUKu2jKHiewiY41xVbnn
         +D1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8uB2msU4lmI1uuXiTOTtgxF5sGZB/eQOQjDE2ApUVpk=;
        b=QpgN82Nq4XvXS9G6jee+hfpsyXjauPkQSWws2W6pzRjL7Cp9R+B6gb8xXLK44/LSNi
         LJxpaYdUSrBfnkMcSkCPQ2scBa9P4J1clKof6BAZg1Wi0lnkEbSqpygHoNBEdOK9ylMT
         aL/XReShSCKUuapg9C2gMNwJnl5BHSMGCWqpVoxSjgIFnnbqMw1NjEzcCRIvlJXmsyq9
         qlJimZxVtnguFvLAGRC6bGNE6icq+5ZW+PoBeDTWcAGWxT3NY/2KMED3hhUToWeX98cO
         10pYydtGZOgsRIA1a+cW+WX8JjR4RSrxZ6ODOfqCdTfkhzpz+u/ql0Fz2cqq3LuN/nHT
         5FAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533iMPZDW46WmeMoRk9rfKy58myXjc8lS1mjhuf3FV3lvhYndXOS
	B1+fSIdq79B7yNirYSuFNMg=
X-Google-Smtp-Source: ABdhPJzSXf63QhHmLLNIua4xkV3HVmXaSlf/HAc/ixN9Wsoqn/2f+SbGeFGT56NCgrXw6oBVWnjjBQ==
X-Received: by 2002:aca:4c5:: with SMTP id 188mr2303792oie.44.1613745492250;
        Fri, 19 Feb 2021 06:38:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:8c0c:: with SMTP id u12ls59072ooj.0.gmail; Fri, 19 Feb
 2021 06:38:11 -0800 (PST)
X-Received: by 2002:a4a:be01:: with SMTP id l1mr2251748oop.89.1613745491875;
        Fri, 19 Feb 2021 06:38:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613745491; cv=none;
        d=google.com; s=arc-20160816;
        b=kwdH9FD6ixemsh61hZD1Ss9Hl9k+fSK45FLoIBYtkLTNKiMC+xepWZ7Mo4PlhKga5Q
         AzUtXpkR7ae5jaVfpC+6NK+BgUS6pUfw9E/vpN61vk0KKo8AuHBm1ogSyqo6w0/8XlNm
         YPeHCsynrKc7xixRqdjU7M6EwXsrQ9IFSQgULPP/Ph14LAl/iKXckRIURGIert3CHo9Y
         0j+2jGtNiyg9WQ6tFwehLKHwKzg/jaq3n3CePw1hv44v/jUHMQB793go/hgkK7fi6SVa
         0bpQFzSvUWg/9u7BcLmwEsD/psKuRJNYAsAbNcngairAGKtc8U6+gblZ9XiDZQeaPS7p
         E/vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=4Qxln1Mh5niI0UdvhxGm2m6pEhzyG1sTAj/uR25LaTs=;
        b=UtotiS/+6Q++y9Ap0+MCnzl798AfGCWJh0lUntM8g638X6dy71UqWGhyGOSKqFp2ml
         qxjwR8muoHJc6edtycWIbQ8G+mXjdt+Q1FsYd6w9IoyfLWx2xo1Pw9gsF/VqsFdHJHon
         1GeD+Jp7ZPYGBDs/h/iQQ3mU1VTR/du9Xoywcec2eNKRXbcWGtaahY9zyk4DMfSxTiUp
         J49y5Un0c1vXVldUbe+kCPjHOH8TvsWeGLLrRUKBqV8OIZ17hVGnTKl82sj5tyjduP44
         22RQmtoQG9xwJ41DndlM0RIDR0rmT0fstPawO6+wf8mU+ctoYdOCVirERV+H1IuTuFf1
         xvPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=A1YqAyaN;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z1si573088otm.3.2021.02.19.06.38.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Feb 2021 06:38:11 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id B2BF664D9A
	for <kasan-dev@googlegroups.com>; Fri, 19 Feb 2021 14:38:10 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id A1DC465337; Fri, 19 Feb 2021 14:38:10 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211787] KASAN (hw-tags): don't leak kernel pointers
Date: Fri, 19 Feb 2021 14:38:10 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-211787-199747-68pCNntKmp@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211787-199747@https.bugzilla.kernel.org/>
References: <bug-211787-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=A1YqAyaN;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211787

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
The same is also applicable to register values. Besides leaking pointers that
can be used to bypass KASLR, registers can contain private user information,
which shouldn't be included in the bug reports (having Android in mind).

KFENCE takes the approach to only show register values when no_hash_pointers is
enabled.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211787-199747-68pCNntKmp%40https.bugzilla.kernel.org/.
