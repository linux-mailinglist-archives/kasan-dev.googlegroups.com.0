Return-Path: <kasan-dev+bncBC24VNFHTMIBBHFL26GAMGQEYXYBPNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id BC4CE4553C9
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 05:25:01 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id 4-20020a170902c20400b0014381f710d5sf2375032pll.11
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 20:25:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637209500; cv=pass;
        d=google.com; s=arc-20160816;
        b=ojKv4Yjr6mUVxBZsjwhshUs8SA197aia3+w1t3pDDszpr6ZsJEMUbsmSTENpZzb5NM
         xoaOOjibc7jYX3ejfdVXmcFPwOvczK6ADRdUVV+N3pPmSFU+0JuvGPKEJcMrRJ0HDMov
         oITl+gUOH09HhdzHq92OInJV9YodGSrX6flzhFoiswvK69oj84ujITOR4vjdPtXE3zD8
         hP2C6FeIbCv1+wKMCNc+8rxAsmaZoPW1xBBhRoFfKQtmuerW8wYSTZhvmppkf4b1TwNv
         ZNg5zR7YXTnAZHcGrUjz4i3jiBNHNDlzscdyjdEBKcJI/TKfRVBfgByEI8yF935VFudb
         3GrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Gm6hnfLWWmYV3Nma617NqdM43ARNbje9qM/g+HLXqGY=;
        b=TW1BZFertP6Um3fRJ9WFYjsmA8QVnqTO7nGF0/34KGGseZveASsQTBDf/GEtSrVguX
         Zp0xZkK3i3Wa+sLTM1utk46mClQjIsBROmWVu9CS2V/Kx+t/fzPq5e6VfASsJiIv4uIc
         MQbSEBDxFyu6XJqPjlOo8iwreaKK61dFTGx5SVzsjtqZgHSjAtPPxirliRrOJ7Jiz8sV
         7c3U8uh3d5qt2miQ2PNP5r69LzG8EARAejD7opHCdVdyEAZlfKU/VhdQlGuodOiJkNo7
         At/1q6WJnELiwlmeBV7GPTO1XXEQO+h8D8rDnWYdeNUAfL4CQzotEKOouCH9eos0Bo9o
         Qp2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ype28P45;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Gm6hnfLWWmYV3Nma617NqdM43ARNbje9qM/g+HLXqGY=;
        b=BKJZj1Q3srd5x9H9AVaZChqlDtRhka0fCjv/hs7woEumi4SFQjLXe8KemfX50Rp/WU
         QPi/N4yWOAYeGerVIRdpZ4zhm+1o4C5hByepelGjMB6I5Uve5cwJO97RDmrmVSb5UevC
         Jhkh6m3MxoMsk89uy5Nw02eXOBgpLWNaTWSyr0iu4qg4Dt8BeQRjCy19EiD+NeEPl1YO
         O2MIoEya6k4JgAnOxBcBvGcVkmkE2w66C7rvtZ+2rEttUplEIjvGGk5hjRCmpqThjm9i
         g4+W6bHV00vUQL5rE4BReuScZoWPjneXWNqr2lHnjttdLn0VfwfHvUwdxoGaJIP5/qER
         2atQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Gm6hnfLWWmYV3Nma617NqdM43ARNbje9qM/g+HLXqGY=;
        b=G3KkmuXDiPAao3cJGdRRjojj+w1EooP5G6UxtC+PxIOkrjwP5dTgNG+Y0wIOQcW8/x
         1UgcHcfP29ZvQjFVt7z0RmJnFm5h4jhEGk/osy0QeZ9dibj0UTIFDAMYE6IL/EgkZWIL
         xaOVvpqADVWokclgEyK2yPcSamgUcWHefGprwUdeRQnE9p8kdXbOr5z6UD5wyurxhJHd
         /jvJYUlu04+fuvGSv64001vreJooHyd+xh7bKK7vWCe1K72+YLF568+EWvKZqQyyBdK2
         chj960ZSyzq9uEwhCmPdqqLPkxA0ORC2GtiHiVSRw8E1tu1a90Q5CDUSh0nr8Sw1O4F4
         OLmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530lTy36YVw3HzDZjl0hZerxc1mmzbxxAkr4LvmOxvDGReyZLMz6
	nlQN2VDlboDzDfyNzJcfYpQ=
X-Google-Smtp-Source: ABdhPJzmCbOg8R/QQT0R4EP9pLUrgsABqjD9MjWCOuFA4YXZZt/u2L22Ito20LEW0ZoIm2nJKOwWrA==
X-Received: by 2002:a17:90b:4b09:: with SMTP id lx9mr6880137pjb.100.1637209500348;
        Wed, 17 Nov 2021 20:25:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:244f:: with SMTP id l15ls1238608pls.8.gmail; Wed, 17
 Nov 2021 20:24:59 -0800 (PST)
X-Received: by 2002:a17:902:b716:b0:141:d36c:78fc with SMTP id d22-20020a170902b71600b00141d36c78fcmr62171243pls.59.1637209499846;
        Wed, 17 Nov 2021 20:24:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637209499; cv=none;
        d=google.com; s=arc-20160816;
        b=wuTmeP62oCSCc0BAB5wtQ+x4NB0QtuD4FW3BicqOCaTHc5QnnWvMqDtgcZvS1Tz/AO
         TIQDRQJudmZD1xgr/0ZdjVVtLJGE7iBTtdEgpv1aG8SzubptHsg6YG43Lbowt1WcjAgs
         wui+f6hqr7e3KEssbqrYyh6jwWkOG3G60UElx3Ohq58bVWaXWD0IiGhS5A0a+Y+0mOwh
         CBdaqXSwUtqvdDsYZmNkXOvJL9tRtzynQhDvNirejCoyfyg/QJb/kJBLfSX/Skg/VrEf
         lk0/WdWdfsku1NtqVSjh7mDaTVqyny0XNZMOaRuOOXu/RwHr1se12xQyooaj/bz+o35M
         xpjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=0Gl/6c3dsFNVUjnzdI2ViUes9raS1JfoXg2ze7BOIc0=;
        b=J5AlRvUJ+adLgXdgHICFCL7MVroTcwRc0ZLnYt8hVRNmdGBxTWdNwFglrEnIOcc/yL
         rToLA8wZYTVkl9kIddfu3+V7UK6KS3bUYiBHYuMx7sZCawAwq/dKi2maHLYP3OYi8geW
         xx+wn6PCaB/aA7EJ0p5eF0zf2Hr0iKsno6N+UrwBRrQIRoBlRf4Y3gm+AHKbF3+2lm0B
         BxwyOnRR2ZXo5GeSkMjodJRjotaoNcriqTAyeH6dWBNIetUlho1sq2TvQcjs8YhggnbK
         atRXoWu4OBzgN1Y9Hb/ktRW4IIJbUjcsyfXLYxBE/NUqlfxXaDZiNrCJf0o06T8wh0+S
         RPvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ype28P45;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id lr18si152466pjb.3.2021.11.17.20.24.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Nov 2021 20:24:59 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 8285961B42
	for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 04:24:59 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 77CC460F46; Thu, 18 Nov 2021 04:24:59 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215051] KASAN (generic): gcc does not reliably detect globals
 left-out-of-bounds accesses
Date: Thu, 18 Nov 2021 04:24:58 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: chithanh.hoang@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-215051-199747-sxYAKQqjHo@https.bugzilla.kernel.org/>
In-Reply-To: <bug-215051-199747@https.bugzilla.kernel.org/>
References: <bug-215051-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ype28P45;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=215051

Chi-Thanh Hoang (chithanh.hoang@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |chithanh.hoang@gmail.com

--- Comment #2 from Chi-Thanh Hoang (chithanh.hoang@gmail.com) ---
Kaiwan N Billimoria asked that I check why KASAN does not detect
left-out-of-bounds accesses on global array in .bss, he started the discussion
with Marco.
I am adding my findings as suggested by Marco.

Using gcc 9.3.0

char global_arr[10];

The following code:
{
 char w;

 char *ptr = global_var;
 ptr = ptr - 1;
 w = *ptr;  >>>> this code does not trigger kasan

}

I found thru inspection of the shadow memory that there is no redzone declared
before global_arr[10], i.e. no 0xf9 and shadow memory before global_arr[10] are
zero (good value).

I therefore create 3 arrays 
char a[10];
char b[10];
char c[10;

{
 char *ptr = b;
 char w;

 ptr = ptr - 1;
 w = *ptr;  >>>>> this would trigger KASAN as -1 will reference redzone from
array a[10]

 ptr = a;
 ptr = ptr - 1;
 w = *ptr;  >>>>> no detection from KASAN since no redzone

} 

So the bug is due to absent of redzone for the first global declared in either
.bss or .data, I have to admit it is a corner case.
Another question I have is how to increase redzone size to better detect OOB?

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215051-199747-sxYAKQqjHo%40https.bugzilla.kernel.org/.
