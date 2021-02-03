Return-Path: <kasan-dev+bncBC24VNFHTMIBBQMF5KAAMGQECEWHMHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id B821230D80D
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 12:02:26 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id e187sf20189580qkf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 03:02:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612350145; cv=pass;
        d=google.com; s=arc-20160816;
        b=e/M+D2qPbF9NH/IA1pNHJkD15FVbReEOzbPqL1CXIzQYoy0it4KKa4xSlV2NGBcczg
         MQ2TJeg97hkYglxxUSFV4oWWNzTfQtshed6LfXefkYp0QblFp+96BuQUFUrVNKrXKTim
         6voUGrncpHdkiqL4KvoTPGvXMJsTLw9EZ/y6msANSRrQjdIikD8a9utQgy7CMQFidYZq
         AapQkv1MhhJYfZvEwFjmNNbsWmf+na+fL5Y0IrhljC+NtFNqLqCtaB9A4WodF1FqGM5A
         lRdTvvJTydpi3j9mKe//DBgYWBPMb4xVw3+pIjdiyTbBiIF/M61y3m7yiyvvBioK6SKK
         FG+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=XgPHddOTB++hniFa66lqr2qjuI2CETLx2DcQrmn4GA4=;
        b=medTvn8xV98mnHETny/8HbQ7Fzj2IyaO+gjbA6p+WFONFWu8KSTVPx+gbCmo/Wfmoe
         AZLnyPsCHtgD1kzcLlh5a6TwSEA4eAjOjW06HAZZuTMDLkprn7156Qogjq0Ar5+uKkJE
         fSmxcodqII/wWDbsW9xkfkzL+F+AVSddIo/mvX1VnCnSSgPzIQPSYtYUjRkowRGilBml
         M1VYd+w83pN4IOxZC5UCCI1Nlysr3c/GRgFhLFWnb/4S9w8V2LSMP61tsui38FOsJW36
         rxR20gSLHnYNjRvB4oi3d1fIYhJ9RP3rA5q3H9qbkGu9NcBV6kLZW2K4UkNu/pZ25eqP
         6vbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mv2TyFVt;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XgPHddOTB++hniFa66lqr2qjuI2CETLx2DcQrmn4GA4=;
        b=ByimSGRzNMH0mDkprzFaD6pp05X/ypS3xEqr9blK/s1Mq9p4/7TC5NJQJsH2kbv4QN
         Q09hEjZVsGfuGr/sJwjsrdQgqcbSrMEBeGE4hlUztTmkzTCfgnEcSOP7YTwvxYzrORZJ
         /ulHcpjYcTFQ3hpcZV+POkg+tcUJ13xdzhz9Jm6vIYPYp0y7QO6JHuJVr7avNmYvmL0i
         2kG52nau9F2+TaNBHk2LyFnMha+PqUs6q/pbqUOcopxEb6IVDAI5cplL1WN4M9mA94oh
         XiQmmXuyCQDROsUuEoBNHdQY4j1uad9266xkBaVfg0syqAWEaMXufo0aAhp4wXi2tiTE
         MVFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XgPHddOTB++hniFa66lqr2qjuI2CETLx2DcQrmn4GA4=;
        b=CGgnLoIEyJvKqWRJ1TaljZKKWQycWnccNEKpT3+ATAfqql3nf1wJ7gtH0k4hOClITX
         52AzhpONL2tU4bnb5kAb9+Jlv0jZ6LzFHIGPc8rnhTYC2G8new2bMCSQsPp2sBDXR3lO
         BFi88hwvsKk+H4W+0/liLRNLtbUWDVij+a3sV+cjHP2qsCsvFUVl16GNCJX12P80MMiS
         m+uY1mjWgGe9RJRHM1dIh3sxbAL3rHFY9vF7mzLIs+To7THrp0cOnldQk3UDDjcnmYKP
         4ETp3r0X+tnl5Ad7O2G9wIrh3ywT5POJ4Fij7O4cCXJUHeAruFRetZ8l9cP1IGnXwC/+
         XwnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532T0Ba/SxYuwPXRpQu3jrb/eNN03vS3Afncp2jQBPSay7RwwXeR
	8OsRQ+YstuMruyACnhyA/PU=
X-Google-Smtp-Source: ABdhPJw2D2LOefazdzjTPOuqIHXKUMKVFuYJmKLiw/tR4cGD9ZTPs5TP7T+7P6nK7l9H3NA69P8YZA==
X-Received: by 2002:ac8:1343:: with SMTP id f3mr1965696qtj.174.1612350145668;
        Wed, 03 Feb 2021 03:02:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1c2:: with SMTP id t2ls665926qtw.10.gmail; Wed, 03
 Feb 2021 03:02:25 -0800 (PST)
X-Received: by 2002:ac8:6b8a:: with SMTP id z10mr1999441qts.384.1612350145329;
        Wed, 03 Feb 2021 03:02:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612350145; cv=none;
        d=google.com; s=arc-20160816;
        b=pT32yphLWkge8eIE8hzbAsSNRqRKJVW+1ThTxJHrBIbg2ShM9exj5hcFO/H6bpjsQQ
         XWyrXvcPzDjRY4kiimvuU+q7KPRkoCAZStBtGoGuGjat5Sjr/gLH8BS5NxRvROtWW2bS
         Y2W8o28FqUVnyS579oJvLyOgbka0bV27a0Nmc0svy61PDdWPJF+WHiADHji+JCTR4sF+
         UKa1sr50cC/szb1dMb9vihhV/6X2GSN9gm/p3D24TpTW1EUcf4yDBWKjxk10dqy5WMhp
         OwKcWmb0LxxYTu/bnJNFo0pVR0bWq+1a9PYnnqSLPk5ofEnRAf9ReeXJlVzjL60t7pDv
         fSsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=drrH4tC7XgEO7iJFA3RlDB/YLJ6naq5j45KsyxXcD60=;
        b=Wq/VzCcsa5B8dEHDePLabB3UGGKSud1oSDIBG0DXfnM3SGIrnxJDgCvaIQCm9l2YV3
         4ZH86B7G1KxuzRzm9ITB8IOVC+wRqfwt2P7X+/lLBQGuCmh5Tc/gUnD+OH6TiSfb4Ihm
         JFPgqRysJS9VfJkJle/7mLZzLnuAELj08AYEzWP6fC1al23CUys8cOOkGHRy8KRfWwRz
         jpc5GaFghvzdkpVffLp6RGENTnhxQlJVXJNIxx+omAJ7lnLPnZJwxwAMJYPl1NwalOz3
         toPbft6N4ggYY37zT66OmXJBnWweUOohYLmUvgVgHr54y+M30r1f2bmKnUJ3zhD+xxd9
         yTmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mv2TyFVt;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p6si84784qti.1.2021.02.03.03.02.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Feb 2021 03:02:25 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 0F67A64F5C
	for <kasan-dev@googlegroups.com>; Wed,  3 Feb 2021 11:02:24 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id EA91365330; Wed,  3 Feb 2021 11:02:23 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 201179] KASAN: print global variable names
Date: Wed, 03 Feb 2021 11:02:23 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-201179-199747-EslDMNd7nP@https.bugzilla.kernel.org/>
In-Reply-To: <bug-201179-199747@https.bugzilla.kernel.org/>
References: <bug-201179-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mv2TyFVt;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=201179

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
This is implemented now:

        if (kernel_or_module_addr(addr) && !init_task_stack_addr(addr)) {
                pr_err("The buggy address belongs to the variable:\n");
                pr_err(" %pS\n", addr);
        }

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-201179-199747-EslDMNd7nP%40https.bugzilla.kernel.org/.
