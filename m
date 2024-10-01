Return-Path: <kasan-dev+bncBAABBTXK563QMGQEJMBGQFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A27798BD1E
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2024 15:12:48 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2e0e931537dsf4584738a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2024 06:12:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727788366; cv=pass;
        d=google.com; s=arc-20240605;
        b=h/lfJTeGWZIvijSHSAzDaq9R+ZhMNBKd7PF/FHmFa5T2ko2gnyifdpP+H6TzOG69eO
         vFwVp8gxDZlRTheanbzTKpP22MW/17t/T4raJ4jFfnUDp5bd+R4eSsqwNHpLCNk8J0ky
         2DVSl/XheyI5EKiWudTjGDKZYMZi55EPKbAwjCSvy8j/Ln3Gn/fzcuLH/xpGnT9HsZtm
         ndRP1csI93yz86QfZepA64K5empUaPYgdiHFrKVkJbuwhEoSP1eYcKnF+XoVVfmiYsl9
         Qijgy2KK6CFHDPBMUHQZOWUnR4rB5mJev+kLp3ckDn8mwWrjGzb91XvGB5GOFjztEeUg
         5Cgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=BlGwpOvu1ZI42EgKTtQQagzd4w0FrTrbvMvhFgtBRkc=;
        fh=ieKZqur1h/yLFIbL6W1Pka18WpgzlenfYGEVWaW2NQE=;
        b=OqGx3zmsH4qe0FqB9kdPN4Cr9JbfJ3ZSZUQFGE+ssJOJNdJrKLLlliCGqyHNhAnkjG
         MnxqWxw/VSt2X0OhuBU8xUBNLgkRDgmb4LWlKaNqm/eqvpIcR0VpvsLPXEGsxDo2jwiY
         h6+ogePUJA4QtPQL6S75ZDsbri7ApA36UzIEj95Q1exbKRQDLtsk/fkF0gzYhXW6Iye6
         I2aWz30wTTWPRNkVCmqMsVg3Y4pu8yjRL9woPWXveKAI7yG4YdyEIuGp34YGAd1MSoaY
         pEab9fErwHTcZwmLhHdUsQ4RJHFofrG24cNI07LMCU/Qg6QQqFIBwEzuyCoqZd+2dNd7
         6xRA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HPkhLGuL;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727788366; x=1728393166; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=BlGwpOvu1ZI42EgKTtQQagzd4w0FrTrbvMvhFgtBRkc=;
        b=vNhX3yG3ZpiRIJVA9UIPC5y6tNJTLMiNWiCr45465ks4qJVstnU1bYXYE9mWGhfduz
         Y37S3/9xn9sazDgc26xMQnT6AbuZm4JkN87FojVdiqHfN5ZGmLuDEx0pQ/jr52r+jIEb
         H/wzjDKgFFJswEa2hmtPKv7q5CyFXoghDZ7mL8LY4TZrtWK1uA72UXrTVAz48zB1Yox5
         RFynB/51ltoAsQSY4EJTWm9p2jM+HdbZSWKTkW4aucZyTaD4r0qVPz0QpedcXXPW/lhW
         XjPjta8Btr30UTATj8roWussMZSlzKig55BXrWOAxGVlJKmnW7GXw9n89cQXpuFU/tKo
         MvhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727788366; x=1728393166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BlGwpOvu1ZI42EgKTtQQagzd4w0FrTrbvMvhFgtBRkc=;
        b=ckjVfecYBpf5kE1EXWIka4iGGtNtEX06cvb57o58ZLAl5+rNWNgoxBenqViztUTWSB
         tH+8VxNKRxGTdc4OR7p4VjJFop9xcCNMDE/59wg9BQ3SIkdl34r75KwfN4cWelMwGphH
         GEYWaStCBiFxQXQ/Q/L0c4huVmvLiJ1dR7UtLvUBjlj/zvI+iChvsu7ug1Upc6ckkvn/
         D3ozE47wKm2XGdIzujXGp1awxBjXENqi9Sc1JWYIApoY29I9vxwkghFDCXkqg/XpAosy
         aYKxqd1vRteSK1eyzju/IptF4MohTq3WCCHOUnT8rpmIB4sW4zTQKIrI/9s73DLefMbl
         WbPQ==
X-Forwarded-Encrypted: i=2; AJvYcCVZSq3WcCI8ApAimoTMW72ZORMxCDvSzQxPrkPL2QcMYOPMhLXmpN8lqaBn08MnVFuoWdGUNA==@lfdr.de
X-Gm-Message-State: AOJu0Yy+Np/jCej8Hj8CvBuiw8MWkB//WOm7ipv/nrUdxpz85XBT3TZR
	kgTCc5F9A7Q6MKQbDHgBIBjpyIZveUW8Y1fvzC20ChKwJWMpEu5L
X-Google-Smtp-Source: AGHT+IF2ZXQEofs4pTczvZQLuMuesxGKW7O8Qpi5YjMVmhZ6LAwHmXD7aoJ3nY0JQYDihpkpDu4EfA==
X-Received: by 2002:a17:90a:c691:b0:2d3:d45b:9e31 with SMTP id 98e67ed59e1d1-2e0b887c870mr19126605a91.2.1727788366419;
        Tue, 01 Oct 2024 06:12:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e395:b0:2e0:82fe:e3f1 with SMTP id
 98e67ed59e1d1-2e090a5ff0bls4412451a91.2.-pod-prod-06-us; Tue, 01 Oct 2024
 06:12:45 -0700 (PDT)
X-Received: by 2002:a17:90b:194d:b0:2d3:cd57:bd3 with SMTP id 98e67ed59e1d1-2e0b8e97a8dmr18043441a91.29.1727788365282;
        Tue, 01 Oct 2024 06:12:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727788365; cv=none;
        d=google.com; s=arc-20240605;
        b=FMTIYMBI9882Onq6l2bzLBS462o1moPscOTeuD8IKi6l2qCoESCLiVnAYCHh4Rjd6C
         MTN6o5EGDFuYmGVkvvaXfB7rPh7FobLT6Wtt8lOmA4EREPPzGTuVtcdEV3DTkCSJStWY
         U9IMnArK/FlfAuRgk6z0EEBUHlQ1HXV+9Bea2JdNowps+rsPyHIdGy4mpTyFISwsOw3S
         liBk5cmuK0oUSlgXdt1FfthcetwFSviI38BeC0VWNRguGIaamU8uDhevZJQH6+xBsITk
         pLXDj0VCALRtNxJExDeICc0wurkVpr0rmrSWlS73346/XdDkLzwvQAiS+PQcWvRJn25h
         5EZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=KqUai3OawDYqGK8LlrjHO8ra43SIqE4eQn3Y3Yzz7HY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=aGtg+dyRbTVW9azNixTUiUbmgxevMwd+Y/dooz9x093xBySgeZrx+Z8uvBfhKnZQn2
         MrnM+tiCBobCK/wwlX5ZViIh2WqFb1u9VnqYeMOKlLMTbT+EEkZJxrf1jh0qYdpiHPJP
         mn4iTrODOdlQRD/YET3/1iw+xjaKDA9+msNS8fGqvEx90DNOqU+7Ja5HUW/lQP5+aGON
         6NvB8rzsZLWqcXc+uIkPz7cjMg/K5Rq2X9M5O6r8aYYFdx9kIsBWE3MLw0rwj4LZAZBW
         dct4SP6XE4hjLwTTJccHzXIMPqsIfh6uZ3CeFYFEGuIzp/T5Y8N/yjGkuIml5rNtheHM
         1SeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HPkhLGuL;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e0b6e1a2ccsi461123a91.3.2024.10.01.06.12.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Oct 2024 06:12:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id DF304A43697
	for <kasan-dev@googlegroups.com>; Tue,  1 Oct 2024 13:12:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C9B11C4CED2
	for <kasan-dev@googlegroups.com>; Tue,  1 Oct 2024 13:12:43 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id B2B67C53BC1; Tue,  1 Oct 2024 13:12:43 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 206267] KASAN: missed checks in copy_to/from_user
Date: Tue, 01 Oct 2024 13:12:43 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: snovitoll@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-206267-199747-heDOheXrnf@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206267-199747@https.bugzilla.kernel.org/>
References: <bug-206267-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HPkhLGuL;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=206267

Sabyrzhan Tasbolatov (snovitoll@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |snovitoll@gmail.com

--- Comment #4 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
I've made the following Coccinelle script (with a lot of help from
cocci@inria.fr group)
to find code where __user attribute is missing for
copy_from_user(..., src, ...).

I've uploaded results in my Github gist:
https://gist.github.com/novitoll/68328a0bec47ba1b3b8d2d8f0a76b663

There might be false-positive matches, I haven't browsed all of them yet,
but should be a good start for candidates who potentially might use
copy_from_user() for the kernel pointers.

Perhaps, there is also the option to validate within copy_from_user()
if the src pointer is from the kernel space, e.g.
`ptr >= TASK_SIZE_MAX + PAGE_SIZE` like it's done in
copy_from_kernel_nofault_allowed() to check user space pointers.

Here is the Coccinelle script I've run in v6.12:

$ spatch --sp-file copy_from_user.cocci ./linux
...
$ cat copy_from_user.cocci
// __user exists in parent function parameter.
@r1 exists@
identifier f, ptr;
attribute name __user;
position p;
type T;
@@
f(..., T __user *ptr, ...)
{
        ... when any
        copy_from_user@p(..., <+...ptr...+>, ...)
        ... when any
}

// __user exists inline copy_from_user() casting.
@r2 exists@
identifier f, ptr;
attribute name __user;
position p;
type T;
@@
f(...)
{
        ... when any
(
        T __user *ptr = ...;
        ... when any
        copy_from_user@p(..., <+...ptr...+>, ...)
|
        copy_from_user@p(..., (T __user *)<+...ptr...+>, ...)
|
        T __user *ptr;
        ... when any
        ptr = ...;
        ... when any
        copy_from_user@p(..., <+...ptr...+>, ...)
|
        T *ptr;
        ... when any
        ptr = u64_to_user_ptr(...);
        ... when any
        copy_from_user@p(..., <+...ptr...+>, ...)
|
        copy_from_user@p(..., u64_to_user_ptr(...), ...)
)
        ... when any
}

@missing@
position p != {r1.p, r2.p};
@@
copy_from_user@p(...)

@script:python@
p << missing.p;
@@
msg = "match !!!"
coccilib.report.print_report(p[0], msg)

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206267-199747-heDOheXrnf%40https.bugzilla.kernel.org/.
