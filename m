Return-Path: <kasan-dev+bncBCMIZB7QWENRBIPCX7YQKGQEPK3OWMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 1974914B0D9
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 09:30:27 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id l25sf8051489qtu.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 00:30:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580200226; cv=pass;
        d=google.com; s=arc-20160816;
        b=FpkuyrOwWtF7YI61qAmFzri+TgxScM9m6sRstNQQnnvorEzct51iJ1poIXrN71tDKZ
         6TDKDkcVTJLll/UvkqR9rJZsVfTNYsfCR4P9U11WKxNvGwmW5VFSgCyMvkQl+dgvSYeA
         ovwr8GDu8xQ1N0vivSOylYxnu5DfZUXdqoNB6Hay2h1yAn5/Y15uVII/DFNGAiF2AjFc
         QMl6D9rrSKr3KAAn708sn7z7jIKeq3PrLGenAmuth5aKYKnsBSbsUWYycYfWc/p6yOpQ
         bNsDw6RrQD6BT9dMwwaIjk9HAxOKMzxZQhhMO+YgKgyCLuubAFCLMO7hScnzgDZtzE2O
         sMhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LtPhV/d+PhlJ6K3GoVOnyP4gWU+P/i59JqKB/Ryiw18=;
        b=DDRlDAE7K0mOhKIciqJBa3fnKap5sObhzTfhpsqExSCRtoyT/f7FUS/KwY2e1v3R0D
         BZS/7edfcpbiQunIUw+sA3QuHHWXMQ5DPh5bBYOynd9AXTVUAL8OH5oreX9s5zc+NUaY
         QBiCHZHCAu4IGsiG1qouAuE1YCo166/E/Wp2OlPxIA1hq7lFwqrIwX3ODd6kXYF8TpHd
         Zefz5Fpxtr81im3MWpmd4vO52k2cDTWsJ0oEiOFT8d5AXHtI1GSoEcyOGdDbNSbcCDc/
         3xPaODSTeBev/DIikJQBJdj9NzxGsNmu/kIdGOMVveGcVqviVmidMGmgQDLaq41Hjnak
         7F3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IYFibCXa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LtPhV/d+PhlJ6K3GoVOnyP4gWU+P/i59JqKB/Ryiw18=;
        b=VHjQi1wQAEhZ9JE4eCAHxzJXX8gdNQIrJWGpDpvHpXVmmq/ZaRGlB/rsC+sS3V/cVx
         QokUPm/1BeS/DWwLqeYU8Aae4rNkrVsq0F5J2S7PSFnqCkVjligNIFhRASJBC4ic4VLm
         +7Wm/0v4cT/vid5QnyCiGH54YHRkpSOr+8IAQdNOVxAPuGoqJRw/46ZHxMHrdBAIV4NR
         fTKyq+u/NNeh2BHuQlrDQFhnd1KFK7SFkgH8SRgyXhO2rb2TSS2kHPQTqUZ8Lk+WVEAZ
         dQcBDjRFiBU5thZXkydr3I6WzmLiuvaENP5ZPKDD7OMq6tCs5QtRzMp4GsUmOqATWMQo
         Vkrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LtPhV/d+PhlJ6K3GoVOnyP4gWU+P/i59JqKB/Ryiw18=;
        b=KhTEqcwFG/hiFjzgpbJAGoZNR9HGZL71M9WDIprSIKkm3ysUjEc3EEY6TtXMxO4P3I
         U11KaU1EjFzb1uQB5AkKM/dnEytTjk6l3shsERv0xdj8EH3JrjAmQwDG4zYSvcSPQcet
         9l9Qezz4CwmG2hHqmcv1+zO7fDcltcCpGOvmysJ7gbMZKv5D9saAJlO+XKppa3lQGK5V
         R8UYAlosLjIHEJLaDL6jNvzNXNr2te/79PAKDQ1IcbCpL08aer+sD2pttuPCQsLJB7Cq
         IoXHcWrORtBtOwJQe+wWkW9x8cBk8BdauYzceCVq5+d/IAJlYFDJIot99P/ZAuubknng
         0OwQ==
X-Gm-Message-State: APjAAAUqzEsWVcB4KXOqIIryC6lxghleTY7qEzB55vzz4F1qZ6QzOnQi
	sVrGSE1/9Kh1yKShmKPAHD8=
X-Google-Smtp-Source: APXvYqxUhtOquAXkDjaLZqk66OTgQAjmGsZ793nGuF8eBzPcSWyA9a7zgnbGYNY8aAImHxgRoSXGiw==
X-Received: by 2002:a05:6214:3aa:: with SMTP id m10mr21299243qvy.125.1580200226059;
        Tue, 28 Jan 2020 00:30:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:73d8:: with SMTP id v24ls4514034qtp.3.gmail; Tue, 28 Jan
 2020 00:30:25 -0800 (PST)
X-Received: by 2002:ac8:6718:: with SMTP id e24mr15068155qtp.188.1580200225597;
        Tue, 28 Jan 2020 00:30:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580200225; cv=none;
        d=google.com; s=arc-20160816;
        b=blyvhE0GV76F1rE5tA5ondKILKTLjJtkqFqCl5T07F+Xnyo6/JdMeSs0JeyOcGSVty
         z6s6fwQpiHrKAcMGu8dd4oVVl2n28T/+TTT86Tcy0y+4QKbNOG/zOv6SsJX0R57z7vIv
         KbXbs7QXE4TWCTs17GiVkTjt23Or4F6Q42AkE4+l1ena229JmXlcEvgitnYo3HTDbCB2
         PimNIpPO2y49sak2Qs76LsNhbhVjRdjjCy5LHE7QANzzlnav0yWT1TmRlwYko3OHopai
         HN3WMVN4pYlqC0h6GphJ8gvzMbtjFnKmdNrdAoQJjgk8hBgoKhgGX/ZENKFiawwZOJjF
         ZHrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=72baebcEVhOQ+bbGAb5mc+gepoARnQnm+on/fRqMIj8=;
        b=bl8ClaPS8r4Z/usqCEzqI93o1eTwE2YqYndVlBhytTNo8Ygv6OmFQBOrXCQoaUO4t2
         zeRXt+aC+rdfiaGw2oN0hMvpM5bGa69Cb9aOo4FE3DCj+Q3bFR4fqd57mBVzvddCL1Ji
         zzSupq+yg8UmeP2M6SY4wQ3jTEMBDYYaNwAP+lA080X/nEueqPevjyjsMV2usPK31VV5
         HrR/OaRZi7ezCN3fyQSNWWOxt4T4T9FOmS2t4dbGFIqZ/bD0TKDfs9aw/55qGO018ElU
         rTK3FbR/ql3vLAPtrqU/0W9VD8t7gFL7cd8FFbihxljZZS/1xwMkripxGN6df6KuOSx0
         WK4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IYFibCXa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id r62si651184qkc.6.2020.01.28.00.30.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jan 2020 00:30:25 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id t8so4159206qtr.2
        for <kasan-dev@googlegroups.com>; Tue, 28 Jan 2020 00:30:25 -0800 (PST)
X-Received: by 2002:aed:36a5:: with SMTP id f34mr12158980qtb.57.1580200224944;
 Tue, 28 Jan 2020 00:30:24 -0800 (PST)
MIME-Version: 1.0
References: <bug-206337-199747@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206337-199747@https.bugzilla.kernel.org/>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jan 2020 09:30:13 +0100
Message-ID: <CACT4Y+YER0N9XoGCRukpknZfN8EKNGjS=sJ4cEVcKy5RmC5o5A@mail.gmail.com>
Subject: Re: [Bug 206337] New: KASAN: str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT
To: bugzilla-daemon@bugzilla.kernel.org, Gary Hook <Gary.Hook@amd.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IYFibCXa;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Jan 28, 2020 at 9:25 AM <bugzilla-daemon@bugzilla.kernel.org> wrote:
>
> https://bugzilla.kernel.org/show_bug.cgi?id=206337
>
>             Bug ID: 206337
>            Summary: KASAN: str* functions are not instrumented with
>                     CONFIG_AMD_MEM_ENCRYPT
>            Product: Memory Management
>            Version: 2.5
>     Kernel Version: 5.1+
>           Hardware: All
>                 OS: Linux
>               Tree: Mainline
>             Status: NEW
>           Severity: normal
>           Priority: P1
>          Component: Sanitizers
>           Assignee: mm_sanitizers@kernel-bugs.kernel.org
>           Reporter: dvyukov@google.com
>                 CC: kasan-dev@googlegroups.com
>         Regression: No
>
> The following commit adds the following change:
>
> commit b51ce3744f115850166f3d6c292b9c8cb849ad4f
> Author: Gary Hook <Gary.Hook@amd.com>
> Date:   Mon Apr 29 22:22:58 2019 +0000
>
>     x86/mm/mem_encrypt: Disable all instrumentation for early SME setup
>
>
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -17,6 +17,17 @@ KCOV_INSTRUMENT_list_debug.o := n
> +# Early boot use of cmdline, don't instrument it
> +ifdef CONFIG_AMD_MEM_ENCRYPT
> +KASAN_SANITIZE_string.o := n
> +endif
>
>
> This is way too coarse-gained instrumentation suppression for an early-boot
> problem. str* functions are widely used throughout kernel during it's whole
> lifetime. They should not be disabled because of a single boot-time problem.
>
> We probably need to do something similar to what we do for mem* functions:
>
> // arch/x86/include/asm/string_64.h
> #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> /*
>  * For files that not instrumented (e.g. mm/slub.c) we
>  * should use not instrumented version of mem* functions.
>  */
> #undef memcpy
> #define memcpy(dst, src, len) __memcpy(dst, src, len)
>
> Then disabling instrumentation in the single problematic file should help for
> direct calls (I don't know if that was a direct call, though).
> Or do something else instead.

+Gary, I can't find you in bugzilla, so CCing here, but please comment
on the bug report.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYER0N9XoGCRukpknZfN8EKNGjS%3DsJ4cEVcKy5RmC5o5A%40mail.gmail.com.
