Return-Path: <kasan-dev+bncBCMIZB7QWENRBB4MQTZAKGQEU5M77EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id E4CA1156FD4
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 08:28:08 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id q1sf4757060pfg.2
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Feb 2020 23:28:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581319687; cv=pass;
        d=google.com; s=arc-20160816;
        b=ruw0tKVIZrHOBMNOaJt/yPpXOp2Jjleo6HYdWBtuxZRGUjp8aig2nN14YJDRuFc5vz
         8cLcaq/ynHMwmD9pTRFPRVIg+ApKauTftw/ueGM4tPJF3h/+HhmxrWMdPWiLbLaZ7ZKY
         suM9EZ2insefSj4iDqz6fK4DcViVCU8eo0r/CoQGW83lE8dTlcj00Cvwv8QwMJcA0LF+
         KC2sQARH6vZ7Cm4K7npE5jO67+JTqfBSeKwQRveAxsPWmxASnETkBdGSH1o6q3RcRAw4
         FQpbQvWK+NLJIbcVVF9zlZUwwblh8LRguI+9r/5DQtE6U+n1CL+MMSZtzLqTCOutoF90
         apqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=keRKLHqdshTjKEXFMHY8gcu7goMms3u65eqfsvl5MvE=;
        b=hKnC7HNGXTESjhaogdoSnby0Tl+FQKmPIZ3bdGyfLgzvKPL5qlEyK4PBXkzKePqaw9
         TLDCRWf1bhUIeAfRRd6clyy8Sa9S1J2XVleUTpeu06ekGRBpYRY6lfRobvKRRQx3Bun/
         C3d44TMCYKpIchG0+gcaQnrgT02/Z1tOS4+iP9sG/W2Gof5OQCq8JIQywpvoRtCK5PZ/
         qcesm+XY8rLBSEXn5qMdAGwTuN8SXqgDc/GwbW/WxblxQceTGp553VzeWlRANlSyaXEa
         zVm9+VH6WSchm2K382qRoBCNixyECOdyZeaSkwhnRxQ/ocfS0V7mM/O+q+QZqL9wIj2j
         9Isw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KzcOIJTh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=keRKLHqdshTjKEXFMHY8gcu7goMms3u65eqfsvl5MvE=;
        b=fgMCMQaB82O1Oyw1NAGBz2ywE11u+XqDuRT+nJCMeefpC1ax7Yll96ghzEbVhtoWJM
         qoHf8KMrrQRwcAEbF6tWAy4HyWATPRBtIOvRk4T05uKE8qjhUUq177Opew8QOQKiTZbm
         JFrC0b6fFI4XwppN6GwFgYPBdHjDGqSphhFd5y3uXGxzPDoERxhivCyq6DIYybzT+/I+
         vwd3Z17RojFf2HP7pH2dLevb52kD0jqClYf7cseEcNDzpKTCl3F/KMr4wPmotx/HtsOQ
         P+caYMOsjjrC9qrJ8wwOINIYxQ8kXlJzHK/RDCiNJUedZhcl1mschOwzprYTt7lCd/nn
         k7cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=keRKLHqdshTjKEXFMHY8gcu7goMms3u65eqfsvl5MvE=;
        b=QC9Q7VLSpTSRvDCJ9WQWaccMdInjMALkV5kWKepZVnNt2ntY+rHcBFEUJN3+FeBC5X
         +czDVJCu8N1CGwfWtRjcIWBBaxT6LVuVBvt47pwWvAzH5qvk98UlKq1zA6X5yBJu8loN
         Pd1aWEGAD9TR7rfYGMfSfVfG4u3OBI+xUHQ+mDtGSEupcqCBXdXY/i8oyVDWnZ/i8OTA
         rRYk1fu/u8Q6vSdJq9DshJJevpIBOuqRmx6/Yk6IzRCQB5LA67wERRaoE7h2IaPyXsKZ
         EeL0k0IeKXpmmNotkVMBsc/9QBXwmFzdv6pdnV7/raJq6sB8woaupQjq7pVlf+8vp90Z
         loEg==
X-Gm-Message-State: APjAAAUHLuaF3jqWvmDKH0xh3G6Vqk6yk3IWtXkMQORe18YQ0nbZRv9e
	Ty7IX6Vp2UOK3k4rYLfs1E0=
X-Google-Smtp-Source: APXvYqxdozlRyRjtaKuw2jCb9tMmAabOK9IZivhcxaq1vkTBGg0bfpp4Iz2mO7RSnUZ/ISCURkZokA==
X-Received: by 2002:a63:d0c:: with SMTP id c12mr255158pgl.173.1581319687582;
        Sun, 09 Feb 2020 23:28:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9f95:: with SMTP id g21ls3442246plq.5.gmail; Sun, 09
 Feb 2020 23:28:07 -0800 (PST)
X-Received: by 2002:a17:90a:26ab:: with SMTP id m40mr226033pje.42.1581319687145;
        Sun, 09 Feb 2020 23:28:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581319687; cv=none;
        d=google.com; s=arc-20160816;
        b=LdxHaOvkYHC1lq+Edy9oc6gWdg4lYXxhvRa3KdVuT3yzsNWkKyPSF82pbXSC+TIuWd
         bJolm7RefePEMhs1tqqjRAOrkze7OOeFDGA0Zk4eIf0JZGlOGWyK92lMHUEEIcwtTNaM
         SFEnROHre+6n1boRn0E6ATRaHJfCzb6DQ4tvbthzIiK+WL3XgrJ+/dy1g7HF3G3APPxj
         Y6Cq+mqjsGky/GeLbxHriZ5zgUs8tMwlBCtUiNGVKymUjsjZljgzxnu41qxaiyYsuhGc
         Bc9tvo5c7vc/TLh3dvXG5F5bH7NTZ1iglW1sQuO5bEYPgO0UoLRLdbRO5c5bwgscvBNZ
         yG/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9aJSYcVShjw9Lb0CxygRCx6IiLyoO1qzlgwQMvTtLho=;
        b=l92wvLaXnaseU8I9QSvZm9LiG4i8JWOHSLIbs1YED5EGxXblOB+5EkEnsRF5gjiHBL
         h1w2zPSYU7a/9hEyE2CBAdEQTKl0W5FP7btFICgegSmMLZVEvjMNNLLnf1cMdzpbnsEh
         YhG454W0Jaxb/+a5fNDIe1F0T76coLqd9NKGS/n57OOA7UIGomYNZnR0MhqtpZSeram4
         15lR8Q4X69bZjOSO+2IdcFbGqsCpVlWnf3bjyc2R9WjI1P3h+f12s0vf6Q/PJ/QuUngB
         UiI8E+ZUwxc7hL/cS6X3sV16gBGgFBkTh7mh8nY71v5dGr0Ifuu6qcGC2qjwGgwNGTKm
         9PjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KzcOIJTh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id 59si267631ple.2.2020.02.09.23.28.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 09 Feb 2020 23:28:07 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id h12so4459619qtu.1
        for <kasan-dev@googlegroups.com>; Sun, 09 Feb 2020 23:28:07 -0800 (PST)
X-Received: by 2002:ac8:71d7:: with SMTP id i23mr9011849qtp.50.1581319685983;
 Sun, 09 Feb 2020 23:28:05 -0800 (PST)
MIME-Version: 1.0
References: <cover.1581282103.git.jbi.octave@gmail.com> <1eca01a2537e0500f4f31c335edfecf0a10bd294.1581282103.git.jbi.octave@gmail.com>
In-Reply-To: <1eca01a2537e0500f4f31c335edfecf0a10bd294.1581282103.git.jbi.octave@gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Feb 2020 08:27:55 +0100
Message-ID: <CACT4Y+b61vEqw6t-deuCyZvDoqg2HTRUdVKi1RBcpen+0k0QDA@mail.gmail.com>
Subject: Re: [PATCH 09/11] kasan: add missing annotation for start_report()
To: Jules Irenge <jbi.octave@gmail.com>
Cc: Boqun Feng <boqun.feng@gmail.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KzcOIJTh;       spf=pass
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

On Sun, Feb 9, 2020 at 11:48 PM Jules Irenge <jbi.octave@gmail.com> wrote:
>
> Sparse reports a warning at start_report()
>
> warning: context imbalance in start_report() - wrong count at exit
>
> The root cause is a missing annotation at start_report()
>
> Add the missing annotation __acquires(&report_lock)
>
> Signed-off-by: Jules Irenge <jbi.octave@gmail.com>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  mm/kasan/report.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 5ef9f24f566b..5451624c4e09 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -77,7 +77,7 @@ static void print_error_description(struct kasan_access_info *info)
>
>  static DEFINE_SPINLOCK(report_lock);
>
> -static void start_report(unsigned long *flags)
> +static void start_report(unsigned long *flags) __acquires(&report_lock)
>  {
>         /*
>          * Make sure we don't end up in loop.
> --
> 2.24.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb61vEqw6t-deuCyZvDoqg2HTRUdVKi1RBcpen%2B0k0QDA%40mail.gmail.com.
