Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW7ERGIAMGQERIEEV5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 825744ADA14
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 14:38:37 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id hi22-20020a17090b30d600b001b8b33cf0efsf2219880pjb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 05:38:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644327516; cv=pass;
        d=google.com; s=arc-20160816;
        b=X/5Y7iuyTRWxvpJiVh5Nsp2ev8Z2Xecv9xRSead3WYrtn15mCzg4WgFG9apcnjTDKp
         14MVFdlv5z4oTXJPurhbzOYndjSqfEBZM3WawHuO8wGkuVPI3pmTpFx8StogiY7Nrbfy
         FSZd6n9CU0m1L6sECJJOM2TLqudQ269AaWNwfXYiP1W4v7Y/pf2O0VCT7B67eq/UkHFA
         lKRJI9FRxbhIXx4LoH6ePHwdryjoefqqKfgmjbKjJ6r0CpZUPg+o/l+p7Pc7Qef1rdw8
         70R2llEZ3uLdxjAYOJ88RFjldW8sXmufrdYOTXmKOAG5rt5TOpRcvovVs3UWLjnc9xST
         CFfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=t5bvTzoHFcgDA4okLw5wDliFo33ndihkFjheKw5Bue8=;
        b=TmnHZf5H/kW3/c9Eq3y7gRnhgw0LHynF9ogCJLZ+I2YG6M80nEocExtXWtZkZn8v0f
         w36CAJktxs/V17uy5xm5/CO5zLUP0dG+gH4pb8lpKiqzlBnxebk9/uE7ZR8shswc8RRp
         u4cWBbsx3JEPjjgodCx909psDneuO7tVtD12zGDlrRS4v9P0lct2Rzv1qd8NVjuFDmuU
         veSOW4LMy+CQwQy0DNi0W3r6N2BEmPx94gvV0PN18rBn7dSzg4rL8JDlU20p7ZxGG9Lq
         836BM1/VEBZwkrD+vV2G1ua6g5EgJHsOPmU+PjtabC24MA/bzhfqCL7cQuhxLaw90uRL
         /lHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CuYzNlzS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t5bvTzoHFcgDA4okLw5wDliFo33ndihkFjheKw5Bue8=;
        b=cQ141tvBIcJlN3ecKecmmzpy55yS5CPGoKMIl4KY7pbIcxfaF9K4pHIoc9xxA+UJoe
         BccIwK7WxajDMJxkkDM/ARYDAs1MDSjrk7V7wnv3pKZ7jjYBAc/+arGBqztIGnwXnHFD
         H2aTGxISL9HYThan6L5prPwFGyvB4zkFWizbjVxraOTwFO2EyAr+Hv7nxe1JHNz5lw+q
         0jokK9EfDoIdulI+9IUJPLgR5iyyPeCQNu3+Q3lbMKwsKmAOMTHUu34h9Tce3PBp16mc
         3WNUwCFS5aHT/gqLAo/veoTzYy+PXGJKfQOQVTlFfwZjv5fSC5dXsyZUQNVmjmG0DDqW
         RRiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t5bvTzoHFcgDA4okLw5wDliFo33ndihkFjheKw5Bue8=;
        b=VJval70zJ+1/wUT0j2mfNA1PIbFTsDvjze1LPlhuccCT2BpoCjc1p0JOYUVBXJ6C+k
         Sa4Aw0KKBm5cmOL1Qw3mPCWPuL8oyrMbulcwyDWBhUutnLl4ny9TfR+DUEIqFH1UInZl
         DQxgpQPulFuznfEwWp2BBjXrwI0PQcqte8hAZhsq7rG3J7jIZt03ylVCZ1tghcJ426C+
         eIZLiOxuEdMbRR81G43n+M0pl5ALP97UqthKTms1g5YYB0356t8jzGcjOt629A3QQFBV
         aptwn2xkqLCEPnc+URSWxVIqnm6bDYl7K0szLu7iyzYG0gA2U0D0TY8grdMKE3a4ScuW
         i+Mw==
X-Gm-Message-State: AOAM530mxmhfEgqvsF+9fKY2w8WRB1/d5wmyU1M9B5UvjFMYGdmwrDzf
	MhY5zOQFG58jdJSlDDG0j3Q=
X-Google-Smtp-Source: ABdhPJwkboL/kitvKuZm8hNqHBGqq/XuLzGGkIUqBiSwr4lthFtVzx2tD+Kj6UmDgq/oxgMTi6IN8Q==
X-Received: by 2002:a17:90a:af8c:: with SMTP id w12mr1433923pjq.153.1644327515822;
        Tue, 08 Feb 2022 05:38:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f542:: with SMTP id h2ls1961990plf.11.gmail; Tue, 08
 Feb 2022 05:38:35 -0800 (PST)
X-Received: by 2002:a17:90a:ea17:: with SMTP id w23mr1452153pjy.2.1644327514938;
        Tue, 08 Feb 2022 05:38:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644327514; cv=none;
        d=google.com; s=arc-20160816;
        b=xTKo3evflR84BuEUfhucveqoZGUd9DWRZQa9WiWciHfSq6IHdK8eXaDSfBC/KEjHLr
         c3tbB8BF7FPIb8nLHCtftBpheglW5U9Se1Ur5B/0OICS5UwTHyBW/a+ei8qC3nUcvjs5
         Qq+Ph82eJpSLsCnALffeBG3FNq+BcE/B50kQ0fx28qTxRah27568TNki/ND2vp0uM5B5
         0e+kDIHG6+5VC8HqSvXVNrvNhD/z4u6zftqyJ2K/GZ3ILG7wDmT9DQaH3jYG+zKhxTWF
         22WhXv0jeVXDOoZkTPSicljA370OJSj2j41EdOcMzPqf6jeZ//QsJAIO1TYOxLG1+oJs
         4yUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aozwudC/vcOos+T4XrEal3CEC5loh3pS7gEJzCAbFj4=;
        b=N/rQ4HXez3m3u1dvcFgJdmRKsW9xVVBZxj6HLbHxiIS3WuZDEdpVdnODFCQvc30iM1
         6XAIunKU+7uPv4JV0ZI/YX2GobEqsjp+phyclaUu0/tDkE64lJbciggTprKsJuBBopZF
         ZLCYhXfvgCSKaft4d2RWEgsRsu7WiSVAmouksTqsRZBkf6xx/iNGmap5kxvhUlE58Tnh
         +w5X1DnIdurvu0utrXyEko/HyT7NZtLHE/B/mrhidFJ0PHg7+XCxyPTUuZyc7lLCtjcL
         TzG2SxSVRYpoVocwfZ1hi4jmjx9dYVWFvHgN8fDQbhj0bn0o72twkaCpgtzJ/IBRCnkW
         rtHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CuYzNlzS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id bx19si101477pjb.2.2022.02.08.05.38.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 05:38:34 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id p5so49782910ybd.13
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 05:38:34 -0800 (PST)
X-Received: by 2002:a25:cc54:: with SMTP id l81mr4366915ybf.236.1644327514316;
 Tue, 08 Feb 2022 05:38:34 -0800 (PST)
MIME-Version: 1.0
References: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn> <1644324666-15947-4-git-send-email-yangtiezhu@loongson.cn>
In-Reply-To: <1644324666-15947-4-git-send-email-yangtiezhu@loongson.cn>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Feb 2022 14:38:22 +0100
Message-ID: <CANpmjNOySkeK6u-JieNBQ4DmAO3LogdZ6gXv1Noz8jUOi3ThDA@mail.gmail.com>
Subject: Re: [PATCH v2 3/5] panic: unset panic_on_warn inside panic()
To: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Baoquan He <bhe@redhat.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Xuefeng Li <lixuefeng@loongson.cn>, kexec@lists.infradead.org, 
	linux-doc@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=CuYzNlzS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 8 Feb 2022 at 13:51, Tiezhu Yang <yangtiezhu@loongson.cn> wrote:
>
> In the current code, the following three places need to unset
> panic_on_warn before calling panic() to avoid recursive panics:
>
> kernel/kcsan/report.c: print_report()
> kernel/sched/core.c: __schedule_bug()
> mm/kfence/report.c: kfence_report_error()
>
> In order to avoid copy-pasting "panic_on_warn = 0" all over the
> places, it is better to move it inside panic() and then remove
> it from the other places.
>
> Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  kernel/panic.c | 20 +++++++++++---------
>  1 file changed, 11 insertions(+), 9 deletions(-)
>
> diff --git a/kernel/panic.c b/kernel/panic.c
> index 55b50e0..95ba825 100644
> --- a/kernel/panic.c
> +++ b/kernel/panic.c
> @@ -185,6 +185,16 @@ void panic(const char *fmt, ...)
>         int old_cpu, this_cpu;
>         bool _crash_kexec_post_notifiers = crash_kexec_post_notifiers;
>
> +       if (panic_on_warn) {
> +               /*
> +                * This thread may hit another WARN() in the panic path.

Alas, this may actually fix another problem: doing a panic() not from
a WARN(), but then hitting a WARN() along in the panic path. So
"another WARN" is irrelevant, just "a WARN" would be enough to break
things.

> +                * Resetting this prevents additional WARN() from panicking the
> +                * system on this thread.  Other threads are blocked by the
> +                * panic_mutex in panic().
> +                */
> +               panic_on_warn = 0;
> +       }
> +
>         /*
>          * Disable local interrupts. This will prevent panic_smp_self_stop
>          * from deadlocking the first cpu that invokes the panic, since
> @@ -576,16 +586,8 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
>         if (regs)
>                 show_regs(regs);
>
> -       if (panic_on_warn) {
> -               /*
> -                * This thread may hit another WARN() in the panic path.
> -                * Resetting this prevents additional WARN() from panicking the
> -                * system on this thread.  Other threads are blocked by the
> -                * panic_mutex in panic().
> -                */
> -               panic_on_warn = 0;
> +       if (panic_on_warn)
>                 panic("panic_on_warn set ...\n");
> -       }
>
>         if (!regs)
>                 dump_stack();
> --
> 2.1.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1644324666-15947-4-git-send-email-yangtiezhu%40loongson.cn.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOySkeK6u-JieNBQ4DmAO3LogdZ6gXv1Noz8jUOi3ThDA%40mail.gmail.com.
