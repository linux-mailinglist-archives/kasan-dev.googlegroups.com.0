Return-Path: <kasan-dev+bncBDYJPJO25UGBBQ6FTP3AKGQEL3X7SCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 815881DD82A
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 22:21:24 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id c20sf9040511qtw.11
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:21:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590092483; cv=pass;
        d=google.com; s=arc-20160816;
        b=FeqdVGn8qMp1w98tU+DTP1sQBgGtLU5xA3DwEBgAglbN2Kc/oTqymL9cvWMSE7jRdN
         odEgIyd3JPbeFsQyK0udyZvSPgBgM1oRbnU0GbgihXyuyjTrTywldJCJHLmiJg7s5Jq+
         JF7AGD2sVJhcGZgqs2B8bzBV2kvqrMvCZ6GIUMbGgPF572H4XnbEep6Jvv8wM27Kp2cr
         14GxTrXX+eBp6osHtFo0VZHzIfKEZpwYtqDeP5JbqMiloM0w61v6BuA+s3fN3qmNISkn
         pBTALkFEw47of9KAmxHakLlFf5SXGJcZLIiZbMws7qrSHHYvw+0V6uob9ay67CZMHaLj
         AAKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6WWNDGIFXZMY3KB5lSxyyvi4r3ptngeBo/ZNdp2UMPg=;
        b=xr7rj327qcAtNlSP+d2donYf8H52dZ7OHazxfufvO6DAHOtFWYJK+/fdAcLLURT3hw
         yd5dtA3KPRD/JCBIED6Odid/k0Djz61vCLTGQNPcew02qw6s/nLJ38dD/C3h101QCQ4O
         A4E0XrqCJulLOgrCqxdT63xSAdlkVcWKG9UmtKDLhniGHE3C9bo5GWSTet2zUe5zUcl1
         1j62bTL/AKZRL8gFDyRn0pzLzHSldIZXqJ4bLSAHhT1h7++m5abN0p/U/JCcY+1T1WrI
         1TTqy3CuPeiTCiRSD9Vz4L7ahUZTlT3y66jLR8TJtt1NvCR8NaqgUhjZGNIuaI67231R
         1WEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e0O+txBU;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6WWNDGIFXZMY3KB5lSxyyvi4r3ptngeBo/ZNdp2UMPg=;
        b=ije/V82bklE9+So7FWLzLgg7TQPL0gOo1ZClu1vYsNnWLdH9rfVGFGiZa88ZQEwO12
         qz8WAY+xENqMDjHlyDdbH057JCrmunsZ3HOoPXHQ1JaQVRE6IM30qsj9BXGUGl+jL7TL
         aF1OH1bln99O3n9Jy8rZhE9Rt7ElUp5N2pd9R0vZ1bkLwMvd9vnlx5dPcBrCtZpQr8ke
         r5R27UzfDRmwuPruPdmPduAVDjdp/nN2ifeh/DADuoiWdXQnf59U/sI6ff6vB0GSxxaI
         gecsMFfXqIep9RgXcxWhqM0DA0ZW7Avc9cyJ73V1/XZKvmDAm6nIYEL3JTmC/Mbizsek
         HiGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6WWNDGIFXZMY3KB5lSxyyvi4r3ptngeBo/ZNdp2UMPg=;
        b=kUEJ3zAMg4Z3im0gjtzRdG5aLh8cJEEYXtqEtFQQBDeqZXxl9mRB9N16j3dL5CUIDE
         1rr1w/MyVhmZnGEY/4ijCeHvMutrmV5EvBvgbVK0QQ25TBVN6GTBB4X/P3bbiaz6JW4u
         NMYmQvwBc+aGwDJ6F+UVfHmFcJIzOsfS5mq1uMdgm4bl76XuI1TFPOwUd1lb/0vLQWe6
         l+yh3UwTmC0YhFtPq3Zf04tEibdmsKMfYsTE5vbUXPON8LS1754C5OVOZzAj4yiIjbVd
         WXB7VP1Wj/zE4FgbDLFgnjMwoWOHhE8/xAEytcPk9o5GcnDNMiiesV/hJ83Pj+QQ9+Vt
         SWTQ==
X-Gm-Message-State: AOAM531UHvqTzpbVmCMJc4wnr7ZzjF5IVuHcfslD6RCOp9dFKWF5Q8y2
	MDidTMHaERVJl2F0ZNuKjwQ=
X-Google-Smtp-Source: ABdhPJz7fKzNkvX5SxFlJr1M+4SOFERmoFWIVeTiL4b2yEUhNgu+B3Qc+i9ookZo0ykHgz68FFEbbA==
X-Received: by 2002:a05:6214:1265:: with SMTP id r5mr453041qvv.171.1590092483095;
        Thu, 21 May 2020 13:21:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:2142:: with SMTP id m2ls1649176qkm.1.gmail; Thu, 21
 May 2020 13:21:22 -0700 (PDT)
X-Received: by 2002:a05:620a:13b0:: with SMTP id m16mr11839069qki.353.1590092482798;
        Thu, 21 May 2020 13:21:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590092482; cv=none;
        d=google.com; s=arc-20160816;
        b=uPAydFczlJEzdD4J5PfMVJ8XLPSc1eerqXgrPjJJ/7Qx9ie0SRRf2VqCrTywWKe0fC
         wgnqdWlJ8kjVsq5LCIWQgUhBwH2XM+hUl/zQNqvMnhNTNEhaRVqPlTJwtZIslSQxGDZX
         kEe3690xR3iHGs1Rbg/EAh9KYaCvFYKVwtJAfjq6maZk9OOXDlDIwV0n7mcgEpH7wbyM
         yEF9qEBTwYUgGY4U3L6FpXvCXsGAYJw8MPOaUb8qrIFPVjQErMAG2gK7lDhPOzwP6VIj
         wjSMuYjGRQcGGX4aw81VxSLthrJOfQEM11awqBXbO367AIV/kHbb10Xai47wP9zk8Ibz
         SvuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y0yJ3RFZMM+B9sO1n4irEzcjxiMNA5r+ntERLJo+fSQ=;
        b=ckUQCXMyz24yaZn3FqcpKWiIlzEiEXYdOkd6cxD+yv3Szwo3+zPspUmEEd1PJu5H7M
         QXq9z1A2pbdeB1HX6kJJ7RneL68ElwCdkUu9Xt6cksrIQmeKhwraQYQocPVUqr4Gxtmb
         9Z9/aE0pt4S/i9TTfwhMfqTHB8bYoA8g/eN/ng5/ZCw4qkqpCZqSAFWG4abY0XSCKDDz
         0L9y5ys4xKg75ZkXvd8KEERY0WyAojwZ7eowtF8GsOvulm0lasCd/8cCY/N8UyVM8aDm
         ufEVUZF4y/oYtsfCA1Bh+TivYvLonr0brfR4y6KWfnvGv4yNPKmom8Vwlz5O2Nk6P/31
         DSsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e0O+txBU;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id e20si191049qka.1.2020.05.21.13.21.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 13:21:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id t11so3803698pgg.2
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 13:21:22 -0700 (PDT)
X-Received: by 2002:a63:d010:: with SMTP id z16mr10089185pgf.381.1590092481542;
 Thu, 21 May 2020 13:21:21 -0700 (PDT)
MIME-Version: 1.0
References: <20200521142047.169334-1-elver@google.com> <20200521142047.169334-10-elver@google.com>
In-Reply-To: <20200521142047.169334-10-elver@google.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 May 2020 13:21:09 -0700
Message-ID: <CAKwvOdnR7BXw_jYS5PFTuUamcwprEnZ358qhOxSu6wSSSJhxOA@mail.gmail.com>
Subject: Re: [PATCH -tip v3 09/11] data_race: Avoid nested statement expression
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Will Deacon <will@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=e0O+txBU;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Thu, May 21, 2020 at 7:22 AM 'Marco Elver' via Clang Built Linux
<clang-built-linux@googlegroups.com> wrote:
>
> It appears that compilers have trouble with nested statement
> expressions. Therefore remove one level of statement expression nesting
> from the data_race() macro. This will help us avoid potential problems
> in future as its usage increases.
>
> Link: https://lkml.kernel.org/r/20200520221712.GA21166@zn.tnic
> Acked-by: Will Deacon <will@kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>

Thanks Marco, I can confirm this series fixes the significant build
time regressions.

Tested-by: Nick Desaulniers <ndesaulniers@google.com>

More measurements in: https://github.com/ClangBuiltLinux/linux/issues/1032

Might want:
Reported-by: Borislav Petkov <bp@suse.de>
Reported-by: Nathan Chancellor <natechancellor@gmail.com>
too.

> ---
> v3:
> * Fix for 'const' non-scalar expressions.
> v2:
> * Add patch to series in response to above linked discussion.
> ---
>  include/linux/compiler.h | 10 +++++-----
>  1 file changed, 5 insertions(+), 5 deletions(-)
>
> diff --git a/include/linux/compiler.h b/include/linux/compiler.h
> index 7444f026eead..379a5077e9c6 100644
> --- a/include/linux/compiler.h
> +++ b/include/linux/compiler.h
> @@ -211,12 +211,12 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
>   */
>  #define data_race(expr)                                                        \
>  ({                                                                     \
> -       __kcsan_disable_current();                                      \
> -       ({                                                              \
> -               __unqual_scalar_typeof(({ expr; })) __v = ({ expr; });  \
> -               __kcsan_enable_current();                               \
> -               __v;                                                    \
> +       __unqual_scalar_typeof(({ expr; })) __v = ({                    \
> +               __kcsan_disable_current();                              \
> +               expr;                                                   \
>         });                                                             \
> +       __kcsan_enable_current();                                       \
> +       __v;                                                            \
>  })
>
>  /*
> --
> 2.26.2.761.g0e0b3e54be-goog
>
> --
> You received this message because you are subscribed to the Google Groups "Clang Built Linux" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to clang-built-linux+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/clang-built-linux/20200521142047.169334-10-elver%40google.com.



-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdnR7BXw_jYS5PFTuUamcwprEnZ358qhOxSu6wSSSJhxOA%40mail.gmail.com.
