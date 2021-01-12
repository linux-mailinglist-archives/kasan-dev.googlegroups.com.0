Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJN46X7QKGQEMSME4BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3286F2F2A04
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 09:30:30 +0100 (CET)
Received: by mail-vs1-xe3a.google.com with SMTP id a18sf262306vsp.9
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 00:30:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610440229; cv=pass;
        d=google.com; s=arc-20160816;
        b=ReyNZbRUQM9kjc4THk3poeoUlFK36guZJ9T3tVDTc6b4zYpG5+DKYQOOyOCOwzOiz9
         KJUfG/5rnNuz/7HJlaqFXN0q4kDAfWcVW/q+xwvKuv/usRZE8xVwnrUE3fZD8QLARWvA
         qQVBQs1PoNfFP9qOB9OBcAXi/JOjG8SZ/LuW8lsz+/1LCgHGo6NZvl688khMKArUb/e+
         t1+HFqu+jUNOm1mipZ3gMNvsghbRJ2w9Am7kqOX0ZlQVzwWnnSl2WC6RVtrZ/cpCIPLm
         4NrwwnQjVxA8iPBTeh3buhmKOkN7TfHVm0we9uknXRcGbO0vJFg2aEusUKo0tXsWGn2g
         0A9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=56TuyPzNmGoe5/QyPPDibNtPlK2qU6TbN5S46DubQxQ=;
        b=VRqBCh3wtrz9T/M3CTDWMpNrVBJYrNiEUoLrhJeWwJGS/j5UJKwHq/udJDkIUpUGSd
         vba1/ohf4Eg5WFSL2s8GpCr+FPszcyjnQSaZYuEurvprCxYtK7Ua4/QteLGF/Ia/xpoF
         Op+KtVe/7Cd9HFYdUlWl6j+52NxMu+hKeqFSBhGBVrhvUVns03/QKs2UWw0P9LnDe0lJ
         sSSj9gJunIvJzIBQgJrVr2gXyfK++edhe4NFPKVhxDtOmH0WdaPU7Jqs4pTV9VO2S5Gu
         gWSBM+mJUNnE4GycVt9aWz/3Dt2zGoCbIA+dEqkjhMNYjmb3itbYGD+Wa/LXreq6+r7h
         qSkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="H7l/xBso";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=56TuyPzNmGoe5/QyPPDibNtPlK2qU6TbN5S46DubQxQ=;
        b=I6OsUBeKEnOYNRGJ0+gfSUj7eesBdvCE54khmAYHUZFZuCYWBtbUlEPnvjsMqckNk6
         gC5/i6ij7wA0/tbLmWxqRs9Vmx/5rP+9k4pgIRiMjfED3C6RaFZvjCNngdg48KJlkywL
         1iU7HVzeI9Z+ixRNF/twH/UAIbittY+mUYgrasFQzBSO9z3AiuArMMeJoioy/TTvyG5a
         mrO8sHwPwxYfe5w2S343ONZJjF+4OR3sCEutfKcWfK4lloFl2ghFMPkaY2/M8GpE1l7R
         KCoaJcqmMlyLyfFlnpUdXsqfSQdUrX7k4xFkqJMpFN3AtzjHrxfCosDfURO73FUXsZ8M
         ZV7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=56TuyPzNmGoe5/QyPPDibNtPlK2qU6TbN5S46DubQxQ=;
        b=rVRNgYTTFSS9Nx5PtwbORM4K7KEMeHQEoBh8PvX4AyovQwTsy/XDsTniXVYB/JVREj
         uXS+AN0PQM0IFRqbvwxzDtKHrj2FPX9SkIlBmNtWJmiaqpmrWrPIdYNhReauqBQu9ky3
         p88QNG1YoC2t4Q47l19jgUqzdbrLyzM54khOYBtjs86BQ1tjoDDUZkrduVyVsQaytESD
         zyD2Lx1xkz2C2QzJjvOMo8MTHLQOjOLE+vIyfR2NuUv/UNnN2HjXpmhkYH4efjjAUpjm
         e4SVez26hnGRwQm7LgqTTmHwwLRmH/aTEYjS3JAZtCcfkB1OAyqahwiKBL3wHyxWA91r
         A4SA==
X-Gm-Message-State: AOAM530jYNLCb1zKkcqkWM/DqQlb+mUITKEoXUtdWu0ytfHkYUZ8vA3J
	DT3+cdPni8JCWb9rNfgJtqc=
X-Google-Smtp-Source: ABdhPJwtBlEHFm2D0dYsJIqe9s1oKAHXqi+uhikQ8trTNl646ZBHGgDepj7cDrf8ZH5SqCT4lrkV2w==
X-Received: by 2002:ab0:13eb:: with SMTP id n40mr2559095uae.43.1610440229278;
        Tue, 12 Jan 2021 00:30:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4823:: with SMTP id b32ls167051uad.2.gmail; Tue, 12 Jan
 2021 00:30:28 -0800 (PST)
X-Received: by 2002:ab0:13eb:: with SMTP id n40mr2559077uae.43.1610440228716;
        Tue, 12 Jan 2021 00:30:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610440228; cv=none;
        d=google.com; s=arc-20160816;
        b=zVNV7u+oFi5Xq88f62slp9mhHlERol1xydFk8xr1/6mCBXLqcl6/CUlwRHH1ZLaWVm
         sSIupaE+y8btchqNzmUaYagFXgvpC6orKLHpd688X7Xqkm1aZp3A5txdK48fdtaAOoiI
         cghYqopQq+n2LyXzFquzWNzal/kKa02eQFY7MmW+g7OSxlz+nW+usE+/N4th1Oca1HDv
         /XxN9GoQNVAuMLsxEXz05IKdF++lwCP75583XogKEXZDtmIxmBdT7+RNgw6oRga/kn4N
         HX+CXGlcrBJ4RfHOL+jlLc+PJnYnIoJQ3vyIQa9z6Nzn6XlzJLwkjecFfTlzSjFL0D64
         5FmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0wLcHsg2X/4z8PrpV9akJDkZzB5hyg40jt+7shI/gTg=;
        b=Ec2t2Lnt73YD1qu8P7KQhCQE66FdCOFp/8hIttyRzKEnas5mwM8KvxXu5V01TRl03K
         BoEbDUFULVtKcBsa6oXP98CQFbalp/gofgAhkH5BiBCWnGMthvivsoMrKo7e1fZwE20R
         v50Nsw6hnkma98yXqFe/gVKDD2Cul7T2gTO0UMOnYgG6uCtaAYeYYMZEmGRGTDW2TLxy
         f2pnQ1XRPLqysRIuHXBIhfTJQh58XHXa4lhGQYBQ7QZvEHgbClNsZy+MiggQmWFyGerw
         Zqj3gt7LKFlN8PQQbuH0X2bJ3a1HIOEQjV9o5OQUdfy0VR81kS5qxrU4I6wmjlK+BtcK
         +HRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="H7l/xBso";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x729.google.com (mail-qk1-x729.google.com. [2607:f8b0:4864:20::729])
        by gmr-mx.google.com with ESMTPS id r13si242833vka.3.2021.01.12.00.30.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 00:30:28 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) client-ip=2607:f8b0:4864:20::729;
Received: by mail-qk1-x729.google.com with SMTP id d14so1160046qkc.13
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 00:30:28 -0800 (PST)
X-Received: by 2002:a05:620a:2051:: with SMTP id d17mr3304130qka.403.1610440228161;
 Tue, 12 Jan 2021 00:30:28 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <0c51a7266ea851797dc9816405fc40d860a48db1.1609871239.git.andreyknvl@google.com>
In-Reply-To: <0c51a7266ea851797dc9816405fc40d860a48db1.1609871239.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 09:30:16 +0100
Message-ID: <CAG_fn=VXe2AZZ3q6+HoV+zB=9GLP+kgyW_r9hfqvX-NJHurTRg@mail.gmail.com>
Subject: Re: [PATCH 09/11] kasan: fix memory corruption in kasan_bitops_tags test
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="H7l/xBso";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Since the hardware tag-based KASAN mode might not have a redzone that
> comes after an allocated object (when kasan.mode=prod is enabled), the
> kasan_bitops_tags() test ends up corrupting the next object in memory.
>
> Change the test so it always accesses the redzone that lies within the
> allocated object's boundaries.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I67f51d1ee48f0a8d0fe2658c2a39e4879fe0832a
> ---
>  lib/test_kasan.c | 12 ++++++------
>  1 file changed, 6 insertions(+), 6 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index b67da7f6e17f..3ea52da52714 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -771,17 +771,17 @@ static void kasan_bitops_tags(struct kunit *test)
>
>         /* This test is specifically crafted for the tag-based mode. */
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -               kunit_info(test, "skipping, CONFIG_KASAN_SW_TAGS required");
> +               kunit_info(test, "skipping, CONFIG_KASAN_SW/HW_TAGS required");
>                 return;
>         }
>
> -       /* Allocation size will be rounded to up granule size, which is 16. */
> -       bits = kzalloc(sizeof(*bits), GFP_KERNEL);
> +       /* kmalloc-64 cache will be used and the last 16 bytes will be the redzone. */
> +       bits = kzalloc(48, GFP_KERNEL);

I think it might make sense to call ksize() here to ensure we have
these spare bytes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVXe2AZZ3q6%2BHoV%2BzB%3D9GLP%2BkgyW_r9hfqvX-NJHurTRg%40mail.gmail.com.
