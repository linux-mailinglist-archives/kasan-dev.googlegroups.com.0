Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2EK5SDAMGQEBINO5WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FF593B715A
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jun 2021 13:35:06 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id t22-20020a0568081596b029023a41b03dc9sf9453083oiw.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jun 2021 04:35:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624966505; cv=pass;
        d=google.com; s=arc-20160816;
        b=zEV7/KccLPEWFzfQsQWF4sMsc+vw1Q3jW3hkmCjBGQbCVnvq7rn9Ni6lAo98WC3aAt
         1VAFHTln1/dujqcSz54fPBPxIETm/LisxlBqd5jgKjsQI+EmAqU3Lx3G2Z5w2uZnh4I8
         D1KrWpEZshNDIO3aBXxAljU/gf4NDyLNXe3kNCoC5QDN2CmHGcFilIx118n+ACS7UNlv
         Dqn4CC3ngoP+kWERhdOd6LMhq+oAYrbIwvCidtAcfizpY3x+EPeofHo/cnEdESMuAAUK
         8BRIZKh9aDl2jp5ekoYqPa3ihMRFylsE4Nv5fKZGPLHq9c8vVgd4XN3uBE5kC69u3hGS
         1T7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tFLAHILDdeNAWDsYVXVI8ssXPsPgRjuBfAiQaqT7xRQ=;
        b=fS1hfBBPmHoCkpM2XX2gPw7yCVGf6GmsGz90d6vEWlwZ5hzXZBZDulI76t7W1y94yd
         zlVfwUF25C6KeevvHgNsMvWC6UC4fdkDQ9mY8Fr/HDs/vwY7fpKD3Sn4FkNpcDq938WD
         gS4auL+Wg9SOOgiFMn1YSeTI1jqCOSdgvy/kCz25Pct2UrN2Ze8zFVNy6LR6DryKhCmG
         LZEmNWm+JZp9Do5zdQoJbgZdn3qlAi0Yz16bKhll0wnj+RPMvac4ODQ7rZQjfLpvOqbO
         wzL7HfQ7IzKtOnHoGQV+qewph2oAUiWRMCnCMj9+pfDl7EQeFML4AhUmuP9ZVCznDypv
         sJKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HDlA19tX;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=tFLAHILDdeNAWDsYVXVI8ssXPsPgRjuBfAiQaqT7xRQ=;
        b=Qp1JiSfj7hpFm0lK9Al+6sB4oAUhXZiYzXLRdBXS5ipbhjNYL7B/nycTJN1PZda+eN
         xOVNk9dEeizIyjAduraIRkCoduN4G4EfbAuZMVgiBN01AMr8Sh4OpY+v9ahln0hOzhx/
         9CFeEbYjccl2DDlKIGBcKiFIlQeWL7YiSH7kMBtQjwV9u2FjXmQ88URrxSJhx72fwzfD
         ClhLtCnIuYIimTP3b7c28D38onYEvuBE+9yfgON4q42KwKGLr1jhAlWMtattB8UbaMUa
         Nzo/B3yqdIfCmb9Nk0AaEuUpnvXMRnYLC7VUJPXMp0tVxcxpeS/k+NblzUbJLcyRF4Yy
         fh4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tFLAHILDdeNAWDsYVXVI8ssXPsPgRjuBfAiQaqT7xRQ=;
        b=s2QepSO5a32Vb/4Qsb1jgs6VNi2rxY/l2ttJT3c3C5NYL0BrFPh9UvQrobZCkWt9u8
         IAbCMT4TFwJHJzXiOU8x2cPyQdSWPPYFv98NNjJ6saltppmoHzJbGJJxdas5TEcliW5A
         BdzeeOfo94WcbMPMq0Ghde7VELNEbyu29OAmlpiOa6ck/qDxjVlHK0zgUiXFjGp2W1UY
         oEQW5Q9qdxE0BM1t9ZdnbuezxYFg8XPQR5QNJI18fuXfUSx/HS6frjq00oRLWW2/EDHt
         FBwiJrrhe+yWW4CuE5uaCmW/+bsL0ONDBbhIq6CNd5FBVDODbDRRl39Hi3nh9ff+GySL
         JSRQ==
X-Gm-Message-State: AOAM532y/q85zQw6R+xd/+bi8Jnp9QuEmdqtm5gr/nL5QcZTg7J/EFbn
	NcB5UuTZZhIF97fRX1LkVak=
X-Google-Smtp-Source: ABdhPJwnLgf2E6IH5T4sTDii47D0kFWNoTsQopdZ2dSvQPKoicOgRsSsjDsPP4gnKKjAzdOHw1sFCA==
X-Received: by 2002:a05:6830:40b4:: with SMTP id x52mr1041394ott.292.1624966504806;
        Tue, 29 Jun 2021 04:35:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5903:: with SMTP id n3ls7778121oib.6.gmail; Tue, 29 Jun
 2021 04:35:04 -0700 (PDT)
X-Received: by 2002:aca:f4cb:: with SMTP id s194mr18589540oih.103.1624966504435;
        Tue, 29 Jun 2021 04:35:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624966504; cv=none;
        d=google.com; s=arc-20160816;
        b=KusVQ6dE384ZBX5ZjBv8GmGl1F03mGYIXuTvmUaUs1nZ0yM0iutWXhttP9Sw2aGqpB
         eT14Nah1xKa1+oCOa6Dr+G9Rb56D/1iDBLsAE3hXOT51mjPG9XFZLbOfaWBb4DMSbIU2
         ZEWPmNIxvas800+ODRP+90n/6AvZ2i9pmiTmSqza3ylilTD0o6Wk/6o2vI7TQWKyiqZi
         V2CPbWv5Ou5yJbIlsKpSb51PBqxURu8i8OksSpriPXBGgAaOnSWFaoHcaYfx8lF0Wm1a
         N8KmnL+nP/Ez59hWUwr/xEkqCIGuFu7S1IotU0qCzVPaORB7K08R+QhchU5GgH4qmtNT
         Pwxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LZBNoVMafaZdSt9KOA/GfK+2t3WWU0PS2M5jLE524Ts=;
        b=jyDWAUlCdYeVyAhY8CE3h8XewkJ3RVVchcob0ajnMrTBePY0dFLZBpwPIxh8YbGieG
         L3WBTi4UQjWzk2VQGb3woTums3LoRKw4+xealIuYcm/gLbo7rvPMp1HG/uwA6+jf2zTa
         iHvUJti5nvC99/gIDOjMKUS4GkbmmyEatigYU+qyR48Otq5VYiKn7H0xfeQmFPHnc0zI
         dF7LisuGMCJzUxul0UHeXj3i1z2wGtzXhAQ87vvUuXEMuz8uySmvHzMM6D1oQcqp07mA
         m5Wvuhzyas0EdAQRq4YldBjaf2iQ3X1zOVRdOEsK/Nl4GBYQhrr0ThH60ERtQkNtFdXk
         WwdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HDlA19tX;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82b.google.com (mail-qt1-x82b.google.com. [2607:f8b0:4864:20::82b])
        by gmr-mx.google.com with ESMTPS id k18si2332808otj.1.2021.06.29.04.35.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jun 2021 04:35:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82b as permitted sender) client-ip=2607:f8b0:4864:20::82b;
Received: by mail-qt1-x82b.google.com with SMTP id w26so15784936qto.13
        for <kasan-dev@googlegroups.com>; Tue, 29 Jun 2021 04:35:04 -0700 (PDT)
X-Received: by 2002:ac8:5bc4:: with SMTP id b4mr22629588qtb.180.1624966503664;
 Tue, 29 Jun 2021 04:35:03 -0700 (PDT)
MIME-Version: 1.0
References: <20210629113323.2354571-1-elver@google.com>
In-Reply-To: <20210629113323.2354571-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Jun 2021 13:34:27 +0200
Message-ID: <CAG_fn=V2H7UX8YQYqsQ08D_xF3VKUMCUkafTMVr-ywtki6S0wA@mail.gmail.com>
Subject: Re: [PATCH] kfence: show cpu and timestamp in alloc/free info
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitriy Vyukov <dvyukov@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, Joern Engel <joern@purestorage.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HDlA19tX;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82b as
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

On Tue, Jun 29, 2021 at 1:33 PM Marco Elver <elver@google.com> wrote:
>
> Record cpu and timestamp on allocations and frees, and show them in
> reports. Upon an error, this can help correlate earlier messages in the
> kernel log via allocation and free timestamps.
>
> Suggested-by: Joern Engel <joern@purestorage.com>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Alexander Potapenko <glider@google.com>

Thanks!

> ---
>  Documentation/dev-tools/kfence.rst | 98 ++++++++++++++++--------------
>  mm/kfence/core.c                   |  3 +
>  mm/kfence/kfence.h                 |  2 +
>  mm/kfence/report.c                 | 19 ++++--
>  4 files changed, 71 insertions(+), 51 deletions(-)
>
> diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools=
/kfence.rst
> index fdf04e741ea5..0fbe3308bf37 100644
> --- a/Documentation/dev-tools/kfence.rst
> +++ b/Documentation/dev-tools/kfence.rst
> @@ -65,25 +65,27 @@ Error reports
>  A typical out-of-bounds access looks like this::
>
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> -    BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0xa3/0x22=
b
> +    BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0xa6/0x23=
4
>
> -    Out-of-bounds read at 0xffffffffb672efff (1B left of kfence-#17):
> -     test_out_of_bounds_read+0xa3/0x22b
> -     kunit_try_run_case+0x51/0x85
> +    Out-of-bounds read at 0xffff8c3f2e291fff (1B left of kfence-#72):
> +     test_out_of_bounds_read+0xa6/0x234
> +     kunit_try_run_case+0x61/0xa0
>       kunit_generic_run_threadfn_adapter+0x16/0x30
> -     kthread+0x137/0x160
> +     kthread+0x176/0x1b0
>       ret_from_fork+0x22/0x30
>
> -    kfence-#17 [0xffffffffb672f000-0xffffffffb672f01f, size=3D32, cache=
=3Dkmalloc-32] allocated by task 507:
> -     test_alloc+0xf3/0x25b
> -     test_out_of_bounds_read+0x98/0x22b
> -     kunit_try_run_case+0x51/0x85
> +    kfence-#72: 0xffff8c3f2e292000-0xffff8c3f2e29201f, size=3D32, cache=
=3Dkmalloc-32
> +
> +    allocated by task 484 on cpu 0 at 32.919330s:
> +     test_alloc+0xfe/0x738
> +     test_out_of_bounds_read+0x9b/0x234
> +     kunit_try_run_case+0x61/0xa0
>       kunit_generic_run_threadfn_adapter+0x16/0x30
> -     kthread+0x137/0x160
> +     kthread+0x176/0x1b0
>       ret_from_fork+0x22/0x30
>
> -    CPU: 4 PID: 107 Comm: kunit_try_catch Not tainted 5.8.0-rc6+ #7
> -    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1=
 04/01/2014
> +    CPU: 0 PID: 484 Comm: kunit_try_catch Not tainted 5.13.0-rc3+ #7
> +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2=
 04/01/2014
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
>  The header of the report provides a short summary of the function involv=
ed in
> @@ -96,30 +98,32 @@ Use-after-free accesses are reported as::
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>      BUG: KFENCE: use-after-free read in test_use_after_free_read+0xb3/0x=
143
>
> -    Use-after-free read at 0xffffffffb673dfe0 (in kfence-#24):
> +    Use-after-free read at 0xffff8c3f2e2a0000 (in kfence-#79):
>       test_use_after_free_read+0xb3/0x143
> -     kunit_try_run_case+0x51/0x85
> +     kunit_try_run_case+0x61/0xa0
>       kunit_generic_run_threadfn_adapter+0x16/0x30
> -     kthread+0x137/0x160
> +     kthread+0x176/0x1b0
>       ret_from_fork+0x22/0x30
>
> -    kfence-#24 [0xffffffffb673dfe0-0xffffffffb673dfff, size=3D32, cache=
=3Dkmalloc-32] allocated by task 507:
> -     test_alloc+0xf3/0x25b
> +    kfence-#79: 0xffff8c3f2e2a0000-0xffff8c3f2e2a001f, size=3D32, cache=
=3Dkmalloc-32
> +
> +    allocated by task 488 on cpu 2 at 33.871326s:
> +     test_alloc+0xfe/0x738
>       test_use_after_free_read+0x76/0x143
> -     kunit_try_run_case+0x51/0x85
> +     kunit_try_run_case+0x61/0xa0
>       kunit_generic_run_threadfn_adapter+0x16/0x30
> -     kthread+0x137/0x160
> +     kthread+0x176/0x1b0
>       ret_from_fork+0x22/0x30
>
> -    freed by task 507:
> +    freed by task 488 on cpu 2 at 33.871358s:
>       test_use_after_free_read+0xa8/0x143
> -     kunit_try_run_case+0x51/0x85
> +     kunit_try_run_case+0x61/0xa0
>       kunit_generic_run_threadfn_adapter+0x16/0x30
> -     kthread+0x137/0x160
> +     kthread+0x176/0x1b0
>       ret_from_fork+0x22/0x30
>
> -    CPU: 4 PID: 109 Comm: kunit_try_catch Tainted: G        W         5.=
8.0-rc6+ #7
> -    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1=
 04/01/2014
> +    CPU: 2 PID: 488 Comm: kunit_try_catch Tainted: G    B             5.=
13.0-rc3+ #7
> +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2=
 04/01/2014
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
>  KFENCE also reports on invalid frees, such as double-frees::
> @@ -127,30 +131,32 @@ KFENCE also reports on invalid frees, such as doubl=
e-frees::
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>      BUG: KFENCE: invalid free in test_double_free+0xdc/0x171
>
> -    Invalid free of 0xffffffffb6741000:
> +    Invalid free of 0xffff8c3f2e2a4000 (in kfence-#81):
>       test_double_free+0xdc/0x171
> -     kunit_try_run_case+0x51/0x85
> +     kunit_try_run_case+0x61/0xa0
>       kunit_generic_run_threadfn_adapter+0x16/0x30
> -     kthread+0x137/0x160
> +     kthread+0x176/0x1b0
>       ret_from_fork+0x22/0x30
>
> -    kfence-#26 [0xffffffffb6741000-0xffffffffb674101f, size=3D32, cache=
=3Dkmalloc-32] allocated by task 507:
> -     test_alloc+0xf3/0x25b
> +    kfence-#81: 0xffff8c3f2e2a4000-0xffff8c3f2e2a401f, size=3D32, cache=
=3Dkmalloc-32
> +
> +    allocated by task 490 on cpu 1 at 34.175321s:
> +     test_alloc+0xfe/0x738
>       test_double_free+0x76/0x171
> -     kunit_try_run_case+0x51/0x85
> +     kunit_try_run_case+0x61/0xa0
>       kunit_generic_run_threadfn_adapter+0x16/0x30
> -     kthread+0x137/0x160
> +     kthread+0x176/0x1b0
>       ret_from_fork+0x22/0x30
>
> -    freed by task 507:
> +    freed by task 490 on cpu 1 at 34.175348s:
>       test_double_free+0xa8/0x171
> -     kunit_try_run_case+0x51/0x85
> +     kunit_try_run_case+0x61/0xa0
>       kunit_generic_run_threadfn_adapter+0x16/0x30
> -     kthread+0x137/0x160
> +     kthread+0x176/0x1b0
>       ret_from_fork+0x22/0x30
>
> -    CPU: 4 PID: 111 Comm: kunit_try_catch Tainted: G        W         5.=
8.0-rc6+ #7
> -    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1=
 04/01/2014
> +    CPU: 1 PID: 490 Comm: kunit_try_catch Tainted: G    B             5.=
13.0-rc3+ #7
> +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2=
 04/01/2014
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
>  KFENCE also uses pattern-based redzones on the other side of an object's=
 guard
> @@ -160,23 +166,25 @@ These are reported on frees::
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>      BUG: KFENCE: memory corruption in test_kmalloc_aligned_oob_write+0xe=
f/0x184
>
> -    Corrupted memory at 0xffffffffb6797ff9 [ 0xac . . . . . . ] (in kfen=
ce-#69):
> +    Corrupted memory at 0xffff8c3f2e33aff9 [ 0xac . . . . . . ] (in kfen=
ce-#156):
>       test_kmalloc_aligned_oob_write+0xef/0x184
> -     kunit_try_run_case+0x51/0x85
> +     kunit_try_run_case+0x61/0xa0
>       kunit_generic_run_threadfn_adapter+0x16/0x30
> -     kthread+0x137/0x160
> +     kthread+0x176/0x1b0
>       ret_from_fork+0x22/0x30
>
> -    kfence-#69 [0xffffffffb6797fb0-0xffffffffb6797ff8, size=3D73, cache=
=3Dkmalloc-96] allocated by task 507:
> -     test_alloc+0xf3/0x25b
> +    kfence-#156: 0xffff8c3f2e33afb0-0xffff8c3f2e33aff8, size=3D73, cache=
=3Dkmalloc-96
> +
> +    allocated by task 502 on cpu 7 at 42.159302s:
> +     test_alloc+0xfe/0x738
>       test_kmalloc_aligned_oob_write+0x57/0x184
> -     kunit_try_run_case+0x51/0x85
> +     kunit_try_run_case+0x61/0xa0
>       kunit_generic_run_threadfn_adapter+0x16/0x30
> -     kthread+0x137/0x160
> +     kthread+0x176/0x1b0
>       ret_from_fork+0x22/0x30
>
> -    CPU: 4 PID: 120 Comm: kunit_try_catch Tainted: G        W         5.=
8.0-rc6+ #7
> -    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1=
 04/01/2014
> +    CPU: 7 PID: 502 Comm: kunit_try_catch Tainted: G    B             5.=
13.0-rc3+ #7
> +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2=
 04/01/2014
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
>  For such errors, the address where the corruption occurred as well as th=
e
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index d7666ace9d2e..0fd7a122e1a1 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -20,6 +20,7 @@
>  #include <linux/moduleparam.h>
>  #include <linux/random.h>
>  #include <linux/rcupdate.h>
> +#include <linux/sched/clock.h>
>  #include <linux/sched/sysctl.h>
>  #include <linux/seq_file.h>
>  #include <linux/slab.h>
> @@ -196,6 +197,8 @@ static noinline void metadata_update_state(struct kfe=
nce_metadata *meta,
>          */
>         track->num_stack_entries =3D stack_trace_save(track->stack_entrie=
s, KFENCE_STACK_DEPTH, 1);
>         track->pid =3D task_pid_nr(current);
> +       track->cpu =3D raw_smp_processor_id();
> +       track->ts_nsec =3D local_clock(); /* Same source as printk timest=
amps. */
>
>         /*
>          * Pairs with READ_ONCE() in
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> index 24065321ff8a..c1f23c61e5f9 100644
> --- a/mm/kfence/kfence.h
> +++ b/mm/kfence/kfence.h
> @@ -36,6 +36,8 @@ enum kfence_object_state {
>  /* Alloc/free tracking information. */
>  struct kfence_track {
>         pid_t pid;
> +       int cpu;
> +       u64 ts_nsec;
>         int num_stack_entries;
>         unsigned long stack_entries[KFENCE_STACK_DEPTH];
>  };
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 2a319c21c939..d1daabdc9188 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -9,6 +9,7 @@
>
>  #include <linux/kernel.h>
>  #include <linux/lockdep.h>
> +#include <linux/math.h>
>  #include <linux/printk.h>
>  #include <linux/sched/debug.h>
>  #include <linux/seq_file.h>
> @@ -100,6 +101,13 @@ static void kfence_print_stack(struct seq_file *seq,=
 const struct kfence_metadat
>                                bool show_alloc)
>  {
>         const struct kfence_track *track =3D show_alloc ? &meta->alloc_tr=
ack : &meta->free_track;
> +       u64 ts_sec =3D track->ts_nsec;
> +       unsigned long rem_nsec =3D do_div(ts_sec, NSEC_PER_SEC);
> +
> +       /* Timestamp matches printk timestamp format. */
> +       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
> +                      show_alloc ? "allocated" : "freed", meta->alloc_tr=
ack.pid,
> +                      meta->alloc_track.cpu, (unsigned long)ts_sec, rem_=
nsec / 1000);
>
>         if (track->num_stack_entries) {
>                 /* Skip allocation/free internals stack. */
> @@ -126,15 +134,14 @@ void kfence_print_object(struct seq_file *seq, cons=
t struct kfence_metadata *met
>                 return;
>         }
>
> -       seq_con_printf(seq,
> -                      "kfence-#%td [0x%p-0x%p"
> -                      ", size=3D%d, cache=3D%s] allocated by task %d:\n"=
,
> -                      meta - kfence_metadata, (void *)start, (void *)(st=
art + size - 1), size,
> -                      (cache && cache->name) ? cache->name : "<destroyed=
>", meta->alloc_track.pid);
> +       seq_con_printf(seq, "kfence-#%td: 0x%p-0x%p, size=3D%d, cache=3D%=
s\n\n",
> +                      meta - kfence_metadata, (void *)start, (void *)(st=
art + size - 1),
> +                      size, (cache && cache->name) ? cache->name : "<des=
troyed>");
> +
>         kfence_print_stack(seq, meta, true);
>
>         if (meta->state =3D=3D KFENCE_OBJECT_FREED) {
> -               seq_con_printf(seq, "\nfreed by task %d:\n", meta->free_t=
rack.pid);
> +               seq_con_printf(seq, "\n");
>                 kfence_print_stack(seq, meta, false);
>         }
>  }
> --
> 2.32.0.93.g670b81a890-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DV2H7UX8YQYqsQ08D_xF3VKUMCUkafTMVr-ywtki6S0wA%40mail.gmai=
l.com.
