Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6FY4C4AMGQEYSWWB4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 578009AB8F1
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 23:43:22 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-7eb07db7812sf201178a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 14:43:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729633401; cv=pass;
        d=google.com; s=arc-20240605;
        b=QOSk78d5Y7lOpU4tkoVWIXsNe25K/L5PJ6D3/0qvuiiX9Dyto8yy1OiYW6pzVcKnYP
         3xvOeQIT24sSs9+sfmK0XPjKJwaRd7U63YsPT/GiiK36CfymHb+c72J95IrduT47RgMn
         dALU3wYUR2vjDqYaQHYb8oTwm0gDcMmoKtloJ8Kl5nrp55ieVEMYFZoEMAXb+L0suVxN
         9KptOHOMu/z/kU9sy9A224Q16LiSRY4S8yw/6f1pbYna88kTFUk6mHnje6J1xH2a17WN
         W2ZNr/gf5GFI74AmtFdpV6+z5X+4dx60e4pys7b/NeE5SW7o/70WH7GVSQaEpTPZA53r
         OTBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZRXB12FTTFpHqNRXcd+7ne/4vlUwveWMpKH0+Iqu4zw=;
        fh=VOCV8xxpmd7Fu9C8HjxHM9ZmO9eHDc7RCkPNSphKnIc=;
        b=f8ghdOf3yCKbYsJ7Ot/4a4OGWK3wHunxv/77Dyn3IyKLO2jfnRdlGf0q2RYQX1mYRz
         KsISO4ElOKOaZ/yZKR7sU9jNwMuehDYyiSo3N0837tKxV6tzO8jrKM9SpdnBw2Oki6NK
         5Kf0yjuHVBKknh8BJPIuiNveccifOl+ooeABxgHanMox0tePtQ6s+PPszBalmZ3FmAKl
         I0lWSpjHAMuzdF5V3gIxKunmyPawUD5f9L7n2oLzi7LJOmzji8lLCdORAHsly0CLE5j1
         JcYRMBNQK4AszeoFTkgE/CCzI6YR6ZJJuNaQHZYgpFgaym3sNRt7QTCADMnZoypbTVi2
         pfuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KoxfEIk0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729633401; x=1730238201; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZRXB12FTTFpHqNRXcd+7ne/4vlUwveWMpKH0+Iqu4zw=;
        b=NPKwT+Poz+MSPcDoCsBXAymUW8Mpy89YyvtE0fdptHYHVVM+cQOXV47CgJ2a01UHrL
         LDgYYmxnTPCNsPibhaF+9UsrA0olbqH85toqkum5oB+rqCM6BRjrsd0hJ21xBdDM+ZyA
         bKfMxAAvaBieLK6QTFN9TxhTOA1py6a8IV/tYEvG5YxibmvK8FkEfLB88eWvxFUpLzsg
         TY8WA/VbNoVKcujfZNmzcelJbRQpdW2ACvos/9YnXATPpj+DGWzLLEzkKt6w2Xjd7ZYH
         hbvCbDduYF2ixRNuRFT/tJmbdMpUJKftDEVYUJzh7ylCGG1UFTYE1slttWCzLIjzhl/m
         kPNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729633401; x=1730238201;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZRXB12FTTFpHqNRXcd+7ne/4vlUwveWMpKH0+Iqu4zw=;
        b=NgRI8AUWd3HnMZtPEZBsvOXm4fR6J9zMbblgo7a/mVng0qcy4AnVZjprF67P4fZ7R4
         rKTkkG/SsxFWE2eUT7twVnp8VtmgAZvPK+C9hekTWKdFxxgDPaOJsweVpf+Je4vX0b3r
         cWT5/pOL5WTWHC4KbbUqVQXroMZbxyuIynJrHFLJ9WvBEeJCaSHB5eudyTgFMiC0+rtY
         luyzahtdENuRwIX1uOIaxDdt+msMfvc6D1tJemNvbuHqqoOSR7aju5AWzxmNKkPo7+oj
         GECyEtVJFG8LmroEQaAuR9MefXug8v6yx+HvnxDf3szeQXNSRUxwpcdRcuKtQGgk2DUC
         NUzw==
X-Forwarded-Encrypted: i=2; AJvYcCUxQOB5EiT2AE02+ElRmum5DJgs2SFijHXTSHEwGRvJxImvNKb4hSu3lF4upjCGn4Q4l9c9Qg==@lfdr.de
X-Gm-Message-State: AOJu0YxSILbXFSN9TGHkZ/xi8W+kE78psO7NkzNE+tw8h73s6zFfTtp7
	nqOCCi4qUVnMZKLdJYi2lj7/Quk7Zy8IlcJCFfpUQtw2R7TTduv7
X-Google-Smtp-Source: AGHT+IErUAewATHAcs4+5dqFc1FRLVUm9dSM1klYhgQCvQAbd0AJN9KQsc/CNzsPjIeAbqA52GhJlQ==
X-Received: by 2002:a05:6a21:38a:b0:1d9:281f:2f27 with SMTP id adf61e73a8af0-1d978659716mr787930637.19.1729633400872;
        Tue, 22 Oct 2024 14:43:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2e23:b0:71e:83c8:3980 with SMTP id
 d2e1a72fcca58-71e8f88e594ls4119803b3a.0.-pod-prod-00-us; Tue, 22 Oct 2024
 14:43:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2P4+yZIuPsV9DqDVKcamcRsPRL9GhwXDKUHStvYMBMouHgfkB0DsjoOSBRNPM54ivHI2tpalMfbM=@googlegroups.com
X-Received: by 2002:a05:6a20:db0a:b0:1d9:d5e:8297 with SMTP id adf61e73a8af0-1d9785726d2mr800728637.6.1729633399135;
        Tue, 22 Oct 2024 14:43:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729633399; cv=none;
        d=google.com; s=arc-20240605;
        b=FS4CKp5ibcpOtwcP3pEIB1hmnKV4hu5/ifsGAeC7nkHiqn3uh4av/A+XaJs9WqSTqh
         CGNsbM6k7khjcRpFMMCyBl8IVExgzDyV0PhHcz7Tzxkz6ajHUdIvdN0eK/osq/qfcelE
         JlZH5V9qi3pLqBQfVlYKOMr/ARw5VcwtBzpS/XUo6unnsKc5Aw64r1EUhG7ZzntbI7jh
         hWY3s5Bk4LthFhVgolasvldCkXUxv5nIsnmDkdccjNBV26yv9zgnBF8YT/G6pCwpuLz3
         jQaFA+bf5gW05syEgifKoGT8mFNo9qouXYNqnzBBaTZOkpFHWSw92qHG8dfrlMhHvPb5
         9Xpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9TRNlHgfETbV9PWZsrG5Dbl77hFjmMLfOcM3aLCB/1g=;
        fh=drzOqBpfK3tMeZv79ijA1relCgndCmPXTgOXnZZe3VE=;
        b=dR0mqUc2y4ggd2EWIJXCmyiza4rOApnIkbPJwrZYV4T5NMyj88baiY9MQcb36u0T3c
         pDvgN6sFB1WN2y3DWeTrYr8j2fVyvKHdoKpuQqUZsiKdc8xBmm9fJ0Cn2lP+vFu64s+e
         tN8XHD3YOV2bmsIrTG67Zc5oC9u0WWo/iDhHr9gfGU2AT2+fpMsYa2j9uTg6o/fVvSQD
         FnGK5bopSPOt69W/QntFKTdtjx47SaMe8BZASvZqFZEqJlBmovWg4iUsp8B4lljldLpw
         FC9gz3E+XzWLz4kiIGixeQe3yed26IVEHEgZT5CZ8EqV754w8pOmjYKWCANjcOdOsVqc
         GiCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KoxfEIk0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71ec13a9b39si319241b3a.1.2024.10.22.14.43.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Oct 2024 14:43:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-20c7edf2872so1870075ad.1
        for <kasan-dev@googlegroups.com>; Tue, 22 Oct 2024 14:43:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXjvEMxmYm5rzdOdnxEP+SRx2J7p6nsqH3a/ROHZWAIL/81w1X0mczNZcN0TraAGl6GiTWCFHPj9C4=@googlegroups.com
X-Received: by 2002:a17:90a:448d:b0:2e0:89f2:f60c with SMTP id
 98e67ed59e1d1-2e76a721744mr802998a91.11.1729633398336; Tue, 22 Oct 2024
 14:43:18 -0700 (PDT)
MIME-Version: 1.0
References: <20241021120013.3209481-1-elver@google.com> <20241021172058.GB26179@willie-the-truck>
 <CA+=Sn1m7KYkJHL3gis6+7M2-o9fuuzDtyUmycKnHK9KKEr2LtA@mail.gmail.com>
In-Reply-To: <CA+=Sn1m7KYkJHL3gis6+7M2-o9fuuzDtyUmycKnHK9KKEr2LtA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Oct 2024 23:42:40 +0200
Message-ID: <CANpmjNOf94nQL8YVr94L=9qXA6eHcm-AxbS+vz+Sm1aHJT2iAQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: Fix Software Tag-Based KASAN with GCC
To: Andrew Pinski <pinskia@gmail.com>
Cc: Will Deacon <will@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Mark Rutland <mark.rutland@arm.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	syzbot+908886656a02769af987@syzkaller.appspotmail.com, 
	"Andrew Pinski (QUIC)" <quic_apinski@quicinc.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=KoxfEIk0;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, 21 Oct 2024 at 19:29, Andrew Pinski <pinskia@gmail.com> wrote:
>
> On Mon, Oct 21, 2024 at 10:21=E2=80=AFAM Will Deacon <will@kernel.org> wr=
ote:
> >
> > On Mon, Oct 21, 2024 at 02:00:10PM +0200, Marco Elver wrote:
> > > Per [1], -fsanitize=3Dkernel-hwaddress with GCC currently does not di=
sable
> > > instrumentation in functions with __attribute__((no_sanitize_address)=
).
> > >
> > > However, __attribute__((no_sanitize("hwaddress"))) does correctly
> > > disable instrumentation. Use it instead.
> > >
> > > Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D117196 [1]
> > > Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.c=
om
> > > Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
> > > Link: https://bugzilla.kernel.org/show_bug.cgi?id=3D218854
> > > Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
> > > Tested-by: Andrey Konovalov <andreyknvl@gmail.com>
> > > Cc: Andrew Pinski <pinskia@gmail.com>
> > > Cc: Mark Rutland <mark.rutland@arm.com>
> > > Cc: Will Deacon <will@kernel.org>
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > >  include/linux/compiler-gcc.h | 4 ++++
> > >  1 file changed, 4 insertions(+)
> > >
> > > diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gc=
c.h
> > > index f805adaa316e..cd6f9aae311f 100644
> > > --- a/include/linux/compiler-gcc.h
> > > +++ b/include/linux/compiler-gcc.h
> > > @@ -80,7 +80,11 @@
> > >  #define __noscs __attribute__((__no_sanitize__("shadow-call-stack"))=
)
> > >  #endif
> > >
> > > +#ifdef __SANITIZE_HWADDRESS__
> > > +#define __no_sanitize_address __attribute__((__no_sanitize__("hwaddr=
ess")))
> > > +#else
> > >  #define __no_sanitize_address __attribute__((__no_sanitize_address__=
))
> > > +#endif
> >
> > Does this work correctly for all versions of GCC that support
> > -fsanitize=3Dkernel-hwaddress?
>
> Yes, tested from GCC 11+, kernel-hwaddress was added in GCC 11.
> Also tested from clang 9.0+ and it works there too.

+1 yes. From what I can tell GCC always supported
no_sanitize("hwaddress") for -fsanitize=3Dkernel-hwaddress.

Even for Clang, we define __no_sanitize_address to include
no_sanitize("hwaddress"):
https://elixir.bootlin.com/linux/v6.11.4/source/include/linux/compiler-clan=
g.h#L29

So this has just been an oversight when GCC support for KASAN_SW_TAGS
was introduced.

Having a Fixes tag for this would be nice, but I don't think we
explicitly added GCC support, and instead just relied on
CC_HAS_KASAN_SW_TAGS with cc-option telling us if the flag is
supported.

But maybe we can use this:

Fixes: 7b861a53e46b ("kasan: Bump required compiler version")

Because it's the first time we encountered issues with no_sanitize,
and bumped the required GCC version as a result. Perhaps going along
with that should have been fixing of compiler-gcc.h's definition of
__no_sanitize_address.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOf94nQL8YVr94L%3D9qXA6eHcm-AxbS%2Bvz%2BSm1aHJT2iAQ%40mail.=
gmail.com.
