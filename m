Return-Path: <kasan-dev+bncBC7OBJGL2MHBB45472VAMGQEWDKU7KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D89DC7F66A1
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 19:48:20 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-587a54afb50sf1001983eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 10:48:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700765299; cv=pass;
        d=google.com; s=arc-20160816;
        b=hZN9wycJ0ZlBXxqLPXjTMNnu2QCeltiIKrZtOVgxym6pE+/Qtzl2qkVKE7oUCHs0fh
         G/EKrZzL6maPztkAHGzmbVbnr/OaopPKFyrjl8tNIja+WSWftSzKnt2cIc+Bfxk60Z3V
         YsgmZXigXc5wvREdO+F4YZ2NCuEZyV7jZXJbSZ8AFBfjbBBasmYrKaXfZDy8+V37m8eN
         GFbeg8J6CnopgnJZWCXJvcAJtVI4+RNT1Oy9LfiKEpKXcu9zQ2SsfswhsMEtCDkWHhqG
         AEIbnphIFsZqhf3kaio+2sTjzHXgRPIgHBuZYmZW3T/BJvMpFSVD8NzDZ5nVlv5tmGOb
         3lIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lC1UnSb9AvFY5gnmt46SjOxLCWxguwaUu+XQ+CKWyzE=;
        fh=NSvAzB9689xOzGb9utbYfCotqde6p2+uodY2iw9anZY=;
        b=mdJgxVdyVlDPmwHXrbJsx7kyROHoER7Z+JKKxVmcpH0bpqJqtlWVui8+SWPUoqsRRw
         6LbprFXUpB9HlA905MaSa1Fa2EJmOauqyLZWIhvupACUZEjkFAjt0odDWdilIPsO5IrS
         1r2fe0ytuYcmoToVi56dyAbV2FtpHzqZH9gnt6SQuDY0UYuTjgjARWGWbe94oZsBCdJG
         M23+jFYTQ+oMbwHgz8t5LZGsLrtliuSvIZfekGzufgLmjXfSX4o4rf4WlWsps2PbfhwV
         iAGiKYqxZZLx+3wgOAAXMyhsRGqEvfvz8/ZPD3VfPMyBeg/aH/DebljDX9hhiGbm/rt8
         wOkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A9fsCeDd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700765299; x=1701370099; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lC1UnSb9AvFY5gnmt46SjOxLCWxguwaUu+XQ+CKWyzE=;
        b=dp44Fj/Sj5E5oxeXPbkHojLzkXAokpneyOEN1DB7UsVIaW7K2w5H20vouUDt2WGoeO
         tDpgL3MZwjG3o0GHAry03X3K+FjBNggJRFCMBjeR3DBNp5SLbklxqgqFD6SsNlXPn4oT
         a6bGjMKji5oiD4P0rxT1rEYv5rg1M3lu+mo6PZc+Fnd01/varDfHNsTV6SRuM1ZqdK6T
         ERy4D9TsoUxAfxB/+k+FO7Zf/466huhG2MbfWUwV94ov6NA+VjYvu1gr1nlUTh7pIR6Q
         RxAOz7oqd8T2jS0oGfvG8Pe4vgQS4sgdCmOP/jUC5yzUkS84U/UkBnN5ctIha70Gj2Ab
         ov3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700765299; x=1701370099;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lC1UnSb9AvFY5gnmt46SjOxLCWxguwaUu+XQ+CKWyzE=;
        b=fA0Tw1D3MP1rnvauZm2ARTuJPskTJB2aBjR7X8yyb8H1qSYD4x1MAoRysxQinOy7KM
         JTTMfxwfSlfTtjbQhdeDlteRZAemxxWcnwGZjbhE+i8laZt/FFlLVRS/axIODV7nGCJS
         W+qqYDp6UwfgyEonPqTS0zbxRkLgHGq0rJt1rdOlA6ZVUtzpUzULXKY7XgTrJ5qk6Ud1
         xccpX3HbHILSVxfF1KabolDYqNZaECsHFmPY2dYHFbYfXtbNSEP6i7Tgs4eSvsqY+I7V
         M2Y5QopMfuVM1b5PFbhODENzMbLqzlAggdSZ7wjCqc3hzqDNFIteOCR5COoSPRZXIKuc
         xmJA==
X-Gm-Message-State: AOJu0YwQ/ZdGIRb6fMB8cZx5XtTEeBQHuXiYNgvpRxy+1qtQ4Kt5n3JK
	MiJtVAlorTaXXYtJXrYLi1I=
X-Google-Smtp-Source: AGHT+IEvIeg8rDPrXqrfPhg+dodc93lOjrckqHraHnbKXGgOTyGuNfW2SgWJBvQv9C0xPvumNqm3yg==
X-Received: by 2002:a05:6820:411:b0:576:bbf6:8a8e with SMTP id o17-20020a056820041100b00576bbf68a8emr1739481oou.2.1700765299285;
        Thu, 23 Nov 2023 10:48:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:613:b0:587:a54a:b88f with SMTP id
 e19-20020a056820061300b00587a54ab88fls453003oow.1.-pod-prod-00-us; Thu, 23
 Nov 2023 10:48:18 -0800 (PST)
X-Received: by 2002:a05:6830:22ea:b0:6cd:9f4:e088 with SMTP id t10-20020a05683022ea00b006cd09f4e088mr2026729otc.5.1700765298511;
        Thu, 23 Nov 2023 10:48:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700765298; cv=none;
        d=google.com; s=arc-20160816;
        b=FYAoy0sTkUkdklYOlfge3iOkQ6RZB7dD2CTh1yz46Au0YeAGwehr7TNrq8UisUFiQu
         UUHvoHaslhxMie95Pw0oyTs9hhoeY2sQFe0mnMNxVABbPpjY0FRlFZWTnoF2lT+qMiTT
         gQFDxqUXgWQ72IRdd9SWf998x2m90BhWYWecaDCbWFqTDirpZ2dCcyscA0+6yGxXBLNj
         CiE05IyGh9oKP9v0q3q0rV/VsoSuHQdSBNrHRuLMJIzvDlVmjIelfiukm3DWp634nLEf
         NqnkcKZcnr1AU7HyLKYvKQvEbMkX+3/UxRbL7cQk0Hflf2c5DUg25THRdnT40dCL4DBY
         PtvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=l1r9JxSmLJtBWwQD5WMXoyMpcIa8PCU8/HG8nOTjmTc=;
        fh=NSvAzB9689xOzGb9utbYfCotqde6p2+uodY2iw9anZY=;
        b=UbzJt3p5bvxsDBahULnv9DhjwVzAB+PGZSn4qcDC6KSHD2JbPOpOtAt8ANKkhW06XX
         iZ6QL9KHYvzD1nwmy8m+t2H1oeP86N9i8r7IS4MZTp0Fbjk/EZ6x0K59tMvv2Ks9TNIi
         pVMI+7hrRsssYVk0HvWzQF1lla3kYzF//SwaoA9Xq6ELEb1vF1CG6MuYMJDeWwYTcIYb
         tjYJVDDfnkq0ua1pULlBpDH8TtkyP+i+TPBn7TelIgtAT+EqeWipBdb144tfRbkttExY
         As1UrlfCGm+izKhu6mQZHQ5SXTX2ysREiIECP1mYWSj7I1wrZoe7fMKmJHxIYzEpWG2H
         zBOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A9fsCeDd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2d.google.com (mail-vs1-xe2d.google.com. [2607:f8b0:4864:20::e2d])
        by gmr-mx.google.com with ESMTPS id r32-20020a05683044a000b006d69ecf7066si121098otv.4.2023.11.23.10.48.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Nov 2023 10:48:18 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) client-ip=2607:f8b0:4864:20::e2d;
Received: by mail-vs1-xe2d.google.com with SMTP id ada2fe7eead31-4629eb39d67so672611137.1
        for <kasan-dev@googlegroups.com>; Thu, 23 Nov 2023 10:48:18 -0800 (PST)
X-Received: by 2002:a05:6102:38c7:b0:457:c953:bc39 with SMTP id
 k7-20020a05610238c700b00457c953bc39mr3960679vst.1.1700765297816; Thu, 23 Nov
 2023 10:48:17 -0800 (PST)
MIME-Version: 1.0
References: <cover.1699297309.git.andreyknvl@google.com> <9752c5fc4763e7533a44a7c9368f056c47b52f34.1699297309.git.andreyknvl@google.com>
 <ZV44eczk0L_ihkwi@elver.google.com> <CA+fCnZft0Nkc2RrKofi-0a0Yq9gX0Fw5Z+ubBfQy+dVYbWuPuQ@mail.gmail.com>
In-Reply-To: <CA+fCnZft0Nkc2RrKofi-0a0Yq9gX0Fw5Z+ubBfQy+dVYbWuPuQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Nov 2023 19:47:40 +0100
Message-ID: <CANpmjNMpPK56mc5wiSoL+AX1pgzG0Kz=SuqGPDme=FFCdhnf9w@mail.gmail.com>
Subject: Re: [PATCH RFC 14/20] mempool: introduce mempool_use_prealloc_only
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=A9fsCeDd;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as
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

On Thu, 23 Nov 2023 at 19:06, Andrey Konovalov <andreyknvl@gmail.com> wrote=
:
>
> On Wed, Nov 22, 2023 at 6:21=E2=80=AFPM Marco Elver <elver@google.com> wr=
ote:
> >
> > On Mon, Nov 06, 2023 at 09:10PM +0100, andrey.konovalov@linux.dev wrote=
:
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > Introduce a new mempool_use_prealloc_only API that tells the mempool =
to
> > > only use the elements preallocated during the mempool's creation and =
to
> > > not attempt allocating new ones.
> > >
> > > This API is required to test the KASAN poisoning/unpoisoning functina=
lity
> > > in KASAN tests, but it might be also useful on its own.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > ---
> > >  include/linux/mempool.h |  2 ++
> > >  mm/mempool.c            | 27 ++++++++++++++++++++++++---
> > >  2 files changed, 26 insertions(+), 3 deletions(-)
> > >
> > > diff --git a/include/linux/mempool.h b/include/linux/mempool.h
> > > index 4aae6c06c5f2..822adf1e7567 100644
> > > --- a/include/linux/mempool.h
> > > +++ b/include/linux/mempool.h
> > > @@ -18,6 +18,7 @@ typedef struct mempool_s {
> > >       int min_nr;             /* nr of elements at *elements */
> > >       int curr_nr;            /* Current nr of elements at *elements =
*/
> > >       void **elements;
> > > +     bool use_prealloc_only; /* Use only preallocated elements */
> >
> > This increases the struct size from 56 to 64 bytes (64 bit arch).
> > mempool_t is embedded in lots of other larger structs, and this may
> > result in some unwanted bloat.
> >
> > Is there a way to achieve the same thing without adding a new bool to
> > the mempool struct?
>
> We could split out the part of mempool_alloc that uses preallocated
> elements without what waiting part and expose it in another API
> function named something like mempool_alloc_preallocated. Would that
> be better?

Yes, that might be better. As long as other users of mempool (esp if
KASAN is disabled) are unaffected then it should be fine.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMpPK56mc5wiSoL%2BAX1pgzG0Kz%3DSuqGPDme%3DFFCdhnf9w%40mail.=
gmail.com.
