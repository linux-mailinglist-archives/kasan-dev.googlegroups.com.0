Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY67YGNAMGQECJ5LL5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CB2D60522D
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 23:45:08 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id b14-20020a056902030e00b006a827d81fd8sf17377567ybs.17
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 14:45:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666215907; cv=pass;
        d=google.com; s=arc-20160816;
        b=fxWWLT0sZwJQqS+oxe4xd1s23WDDOxDyxUyTCHac4pcR3+SkhbEmHvHFgiiCzzAXC4
         gXMm9JNJb9+ui0LMxP3hzyte7zud15iEB0s9pygyvx7Zh1gwmiSKtOq9gnSbyCb3Kt4K
         AVeQQhZpGuZHr72+A+HllpwPTM0+RTmKsyCjSPJp7tKAYdolx2kuJlNYaLN+KOlHBsST
         FdOlHYHlguNxPvId4W1OCtH5u5UeQvVZPfO4oiWY78kU9FJuThUKmS7/Pb1A6Li2zawq
         kTNZddf8m1DoAxo/DL98u/TNkmFdEu3TReD5Fj7pPDJ6YGIZy44i/Wp9ihi1J128HiDH
         lzCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=unz2xazXNUMrrX27f2WAJNzMMQiL3XnBI1dGpeqogkg=;
        b=s8aPRtnxBmwKQSSvPP3qZ789CGFh6FeUfKt/AzZkVhFiN/a213J5Pu+3RnfafJfaam
         /UykqB9qHV0uAjZ3yYfO5DdG2iWLnTplN4p2004jpTxJwCbO4V0VMJZyz9uU0chmKq6C
         GPBw0nYC+qsZSoox9HH9s+8Zy5k75yqkZHsxqGGDjUD+GwZRQ6lyXEtGrZlhk52leBTO
         Dd8O2+EQ7l8CFse8/QLU8GMAYIKTQIeDCIFOWjxO2PigAcBu//9cKoLvZNfrDxzBNLf2
         g58CRXKx4loGqDPtP9ag03CPrauFP3qaLG5qu4JPmF8no3cYkLVOdEkcQiYJaoiRluyh
         5W+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=liH6o19V;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=unz2xazXNUMrrX27f2WAJNzMMQiL3XnBI1dGpeqogkg=;
        b=nrwrSbm6uOEixgKYNVV3DazTpWt3BDNT/eoBxDNHev8xpeCYdvjSFyd8w4B5dr/5rj
         dvoMSahJcv5kcLfSN1Ck2RW2yufkjL5W9bCQUIAt4B1K3ALkvmtvENdOikXbPOrBKBoV
         MNHJ3xIi/pR7gtrT/k5PuNcIWpFOdj0R5d7mqkJxQ45neKISMnlWex4FKWuywIx5B9Ts
         6afwogR0OuNq6SHn8jTYuNiggcklAWiTWjrHW3ZyN1EFbrISGOKP5yHND2NNa4iPnZ6G
         C6gHFR/C1yWD0ET4776Dgnl5tQ4rJKigvK8wKgAE7SL5b7krUf2hW/dK3GnpK60GElSI
         CfZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=unz2xazXNUMrrX27f2WAJNzMMQiL3XnBI1dGpeqogkg=;
        b=0Ue8dwrZKqQXL7tPkVgluddErvhQpwZM3jjMUFAVV6wntoobaRhY3/S1pX3tNabRad
         KLhor9bkyXjl/gwRfqvk31ltRlAGXZ7R+kJGrBE9seKbbLTZ3HNQongZBVuYyNFs5FEw
         eL3f0rSYA2A19umxIZ2kWYDD+Nrj61vUg7FjBq43NRD1Yl7DuE/8KEMlUhqIT1veGxQE
         goDIfIkyNsgSip5IdEcv/Q5gXHVdDFF9IamoItwB6YB6VXXGlv8NQ8PGIN8SSt7nS/2+
         uub8Zd5Wb8Cy3RhCn4bEEaaJQUWBiCby/quNdCb1lxO9remsaqwgPmgL844+NQ3Fkhd9
         zfjw==
X-Gm-Message-State: ACrzQf3xBFTDvyz2Dy8r3/NL7zMWWCLw4pbKd0NXSPpf2Z6wn+njOx7l
	vglSNbSbENjsfS84R4DXuOY=
X-Google-Smtp-Source: AMsMyM62SN696gz3HSMMlKhBL3+GL9THxW7gtjJtCHj7R9S88N4mKthqXUXbyPGtBStbLOoOl5ayKw==
X-Received: by 2002:a0d:cb4b:0:b0:354:473f:a431 with SMTP id n72-20020a0dcb4b000000b00354473fa431mr8395275ywd.463.1666215907351;
        Wed, 19 Oct 2022 14:45:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:cb85:0:b0:367:9f9a:d872 with SMTP id n127-20020a0dcb85000000b003679f9ad872ls790729ywd.11.-pod-prod-gmail;
 Wed, 19 Oct 2022 14:45:06 -0700 (PDT)
X-Received: by 2002:a81:7058:0:b0:34d:a44f:2336 with SMTP id l85-20020a817058000000b0034da44f2336mr8442664ywc.361.1666215906825;
        Wed, 19 Oct 2022 14:45:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666215906; cv=none;
        d=google.com; s=arc-20160816;
        b=TrXBv64hlj8AMuwK8AJ9+noyIFWtOgk71aI10pYcQOa4fGf2xRv9JheaSSlxgYobIj
         oggOv5kKsp8FbobGZi/MPq9MYZBFFxD4dklSxghO/FvGI/ffPTuDKxE+E3ThJ0YkFjke
         hGz6E+Bmbf8WCdFCglaFN6g260KeeD+BhK6nOAOXNxHpQXaUReuaMSw5tor2sG9tuhV0
         nB2Sc1F3f3IW6eqw/skUh7359eHAd+NRUX1dMyxF4jH19VIIlm7DyVZnnCpryAw5TZTM
         xD1Ft5S0sg5vDFUemd/vygMvmr9gPi2+qZxF74bxZUitX3nEGJgEcQFGHFiVZpiqIRqr
         c3Bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7ghDToPdvK1mpXEhLmg0q2dWGU3wc/xDHdpsX0rO9Q0=;
        b=sv4nXNH89v3VGo5a91bNxKmVimxGJkW+tafwprnuZB0SQ7z7Qoe4t3h1UesmRo9fSW
         kuq2V7j7amVPBGtdYu0/YKnHG+vioeT61siis+43g5DGr7HD8kTrBTyEp0fvuBEiFovZ
         0Fcu54psVlCj3NKamBwaNM3IjlTm/jj3ir48pqEPZ3EcB6vnntiiXgZqAox7wVMekXyr
         JmcwJtbx7fs9MzgpLXsBo9RUflce2wuAKtBv3swbCc/uTMP/QwlnUj4I4CQ+EgVgxnhv
         vgMAypucZm2aHNpuJvwUbvglvZz7GiElXwuVcqo3rMkuGo7qWKFIhrTlpvkQKwy9LENL
         S9/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=liH6o19V;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id s187-20020a2577c4000000b006be3d17ff2asi1061445ybc.1.2022.10.19.14.45.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 14:45:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id j7so22440526ybb.8
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 14:45:06 -0700 (PDT)
X-Received: by 2002:a05:6902:1369:b0:6c4:8ae:7b14 with SMTP id
 bt9-20020a056902136900b006c408ae7b14mr8299284ybb.549.1666215906319; Wed, 19
 Oct 2022 14:45:06 -0700 (PDT)
MIME-Version: 1.0
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
 <Y1BXQlu+JOoJi6Yk@elver.google.com> <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
In-Reply-To: <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Oct 2022 14:44:28 -0700
Message-ID: <CAG_fn=WF1i+JL_E-7wWEpgtxRNssm_vZx+hqGh_pYDuX1WGPVQ@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: youling 257 <youling257@gmail.com>
Cc: Marco Elver <elver@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Biggers <ebiggers@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=liH6o19V;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as
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

On Wed, Oct 19, 2022 at 1:07 PM youling 257 <youling257@gmail.com> wrote:
>
> That is i did,i already test, remove "u64 __tmp=E2=80=A6kmsan_unpoison_me=
mory", no help.
> i only remove kmsan_copy_to_user, fix my issue.

Do you have any profiling results that can help pinpoint functions
that are affected by this change?
Also, am I getting it right you are building x86 Android?


> 2022-10-20 4:00 GMT+08:00, Marco Elver <elver@google.com>:
> > On Thu, Oct 20, 2022 at 03:29AM +0800, youling 257 wrote:
> > [...]
> >> > What arch?
> >> > If x86, can you try to revert only the change to
> >> > instrument_get_user()? (I wonder if the u64 conversion is causing
> >> > issues.)
> >> >
> >> arch x86, this's my revert,
> >> https://github.com/youling257/android-mainline/commit/401cbfa61cbfc20c=
87a5be8e2dda68ac5702389f
> >> i tried different revert, have to remove kmsan_copy_to_user.
> >
> > There you reverted only instrument_put_user() - does it fix the issue?
> >
> > If not, can you try only something like this (only revert
> > instrument_get_user()):
> >
> > diff --git a/include/linux/instrumented.h b/include/linux/instrumented.=
h
> > index 501fa8486749..dbe3ec38d0e6 100644
> > --- a/include/linux/instrumented.h
> > +++ b/include/linux/instrumented.h
> > @@ -167,9 +167,6 @@ instrument_copy_from_user_after(const void *to, con=
st
> > void __user *from,
> >   */
> >  #define instrument_get_user(to)                              \
> >  ({                                                   \
> > -     u64 __tmp =3D (u64)(to);                          \
> > -     kmsan_unpoison_memory(&__tmp, sizeof(__tmp));   \
> > -     to =3D __tmp;                                     \
> >  })
> >
> >
> > Once we know which one of these is the issue, we can figure out a prope=
r
> > fix.
> >
> > Thanks,
> >
> > -- Marco
> >
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/CAOzgRdY6KSxDMRJ%2Bq2BWHs4hRQc5y-PZ2NYG%2B%2B-AMcUrO8YOgA%40mai=
l.gmail.com.



--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWF1i%2BJL_E-7wWEpgtxRNssm_vZx%2BhqGh_pYDuX1WGPVQ%40mail.=
gmail.com.
