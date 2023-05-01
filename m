Return-Path: <kasan-dev+bncBDYJPJO25UGBBG73YCRAMGQEUYXR62Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9377C6F3A6E
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 00:30:53 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-64115ef7234sf24670192b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 15:30:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682980252; cv=pass;
        d=google.com; s=arc-20160816;
        b=x+t3Kj8kbl56Ajdau1p2cnv4dmXn6SycK+YdjxDD6fwHGixd3jH7Tdbqs46YTeL8dH
         IKB+pjPBP0QqSqQpg16u3Fx8WnIndpUfdhf1wkxZ8GHAyUV2cejarQGpOaEkr6phrlU/
         ZgKg6CH830mMM3mvlhd/bnfHtuY6mUZkJgKdqv/ndzuYmJGPu8zmSQ3q2UTTIGDic71R
         0m26DNilMRLyXbSPMsJwkE71W7EApSNOM1Gp36GIKAX1Dgk6SSbv6kb5MeUy0kzoPeVJ
         kQ+FkghaEAJ48pLfIyLkwJJYHD090WIuzBvotMyBvPpg7qfYCVX7wu1l9nKjaop3TwKO
         rWcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IF8XNxLtOwLE2rkvZzrw9bEgtTTwnw8zuN6JDTxtMGQ=;
        b=0gyBeay77x4oDCF1637aFNbPAUTz3Cl94TRTQPubJYmLgbMYIWWOrnpOoPBrvSaarv
         fFaloyLztZGSi5orJz8Cxrpekpo99ml+vvsTJ7KDGpWl4p8XwLice07gWPqTE0dfzipp
         47nSzYaPa9bR3afqwbu0wmDbCyl0lTEi9eCBEC7Lbu0OgqTNknAfiPSLKFIK/usvHCdg
         gOD8SUhAFvNATCI5TkfZNfne0q9MOD6SvgGkbsFQnX2oKmI5oqDm2wp9xfQfFjjtdIMg
         X+5sMRHk98+7fM2UKso9Kt5HfHddhxCB6tcSlOeyBvMnaWEWRGZGNVLLDYIOk79yKy7l
         W8Tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=WKCw2ix+;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682980252; x=1685572252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IF8XNxLtOwLE2rkvZzrw9bEgtTTwnw8zuN6JDTxtMGQ=;
        b=SicPi7Jj5bxiejGrR9ez2/zzlJGOieCBqMbmoiYlZazqkH1HoZ3Jx9vLcJjJIvGaTK
         OXCXgP/l8OKo7+1D0ewRBGFxzC2f2N8TUEJvI/f0ymZJuc+tZsZ21OqoX+JGcHcHKrpu
         JY4YVQsZG6M1fJH5bXb8jqpho95oeO0FmVsCwFlmha8qNCMq/r6MCiwYwU/PTdrV/ngg
         DpqxDlqk4nLJ4pT3+OL1O6l0XxyfOHnbCSJW1en0waOExI/FJY2g2EzhUHPWIlmE6TlQ
         8JMISTfBXmcHRvHeGAqrTBCZsLTh0xglUMlYUlSG0CcZcgPiSl+HodGGRDCvSpIkE1Hh
         9x7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682980252; x=1685572252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IF8XNxLtOwLE2rkvZzrw9bEgtTTwnw8zuN6JDTxtMGQ=;
        b=C3msPUTiLTUa9Zkx29SJ8rRVMl28u5rCf3+EY5UyNY8Q3xkAcOTfloSJtnceWVudc0
         Nx5FlNRsZnLedi4vIO/I6DNG54h/LvKPuOfzlOmWSf+H8Jba0EJF9S7bZPPkTi8FW5ze
         SUXrEWKJWdIXdhE4qKScMVW/QYiWUo+GrnVIBEg+VIpQESeQQu4HbEGq4e7h38GcjD7e
         n0973ce+4G8Y96mGcFkppXCi9j1tKpnqBj/RSaAfY04f5PdxyYL+4S0EPcnuRqHNjVWj
         EJKuQurYG5xRKHG6rm0WVHt35ENSKAwd0WoccX438muQu8XLFN531rfLa2Y9sFa7ISUI
         J9nA==
X-Gm-Message-State: AC+VfDwm209OrW4l4DB7+d20c5iNBtRUmlK4ewHhHBZtfcnKqiQIxv+Y
	zERNbj2OTM6fSKOsk8OwZPI=
X-Google-Smtp-Source: ACHHUZ70B84UEgjVrYDImn/SZckJkH/bvCCdlXEDZ159NRXlu1gjkIcnpmQpKdksGhWwvRz657NcQQ==
X-Received: by 2002:a05:6a00:7c9:b0:63d:38db:60e9 with SMTP id n9-20020a056a0007c900b0063d38db60e9mr3547324pfu.2.1682980251927;
        Mon, 01 May 2023 15:30:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4f88:b0:24d:d807:e954 with SMTP id
 qe8-20020a17090b4f8800b0024dd807e954ls6068605pjb.3.-pod-control-gmail; Mon,
 01 May 2023 15:30:51 -0700 (PDT)
X-Received: by 2002:a17:90a:8185:b0:247:6be6:7ba3 with SMTP id e5-20020a17090a818500b002476be67ba3mr14963957pjn.32.1682980251208;
        Mon, 01 May 2023 15:30:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682980251; cv=none;
        d=google.com; s=arc-20160816;
        b=SY7WYWIRFGvcwA60z7Sy/1+E23lccbK62a+RK/Liz2RQ7TfIPUa6aRMrRasImtAY0+
         tXvBhjsOLB11+wmcL4gFruTvfSjjhvQwDL9CL6Zo6mrwE/NrmfkM6rXyBDZ+67sDD6iR
         QAXkCuwfpBlI5ptQfVzadTQItVtQ4p4sYSrKgRFQXt4ub/OHKeI+vYLLAq9ZQmsKV9us
         E6mLvyM/IwGAoM/4Sd51cjmpyj/sWjZyG0MnX1HKFXitAmErp+6yRTfQ0VfuGkaKTzSN
         24Ug5BJAYm2mC7a/cMlHc1rAE5g6/p8Pa4K2B/nyfuY5GjJRc0dSEEQoKXgii6b/ynX3
         gI2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=r0vZEv/FmAjqR4OATKlbblWETdmbuJQmkbVqTAuStBc=;
        b=Cacu3mX1+h1L52+63kPR72u3zFXgkncBBtGKxMoWdvMnVOTAZvd17KgL8QCg3V9beD
         jkZHAj7HtnjybIDCwHXpeOfZ0fOi2BoczWSIGaZpsfAfCMoHZeVhEeXKgsD/e/HGIcQW
         wFh+uECnzgAGciXKPQAlhmMO2qeFfPaalJSda5fzWAnw8V3c/LTBYuoiFTZada9i20b/
         9KPN2RDyiV4+O1a+RFTEvoaOrAYbCWcj6GuXtfvccvNyH2JADy4thgirSP+xjfchkcl2
         XD+1ZU1iEhzYggp4J+yO5YWWcJRuz6ioNxx96mi5gw8pmZ5VPCWjuJYsoGo4gBy60zE2
         5CiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=WKCw2ix+;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id z65-20020a17090a6d4700b0024decfd9cd8si422101pjj.2.2023.05.01.15.30.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 15:30:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-24de2954bc5so1703599a91.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 15:30:51 -0700 (PDT)
X-Received: by 2002:a17:902:e744:b0:1a6:b23c:3bf2 with SMTP id
 p4-20020a170902e74400b001a6b23c3bf2mr18550422plf.10.1682980250619; Mon, 01
 May 2023 15:30:50 -0700 (PDT)
MIME-Version: 1.0
References: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
 <CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ@mail.gmail.com>
 <CANpmjNNvGL--j-20UxqX_WjeXGiAcjfDAQpfds+Orajz0ZeBsg@mail.gmail.com>
 <CAMn1gO6reT+MTmogLOrOVoNqzLH+fKmQ2JRAGy-tDOTLx-fpyw@mail.gmail.com>
 <CANpmjNN7Gf_aeX+Y6g0UBL-cmTGEF9zgE7hQ1VK8F+0Yeg5Rvg@mail.gmail.com>
 <20230215143306.2d563215@rorschach.local.home> <CAMn1gO4_+-0x4ibpcASy4bLeZ+7rsmjx=0AYKGVDUApUbanSrQ@mail.gmail.com>
 <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
In-Reply-To: <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 May 2023 15:30:38 -0700
Message-ID: <CAKwvOdkgwHcZKndei2NcMn+Z8y1HjKCUpMxnNCbcCGm9EB-o0A@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
To: Peter Collingbourne <pcc@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Marco Elver <elver@google.com>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, linux-trace-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=WKCw2ix+;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::102f
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

On Mon, May 1, 2023 at 3:02=E2=80=AFPM Peter Collingbourne <pcc@google.com>=
 wrote:
>
> On Thu, Feb 23, 2023 at 10:45=E2=80=AFPM Peter Collingbourne <pcc@google.=
com> wrote:
> >
> > On Wed, Feb 15, 2023 at 11:33 AM Steven Rostedt <rostedt@goodmis.org> w=
rote:
> > >
> > > On Wed, 15 Feb 2023 09:57:40 +0100
> > > Marco Elver <elver@google.com> wrote:
> > >
> > > > Yes, you are right, and it's something I've wondered how to do bett=
er
> > > > as well. Let's try to consult tracing maintainers on what the right
> > > > approach is.
> > >
> > > I have to go and revisit the config options for CONFIG_FTRACE and
> > > CONFIG_TRACING, as they were added when this all started (back in
> > > 2008), and the naming was rather all misnomers back then.
> > >
> > > "ftrace" is really for just the function tracing, but CONFIG_FTRACE
> > > really should just be for the function tracing infrastructure, and
> > > perhaps not even include trace events :-/ But at the time it was
> > > created, it was for all the "tracers" (this was added before trace
> > > events).
> >
> > It would be great to see this cleaned up. I found this aspect of how
> > tracing works rather confusing.
> >
> > So do you think it makes sense for the KASAN tests to "select TRACING"
> > for now if the code depends on the trace event infrastructure?
>
> Any thoughts? It looks like someone else got tripped up by this:
> https://reviews.llvm.org/D144057

https://reviews.llvm.org/D144057#4311029
Peter, please triple check.
--=20
Thanks,
~Nick Desaulniers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKwvOdkgwHcZKndei2NcMn%2BZ8y1HjKCUpMxnNCbcCGm9EB-o0A%40mail.gmai=
l.com.
