Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ4JTL3AKGQE5TV4SPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id E63A51DCE4E
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 15:39:52 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id w11sf5218938pll.15
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 06:39:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590068391; cv=pass;
        d=google.com; s=arc-20160816;
        b=sfhoLGWvjcLt5NRYXikUfYnbzMiN9ox06drLflZ0rfWMWOa7z+132tN6wdH8c6Ydv7
         Z27Q2/Vmit5TE+7QisMmNML+YstNstDC7ejq0l0c3yIRWbIcA0gHe2ZXhBRH1Noxei6I
         wcDx3aH3PmWdWaN7rKxfzRu8BjsHmm7M+a7msVn0Iw6eHTK/Sz2RJOF1Ec1RHABM4zIU
         zp4V7IeXZGer9/GBEleIYv7KlPaZ7vMKegaSEfYIFGQDlusONVtYsE0xfw9FtHJAdo0o
         lr79VD5O/7JAvJ1DR7mb0lGL2TJElufsqPxVS+w3fOhGK8ezMroHHkXGtivVHurCWHyB
         HiQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/E+w/3GafQ0zWngQ6QQv9+8pb0t6DuXWJp8D5AW0/AQ=;
        b=Iw0Iw0hyfVvftfAHGwJDPHpZSQTXhKOeIRKJafgD5de/lqzVx/1mcq4ucSjcOTZP4z
         S130WcGUeRBK5CmddpQTqacj4yvmhPsQ0IKVBy7WcWdE3oKajOmvR9hYg2apOd0xXPZH
         Rxz3qZlFTuwrERrANXIiE+KLCaR2LTdNvLKJuVifsqe8IwPKNopLFHCSqDSJMxUhXIo2
         9e6l8dse6JMdmWFOQ/t5omOGcCrhpdrPKDCXc0zXefY2t10mB+KGV/TdiPhkllo4vyNl
         KpfypLuU/M1uDDj56Tqi9E/APxulL6g59RFckkAjeGgjj6SjXHghUSsT8FC3MSsW69Nc
         oMBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gA+IMnIW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/E+w/3GafQ0zWngQ6QQv9+8pb0t6DuXWJp8D5AW0/AQ=;
        b=MCbStEegQFdBUEHyz+WuRES75rF1+O4s31/A8f+be6n3e526csbQKD1ak0+V+8GW6h
         i7Y/Jt2jx66HUaz8xgBF8WWmeCTR8JC6KbJqmPTxBnPll0JpnxYRzYfk+lNDSbK7E7sB
         EaY70PYgjMBOCqK4zup4eVwpnlLAxKtU+kshVwZEWjmeUePUgPvjouIN+yfCH3qsg3j6
         n+kebxt3nIRIjDv/kzhDuqyoGGFkFyiHGMO+pZx7a/GULoqB0ov0Vb/uxAj4RHPsvz+s
         bt6TumZvWnYO5fr1zt0378VwHQhmjAOvwPByOjowlMMNfIZN8dphwM+LPpY9+lyj4KcN
         fTKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/E+w/3GafQ0zWngQ6QQv9+8pb0t6DuXWJp8D5AW0/AQ=;
        b=IhzfQ1wriwSVaJ9yGBe1M0v5v3ZWY7RSc+Whl7TF4P5l/wtNnIlCdsxpzlAvoovEBJ
         ZaEos8ETvWPNcNZnsmdoWiF0YQEVQbEFLBuVOc09RVXn4y9Yt1HRP1K36ghPkykwXW60
         siAxDXClV9Bku+XDok2gyHJNiDjDO3P58vW8zZaS1jNprAjeRPwFeL1nmIU6W2sUSKbo
         TT62BKrf9vjOExsPmC1vzc3R2LkfhoxFTuZnUfJco+jYLefIPAwFvkk7h4IQg3O1J2Qp
         u7z+VrWI/DJbsPKNRyzbBlXVAGSIVyfAmDgJmOnzf+SUZAvk/sts5nq8pwCP93u4nGQv
         IICA==
X-Gm-Message-State: AOAM530Qm/WOkASOWuyAdzS3Vb0P/qV/sCvligdTVGrsSg+vf8xRsaJ0
	+1Wy76STr5F5k64KscBB5BI=
X-Google-Smtp-Source: ABdhPJy9lVZtd+fnYOUibVMCqieraSS3yj7YHUECcZpI+esj/C0HVoxbcKp496AUiiT1ZWB8pui8Wg==
X-Received: by 2002:a63:2f41:: with SMTP id v62mr8943664pgv.178.1590068391603;
        Thu, 21 May 2020 06:39:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1acc:: with SMTP id a195ls668473pfa.11.gmail; Thu, 21
 May 2020 06:39:51 -0700 (PDT)
X-Received: by 2002:a65:608c:: with SMTP id t12mr9215959pgu.46.1590068391130;
        Thu, 21 May 2020 06:39:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590068391; cv=none;
        d=google.com; s=arc-20160816;
        b=NevOAqysN+8CqetS5us7d5ODAaXdAC4RxsaZlDj+i6WrtyXSpXZLmaC/RTWJNsd/l5
         +KjdIO4vqRyGktHcmOZZjFbAbO6+K/xG3+q4bGytOEDm3VkrdF4YqIofxoiPiYd6DSmy
         oMxXUij27MlRZFsupEpdRB5iRgC7Rm2XZnw1hWsOpW5sqY01RbLJm5oZqG9EIuYJDrYH
         Q//2AYs7y3Pd3vNdBF3K3sFUeqs8Lak2fi56ylnJV86t1CertxZpmkhAQTzJbGlS0Ltu
         f5i/zpArEQVSSLKYvxRDAk4648DnqqL8gyRBhV7InZzKqb93d9Q8XPbJ26ZTocuv7h77
         2Cag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L/LyXHTvDj+xHsQkYhu/jnhClGb0G5rs8Coqbegx7nM=;
        b=fnMDFd0g57ohW3k/Ay9VpfpDkzYJEPkPXpGYzLIoo1rQITUGgmJPQJnbC7vQmVOnjv
         mSl5AGcaCKgcusDErwfOEDf7hovY7MHgTudnEitqrM3s1nY0Pid0bFv+vb7YL7c+cb0u
         gT4xMjfSHmS+yxTV7rEuLIlc2cnmjj7CHj9KM4r6B4Ujn3CpTn3F7n63y6wsBEexLZq0
         OBRFyZf06wA9ANPdWY/zE67TZZOfcyixm5PMXhLs3ndYlCuQw57rkfHOpx+SKtuEVNod
         YurfdDj8wdCcSCMQ2OqgcWxkNTgFyAnk34+MMpUSz/gYSHQmbtE5CVfGHKM3pR15eh8X
         nF4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gA+IMnIW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id c14si639216pfr.6.2020.05.21.06.39.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 06:39:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id o13so5518988otl.5
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 06:39:51 -0700 (PDT)
X-Received: by 2002:a9d:27a3:: with SMTP id c32mr7608614otb.233.1590068390262;
 Thu, 21 May 2020 06:39:50 -0700 (PDT)
MIME-Version: 1.0
References: <20200521110854.114437-1-elver@google.com> <20200521110854.114437-10-elver@google.com>
 <20200521133150.GB6608@willie-the-truck>
In-Reply-To: <20200521133150.GB6608@willie-the-truck>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 May 2020 15:39:38 +0200
Message-ID: <CANpmjNORDOZxpk8=dRNu86V5YcJeinAq0K=8PZs39HXDLwNNJw@mail.gmail.com>
Subject: Re: [PATCH -tip v2 09/11] data_race: Avoid nested statement expression
To: Will Deacon <will@kernel.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gA+IMnIW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Thu, 21 May 2020 at 15:31, Will Deacon <will@kernel.org> wrote:
>
> On Thu, May 21, 2020 at 01:08:52PM +0200, Marco Elver wrote:
> > It appears that compilers have trouble with nested statements
> > expressions, as such make the data_race() macro be only a single
> > statement expression. This will help us avoid potential problems in
> > future as its usage increases.
> >
> > Link: https://lkml.kernel.org/r/20200520221712.GA21166@zn.tnic
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v2:
> > * Add patch to series in response to above linked discussion.
> > ---
> >  include/linux/compiler.h | 9 ++++-----
> >  1 file changed, 4 insertions(+), 5 deletions(-)
> >
> > diff --git a/include/linux/compiler.h b/include/linux/compiler.h
> > index 7444f026eead..1f9bd9f35368 100644
> > --- a/include/linux/compiler.h
> > +++ b/include/linux/compiler.h
> > @@ -211,12 +211,11 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
> >   */
> >  #define data_race(expr)                                                      \
> >  ({                                                                   \
> > +     __unqual_scalar_typeof(({ expr; })) __v;                        \
> >       __kcsan_disable_current();                                      \
> > -     ({                                                              \
> > -             __unqual_scalar_typeof(({ expr; })) __v = ({ expr; });  \
> > -             __kcsan_enable_current();                               \
> > -             __v;                                                    \
> > -     });                                                             \
> > +     __v = ({ expr; });                                              \
> > +     __kcsan_enable_current();                                       \
> > +     __v;                                                            \
>
> Hopefully it doesn't matter, but this will run into issues with 'const'
> non-scalar expressions.

Good point. We could move the kcsan_disable_current() into ({
__kcsan_disable_current(); expr; }).

Will fix for v3.

Thanks,
-- Marco

> Will
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521133150.GB6608%40willie-the-truck.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNORDOZxpk8%3DdRNu86V5YcJeinAq0K%3D8PZs39HXDLwNNJw%40mail.gmail.com.
