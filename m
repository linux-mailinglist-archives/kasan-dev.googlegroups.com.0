Return-Path: <kasan-dev+bncBCMIZB7QWENRBN5WXD7AKGQEE3NAJVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F4BA2D1013
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 13:08:25 +0100 (CET)
Received: by mail-vs1-xe37.google.com with SMTP id a200sf545664vsd.18
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 04:08:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607342904; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fi+sYdpkkn31tO4NxU4D+t/jDzDj4wpQ9CrlQw0Laq0Htb2QohNOfDzMl+Qo9oQfbq
         h/MDk8NoEeJdMjpCVSRRVaOYIG7WiacaEr7zJ4E0PeV9UOXRu9nb3WaB6iJj1xhamF2w
         jpG9+7CBMaaZCNo2u5bzvLxlgqzj7CeGQzrSWHeR5tDYuFy0pMh6O5rFWh24lPoT9vak
         iDPJGREhMcgwQzps5ltRnGNt3wsElAYM+8pLKqSLQ1K3WY1hGyYdo4xBbDSMAhKCJM2+
         f0Enn+tI1NqgMFMF3fNSB/hZZkCjy+QlLEUcqpOveencuy19v7vXjY5jyE3tguq0vTox
         Uz2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JEsUVvSVUz9l6oHbQHzaFwksrooJRzgQIm5zeYkNtv0=;
        b=LzxE867d1P6x7xIRhbqfKg2c3EMwG0avvZj3eQVvayy5fLKrKCkIkM6WWTSTB+Okmf
         7yKkDkrJNIYS/0zy0ARckAhRCYapXPzA4URVcSoHdfiPw3WEnEV9vqh3gPPDB9YPbfb0
         7Grw1wLPFmByLVi5WTMlRGnkHcmAm6npwnwOWG0DPsYRgKyxc7wLv4abqxbYaVZBVxfI
         KD3o1H5AHBi5B2oJAgFuox8ISUFk7zhiqxTax4EhKiM3uxaf0ZsErrGht12X8EW4WJMP
         ydwJ83yIpaoow3wBnuu3ebzLvghHJzBkGLzpm+PnMvIa2GwdkDAF8cjNSbfLl1JOQ+rh
         v0kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gTDKlWp7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=JEsUVvSVUz9l6oHbQHzaFwksrooJRzgQIm5zeYkNtv0=;
        b=qnhPKVdwlkc1G3baRuUn2eQvSHzUGJSH+M1/yPlWRuiWV49khBA7NAinU6lXsFWJHS
         wy0+O/SumLyKiEaGgED4l0Lrx8tEPhDYlGRaxSP4pjRPQjtAxtNzbgahD5ochqBOsIh1
         i+3aUr0YKqW+GogGU/6B2JvjDiXLAn7B5YIVjhJonaxXyCSbvakceG8Wn0lm+1QK012J
         CReCI5sc3ovj9R2N/jw112elc64d9+dNBpDsPBpI13nf1TAfjNMzs/WUV1c1D14loY0z
         ie+fxend8g39qLlqcMlcscFkdb/cFd/ab+pIeXqX5WfchOUnEPATgPDtzwLqJPeIyqBZ
         hgBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JEsUVvSVUz9l6oHbQHzaFwksrooJRzgQIm5zeYkNtv0=;
        b=tAAM2XncFV20dbjUt96XpJ6V5zIoN/incZdgYy7z1+vQkCaiHWupjwrsjPN1m4c9oh
         /3Inz1TCRBdyvrUXjgvJtkrvMeblOTTcNl/XfZXAv3SrDjDTi0dbsgSshlkWbMT2+dK/
         dWmuUYlMPv1BZ+MCRZJncDxkT7e0xMrCut5olsDAFG2lUE3eJD6ff4zvoXy95xTc009s
         YtwskeBlUVFQl/Da+z3Wyi8y4iopVVcCQ0ozs2jyW45/cocjvmLmElVbZev/L5UMxvDs
         zzMusQ9VVi/6DC9Es/userRSBuSEmNR4nIy4leOGCy4jVztQIK6BUh93p3bgSC1SIcFm
         Tzzw==
X-Gm-Message-State: AOAM533mnwUXCqEjdCV/7QqO/b9oKNPDqQVilzOjB0h+44l7i0IbNXLk
	w2T/9owaSkk333Ou7DWEkvU=
X-Google-Smtp-Source: ABdhPJz/e4CrOJU60FkhUw3G5zmNrgG2qy5VuRnPJEn2h1gZHpqOEgaoCKR3T4dReY2BHugEOKjo5w==
X-Received: by 2002:a67:ec45:: with SMTP id z5mr1744588vso.10.1607342904034;
        Mon, 07 Dec 2020 04:08:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:24af:: with SMTP id 44ls651969uar.10.gmail; Mon, 07 Dec
 2020 04:08:23 -0800 (PST)
X-Received: by 2002:ab0:4306:: with SMTP id k6mr11324715uak.113.1607342903478;
        Mon, 07 Dec 2020 04:08:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607342903; cv=none;
        d=google.com; s=arc-20160816;
        b=YO0vBfFcr/PjvpC5MuFN6vT/G6JoIMarYMQ4jwEXrR60HYGmhCcphVtV0aGopAM1QB
         LFpF+xJSz0lkBxCJA+H/56R3vLB5jt4YM2+gpszdOgj1S0bwW2sgelIFAt2Fc7GIRrLS
         VnKoPAgnOBCkGSQIF9chocQGyHVA9PLAz1YWO31QQv15xVbUluplfCLJGpikycn85jy/
         gjoi+TA77AelYPtIr7QK+qzIb67bGS9GV5pNUGKAE3p8+9DM8SsPJ81u3P1wR122ftg5
         cVcaa/XtDkq3Yr6GprRjqjpCngtQfLUAIsOdZO1pH93oxJrwMyw/2iAHqaL/k3wXB0jy
         m9OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=j6WcPj0IELZyPAeHgxTFV18eYU66eVdxYM8UMBwb+6k=;
        b=R14/xE79SjCgJAJ2l9PCEWDtuYLBQNPDXZyBGX/IHyGsq1BpiU234+51MgrgqOKKWQ
         61BuMnLsC80yFykYIpR7hSKIOkadKA/8OunfYR1+btVu/MLCDsdGZpVxn64obuiJ0jmj
         5+uQ7l7AxOPT/fT4a6OUymkhs/nSNr6Fiw5ESzW/3ldQNjTMTzTI3FkJ0C1c1MT6Pcjp
         ezxxEA3caqEwqRNQxfQFm/WbYXDsnwRhzjmZg3k3YI9dPSM06PMtmiXZHA1YsEgOtf8r
         OdpiCVrj+TJid+dFD0mEH5ar4AyillufDgPnWzCarFcBixFDdEcJG+nDVTXRb/WDSDvD
         j7TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gTDKlWp7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id e2si983083vkk.0.2020.12.07.04.08.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Dec 2020 04:08:23 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id b9so9155628qtr.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Dec 2020 04:08:23 -0800 (PST)
X-Received: by 2002:ac8:5386:: with SMTP id x6mr23435656qtp.43.1607342902842;
 Mon, 07 Dec 2020 04:08:22 -0800 (PST)
MIME-Version: 1.0
References: <20201204210000.660293c6@canb.auug.org.au> <20201204211923.a88aa12dc06b61780282dd1b@linux-foundation.org>
In-Reply-To: <20201204211923.a88aa12dc06b61780282dd1b@linux-foundation.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Dec 2020 13:08:11 +0100
Message-ID: <CACT4Y+bYVC=r+bPF7MziOZpJCYqrUj7CFt47Z5PSWjohZLYm+w@mail.gmail.com>
Subject: Re: linux-next: build warning after merge of the akpm tree
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Next Mailing List <linux-next@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kees Cook <keescook@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gTDKlWp7;       spf=pass
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

On Sat, Dec 5, 2020 at 6:19 AM Andrew Morton <akpm@linux-foundation.org> wr=
ote:
>
> On Fri, 4 Dec 2020 21:00:00 +1100 Stephen Rothwell <sfr@canb.auug.org.au>=
 wrote:
>
> > Hi all,
> >
> > After merging the akpm tree, today's linux-next build (powerpc
> > allyesconfig) produced warnings like this:
> >
> > kernel/kcov.c:296:14: warning: conflicting types for built-in function =
'__sanitizer_cov_trace_switch'; expected 'void(long unsigned int,  void *)'=
 [-Wbuiltin-declaration-mismatch]
> >   296 | void notrace __sanitizer_cov_trace_switch(u64 val, u64 *cases)
> >       |              ^~~~~~~~~~~~~~~~~~~~~~~~~~~~
>
> Odd.  clang wants that signature, according to
> https://clang.llvm.org/docs/SanitizerCoverage.html.  But gcc seems to
> want a different signature.  Beats me - best I can do is to cc various
> likely culprits ;)
>
> Which gcc version?  Did you recently update gcc?
>
> > ld: warning: orphan section `.data..Lubsan_data177' from `arch/powerpc/=
oprofile/op_model_pa6t.o' being placed in section `.data..Lubsan_data177'
> >
> > (lots of these latter ones)
> >
> > I don't know what produced these, but it is in the akpm-current or
> > akpm trees.

I can reproduce this in x86_64 build as well but only if I enable
UBSAN as well. There were some recent UBSAN changes by Kees, so maybe
that's what affected the warning.
Though, the warning itself looks legit and unrelated to UBSAN. In
fact, if the compiler expects long and we accept u64, it may be broken
on 32-bit arches...

I have gcc version 10.2.0 (Debian 10.2.0-15)
On next-20201207
config is defconfig +
CONFIG_KCOV=3Dy
CONFIG_KCOV_ENABLE_COMPARISONS=3Dy
CONFIG_UBSAN=3Dy

$ make -j8 kernel/kcov.o
  CC      kernel/kcov.o
kernel/kcov.c:296:14: warning: conflicting types for built-in function
=E2=80=98__sanitizer_cov_trace_switch=E2=80=99; expected =E2=80=98void(long=
 unsigned int,
void *)=E2=80=99 [-Wbuiltin-declaration-mismatch]
  296 | void notrace __sanitizer_cov_trace_switch(u64 val, u64 *cases)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BbYVC%3Dr%2BbPF7MziOZpJCYqrUj7CFt47Z5PSWjohZLYm%2Bw%40mai=
l.gmail.com.
