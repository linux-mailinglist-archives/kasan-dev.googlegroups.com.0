Return-Path: <kasan-dev+bncBDQ27FVWWUFRBI5M433AKGQEOWZO5RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id B1B971EEEDF
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jun 2020 02:47:38 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id m2sf5866336plt.17
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 17:47:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591318057; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dj36DDWTa/jaf3DVN3auR8FgYSJBRZQ02CcV23kRv6zveGLEI/Qp4RqhZNPZTnuy5c
         7GI5rO+YXaTCsgAZtfZczxh+tQPcw4eJY7HfjfcrSSkJOllnLxWUpQX8lvS4ZtrvyX7O
         I/xnbRrS/NNtd1FU0Wq2kE0xPMmFX0uJ3YSxyGvfVq9TvBsJbtp4F9U902CNtxM4UWA3
         PnVgqUmCEBMLHPIjSuDf4iHeJkmn2AIhCgEzqQKln+NDnTZPyphqLEczavQ71Qjcyl46
         4iMYdPEk7jq7d4AUT9ME+MxK/XoqvsM75v3BiONqAvQWTeKx5ThQKS2RRuAVidgV2mvu
         LQLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=+mdsasYa9aoSrVFYqNu7o6ZuPVmRGj88IMB+jCwEOAU=;
        b=L6rStf9X+8K/EvmzOby71ZHxalsFVNjDOq+/HyiPu/1/AQ5eqH3VpCKrRws9Tb6Gkz
         Y+w/1UDcO60xe4BA8HBPjkSTmA+GkjoBFCQa+vhEzuLTGQWpuBOHXUFgFNL7P97BLzjX
         rGBnGGI7LbLwiVAelRHuaocx/Anq0/axpJ9N3vWpFTZMVPch5Hpxl9S8rjfVLPMzRLOX
         wmgLa8uxV17zmrZwxUNuLR7ekYSjFofTmkKy3olKL/2xYqDmc6R0yBlQWT+qqMaojqUR
         mO8vPUqSgKH2scXEFXIYxfXAjpybiCbN21TwRwXLSfDmCDd61pjXCHS/zsUsuZblvbsz
         yPRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=TqG0v5Gm;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+mdsasYa9aoSrVFYqNu7o6ZuPVmRGj88IMB+jCwEOAU=;
        b=W2FNG4DWxf3NJZ1wOp8GNMbfBeUW2CAemXSGJzijwcApO4EliAA85w4fw2dzo41GdS
         qa29eD7ThsMn/0+SBnhzG7UECPbNUk4gZipfl2aFVmYh1U/RwklG7uiKRJ26ngQufBqP
         HMZ2B2YUaAjS5RzHUFFDZtcP1GH4cO3w49fNkGZoB+iZ+te8ktB2YM/n1KkI5mpvwV5R
         WXyZa8tJ9PXV7RACrCg4XOblEd82qIgwF3Gkry23tkQpeiu3r9eHLyawFyqA6sEANL5M
         aiESPCUAZ0NqHvTzCglvjS0Hx7cngs+gaIsM+iU6fc3RXEsMA8Qj1Qbjlq45hnMM1C8u
         1F1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+mdsasYa9aoSrVFYqNu7o6ZuPVmRGj88IMB+jCwEOAU=;
        b=ObfRw4BFGO5/wEKxmF9OKTiEzkS61H5k9MIiUdrEGDNZ66ODKJRjQoQQhja0jO4oO9
         cl6kqh0E7D+0VtLe8YAeDuyVdqZos9m71puIUzPPVdqRMENt+JokI9Ib0zECdieXVLfb
         SVXMyfsJE0IedpwC+Y78UCf5ZTrEpbF88gI5ne6w3ui0z7ufWgS7nhi5xLvRYn/9IApw
         Gb5uUzu8KENs2atO2di5SNrLLWAgxfkcC4J7zY59TPDSFTW+wVxlrarqePXL05MAUmUn
         ygcbn0QhVYaB7LYF7B5bAs2pehIH0f6GdTzLVc9mJWhFKOV/JVbuVc6xIY3XtvxfMnfp
         u3Sg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532DHL+Wp01RQcnxnbu/d09qNrnsfG8+9r1v3XYcP9YwZmN1yyEM
	N5+XeKSpkEYPeZOzAjZC9fo=
X-Google-Smtp-Source: ABdhPJyhYPQrJ0yFao2uTkljyE0sc9h2b15Yw7yg7eyzH7DQEHNlkkFTO2PVVudXc/GqeJDTufsC+A==
X-Received: by 2002:a63:7988:: with SMTP id u130mr7161076pgc.447.1591318057433;
        Thu, 04 Jun 2020 17:47:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:94:: with SMTP id 142ls68109pfa.4.gmail; Thu, 04 Jun
 2020 17:47:30 -0700 (PDT)
X-Received: by 2002:a05:6a00:2ae:: with SMTP id q14mr1393149pfs.255.1591318050731;
        Thu, 04 Jun 2020 17:47:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591318050; cv=none;
        d=google.com; s=arc-20160816;
        b=DuurnXCPWVD3eLkM13VGOi5QuyNi//6rPlmZjEXMwjeT+NVAZQJaMvV8sBSnTob/1U
         dJkY1YsqbaqAkIMDU8kOrzxhiQPcVzURem9bOwxVdlYYjkZi6uAZQXjlpvejua63etS5
         DP+u+ClgNhh2uJvDh6hFK0DSNXDP9Ya2Z8VIbunTUaAiQ9nSmWDcVngHRqEzUKIlL1o8
         UlggUjeYsUz0I4ieNkaRkNIJFfWBdX1SU0VtK/KkfGCbz1iTLZt3E6uMLgaJp2niyK35
         xH+iDr36RmJ2v4JsBk2TuhlY/cVGvQT3Jllz772Jslf2h9RQpPCwioAkadNUZ7/RmLGk
         rx6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=rLe4dy6o0telBopxOwCIhML+PrpDd2LQ5Ti9SgX6l3E=;
        b=q4JHrTXLidZ8/Y9rVfpVInj4I1lweN8bHJjO7o+QYE/02O1ck98imx2p+nFRHCFf6o
         DQ2mRfzeojcn5r3rL/iCPi+xPycTyw/JFxFuPjXvMoxhiWT6Wx5ymefrCwbufBJYbXte
         r5BLNrB/+Z+0bcoS6hGC8lu6VAB6s2S14nNiNw9ngF4B4d6Zc6+lfCx9Ar/re6+1DjXV
         D/t07YlbIM2hFt15aSj3PD/hmYG1SQUxVNJC9JFf2UUk7IvuwLIcmSQyRdz16vDTbhAW
         Sxu/z+FhCCSPqq0vYnt2TNt1UK055HmGHIjLQ8hMGRkRl3t+oifR8s0nIQp+ioaop4lc
         XFsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=TqG0v5Gm;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id l22si442469pgt.3.2020.06.04.17.47.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 17:47:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id s23so2767130pfh.7
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 17:47:30 -0700 (PDT)
X-Received: by 2002:a63:3859:: with SMTP id h25mr6930234pgn.370.1591318050324;
        Thu, 04 Jun 2020 17:47:30 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-38ff-14ae-6725-69ce.static.ipv6.internode.on.net. [2001:44b8:1113:6700:38ff:14ae:6725:69ce])
        by smtp.gmail.com with ESMTPSA id 10sm5540793pfn.6.2020.06.04.17.47.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 17:47:29 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Raju Sana <venkat.rajuece@gmail.com>, Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>, Linus Walleij <linus.walleij@linaro.org>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Abbott Liu <liuwenliang@huawei.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
In-Reply-To: <CA+dZkakGP0O_H2x0z+z_xojtDHR59jKqb1M97KvO7yjzxsC5+g@mail.gmail.com>
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
 <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
 <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com>
 <CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1+jrLZNqVrLvKQWA@mail.gmail.com>
 <CA+dZka=1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg@mail.gmail.com>
 <CAG_fn=WM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0tYg4Q@mail.gmail.com>
 <CA+dZkako-AaeWJ71eHHLnJVWxbCUWkrc7b9sSWZPUSLL-ty=-w@mail.gmail.com>
 <CA+dZkakg-PpowaqknoKcoy3RDWSNbEAqSVm01SOOYDxZKV-WOA@mail.gmail.com>
 <CACRpkdY9pbM--gBU2F_3Q=AdB1Fsx4vHzc5O-3Fq0M105SQWLg@mail.gmail.com>
 <CA+dZkann4Z1TavtJ+iq9oBrAiAaohZfke8aoyhcqvs_CYSuirA@mail.gmail.com>
 <CAG_fn=XjmgyxDANUN0a8kY2CuucQ2gHFfQqsk6TF_XpiqWGCgw@mail.gmail.com>
 <CA+dZkakFEJZLtfe7L2oN4w4O=T+x1L2WxZyKtSyofs8m3wLEzw@mail.gmail.com>
 <CAAeHK+xA6NaC0d36OtAhMgbA=sCvKHa1bN-a4zQZkzLh+EMGDQ@mail.gmail.com>
 <CA+dZkakGP0O_H2x0z+z_xojtDHR59jKqb1M97KvO7yjzxsC5+g@mail.gmail.com>
Date: Fri, 05 Jun 2020 10:47:26 +1000
Message-ID: <87lfl2tk2p.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=TqG0v5Gm;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Raju Sana <venkat.rajuece@gmail.com> writes:

> Thank you Andrey.
>
> How do I access those patches ?

They're now upstream in Linus' master:

commit adb72ae1915d ("kasan: stop tests being eliminated as dead code with =
FORTIFY_SOURCE")
commit 47227d27e2fc ("string.h: fix incompatibility between FORTIFY_SOURCE =
and KASAN")

Regards,
Daniel

>
> Thanks,
> Venkat Sana.
>
> On Thu, Jun 4, 2020 at 5:20 PM Andrey Konovalov <andreyknvl@google.com>
> wrote:
>
>> On Fri, Jun 5, 2020 at 2:14 AM Raju Sana <venkat.rajuece@gmail.com> wrot=
e:
>> >
>> > Hello ALL,
>> >
>> > Thanks Alexander, I did attach to lauterbach  and debugging this now..
>> to see where exactly failures..
>> >
>> > Initial Issue  behind memcpy failure is due to  FORTIFY  is enabled in
>> my build, after turning off the FORTIFY  like below  , I was bale to gte
>> pass memcpy issue.
>> >
>> > index 947f93037d87..64f0c81ac9a0 100644
>> > --- a/arch/arm/include/asm/string.h
>> > +++ b/arch/arm/include/asm/string.h
>> > @@ -58,6 +58,9 @@ static inline void *memset64(uint64_t *p, uint64_t v=
,
>> __kernel_size_t n)
>> >  #define memcpy(dst, src, len) __memcpy(dst, src, len)
>> >  #define memmove(dst, src, len) __memmove(dst, src, len)
>> >  #define memset(s, c, n) __memset(s, c, n)
>> > +#ifndef __NO_FORTIFY
>> > +#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
>> > +#endif
>> >  #endif
>> >
>> >
>> > Is  KASAN expected to  work when  FORTIFY enabled  ?
>>
>> There's a series from Daniel related to KASAN + FORTIFY_SOURCE [1]
>> btw, which might help you here.
>>
>> [1] https://lkml.org/lkml/2020/4/24/729
>>
>> >
>> > After above change , I was  table to succeed with all  early init call=
s
>> and also was able to dump the cmd_line args using lauterbach it was show=
ing
>> as accurate.
>> >
>> > Now I ran into  READ_ONCE and JUMP_LABEL issues  while running arch
>> specific CPU hooks   ?  aAe these two related ? Appreciate any pointers
>> here.
>> >
>> > Thanks
>> > Venkat Sana.
>> >
>> >
>> >
>> >
>> >
>> >
>> > BTW,  is this tested with FORTIFY
>> >
>> >
>> > On Tue, Jun 2, 2020 at 5:55 AM Alexander Potapenko <glider@google.com>
>> wrote:
>> >>
>> >> On Mon, Jun 1, 2020 at 10:18 PM Raju Sana <venkat.rajuece@gmail.com>
>> wrote:
>> >> >
>> >> > Thank you Walleij.
>> >> >
>> >> > I tried booting form 0x50000000,  but  hit the same issue.
>> >> > I tried disabling instrumentation by passing KASAN_SANITIZE :=3Dn  =
@
>> arch/arm/Makefile , but still no luck.
>> >>
>> >> This only disables instrumentation for files in arch/arm, which might
>> >> be not enough.
>> >> Try removing the -fsanitize=3Dkernel-address flag from
>> scripts/Makefile.kasan
>> >>
>> >> > Thanks,
>> >> > Venkat Sana.
>> >> >
>> >> > On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij <
>> linus.walleij@linaro.org> wrote:
>> >> >>
>> >> >> On Mon, Jun 1, 2020 at 1:07 AM Raju Sana <venkat.rajuece@gmail.com=
>
>> wrote:
>> >> >>
>> >> >>> And I am  loading image @ 0x44000000 in DDR and boot  using
>> "bootm   0x44000000"
>> >> >>
>> >> >>
>> >> >> Hm... can you try loading it at 0x50000000 and see what happens?
>> >> >>
>> >> >> We had issues with non-aligned physical base.
>> >> >>
>> >> >> Yours,
>> >> >> Linus Walleij
>> >> >
>> >> > --
>> >> > You received this message because you are subscribed to the Google
>> Groups "kasan-dev" group.
>> >> > To unsubscribe from this group and stop receiving emails from it,
>> send an email to kasan-dev+unsubscribe@googlegroups.com.
>> >> > To view this discussion on the web visit
>> https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBr=
AiAaohZfke8aoyhcqvs_CYSuirA%40mail.gmail.com
>> .
>> >>
>> >>
>> >>
>> >> --
>> >> Alexander Potapenko
>> >> Software Engineer
>> >>
>> >> Google Germany GmbH
>> >> Erika-Mann-Stra=C3=9Fe, 33
>> >> 80636 M=C3=BCnchen
>> >>
>> >> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
>> >> Registergericht und -nummer: Hamburg, HRB 86891
>> >> Sitz der Gesellschaft: Hamburg
>> >
>> > --
>> > You received this message because you are subscribed to the Google
>> Groups "kasan-dev" group.
>> > To unsubscribe from this group and stop receiving emails from it, send
>> an email to kasan-dev+unsubscribe@googlegroups.com.
>> > To view this discussion on the web visit
>> https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkakFEJZLtfe7L2oN4w4O%=
3DT%2Bx1L2WxZyKtSyofs8m3wLEzw%40mail.gmail.com
>> .
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87lfl2tk2p.fsf%40dja-thinkpad.axtens.net.
