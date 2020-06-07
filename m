Return-Path: <kasan-dev+bncBCFLDU5RYAIRB27W6T3AKGQEHSLXZUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E3B2A1F0EE0
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Jun 2020 21:09:31 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id y139sf5000648lff.4
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Jun 2020 12:09:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591556971; cv=pass;
        d=google.com; s=arc-20160816;
        b=BG6y198w0W98yXXaXcI42ElzPxWS4/JxoPQMs0OV/2vOpItGNK4TI0jzmegPPgWWgV
         SUH0THun6eZbH0ciBIobE8DvT0gFtbO7UPTb/iegncn392UWIZOheE8gnNCHJZTHaDAs
         53zbq4JoHS7mXmAHaZ5mObqWxoSiyHnL5v1J7W0SEHkveq8ykou4nD093xZveHTr5qsW
         RsrWN/VVtmNhSOogy4AKRjNjfGk91SAxmvZ20yqMKfNtj3faCGfxoezdJ8/qeZwnuYlo
         Th07a3yPp1TTUDUQfCgwaeJpxW5qDEGHX6bHnr4XOSgriDevh0dZwQPqZx9fWN+o7dTR
         k0ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=2e/CypRz1cdLkvRxm3mdTKSCinjRwwgRbkOKca3GlCc=;
        b=ivS9QIdx7gkwEYxx0Xt4vQcd4w1xSYph9F4MiyE+fxQW/EXlOYJjYr/H5VdCULLpmg
         89QyJz6/UEQoCdZVQnaY6LL7AiwU85jrDUFoNzkHJ6IXvmS3dpwNyHn1jJfclWrGuU1/
         FTwGPqXP7jpoH1p3nkXGq/Rs4J0JcbRq/A2YgeIH8Oi5YfnJB2UIdUuzP+OlgNfiiuwW
         OIBSI4WTERyWCOt91H0tfCh3rRPj8fqz0DOZeDRphQqV8k8dF6gWqk4yJrPqgAAn87jH
         FTZLKWMgtKVeCtdJzvfEPmz9eQPifbrUJz8iJ2duZDJV8j29fHHeZPYVbMqWOj8USyjR
         TamA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Qa2G9UgR;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2e/CypRz1cdLkvRxm3mdTKSCinjRwwgRbkOKca3GlCc=;
        b=JJ2Oq/mV5VEQ97b2WVPxlIHwd/SQEra2RvI/drZBB+Wv15G0NOQfeVifKzE31e3L+H
         /zuxXQGeMk5zOjUwQt3PLiiSmbTTqaISOpxwCJHXi6cpltClhIHa//CruV8SJAvYdaQN
         PdxxzUNM2D96KLL9MSyP2UkJYSlPtVsfW4+I2Gd0AAcQbVM9zVPy8+5u0w5b1C+bP0s7
         Dq5iIUjk6/fVoGSLNTE0mi/Ou8pIpzhkjhOl/FhTXvBugpeYVAc/sSGughmEKnwRtGD8
         wGeIbJwPqxbPA1Y4cHcNqby0JSLUXLW4EFPyWW71yA4RvtEzHESeTv4BRhVFySR7rVo6
         VfTw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2e/CypRz1cdLkvRxm3mdTKSCinjRwwgRbkOKca3GlCc=;
        b=f0X1CmEuDPzUzYwxx1eQZcOwn0/Vrw/vp+KmPf/EP2PAhA1pHd5eDTWPTFGND2fmEk
         C/4IbQW0m8S2AnT7BYCs6JzMezmPeu4tPQzS6JjJ4JKmL34P6VEOFQs8y85VkHA4SCEe
         gYRih/aVenRrM7TGNCiJp9rlHP+drsU7ZgezwiHCPMS8lfC6yjdwip9u9JEpCf06kxeI
         7B3AqHaNluSPENpi5Qm8ieaC+IEJ4NLfhUGIa9mwqzjHfp4ecRrDZLyhGaUazHWiQIUs
         tHaL119DgxurQDVEm0hnoQYJm/hIi2VBKuAnaVv0Al+9UnUNIYXVYhZUc6yUISN7N8kc
         cd4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2e/CypRz1cdLkvRxm3mdTKSCinjRwwgRbkOKca3GlCc=;
        b=PbPvAJnuIxICXgJQeeHHr68ERqNnmfWOf34owC2rlV4hmsCWoHgG6GuluNJR4LCdcC
         D/op3KDarS8aPiEUWZtusl+F54PsShdVMQbG7JseglLRU4hSwp4kty0L9QQN7uXvRRE/
         om5c4YAWJgs8AwjJwJIeRTWPIW/yJhRSVIiIXOj9CLvKOYPNKvTX0EG/pnTpybSpQ7fu
         ECWL+XCOhW0uLk+1/mL+MNgrNuXng9jPZ2bG1Naaen1fgG+doeKD/piulc8Ttt3/4CqK
         K8Y2GfoSEn/EfQzzN3HeU/iryEDLZmE4LpW6gRRoCbl3yox9LWZidbW+zsSzPZ22u5iV
         f3Sg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533C09bRqCiuEtF6mJXyc15yiRA/46VZLrhD1trVRzPCzZvepr0f
	W8/PINCDluZhcQUIqozAEv0=
X-Google-Smtp-Source: ABdhPJwPR+JjElGdR61UQoNGcu6/cYZwsn46coYZg8Ioi48DEd/3nX9R29YJ3WHsgBr/eMW3+4OmEQ==
X-Received: by 2002:a2e:98cb:: with SMTP id s11mr9030847ljj.402.1591556971388;
        Sun, 07 Jun 2020 12:09:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8843:: with SMTP id z3ls129130ljj.11.gmail; Sun, 07 Jun
 2020 12:09:30 -0700 (PDT)
X-Received: by 2002:a2e:9ac6:: with SMTP id p6mr9938229ljj.417.1591556970627;
        Sun, 07 Jun 2020 12:09:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591556970; cv=none;
        d=google.com; s=arc-20160816;
        b=kcLLPshZp/unMNrVR5pAX1N/etSJamcFMFlaQU9X7Lca7xsGQF9luLAhi/EwwXKFNc
         Rqe7/sEz56YvTxR3WwkYMkEuEm+Uzostma1zNV4DdRZqPPU8orOkUEGQejIm+qQM0+cH
         GkheNlYPwGPWwx2v6Q8FoKOLLNMHD/0UL2SFMdlh0oR3FQQYw4/Ur174uIiPOa8fYo/5
         yJMmw7cLXdFpFqpXCsI6vCqLIQEEE13tiEmgTd9eNhnR3H2sPVARxRZ4sFlzAFLc3bPp
         BYfemIZqZm1gJrs/0mLkbdeyWITrFbZv/AbCIUZRqhddjyBI3EGhEMZ+fEp/X0F8/hKp
         I0nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v4rZKReNXZuuICXBqqQuOdGeHTypHLzBjERobWCHV9k=;
        b=BI7IZidUsbdcnL/3a7Buxzy+Q+qyaN0PRWT1HcEa+aFw/CsnnKltU1Vtsz/YTEG2FX
         CEfUfAGdMVK9gEoOwyHoIBncJFTaGydR8yPYW2BVhQZcqBvfwwjEE6baxhdKxRXAhMny
         ws0XqnFhUS/YvY664pn0HzehbXGkxPirK+4KLqMSjeebNiiJj5pPS8i7ThZswUx4M1H0
         ScKTm2gerpA/5BwqXaPSispZ273wUw4rtBqW4mYe8eKu+blMLmJKYrHLFPp8orHinXcj
         GEwZx9FducT+UpuIbf3NWSII07AKq7xac4dTuR7Cyn/mNWY+7bQe5G83PluL2RxZzjiz
         m7xA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Qa2G9UgR;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id 14si648905lfy.1.2020.06.07.12.09.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Jun 2020 12:09:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id 202so8884377lfe.5
        for <kasan-dev@googlegroups.com>; Sun, 07 Jun 2020 12:09:30 -0700 (PDT)
X-Received: by 2002:a19:7612:: with SMTP id c18mr10934311lff.7.1591556970247;
 Sun, 07 Jun 2020 12:09:30 -0700 (PDT)
MIME-Version: 1.0
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
 <CA+dZkakGP0O_H2x0z+z_xojtDHR59jKqb1M97KvO7yjzxsC5+g@mail.gmail.com> <87lfl2tk2p.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <87lfl2tk2p.fsf@dja-thinkpad.axtens.net>
From: Raju Sana <venkat.rajuece@gmail.com>
Date: Sun, 7 Jun 2020 12:09:18 -0700
Message-ID: <CA+dZkamULgVfngAu7rW3rPEeQxXXURy3r49UaTaPL+ok+-aNcg@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Daniel Axtens <dja@axtens.net>, vrsana@codeaurora.org
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Linus Walleij <linus.walleij@linaro.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Abbott Liu <liuwenliang@huawei.com>
Content-Type: multipart/alternative; boundary="000000000000d9fa4c05a7833b44"
X-Original-Sender: venkat.rajuece@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Qa2G9UgR;       spf=pass
 (google.com: domain of venkat.rajuece@gmail.com designates
 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000d9fa4c05a7833b44
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Thank you Daniel and Amdnrey, I took those patches.


Further debug with lauterbach  , I still  observe  that there  is
mismatch/discrepancy  when we use mem related functions with
__builtin(Especially.,  __built_memcpy , I see  it from /lib/vsprintf
 during init) ,  it always chose the instrumented mem function @ KASan
despite passing   the KASAN_SANITIZE_"file_name".o  ,

I see that __SANITIZE_ADDRESS__  is defined @compiler-clang.h , for
some reason CLANG version is my config is zero , Does CLANG has anything to
do with KASAN ennoblement ?  Will dig more(Little confused about this flag
__SANITIZE_ADDRESS__),  but will appreciate any pointers here will help me
to get pass this.

Can we disable CLANG ? Are we loosing any functionality of KASan when we
disable CLANG ? Another observation while debugging  STACK  size is very
high I see a a frame of around 2000 in  number (not sure if its due to
recursive calls or  due to  disabled FRAME_WARN inside kernel when KASAN is
enabled which I did.)


Thanks,
Venkat Sana.







On Thu, Jun 4, 2020 at 5:47 PM Daniel Axtens <dja@axtens.net> wrote:

> Raju Sana <venkat.rajuece@gmail.com> writes:
>
> > Thank you Andrey.
> >
> > How do I access those patches ?
>
> They're now upstream in Linus' master:
>
> commit adb72ae1915d ("kasan: stop tests being eliminated as dead code wit=
h
> FORTIFY_SOURCE")
> commit 47227d27e2fc ("string.h: fix incompatibility between FORTIFY_SOURC=
E
> and KASAN")
>
> Regards,
> Daniel
>
> >
> > Thanks,
> > Venkat Sana.
> >
> > On Thu, Jun 4, 2020 at 5:20 PM Andrey Konovalov <andreyknvl@google.com>
> > wrote:
> >
> >> On Fri, Jun 5, 2020 at 2:14 AM Raju Sana <venkat.rajuece@gmail.com>
> wrote:
> >> >
> >> > Hello ALL,
> >> >
> >> > Thanks Alexander, I did attach to lauterbach  and debugging this now=
..
> >> to see where exactly failures..
> >> >
> >> > Initial Issue  behind memcpy failure is due to  FORTIFY  is enabled =
in
> >> my build, after turning off the FORTIFY  like below  , I was bale to g=
te
> >> pass memcpy issue.
> >> >
> >> > index 947f93037d87..64f0c81ac9a0 100644
> >> > --- a/arch/arm/include/asm/string.h
> >> > +++ b/arch/arm/include/asm/string.h
> >> > @@ -58,6 +58,9 @@ static inline void *memset64(uint64_t *p, uint64_t
> v,
> >> __kernel_size_t n)
> >> >  #define memcpy(dst, src, len) __memcpy(dst, src, len)
> >> >  #define memmove(dst, src, len) __memmove(dst, src, len)
> >> >  #define memset(s, c, n) __memset(s, c, n)
> >> > +#ifndef __NO_FORTIFY
> >> > +#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. =
*/
> >> > +#endif
> >> >  #endif
> >> >
> >> >
> >> > Is  KASAN expected to  work when  FORTIFY enabled  ?
> >>
> >> There's a series from Daniel related to KASAN + FORTIFY_SOURCE [1]
> >> btw, which might help you here.
> >>
> >> [1] https://lkml.org/lkml/2020/4/24/729
> >>
> >> >
> >> > After above change , I was  table to succeed with all  early init
> calls
> >> and also was able to dump the cmd_line args using lauterbach it was
> showing
> >> as accurate.
> >> >
> >> > Now I ran into  READ_ONCE and JUMP_LABEL issues  while running arch
> >> specific CPU hooks   ?  aAe these two related ? Appreciate any pointer=
s
> >> here.
> >> >
> >> > Thanks
> >> > Venkat Sana.
> >> >
> >> >
> >> >
> >> >
> >> >
> >> >
> >> > BTW,  is this tested with FORTIFY
> >> >
> >> >
> >> > On Tue, Jun 2, 2020 at 5:55 AM Alexander Potapenko <glider@google.co=
m
> >
> >> wrote:
> >> >>
> >> >> On Mon, Jun 1, 2020 at 10:18 PM Raju Sana <venkat.rajuece@gmail.com=
>
> >> wrote:
> >> >> >
> >> >> > Thank you Walleij.
> >> >> >
> >> >> > I tried booting form 0x50000000,  but  hit the same issue.
> >> >> > I tried disabling instrumentation by passing KASAN_SANITIZE :=3Dn=
  @
> >> arch/arm/Makefile , but still no luck.
> >> >>
> >> >> This only disables instrumentation for files in arch/arm, which mig=
ht
> >> >> be not enough.
> >> >> Try removing the -fsanitize=3Dkernel-address flag from
> >> scripts/Makefile.kasan
> >> >>
> >> >> > Thanks,
> >> >> > Venkat Sana.
> >> >> >
> >> >> > On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij <
> >> linus.walleij@linaro.org> wrote:
> >> >> >>
> >> >> >> On Mon, Jun 1, 2020 at 1:07 AM Raju Sana <
> venkat.rajuece@gmail.com>
> >> wrote:
> >> >> >>
> >> >> >>> And I am  loading image @ 0x44000000 in DDR and boot  using
> >> "bootm   0x44000000"
> >> >> >>
> >> >> >>
> >> >> >> Hm... can you try loading it at 0x50000000 and see what happens?
> >> >> >>
> >> >> >> We had issues with non-aligned physical base.
> >> >> >>
> >> >> >> Yours,
> >> >> >> Linus Walleij
> >> >> >
> >> >> > --
> >> >> > You received this message because you are subscribed to the Googl=
e
> >> Groups "kasan-dev" group.
> >> >> > To unsubscribe from this group and stop receiving emails from it,
> >> send an email to kasan-dev+unsubscribe@googlegroups.com.
> >> >> > To view this discussion on the web visit
> >>
> https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrA=
iAaohZfke8aoyhcqvs_CYSuirA%40mail.gmail.com
> >> .
> >> >>
> >> >>
> >> >>
> >> >> --
> >> >> Alexander Potapenko
> >> >> Software Engineer
> >> >>
> >> >> Google Germany GmbH
> >> >> Erika-Mann-Stra=C3=9Fe, 33
> >> >> 80636 M=C3=BCnchen
> >> >>
> >> >> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> >> >> Registergericht und -nummer: Hamburg, HRB 86891
> >> >> Sitz der Gesellschaft: Hamburg
> >> >
> >> > --
> >> > You received this message because you are subscribed to the Google
> >> Groups "kasan-dev" group.
> >> > To unsubscribe from this group and stop receiving emails from it, se=
nd
> >> an email to kasan-dev+unsubscribe@googlegroups.com.
> >> > To view this discussion on the web visit
> >>
> https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkakFEJZLtfe7L2oN4w4O%3=
DT%2Bx1L2WxZyKtSyofs8m3wLEzw%40mail.gmail.com
> >> .
> >>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BdZkamULgVfngAu7rW3rPEeQxXXURy3r49UaTaPL%2Bok%2B-aNcg%40mail.=
gmail.com.

--000000000000d9fa4c05a7833b44
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Thank you Daniel and Amdnrey, I took those patches.<div><b=
r></div><div><br></div><div>Further debug with lauterbach=C2=A0 , I still=
=C2=A0 observe=C2=A0 that there=C2=A0 is=C2=A0 mismatch/discrepancy=C2=A0 w=
hen we use mem related functions with __builtin(Especially.,=C2=A0 __built_=
memcpy , I see=C2=A0 it from /lib/vsprintf=C2=A0 =C2=A0during init) ,=C2=A0=
 it always chose the instrumented mem function=C2=A0@ KASan despite passing=
=C2=A0 =C2=A0the KASAN_SANITIZE_&quot;file_name&quot;.o=C2=A0 ,</div><div><=
br></div><div>I see that __SANITIZE_ADDRESS__=C2=A0 is defined=C2=A0@compil=
er-clang.h , for some=C2=A0reason CLANG version=C2=A0is my config is zero ,=
 Does CLANG has anything to do with KASAN ennoblement ?=C2=A0 Will dig more=
(Little confused about this flag __SANITIZE_ADDRESS__),=C2=A0 but will appr=
eciate any pointers here will help me to get pass this.</div><div><br></div=
><div>Can we disable CLANG ? Are we loosing=C2=A0any functionality of KASan=
 when we disable=C2=A0CLANG ? Another observation while debugging=C2=A0 STA=
CK=C2=A0 size is very high I see a a frame of around=C2=A02000 in=C2=A0 num=
ber (not sure if its due to recursive calls or=C2=A0 due to=C2=A0 disabled =
FRAME_WARN inside kernel=C2=A0when KASAN is enabled which I did.)</div><div=
><br></div><div><br></div><div>Thanks,</div><div>Venkat Sana.</div><div><br=
></div><div><br></div><div><br></div><div><br></div><div><br></div><div><br=
></div></div><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail=
_attr">On Thu, Jun 4, 2020 at 5:47 PM Daniel Axtens &lt;<a href=3D"mailto:d=
ja@axtens.net" target=3D"_blank">dja@axtens.net</a>&gt; wrote:<br></div><bl=
ockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-lef=
t:1px solid rgb(204,204,204);padding-left:1ex">Raju Sana &lt;<a href=3D"mai=
lto:venkat.rajuece@gmail.com" target=3D"_blank">venkat.rajuece@gmail.com</a=
>&gt; writes:<br>
<br>
&gt; Thank you Andrey.<br>
&gt;<br>
&gt; How do I access those patches ?<br>
<br>
They&#39;re now upstream in Linus&#39; master:<br>
<br>
commit adb72ae1915d (&quot;kasan: stop tests being eliminated as dead code =
with FORTIFY_SOURCE&quot;)<br>
commit 47227d27e2fc (&quot;string.h: fix incompatibility between FORTIFY_SO=
URCE and KASAN&quot;)<br>
<br>
Regards,<br>
Daniel<br>
<br>
&gt;<br>
&gt; Thanks,<br>
&gt; Venkat Sana.<br>
&gt;<br>
&gt; On Thu, Jun 4, 2020 at 5:20 PM Andrey Konovalov &lt;<a href=3D"mailto:=
andreyknvl@google.com" target=3D"_blank">andreyknvl@google.com</a>&gt;<br>
&gt; wrote:<br>
&gt;<br>
&gt;&gt; On Fri, Jun 5, 2020 at 2:14 AM Raju Sana &lt;<a href=3D"mailto:ven=
kat.rajuece@gmail.com" target=3D"_blank">venkat.rajuece@gmail.com</a>&gt; w=
rote:<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Hello ALL,<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Thanks Alexander, I did attach to lauterbach=C2=A0 and debugg=
ing this now..<br>
&gt;&gt; to see where exactly failures..<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Initial Issue=C2=A0 behind memcpy failure is due to=C2=A0 FOR=
TIFY=C2=A0 is enabled in<br>
&gt;&gt; my build, after turning off the FORTIFY=C2=A0 like below=C2=A0 , I=
 was bale to gte<br>
&gt;&gt; pass memcpy issue.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; index 947f93037d87..64f0c81ac9a0 100644<br>
&gt;&gt; &gt; --- a/arch/arm/include/asm/string.h<br>
&gt;&gt; &gt; +++ b/arch/arm/include/asm/string.h<br>
&gt;&gt; &gt; @@ -58,6 +58,9 @@ static inline void *memset64(uint64_t *p, u=
int64_t v,<br>
&gt;&gt; __kernel_size_t n)<br>
&gt;&gt; &gt;=C2=A0 #define memcpy(dst, src, len) __memcpy(dst, src, len)<b=
r>
&gt;&gt; &gt;=C2=A0 #define memmove(dst, src, len) __memmove(dst, src, len)=
<br>
&gt;&gt; &gt;=C2=A0 #define memset(s, c, n) __memset(s, c, n)<br>
&gt;&gt; &gt; +#ifndef __NO_FORTIFY<br>
&gt;&gt; &gt; +#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy=
, etc. */<br>
&gt;&gt; &gt; +#endif<br>
&gt;&gt; &gt;=C2=A0 #endif<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Is=C2=A0 KASAN expected to=C2=A0 work when=C2=A0 FORTIFY enab=
led=C2=A0 ?<br>
&gt;&gt;<br>
&gt;&gt; There&#39;s a series from Daniel related to KASAN + FORTIFY_SOURCE=
 [1]<br>
&gt;&gt; btw, which might help you here.<br>
&gt;&gt;<br>
&gt;&gt; [1] <a href=3D"https://lkml.org/lkml/2020/4/24/729" rel=3D"norefer=
rer" target=3D"_blank">https://lkml.org/lkml/2020/4/24/729</a><br>
&gt;&gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; After above change , I was=C2=A0 table to succeed with all=C2=
=A0 early init calls<br>
&gt;&gt; and also was able to dump the cmd_line args using lauterbach it wa=
s showing<br>
&gt;&gt; as accurate.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Now I ran into=C2=A0 READ_ONCE and JUMP_LABEL issues=C2=A0 wh=
ile running arch<br>
&gt;&gt; specific CPU hooks=C2=A0 =C2=A0?=C2=A0 aAe these two related ? App=
reciate any pointers<br>
&gt;&gt; here.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Thanks<br>
&gt;&gt; &gt; Venkat Sana.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; BTW,=C2=A0 is this tested with FORTIFY<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; On Tue, Jun 2, 2020 at 5:55 AM Alexander Potapenko &lt;<a hre=
f=3D"mailto:glider@google.com" target=3D"_blank">glider@google.com</a>&gt;<=
br>
&gt;&gt; wrote:<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; On Mon, Jun 1, 2020 at 10:18 PM Raju Sana &lt;<a href=3D"=
mailto:venkat.rajuece@gmail.com" target=3D"_blank">venkat.rajuece@gmail.com=
</a>&gt;<br>
&gt;&gt; wrote:<br>
&gt;&gt; &gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; Thank you Walleij.<br>
&gt;&gt; &gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; I tried booting form 0x50000000,=C2=A0 but=C2=A0 hit=
 the same issue.<br>
&gt;&gt; &gt;&gt; &gt; I tried disabling instrumentation by passing KASAN_S=
ANITIZE :=3Dn=C2=A0 @<br>
&gt;&gt; arch/arm/Makefile , but still no luck.<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; This only disables instrumentation for files in arch/arm,=
 which might<br>
&gt;&gt; &gt;&gt; be not enough.<br>
&gt;&gt; &gt;&gt; Try removing the -fsanitize=3Dkernel-address flag from<br=
>
&gt;&gt; scripts/Makefile.kasan<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; &gt; Thanks,<br>
&gt;&gt; &gt;&gt; &gt; Venkat Sana.<br>
&gt;&gt; &gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij &lt;<br=
>
&gt;&gt; <a href=3D"mailto:linus.walleij@linaro.org" target=3D"_blank">linu=
s.walleij@linaro.org</a>&gt; wrote:<br>
&gt;&gt; &gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; &gt;&gt; On Mon, Jun 1, 2020 at 1:07 AM Raju Sana &lt;<a =
href=3D"mailto:venkat.rajuece@gmail.com" target=3D"_blank">venkat.rajuece@g=
mail.com</a>&gt;<br>
&gt;&gt; wrote:<br>
&gt;&gt; &gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; &gt;&gt;&gt; And I am=C2=A0 loading image @ 0x44000000 in=
 DDR and boot=C2=A0 using<br>
&gt;&gt; &quot;bootm=C2=A0 =C2=A00x44000000&quot;<br>
&gt;&gt; &gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; &gt;&gt; Hm... can you try loading it at 0x50000000 and s=
ee what happens?<br>
&gt;&gt; &gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; &gt;&gt; We had issues with non-aligned physical base.<br=
>
&gt;&gt; &gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; &gt;&gt; Yours,<br>
&gt;&gt; &gt;&gt; &gt;&gt; Linus Walleij<br>
&gt;&gt; &gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; --<br>
&gt;&gt; &gt;&gt; &gt; You received this message because you are subscribed=
 to the Google<br>
&gt;&gt; Groups &quot;kasan-dev&quot; group.<br>
&gt;&gt; &gt;&gt; &gt; To unsubscribe from this group and stop receiving em=
ails from it,<br>
&gt;&gt; send an email to <a href=3D"mailto:kasan-dev%2Bunsubscribe@googleg=
roups.com" target=3D"_blank">kasan-dev+unsubscribe@googlegroups.com</a>.<br=
>
&gt;&gt; &gt;&gt; &gt; To view this discussion on the web visit<br>
&gt;&gt; <a href=3D"https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkann=
4Z1TavtJ%2Biq9oBrAiAaohZfke8aoyhcqvs_CYSuirA%40mail.gmail.com" rel=3D"noref=
errer" target=3D"_blank">https://groups.google.com/d/msgid/kasan-dev/CA%2Bd=
Zkann4Z1TavtJ%2Biq9oBrAiAaohZfke8aoyhcqvs_CYSuirA%40mail.gmail.com</a><br>
&gt;&gt; .<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; --<br>
&gt;&gt; &gt;&gt; Alexander Potapenko<br>
&gt;&gt; &gt;&gt; Software Engineer<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; Google Germany GmbH<br>
&gt;&gt; &gt;&gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt;&gt; &gt;&gt; 80636 M=C3=BCnchen<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine =
Prado<br>
&gt;&gt; &gt;&gt; Registergericht und -nummer: Hamburg, HRB 86891<br>
&gt;&gt; &gt;&gt; Sitz der Gesellschaft: Hamburg<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; --<br>
&gt;&gt; &gt; You received this message because you are subscribed to the G=
oogle<br>
&gt;&gt; Groups &quot;kasan-dev&quot; group.<br>
&gt;&gt; &gt; To unsubscribe from this group and stop receiving emails from=
 it, send<br>
&gt;&gt; an email to <a href=3D"mailto:kasan-dev%2Bunsubscribe@googlegroups=
.com" target=3D"_blank">kasan-dev+unsubscribe@googlegroups.com</a>.<br>
&gt;&gt; &gt; To view this discussion on the web visit<br>
&gt;&gt; <a href=3D"https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkakF=
EJZLtfe7L2oN4w4O%3DT%2Bx1L2WxZyKtSyofs8m3wLEzw%40mail.gmail.com" rel=3D"nor=
eferrer" target=3D"_blank">https://groups.google.com/d/msgid/kasan-dev/CA%2=
BdZkakFEJZLtfe7L2oN4w4O%3DT%2Bx1L2WxZyKtSyofs8m3wLEzw%40mail.gmail.com</a><=
br>
&gt;&gt; .<br>
&gt;&gt;<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BdZkamULgVfngAu7rW3rPEeQxXXURy3r49UaTaPL%2Bok%2B-a=
Ncg%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CA%2BdZkamULgVfngAu7rW3rPEeQxXXURy3r49UaTaPL%=
2Bok%2B-aNcg%40mail.gmail.com</a>.<br />

--000000000000d9fa4c05a7833b44--
