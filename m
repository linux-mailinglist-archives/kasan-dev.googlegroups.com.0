Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGNN7H3AKGQEZU323XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 41CA11F1BE1
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jun 2020 17:17:47 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id x15sf1882440oie.6
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jun 2020 08:17:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591629466; cv=pass;
        d=google.com; s=arc-20160816;
        b=zOrmhtjAh2mWeCrNPsyLTJ55dIngS87PEGV7Hw9VUS0wnz8Cev9AxMf1+m78Mgaf11
         EZyL36VCxGNayXAG//KFLGDB9Kgx45quSMekNmU+WBnUk6jtRFq4Ps1N6USYg1pEqJWN
         Qmdd6/qQsTmICMeih9oYb/bVAzpIEyu/JvFNXsI1bBsl/kDSMhBo5v3J+ubfC+7vol1l
         RYarYPM0oyVvp9qN1wGBB19LDArCHaVGoPBBMwKHqfVRrWPx3COe1nJBIJTcx+3lS4Fq
         LUR4Yo8CZcYs4aak8Gwcwj3hVvDYCK2dbqUlsEdraO7a2W6P9zKb43AhoA693iw3JEZm
         BhPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3dyvEak5hwysL8whiXo5yB5a6xmEu0B8zaHQMpBFRpE=;
        b=gVcOSKMPwCbELCv1URDY3AgjsfZVMoxPtbKU4mogzAdknV2xQiNI/gZta3Gy9aSd63
         BI//HvKEBEB9VTpRxjvbpM5OEbGqBzwsSnOo+1+roY2FELD5OSNl2rSpeTvzeTXuj/CU
         RcO6+gd3Grg3RWiMOvUAxX8QcRv3AzcSJGtanLKsgR7CWWN5yxqQvaPtQ26ZQBqmGNno
         8aEqSYZlAoQQYJtOcMHZnvmEBQVqg2lZIJKsXzFDrw+JvJhaYz1roBHDOB323YXMYvuJ
         I0GnS5wxs8QmE+2oZp2znmd/uuugNu3jw6h1WNHsnOEWiJIg7Tu5t68/tGsY0c1Nzg+i
         z9Gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=guIfm6Fq;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=3dyvEak5hwysL8whiXo5yB5a6xmEu0B8zaHQMpBFRpE=;
        b=J//uId5P+76H0Sg4lieZ/hOhd6lYnnuj0Y1my05WQcAn4CMSo4ieHXelPugEUzuqH+
         5NLmqaphe9Vt1XTJ5KwWS3o84GrV/JrIURTfuzY2lMnWxsZkSSZTjfXXjNl90kzWBHou
         2/vPxBY191dL7LS1AdCBN+E6tmaeUizPUjh2kr/f5fDorzo9gdwQoKWVVgCh/KXthoeS
         F96w20EYkAxHVANV+eNO6GURojnUPlg9d6zsKrBz8P2BjAfVWi8ysVFbs04Tmu0l2yhZ
         g8k3i0KXwkX9V/A6Fo7bXbemKZj0gBGSBLTrO0No2zy/OFb0X27liHkWfSdhqY2nP9q+
         XSVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3dyvEak5hwysL8whiXo5yB5a6xmEu0B8zaHQMpBFRpE=;
        b=HwbGCSepTlrTShODcp/TFSWZBTkpaRSjiY7EpfDxmzHJ0j1PgKpqwvA4a6wRS721TF
         k4GMKoX8n8Tw8bsIWOtfaWMbuu5AmGQWCsFXNLUvoVLb86YrBgHS/WkOLsczIgBBCKhu
         wW2fKZAEf63N7iZHP35hOiMVTdO8nEnIBri09iVkChAmKJqaRVybgWeSPJGe7aZygqPA
         jzRXcuD61Q4ZKN2UKlZsm5/fVJTckHtlbuNJ+yMf3T9vQs/fNWSDMe1s0/SPJuw3Rvln
         rSOhj9xjrVoqOZKvC4cbb3W1bJIy61D6py/Y01OAQfmN6oZP1EKZo3S6m41m7pJV9T/I
         9onQ==
X-Gm-Message-State: AOAM532mB4DUbZ3rmSOZPpcmOGdERFaLtXgJZhCGEQHiP2woGiYiHYjM
	NrtL9JYBPLB3xG/XmKQyv6Y=
X-Google-Smtp-Source: ABdhPJx8wIO53FIFNgG+iejIoB8HB30SvzUymlIldQEzrkqll3KBZFwZO1qu4FHraHM7enuYDTPkXQ==
X-Received: by 2002:a05:6808:50:: with SMTP id v16mr10323262oic.93.1591629465857;
        Mon, 08 Jun 2020 08:17:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cf10:: with SMTP id f16ls3200158oig.10.gmail; Mon, 08
 Jun 2020 08:17:45 -0700 (PDT)
X-Received: by 2002:aca:3145:: with SMTP id x66mr11261808oix.159.1591629465560;
        Mon, 08 Jun 2020 08:17:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591629465; cv=none;
        d=google.com; s=arc-20160816;
        b=qrBsZRMRF5yyZCkYpnC1wZsH7IXejKrJAW6jO4GszuUYDszsgv/Vqwoh1ld0UmlS5M
         DPMdZ4+zSXnHLUKzJoAmFEHs05WNFoe0/ifu24J393zws+GAAD58rxG5RjonIBsTSsCN
         a+rGex66a3uRVqew7RtuG78n5gJtCHfDU1k0EyG6IvWY9xWEKRxuBnzT29kfXJ8bwbG8
         qbMIcPV1O7lANSNjKEguxEopIJu0WCDzc+4BJuWmA7b9XYzw4uRNTLd2NkfsZaEzMkie
         Oebs8wk9qGwKiVoEhbOXqagAnUXicHKSkZNo5ITtdNFN8WTK0bHOjq8PYMgQf8Rx1qIC
         jwzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Vl44xARUelN/Fpu9c3gwzvx2nTc3I0ii+qn5ky+cxZs=;
        b=GuEk+57kWKsnkEWtrW9xAFvE4JJNEA39NsX0vUNrTmvS6r8xrc8f5HzzLUh/R50o5D
         3NmzN5VE6YxH5bUxTP42tMGAI3dDAOvlfAlMcJ2hB+zmDzbAyfEvJJtCk3JCflETS1Mc
         T8qFaKLkOyv/2aIEfLQCwYR8T4bvZVVfM/keetrJefQxd7KuTwLQfthsv4ce6N92jRAx
         AEdU9ZvfQ3Cz8Lb3y/VYIi9GAVjRGWU3/WYYuvn+eQTfFveq410e5uaT4pzjAYkqMxr0
         zAAHUDYJoDvAbndKQoYunOJQDgEALRaatv0qumcVRtfR+Ypeoxkwh/0GiNO4Ww4n/LZO
         PqJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=guIfm6Fq;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id t3si424736oth.3.2020.06.08.08.17.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Jun 2020 08:17:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id jz3so5888352pjb.0
        for <kasan-dev@googlegroups.com>; Mon, 08 Jun 2020 08:17:45 -0700 (PDT)
X-Received: by 2002:a17:902:e9d2:: with SMTP id 18mr2752557plk.336.1591629464536;
 Mon, 08 Jun 2020 08:17:44 -0700 (PDT)
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
 <CA+dZkakGP0O_H2x0z+z_xojtDHR59jKqb1M97KvO7yjzxsC5+g@mail.gmail.com>
 <87lfl2tk2p.fsf@dja-thinkpad.axtens.net> <CA+dZkamULgVfngAu7rW3rPEeQxXXURy3r49UaTaPL+ok+-aNcg@mail.gmail.com>
In-Reply-To: <CA+dZkamULgVfngAu7rW3rPEeQxXXURy3r49UaTaPL+ok+-aNcg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Jun 2020 17:17:33 +0200
Message-ID: <CAAeHK+x9O=W8pYQLEeSpDkJ3zd4Dy-aU5C1ysXC7FSMeue=imA@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Raju Sana <venkat.rajuece@gmail.com>
Cc: Daniel Axtens <dja@axtens.net>, vrsana@codeaurora.org, 
	Alexander Potapenko <glider@google.com>, Linus Walleij <linus.walleij@linaro.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Abbott Liu <liuwenliang@huawei.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=guIfm6Fq;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Sun, Jun 7, 2020 at 9:09 PM Raju Sana <venkat.rajuece@gmail.com> wrote:
>
> Thank you Daniel and Amdnrey, I took those patches.
>
>
> Further debug with lauterbach  , I still  observe  that there  is  mismat=
ch/discrepancy  when we use mem related functions with __builtin(Especially=
.,  __built_memcpy , I see  it from /lib/vsprintf   during init) ,  it alwa=
ys chose the instrumented mem function @ KASan despite passing   the KASAN_=
SANITIZE_"file_name".o  ,
>
> I see that __SANITIZE_ADDRESS__  is defined @compiler-clang.h , for some =
reason CLANG version is my config is zero , Does CLANG has anything to do w=
ith KASAN ennoblement ?  Will dig more(Little confused about this flag __SA=
NITIZE_ADDRESS__),  but will appreciate any pointers here will help me to g=
et pass this.
>
> Can we disable CLANG ? Are we loosing any functionality of KASan when we =
disable CLANG ?

What do you mean by "CLANG version in your config"? Clang is a
compiler like GCC. You can use it, or use GCC, KASAN works with both.
Although with Clang KASAN doesn't yet instrument globals (support for
them is currently in progress).

> Another observation while debugging  STACK  size is very high I see a a f=
rame of around 2000 in  number (not sure if its due to recursive calls or  =
due to  disabled FRAME_WARN inside kernel when KASAN is enabled which I did=
.)

KASAN inserts redzones around stack variables, so stack usage
increases. This might cause crashes if the stack overflows. You can
try disabling KASAN_STACK for now and get it working without stack
instrumentation first.

>
>
> Thanks,
> Venkat Sana.
>
>
>
>
>
>
>
> On Thu, Jun 4, 2020 at 5:47 PM Daniel Axtens <dja@axtens.net> wrote:
>>
>> Raju Sana <venkat.rajuece@gmail.com> writes:
>>
>> > Thank you Andrey.
>> >
>> > How do I access those patches ?
>>
>> They're now upstream in Linus' master:
>>
>> commit adb72ae1915d ("kasan: stop tests being eliminated as dead code wi=
th FORTIFY_SOURCE")
>> commit 47227d27e2fc ("string.h: fix incompatibility between FORTIFY_SOUR=
CE and KASAN")
>>
>> Regards,
>> Daniel
>>
>> >
>> > Thanks,
>> > Venkat Sana.
>> >
>> > On Thu, Jun 4, 2020 at 5:20 PM Andrey Konovalov <andreyknvl@google.com=
>
>> > wrote:
>> >
>> >> On Fri, Jun 5, 2020 at 2:14 AM Raju Sana <venkat.rajuece@gmail.com> w=
rote:
>> >> >
>> >> > Hello ALL,
>> >> >
>> >> > Thanks Alexander, I did attach to lauterbach  and debugging this no=
w..
>> >> to see where exactly failures..
>> >> >
>> >> > Initial Issue  behind memcpy failure is due to  FORTIFY  is enabled=
 in
>> >> my build, after turning off the FORTIFY  like below  , I was bale to =
gte
>> >> pass memcpy issue.
>> >> >
>> >> > index 947f93037d87..64f0c81ac9a0 100644
>> >> > --- a/arch/arm/include/asm/string.h
>> >> > +++ b/arch/arm/include/asm/string.h
>> >> > @@ -58,6 +58,9 @@ static inline void *memset64(uint64_t *p, uint64_=
t v,
>> >> __kernel_size_t n)
>> >> >  #define memcpy(dst, src, len) __memcpy(dst, src, len)
>> >> >  #define memmove(dst, src, len) __memmove(dst, src, len)
>> >> >  #define memset(s, c, n) __memset(s, c, n)
>> >> > +#ifndef __NO_FORTIFY
>> >> > +#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc.=
 */
>> >> > +#endif
>> >> >  #endif
>> >> >
>> >> >
>> >> > Is  KASAN expected to  work when  FORTIFY enabled  ?
>> >>
>> >> There's a series from Daniel related to KASAN + FORTIFY_SOURCE [1]
>> >> btw, which might help you here.
>> >>
>> >> [1] https://lkml.org/lkml/2020/4/24/729
>> >>
>> >> >
>> >> > After above change , I was  table to succeed with all  early init c=
alls
>> >> and also was able to dump the cmd_line args using lauterbach it was s=
howing
>> >> as accurate.
>> >> >
>> >> > Now I ran into  READ_ONCE and JUMP_LABEL issues  while running arch
>> >> specific CPU hooks   ?  aAe these two related ? Appreciate any pointe=
rs
>> >> here.
>> >> >
>> >> > Thanks
>> >> > Venkat Sana.
>> >> >
>> >> >
>> >> >
>> >> >
>> >> >
>> >> >
>> >> > BTW,  is this tested with FORTIFY
>> >> >
>> >> >
>> >> > On Tue, Jun 2, 2020 at 5:55 AM Alexander Potapenko <glider@google.c=
om>
>> >> wrote:
>> >> >>
>> >> >> On Mon, Jun 1, 2020 at 10:18 PM Raju Sana <venkat.rajuece@gmail.co=
m>
>> >> wrote:
>> >> >> >
>> >> >> > Thank you Walleij.
>> >> >> >
>> >> >> > I tried booting form 0x50000000,  but  hit the same issue.
>> >> >> > I tried disabling instrumentation by passing KASAN_SANITIZE :=3D=
n  @
>> >> arch/arm/Makefile , but still no luck.
>> >> >>
>> >> >> This only disables instrumentation for files in arch/arm, which mi=
ght
>> >> >> be not enough.
>> >> >> Try removing the -fsanitize=3Dkernel-address flag from
>> >> scripts/Makefile.kasan
>> >> >>
>> >> >> > Thanks,
>> >> >> > Venkat Sana.
>> >> >> >
>> >> >> > On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij <
>> >> linus.walleij@linaro.org> wrote:
>> >> >> >>
>> >> >> >> On Mon, Jun 1, 2020 at 1:07 AM Raju Sana <venkat.rajuece@gmail.=
com>
>> >> wrote:
>> >> >> >>
>> >> >> >>> And I am  loading image @ 0x44000000 in DDR and boot  using
>> >> "bootm   0x44000000"
>> >> >> >>
>> >> >> >>
>> >> >> >> Hm... can you try loading it at 0x50000000 and see what happens=
?
>> >> >> >>
>> >> >> >> We had issues with non-aligned physical base.
>> >> >> >>
>> >> >> >> Yours,
>> >> >> >> Linus Walleij
>> >> >> >
>> >> >> > --
>> >> >> > You received this message because you are subscribed to the Goog=
le
>> >> Groups "kasan-dev" group.
>> >> >> > To unsubscribe from this group and stop receiving emails from it=
,
>> >> send an email to kasan-dev+unsubscribe@googlegroups.com.
>> >> >> > To view this discussion on the web visit
>> >> https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9=
oBrAiAaohZfke8aoyhcqvs_CYSuirA%40mail.gmail.com
>> >> .
>> >> >>
>> >> >>
>> >> >>
>> >> >> --
>> >> >> Alexander Potapenko
>> >> >> Software Engineer
>> >> >>
>> >> >> Google Germany GmbH
>> >> >> Erika-Mann-Stra=C3=9Fe, 33
>> >> >> 80636 M=C3=BCnchen
>> >> >>
>> >> >> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
>> >> >> Registergericht und -nummer: Hamburg, HRB 86891
>> >> >> Sitz der Gesellschaft: Hamburg
>> >> >
>> >> > --
>> >> > You received this message because you are subscribed to the Google
>> >> Groups "kasan-dev" group.
>> >> > To unsubscribe from this group and stop receiving emails from it, s=
end
>> >> an email to kasan-dev+unsubscribe@googlegroups.com.
>> >> > To view this discussion on the web visit
>> >> https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkakFEJZLtfe7L2oN4w=
4O%3DT%2Bx1L2WxZyKtSyofs8m3wLEzw%40mail.gmail.com
>> >> .
>> >>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2Bx9O%3DW8pYQLEeSpDkJ3zd4Dy-aU5C1ysXC7FSMeue%3DimA%40mail.=
gmail.com.
