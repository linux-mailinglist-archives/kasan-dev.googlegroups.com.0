Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYM7433AKGQE3KVQQVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 1240D1EEEB7
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jun 2020 02:20:51 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id e143sf6081792pfh.4
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 17:20:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591316449; cv=pass;
        d=google.com; s=arc-20160816;
        b=vEkrJyw5v15MWZ1lSXKcjwj8Gtt/jyWNB86iC+m0WevnMQaQOv+7ox/qR7SZVEHSTY
         oYYDsDdZCs2DeTfGc/FwGT6vlK5eAQSGMuq3QJuVtbUQiy0ndsOp5ZXiP0fwoefUrOk6
         dv64YZuDS5WtT9vSljgGZ8ySbUSJl2RIgNyo8g6YvXf2hhfibtAKa++DPF03Uys6xbFT
         JvDz9VsHgXqrgyFWI8rYyyo497ud+j5QWgvQur+ueD3quGk6seKCrrrJXO0IGGTwUDrx
         sdSelE+FQQ/e59afaESPjoiUlNCjFltxgU+5R2BrwtA/XFZ0QCmSenFddQkRy3dZMGo7
         QgKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1Z2GV0Gl9sZpKKIqfR5cMwtWGIQDtjjt6THkaUJnylo=;
        b=a/fqs1dxkH2S2t475+nQDUywjG9SD9E0uQp+kiMe6n7clpQtm1JRGTI/w+fzW7qHWq
         mM9EYflT+1rS9Eb98umPCBjciF810PNuX8c+RU9EYszRaL/pQcm48pR1V1PQlGukEBLv
         1SvHwU3d/LQ4s4W3ihVvGkzZLBcQPpfshOx4O8X5ANSXbur+XrvagNiX2DaKYCBQoiY0
         xDy/6wuOxNtdGaC2I/1y1Ib9nCV3re4ap1+VNIfr0nsMZ+VsyiY3rbvf+66AXiocBifF
         WG8jhB3oamzUOVr7+ouk04tLFSP9qH3FA0+1uCu59ti5jbnb6FdEdBA4pIMSlViYslOr
         U8iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zux4DUE6;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1Z2GV0Gl9sZpKKIqfR5cMwtWGIQDtjjt6THkaUJnylo=;
        b=M8SMHffFgxyAhWUw74w1vrVHIudF774uT2cLKA9GnZnEmZqcz3EoLWEa5Ep+/CG4Jp
         lERuV/g0bSfdwId/1/Jxe9qLf0d7L85UX6LD8ATik0tn03FO4YXWMsRKiIRMwJtO/G+u
         DhfA99H7BAR18Fxb7gZfHGkd4hQWUnU1ub1zv9YH+rIIyMGgR2tnEBN/Gy0yTHnnhCLx
         OHPwfasq0HSYlOexdAD018iQa2PptjbDh3BflB4PDxUBRqfexlKaE3Cx5UunrRyW3Hcg
         MuQXwqjAbYUFNB1RaWFhfUNBDVG7ixtNKAjiYT4yPBIQQooH0ixntiy3vIZzexHSrA4q
         I2lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1Z2GV0Gl9sZpKKIqfR5cMwtWGIQDtjjt6THkaUJnylo=;
        b=gKpglIbJV3MY9UmJk1tQuZk+LrxOM1nv/U+fuH+3u0JmQuawFYYFWEew3GWKyBy1Q2
         JnzYqCccxIhbUpli24cH9iiY2YolIRVnMWs/uEW9oghkln3fL+UyF/Y+7SEsT7kMzUeo
         QxoGrlTaHhXYZOYx+0byHP2QjDKhE3yCUylQq3a3V3S6CF33CLolwewl+qmAs4EfLtZk
         vW1hR2Hq0IRt4E5BmjeTapTMnmDpzscw1/6YKJLPMmc+hZQkx8wQYhEsSZbbgrKFzhrA
         mkuEUSZxTtp3Yung8M86lLJ3qzZ03mmJ8ZXARtTJIxL3LzY19LAWdRE9nEylP81EZs1a
         rh9Q==
X-Gm-Message-State: AOAM533aHWAroEc4VYS/2+m3ZgvuM5OmzrngLn2t9llJRg9mIRfAaopK
	SgJyehqWXLfbW+u3ZpEgPpU=
X-Google-Smtp-Source: ABdhPJyt72v7I++w5k3GUneCSYGocguvANnEgBm/sXwQxXHgAio8N7g3Hd9MhvOdsb8sju/rOZVRdw==
X-Received: by 2002:a63:ad0b:: with SMTP id g11mr6916252pgf.275.1591316449214;
        Thu, 04 Jun 2020 17:20:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bc4a:: with SMTP id t10ls2720626plz.4.gmail; Thu, 04
 Jun 2020 17:20:48 -0700 (PDT)
X-Received: by 2002:a17:902:9043:: with SMTP id w3mr6862787plz.250.1591316448639;
        Thu, 04 Jun 2020 17:20:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591316448; cv=none;
        d=google.com; s=arc-20160816;
        b=HetBG85Jp6CnQSG68F9U7XogKtc6EJjt5kfQWIxHYMfA5bZI78TNn8qdA8EaSqHZtP
         8Ydh4tzM4rzltg3Gt4A0uE1tw9ZVieJWEzCtXJtnlHp6OkjAKNL/R4pSO06pxygOQtd9
         xklwGo1HmP5fHJ2ZmcbQolE9RGOjdWB16XWn6nLFBJQdFQy+rT8q1S6lbKeEuRg736w/
         7Aa9rISO1OfkR3RI41I1pdlIZtodrXKNAaAk4JHZtwIEaQM3Ja0A2dyLM/1XwKCgnKXm
         ob/UINcwBthrN+pH230Lq5iP1tCs2YJpk2+OL6tqgGwEc2OacgxZfZ8oo27v2xom9AEB
         3FAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2RYP+RudF/nyEKA/rCkh4BQbZTC+SmjOsZisXvVJcaI=;
        b=QHJgHEZJeSxbqf1BgoFIdYRZSRZ65eayMYZEnltakMAzOqwE5ydsJ94QpSg5VXDJoU
         k9Vajy2NwnTsHTlrLkajueTHh5PEvHKKojmknmW7/QSmndJe+rFR4tDYPNVq1fcN45hD
         HPBs6XBZMKxIaksGrdw3w/AtkQUqDOuIbzPZdAwstp+1DRBZr/UwR06hxq3fTekNpgI2
         GOcDRyj+3vLidQdc4e8eLfWH2iCVrslhTTZwS6/Pbp/r+uwINQculA7Foq44i1OVf5BU
         601x/ILfXZifvBb/n7+s6v8ga5hFgzyewcYDYyI5xUtc4KqC31s/KvKuIKwLPDl4MoZ7
         GI9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zux4DUE6;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id q1si375862pgg.5.2020.06.04.17.20.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 17:20:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id r10so4267274pgv.8
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 17:20:48 -0700 (PDT)
X-Received: by 2002:a62:7ccb:: with SMTP id x194mr7124773pfc.318.1591316448031;
 Thu, 04 Jun 2020 17:20:48 -0700 (PDT)
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
 <CAG_fn=XjmgyxDANUN0a8kY2CuucQ2gHFfQqsk6TF_XpiqWGCgw@mail.gmail.com> <CA+dZkakFEJZLtfe7L2oN4w4O=T+x1L2WxZyKtSyofs8m3wLEzw@mail.gmail.com>
In-Reply-To: <CA+dZkakFEJZLtfe7L2oN4w4O=T+x1L2WxZyKtSyofs8m3wLEzw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Jun 2020 02:20:37 +0200
Message-ID: <CAAeHK+xA6NaC0d36OtAhMgbA=sCvKHa1bN-a4zQZkzLh+EMGDQ@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Raju Sana <venkat.rajuece@gmail.com>
Cc: Alexander Potapenko <glider@google.com>, Linus Walleij <linus.walleij@linaro.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Abbott Liu <liuwenliang@huawei.com>, Daniel Axtens <dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Zux4DUE6;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544
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

On Fri, Jun 5, 2020 at 2:14 AM Raju Sana <venkat.rajuece@gmail.com> wrote:
>
> Hello ALL,
>
> Thanks Alexander, I did attach to lauterbach  and debugging this now.. to=
 see where exactly failures..
>
> Initial Issue  behind memcpy failure is due to  FORTIFY  is enabled in my=
 build, after turning off the FORTIFY  like below  , I was bale to gte pass=
 memcpy issue.
>
> index 947f93037d87..64f0c81ac9a0 100644
> --- a/arch/arm/include/asm/string.h
> +++ b/arch/arm/include/asm/string.h
> @@ -58,6 +58,9 @@ static inline void *memset64(uint64_t *p, uint64_t v, _=
_kernel_size_t n)
>  #define memcpy(dst, src, len) __memcpy(dst, src, len)
>  #define memmove(dst, src, len) __memmove(dst, src, len)
>  #define memset(s, c, n) __memset(s, c, n)
> +#ifndef __NO_FORTIFY
> +#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
> +#endif
>  #endif
>
>
> Is  KASAN expected to  work when  FORTIFY enabled  ?

There's a series from Daniel related to KASAN + FORTIFY_SOURCE [1]
btw, which might help you here.

[1] https://lkml.org/lkml/2020/4/24/729

>
> After above change , I was  table to succeed with all  early init calls  =
and also was able to dump the cmd_line args using lauterbach it was showing=
 as accurate.
>
> Now I ran into  READ_ONCE and JUMP_LABEL issues  while running arch speci=
fic CPU hooks   ?  aAe these two related ? Appreciate any pointers here.
>
> Thanks
> Venkat Sana.
>
>
>
>
>
>
> BTW,  is this tested with FORTIFY
>
>
> On Tue, Jun 2, 2020 at 5:55 AM Alexander Potapenko <glider@google.com> wr=
ote:
>>
>> On Mon, Jun 1, 2020 at 10:18 PM Raju Sana <venkat.rajuece@gmail.com> wro=
te:
>> >
>> > Thank you Walleij.
>> >
>> > I tried booting form 0x50000000,  but  hit the same issue.
>> > I tried disabling instrumentation by passing KASAN_SANITIZE :=3Dn  @ a=
rch/arm/Makefile , but still no luck.
>>
>> This only disables instrumentation for files in arch/arm, which might
>> be not enough.
>> Try removing the -fsanitize=3Dkernel-address flag from scripts/Makefile.=
kasan
>>
>> > Thanks,
>> > Venkat Sana.
>> >
>> > On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij <linus.walleij@linaro.org=
> wrote:
>> >>
>> >> On Mon, Jun 1, 2020 at 1:07 AM Raju Sana <venkat.rajuece@gmail.com> w=
rote:
>> >>
>> >>> And I am  loading image @ 0x44000000 in DDR and boot  using  "bootm =
  0x44000000"
>> >>
>> >>
>> >> Hm... can you try loading it at 0x50000000 and see what happens?
>> >>
>> >> We had issues with non-aligned physical base.
>> >>
>> >> Yours,
>> >> Linus Walleij
>> >
>> > --
>> > You received this message because you are subscribed to the Google Gro=
ups "kasan-dev" group.
>> > To unsubscribe from this group and stop receiving emails from it, send=
 an email to kasan-dev+unsubscribe@googlegroups.com.
>> > To view this discussion on the web visit https://groups.google.com/d/m=
sgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrAiAaohZfke8aoyhcqvs_CYSuirA%40ma=
il.gmail.com.
>>
>>
>>
>> --
>> Alexander Potapenko
>> Software Engineer
>>
>> Google Germany GmbH
>> Erika-Mann-Stra=C3=9Fe, 33
>> 80636 M=C3=BCnchen
>>
>> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
>> Registergericht und -nummer: Hamburg, HRB 86891
>> Sitz der Gesellschaft: Hamburg
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/CA%2BdZkakFEJZLtfe7L2oN4w4O%3DT%2Bx1L2WxZyKtSyofs8m3wLEzw%40mai=
l.gmail.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2BxA6NaC0d36OtAhMgbA%3DsCvKHa1bN-a4zQZkzLh%2BEMGDQ%40mail.=
gmail.com.
