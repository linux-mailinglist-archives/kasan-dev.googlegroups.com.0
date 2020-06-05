Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7FK433AKGQEJEIZTOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id A63841EEED7
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jun 2020 02:44:45 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id k46sf1300800ooi.18
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 17:44:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591317884; cv=pass;
        d=google.com; s=arc-20160816;
        b=zCR1H/DGmQyRxkv5xIrJIDs5D5f4umcjU+Mffq3ineGt4gAQagD3J5b4Y8l8PFrcT6
         1fiWxY+zg9Oon4L7VkyNsK73lI0koY+vpwnxj2Lx75ZpDFSigzq79ErDFzV9qNS61oZX
         D3N7MouTusVR+VfVYPBMfaQ+qIsV7CsumloNTU6EBAYvfRn5fjPZduqNdekJnLWGYXeR
         opHn76Hs8CGPfUMCkeKXGvxO/PnwuNKXj/H4MJ0MnY3G2d1OcTb5pc6DtLjGQK57wIJ8
         KpgyHIGBr1xEYgE++Oa0BgfOCwZgHeD72lYjnv/A0qbMVRg4UcvSf+S57EpYx6Un7aAS
         VywQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JqVeCjuW6I7oYOdM5LWRmE6yiwshSuMFPCxvtiCnJmE=;
        b=qqBWKdoChkXHRpqtxWFnPme4UbinMdRivG+x7GtHs0WqMIGlJoSDaopLjQqZxjHhyX
         HgWaz0eUGqXnSHsWAyB3s9Yw5/1YS+BrAuVUGiHwFb2weuuqtkDS5d2ZZx/LyWls18Qc
         m536dkiF/vwlz/fUF24+zjuiFpY6A7rfEurZrr8oU4sHw7pW0SRQOhikmHFK5/zHxrR+
         R5G/yPe2bE1brNxMal5gqHFm18P8BPTm++I8hDIlNBjwsacQXmF9CmE+BHQod3a8T93N
         H0vBdDGbKPQepCcOMjnFWppO5faXrkpcmz3oCXe/vlpNB7pykTaOV6h439bX1aRnjACj
         wnOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sEbIZ+EL;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=JqVeCjuW6I7oYOdM5LWRmE6yiwshSuMFPCxvtiCnJmE=;
        b=Wx7LlU2lzkHIcw32tF9gpzEzAunxjGQJM7wHC5cZPegO1UgyCpcP3VmPw4o/GEmrZ+
         ZpLCGngnAYRpqoTSMArqOFItubaUfbL9y745sGf4WU3UTiQHDGGJ7I/7frNPknwcoGCr
         UrKSP6ofoXCd3wpiTGB6UScX2qPcbpfAfG3A9sV500tMBUivQDi0fV4/rCLUpiuQq2mF
         T/IXs0QldIsRFnNmRoGMx1ey+ADC7WxKIbKip+TGstf1tk6Koxm2BQM0RazU/3joaVNu
         kuQC4Vsfb9JJy/RSq7+PhjgvePkzdc7umQ0FyREmlkByN7Wsf3gS5PsVig/pXBtdfHKE
         87TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JqVeCjuW6I7oYOdM5LWRmE6yiwshSuMFPCxvtiCnJmE=;
        b=KS/5tjKet41AvpZFeRQmBspmfkgR+vS73JfqNLjM0MN2srlOZTpEAMfKkWKNHnrWlq
         tWVMwE1EgO/eqA9QVbN2zBiDmfJAID+qJ/OR0VMOTDFFarPc2hBoRwpOnAKu6ptKWwa6
         gnPKlLEr3mpwkPEY+0No6F7m8dwH9b1/CQ+bFxkx26dEgBt/U6t4iFz8qQxHPWf2qN3+
         b8l+CKaGxxLLTLrMbbXtg2md9hEu/cHQnDaP+FKj6huDonhnyJaSh+6vgbU/zQoJySUl
         bcBS42LIh0jwACl48E29dvAxxemD5fWYd4mLeopZdX52WudVRMrjZqQtrFktRjYCs5Ne
         k+jg==
X-Gm-Message-State: AOAM530wr1RMc9fN61Tgd0WE6e8VAvGvb3dJS9p0UM9MQsQDt/IHtyrz
	Eu8oiYrhzI5Klh7YLOLijHc=
X-Google-Smtp-Source: ABdhPJyU3af85BWFxb2xmjIjqwWGU/G8eIBLzuM5dH81PVf2TU612Bm4RZJv/MMZELijr3Gao1IDYw==
X-Received: by 2002:a4a:d292:: with SMTP id h18mr5773125oos.80.1591317884620;
        Thu, 04 Jun 2020 17:44:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:590c:: with SMTP id t12ls1689207oth.1.gmail; Thu, 04 Jun
 2020 17:44:44 -0700 (PDT)
X-Received: by 2002:a9d:4602:: with SMTP id y2mr5815873ote.199.1591317883733;
        Thu, 04 Jun 2020 17:44:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591317883; cv=none;
        d=google.com; s=arc-20160816;
        b=gCrMhFLvM+UnnOdGoDImQbiLVEX9kMiMO94MkbD5qCZiEr1zze8n/cy9RjNqJSltXa
         tFDYjyETtRKuySs+dhQJkkt86oD9F178sDW5vQ45e7Dr4gE6ghZ9qyu87YpfQ1U/GoTN
         2yNiesfoMsYhtOxqO/WoL4Vpon9Wf1S3KJxoMldWiXde5ZAVWnPuzNlzgMLcuYXKyC3Q
         aGavQYJ3AEddM7dXHIvB2L+E/KAkBsFFf5vxsF6sNkPZYGsw76y5s6X2ZkwcZIg3LMsH
         cwXMt8G2XPqdpkddw1neSlDpum5ilCpnl69C4Xob4nqi0zoB/KncrrGlLKAmzVuhl3dF
         o5yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wNx9CtbUDbsk7qLSM9L7r0hhPdO7LkpXTBCCEaqdwQw=;
        b=luhfOfOgVw304ulu5JflCLOTLsz/DfESWRA18rusuzv4HQFLchGKtaLkliHYCb8fMd
         vWr1xxtmuD3BSXg9c7fNr/2jxP3qiE0n7n5Jz30ZNoRfwFAUTXy3DiWkobeC+M6DsBv2
         33Lr8uN0wtpBs41O5RY00Xmdq0J6iEfPI2Qc29URE5R5ffsE+fpBzRg9H9nM6ZjCJjpK
         rTlTPvgq51kWzNPZdgwyBsmO72cx3VEpzAAwTo4PxePiz+BM1PCySwDJ23yqmCNKs2yz
         GqnXyiekC3cOH5p5CgrMWCC0kOXMbMzerGvI+tFjCH8EZhK3L3JCESAPDZjV7C1IV4ut
         A9Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sEbIZ+EL;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id a13si389561otl.0.2020.06.04.17.44.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 17:44:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id bh7so2910162plb.11
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 17:44:43 -0700 (PDT)
X-Received: by 2002:a17:90b:1244:: with SMTP id gx4mr26711pjb.136.1591317882820;
 Thu, 04 Jun 2020 17:44:42 -0700 (PDT)
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
 <CAAeHK+xA6NaC0d36OtAhMgbA=sCvKHa1bN-a4zQZkzLh+EMGDQ@mail.gmail.com> <CA+dZkakGP0O_H2x0z+z_xojtDHR59jKqb1M97KvO7yjzxsC5+g@mail.gmail.com>
In-Reply-To: <CA+dZkakGP0O_H2x0z+z_xojtDHR59jKqb1M97KvO7yjzxsC5+g@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Jun 2020 02:44:31 +0200
Message-ID: <CAAeHK+wdrp2thVDwMTjO3gk+XURaq2m1fcmjj4RZZOMhEM9WnQ@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Raju Sana <venkat.rajuece@gmail.com>
Cc: Alexander Potapenko <glider@google.com>, Linus Walleij <linus.walleij@linaro.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Abbott Liu <liuwenliang@huawei.com>, Daniel Axtens <dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sEbIZ+EL;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641
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

On Fri, Jun 5, 2020 at 2:29 AM Raju Sana <venkat.rajuece@gmail.com> wrote:
>
> Thank you Andrey.
>
> How do I access those patches ?

https://lkml.org/lkml/diff/2020/4/24/731/1

https://lkml.org/lkml/diff/2020/4/24/732/1

>
> Thanks,
> Venkat Sana.
>
> On Thu, Jun 4, 2020 at 5:20 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>>
>> On Fri, Jun 5, 2020 at 2:14 AM Raju Sana <venkat.rajuece@gmail.com> wrot=
e:
>> >
>> > Hello ALL,
>> >
>> > Thanks Alexander, I did attach to lauterbach  and debugging this now..=
 to see where exactly failures..
>> >
>> > Initial Issue  behind memcpy failure is due to  FORTIFY  is enabled in=
 my build, after turning off the FORTIFY  like below  , I was bale to gte p=
ass memcpy issue.
>> >
>> > index 947f93037d87..64f0c81ac9a0 100644
>> > --- a/arch/arm/include/asm/string.h
>> > +++ b/arch/arm/include/asm/string.h
>> > @@ -58,6 +58,9 @@ static inline void *memset64(uint64_t *p, uint64_t v=
, __kernel_size_t n)
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
s  and also was able to dump the cmd_line args using lauterbach it was show=
ing as accurate.
>> >
>> > Now I ran into  READ_ONCE and JUMP_LABEL issues  while running arch sp=
ecific CPU hooks   ?  aAe these two related ? Appreciate any pointers here.
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
>> > On Tue, Jun 2, 2020 at 5:55 AM Alexander Potapenko <glider@google.com>=
 wrote:
>> >>
>> >> On Mon, Jun 1, 2020 at 10:18 PM Raju Sana <venkat.rajuece@gmail.com> =
wrote:
>> >> >
>> >> > Thank you Walleij.
>> >> >
>> >> > I tried booting form 0x50000000,  but  hit the same issue.
>> >> > I tried disabling instrumentation by passing KASAN_SANITIZE :=3Dn  =
@ arch/arm/Makefile , but still no luck.
>> >>
>> >> This only disables instrumentation for files in arch/arm, which might
>> >> be not enough.
>> >> Try removing the -fsanitize=3Dkernel-address flag from scripts/Makefi=
le.kasan
>> >>
>> >> > Thanks,
>> >> > Venkat Sana.
>> >> >
>> >> > On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij <linus.walleij@linaro.=
org> wrote:
>> >> >>
>> >> >> On Mon, Jun 1, 2020 at 1:07 AM Raju Sana <venkat.rajuece@gmail.com=
> wrote:
>> >> >>
>> >> >>> And I am  loading image @ 0x44000000 in DDR and boot  using  "boo=
tm   0x44000000"
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
>> >> > You received this message because you are subscribed to the Google =
Groups "kasan-dev" group.
>> >> > To unsubscribe from this group and stop receiving emails from it, s=
end an email to kasan-dev+unsubscribe@googlegroups.com.
>> >> > To view this discussion on the web visit https://groups.google.com/=
d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrAiAaohZfke8aoyhcqvs_CYSuirA%4=
0mail.gmail.com.
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
>> > You received this message because you are subscribed to the Google Gro=
ups "kasan-dev" group.
>> > To unsubscribe from this group and stop receiving emails from it, send=
 an email to kasan-dev+unsubscribe@googlegroups.com.
>> > To view this discussion on the web visit https://groups.google.com/d/m=
sgid/kasan-dev/CA%2BdZkakFEJZLtfe7L2oN4w4O%3DT%2Bx1L2WxZyKtSyofs8m3wLEzw%40=
mail.gmail.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2Bwdrp2thVDwMTjO3gk%2BXURaq2m1fcmjj4RZZOMhEM9WnQ%40mail.gm=
ail.com.
