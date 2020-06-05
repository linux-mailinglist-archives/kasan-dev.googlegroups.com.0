Return-Path: <kasan-dev+bncBCFLDU5RYAIRB7E4433AKGQEKKZWN3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 25BA61EEEB3
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jun 2020 02:14:53 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id s17sf2997973wrt.7
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 17:14:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591316093; cv=pass;
        d=google.com; s=arc-20160816;
        b=p9XPfbf6R/WLGEihXlASZTc0gzfHcr9OMF0w/G+gb360apR9Aw9GoKSt2r1heiF/PH
         ThDfi0jp9qAk202z7wDWIav6GRifLaIYePK0CsjvkdEH7Vizljymwqo8TMA9VXMcxQd0
         ASGO0itulCH5Su6W3BIV+78jx8FKdxFJ2QlF2OsqrBPUsluMQAmPNpHvTpnyKYAagbfs
         xzZsxkNyH+vh447pJlWe/iBtE+bB+5Yp+enNrkGb1O4t3fnu+yRCEr9H9GP6cR/Dicak
         feVH3z+OUHcFaMg3wPwxB8r3J8hkMAwmzTQqDAshicC4uD4+yJjZLTDFs4PqujDHfkDx
         Vvvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=OqK2zzsmtCaHjpNhFXCeFv+PPbmrWXlBiX02wUs9wxs=;
        b=mLneC28szk2B4edqtvAioxWuvLl+XZrUZha35Dm4LOAn12iCPgCYxUsKjEPo1bEFds
         k/xQTyPztGuIXQJfICUxjcR9ZAjwcWHY3nFpMvVoL6ate2OxJlzrby3g8gAQa+BMUa6I
         LZLPuz6JDxKhH0pN0ljsYpFVabnwMMCmcMCHGf7JV5y6C2eCKgcZMDyZ/05M9x0GVWMf
         Ab2vWeUavd9bRzHuhe+fh+UFBfvk46d1LVd8GCG4dlYJm7cP4mW96j2fd0JmLfmPeLNv
         oRgi6g4Usu4wvz5Rox6MGVe8aIitR60TXAPeWkZioE3y4Wf/m4QR1KAH/BdGAUy4e7do
         d4jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=PSODGXTn;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OqK2zzsmtCaHjpNhFXCeFv+PPbmrWXlBiX02wUs9wxs=;
        b=ivz9h5an7RDkmB2VC0sEEpWuCVYRI9DN5zEE6AURwOabTI25chtxxQQXCk/kebDFmS
         v53gn2+9br1JHZr2LwvNDt18ujsAysFAHEcCF4aBdTLy/8VuIHyZ3N2pVzQ410Mk8RvR
         4CZPE/eqALFhlBLHb5o2FuSRq1jIDZ8jMZZ/OiVJNJ7iI30G5KqFB77PQBwE6r/CaHdX
         xPYdCsYJpQZuZ/rrwaPrUBYUeYUijJxTkz2TkpjEvnztY0mOSjv+tJy1qobOKeXYsg+A
         La7oq73Iai5ZMPCUN0tJ2RD8Ozsxwufi1psV6/bu+YQ0OStPxZvBYg36sUNieND4L3VG
         TjOw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OqK2zzsmtCaHjpNhFXCeFv+PPbmrWXlBiX02wUs9wxs=;
        b=RvPYioh3gcOLJm7WOdDC7XkBxf2YjIFLPE81UoXz6SXcFmhsWIZCmalBBKHyNrmuza
         MrEbLlrffhOxPdtXPCQnd+ZU5yrGg9UsKDLu2injlTfGzayKtF8PrYaeKyPlDiNqoHO/
         t8LuKnHtUo4gxjDkuIdqSs6GKOH9yisYP2risxh9EtJRJBpooojzf1Byz2hhBVTUbJFZ
         XmtQnsuby+HFYFjE0eZptaykldXt5rQ9Bq+BhEhQRFI0XamJxYq0h5LMPw0ejYfuH2zj
         gTlIQ2BR5th5gzhvb9p2y/DQ5zZ/Fs+LFG9NOaCdSigPsPX8j6FktYznpVul3IIu4C61
         pCiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OqK2zzsmtCaHjpNhFXCeFv+PPbmrWXlBiX02wUs9wxs=;
        b=DzUqsUjjml/v/Rwbu0rp02i3Uu3LnQhTXIKpaq0wtNbw4aTuri7pka9zOi1rSgQNk6
         OKRvFVvWiTzyLxdYmBiifo4V897y05l+tZHBwkatGUwXRjHHPAppAA1Lt3Mb6dCEe4d8
         RbtsEOJml7bgiUPduyCBvVVZefKcfoDRZ7MWTtTyZraNDk2TaSSmj4Hr0WgwrBDTsIL8
         HZIOz1O5TLljUj97sg3i8wpwfwZQiuH7SyRtCdShHRx8R0rbE8V/RCaGX2NmTpaA95bt
         BCzSzNxNbyNbCKvUA5+4IZTqmCMouI9yYHHbi5JXO6JlTlqv08/Nktn6IxPXdpXo768P
         hbww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531aHC0/vh4zxL38+2jkMdmXTojf+79p24OKxaXqxwVjUUKKiC49
	wl6GNc7kstoLHdTLej+rhyk=
X-Google-Smtp-Source: ABdhPJzOmd1mb+EBuK9N5jOhn2f93MXeUIQcbW/7kdy52b/GHyrvpAxTVpG+MrQTMzz2aqZqHce5bg==
X-Received: by 2002:adf:9795:: with SMTP id s21mr7282510wrb.166.1591316092753;
        Thu, 04 Jun 2020 17:14:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:62d6:: with SMTP id w205ls3579107wmb.1.canary-gmail;
 Thu, 04 Jun 2020 17:14:52 -0700 (PDT)
X-Received: by 2002:a7b:c40e:: with SMTP id k14mr5583722wmi.59.1591316092099;
        Thu, 04 Jun 2020 17:14:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591316092; cv=none;
        d=google.com; s=arc-20160816;
        b=M9awo9fIG0e04s0N5tKvbHoi4OUVjGL8EKcAR3RAHy8HSNLqyD3h0Tvr39V6rHykXq
         jt5xRZSo0N3/bvAhKCgTkzlqvXmsx+rcZDaNFfdggAkOFV2evHbCS3DKBNDl9pCvvT+9
         BT+XBwFLoHursEaIJ6qz+zpSSAv+70UlwOM67ravH3iBTahSc40F5A3c2CNycnlH+n5Z
         6yhyJm3DPtsEFa48RnkBhDkAkI8ThYX+Z1N3/CqdOyHWbPEx+If2x4+nn3U1ND0rGb1u
         qYF3OYqj5rkzDGe4oJsSiRPjiy05ByqhI0gTCPedI/Tsi0a4cZNHF86/znC6JF7uqVgB
         Q4KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DdtB4XFIcfGRISPvIFQp9RceA5KAcxL7XvUqCSfYSjQ=;
        b=zQiod5wIvs1R8UHOSboorEkVGhwuqZ+/Xth1d/en2ww8ZH6aYAPVaK8WTK/ksov+Zo
         359DQJTnRBDKLwnBWO3EywiF/e7ruTAtqtA2WOkafo8c5223IcaGhLDdiVREyIcOFN1A
         j29X/SMnebfxDYNY4w9i05zfUDw6ad7822KX0K6x7u7muV26rVqz7u/pfFnwr4ml3seM
         adGCApgXbdd4auZYPRsBefV8e9flxx4NKwCnKl+Db61fb9zKHHCycuvNQ6n2kfB+Vzor
         pY2jQiqW5pQ0hLyjJYZZYuolPc51dceGET5EuWiMD70k0kfPaEV2A/ydGNTjg/3x/ll0
         O38A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=PSODGXTn;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id y65si313451wmb.0.2020.06.04.17.14.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 17:14:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id c17so9504975lji.11
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 17:14:52 -0700 (PDT)
X-Received: by 2002:a2e:b529:: with SMTP id z9mr3457061ljm.390.1591316091355;
 Thu, 04 Jun 2020 17:14:51 -0700 (PDT)
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
 <CA+dZkann4Z1TavtJ+iq9oBrAiAaohZfke8aoyhcqvs_CYSuirA@mail.gmail.com> <CAG_fn=XjmgyxDANUN0a8kY2CuucQ2gHFfQqsk6TF_XpiqWGCgw@mail.gmail.com>
In-Reply-To: <CAG_fn=XjmgyxDANUN0a8kY2CuucQ2gHFfQqsk6TF_XpiqWGCgw@mail.gmail.com>
From: Raju Sana <venkat.rajuece@gmail.com>
Date: Thu, 4 Jun 2020 17:14:40 -0700
Message-ID: <CA+dZkakFEJZLtfe7L2oN4w4O=T+x1L2WxZyKtSyofs8m3wLEzw@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Alexander Potapenko <glider@google.com>
Cc: Linus Walleij <linus.walleij@linaro.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Abbott Liu <liuwenliang@huawei.com>
Content-Type: multipart/alternative; boundary="00000000000059cc7805a74b2605"
X-Original-Sender: venkat.rajuece@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=PSODGXTn;       spf=pass
 (google.com: domain of venkat.rajuece@gmail.com designates
 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
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

--00000000000059cc7805a74b2605
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hello ALL,

Thanks Alexander, I did attach to lauterbach  and debugging this now.. to
see where exactly failures..

Initial Issue  behind memcpy failure is due to  FORTIFY  is enabled in my
build, after turning off the FORTIFY  like below  , I was bale to gte pass
memcpy issue.

index 947f93037d87..64f0c81ac9a0 100644
--- a/arch/arm/include/asm/string.h
+++ b/arch/arm/include/asm/string.h
@@ -58,6 +58,9 @@ static inline void *memset64(uint64_t *p, uint64_t v,
__kernel_size_t n)
 #define memcpy(dst, src, len) __memcpy(dst, src, len)
 #define memmove(dst, src, len) __memmove(dst, src, len)
 #define memset(s, c, n) __memset(s, c, n)
+#ifndef __NO_FORTIFY
+#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
+#endif
 #endif


Is  KASAN expected to  work when  FORTIFY enabled  ?

After above change , I was  table to succeed with all  early init calls
and also was able to dump the cmd_line args using lauterbach it was showing
as accurate.

Now I ran into  READ_ONCE and JUMP_LABEL issues  while running arch
specific CPU hooks   ?  aAe these two related ? Appreciate any pointers
here.

Thanks
Venkat Sana.






BTW,  is this tested with FORTIFY


On Tue, Jun 2, 2020 at 5:55 AM Alexander Potapenko <glider@google.com>
wrote:

> On Mon, Jun 1, 2020 at 10:18 PM Raju Sana <venkat.rajuece@gmail.com>
> wrote:
> >
> > Thank you Walleij.
> >
> > I tried booting form 0x50000000,  but  hit the same issue.
> > I tried disabling instrumentation by passing KASAN_SANITIZE :=3Dn  @
> arch/arm/Makefile , but still no luck.
>
> This only disables instrumentation for files in arch/arm, which might
> be not enough.
> Try removing the -fsanitize=3Dkernel-address flag from scripts/Makefile.k=
asan
>
> > Thanks,
> > Venkat Sana.
> >
> > On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij <linus.walleij@linaro.org>
> wrote:
> >>
> >> On Mon, Jun 1, 2020 at 1:07 AM Raju Sana <venkat.rajuece@gmail.com>
> wrote:
> >>
> >>> And I am  loading image @ 0x44000000 in DDR and boot  using  "bootm
>  0x44000000"
> >>
> >>
> >> Hm... can you try loading it at 0x50000000 and see what happens?
> >>
> >> We had issues with non-aligned physical base.
> >>
> >> Yours,
> >> Linus Walleij
> >
> > --
> > You received this message because you are subscribed to the Google
> Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send
> an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrA=
iAaohZfke8aoyhcqvs_CYSuirA%40mail.gmail.com
> .
>
>
>
> --
> Alexander Potapenko
> Software Engineer
>
> Google Germany GmbH
> Erika-Mann-Stra=C3=9Fe, 33
> 80636 M=C3=BCnchen
>
> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> Registergericht und -nummer: Hamburg, HRB 86891
> Sitz der Gesellschaft: Hamburg
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BdZkakFEJZLtfe7L2oN4w4O%3DT%2Bx1L2WxZyKtSyofs8m3wLEzw%40mail.=
gmail.com.

--00000000000059cc7805a74b2605
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hello ALL,<div><br></div><div>Thanks Alexander, I did atta=
ch=C2=A0to lauterbach=C2=A0 and debugging=C2=A0this now.. to see where exac=
tly failures..</div><div><br></div><div>Initial Issue=C2=A0=C2=A0behind=C2=
=A0memcpy failure is due to=C2=A0 FORTIFY=C2=A0 is enabled in my build, aft=
er turning off the FORTIFY=C2=A0 like below=C2=A0 , I was bale to gte=C2=A0=
pass memcpy issue.</div><div><br></div><div>index 947f93037d87..64f0c81ac9a=
0 100644<br>--- a/arch/arm/include/asm/string.h<br>+++ b/arch/arm/include/a=
sm/string.h<br>@@ -58,6 +58,9 @@ static inline void *memset64(uint64_t *p, =
uint64_t v, __kernel_size_t n)<br>=C2=A0#define memcpy(dst, src, len) __mem=
cpy(dst, src, len)<br>=C2=A0#define memmove(dst, src, len) __memmove(dst, s=
rc, len)<br>=C2=A0#define memset(s, c, n) __memset(s, c, n)<br>+#ifndef __N=
O_FORTIFY<br>+#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy,=
 etc. */<br>+#endif<br>=C2=A0#endif<br></div><div><br></div><div><br></div>=
<div>Is=C2=A0 KASAN expected to=C2=A0 work when=C2=A0 FORTIFY enabled=C2=A0=
 ?</div><div><br></div><div>After above change , I was=C2=A0 table to succe=
ed=C2=A0with all=C2=A0 early init calls=C2=A0 and also was able to dump the=
 cmd_line args using lauterbach it was showing as accurate.</div><div><br><=
/div><div>Now I ran into=C2=A0 READ_ONCE and JUMP_LABEL issues=C2=A0 while =
running arch specific CPU hooks=C2=A0 =C2=A0?=C2=A0 aAe these two related ?=
 Appreciate any pointers here.</div><div><br></div><div>Thanks</div><div>Ve=
nkat Sana.</div><div><br></div><div><br></div><div><br></div><div><br></div=
><div><br></div><div><br></div><div>BTW,=C2=A0 is this tested with FORTIFY=
=C2=A0</div><div><br></div></div><br><div class=3D"gmail_quote"><div dir=3D=
"ltr" class=3D"gmail_attr">On Tue, Jun 2, 2020 at 5:55 AM Alexander Potapen=
ko &lt;<a href=3D"mailto:glider@google.com">glider@google.com</a>&gt; wrote=
:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.=
8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">On Mon, Jun 1,=
 2020 at 10:18 PM Raju Sana &lt;<a href=3D"mailto:venkat.rajuece@gmail.com"=
 target=3D"_blank">venkat.rajuece@gmail.com</a>&gt; wrote:<br>
&gt;<br>
&gt; Thank you Walleij.<br>
&gt;<br>
&gt; I tried booting form 0x50000000,=C2=A0 but=C2=A0 hit the same issue.<b=
r>
&gt; I tried disabling instrumentation by passing KASAN_SANITIZE :=3Dn=C2=
=A0 @ arch/arm/Makefile , but still no luck.<br>
<br>
This only disables instrumentation for files in arch/arm, which might<br>
be not enough.<br>
Try removing the -fsanitize=3Dkernel-address flag from scripts/Makefile.kas=
an<br>
<br>
&gt; Thanks,<br>
&gt; Venkat Sana.<br>
&gt;<br>
&gt; On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij &lt;<a href=3D"mailto:lin=
us.walleij@linaro.org" target=3D"_blank">linus.walleij@linaro.org</a>&gt; w=
rote:<br>
&gt;&gt;<br>
&gt;&gt; On Mon, Jun 1, 2020 at 1:07 AM Raju Sana &lt;<a href=3D"mailto:ven=
kat.rajuece@gmail.com" target=3D"_blank">venkat.rajuece@gmail.com</a>&gt; w=
rote:<br>
&gt;&gt;<br>
&gt;&gt;&gt; And I am=C2=A0 loading image @ 0x44000000 in DDR and boot=C2=
=A0 using=C2=A0 &quot;bootm=C2=A0 =C2=A00x44000000&quot;<br>
&gt;&gt;<br>
&gt;&gt;<br>
&gt;&gt; Hm... can you try loading it at 0x50000000 and see what happens?<b=
r>
&gt;&gt;<br>
&gt;&gt; We had issues with non-aligned physical base.<br>
&gt;&gt;<br>
&gt;&gt; Yours,<br>
&gt;&gt; Linus Walleij<br>
&gt;<br>
&gt; --<br>
&gt; You received this message because you are subscribed to the Google Gro=
ups &quot;kasan-dev&quot; group.<br>
&gt; To unsubscribe from this group and stop receiving emails from it, send=
 an email to <a href=3D"mailto:kasan-dev%2Bunsubscribe@googlegroups.com" ta=
rget=3D"_blank">kasan-dev+unsubscribe@googlegroups.com</a>.<br>
&gt; To view this discussion on the web visit <a href=3D"https://groups.goo=
gle.com/d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrAiAaohZfke8aoyhcqvs_C=
YSuirA%40mail.gmail.com" rel=3D"noreferrer" target=3D"_blank">https://group=
s.google.com/d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrAiAaohZfke8aoyhc=
qvs_CYSuirA%40mail.gmail.com</a>.<br>
<br>
<br>
<br>
-- <br>
Alexander Potapenko<br>
Software Engineer<br>
<br>
Google Germany GmbH<br>
Erika-Mann-Stra=C3=9Fe, 33<br>
80636 M=C3=BCnchen<br>
<br>
Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado<br>
Registergericht und -nummer: Hamburg, HRB 86891<br>
Sitz der Gesellschaft: Hamburg<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BdZkakFEJZLtfe7L2oN4w4O%3DT%2Bx1L2WxZyKtSyofs8m3wL=
Ezw%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CA%2BdZkakFEJZLtfe7L2oN4w4O%3DT%2Bx1L2WxZyKtS=
yofs8m3wLEzw%40mail.gmail.com</a>.<br />

--00000000000059cc7805a74b2605--
