Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFX22DXAKGQESZB5L4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id D9C2C102C50
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 20:05:59 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id m13sf4868405pgk.12
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 11:05:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574190358; cv=pass;
        d=google.com; s=arc-20160816;
        b=z/eUW6UqJsqAUc8koAkGiMHv8g0B847tlrBcTyvwdGwqX8lRllfR7oOmUgXXMUdJ4n
         /rH7Chz076q6W2oanV+Ry6sgc2pObqEq5rh0w2c31XEZ7x+u4Rjj9lM2s8wJHKstbyA2
         +7s2KsHNQmij2okC/x02BzpKAl31c6K5/+prNq837dunHdXWpVmDlY3BkeKuwxqkpDyM
         IefuX+Rjr7NpD+440UJylFIzqQj7kGk8kpZ1gJAtWUBeP4aFglJva7pQ77LLzfeOrWZr
         1RGXlNRgG49zajwWiju4yJQindl1NpvUHqTKivuVzZ/Q5RvhRKH/KyZ+ZossYHTUypOj
         TOkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=t2Vuqk6mnl6BjSFqPSbMp1S2LDTLRHFsEW7lzUgfBxA=;
        b=c4BIsRPwrqieKlRBH2CXy1hESxJPzTjhGJZEfxJ+amcSTRDntZ6iZxDLDl2qt+oXXR
         ejCq+pUt7zQhyagtCkJ2fuOFpDnaHLmSm8ir1Vk1MQq+Ung8TzjyPJ6HME+ClBTzyBHi
         dS0+LRijjpW6PZ6Ayb+iaaV0hCa2KoOkyRqDa1hu5boq04DFQVlc3UMD1cJzM/COpJXW
         h1Lkg+kr6++4SfeMEIYcH9OqJupCLK62XAjzOPDGezNovCoalcRxbe4KSdcq5bjAGpmK
         oCoITfKFix7gCxWV7aYwA0DMo9zqpT0iTy3pwt+h+/OeyD+xTfKmhTznBcrnp/d0AQaK
         +mKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z5T8NRw+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=t2Vuqk6mnl6BjSFqPSbMp1S2LDTLRHFsEW7lzUgfBxA=;
        b=B98KPQC28x7wO2jpTwY4D6Hd+R724jv9W9Sfqp2xPXI50tt+fwJcs4MC66ZjTWKtit
         WnwZNShJytI15Q1Sz6pd9kiOfPp/nLCBBoyWYF0yHaIp7v5mJaUPGgZtSbBl/q2jZCAo
         IQHxr7byaEqzputTVZSJW80ZD1gLFhMyrx80tZJhcclbx49/Dc+e4z5GHV3VfRkceFoj
         /bTQ6L1993mVHEkVAu4E0Od8on+UZmoBdue2eE3dP4yo5vlO7J9/Iya0A0XrEwSdKn+X
         GqMa/BHiaXw5KtuYJCZrJBkcXnFY/OH5beEuCpsBxdT2bMCvEj8d8rSXYlc3gvoPEw/R
         ossA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=t2Vuqk6mnl6BjSFqPSbMp1S2LDTLRHFsEW7lzUgfBxA=;
        b=c4chiOYgWjeotS/s1kdJ2YxJ3Ca5eyxSqOQFs9M2TeOXVAyd3jbl+05PJqJsNo7ex/
         sRKFyLAjks0EL+NWnpbnjScah1ZCcH3/BSzNpkKJ4SXBx3jxtQgPjVo4z0320VoY/FSQ
         f/Hgmbd+FISG5d/3+mDIXAgK690C2fgbYX4lcAyPMrXfGusd6ztcHJxA/PwCuf/UNgyk
         +GuVanCiTz1DRHgJJXuaboYWaAdWe/RlMnXWc08Hby3N5UhBURrcqca8Ips8EB0Hw7CE
         4OyYDikeQ5xc3fn8F6Onl4DMbrriDs9tH+8VOnf0D659JB4IMsa2UR6rV29I+qL1ap5E
         tjQg==
X-Gm-Message-State: APjAAAUulNj536YPp4FFUF9BsFdULryfbs9VlObb7/i/lPrDqIV+ATYa
	Sepur732H3FKOwD9ZqfzDGE=
X-Google-Smtp-Source: APXvYqzR2GXerdOzBAEUtMHRRFA8sU/nYdZPlWySGeIwcGeSt/BSTeVnG+hnJv+KDnA7v045VRiKLw==
X-Received: by 2002:a63:ea09:: with SMTP id c9mr7357339pgi.232.1574190358268;
        Tue, 19 Nov 2019 11:05:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:52d1:: with SMTP id g200ls5320268pfb.3.gmail; Tue, 19
 Nov 2019 11:05:57 -0800 (PST)
X-Received: by 2002:a63:586:: with SMTP id 128mr7109983pgf.198.1574190357741;
        Tue, 19 Nov 2019 11:05:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574190357; cv=none;
        d=google.com; s=arc-20160816;
        b=lHxVdIAU4bAXtvyCTYt5QzEJXrAEtLqWw+nV/Ze7OhMTJG0rtwKPh5z1QQ8/AKFysE
         0KoCwpXlofmUdy8hivQ7NukGAQJ3qeqFoF3o34keSvKXUvzMZo8q9DkxhKRYN3jhwSF+
         fWMsJUGk3B/4ms9SldvRTMldihxGOg0LOm677rhZ8T9XojIzDMmpC33TdwjkGzNe0oop
         TrylVpyUnFT7NN7vvvPd0MwS8cx17Dv/P6fx8H9rEMg5XDUrMSm6uE0QIbdoslTZH0JR
         Eje+k+eEPgTpW0y5VDEd7litlSWvqFZOTyYtQrqSE3fM8LKqrg3+/5CARbmefuQqgVUE
         7FnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0NatauBtPtJXOsbjFvuk9RBByg3dOvLiEzcuEjEIyik=;
        b=SVy27dWcl0ydwUH+1DTgMtwDHHQgXPcgtQri19238kqQNKn8K0p1HFu5gL3pbe6uRn
         sXOg92PvJpE4mnSPF71P2llAQaLw+jJFpO+BwINDEKbfe+A7Hcv2VMNKpZrjovnK8zrx
         MyG1LL86YAhcStUaNS4AC05bfRKjYgPArlvlX4+eoGZxeKpxeiioPlRWenxA25DLJW33
         jKXY/hokRi+ZJpBEXN5WQ5sPFvEenwKBLJDKw3+aiqNB35kcTRW9XvmXfTRdX94HjmAD
         jgrlynCwKTnJxvwHN8dPxi1t6Aj0XjP3745K/cxU5BLRmOg9O5M9FYDzcRFSNfiCRgil
         C5rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z5T8NRw+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id c101si133737pje.1.2019.11.19.11.05.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 11:05:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id z25so18916760oti.5
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 11:05:57 -0800 (PST)
X-Received: by 2002:a9d:69cf:: with SMTP id v15mr4680730oto.251.1574190357041;
 Tue, 19 Nov 2019 11:05:57 -0800 (PST)
MIME-Version: 1.0
References: <20191119194658.39af50d0@canb.auug.org.au> <e75be639-110a-c615-3ec7-a107318b7746@infradead.org>
 <CANpmjNMpnY54kDdGwOPOD84UDf=Fzqtu62ifTds2vZn4t4YigQ@mail.gmail.com>
 <fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org> <20191119183407.GA68739@google.com>
 <1574190168.9585.4.camel@lca.pw>
In-Reply-To: <1574190168.9585.4.camel@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Nov 2019 20:05:45 +0100
Message-ID: <CANpmjNMfCNqgsXQdDckOg0kuMgvnD8_jka8N0AT2K3hC=CUe0w@mail.gmail.com>
Subject: Re: linux-next: Tree for Nov 19 (kcsan)
To: Qian Cai <cai@lca.pw>
Cc: Randy Dunlap <rdunlap@infradead.org>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	Linux Next Mailing List <linux-next@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, "Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Z5T8NRw+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Tue, 19 Nov 2019 at 20:02, Qian Cai <cai@lca.pw> wrote:
>
> On Tue, 2019-11-19 at 19:34 +0100, 'Marco Elver' via kasan-dev wrote:
> > On Tue, 19 Nov 2019, Randy Dunlap wrote:
> >
> > > On 11/19/19 8:12 AM, Marco Elver wrote:
> > > > On Tue, 19 Nov 2019 at 16:11, Randy Dunlap <rdunlap@infradead.org> =
wrote:
> > > > >
> > > > > On 11/19/19 12:46 AM, Stephen Rothwell wrote:
> > > > > > Hi all,
> > > > > >
> > > > > > Changes since 20191118:
> > > > > >
> > > > >
> > > > > on x86_64:
> > > > >
> > > > > It seems that this function can already be known by the compiler =
as a
> > > > > builtin:
> > > > >
> > > > > ../kernel/kcsan/core.c:619:6: warning: conflicting types for buil=
t-in function =E2=80=98__tsan_func_exit=E2=80=99 [-Wbuiltin-declaration-mis=
match]
> > > > >  void __tsan_func_exit(void)
> > > > >       ^~~~~~~~~~~~~~~~
> > > > >
> > > > >
> > > > > $ gcc --version
> > > > > gcc (SUSE Linux) 7.4.1 20190905 [gcc-7-branch revision 275407]
> > > >
> > > > Interesting. Could you share the .config? So far I haven't been abl=
e
> > > > to reproduce.
> > >
> > > Sure, it's attached.
> >
> > Thanks, the config did the trick, even for gcc 9.0.0.
> >
> > The problem is CONFIG_UBSAN=3Dy. We haven't explicitly disallowed it li=
ke
> > with KASAN. In principle there should be nothing wrong with KCSAN+UBSAN=
.
> >
> > There are 3 options:
> > 1. Just disable UBSAN for KCSAN, and also disable KCSAN for UBSAN.
> > 2. Restrict the config to not allow combining KCSAN and UBSAN.
> > 3. Leave things as-is.
> >
> > Option 1 probably makes most sense, and I'll send a patch for that
> > unless there are major objections.
>
> Both option #1 and #2 sounds quite unfortunate, as UBSAN is quite valuabl=
e for
> debugging. Hence, it is desire to make both work at the same time.

Apologies, I think I was a bit unclear with #1. For #1, this just
means that UBSAN is being disabled for the KCSAN runtime and
vice-versa. All other parts of the kernel are still instrumented with
both.

See here: https://lore.kernel.org/linux-next/20191119185742.GB68739@google.=
com/

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMfCNqgsXQdDckOg0kuMgvnD8_jka8N0AT2K3hC%3DCUe0w%40mail.gmai=
l.com.
