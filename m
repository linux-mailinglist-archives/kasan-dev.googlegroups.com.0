Return-Path: <kasan-dev+bncBC7OBJGL2MHBB76YQOBAMGQE7VWQFJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 34D8732D522
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 15:19:45 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id u9sf7624462oon.23
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 06:19:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614867584; cv=pass;
        d=google.com; s=arc-20160816;
        b=C9JiBdlnXsf7+EEQg+ZFHn3p2473pkjkNyDb6X1IDwXIcj/XfZ8jseG4/Ofk0eeFnG
         4WNC3pyT5z3qSBu11kM3m4jXjM7ErlQOZxtr1rvqdnqZtZPrBEtx9DvHkGsS9W3sDHvv
         a2ElQ2Y36H9F3caZLjXSUdG7ScJMxnWroQeskQ3eLnECRYq0V8JpOz1XvRMWavBnNVnD
         Qg5nQu9sf2EmI29pcpsP9GMpJvUwoqrXo8SBf8zD6x050ZkX4XUvdDprmsdI5+u2dOGX
         +ro5PUzIy3ljoajElLcWEU8LsQ6U9a1Mphh0NfKQeHGFjCkwaGLv8h4wi+C0H3s5Znie
         zFxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h2C+xddIw7t1GZpd2+kLee5XvpARytv5vKaFCyEnazk=;
        b=QvuezMcP6mOGNP7SshqUaBQaxQK25IIRhSdN+gg/X4r4e7LsJaZ4WMoxXB6Ty75heg
         UI86yL9hLxnuzMLWtnB8wpKyRjRUtz633n/Bsj/3XvKDLQJyVNeBwsM81grCdJU30ytP
         eaUjdQKwhfa9/n/3f/wICQu1OfmdbEcSYowqnmAMuM1Apxkm5bbfdZsKGXVyGKdpnL/V
         hS4vtO4Ha2Rnd5TzQPRzFC42qUPaq4jDgO3S+k6iWiUJiDhIa65dWPLBhC4zfWwkt266
         uQP4XFyIOFajseL264+ZwCOyuM5MdK8bdmAzP7IDZZk0AOvptLgU2PqVJ6BVWqsKLpSt
         Lg9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=quhqijAS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=h2C+xddIw7t1GZpd2+kLee5XvpARytv5vKaFCyEnazk=;
        b=ZN3kA1sJfDoiyIxgqqUpp+iBjgDRSMRAwGLPwOT/AhpLqdh4hQR+lRobLvrPutw8e+
         RDBmz7r/oL6cgNeA1mfhXbZlNw+wtOOammvJomUNYn1PaLfhxYTj7e4kPcwmMWVN4z8a
         wTirh2LqH2A251erVG/CKDTppI0ZC65bX1bTdWnWbvwqjwQ/4lKp60mqySJd9uE7XgWs
         /qEKBFYAIhlYJKjO4H1770D6Sk5fPFpv741hSGMwyk8Lo3oM8e5tIGa92q7Y7QqQSv0G
         2pnN/NsqS5hb6sfgbPcgo1Af9fhgmZbPPXD+COo7JrOvPxWHsBWWqhvmMvOifjDFrNl8
         Q8KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=h2C+xddIw7t1GZpd2+kLee5XvpARytv5vKaFCyEnazk=;
        b=MNFZ5CbTFEXfUAXO8U6U2QcXaUKdWzFFzN9MLv8UPByqcc/BEL6gB393SynAimjuLJ
         XwbrQYbAfY21ADildzHs89sVoWhOpZ3uGgZqX3rfd3qO9cpSqke8FX7YlUov1x+ezAEX
         iPiHJhtBcc9Q+kKEAs0z8yTFcoSIRqHsI2QI7vRbDjbzY04exEM7+b0ZlXE/QA0cCq2P
         JP/HnrbMPbir0aIavXTIUQ7BC+QywsH1akfJillwA/V/vrvOCzlJj5L7BS5kRH3P4Ju3
         66oBmnOJHhQ9/plEv4bjexpl+E4nfAgAnou4+/7RQVxMwpXsetYKuxyj4v8xS6nQIDUV
         TBHg==
X-Gm-Message-State: AOAM531DuajgiHU0dRn2YgG1TAl9E6FUWRJ+LGIYmlaaQ0hSEaaIhT+W
	sKvyOAE78NU2uJP6BUYN0K0=
X-Google-Smtp-Source: ABdhPJy2ONbxIHdDiWesU2Ew9IdcrPrzmB+QszL3OkBAeOPZEtrBpsVnQUjRzZqMcRyVqHDblNRB2Q==
X-Received: by 2002:a05:6830:1502:: with SMTP id k2mr3706483otp.166.1614867583843;
        Thu, 04 Mar 2021 06:19:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6c57:: with SMTP id g23ls1588304otq.11.gmail; Thu, 04
 Mar 2021 06:19:43 -0800 (PST)
X-Received: by 2002:a9d:8d1:: with SMTP id 75mr3669734otf.366.1614867583473;
        Thu, 04 Mar 2021 06:19:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614867583; cv=none;
        d=google.com; s=arc-20160816;
        b=U4ruWPh49BTuuOty6pvjO6cbSZpwsbyqbAdUDZc3Zgk5KzeZD6Y7gTy5LvxxQrZt4R
         IWi/tJ6m5nj6J/Aj+sG6XX4+h3CmqSlVV/scNmKLOdU04iDw/x+02PxZLGxGHcsRbXUL
         mQAfoS5vkcbOgvV3V5XTYZOhzqRrxMU0WMD/3diDwNUUs4ukfIUeKS1pkEc8eTY9l9ad
         31ObFT1m1sO3J1EtEzJHX1ywPUP65SFqK5oMYhwcMHaUrNRqLrkPSSCbZ+dwEkoWuW/i
         Osv7Mebt4PQmx/ykd4yh1+6NDAm/JjGg5IEJLPZKulhWT+PBHMwd2UBQyJoVDzDhtrzS
         BB+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=B6t/iRhxaz6mIiZvKsR4Ph8NTlJXLnsmBsm+Fu3vxVg=;
        b=JbTomICfh0jX7Xz6qVyq5XDxg6oTgr6aGryAbJTVrKi4/wpO4KKdTfpM1UIaC2G8Av
         WiTsYxZ+DZYbutCCWMG3SO9q7Uc7WVaH1n9ficCFMkXseGMINB1yMC13Ni1m0R0SqjVU
         AjYYpOCFByMIhcQ6B51ggPh6aL3Ma32an46CuJZXekr47KLNMaWkRHRVGV0IRcV2bG55
         ZHKSwh98s69LgdiAfrAQJmqN0FOlDwgTGn4C5og/WtP3Bx1pBucwfaTf7qqnEBJqr6EM
         +7ZEa/shj9/OOJMPnX/1Hizljf1wV9r8Rca4nKpxdJawaK2Gqtch4i6pncZYgYoHSth1
         JV/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=quhqijAS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id c7si174172oto.1.2021.03.04.06.19.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 06:19:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id s73so4455630oie.1
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 06:19:43 -0800 (PST)
X-Received: by 2002:aca:d515:: with SMTP id m21mr3162609oig.172.1614867583032;
 Thu, 04 Mar 2021 06:19:43 -0800 (PST)
MIME-Version: 1.0
References: <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu> <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu> <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu> <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
 <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu> <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
 <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu> <YEDXJ5JNkgvDFehc@elver.google.com>
 <4b46ecc9-ae47-eee1-843e-e0638a356b51@csgroup.eu>
In-Reply-To: <4b46ecc9-ae47-eee1-843e-e0638a356b51@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Mar 2021 15:19:31 +0100
Message-ID: <CANpmjNMMMyvsF23U_5HCUe=k7eGaF-WwKV6=YZ81OJedAd2DBQ@mail.gmail.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Alexander Potapenko <glider@google.com>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=quhqijAS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
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

On Thu, 4 Mar 2021 at 15:08, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
>
>
> Le 04/03/2021 =C3=A0 13:48, Marco Elver a =C3=A9crit :
> >  From d118080eb9552073f5dcf1f86198f3d86d5ea850 Mon Sep 17 00:00:00 2001
> > From: Marco Elver <elver@google.com>
> > Date: Thu, 4 Mar 2021 13:15:51 +0100
> > Subject: [PATCH] kfence: fix reports if constant function prefixes exis=
t
> >
> > Some architectures prefix all functions with a constant string ('.' on
> > ppc64). Add ARCH_FUNC_PREFIX, which may optionally be defined in
> > <asm/kfence.h>, so that get_stack_skipnr() can work properly.
>
>
> It works, thanks.
>
> >
> > Link: https://lkml.kernel.org/r/f036c53d-7e81-763c-47f4-6024c6c5f058@cs=
group.eu
> > Reported-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Tested-by: Christophe Leroy <christophe.leroy@csgroup.eu>

Thanks, I'll send this to Andrew for inclusion in -mm, since this is
not a strict dependency (it'll work without the patch, just the stack
traces aren't that pretty but still useful). If the ppc patches and
this make it into the next merge window, everything should be good for
5.13.

> > ---
> >   mm/kfence/report.c | 18 ++++++++++++------
> >   1 file changed, 12 insertions(+), 6 deletions(-)
> >
> > diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> > index 519f037720f5..e3f71451ad9e 100644
> > --- a/mm/kfence/report.c
> > +++ b/mm/kfence/report.c
> > @@ -20,6 +20,11 @@
> >
> >   #include "kfence.h"
> >
> > +/* May be overridden by <asm/kfence.h>. */
> > +#ifndef ARCH_FUNC_PREFIX
> > +#define ARCH_FUNC_PREFIX ""
> > +#endif
> > +
> >   extern bool no_hash_pointers;
> >
> >   /* Helper function to either print to a seq_file or to console. */
> > @@ -67,8 +72,9 @@ static int get_stack_skipnr(const unsigned long stack=
_entries[], int num_entries
> >       for (skipnr =3D 0; skipnr < num_entries; skipnr++) {
> >               int len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)st=
ack_entries[skipnr]);
> >
> > -             if (str_has_prefix(buf, "kfence_") || str_has_prefix(buf,=
 "__kfence_") ||
> > -                 !strncmp(buf, "__slab_free", len)) {
> > +             if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfence_") ||
> > +                 str_has_prefix(buf, ARCH_FUNC_PREFIX "__kfence_") ||
> > +                 !strncmp(buf, ARCH_FUNC_PREFIX "__slab_free", len)) {
> >                       /*
> >                        * In case of tail calls from any of the below
> >                        * to any of the above.
> > @@ -77,10 +83,10 @@ static int get_stack_skipnr(const unsigned long sta=
ck_entries[], int num_entries
> >               }
> >
> >               /* Also the *_bulk() variants by only checking prefixes. =
*/
> > -             if (str_has_prefix(buf, "kfree") ||
> > -                 str_has_prefix(buf, "kmem_cache_free") ||
> > -                 str_has_prefix(buf, "__kmalloc") ||
> > -                 str_has_prefix(buf, "kmem_cache_alloc"))
> > +             if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfree") ||
> > +                 str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_free=
") ||
> > +                 str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmalloc") ||
> > +                 str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_allo=
c"))
> >                       goto found;
> >       }
> >       if (fallback < num_entries)
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMMMyvsF23U_5HCUe%3Dk7eGaF-WwKV6%3DYZ81OJedAd2DBQ%40mail.gm=
ail.com.
