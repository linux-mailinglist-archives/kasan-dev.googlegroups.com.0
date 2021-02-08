Return-Path: <kasan-dev+bncBDUPB6PW4UKRBHMKQKAQMGQEYZTQD2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id AF531312894
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 01:26:06 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id 137sf9516648pfw.4
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Feb 2021 16:26:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612743965; cv=pass;
        d=google.com; s=arc-20160816;
        b=wZCoYIAAZNNNT82DV8BNR0YNKApFaWKgekSAUbtc11QvDElIbAMcqGZERBNw4d/eHM
         Cc3a0HcmU7xTHumT3A3CurcBnJdRE099qAw/dIoTbmaW7zB/lh8dJ4mvJ/fnEHTthpaZ
         7w933wtbbZKuZwQD36dIFeeJNDIOJvTV3JK8sEnNM8T5ajcqPe7/iPHWoBN4IcgvycZN
         wIOjyZw3rd9l1W2ITJk6gmepEUUkW168McHKNwc0bY3bJWhp2rnNyvjUn4cwpsOeoTmN
         ZQyqXCe801aue77l6fpbnD0l72VxyVsHg+zqY4SkXebxTD4W95kjOgS/foBeYhnoQTbC
         lWvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=S5ZZIIl7FpHg3XqK0SQ3WbV/Z4k46oJ8qFi4OEPgPQA=;
        b=T8xH9xxM2w1hy5iePBrxAJMWJjM52DIJfQKaRK50R3WPtbBmKR5kSs7ES6yse7Ha/E
         1jaIa6t4Z75iXfQ1200q3J8aeRhT9P/mY25PvrJrQ0nqK2BOcK3EDSSNynGS91H6VD9d
         y+KNs/JujymITjYBJLQiVpw3VV8EZPUoSA1/jaR3Y+hgbdapAvGyGvvrANcKiiPsYZL8
         shieAcgi2v8p3IZQFtWo2JUc3kF6DqwtG9x2YT1TvJvxar59/2jU8Zr+ihWT4pr+i4yD
         Oidtsf1jPW2rnZXsS3scYBmleh7UGyW8t5ZFL40t1NJKCAcNFbWD0d2TpDBbSATNsfqp
         lwjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=jz7LMxEY;
       spf=pass (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=achirvasub@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S5ZZIIl7FpHg3XqK0SQ3WbV/Z4k46oJ8qFi4OEPgPQA=;
        b=IlW9LFze1r/MDv6cBhoNq13p8Ib1GmFF8pEraQKX9jL/RbXebx7cUIYzh9SgW2KItC
         uhtlMs0/KlCt9Doghqb0GiBETZP8BdS+I2eTJQrLmf/MyhNRUIq6eJyvw+Eva+PbkE1Y
         Rr0IvHmbBZ85zzdHv5ZmMPmOVspiSifQ0iauAkfgLtRZ5UTreVK5DAKBzno4DqWWOHCb
         vTIvMiyHZGGD6B7xrNF9pY17yIkfqREgz69215QU0bJeJwub2oXt94xEqcbiDzXshcH4
         td/2Y/LFWZF7yOKUTvHk+GFhT0AdB66QoXGujjexX8d1gk7Fb3kv0mwLjDLhfdKC0khf
         ek4w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S5ZZIIl7FpHg3XqK0SQ3WbV/Z4k46oJ8qFi4OEPgPQA=;
        b=bF9jP/ZUZ1Uz+FiAcIfTQUwK6H5ppjT/lQ92if9nr71zAnPKX1+IZUyN3cdoZNIhcJ
         EvvNsRHjnUZkny1BtsTaPC1OtDEuMN3ZX9afJZms9ez1YzgSl6bU6N+Oaw5RN4NLV6J4
         dcq1GhLJ4r5eX1g/bm/6lyfdSFwFrNmFtyZBEdEnctpmamdVsJqpsq57sRTau5EnUXWV
         mIaGDr5LrY3d8sD48sWQ9NlhegNAJq+/JLHsc6HxSvX+XtOadzCxGlSMn//ul+xVgYWG
         X3m7c6fqL+We8FLJ+rJX1g9oMv6HBUuA+c8fhRWfmA+3t+67JmAA6qFnFNGJ9yEa/Dvw
         s88Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S5ZZIIl7FpHg3XqK0SQ3WbV/Z4k46oJ8qFi4OEPgPQA=;
        b=fXB1Di1IGZEAsO9VMfZZM5abfM2c0JNn3Uc1laR+oXH/inp3LFSlkscf8BHIJ5/4Ry
         lzJX/vokbtJA6FiI6rdb3OiEhuVkW1f1Nm5UNfI3McVmAn7NoDMId1Y/5RamdGs6J7iC
         ZqVcXAXYisw1IWzrMi7bZZ+vPMDDFH6ZYA0+QriB8gxBc4iqXj9UMAsI/NGowxQHhDik
         bHLn5XJpQb+3BWVEZdWGtuFgNtF7fZdsaLaFewq9TfXGDTQ5bof8/OxoaEG9Lvp05LUL
         sNpwt0fBPnpE0H3cvaqG8g/P7x/deVocJOxHseou/NBjg8mKju64p6hs0nMfZPpcclxM
         qL/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PMVN2Khsu77J/JTRshdQY3/vp9SpwfOiLYbs8X3FJCI760ntE
	h1eLm/90e6GdbIuOSSvSjTU=
X-Google-Smtp-Source: ABdhPJyqnKcByZ89A77OWzEp7wz/LuLPDyCxwaJKP3w3PUAX0fa0L3KOTQ51GZoL+1Buq/V2NsvM3w==
X-Received: by 2002:a63:c1d:: with SMTP id b29mr14792820pgl.9.1612743965358;
        Sun, 07 Feb 2021 16:26:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:412:: with SMTP id 18ls1961714pge.0.gmail; Sun, 07 Feb
 2021 16:26:04 -0800 (PST)
X-Received: by 2002:a63:cb4c:: with SMTP id m12mr14490393pgi.51.1612743964712;
        Sun, 07 Feb 2021 16:26:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612743964; cv=none;
        d=google.com; s=arc-20160816;
        b=KWgWw+mKX1Zp6m4IwIrSWneppAMaYfzsTmsyywyfgIkXY+ClV847Y5QsieLiFMn62M
         cD6g6ud+LMsiAqDQ6zk8GFxgGcs5aNPmpmVmW1IoP+tu2rWmc9vqNOdpCw2QZd0z9NJP
         tYRgfUSenvbZB+kXkfg1Upv6SBOhKFVpKxvd5bZMZpYh8mMois4Rq976bam719ke1n3d
         BSstBDkSzjUXvHqTGcadWZicnlK2XXITCMBczBnvszYW/4Cvv6R5sAi2YsJ00NDgXpAP
         ml6L8yfSSaOElPo3yuH1xkr8GKles0LKBVr2TfuN4wRbX0FpjsnBzZlOvOq49u1rF2N7
         A5vQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=dDf+QsV3I3slhxIeK/jswJxScHK7l3HKSebkL3FSL9k=;
        b=rSCba4iQniDGuewgRxz5Bg9ai9yCPxzRsAUxiEJQDEMO61CCwsp/rCQtPvF+tGupHT
         ui9tX7NxKJX037m518I1kkc8z8P4VD2GqpkGipR1A7c0IyRIyos2ieQnTq9OHgBrNlpS
         rUOAb24ioRrxuUWZ1KmaJ5VaEMVz9+rccq5Me3bHNpmHfYkPnaW5NY/YYn+LDXwkJGrr
         Ew8MGN7e8FsVD3Vm91CSUj2cTkGWFqXLMqifz10puGbgP/V5UuWAPwCTf1NEOVNo3uAo
         UlO06j6yjk3eeEJARP60M6QGDhVKsZbmZtuF0cbsjKE/uAyXHa3TozZnpwU4uBU21EBB
         7b3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=jz7LMxEY;
       spf=pass (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=achirvasub@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id q21si600320pgt.3.2021.02.07.16.26.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Feb 2021 16:26:04 -0800 (PST)
Received-SPF: pass (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id h8so2633543qkk.6
        for <kasan-dev@googlegroups.com>; Sun, 07 Feb 2021 16:26:04 -0800 (PST)
X-Received: by 2002:ae9:d881:: with SMTP id u123mr14644020qkf.133.1612743963970;
        Sun, 07 Feb 2021 16:26:03 -0800 (PST)
Received: from arch-chirva.localdomain (pool-68-133-6-116.bflony.fios.verizon.net. [68.133.6.116])
        by smtp.gmail.com with ESMTPSA id y186sm7645292qka.121.2021.02.07.16.26.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 07 Feb 2021 16:26:03 -0800 (PST)
Date: Sun, 7 Feb 2021 19:26:01 -0500
From: Stuart Little <achirvasub@gmail.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Arnd Bergmann <arnd@arndb.de>
Cc: linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: PROBLEM: 5.11.0-rc7 fails =?utf-8?Q?to?=
 =?utf-8?Q?_compile_with_error=3A_=E2=80=98-mindirect-branch=E2=80=99_and_?=
 =?utf-8?B?4oCYLWZjZi1wcm90ZWN0aW9u4oCZ?= are not compatible
Message-ID: <YCCFGc97d2U5yUS7@arch-chirva.localdomain>
References: <YCB4Sgk5g5B2Nu09@arch-chirva.localdomain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <YCB4Sgk5g5B2Nu09@arch-chirva.localdomain>
X-Original-Sender: achirvasub@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=jz7LMxEY;       spf=pass
 (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::736
 as permitted sender) smtp.mailfrom=achirvasub@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

The result of the bisect on the issue reported in the previous message:

--- cut ---

20bf2b378729c4a0366a53e2018a0b70ace94bcd is the first bad commit
commit 20bf2b378729c4a0366a53e2018a0b70ace94bcd
Author: Josh Poimboeuf <jpoimboe@redhat.com>
Date:   Thu Jan 28 15:52:19 2021 -0600

    x86/build: Disable CET instrumentation in the kernel
   =20
    With retpolines disabled, some configurations of GCC, and specifically
    the GCC versions 9 and 10 in Ubuntu will add Intel CET instrumentation
    to the kernel by default. That breaks certain tracing scenarios by
    adding a superfluous ENDBR64 instruction before the fentry call, for
    functions which can be called indirectly.
   =20
    CET instrumentation isn't currently necessary in the kernel, as CET is
    only supported in user space. Disable it unconditionally and move it
    into the x86's Makefile as CET/CFI... enablement should be a per-arch
    decision anyway.
   =20
     [ bp: Massage and extend commit message. ]
   =20
    Fixes: 29be86d7f9cb ("kbuild: add -fcf-protection=3Dnone when using ret=
poline flags")
    Reported-by: Nikolay Borisov <nborisov@suse.com>
    Signed-off-by: Josh Poimboeuf <jpoimboe@redhat.com>
    Signed-off-by: Borislav Petkov <bp@suse.de>
    Reviewed-by: Nikolay Borisov <nborisov@suse.com>
    Tested-by: Nikolay Borisov <nborisov@suse.com>
    Cc: <stable@vger.kernel.org>
    Cc: Seth Forshee <seth.forshee@canonical.com>
    Cc: Masahiro Yamada <yamada.masahiro@socionext.com>
    Link: https://lkml.kernel.org/r/20210128215219.6kct3h2eiustncws@treble

 Makefile          | 6 ------
 arch/x86/Makefile | 3 +++
 2 files changed, 3 insertions(+), 6 deletions(-)

--- end ---

On Sun, Feb 07, 2021 at 06:31:22PM -0500, Stuart Little wrote:
> I am trying to compile on an x86_64 host for a 32-bit system; my config i=
s at
>=20
> https://termbin.com/v8jl
>=20
> I am getting numerous errors of the form
>=20
> ./include/linux/kasan-checks.h:17:1: error: =E2=80=98-mindirect-branch=E2=
=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible
>=20
> and
>=20
> ./include/linux/kcsan-checks.h:143:6: error: =E2=80=98-mindirect-branch=
=E2=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible
>=20
> and
>=20
> ./arch/x86/include/asm/arch_hweight.h:16:1: error: =E2=80=98-mindirect-br=
anch=E2=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible
>=20
> (those include files indicated whom I should add to this list; apologies =
if this reaches you in error).
>=20
> The full log of the build is at
>=20
> https://termbin.com/wbgs
>=20
> ---
>=20
> 5.11.0-rc6 built fine last week on this same setup.=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YCCFGc97d2U5yUS7%40arch-chirva.localdomain.
