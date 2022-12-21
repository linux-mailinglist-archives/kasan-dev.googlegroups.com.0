Return-Path: <kasan-dev+bncBDCLJAGETYJBB7F6RSOQMGQEKQ7NJ2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 883606532CD
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Dec 2022 16:00:15 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-14496b502dfsf7063257fac.17
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Dec 2022 07:00:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671634814; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y2DG0OJz5/z4J5LDpL6CpcQvlKQ1R2BoNNtxuxFWb4iMuCzjjYJkOmTe+2JEJ/yjKc
         Uaea3b7r1YRkI6iOBb1gG0E826fZk7FKr3KZ+Sd2ujbO8Bd2Ff+iGDgjKSEHXTmpBowB
         9GJKFszFdMjQlPOUb1ZzM3nueW12q6riZMLolJ41vPTBBRbQmtexWoGqfGaBDXOLSvoG
         CiCR+NgYjJYr2c03lXcebGTgVPqsXsU08/SuSpQ6jUD8NdF/uRZKCN/nR+9+00+eLCXN
         81sfVL69xMrfBiQ4rbgKg9G3WXMnWNs6SvnxklJaYjEfBI035En1MRqedtnoow+Vgbmr
         XvEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KXVWjq+wPU2Omovqmd6EUAbtgj+aBsY2xCGQwGc+yYU=;
        b=ml9gBEInJ8d/iUUvP5IFZQar6m+pnrUWcIo1+jhaBUEBiLelGblNd3WVbwUX5g0Qe3
         dM3m3dlXj4iMcYvAETeV+4huRoxv/MJz0PPZN5ozYOZPcCV75cS5FgU1Yv2XJDvvFO6Y
         2JngEhwL+2QHqT1A2iYR0aAvePDxhDkJGEdOxTr4Nokqsk2I0zred217KZEO/8ciZyUb
         RMuIVEsDD+h2FKvh8/3m6vvTzbKlGWDonDhqh4ViTzR9xmdxuhD5s64SBpOhTMPruPfy
         XM+f8aMCTd3nQNQnJE5A3G9iNg4JtDQ6ekiROBzFbA2aYUjzEAVu93EcUWNy/1H7FMuJ
         jqPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=igRLuaTw;
       spf=pass (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KXVWjq+wPU2Omovqmd6EUAbtgj+aBsY2xCGQwGc+yYU=;
        b=c8CYnCo91yRk2SL/pAuJhg86+VZOKT4w29KcOsKAdvFSfVk3l7XKqzKRrcS5u69Ez2
         D9rsqCBchQNqqrQR4zWPnlbVOMBAzr741neJgpi9tWu2lhzEDfwJ8fT5Y9IbA6eH8Myz
         DEBolpcGaFUP183UvwRM2ben5SMfE4+SWswa4aR4ziiWlF0n/yBJPytc2jUgjoS3LM2N
         aal42YhGtxzbdsmY5sqo0VEtPEtJ92GizvIV9IYFR5Qc58o5m9ZLOu51DtatB54yMeDI
         KXJiv/7ojugLC3TQlEGgRHerhxwW0Z02QBV1lZBsCw61KNkIw2NXpMkV370Sfux8Kgm6
         aQ0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KXVWjq+wPU2Omovqmd6EUAbtgj+aBsY2xCGQwGc+yYU=;
        b=UQV2m41VhhMfbofAtUvu2z7PGUnIAxGQFRC9mnAXpb5/80pPoMgO3oJsFGXRF7c2/h
         VftlqKpNRm6SXclVzT7ChICMsAlLW8CTDZEVVa0ehLs75zW4yu+jh5TuEHvX7Cs4tQzm
         7FH7knQ3ZMbOJof6Svlm2/n1d5rpdcU8jR8tT8CK534wPHvwRFESwVTI/9lIAjgOo7Ad
         GPhUjQOgu83P0Nji9NxPsu+OJpdi8WDMctHnhWO422AlihBRyU8mc9MJTLN3kTw8ASsX
         TgvaLWEyKVfxMipuVu013TzXcRh6vcD/EF7kSf4qMc0hiBVG9V8m701R42E3cDhfSRSz
         /eRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq07VzGChMGXpsQp/f87bb8qgd5yPQDiW/r+xXW/AfaJSt95582
	2QpZxp2M+eMh4HjP7b9nvbE=
X-Google-Smtp-Source: AMrXdXt7QJeeuoQUC2UMF+IvIi4bYf1ZFehKTcFDQ1qLx1eaOy4g4gTw6eM1CzcJNr+RHndyBN0jHA==
X-Received: by 2002:a05:6808:23ce:b0:35b:f951:e42f with SMTP id bq14-20020a05680823ce00b0035bf951e42fmr84124oib.249.1671634812597;
        Wed, 21 Dec 2022 07:00:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a555:b0:143:1d71:23f2 with SMTP id
 p21-20020a056870a55500b001431d7123f2ls5593938oal.9.-pod-prod-gmail; Wed, 21
 Dec 2022 07:00:12 -0800 (PST)
X-Received: by 2002:a05:6870:6b9a:b0:137:3adf:c109 with SMTP id ms26-20020a0568706b9a00b001373adfc109mr928790oab.40.1671634812017;
        Wed, 21 Dec 2022 07:00:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671634812; cv=none;
        d=google.com; s=arc-20160816;
        b=SmNGqG22e1YgQnjNRRO7X+CbfGOrgjQRd2deWKAm9VskojlvIJBH+3AHXaVW893hRL
         P6ncjwsNdk4kQlPz09NwbJCteGlQ5RIVaKTI0+Xhhuglhj4P0vabaD2aZJaLMViyurXi
         6FauzuToZr8d0ay1hu4taz2ayzMZrSao/KpITIfKQoy3JilS77WWzRqT7PqwgVk7snB7
         3/uzb9FZcZRT9BLZruJsdNsN4L+unlLiW+66AJYRpqAQ0E4ZVYjQLSaemExPGrbhl8BT
         /VkK/xMKcvDFV3CDhojUm54zC8S77t+aJ9fwYeKSKyLEAiDldJsJ7HNnLHA+qAUGL+WR
         wayA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LTUmJA2oY+jUcFRppvNPYxp/0Lp+vuZzKLjZzjCKEH4=;
        b=PFvFC3SZUOcxz8ZmyhsMTv4hFAmR9SpbG3cAJJbptcDMZ+ryQzvk3vP5BwbO8MaBBt
         4FhCqi2EoZFCn/bm6ES2jYxrfByaUXEZCvdbc4iR/h0H8y+nRWXSnluYfpxMt9FDZjMj
         mjcrC9J6tsjxSpnE/DG6YPHDmTYx5Jd5ofMjUTZXMVYUhPIeagvwrtb19mJGQE3u/an6
         KvpKmz4PczeE9NoVnZ2+ErY+6UvE3Qk5AcX4YujFsOPvMDlePUgf1MB8Lv3qHx9h7+sQ
         OzYpbHCy2lME2DhZ0JHCrv52ZrL3klm2f5TbrFIbImjytEB6HEl9KD/WlIdK/YVHuweY
         lkQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=igRLuaTw;
       spf=pass (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id s3-20020a056870248300b00144a469b41dsi1783562oaq.4.2022.12.21.07.00.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Dec 2022 07:00:11 -0800 (PST)
Received-SPF: pass (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id C2A66617F3;
	Wed, 21 Dec 2022 15:00:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 638E9C433D2;
	Wed, 21 Dec 2022 15:00:08 +0000 (UTC)
Date: Wed, 21 Dec 2022 15:00:05 +0000
From: Conor Dooley <conor@kernel.org>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Subject: Re: [PATCH 4/6] riscv: Fix EFI stub usage of KASAN instrumented
 string functions
Message-ID: <Y6MfdfRhlWYBL2KH@spud>
References: <20221216162141.1701255-1-alexghiti@rivosinc.com>
 <20221216162141.1701255-5-alexghiti@rivosinc.com>
 <Y6MSxBaJU7JqfkJO@spud>
 <CAHVXubgzac0gXNF2FVeUrCAnOe7U9QhAfj3nWd_jc0maaepN2g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="YCPDz/kjihqgJ7An"
Content-Disposition: inline
In-Reply-To: <CAHVXubgzac0gXNF2FVeUrCAnOe7U9QhAfj3nWd_jc0maaepN2g@mail.gmail.com>
X-Original-Sender: conor@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=igRLuaTw;       spf=pass
 (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=conor@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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


--YCPDz/kjihqgJ7An
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Wed, Dec 21, 2022 at 03:23:36PM +0100, Alexandre Ghiti wrote:
> Hi Conor,
> 
> On Wed, Dec 21, 2022 at 3:06 PM Conor Dooley <conor@kernel.org> wrote:
> >
> > Hey Alex!
> >
> > On Fri, Dec 16, 2022 at 05:21:39PM +0100, Alexandre Ghiti wrote:
> > > The EFI stub must not use any KASAN instrumented code as the kernel
> > > proper did not initialize the thread pointer and the mapping for the
> > > KASAN shadow region.
> > >
> > > Avoid using generic string functions by copying stub dependencies from
> > > lib/string.c to drivers/firmware/efi/libstub/string.c as RISC-V does
> > > not implement architecture-specific versions of those functions.
> >
> > To the unaware among us, how does this interact with Heiko's custom
> > functions for bitmanip extensions? Is this diametrically opposed to
> > that, or does it actually help avoid having to have special handling
> > for the efi stub?
> 
> I'm not sure which patchset you are referring to, but I guess you are
> talking about arch-specific string functions:

Oh sorry, I thought I had linked it..
https://lore.kernel.org/linux-riscv/20221130225614.1594256-1-heiko@sntech.de/

> - If they are written in assembly and are then not kasan-instrumented,
> we'll be able to use them and then revert part of this patch.

They are indeed written in assembly. Ard had left some comments there.
Heiko's intention was to keep them out of the efistub, so perhaps your
patchset helps him out.

> - If they are written in C and are then kasan-instrumented (because
> we'll want to instrument them), we'll keep using the implementation
> added here.
> 
> Hope that answers your question!
> 
> Alex
> 
> >
> > Also, checkpatch seems to be rather unhappy with you here:
> > https://gist.github.com/conor-pwbot/e5b4c8f2c3b88b4a8fcab4df437613e2
> 
> Yes, those new functions are exact copies from lib/string.c, I did not
> want to fix those checkpatch errors in this patchset.

I figured from the description that that was likely, just mentioned it
as I was already replying! Apologies for not looking at the source of
the copy.

Thanks!

> > >
> > > Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
> > > ---
> > >  arch/riscv/kernel/image-vars.h        |   8 --
> > >  drivers/firmware/efi/libstub/Makefile |   7 +-
> > >  drivers/firmware/efi/libstub/string.c | 133 ++++++++++++++++++++++++++
> > >  3 files changed, 137 insertions(+), 11 deletions(-)
> > >
> > > diff --git a/arch/riscv/kernel/image-vars.h b/arch/riscv/kernel/image-vars.h
> > > index d6e5f739905e..15616155008c 100644
> > > --- a/arch/riscv/kernel/image-vars.h
> > > +++ b/arch/riscv/kernel/image-vars.h
> > > @@ -23,14 +23,6 @@
> > >   * linked at. The routines below are all implemented in assembler in a
> > >   * position independent manner
> > >   */
> > > -__efistub_memcmp             = memcmp;
> > > -__efistub_memchr             = memchr;
> > > -__efistub_strlen             = strlen;
> > > -__efistub_strnlen            = strnlen;
> > > -__efistub_strcmp             = strcmp;
> > > -__efistub_strncmp            = strncmp;
> > > -__efistub_strrchr            = strrchr;
> > > -
> > >  __efistub__start             = _start;
> > >  __efistub__start_kernel              = _start_kernel;
> > >  __efistub__end                       = _end;
> > > diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
> > > index b1601aad7e1a..031d2268bab5 100644
> > > --- a/drivers/firmware/efi/libstub/Makefile
> > > +++ b/drivers/firmware/efi/libstub/Makefile
> > > @@ -130,9 +130,10 @@ STUBCOPY_RELOC-$(CONFIG_ARM)     := R_ARM_ABS
> > >  # also means that we need to be extra careful to make sure that the stub does
> > >  # not rely on any absolute symbol references, considering that the virtual
> > >  # kernel mapping that the linker uses is not active yet when the stub is
> > > -# executing. So build all C dependencies of the EFI stub into libstub, and do
> > > -# a verification pass to see if any absolute relocations exist in any of the
> > > -# object files.
> > > +# executing. In addition, we need to make sure that the stub does not use KASAN
> > > +# instrumented code like the generic string functions. So build all C
> > > +# dependencies of the EFI stub into libstub, and do a verification pass to see
> > > +# if any absolute relocations exist in any of the object files.
> > >  #
> > >  STUBCOPY_FLAGS-$(CONFIG_ARM64)       += --prefix-alloc-sections=.init \
> > >                                  --prefix-symbols=__efistub_
> > > diff --git a/drivers/firmware/efi/libstub/string.c b/drivers/firmware/efi/libstub/string.c
> > > index 5d13e43869ee..5154ae6e7f10 100644
> > > --- a/drivers/firmware/efi/libstub/string.c
> > > +++ b/drivers/firmware/efi/libstub/string.c
> > > @@ -113,3 +113,136 @@ long simple_strtol(const char *cp, char **endp, unsigned int base)
> > >
> > >       return simple_strtoull(cp, endp, base);
> > >  }
> > > +
> > > +#ifndef __HAVE_ARCH_STRLEN
> > > +/**
> > > + * strlen - Find the length of a string
> > > + * @s: The string to be sized
> > > + */
> > > +size_t strlen(const char *s)
> > > +{
> > > +     const char *sc;
> > > +
> > > +     for (sc = s; *sc != '\0'; ++sc)
> > > +             /* nothing */;
> > > +     return sc - s;
> > > +}
> > > +EXPORT_SYMBOL(strlen);
> > > +#endif
> > > +
> > > +#ifndef __HAVE_ARCH_STRNLEN
> > > +/**
> > > + * strnlen - Find the length of a length-limited string
> > > + * @s: The string to be sized
> > > + * @count: The maximum number of bytes to search
> > > + */
> > > +size_t strnlen(const char *s, size_t count)
> > > +{
> > > +     const char *sc;
> > > +
> > > +     for (sc = s; count-- && *sc != '\0'; ++sc)
> > > +             /* nothing */;
> > > +     return sc - s;
> > > +}
> > > +EXPORT_SYMBOL(strnlen);
> > > +#endif
> > > +
> > > +#ifndef __HAVE_ARCH_STRCMP
> > > +/**
> > > + * strcmp - Compare two strings
> > > + * @cs: One string
> > > + * @ct: Another string
> > > + */
> > > +int strcmp(const char *cs, const char *ct)
> > > +{
> > > +     unsigned char c1, c2;
> > > +
> > > +     while (1) {
> > > +             c1 = *cs++;
> > > +             c2 = *ct++;
> > > +             if (c1 != c2)
> > > +                     return c1 < c2 ? -1 : 1;
> > > +             if (!c1)
> > > +                     break;
> > > +     }
> > > +     return 0;
> > > +}
> > > +EXPORT_SYMBOL(strcmp);
> > > +#endif
> > > +
> > > +#ifndef __HAVE_ARCH_STRRCHR
> > > +/**
> > > + * strrchr - Find the last occurrence of a character in a string
> > > + * @s: The string to be searched
> > > + * @c: The character to search for
> > > + */
> > > +char *strrchr(const char *s, int c)
> > > +{
> > > +     const char *last = NULL;
> > > +     do {
> > > +             if (*s == (char)c)
> > > +                     last = s;
> > > +     } while (*s++);
> > > +     return (char *)last;
> > > +}
> > > +EXPORT_SYMBOL(strrchr);
> > > +#endif
> > > +
> > > +#ifndef __HAVE_ARCH_MEMCMP
> > > +/**
> > > + * memcmp - Compare two areas of memory
> > > + * @cs: One area of memory
> > > + * @ct: Another area of memory
> > > + * @count: The size of the area.
> > > + */
> > > +#undef memcmp
> > > +__visible int memcmp(const void *cs, const void *ct, size_t count)
> > > +{
> > > +     const unsigned char *su1, *su2;
> > > +     int res = 0;
> > > +
> > > +#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
> > > +     if (count >= sizeof(unsigned long)) {
> > > +             const unsigned long *u1 = cs;
> > > +             const unsigned long *u2 = ct;
> > > +             do {
> > > +                     if (get_unaligned(u1) != get_unaligned(u2))
> > > +                             break;
> > > +                     u1++;
> > > +                     u2++;
> > > +                     count -= sizeof(unsigned long);
> > > +             } while (count >= sizeof(unsigned long));
> > > +             cs = u1;
> > > +             ct = u2;
> > > +     }
> > > +#endif
> > > +     for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
> > > +             if ((res = *su1 - *su2) != 0)
> > > +                     break;
> > > +     return res;
> > > +}
> > > +EXPORT_SYMBOL(memcmp);
> > > +#endif
> > > +
> > > +#ifndef __HAVE_ARCH_MEMCHR
> > > +/**
> > > + * memchr - Find a character in an area of memory.
> > > + * @s: The memory area
> > > + * @c: The byte to search for
> > > + * @n: The size of the area.
> > > + *
> > > + * returns the address of the first occurrence of @c, or %NULL
> > > + * if @c is not found
> > > + */
> > > +void *memchr(const void *s, int c, size_t n)
> > > +{
> > > +     const unsigned char *p = s;
> > > +     while (n-- != 0) {
> > > +             if ((unsigned char)c == *p++) {
> > > +                     return (void *)(p - 1);
> > > +             }
> > > +     }
> > > +     return NULL;
> > > +}
> > > +EXPORT_SYMBOL(memchr);
> > > +#endif
> > > --
> > > 2.37.2
> > >
> > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y6MfdfRhlWYBL2KH%40spud.

--YCPDz/kjihqgJ7An
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYIAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCY6MfdQAKCRB4tDGHoIJi
0rD1AQCqrDhav6hfY0d+Zxo7d411z36snzEbHw/G2g8zY1b+aQEA5L8T8mE5iRl3
Ov5E1pIIrfvvmg4vRhlfFTAQXS7AkQs=
=gSFB
-----END PGP SIGNATURE-----

--YCPDz/kjihqgJ7An--
