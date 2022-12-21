Return-Path: <kasan-dev+bncBDXY7I6V6AMRB5FNRSOQMGQEQETXXMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id D09B665325B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Dec 2022 15:23:48 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id m38-20020a05600c3b2600b003d1fc5f1f80sf1012079wms.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Dec 2022 06:23:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671632628; cv=pass;
        d=google.com; s=arc-20160816;
        b=hcOjSj3XuALdc/YSPmCw5iXHA+uvtLB47nBeDDNnYXq5Vp1WXZnXXBPQKwVwcc3CcF
         cihnBWF2jmyh289hgJ8Mx+PUBfTULoOv0tIUv+gIAkIo2NcVYk6lOAd9zJeptsF5XHKS
         OiW+BxWaT8gJVP7zg14Gz/Tm9saL+eMhr6Puw2xao3Kmr/jyDMCYhmCsf7ijsZ0q7Evi
         fKmPpXHjji2cFmsAeMCbsnrbtooKAUMLMUrZdOeuAbJGAKKvSQBSjWK680Xpww+sEgV6
         wTqBNBWwlfkv38W9VX3S1bVo174XMvkaqHGIu3zZvlFQbHP2x01PwCmX7QXGloV0g2sw
         R6Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=baD8hx6mkcIr5JfMCoulOQqGOIg1GmWCNfzHJR7LRC8=;
        b=VVrLEHgo8WQsIw9KHvsUtAkxxxr/62GfBbbsgACQGPhuNgU8BHeLlI35vsgEylD08i
         k82Z3I+RH80X8bcCfWE7Avh/VQi5EXEuUI91lHc/AU1ndv9cHUcS1+3212gEn2LSTh/h
         jKYdxPLAmj1LM9sZZdCZRfwQJ5sjbZrNxVZqXR0NQRCRr0ReqKMbRVyxkWHsxM8nqSaO
         FizpMALe48fs5mL/t0JIc99x0StFo3BorTt5zkU4k9Yl9MDlQI63e6hoi/J1IokWC7dR
         JzE77YsD64N8hOKBgSCZBKH6ol7Qtf5RnDJBuohjd7gq2H0FOQTOkey9FxFzbPQ9hlb7
         K7vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=Rdsoz3up;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=baD8hx6mkcIr5JfMCoulOQqGOIg1GmWCNfzHJR7LRC8=;
        b=HPhatRJhUGmF+t03JSu92uZCaDw6zSE6YWmuGP4Jzsf0FTMz3UcAF5bws6aPUwKnaL
         dsR2NWSN4uYzuaMjA2amwsxLdcm9GvyFqbCWp9pcFhgsaeBAW8Pgdr4oyyDw0wK6dFDF
         U2JQcDG44tQhAfQbDMS0xb7N9ObT8d0vKLh6nwBx5Il2dvxwAtjYXLT0GLK5ZS9c4TQs
         AA7dWzHzD62ymvGe2JOH1bGdi5miGwfpMwZbdjkYtEea6+pamAuzhxeg5dOlWLWxzRcg
         QvFs4FM8SiQ3zCD47jbrOXN28eV7Jf5zfGCvr1Pr4y6vxnaPEa42ZK4LfFqUaZ+I3lLE
         xu2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=baD8hx6mkcIr5JfMCoulOQqGOIg1GmWCNfzHJR7LRC8=;
        b=r4HtkvRvXlmCbXvv8bu62hk9PIZOopLjunX3PRBzIE6eQopZe8TyMF/bl5k6oJ5prr
         laCeLVUw8xeaLbmBKnCNABKfVC0uQVmm9134P5o+tpTn4vVcZj3PzBL5s5KSARg+stC+
         cO2ffPJfI6gIa9X3LLafqHyDx0pmPE3ZaOgZqOjhOKglc4H7jz4zKwVDwHznIz4kGC6B
         FwaHqidI7PLgrV7nSDYkqEBsNOz2PqIN7OcdLtiOsadzZkrn4NjZmz5eMNlMP21kuLYt
         SYu8nAjNbAJlH08VUAVgjJJ+OTGCF2v6kVY+EsTeL53jZkEZMF9CpBR3X30O2vFSyacP
         0M6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krg3orpXR30jmPlHDpRow0sF6c/bUCpm+frfotlANKyE3F0HBD9
	xpyZ3cuY6mx/2L46tJIbnwk=
X-Google-Smtp-Source: AMrXdXvfP9CyCq/HkTOd0iZLpyk4MwYUq5xL9W5FgSSnO7rHl//A0Ic92JVnHj7Y8sVLh4+Lxy8lFw==
X-Received: by 2002:a5d:428b:0:b0:250:777b:da9e with SMTP id k11-20020a5d428b000000b00250777bda9emr74105wrq.495.1671632628211;
        Wed, 21 Dec 2022 06:23:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce11:0:b0:3cf:afd2:ab84 with SMTP id m17-20020a7bce11000000b003cfafd2ab84ls1170922wmc.2.-pod-control-gmail;
 Wed, 21 Dec 2022 06:23:47 -0800 (PST)
X-Received: by 2002:a05:600c:4e48:b0:3cf:5d41:b748 with SMTP id e8-20020a05600c4e4800b003cf5d41b748mr4553588wmq.36.1671632627215;
        Wed, 21 Dec 2022 06:23:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671632627; cv=none;
        d=google.com; s=arc-20160816;
        b=MztvGlV7T0PMsG80yofHUkOwuxMHQleLiHQaI5lUAQHngLuj8dRjJP5PKYNEyFfWkc
         R9bYt4x+8y4HESRqGIZILWaEC3o31YmsnOQJKf9Gy4KrATHG5kJ6saPu7vwhr+t86eeD
         NubcbG0T70tZgjZqDUCR6MkiaQZakOvs3FOnLppRSXHL6olZtg/DlX773PqIE8wVtXSA
         fEa2T/e6Eyk8B9w9ubo7RoECpZaYqEMWoJVebgyI7wmbQG6ArQ7G8DOr3INLORQOprJl
         jlBy1EYOLGvQeIpx/4x+0IjKUGaK2acxjMZgHvo2IDwetDSdJqBisf2y6XLNnxO3wj+x
         SAWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pHd3rehtJfdxGw9liVvNFHcBIni6Z85SwwxIj+0xI2s=;
        b=hXXl8ygnfsqfd6PmaaFFRX1v2o8YlPnWons2MCfSSjpFKDm53CctKKLeJErXv2OaaJ
         AHmGvLt2H42aG1V3kITxaEUjoaZ8C43I5eksTwtXOW0ZJ1orII/yFI3sPLbQXw5D5gvC
         Z578jvcO+lfnfFd3UQjKGKVyBsBNm+HYrF/NU/0gGnOBosL5i4lAoeFgUbahBOslMr7x
         89OpdMI95RXqc40Y1z0FdyEuRRpTUY3wP5NXdj8UJbXHy2TcohhTBvVp+cw9oiboARrt
         e5wnxCXNXl5sCGn/qqnWTF1wdMpgMr3v+/LmLMwKOwaIZAu5tiDs31VdrtBNCXEGo0zO
         QNnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=Rdsoz3up;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id c3-20020a7bc843000000b003c4ecff4e2bsi111735wml.1.2022.12.21.06.23.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Dec 2022 06:23:47 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id p13-20020a05600c468d00b003cf8859ed1bso1568231wmo.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Dec 2022 06:23:47 -0800 (PST)
X-Received: by 2002:a05:600c:3d16:b0:3cf:a80d:59cd with SMTP id
 bh22-20020a05600c3d1600b003cfa80d59cdmr137973wmb.5.1671632626854; Wed, 21 Dec
 2022 06:23:46 -0800 (PST)
MIME-Version: 1.0
References: <20221216162141.1701255-1-alexghiti@rivosinc.com>
 <20221216162141.1701255-5-alexghiti@rivosinc.com> <Y6MSxBaJU7JqfkJO@spud>
In-Reply-To: <Y6MSxBaJU7JqfkJO@spud>
From: Alexandre Ghiti <alexghiti@rivosinc.com>
Date: Wed, 21 Dec 2022 15:23:36 +0100
Message-ID: <CAHVXubgzac0gXNF2FVeUrCAnOe7U9QhAfj3nWd_jc0maaepN2g@mail.gmail.com>
Subject: Re: [PATCH 4/6] riscv: Fix EFI stub usage of KASAN instrumented
 string functions
To: Conor Dooley <conor@kernel.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Ard Biesheuvel <ardb@kernel.org>, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-efi@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=Rdsoz3up;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Hi Conor,

On Wed, Dec 21, 2022 at 3:06 PM Conor Dooley <conor@kernel.org> wrote:
>
> Hey Alex!
>
> On Fri, Dec 16, 2022 at 05:21:39PM +0100, Alexandre Ghiti wrote:
> > The EFI stub must not use any KASAN instrumented code as the kernel
> > proper did not initialize the thread pointer and the mapping for the
> > KASAN shadow region.
> >
> > Avoid using generic string functions by copying stub dependencies from
> > lib/string.c to drivers/firmware/efi/libstub/string.c as RISC-V does
> > not implement architecture-specific versions of those functions.
>
> To the unaware among us, how does this interact with Heiko's custom
> functions for bitmanip extensions? Is this diametrically opposed to
> that, or does it actually help avoid having to have special handling
> for the efi stub?

I'm not sure which patchset you are referring to, but I guess you are
talking about arch-specific string functions:

- If they are written in assembly and are then not kasan-instrumented,
we'll be able to use them and then revert part of this patch.
- If they are written in C and are then kasan-instrumented (because
we'll want to instrument them), we'll keep using the implementation
added here.

Hope that answers your question!

Alex

>
> Also, checkpatch seems to be rather unhappy with you here:
> https://gist.github.com/conor-pwbot/e5b4c8f2c3b88b4a8fcab4df437613e2

Yes, those new functions are exact copies from lib/string.c, I did not
want to fix those checkpatch errors in this patchset.

>
> Thanks,
> Conor.
>
> >
> > Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
> > ---
> >  arch/riscv/kernel/image-vars.h        |   8 --
> >  drivers/firmware/efi/libstub/Makefile |   7 +-
> >  drivers/firmware/efi/libstub/string.c | 133 ++++++++++++++++++++++++++
> >  3 files changed, 137 insertions(+), 11 deletions(-)
> >
> > diff --git a/arch/riscv/kernel/image-vars.h b/arch/riscv/kernel/image-vars.h
> > index d6e5f739905e..15616155008c 100644
> > --- a/arch/riscv/kernel/image-vars.h
> > +++ b/arch/riscv/kernel/image-vars.h
> > @@ -23,14 +23,6 @@
> >   * linked at. The routines below are all implemented in assembler in a
> >   * position independent manner
> >   */
> > -__efistub_memcmp             = memcmp;
> > -__efistub_memchr             = memchr;
> > -__efistub_strlen             = strlen;
> > -__efistub_strnlen            = strnlen;
> > -__efistub_strcmp             = strcmp;
> > -__efistub_strncmp            = strncmp;
> > -__efistub_strrchr            = strrchr;
> > -
> >  __efistub__start             = _start;
> >  __efistub__start_kernel              = _start_kernel;
> >  __efistub__end                       = _end;
> > diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
> > index b1601aad7e1a..031d2268bab5 100644
> > --- a/drivers/firmware/efi/libstub/Makefile
> > +++ b/drivers/firmware/efi/libstub/Makefile
> > @@ -130,9 +130,10 @@ STUBCOPY_RELOC-$(CONFIG_ARM)     := R_ARM_ABS
> >  # also means that we need to be extra careful to make sure that the stub does
> >  # not rely on any absolute symbol references, considering that the virtual
> >  # kernel mapping that the linker uses is not active yet when the stub is
> > -# executing. So build all C dependencies of the EFI stub into libstub, and do
> > -# a verification pass to see if any absolute relocations exist in any of the
> > -# object files.
> > +# executing. In addition, we need to make sure that the stub does not use KASAN
> > +# instrumented code like the generic string functions. So build all C
> > +# dependencies of the EFI stub into libstub, and do a verification pass to see
> > +# if any absolute relocations exist in any of the object files.
> >  #
> >  STUBCOPY_FLAGS-$(CONFIG_ARM64)       += --prefix-alloc-sections=.init \
> >                                  --prefix-symbols=__efistub_
> > diff --git a/drivers/firmware/efi/libstub/string.c b/drivers/firmware/efi/libstub/string.c
> > index 5d13e43869ee..5154ae6e7f10 100644
> > --- a/drivers/firmware/efi/libstub/string.c
> > +++ b/drivers/firmware/efi/libstub/string.c
> > @@ -113,3 +113,136 @@ long simple_strtol(const char *cp, char **endp, unsigned int base)
> >
> >       return simple_strtoull(cp, endp, base);
> >  }
> > +
> > +#ifndef __HAVE_ARCH_STRLEN
> > +/**
> > + * strlen - Find the length of a string
> > + * @s: The string to be sized
> > + */
> > +size_t strlen(const char *s)
> > +{
> > +     const char *sc;
> > +
> > +     for (sc = s; *sc != '\0'; ++sc)
> > +             /* nothing */;
> > +     return sc - s;
> > +}
> > +EXPORT_SYMBOL(strlen);
> > +#endif
> > +
> > +#ifndef __HAVE_ARCH_STRNLEN
> > +/**
> > + * strnlen - Find the length of a length-limited string
> > + * @s: The string to be sized
> > + * @count: The maximum number of bytes to search
> > + */
> > +size_t strnlen(const char *s, size_t count)
> > +{
> > +     const char *sc;
> > +
> > +     for (sc = s; count-- && *sc != '\0'; ++sc)
> > +             /* nothing */;
> > +     return sc - s;
> > +}
> > +EXPORT_SYMBOL(strnlen);
> > +#endif
> > +
> > +#ifndef __HAVE_ARCH_STRCMP
> > +/**
> > + * strcmp - Compare two strings
> > + * @cs: One string
> > + * @ct: Another string
> > + */
> > +int strcmp(const char *cs, const char *ct)
> > +{
> > +     unsigned char c1, c2;
> > +
> > +     while (1) {
> > +             c1 = *cs++;
> > +             c2 = *ct++;
> > +             if (c1 != c2)
> > +                     return c1 < c2 ? -1 : 1;
> > +             if (!c1)
> > +                     break;
> > +     }
> > +     return 0;
> > +}
> > +EXPORT_SYMBOL(strcmp);
> > +#endif
> > +
> > +#ifndef __HAVE_ARCH_STRRCHR
> > +/**
> > + * strrchr - Find the last occurrence of a character in a string
> > + * @s: The string to be searched
> > + * @c: The character to search for
> > + */
> > +char *strrchr(const char *s, int c)
> > +{
> > +     const char *last = NULL;
> > +     do {
> > +             if (*s == (char)c)
> > +                     last = s;
> > +     } while (*s++);
> > +     return (char *)last;
> > +}
> > +EXPORT_SYMBOL(strrchr);
> > +#endif
> > +
> > +#ifndef __HAVE_ARCH_MEMCMP
> > +/**
> > + * memcmp - Compare two areas of memory
> > + * @cs: One area of memory
> > + * @ct: Another area of memory
> > + * @count: The size of the area.
> > + */
> > +#undef memcmp
> > +__visible int memcmp(const void *cs, const void *ct, size_t count)
> > +{
> > +     const unsigned char *su1, *su2;
> > +     int res = 0;
> > +
> > +#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
> > +     if (count >= sizeof(unsigned long)) {
> > +             const unsigned long *u1 = cs;
> > +             const unsigned long *u2 = ct;
> > +             do {
> > +                     if (get_unaligned(u1) != get_unaligned(u2))
> > +                             break;
> > +                     u1++;
> > +                     u2++;
> > +                     count -= sizeof(unsigned long);
> > +             } while (count >= sizeof(unsigned long));
> > +             cs = u1;
> > +             ct = u2;
> > +     }
> > +#endif
> > +     for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
> > +             if ((res = *su1 - *su2) != 0)
> > +                     break;
> > +     return res;
> > +}
> > +EXPORT_SYMBOL(memcmp);
> > +#endif
> > +
> > +#ifndef __HAVE_ARCH_MEMCHR
> > +/**
> > + * memchr - Find a character in an area of memory.
> > + * @s: The memory area
> > + * @c: The byte to search for
> > + * @n: The size of the area.
> > + *
> > + * returns the address of the first occurrence of @c, or %NULL
> > + * if @c is not found
> > + */
> > +void *memchr(const void *s, int c, size_t n)
> > +{
> > +     const unsigned char *p = s;
> > +     while (n-- != 0) {
> > +             if ((unsigned char)c == *p++) {
> > +                     return (void *)(p - 1);
> > +             }
> > +     }
> > +     return NULL;
> > +}
> > +EXPORT_SYMBOL(memchr);
> > +#endif
> > --
> > 2.37.2
> >
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHVXubgzac0gXNF2FVeUrCAnOe7U9QhAfj3nWd_jc0maaepN2g%40mail.gmail.com.
