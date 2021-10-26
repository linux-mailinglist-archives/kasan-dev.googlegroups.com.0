Return-Path: <kasan-dev+bncBCMIZB7QWENRBN4R32FQMGQE5HR3R5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 644E543AB75
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Oct 2021 06:48:56 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id s20-20020a05620a0bd400b0045e893f2ed8sf10598857qki.11
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Oct 2021 21:48:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635223735; cv=pass;
        d=google.com; s=arc-20160816;
        b=gh+M9ixbLzd+U1Z62HCuSg+sTIDjSl0ziL41uV3uz/7C4IfHhzOvJJ8SLzuv5S4Qw3
         iVZa1c2HojvWXY6ukQxtQ/2MR6gcfTaje9LkBzQmqYTwFR5Xyk2Pd1cvgWeJvAiZgRwR
         QgNeLPbn1j7t9CB19jZKRcgPkixRuCZryylXnH814RqSzmhqrgQQRGrbZKKiuRddxT1B
         8lc6B/bF43zmDEQ8/4zDWrFygmW2T7qIbbGNZtax+kfBRHWxLVl7BkuMwa1MXMRUXayw
         pHuOrApXydqili8xXNP/xcBrk23FZJn8TWGkO4F2euuNkuiCb/SkuluEcQXUf01jaJNO
         geFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2Wxd98bfFUnltf02tDNo0PNN/jm8ZyOSru4uW93o/AM=;
        b=xLIEYuGcbqqBOoKj+ZwAQRCad47aHHOthWMJ1E17iZDT3R2HuhTo7MMwsEtaPLtd94
         z0Hvp5Kq4SRMe/HHfGPfVLP1IptPeQs5mjVUWf0FwCIRb6RYQE8hCVE9l3b8kJyCR89y
         EX8XiS79trfcbRznVr30yz2Hi0haZycsvTzq+YmjsMyU6fu7ddK+lprlP3LG6yiFGD1r
         6ODHJfdE8cMARwLWj039gT8SASFG6j2KWxvzwH9dZOki1kSSKBKgsdfcfPfKEIUxZL8l
         5yHuR5oKuwRtJtHGBGfdbt0201YEbn5tTOYahPmbSkY/ugHVrYRTT0gMMvXDJUz3yELe
         rfiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=T8WI27PG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2Wxd98bfFUnltf02tDNo0PNN/jm8ZyOSru4uW93o/AM=;
        b=dvb/P0OCM1T5955Y8kMCl+Hhwrcsqroh2zK5+3QjnxJBaSqjK4vGBWaRPOSLywwkjX
         cKqCrqZGRzQVQaKqPds+QkXA5D0mw89RXTs1XsAhu6zSh0oyQJaRkyqtm50p/nYYRU9F
         Sl4kbT/pdyxApDoDeuuCbqtxT2XXpdiLM+AzkM45DL0um0EZX24PJDBdv5/QX243O2Qr
         seasiDFjbBkbDYq9wr+1EUTSjjxwF1OC4eFUMX8J+3Yt2VpqEjBxLfly15q60R1KqAfF
         UGHepOQ1+TG5cpgOEF+yJlQUfAX97Ax/uD/MHdNEJ//8Jne0kmwTJd+x8y3X8E2g/Qsa
         fsyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2Wxd98bfFUnltf02tDNo0PNN/jm8ZyOSru4uW93o/AM=;
        b=TyRI0Z2j43dV8fbeQl0WEZsMCk2eqXKUdYtt0qbwQh67dXOY7vji3dmrL457ds6u9O
         e6pXlmg6cOcpwLCdjxZ6O5E7qnU9BTyY8yPymLnlbbmf/wHfQTMGRXq8/BGQp2QJZsOt
         qB1N8NVqj/aIqtVWSkJHyj5qQPejAanKPyEOgJChvs0CkPex1iqETSwW4DcF52wzC0X7
         ycGrVvEK6KfgQcm35WVwJaNDrFgX6sv8vTNG6U0mVov1ernY4JHIzCvMTjqHnSlGsO3r
         iB3gR2d/eQ4DEp4zScNvsDgm2e1YvX6KIegXdwnI0SZ6FW5U/62KLiVEnhWlJ3qqu0Gs
         w3fA==
X-Gm-Message-State: AOAM532fV6El9RVB9ydh1jabdbAvvWvo/wfooQ55pdHN6tRyp8gSTOFJ
	Uh3aoHw1T7Qg2mg04zSaXHo=
X-Google-Smtp-Source: ABdhPJyu3OGMaOgSXVr/8fdUBqmQ8tQhqiIdEoWbIsZDQS89y6lQmexwPkKT9M+C5TJr7+p5P/bNEw==
X-Received: by 2002:ac8:615c:: with SMTP id d28mr21210397qtm.103.1635223735365;
        Mon, 25 Oct 2021 21:48:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4692:: with SMTP id bq18ls7302661qkb.0.gmail; Mon,
 25 Oct 2021 21:48:55 -0700 (PDT)
X-Received: by 2002:a37:4152:: with SMTP id o79mr17213718qka.169.1635223734939;
        Mon, 25 Oct 2021 21:48:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635223734; cv=none;
        d=google.com; s=arc-20160816;
        b=Jcf3qmEC6AL3O9jbWTq/b6IuwDv3LZN+LEgNzg4NQtjQqSaBTOzV/1e44QxkD39njK
         ABuSKoO4ntoHLGgxRUsu+YazdA1UIFbVDpWc9ivTczoMOuAVNh6UErcqdsaPIbhvQJxp
         QPh2JcL7o+kZMyHaVliPZ5s0jWDYy4iAsX5ESRRuek2su3i2944G4h7/5ufNBUdWI1nk
         sTD1OElnFJZy7r5E2iEM7dm2IItaUo7jmwGOYvg/p8XA/55CZfvGEQr0yDQPoDwLgcnz
         6WuHnCCRwKIdpBKZ8KkpXwbwj4N+pQQtDu935StXkObYt7d6ivGdgs4LkQ5VILv1vJK1
         XHyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QUu57E+IbafflI6/qVuHyQy7kRwajg1mknD459Ucq7I=;
        b=zpsv7F70YGrOeixMGrqeeR0EOAayraV8uUkKuw2npk6u2BdPXSqO/1HUbkwbxlNeuX
         6Yy7J2fsnf6QjdCZq90RibDfSOCkLgPOebkCiQsM+VJznRcLoFVNtlERe1KTtnshNbDT
         0mVDC6DMfBsM8bo6eeZde2A6KUV1mvFK8utM4V7Dv5R3wnOQiD17jeTFAucCHe7ZjhVd
         uL4VF9/uBqyUwmif9dQ06bM03bFp5hWwPGaJ5G2KJxAI+j0+bvL0PSX+HsHVzZNwNsmL
         UC2IgOyT2eyn3IsLJN9l1oBLKesK+T+upOxlN7oeEObmNMMND8pid69kkobld6VCcHBb
         6Dog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=T8WI27PG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id s15si343456qkp.3.2021.10.25.21.48.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Oct 2021 21:48:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id q124so74230oig.3
        for <kasan-dev@googlegroups.com>; Mon, 25 Oct 2021 21:48:54 -0700 (PDT)
X-Received: by 2002:a05:6808:ec9:: with SMTP id q9mr25537738oiv.160.1635223734188;
 Mon, 25 Oct 2021 21:48:54 -0700 (PDT)
MIME-Version: 1.0
References: <YUyWYpDl2Dmegz0a@archlinux-ax161> <mhng-b5f8a6a0-c3e8-4d25-9daa-346fdc8a2e5e@palmerdabbelt-glaptop>
 <YWhg8/UzjJsB51Gd@archlinux-ax161> <afeaea5f-70f2-330f-f032-fb0c8b5d0aa5@ghiti.fr>
 <990a894c-1806-5ab2-775e-a6f2355c2299@ghiti.fr> <CA+zEjCt28iYQARQa=8Nsw8+_j0PuEee==gUqjKjasMo+w2Ohwg@mail.gmail.com>
In-Reply-To: <CA+zEjCt28iYQARQa=8Nsw8+_j0PuEee==gUqjKjasMo+w2Ohwg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Oct 2021 06:48:42 +0200
Message-ID: <CACT4Y+YB8bjqxFfSrXKbfETXJAUxH=HR+kizC0T-AZLArY3A5A@mail.gmail.com>
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Alexandre ghiti <alex@ghiti.fr>, Nathan Chancellor <nathan@kernel.org>, 
	Palmer Dabbelt <palmer@dabbelt.com>, elver@google.com, akpm@linux-foundation.org, 
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	ndesaulniers@google.com, Arnd Bergmann <arnd@arndb.de>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	linux-riscv@lists.infradead.org, Paul Walmsley <paul.walmsley@sifive.com>, 
	aou@eecs.berkeley.edu, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=T8WI27PG;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::231
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 26 Oct 2021 at 06:39, Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> Hi,
>
> On Fri, Oct 15, 2021 at 3:08 PM Alexandre ghiti <alex@ghiti.fr> wrote:
> >
> > On 10/14/21 8:31 PM, Alex Ghiti wrote:
> > > Hi Nathan,
> > >
> > > Le 14/10/2021 =C3=A0 18:55, Nathan Chancellor a =C3=A9crit :
> > >> On Fri, Oct 08, 2021 at 11:46:55AM -0700, Palmer Dabbelt wrote:
> > >>> On Thu, 23 Sep 2021 07:59:46 PDT (-0700), nathan@kernel.org wrote:
> > >>>> On Thu, Sep 23, 2021 at 12:07:17PM +0200, Marco Elver wrote:
> > >>>>> On Wed, 22 Sept 2021 at 22:55, Nathan Chancellor
> > >>>>> <nathan@kernel.org> wrote:
> > >>>>>> Currently, the asan-stack parameter is only passed along if
> > >>>>>> CFLAGS_KASAN_SHADOW is not empty, which requires
> > >>>>>> KASAN_SHADOW_OFFSET to
> > >>>>>> be defined in Kconfig so that the value can be checked. In RISC-=
V's
> > >>>>>> case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means
> > >>>>>> that
> > >>>>>> asan-stack does not get disabled with clang even when
> > >>>>>> CONFIG_KASAN_STACK
> > >>>>>> is disabled, resulting in large stack warnings with allmodconfig=
:
> > >>>>>>
> > >>>>>> drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q=
02.c:117:12:
> > >>>>>>
> > >>>>>> error: stack frame size (14400) exceeds limit (2048) in function
> > >>>>>> 'lb035q02_connect' [-Werror,-Wframe-larger-than]
> > >>>>>> static int lb035q02_connect(struct omap_dss_device *dssdev)
> > >>>>>>             ^
> > >>>>>> 1 error generated.
> > >>>>>>
> > >>>>>> Ensure that the value of CONFIG_KASAN_STACK is always passed
> > >>>>>> along to
> > >>>>>> the compiler so that these warnings do not happen when
> > >>>>>> CONFIG_KASAN_STACK is disabled.
> > >>>>>>
> > >>>>>> Link: https://github.com/ClangBuiltLinux/linux/issues/1453
> > >>>>>> References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-=
8
> > >>>>>> and earlier")
> > >>>>>> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> > >>>>>
> > >>>>> Reviewed-by: Marco Elver <elver@google.com>
> > >>>>
> > >>>> Thanks!
> > >>>>
> > >>>>> [ Which tree are you planning to take it through? ]
> > >>>>
> > >>>> Gah, I was intending for it to go through -mm, then I cc'd neither
> > >>>> Andrew nor linux-mm... :/ Andrew, do you want me to resend or can =
you
> > >>>> grab it from LKML?
> > >>>
> > >>> Acked-by: Palmer Dabbelt <palmerdabbelt@google.com>
> > >>>
> > >>> (assuming you still want it through somewhere else)
> > >>
> > >> Thanks, it is now in mainline as commit 19532869feb9 ("kasan: always
> > >> respect CONFIG_KASAN_STACK").
> > >>
> > >>>>> Note, arch/riscv/include/asm/kasan.h mentions KASAN_SHADOW_OFFSET=
 in
> > >>>>> comment (copied from arm64). Did RISC-V just forget to copy over =
the
> > >>>>> Kconfig option?
> > >>>>
> > >>>> I do see it defined in that file as well but you are right that
> > >>>> they did
> > >>>> not copy the Kconfig logic, even though it was present in the tree
> > >>>> when
> > >>>> RISC-V KASAN was implemented. Perhaps they should so that they get
> > >>>> access to the other flags in the "else" branch?
> > >>>
> > >>> Ya, looks like we just screwed this up.  I'm seeing some warnings l=
ike
> > >>>
> > >>>     cc1: warning: =E2=80=98-fsanitize=3Dkernel-address=E2=80=99 wit=
h stack protection
> > >>> is not supported without =E2=80=98-fasan-shadow-offset=3D=E2=80=99 =
for this target
> > >>
> > >> Hmmm, I thought I did a GCC build with this change but I must not ha=
ve
> > >> :/
> > >>
> > >>> which is how I ended up here, I'm assuming that's what you're
> > >>> talking about
> > >>> here?  LMK if you were planning on sending along a fix or if you
> > >>> want me to
> > >>> go figure it out.
> > >>
> > >> I took a look at moving the logic into Kconfig like arm64 before sen=
ding
> > >> this change and I did not really understand it well enough to do so.=
 I
> > >> think it would be best if you were able to do that so that nothing g=
ets
> > >> messed up.
> > >>
> > >
> > > I'll do it tomorrow, I'm the last one who touched kasan on riscv :)
> > >
> >
> > Adding KASAN_SHADOW_OFFSET config makes kasan kernel fails to boot.
> > It receives a *write* fault at the beginning of a memblock_alloc
> > function while populating the kernel shadow memory: the trap address is
> > in the kasan shadow virtual address range and this corresponds to a
> > kernel address in init_stack. The question is: how do I populate the
> > stack shadow mapping without using memblock API? It's weird, I don't
> > find anything on other architectures.
>
> @kasan: Any idea what we are doing wrong in riscv to encounter the
> above situation?

Hi Alex, Palmer,

The patch changes the definition of the KASAN_SHADOW_OFFSET const.
Does it's value change as a result or not? Have you tried to print it
before/after?
If value does not change, then this is more mysterious. If it changes,
then there lots of possible explanations (points to unmapped region,
overlaps with something), but we need to know values before/after to
answer this.


> Thanks,
>
> Alex
>
> >
> > And just a short note: I have realized this will break with the sv48
> > patchset as we decide at runtime the address space width and the kasan
> > shadow start address is different between sv39 and sv48. I will have to
> > do like x86 and move the kasan shadow start at the end of the address
> > space so that it is the same for both sv39 and sv48.
> >
> > Thanks,
> >
> > Alex
> >
> >
> > > Thanks,
> > >
> > > Alex
> > >
> > >> Cheers,
> > >> Nathan
> > >>
> > >> _______________________________________________
> > >> linux-riscv mailing list
> > >> linux-riscv@lists.infradead.org
> > >> http://lists.infradead.org/mailman/listinfo/linux-riscv
> > >>
> > >
> > > _______________________________________________
> > > linux-riscv mailing list
> > > linux-riscv@lists.infradead.org
> > > http://lists.infradead.org/mailman/listinfo/linux-riscv
> >
> > _______________________________________________
> > linux-riscv mailing list
> > linux-riscv@lists.infradead.org
> > http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYB8bjqxFfSrXKbfETXJAUxH%3DHR%2BkizC0T-AZLArY3A5A%40mail.=
gmail.com.
