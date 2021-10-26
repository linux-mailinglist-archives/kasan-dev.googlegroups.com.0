Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBE4N32FQMGQEYA6SGAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E916F43AB5B
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Oct 2021 06:39:47 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id g6-20020a0565123b8600b003ffa7685526sf2086756lfv.21
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Oct 2021 21:39:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635223187; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ia5GlNEuU4BuqPqbKOCV5l1xCnyYtv5wLvvpaWZ+5tiWGTHS0pfZMn+eJ9cy3W84wP
         8uFKfGcZb46gid2tGIvsYH0F0u6o/Of9My5QImZOg2e04AcZ24aUIum24J3yJegbhdgE
         iKlRvXQy6LCTxggg++d8IX6+s9K4zeAnO6UlwruCXNhLTTymOwDn1QwoYhN+WglY8f8n
         ShT25aKSCLBSg2IK24fyideQlpNfioJcTpp3SNZgtY8MWL4SmaTSkzngQj6HIWA9OTLW
         HkP02yN0GYOvghMmslaFYlusy6Mso3pLnMUj+MHCrmp6yMGElpl42iVboY0BV7wjBWul
         pVZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=sZezBR5HykvpC1sIN+9Xhtpk4uvdTZ01lu6mR5HN7g0=;
        b=x1qsuWXS2k/StTu3izNiXHGqavmC/SrcjRURRRkXstDolTqOnQIsSrYO9aLNRAkh0t
         eWkY0LStW23THJSVlr3svCGmQaYalBvLuRdFIRsYvluuoR6/EPDJyQTKjOqJpkzQ3O8J
         veFlYNt2BuYkIDQyiYPNdcMEpAFV113xvvn5eAEkO38tn083TSB66W1J3Wwg0jMaRbo7
         HU4w2OM/NWZDDkKzItUBix6AfOcHmZgNgH+dIMafovNKYP437lKaJOeCaIq/lp5hUDpS
         zy3q4dZFNn/4ptd84tJ64i4BkG+2dFDsSIT3Za9JBdS/AZXrA1N3sDHp+jtMR6k64ZYG
         +oZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=cdEzxWE4;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sZezBR5HykvpC1sIN+9Xhtpk4uvdTZ01lu6mR5HN7g0=;
        b=gC39+Nbdf8n2H0RS5CVVu91F4tS3pCOxnyiEqYYZoQG8udqt5toonvWQpMuT+s5yDz
         VcfM7VlOeOE3j6UjQu9dGyOSM/57p/k5ed3DVRfszg8EERq9R67mhQYMTtPik+xKOQDd
         UKTadbL5Dr02XNLNrZu2o+enibfA1FKCiGa9pBSefJlpmfzLoBBCiveuiz2IexvmYQsU
         fkSGsgeVy2ZI7MUpValSedF+vJXB0Pg4/TcbJQk7hpnu/Y9G95HH5TgSmTrV3bAr/WEV
         BgzMchwj/K9rs0TdKsGGAvaQYMRD2z2BRMdG8gBjTi5u7p0G3ODz4gZXrywe45mNo2dT
         1Ebw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sZezBR5HykvpC1sIN+9Xhtpk4uvdTZ01lu6mR5HN7g0=;
        b=RebuXxkgmmp91NCN3Q05IN35/PAg6aoSF+UDCYGqIF7lhgQLojAWafR5gTIMB3qtd1
         gd8lyqWs/piK/hSisuIFKtlyxCruOMeP5BSU/9EpRKUoGwDWkyuFxUU1+fyQ/6XpnsKw
         Wc2ucyHopMUXr8LLQ9byAEVv9OjhcD0Vqje51GT8L7H6IJO2VF1ZMpiXli0xzcUzaMP3
         B4ItIgylKesVNXPEhc+uXCx8NyGjfKQyTdSnZRBTpevuGQz3Q+w71qhAzlOfihBV6k3D
         7kVI1iTdR1fkExES36BclMpNq3naQnX5JEKJW/mBbJynqjWCiAmw7fhPjOy8Q/G0PgT5
         UNVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333S4zblvC1mLYYCekrvqdIVg8uiGZoF55B3fiCrgYfkbyt1OdJ
	q52vOyUypNg36dCvTC8CeCs=
X-Google-Smtp-Source: ABdhPJwgcYvdBcHj1U1qEHUczR4LFQzXZF2GReaLO9Z9ylcYOD0s4Cd7gIm5fyjYym4YCZgfw2uFDw==
X-Received: by 2002:a05:6512:2292:: with SMTP id f18mr20274130lfu.619.1635223187446;
        Mon, 25 Oct 2021 21:39:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc17:: with SMTP id b23ls1701981ljf.6.gmail; Mon, 25 Oct
 2021 21:39:46 -0700 (PDT)
X-Received: by 2002:a2e:a303:: with SMTP id l3mr23971490lje.242.1635223186490;
        Mon, 25 Oct 2021 21:39:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635223186; cv=none;
        d=google.com; s=arc-20160816;
        b=qAJ+YEY4TMkhJ2rTSDYxkrTU6vM6W58NlV64/rs+T58k2soUYetVjPB5BLyObu56/A
         QLpD7Y6NNSZWrJZAQ5znYHrPGtFQsW+XIxUkDHDMvScz8Nm/DL37jET6YkvwqMK4pUwl
         FP1DHlJ5eEqXK8uBYIa24Zclrb6TpeUeAhuxU06aBaMSd5ZU+Q4FBIfixAqQcyNFLCX6
         7nRwpGypNa+8I/9cCIHGsdYiuH76GqB69uIqNWcmUYq5yAy7n8+Oa+u/D/lpkiJ6i+0K
         7Ti8uKfh8QgK9fso6dS9lntwQuhWzg+uDCdDx1fZBFj1lcIJSvcWmVb6CiaPdTfH31/1
         1BfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KVhIZhSXB0M0vyj9/7/Cl1UkXRcb4g+5QcVGTYNYcgo=;
        b=RReObkcDMRSaVqkPG6GowthRyY88VisFvnmDmDKoFhV/mLjDFysHq8CcQ578vhjqfH
         3P+Ftjmo60++YMY7wU+zI4HtN/PJ0CjuUjWwihEIzr+nd1N7xK6DBOnJvIMjIQscx/7a
         vSPwi1qv6gA7b67XeGNMe24YTNLWft3HtzpAl6dV1+5nrmqyLH6zWOTbNPQthBo+JGwk
         bFJaJjiL+dXmpJQIDB6adJf21ovq/Z4Ls0etvYwYPwls7szoMNdQcRgI+hjcErGaGpUw
         OEuksdUSifbE4soYrq8Q2szFu20zKx+SV+YX+PJzBZhH1Ch5ZQsGayS8/SeZsaIIER/i
         lU1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=cdEzxWE4;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id s16si1387602lfp.6.2021.10.25.21.39.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Oct 2021 21:39:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f69.google.com (mail-ed1-f69.google.com [209.85.208.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 2FB7B4029D
	for <kasan-dev@googlegroups.com>; Tue, 26 Oct 2021 04:39:45 +0000 (UTC)
Received: by mail-ed1-f69.google.com with SMTP id v9-20020a50d849000000b003dcb31eabaaso11912941edj.13
        for <kasan-dev@googlegroups.com>; Mon, 25 Oct 2021 21:39:45 -0700 (PDT)
X-Received: by 2002:a17:907:3e0a:: with SMTP id hp10mr2839499ejc.156.1635223183481;
        Mon, 25 Oct 2021 21:39:43 -0700 (PDT)
X-Received: by 2002:a17:907:3e0a:: with SMTP id hp10mr2839461ejc.156.1635223183204;
 Mon, 25 Oct 2021 21:39:43 -0700 (PDT)
MIME-Version: 1.0
References: <YUyWYpDl2Dmegz0a@archlinux-ax161> <mhng-b5f8a6a0-c3e8-4d25-9daa-346fdc8a2e5e@palmerdabbelt-glaptop>
 <YWhg8/UzjJsB51Gd@archlinux-ax161> <afeaea5f-70f2-330f-f032-fb0c8b5d0aa5@ghiti.fr>
 <990a894c-1806-5ab2-775e-a6f2355c2299@ghiti.fr>
In-Reply-To: <990a894c-1806-5ab2-775e-a6f2355c2299@ghiti.fr>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Tue, 26 Oct 2021 06:39:31 +0200
Message-ID: <CA+zEjCt28iYQARQa=8Nsw8+_j0PuEee==gUqjKjasMo+w2Ohwg@mail.gmail.com>
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
To: Alexandre ghiti <alex@ghiti.fr>
Cc: Nathan Chancellor <nathan@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, elver@google.com, 
	akpm@linux-foundation.org, ryabinin.a.a@gmail.com, glider@google.com, 
	andreyknvl@gmail.com, dvyukov@google.com, ndesaulniers@google.com, 
	Arnd Bergmann <arnd@arndb.de>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-riscv@lists.infradead.org, 
	Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=cdEzxWE4;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

Hi,

On Fri, Oct 15, 2021 at 3:08 PM Alexandre ghiti <alex@ghiti.fr> wrote:
>
> On 10/14/21 8:31 PM, Alex Ghiti wrote:
> > Hi Nathan,
> >
> > Le 14/10/2021 =C3=A0 18:55, Nathan Chancellor a =C3=A9crit :
> >> On Fri, Oct 08, 2021 at 11:46:55AM -0700, Palmer Dabbelt wrote:
> >>> On Thu, 23 Sep 2021 07:59:46 PDT (-0700), nathan@kernel.org wrote:
> >>>> On Thu, Sep 23, 2021 at 12:07:17PM +0200, Marco Elver wrote:
> >>>>> On Wed, 22 Sept 2021 at 22:55, Nathan Chancellor
> >>>>> <nathan@kernel.org> wrote:
> >>>>>> Currently, the asan-stack parameter is only passed along if
> >>>>>> CFLAGS_KASAN_SHADOW is not empty, which requires
> >>>>>> KASAN_SHADOW_OFFSET to
> >>>>>> be defined in Kconfig so that the value can be checked. In RISC-V'=
s
> >>>>>> case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means
> >>>>>> that
> >>>>>> asan-stack does not get disabled with clang even when
> >>>>>> CONFIG_KASAN_STACK
> >>>>>> is disabled, resulting in large stack warnings with allmodconfig:
> >>>>>>
> >>>>>> drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q02=
.c:117:12:
> >>>>>>
> >>>>>> error: stack frame size (14400) exceeds limit (2048) in function
> >>>>>> 'lb035q02_connect' [-Werror,-Wframe-larger-than]
> >>>>>> static int lb035q02_connect(struct omap_dss_device *dssdev)
> >>>>>>             ^
> >>>>>> 1 error generated.
> >>>>>>
> >>>>>> Ensure that the value of CONFIG_KASAN_STACK is always passed
> >>>>>> along to
> >>>>>> the compiler so that these warnings do not happen when
> >>>>>> CONFIG_KASAN_STACK is disabled.
> >>>>>>
> >>>>>> Link: https://github.com/ClangBuiltLinux/linux/issues/1453
> >>>>>> References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-8
> >>>>>> and earlier")
> >>>>>> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> >>>>>
> >>>>> Reviewed-by: Marco Elver <elver@google.com>
> >>>>
> >>>> Thanks!
> >>>>
> >>>>> [ Which tree are you planning to take it through? ]
> >>>>
> >>>> Gah, I was intending for it to go through -mm, then I cc'd neither
> >>>> Andrew nor linux-mm... :/ Andrew, do you want me to resend or can yo=
u
> >>>> grab it from LKML?
> >>>
> >>> Acked-by: Palmer Dabbelt <palmerdabbelt@google.com>
> >>>
> >>> (assuming you still want it through somewhere else)
> >>
> >> Thanks, it is now in mainline as commit 19532869feb9 ("kasan: always
> >> respect CONFIG_KASAN_STACK").
> >>
> >>>>> Note, arch/riscv/include/asm/kasan.h mentions KASAN_SHADOW_OFFSET i=
n
> >>>>> comment (copied from arm64). Did RISC-V just forget to copy over th=
e
> >>>>> Kconfig option?
> >>>>
> >>>> I do see it defined in that file as well but you are right that
> >>>> they did
> >>>> not copy the Kconfig logic, even though it was present in the tree
> >>>> when
> >>>> RISC-V KASAN was implemented. Perhaps they should so that they get
> >>>> access to the other flags in the "else" branch?
> >>>
> >>> Ya, looks like we just screwed this up.  I'm seeing some warnings lik=
e
> >>>
> >>>     cc1: warning: =E2=80=98-fsanitize=3Dkernel-address=E2=80=99 with =
stack protection
> >>> is not supported without =E2=80=98-fasan-shadow-offset=3D=E2=80=99 fo=
r this target
> >>
> >> Hmmm, I thought I did a GCC build with this change but I must not have
> >> :/
> >>
> >>> which is how I ended up here, I'm assuming that's what you're
> >>> talking about
> >>> here?  LMK if you were planning on sending along a fix or if you
> >>> want me to
> >>> go figure it out.
> >>
> >> I took a look at moving the logic into Kconfig like arm64 before sendi=
ng
> >> this change and I did not really understand it well enough to do so. I
> >> think it would be best if you were able to do that so that nothing get=
s
> >> messed up.
> >>
> >
> > I'll do it tomorrow, I'm the last one who touched kasan on riscv :)
> >
>
> Adding KASAN_SHADOW_OFFSET config makes kasan kernel fails to boot.
> It receives a *write* fault at the beginning of a memblock_alloc
> function while populating the kernel shadow memory: the trap address is
> in the kasan shadow virtual address range and this corresponds to a
> kernel address in init_stack. The question is: how do I populate the
> stack shadow mapping without using memblock API? It's weird, I don't
> find anything on other architectures.

@kasan: Any idea what we are doing wrong in riscv to encounter the
above situation?

Thanks,

Alex

>
> And just a short note: I have realized this will break with the sv48
> patchset as we decide at runtime the address space width and the kasan
> shadow start address is different between sv39 and sv48. I will have to
> do like x86 and move the kasan shadow start at the end of the address
> space so that it is the same for both sv39 and sv48.
>
> Thanks,
>
> Alex
>
>
> > Thanks,
> >
> > Alex
> >
> >> Cheers,
> >> Nathan
> >>
> >> _______________________________________________
> >> linux-riscv mailing list
> >> linux-riscv@lists.infradead.org
> >> http://lists.infradead.org/mailman/listinfo/linux-riscv
> >>
> >
> > _______________________________________________
> > linux-riscv mailing list
> > linux-riscv@lists.infradead.org
> > http://lists.infradead.org/mailman/listinfo/linux-riscv
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BzEjCt28iYQARQa%3D8Nsw8%2B_j0PuEee%3D%3DgUqjKjasMo%2Bw2Ohwg%4=
0mail.gmail.com.
