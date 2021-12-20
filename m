Return-Path: <kasan-dev+bncBAABB4UPQKHAMGQE5Z4A5IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id A2A5647AA78
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:41:06 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id f20-20020a056402355400b003f81df0975bsf6540062edd.9
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 05:41:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640007666; cv=pass;
        d=google.com; s=arc-20160816;
        b=s1+kHEcYoYPHFkRoUWRDMLN/GTaKuW14/k9h7qFpYLbzxWZ8r6SVebZnTCIWof4jvL
         V02JR1+Qu54LpOHHI151HSGOGNzXIgws0FJhNlyDTs9dVSeGBGoVFmOR9csUVY3zMlAP
         i7x0Q1hiMsOF2XzzpHjR46WJF6uYrCn7a5c/wTh69qMto81z69sOa3m7KPVxOnLGKM/8
         hB6G2633t9Fb741hzk5MNgzVVf99K6pwa9WW5njExsztV/9ie4FuBw35CLPekyIQqYni
         FujzTUvn1NNKGvXcSbiMJHUEQd1s7fycJGBzHjcazXi9XXTJzYZYCNqGW1hfIcqN6Bk6
         yxKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=bSk1jZIvQkanVv5JSzZQINyi+OGg5ksaLYK5X/KmFVg=;
        b=O5JLJF/aAFH8j23r0sx8Hvw0IFJsXZcF0v3Iuuo8xGPUo1ZMnKKtoFPdmsCktjmzDW
         wF0kclc557rjxiRZ+f0zSImaYGgSLR1EQOXiUzuJas08XlTb/MVllbQuY4cPrHOCyJ+T
         wxXt7lyjjxKCKTRucUU0smhP6WhUC6Z3Mcn0VJQYd/GkzJKQuD4vCs+w6CHpbHQpLw/X
         PMRcGqrVWS4TuXzrBbrqzdOYmk3+YwljQ2eDXAOP8uyy0XuiGQ8AxEHbTi/Oq+qEfJOq
         FJXZIoCm59m7aR+V70L1CKgH3a+WCZxZdJKqupFinxbXo4R3ZulFAzeFuYzwgRgOdPnm
         HMCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oT13uPmk;
       spf=pass (google.com: domain of guoren@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=guoren@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bSk1jZIvQkanVv5JSzZQINyi+OGg5ksaLYK5X/KmFVg=;
        b=Jpyx4LOsBaIncUhmSSlaV7UT/4Btq3BDuc+fS6/1uz7gIrrNSar7XlnNk6Tg7G7riq
         YldQZXTvmTeDaBbAr4JUzcZcFYfEM9vKedhgNtDafGDhOjMOVjlOKaPeQlfIjJUivx6I
         z2x9knoU7aCtWOgkp5vWDOxA97EM7Q7IftvdOArSKMXssshdUaS4NEbWOghhBTyoviqQ
         //E335FIzRMUuxVV7oCtMPfZL0rFCtPYj6Jo3pohHl/xphSw3Y1zhvKi25JUBZECTJK1
         mnZp4JOEGocjksPnwc+R46jqK79w/duZD8PXmIzZWqe3+wAYQS8eoQuazd5sPxn0c94G
         X47A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bSk1jZIvQkanVv5JSzZQINyi+OGg5ksaLYK5X/KmFVg=;
        b=wIzCgHn5a+hMzbzuBWR5pzdvhzBrmij65sp9PZgk/JXVg9q5J1DmhaJxOYLZXkV8X0
         HSIWtRijQmIgbRUXU76azM3NL/sSPe+j0BjGDpxVw22MvIMugVPEWXdq9wc5W7rx3tfC
         0P5YrtJvNKCcoAEzJ0wcLJ/GIhyYeJk/dbg3wZlT45I6dQC2ErsC+d6epsMR0zv49L4f
         daScZUQSxcxb2ZpEQt9megHQbO2rPyRVP0EaHAfQe/Leqg32HdHCJv5BGqA9KSJIiNll
         q3jrosgunDZElJqA7z+HCniEHPfqp26E/pjfl9/dbV4IH5gFPJaQTusP7uUTxDdHkS0w
         J/cQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530GpA2ag0UuCEyldPifTaKQBSVPVCeB5L7iyERlwXv+JDmYHvQ3
	TClbAtXs7tss/ZMdOc87Drw=
X-Google-Smtp-Source: ABdhPJwT5hzXRD3sDCcvvpwb3MMCKagPLofdUUlyTuANhmsPeaLX79oXMn+lvBQiNK76JHed2gLkfg==
X-Received: by 2002:a05:6402:516a:: with SMTP id d10mr16149164ede.131.1640007666309;
        Mon, 20 Dec 2021 05:41:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2691:: with SMTP id w17ls1045584edd.0.gmail; Mon,
 20 Dec 2021 05:41:05 -0800 (PST)
X-Received: by 2002:a05:6402:3550:: with SMTP id f16mr1773897edd.332.1640007665578;
        Mon, 20 Dec 2021 05:41:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640007665; cv=none;
        d=google.com; s=arc-20160816;
        b=cXsWiJCmuLPZErrFLD7jVXM60dcJskqrmFmPHyJahaDYF3HSdEDM0CVakrNwdaLl2U
         OuSX3/XwBzF25qROeG2qsD+dtEICBtvvi60kL68EOk4yXdybsjc0mFYQ9VZoojn7pXM7
         MNUWNWNpF+3XSForU77KlhcyaPiMyvfeyhkEfrzJsQmk8zG3qDxZpkk55RLZcsaOs3YS
         NQ6xQQprwYpOcRtKL+9D7oEexrLCJUYyYuwwoXBfBT5PjYMAbhraR3DHJarScREPJfUN
         lxE27JfyrmXIfy6VeQZzWtR/PRH9gtU4ZQwadXK9rDHSPJWMwrRRXMc9DH77Qm7+BUHM
         mcsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rVsoAr8j2KN6A8WtXTWE4QQxPC8gzYB5/aPRQ0YYi0Q=;
        b=ZQNUqLcgB9LjPsW0AyMaEYOoAeRIF75PoyteVxqAPL9gM3Z8b7bVBKMYeM0Hx8DPdV
         IfXdgRJ4Po3pIL2xa/RB/h0LDQz2CTjSDR63fPX8Dxc4LkzyRSCu4Rv88osDwP6xnLtv
         MajeYU8DDBTmynCaAfg5KFXWlytLWS48IBiDeRNcTOHsRzUPUIdRPtLk2dIgaH8EPxA5
         lIc33vzTmzoniI2O6+MunqP2BRBpObCegmBZGQgxuRuDo2R7PN0YXqz0SdeLxe98JliJ
         ZfO2ywCYSIaWKv5xiCPa6fzYWtuNKytiK3P0oKl6EjcJhptIhD92Rtb498g77W4zveHa
         juUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oT13uPmk;
       spf=pass (google.com: domain of guoren@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=guoren@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id dk14si1116988edb.4.2021.12.20.05.41.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Dec 2021 05:41:05 -0800 (PST)
Received-SPF: pass (google.com: domain of guoren@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 5C4AE610D5
	for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 13:41:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2FBE1C36AF2
	for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 13:41:03 +0000 (UTC)
Received: by mail-ua1-f43.google.com with SMTP id u40so17741004uad.1
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 05:41:03 -0800 (PST)
X-Received: by 2002:a05:6102:316e:: with SMTP id l14mr233250vsm.8.1640007662059;
 Mon, 20 Dec 2021 05:41:02 -0800 (PST)
MIME-Version: 1.0
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
 <20211206104657.433304-13-alexandre.ghiti@canonical.com> <CAJF2gTQEHv1dVzv=JNCYSzD8oh6UxYOFRTdBOp-FFeeeOhSJrQ@mail.gmail.com>
 <CAMj1kXHmdDKFozkoAfM-mxsxxfanhVq5HcA1qKTrkp=vAt=Umg@mail.gmail.com>
In-Reply-To: <CAMj1kXHmdDKFozkoAfM-mxsxxfanhVq5HcA1qKTrkp=vAt=Umg@mail.gmail.com>
From: Guo Ren <guoren@kernel.org>
Date: Mon, 20 Dec 2021 21:40:51 +0800
X-Gmail-Original-Message-ID: <CAJF2gTR2pDN8vvknmE2s1nj2WSuCfTkXYkU074rCck+CCwQv7Q@mail.gmail.com>
Message-ID: <CAJF2gTR2pDN8vvknmE2s1nj2WSuCfTkXYkU074rCck+CCwQv7Q@mail.gmail.com>
Subject: Re: [PATCH v3 12/13] riscv: Initialize thread pointer before calling
 C functions
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>, Jonathan Corbet <corbet@lwn.net>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Zong Li <zong.li@sifive.com>, 
	Anup Patel <anup@brainfault.org>, Atish Patra <Atish.Patra@rivosinc.com>, 
	Christoph Hellwig <hch@lst.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Arnd Bergmann <arnd@arndb.de>, Kees Cook <keescook@chromium.org>, 
	Guo Ren <guoren@linux.alibaba.com>, 
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>, 
	Mayuresh Chitale <mchitale@ventanamicro.com>, panqinglin2020@iscas.ac.cn, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, linux-riscv <linux-riscv@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-efi <linux-efi@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: guoren@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oT13uPmk;       spf=pass
 (google.com: domain of guoren@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=guoren@kernel.org;       dmarc=pass (p=NONE
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

On Mon, Dec 20, 2021 at 5:17 PM Ard Biesheuvel <ardb@kernel.org> wrote:
>
> On Mon, 20 Dec 2021 at 10:11, Guo Ren <guoren@kernel.org> wrote:
> >
> > On Tue, Dec 7, 2021 at 11:55 AM Alexandre Ghiti
> > <alexandre.ghiti@canonical.com> wrote:
> > >
> > > Because of the stack canary feature that reads from the current task
> > > structure the stack canary value, the thread pointer register "tp" must
> > > be set before calling any C function from head.S: by chance, setup_vm
> > Shall we disable -fstack-protector for setup_vm() with __attribute__?
>
> Don't use __attribute__((optimize())) for that: it is known to be
> broken, and documented as debug purposes only in the GCC info pages:
>
> https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html
Oh, thx for the link.

>
>
>
>
> > Actually, we've already init tp later.
> >
> > > and all the functions that it calls does not seem to be part of the
> > > functions where the canary check is done, but in the following commits,
> > > some functions will.
> > >
> > > Fixes: f2c9699f65557a31 ("riscv: Add STACKPROTECTOR supported")
> > > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > > ---
> > >  arch/riscv/kernel/head.S | 1 +
> > >  1 file changed, 1 insertion(+)
> > >
> > > diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
> > > index c3c0ed559770..86f7ee3d210d 100644
> > > --- a/arch/riscv/kernel/head.S
> > > +++ b/arch/riscv/kernel/head.S
> > > @@ -302,6 +302,7 @@ clear_bss_done:
> > >         REG_S a0, (a2)
> > >
> > >         /* Initialize page tables and relocate to virtual addresses */
> > > +       la tp, init_task
> > >         la sp, init_thread_union + THREAD_SIZE
> > >         XIP_FIXUP_OFFSET sp
> > >  #ifdef CONFIG_BUILTIN_DTB
> > > --
> > > 2.32.0
> > >
> >
> >
> > --
> > Best Regards
> >  Guo Ren
> >
> > ML: https://lore.kernel.org/linux-csky/



-- 
Best Regards
 Guo Ren

ML: https://lore.kernel.org/linux-csky/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJF2gTR2pDN8vvknmE2s1nj2WSuCfTkXYkU074rCck%2BCCwQv7Q%40mail.gmail.com.
