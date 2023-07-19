Return-Path: <kasan-dev+bncBAABBCH536SQMGQELWERN6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AA1675994F
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 17:17:30 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-565dd317fe8sf9312308eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 08:17:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689779849; cv=pass;
        d=google.com; s=arc-20160816;
        b=qtEQl5Z+9vZnWuz2QDrwlZqQz/IQmTskrldpoGR2bvm+TDGszFe+OHDg+bWHpCaUq4
         zIeqVk7oPxbu3+6/s634IWBvjcvNvmoxrsc7eQzKh/v/TDdKfHMajvwlEpmoCEfujUre
         WZ71BkYVyrzIsHXIgS+S30e6Gg/L3UEwND+TS7okAO13PzbzfYIkXZ0kDVqqSWKrpX6d
         bWVJ5xKatpmv2yu2+Sj9l2yKuNxfQhxDOoYz7y4WlsW15zzASJFeg7hq1qhygBM+DgXH
         cc+Gge1RPVnRO9oyF0rEXzgoI8v6iKCQ04s6AEV+1LbspAB2KxP2ZHxg4fZTUOE/cPMb
         o3rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=197aufD/UrJEO3Gv6kMIDZoyExiNqG6XBszuGd+FrCY=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=lJROwJC60UAS++NEb9vQza1Nga7rt6976ii/0Gzr/l5IcA79OdmuLAxGVL+MiVlo2l
         RbCNh/2AjeRlzmxjd6IphWTokjD0A5vmjHvMRybtTjQxKiV+O9j9F113v40YHTTMShDi
         VU2X3nJnES5BsGxZwKRrW6BH+IeoXwRe3zbaeI3jNHM5nHjnWz6vAk8le0SOqGTL9C4K
         5uJ+JjdY+t/+xsNk3AYUMXEZRPC6zJsbj9AbVfbK99WLu+o1ulxa/RAUfvsmJg/o3pfo
         Gu74UXeiIRmRaMKzsB5ECHHn5jWVIg64JUrX8zkqqQo/tjPjLdmILrZ+eCUy+bIcXs9t
         pgFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TUQy3Qjs;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689779849; x=1692371849;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=197aufD/UrJEO3Gv6kMIDZoyExiNqG6XBszuGd+FrCY=;
        b=gyILalx2ozq4d/uEhO9GNh4Tog4MlgzaHc4rjrW0X+9hEsb7ROcyuubVKH6c4/y44L
         Sk4ixaKJB5rfUU4EcfJ6DUX22fd2Y9kjnZrhsnJxPCzheyniPeR7RtTdWkwuq9jkFtzv
         ZM0hfQE2tACGtlUHNEwyp+O3dnUrWGwvizVXpVUk9nEW4FTAKhrEcxukc/FPJjx+blW5
         ghAdMer9oeBzmZ5wiqgAugm7V8DJmNmtF780ThZN3B7GOjlGL3jwuYDrw/hbi3CLgWuq
         LRLxvqs4ATEjReEzyhHZR0aTmXCKqupTboSCKImQacbnEqzsGHLp3ckU/o+FXR/W2/Su
         dn+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689779849; x=1692371849;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=197aufD/UrJEO3Gv6kMIDZoyExiNqG6XBszuGd+FrCY=;
        b=hiR8D3j0UVRM9h55QPJutzIRwkZachkuI+ovPcG8b8ZH6H/2OOgiE8X23wMB934PqW
         b2XMSiD4+4RfiwMC/PF2ijAE4EjkJDQmU08SRwPU/3xOmzvkEkPWugCfFr4zAjGLhyhA
         cj3o8c9hxD7D730FEOe4zq4w4w8Yd1p6MsJcRuQGS8PRL9gLFeQteZdqq/in9JdG/oPI
         g4IBKagrBHT0Wpv23frtptVtRB9MJlf+SJlU802VIX0nSBLSoja2QYtUNCnwdt+GPBo7
         OOJSIjC2p4sGkgC7EL1hGLlYB268JL0jR7dtV3LglJkguhz1TN2ejxcf5K7MhnsyUcMf
         wJBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaAPEFKWEjV4dAlmIxJ4aaX+ib7o/VsXZH7S3qL8V9j3mEbteq/
	xJvDWw/yiqpb59pSTuUEwpQ=
X-Google-Smtp-Source: APBJJlEAryuIHcyEEIecNpyz9AmxX4khK1jWygAmk6W0WNGdiB9qHpGXdrC9XBwRFCihjqmy/cFQ3A==
X-Received: by 2002:a4a:d20b:0:b0:566:fba5:e51b with SMTP id c11-20020a4ad20b000000b00566fba5e51bmr10243841oos.7.1689779848844;
        Wed, 19 Jul 2023 08:17:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5b83:0:b0:566:c77c:551 with SMTP id g125-20020a4a5b83000000b00566c77c0551ls2954439oob.0.-pod-prod-05-us;
 Wed, 19 Jul 2023 08:17:28 -0700 (PDT)
X-Received: by 2002:a05:6808:181d:b0:39e:c660:a5fa with SMTP id bh29-20020a056808181d00b0039ec660a5famr3544628oib.10.1689779848188;
        Wed, 19 Jul 2023 08:17:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689779848; cv=none;
        d=google.com; s=arc-20160816;
        b=fkAtED43BDx3AnODjgQQdGNBj2IdxFxT1tZH2y2EKvuLgt9DJW43XdYYpTi1l5wbTE
         LTLVsSopuCOQxEu+IqkyW5FKzotWSi7LOmNC7olZyJ+Prji7wzaHNbpQOWncEUl2IkWX
         Kwh0nG1nwvXZ8plG4LDG2b4khKegrbRrD24Wq40R5GPFV98zglEiP82ZXxo6852ygIIl
         zkxvorPfl59CvvhftXxhHj8lyl6TW0nRpZF/OsvBhgyXHALyj49W8hYty1VfeAXLxKqs
         bsCSRkzYPHrUeR+X9cXqQFTDoy5iCT1BUokFK4kXhZUeAMXsRDezZVHpt+z+gUhU2nMi
         4v6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LbXQUPBOp4z8nItOaJBGrSJEUVzQ5oGTy8O4AE+GSP8=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=WaTzzWj+JESyAvSZHWaFZ+s6slmAtPQ4y4mcz0bZakIuONS53kkyRHsXd1hluB7Yb5
         LR5LUTTUUb+SLddNP6y8xRvL9AfZH0q2WPBGtMBy7PlkNPtPImqr55MjlbLI+akEwqiL
         QsuP3wPMZUNdMPTw4L3XIqKTs+I0RDa8rg/txub56F3wQIjSpSPVOkov0GNPQV/HVuva
         GEi1dsTeO1PmZQAHALkDiQ8Ka/6dLYr4Q7UQSWbKPdfCqT1P6FV5gTaDcY/Xm5H0qJ0r
         Saj+iJkNdC8LBdy2UKQj8pxHIMJtqrAnQhU3C8k+6m0piEo0G3GoAnxwLHph8A/fWqNC
         YFfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TUQy3Qjs;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id cc13-20020a05622a410d00b0040372a5968bsi339891qtb.5.2023.07.19.08.17.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jul 2023 08:17:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 87BBA61740
	for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 15:17:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0B79AC4339A
	for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 15:17:26 +0000 (UTC)
Received: by mail-ed1-f54.google.com with SMTP id 4fb4d7f45d1cf-51f90f713b2so10523444a12.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 08:17:25 -0700 (PDT)
X-Received: by 2002:aa7:c148:0:b0:51d:d3d4:d02f with SMTP id
 r8-20020aa7c148000000b0051dd3d4d02fmr3112041edp.8.1689779844119; Wed, 19 Jul
 2023 08:17:24 -0700 (PDT)
MIME-Version: 1.0
References: <20230719082732.2189747-1-lienze@kylinos.cn> <20230719082732.2189747-3-lienze@kylinos.cn>
In-Reply-To: <20230719082732.2189747-3-lienze@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Wed, 19 Jul 2023 23:17:14 +0800
X-Gmail-Original-Message-ID: <CAAhV-H5y2cbbzrWtPKPZtP-DwzAq+g=PvEExD=rru1PkQg37dA@mail.gmail.com>
Message-ID: <CAAhV-H5y2cbbzrWtPKPZtP-DwzAq+g=PvEExD=rru1PkQg37dA@mail.gmail.com>
Subject: Re: [PATCH 2/4] LoongArch: Get stack without NMI when providing regs parameter
To: Enze Li <lienze@kylinos.cn>
Cc: kernel@xen0n.name, loongarch@lists.linux.dev, glider@google.com, 
	elver@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, zhangqing@loongson.cn, yangtiezhu@loongson.cn, 
	dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TUQy3Qjs;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hi, Enze,

On Wed, Jul 19, 2023 at 4:34=E2=80=AFPM Enze Li <lienze@kylinos.cn> wrote:
>
> Currently, executing arch_stack_walk can only get the full stack
> information including NMI.  This is because the implementation
> of arch_stack_walk is forced to ignore the information passed by the
> regs parameter and use the current stack information instead.
>
> For some detection systems like KFENCE, only partial stack information
> is needed.  In particular, the stack frame where the interrupt occurred.
>
> To support KFENCE, this patch modifies the implementation of the
> arch_stack_walk function so that if this function is called with the
> regs argument passed, it retains all the stack information in regs and
> uses it to provide accurate information.
>
> Before the patch applied, I get,
> [    1.531195 ] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [    1.531442 ] BUG: KFENCE: out-of-bounds read in stack_trace_save_regs+=
0x48/0x6c
> [    1.531442 ]
> [    1.531900 ] Out-of-bounds read at 0xffff800012267fff (1B left of kfen=
ce-#12):
> [    1.532046 ]  stack_trace_save_regs+0x48/0x6c
> [    1.532169 ]  kfence_report_error+0xa4/0x528
> [    1.532276 ]  kfence_handle_page_fault+0x124/0x270
> [    1.532388 ]  no_context+0x50/0x94
> [    1.532453 ]  do_page_fault+0x1a8/0x36c
> [    1.532524 ]  tlb_do_page_fault_0+0x118/0x1b4
> [    1.532623 ]  test_out_of_bounds_read+0xa0/0x1d8
> [    1.532745 ]  kunit_generic_run_threadfn_adapter+0x1c/0x28
> [    1.532854 ]  kthread+0x124/0x130
> [    1.532922 ]  ret_from_kernel_thread+0xc/0xa4
> <snip>
>
> With this patch applied, I get the correct stack information.
> [    1.320220 ] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [    1.320401 ] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_rea=
d+0xa8/0x1d8
> [    1.320401 ]
> [    1.320898 ] Out-of-bounds read at 0xffff800012257fff (1B left of kfen=
ce-#10):
> [    1.321134 ]  test_out_of_bounds_read+0xa8/0x1d8
> [    1.321264 ]  kunit_generic_run_threadfn_adapter+0x1c/0x28
> [    1.321392 ]  kthread+0x124/0x130
> [    1.321459 ]  ret_from_kernel_thread+0xc/0xa4
> <snip>
>
> Signed-off-by: Enze Li <lienze@kylinos.cn>
> ---
>  arch/loongarch/kernel/stacktrace.c | 16 ++++++++++------
>  1 file changed, 10 insertions(+), 6 deletions(-)
>
> diff --git a/arch/loongarch/kernel/stacktrace.c b/arch/loongarch/kernel/s=
tacktrace.c
> index 2463d2fea21f..21f60811e26f 100644
> --- a/arch/loongarch/kernel/stacktrace.c
> +++ b/arch/loongarch/kernel/stacktrace.c
> @@ -18,16 +18,20 @@ void arch_stack_walk(stack_trace_consume_fn consume_e=
ntry, void *cookie,
>         struct pt_regs dummyregs;
>         struct unwind_state state;
>
> -       regs =3D &dummyregs;
> -
>         if (task =3D=3D current) {
> -               regs->regs[3] =3D (unsigned long)__builtin_frame_address(=
0);
> -               regs->csr_era =3D (unsigned long)__builtin_return_address=
(0);
> +               if (regs)
> +                       memcpy(&dummyregs, regs, sizeof(*regs));
> +               else {
> +                       dummyregs.regs[3] =3D (unsigned long)__builtin_fr=
ame_address(0);
> +                       dummyregs.csr_era =3D (unsigned long)__builtin_re=
turn_address(0);
> +               }
>         } else {
When "task !=3D current", we don't need to handle the "regs !=3D NULL" case=
?

Huacai

> -               regs->regs[3] =3D thread_saved_fp(task);
> -               regs->csr_era =3D thread_saved_ra(task);
> +               dummyregs.regs[3] =3D thread_saved_fp(task);
> +               dummyregs.csr_era =3D thread_saved_ra(task);
>         }
>
> +       regs =3D &dummyregs;
> +
>         regs->regs[1] =3D 0;
>         for (unwind_start(&state, task, regs);
>              !unwind_done(&state) && !unwind_error(&state); unwind_next_f=
rame(&state)) {
> --
> 2.34.1
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H5y2cbbzrWtPKPZtP-DwzAq%2Bg%3DPvEExD%3Drru1PkQg37dA%40mail.=
gmail.com.
