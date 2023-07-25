Return-Path: <kasan-dev+bncBAABB6XY7WSQMGQEWLV5DPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 56481760C1A
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 09:40:44 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4068841fccfsf5447181cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 00:40:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690270843; cv=pass;
        d=google.com; s=arc-20160816;
        b=hcAT7QaYEv6YH7lGtOcAaEv43MB1cIDSomak1G1wC7gzxiCgHYMbyMLMOIfa4cNJQa
         LgaIRp2cSBnEZSS6UjCtdF7N8C/DUOd7YrgxnPbY2UWJ+AHS6wJUUpqZS8ZNkg9hiNtI
         oYfNaZrCdONIdyJN98WNe8nYS8uFFlQZcyxrwbHaP1MoaTOf/AzSNF1xK1bZ/0cRipny
         VEwURZP8oKZ6KlomA9d9wWyELRIC5y1D6v9MiZd3HUn4/EcV1JQmt/6gXgU477MfTS5A
         OYWfkA+5PsKkP4Twoe3h3Y96Eh2PcfmcojoAURau2vsxxFyG2JwoLh8+DmQ0XQ48/z78
         W7XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=tDZQeMxAD0EG8pq8bT8+gX9WzNMJgoAm7LVD9ONBlLc=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=z8Nvsq7IlFAwqg3bnGJYsPLUYh5J2LR588gqcKPn/ApIAnrcAHnbwp9kMXJ4/r2a30
         njUAP2gJBWB5TpFcQWEEqD9ZSZ5iJejlshmIffwFA/2Ot1hqophGwjmgHBsGVVDf/EiI
         CzR7IHYE4BuaslCTbn5Q9iTXTLfyxIOtRAYXmt9U+2q1bGbX8SLLePDrA7HncOd+7/QQ
         GVbLLWS/t4V2wBVi/nwynoamqoCxhNJhMSAWt4ndsJoXLPnPUdJ4TgBsZlq5rD80PQz6
         mxZ4vgZtjwq86AeJ33xDADLmsBxu555zaOsBnIqe5oK8DnvWdNa5QMpDQA8T89pt+Gvg
         wJWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MVtiqIi6;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690270843; x=1690875643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tDZQeMxAD0EG8pq8bT8+gX9WzNMJgoAm7LVD9ONBlLc=;
        b=lhv4kpHr4Zk5AhPrkH1mVdW8peoOpC2+RSVD9iZdLj3XlR5deYNXC5rQaztnhFtyxx
         hzV/13mYNLRG/A+KwqANvXiaoFVxWe797E5BAq/MRRCxqCcgS33oh1lrniPRokcyURb0
         VdEES/CRFelJUvfcNXavzt+3MiNZNg9H2Wvk8GCNkCOoovvHEGMvQCmKuuAdjNXCfq4K
         nrNGkM0Jw+nfxyq6/BS+eC6ZOKcDuht3f3Q17fXLKhQXGfKCI+g2jsYAjVxEzRwPEl9f
         gf2bHr3kFLMvQhM/TXL8p03JvIMxOKkF+mEDkiZfmpepMYdRlcbh6zRxVheQHB6EG3gn
         CZUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690270843; x=1690875643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tDZQeMxAD0EG8pq8bT8+gX9WzNMJgoAm7LVD9ONBlLc=;
        b=UaVOufIJHspieA+WSNn7aBxtvVbNupvYMibnqaIEBPH5GzQ16Iw4LtlNddmjOdVGLK
         t3G76HPmOkN119r9nyMSybAwSeZdnmcWTK2CfdNccyBkbWhXjLRKhjzccinW+qD6VFeZ
         qiBBAqZKSnLd96Q/66fumgiRXB/W28TmqCwodzphEXNBPj8klHUHWG2dw1CwL8jfVMwO
         IO4lzTd+mJOnGW9OJZJ9BYddTFaQWp4tru18w869O/apsK652I0y3Ft6OkW2S76WX0hR
         E3GrkflG+m9yW8r9LiO4HtEAiFrxmKylkPA04UA8XzZztvHG0jV5K54CWAh1qJDgDnu/
         TXhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbETdLNZqPIEIJGuC2K1fA9e/JhuUwkLgWPaH/H+L8V3ArnDWnX
	oi+bZVyBhe0m4mUUqe2QP24=
X-Google-Smtp-Source: APBJJlHySCD7LdcCJcggMC6P59IGE0q/s6XqQU0bqZ3cn+vuPcVG1i1tApaFd5OE8erw1VBh+K2qXg==
X-Received: by 2002:a05:622a:1a26:b0:403:2818:7041 with SMTP id f38-20020a05622a1a2600b0040328187041mr15732041qtb.1.1690270842795;
        Tue, 25 Jul 2023 00:40:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:714b:0:b0:3f8:3b67:f359 with SMTP id h11-20020ac8714b000000b003f83b67f359ls683109qtp.1.-pod-prod-00-us;
 Tue, 25 Jul 2023 00:40:42 -0700 (PDT)
X-Received: by 2002:a05:622a:1ba8:b0:3f5:16af:17db with SMTP id bp40-20020a05622a1ba800b003f516af17dbmr1853393qtb.0.1690270842005;
        Tue, 25 Jul 2023 00:40:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690270841; cv=none;
        d=google.com; s=arc-20160816;
        b=yha1TQ9pX/L8B0J2XPmX+cRiGXQ82m40/ZSjHDSayDlny+NWqkADDAmS4hr7lKJR6i
         gpaEhhu/D4DZ1w/OwMiMGDL43rkqbGcrQ0OttKzX87WjArtQ3yWixOFRPsyiYP9m5oZ/
         7PE/N+FI0AmRaf7VB0Pd5Ibosb1/JKLCKOsruFdOmqo5ihBN4Jyh8wrnE5dRq0GZaePG
         vn0xxsYu46RxfYFpg4GcoxebtqW008NmS7GXdnpuI7UPeb96fcou4LfEuyMy9jXBAhPO
         HccZCQKiwT+eOpEnW8poy+p7Fw1ru53YiYkIsdy2jn1i/ls7XC3aSP/dYkjkkahHvG4I
         wSLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LD/vJEoOfVWeJBE2BduLQ4V5v2ACqODtMWh5nNOSqMo=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=fPT68FMuLtlmLr1Kd/ODZBdZ7V/upF9q5dFq15A+1qdFoMdVWCgY6PPxyuG+AHXpvG
         Ja2cJvU3DhSXZHbdIDuDhQxKPlAXIEgZ4dL2ZUhpEiWkBAwgps+4fPzqZ9I+tw1KWp0x
         iSnRM1EXQDrru5w4pj2eiPmodivkhCdGNsTE+ybNY6hj6HLely8qyCIx/Nz38cjwAWO0
         VkEH8nljVwOugjSdi01/aD5huHUh8+AxRwpaULcZoARJaZj+d/5W+ctZS1GK3PBZz5pk
         mNlsNJ7ka5VFw9GV3n62tU2j6A4pPJMcVsq7suE54bqsCwkh/84MhNeemHACA1bjUtCY
         7jdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MVtiqIi6;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ge16-20020a05622a5c9000b00403ea989befsi812088qtb.1.2023.07.25.00.40.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jul 2023 00:40:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 90B606120F
	for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 07:40:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7B195C433D9
	for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 07:40:40 +0000 (UTC)
Received: by mail-ed1-f46.google.com with SMTP id 4fb4d7f45d1cf-5222bc91838so2991099a12.0
        for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 00:40:40 -0700 (PDT)
X-Received: by 2002:aa7:c613:0:b0:522:4f0a:6822 with SMTP id
 h19-20020aa7c613000000b005224f0a6822mr695646edq.22.1690270838627; Tue, 25 Jul
 2023 00:40:38 -0700 (PDT)
MIME-Version: 1.0
References: <20230725061451.1231480-1-lienze@kylinos.cn> <20230725061451.1231480-3-lienze@kylinos.cn>
In-Reply-To: <20230725061451.1231480-3-lienze@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Tue, 25 Jul 2023 15:40:27 +0800
X-Gmail-Original-Message-ID: <CAAhV-H5nAwmjNsaA+=iR9EjrTSRogZUaoTcCULoe0YMgbAuFvg@mail.gmail.com>
Message-ID: <CAAhV-H5nAwmjNsaA+=iR9EjrTSRogZUaoTcCULoe0YMgbAuFvg@mail.gmail.com>
Subject: Re: [PATCH 2/4 v2] LoongArch: Get stack without NMI when providing
 regs parameter
To: Enze Li <lienze@kylinos.cn>
Cc: kernel@xen0n.name, loongarch@lists.linux.dev, glider@google.com, 
	elver@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, zhangqing@loongson.cn, yangtiezhu@loongson.cn, 
	dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MVtiqIi6;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
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

On Tue, Jul 25, 2023 at 2:15=E2=80=AFPM Enze Li <lienze@kylinos.cn> wrote:
>
> Currently, arch_stack_walk() can only get the full stack information
> including NMI.  This is because the implementation of arch_stack_walk()
> is forced to ignore the information passed by the regs parameter and use
> the current stack information instead.
>
> For some detection systems like KFENCE, only partial stack information
> is needed.  In particular, the stack frame where the interrupt occurred.
>
> To support KFENCE, this patch modifies the implementation of the
> arch_stack_walk() function so that if this function is called with the
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
>  arch/loongarch/kernel/stacktrace.c | 20 ++++++++++++++------
>  1 file changed, 14 insertions(+), 6 deletions(-)
>
> diff --git a/arch/loongarch/kernel/stacktrace.c b/arch/loongarch/kernel/s=
tacktrace.c
> index 2463d2fea21f..9dab30ae68ec 100644
> --- a/arch/loongarch/kernel/stacktrace.c
> +++ b/arch/loongarch/kernel/stacktrace.c
> @@ -18,16 +18,24 @@ void arch_stack_walk(stack_trace_consume_fn consume_e=
ntry, void *cookie,
>         struct pt_regs dummyregs;
>         struct unwind_state state;
>
> -       regs =3D &dummyregs;
We can move the 'if (regs)' logic here and simplify the whole function.

Huacai
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
> -               regs->regs[3] =3D thread_saved_fp(task);
> -               regs->csr_era =3D thread_saved_ra(task);
> +               if (regs)
> +                       memcpy(&dummyregs, regs, sizeof(*regs));
> +               else {
> +                       dummyregs.regs[3] =3D thread_saved_fp(task);
> +                       dummyregs.csr_era =3D thread_saved_ra(task);
> +               }
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
kasan-dev/CAAhV-H5nAwmjNsaA%2B%3DiR9EjrTSRogZUaoTcCULoe0YMgbAuFvg%40mail.gm=
ail.com.
