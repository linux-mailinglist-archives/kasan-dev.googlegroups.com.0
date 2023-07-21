Return-Path: <kasan-dev+bncBAABBXGV46SQMGQEO6HXDJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 43A0F75BC27
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jul 2023 04:18:07 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-55c79a55650sf1128924a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jul 2023 19:18:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689905885; cv=pass;
        d=google.com; s=arc-20160816;
        b=bNmUB9z0CPsJvBXFreYs6+/s4QrJ6KGUksgOJjQqTSIdHHxXfs3xwA5SwwOEIb6g6B
         9B1jCRA3Gk22yUB9wPU7rYudg6ve0TcbpZEd2qRxhz8/zL41yXdk22S+hy8pYI7LjMEc
         Ex4KU2MWE+XleGgIcviUnSimrDED2nHPYGK7zto6JX+5/v+FIYM/Dy487y2ByZnnI4m1
         0bZIajI/ns1Dcu0VWsGhudJRtPLhwfKHVTGRyETxpK3velT1ENdnOBI+dDC6hzgVEv17
         akOd0OgmIDEr/SkFJjMEeMtjaJp4QutsaeMtV6ducYTzBKr/x3GOCnmKn6nqLs34Uu3k
         p50A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=eG3PlV2d9F3P4HI3e/08LeHPTZ3QCAEAVwQaMXaYgYk=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=d8F+ihMe13KuMkWJtYH40f7BFd85t+wC5PtA5nmkFPbJD/wCBIMZAeWXNE+fMcwG9R
         GdnESVJldXtjkIUCLxDZ+cdrrWNCKrBbKwqbNRevsfqGFD6HcGlVMhN55Y5ccEMEgatA
         i3Vgxrito/JRAmh5USLOTY5FLZjHWxc+1N0ehePc1c3euqozfF+RNJnvVmylE2sxfUMr
         OTpeC8FRY0Y7AD8sTAzBou5OYb9ridhI7x5wtqAJjtyue82WiPHqbljFd/lZk5XeG+s+
         5AnO8wI/PYsLC15zy/CkVbAWDMhXqt/TB7kGVicghgehpQqm5LwKHG5T7ojMSO4mraLS
         eAZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O0Q0sK61;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689905885; x=1690510685;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eG3PlV2d9F3P4HI3e/08LeHPTZ3QCAEAVwQaMXaYgYk=;
        b=eYVlebTSp8rBudv+eRdrxL2Oa9gDj385rNxGqmKwydYFuZ7Nks95umeb5MCuwWcuLP
         8fn6xufwmZtq65KWDmmg45qv3cpKlo4T6fGNwrwaZBiEybRHpXXrzGXA+yN4TB/kJP3k
         iwojkcu2XGcQ/GL4BFtl8051LYf4rRHtx9mFBrDbp0bbZT3RxDyGFscSmEwOwtGuJChm
         2rRPKRLiN/xjDDNheIBrftgFz2M4ojwnEpLPxpbW9JrXch6NDrjTt7lFw6llkXxXS3AS
         r5JC2tZyBl3gzVF0HHCfFhvkkkSPhrqENlV6RIopM27hyWqP4NZ7wrI8Gz20Jxr6uIVb
         xcbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689905885; x=1690510685;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eG3PlV2d9F3P4HI3e/08LeHPTZ3QCAEAVwQaMXaYgYk=;
        b=mALxS2ujGEpXEuHwAGlcYwbEfPrS8eba7R4SrQE1OxZgzHy+cuVZHpoQDvw1t3fubs
         rI/jGKpBN2T5b1YS1ByqYE2XUAMjC+LPTuo3zAox2vVLqgN1BmsOTUA7OsNANpnfmSib
         LiJz7X4n46OzwUWiK1HnRd/XwZ96TiVpMuL9UJRW7qPd+vOj7zx5G/nqEmTv7xBStKla
         K2v5gvPXHGEOR5gMlRhC8cZ3ScDvcI6MhmKCs72JB7sDpn2g9HHY/4Vv2vyEeYaRHkzx
         iWb7PflSnuHTgKgoey+Pt4rfBDpi8Tc+RpTrZaVE9a6iHr0oK9ZW4QWoywlSMig82QXr
         Dpng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaog5bVc36LXbdeWnGyOlRYV+r5Zs/AP8hl1ffF0CkMrAttsrZV
	5BkqUS0pssMN1c06NCkoAas=
X-Google-Smtp-Source: APBJJlEqnkIuzIyariZqPDecdniEM3b/O+txqkxYOQCymx8dlfAaD5UeecqrWgr6kQLOstg+JVZesQ==
X-Received: by 2002:a17:902:a986:b0:1b8:76fc:5bf6 with SMTP id bh6-20020a170902a98600b001b876fc5bf6mr628619plb.43.1689905884946;
        Thu, 20 Jul 2023 19:18:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6548:b0:1b8:8dab:64f6 with SMTP id
 d8-20020a170902654800b001b88dab64f6ls746716pln.0.-pod-prod-06-us; Thu, 20 Jul
 2023 19:18:04 -0700 (PDT)
X-Received: by 2002:a17:902:e748:b0:1b6:b805:5ae3 with SMTP id p8-20020a170902e74800b001b6b8055ae3mr889721plf.3.1689905884006;
        Thu, 20 Jul 2023 19:18:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689905883; cv=none;
        d=google.com; s=arc-20160816;
        b=ZRRuW4syx5Y4EJjSpigBirxzgbf8K+eKNOIaCrqZ/mc56ODSZs26tWbBuZxLYvskh+
         y+iswZBAOYPu870amutoxJIoc8vHKHyBdsOx5SuXckryLSl6Vhhgk5RrFr2i8AqCzJma
         X4F6iBAGNU+/6hG+7habQWhMizumu9gk/yo0nJmdVHj0oGkD5oosi84NUwDVfCi5Ucnl
         zFEwww72LPCkhN7It0dXPy/NQaJ6nKZt5oRgRFKfKYknqRhikr94YVUY232Vs051vxKo
         Tvk3UrjqQxp+WfEBhDnBUfXNUb69ucEH1D4zQ5H4NpEceFM5Jaua5UrkDpkzMemBFSL1
         VDxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2pwUjIqWGxpZikfBgBgd87CYfG2HI8r2bvuZKY9Dxs8=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=OVp1HSMnLMqFMxco7oGrJBmCzpprnHFSVfguPWr3szMrOjTy/jmkzGywVNssx+SpLJ
         LByUXUxIyGzFV2YuSDtpikmtOl1h/d0YfneaEHC5EX6Zi40G2T5UMM/u38DC1vrL5gny
         5bF6cvTyt865P/EdcTwCctRjZ9zCFxHu6Elg4s29z6vw5gKiFYSA1Pa0NX22MEXMYsK1
         ejSFJF2gsclTgNAB8EPpwyt1G+VQ3WuwlDXSXMFlPtjBvWjJGfB/bUSK3K9bz+LqxHJG
         KB6elwWsEVroYZ3yhV+pppBzdeXl4rjB8G6xAF4/01gNz4imrsHC4xO1L4deeftjcrpA
         7qng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O0Q0sK61;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id c1-20020a170903234100b001b878f9e121si102742plh.0.2023.07.20.19.18.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Jul 2023 19:18:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 6539161CD6
	for <kasan-dev@googlegroups.com>; Fri, 21 Jul 2023 02:18:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C3ECDC433CB
	for <kasan-dev@googlegroups.com>; Fri, 21 Jul 2023 02:18:02 +0000 (UTC)
Received: by mail-lf1-f44.google.com with SMTP id 2adb3069b0e04-4fbaef9871cso2345317e87.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Jul 2023 19:18:02 -0700 (PDT)
X-Received: by 2002:a05:6512:2826:b0:4fb:76f7:fde9 with SMTP id
 cf38-20020a056512282600b004fb76f7fde9mr369862lfb.30.1689905880781; Thu, 20
 Jul 2023 19:18:00 -0700 (PDT)
MIME-Version: 1.0
References: <20230719082732.2189747-1-lienze@kylinos.cn> <20230719082732.2189747-3-lienze@kylinos.cn>
 <CAAhV-H5y2cbbzrWtPKPZtP-DwzAq+g=PvEExD=rru1PkQg37dA@mail.gmail.com> <87tttyf2zj.fsf@kylinos.cn>
In-Reply-To: <87tttyf2zj.fsf@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Fri, 21 Jul 2023 10:17:48 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4TUnX_mgdn_GUFMvKZeNCi6TSUfpLr-Gr_Vt0m=wGs4g@mail.gmail.com>
Message-ID: <CAAhV-H4TUnX_mgdn_GUFMvKZeNCi6TSUfpLr-Gr_Vt0m=wGs4g@mail.gmail.com>
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
 header.i=@kernel.org header.s=k20201202 header.b=O0Q0sK61;       spf=pass
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

On Fri, Jul 21, 2023 at 9:50=E2=80=AFAM Enze Li <lienze@kylinos.cn> wrote:
>
> Hi Huacai,
>
> Thanks for your review.
>
> On Wed, Jul 19 2023 at 11:17:14 PM +0800, Huacai Chen wrote:
>
> > Hi, Enze,
> >
> > On Wed, Jul 19, 2023 at 4:34=E2=80=AFPM Enze Li <lienze@kylinos.cn> wro=
te:
> >>
> >> Currently, executing arch_stack_walk can only get the full stack
> >> information including NMI.  This is because the implementation
> >> of arch_stack_walk is forced to ignore the information passed by the
> >> regs parameter and use the current stack information instead.
> >>
> >> For some detection systems like KFENCE, only partial stack information
> >> is needed.  In particular, the stack frame where the interrupt occurre=
d.
> >>
> >> To support KFENCE, this patch modifies the implementation of the
> >> arch_stack_walk function so that if this function is called with the
> >> regs argument passed, it retains all the stack information in regs and
> >> uses it to provide accurate information.
> >>
> >> Before the patch applied, I get,
> >> [    1.531195 ] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> [    1.531442 ] BUG: KFENCE: out-of-bounds read in stack_trace_save_re=
gs+0x48/0x6c
> >> [    1.531442 ]
> >> [    1.531900 ] Out-of-bounds read at 0xffff800012267fff (1B left of k=
fence-#12):
> >> [    1.532046 ]  stack_trace_save_regs+0x48/0x6c
> >> [    1.532169 ]  kfence_report_error+0xa4/0x528
> >> [    1.532276 ]  kfence_handle_page_fault+0x124/0x270
> >> [    1.532388 ]  no_context+0x50/0x94
> >> [    1.532453 ]  do_page_fault+0x1a8/0x36c
> >> [    1.532524 ]  tlb_do_page_fault_0+0x118/0x1b4
> >> [    1.532623 ]  test_out_of_bounds_read+0xa0/0x1d8
> >> [    1.532745 ]  kunit_generic_run_threadfn_adapter+0x1c/0x28
> >> [    1.532854 ]  kthread+0x124/0x130
> >> [    1.532922 ]  ret_from_kernel_thread+0xc/0xa4
> >> <snip>
> >>
> >> With this patch applied, I get the correct stack information.
> >> [    1.320220 ] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> [    1.320401 ] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_=
read+0xa8/0x1d8
> >> [    1.320401 ]
> >> [    1.320898 ] Out-of-bounds read at 0xffff800012257fff (1B left of k=
fence-#10):
> >> [    1.321134 ]  test_out_of_bounds_read+0xa8/0x1d8
> >> [    1.321264 ]  kunit_generic_run_threadfn_adapter+0x1c/0x28
> >> [    1.321392 ]  kthread+0x124/0x130
> >> [    1.321459 ]  ret_from_kernel_thread+0xc/0xa4
> >> <snip>
> >>
> >> Signed-off-by: Enze Li <lienze@kylinos.cn>
> >> ---
> >>  arch/loongarch/kernel/stacktrace.c | 16 ++++++++++------
> >>  1 file changed, 10 insertions(+), 6 deletions(-)
> >>
> >> diff --git a/arch/loongarch/kernel/stacktrace.c b/arch/loongarch/kerne=
l/stacktrace.c
> >> index 2463d2fea21f..21f60811e26f 100644
> >> --- a/arch/loongarch/kernel/stacktrace.c
> >> +++ b/arch/loongarch/kernel/stacktrace.c
> >> @@ -18,16 +18,20 @@ void arch_stack_walk(stack_trace_consume_fn consum=
e_entry, void *cookie,
> >>         struct pt_regs dummyregs;
> >>         struct unwind_state state;
> >>
> >> -       regs =3D &dummyregs;
> >> -
> >>         if (task =3D=3D current) {
> >> -               regs->regs[3] =3D (unsigned long)__builtin_frame_addre=
ss(0);
> >> -               regs->csr_era =3D (unsigned long)__builtin_return_addr=
ess(0);
> >> +               if (regs)
> >> +                       memcpy(&dummyregs, regs, sizeof(*regs));
> >> +               else {
> >> +                       dummyregs.regs[3] =3D (unsigned long)__builtin=
_frame_address(0);
> >> +                       dummyregs.csr_era =3D (unsigned long)__builtin=
_return_address(0);
> >> +               }
> >>         } else {
> > When "task !=3D current", we don't need to handle the "regs !=3D NULL" =
case?
> >
> > Huacai
> >
>
> So far, I have not encountered this situation.  I'm not sure what
> problems would arise from extending the modifications with "task !=3D
> current".
>
> However, these modifications now are sufficient for the KFENCE
> system.  I would suggest that we don't modify other parts until we
> encounter problems.  This way, we can forge ahead steadily.
I don't think so. In my opinion, "partial stack information" is a
clear requirement, whether the task is current or not.

So, if  the input regs is not NULL, we should always
memcpy(&dummyregs, regs, sizeof(*regs));

Or we may listen to Tiezhu's idea?

Huacai
>
> Best Regards,
> Enze
>
> >> -               regs->regs[3] =3D thread_saved_fp(task);
> >> -               regs->csr_era =3D thread_saved_ra(task);
> >> +               dummyregs.regs[3] =3D thread_saved_fp(task);
> >> +               dummyregs.csr_era =3D thread_saved_ra(task);
> >>         }
> >>
> >> +       regs =3D &dummyregs;
> >> +
> >>         regs->regs[1] =3D 0;
> >>         for (unwind_start(&state, task, regs);
> >>              !unwind_done(&state) && !unwind_error(&state); unwind_nex=
t_frame(&state)) {
> >> --
> >> 2.34.1
> >>
> >>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H4TUnX_mgdn_GUFMvKZeNCi6TSUfpLr-Gr_Vt0m%3DwGs4g%40mail.gmai=
l.com.
