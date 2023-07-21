Return-Path: <kasan-dev+bncBAABBMWI46SQMGQERYSEQXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 80E8975BBFD
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jul 2023 03:49:40 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-d00a63fcdefsf592255276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jul 2023 18:49:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689904179; cv=pass;
        d=google.com; s=arc-20160816;
        b=IENCiH+PcDXRmwtWEX2umX2rp7WxrPirAd+t/W0GqDrj4PNQhDJg/ZfcCg5Ojf/Za4
         EZlRMN1+XJX8LszPfcdeNfs2QyiSIaUwK7fzAbPQq4fH2etzhefbwEfSI9hAyg3N/ZsT
         7UID4RcKWeDl2kS0aHPheDg0NTXbpG+eI2Ul4AQW/I8MeJ1+nIuWcT26NP1cvrW2YrhP
         UYtUoOQLiOwCvNOhhpFHFH5+zoqVshDdLN9EuiejhuJX7rJtlDtpd4CKzIPhlqIfAysP
         fksG+HGCah+psAld0qfY6GgJajLuGl4AYHT5otXI4qZ9hwjRF0Z0Q9/1sV9NbpS6ofqu
         /xMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=z1j4tFHGkyq9LUEIeAuQoHiEEehTbFPDt68oE9IsxTs=;
        fh=PtPKd2tcWuVtu+yL18J6sFXYyO2PPLg/Xbo07e2JVhk=;
        b=HlFoLphWvuzqVCCbGzCOtzF/BsLeIJZiHco5HZ/jR6nOg41eKbjHwtQYSlhV4oQ5A0
         9CchGmZz9vPRhHa7Eo+HqZM91khT9frNMMAZ/hJTZ262+QnAGIJ2OwgT/rR/I4APud2V
         GOIYsvpTP4MsSxD11x/cm7LTrbOuglfJ2wKnwuVGN238Qa8MymO1WFRY68fuNjJZTY0s
         Hw8y7aHJ3qqGufBkHQMRNaEUS7BQ0MX9POGl1NR9b1m/gG4tKm+d31TBhNGUlbccbiAv
         Y6qeH3ZTDefZYRGFU5XarqHsY6Z3JQRZicx5zYy6loUXBQvqTJSNp8LkwSfvVxNBYKjw
         BJ6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689904179; x=1690508979;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z1j4tFHGkyq9LUEIeAuQoHiEEehTbFPDt68oE9IsxTs=;
        b=BbZGNUiKMbO3p6VDRhQa85T0I6zwbE4D1QKUtIy3XUWKpI+GoCJWSkbpxraJUG4JNL
         BXdSfUCSXpu+MsDoa/Pvd3WgiDW12OvvUe5lKYRG1WK5Q7r4Dw6Omcj66nd+SPnmQXOD
         y6gt6gl38190r5vS5swZoymQKxUuXavv+hslMpI4RMFPphkrHHrtl+QglJrwLLKN9XID
         5UtnF4LQwv6npbtWjiLsu8jrddLvP2hMfVie6QdQQH9Ajljsj7Q/Nw+CcKyqwb4c75z9
         W0zXdGHYNOb5hN19x2yEfnXAOOOJ0qmkxdv3bTPmp+o9gmdbhkHKeqSfS5unPNceqKue
         nGqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689904179; x=1690508979;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=z1j4tFHGkyq9LUEIeAuQoHiEEehTbFPDt68oE9IsxTs=;
        b=gIq7Sp/ziDovkVmk9V/vlSs28invEu1uHkIDdIqf5C1FVXl5wkCDqOebnmAUje+3yE
         nsoWx5o+F7SDWuRRPEvWMyI3akOuHlxXFSp+mqtNQFv2ZfCvBYad0zkf86x+1pYEPsTm
         1DzoeaqfZom0sALfTHJ0kVCa6i49nCWxVBUMA7xCRI4T9VnDpUArkvZKf5RU3cp+Kg6k
         sb9/0bM7gJKbkCIMct3i2CkOBRJ+0KRBF8t5z7N6pGO3n5LlkweoYiQ2/7ba9NMCmU8Y
         XuB6gtFyV200nx+QVCHiLFhHCNgZy0ka8qG18yjY5fEoNpCGrM6R7j1Z5VHUCEd6Snck
         BG6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZt/EkeM/bESO2G+y+exgzAkOyTrtNRVmnIa0UD4fuwCBRzfsRA
	wj4B+N+5oekk8SKkGjScuMw=
X-Google-Smtp-Source: APBJJlF3mEyQObMwminKLVaF/UGvjyFMcEBsBgWZYNTEM7JXmYIVsof7wWtN/ZVR80HfOei6s9DayQ==
X-Received: by 2002:a25:fc20:0:b0:ce9:daac:11a1 with SMTP id v32-20020a25fc20000000b00ce9daac11a1mr624708ybd.46.1689904178566;
        Thu, 20 Jul 2023 18:49:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1244:b0:c59:399a:d1b3 with SMTP id
 t4-20020a056902124400b00c59399ad1b3ls1384450ybu.2.-pod-prod-08-us; Thu, 20
 Jul 2023 18:49:38 -0700 (PDT)
X-Received: by 2002:a81:65c1:0:b0:577:3eaa:8d97 with SMTP id z184-20020a8165c1000000b005773eaa8d97mr845425ywb.17.1689904178000;
        Thu, 20 Jul 2023 18:49:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689904177; cv=none;
        d=google.com; s=arc-20160816;
        b=qa66MBgFG81jAqP9RAs5MMkEMzALuk+4cCrGrQ1w6fcA922wUhGexf/Yq0M/G0KRZP
         fdZfGv5CmKQLd3TtAHYsfwOqk4GpVv3GN5OOQQqrPEtmsjvHSVEPAg6upkicxVZLsdHQ
         qDB/7fD72m0U36G72ZXJxV4KfLrmFqXyGN4llWZYQ2v0p9cvBeWCwG5wHKCs9AfUizfP
         +X2j8j+zGG2hNj1Cm+lGV+whljc6bfnrf1RbI/LUx3CVw4/tMV5Eg7ZcE1aCK+fVMgmF
         ZxHmoTWjI15oV0/XfqSprwUObNsbam+JSY5bCJczRQZgr65YtcUbGiN10mYD39By0qA8
         vjWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from;
        bh=wCYFLxJMwdVHpmPwwehJRwq8rFnMVh4buA99gxXefDA=;
        fh=PtPKd2tcWuVtu+yL18J6sFXYyO2PPLg/Xbo07e2JVhk=;
        b=dbOcby9C7ShNyMx8UCSybxjcpwW9SAGPUfvGQ3dKQBR/qGT5IrQLCHJaFoHfO5ZScO
         r6QoW/yRIR+LKyzcri6pwRPZJzQYh0Ip5q4g4LAOpsWs2+GEUUHRqsPgFanQofyvHH6Z
         rMzOgJo/H4JysVmk+Mv+lDmrzauXZHMMpr4uRE/ccWSh0zufkEyswrVpkgkUJAE34fMD
         BTUEHrEgrRJc1dKmUiAg+s0KP3OcboBBvwVsBzP4FnqCZ6LX7s0JpfkLX7smO8+kGLh4
         IHbFvJUfjNCZ6t/PlO/caniSFy8+t5DXto/y80N+KW4RoYMRiuC3Zpo4q2Tmwe2RLdst
         bI1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id fl5-20020a05690c338500b00565aabff14bsi128761ywb.0.2023.07.20.18.49.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jul 2023 18:49:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 44fc00ce998c430ca28cc240fb33ea67-20230721
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:b0624744-c03f-4a97-b859-c2f46250c0d1,IP:15,
	URL:0,TC:0,Content:-5,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACT
	ION:release,TS:-5
X-CID-INFO: VERSION:1.1.28,REQID:b0624744-c03f-4a97-b859-c2f46250c0d1,IP:15,UR
	L:0,TC:0,Content:-5,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTIO
	N:release,TS:-5
X-CID-META: VersionHash:176cd25,CLOUDID:ac43e88e-7caa-48c2-8dbb-206f0389473c,B
	ulkID:230721094930VGG5JF1A,BulkQuantity:0,Recheck:0,SF:19|44|24|17|102,TC:
	nil,Content:0,EDM:-3,IP:-2,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OS
	I:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI,TF_CID_SPAM_SNR
X-UUID: 44fc00ce998c430ca28cc240fb33ea67-20230721
X-User: lienze@kylinos.cn
Received: from ubuntu [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1944297572; Fri, 21 Jul 2023 09:49:29 +0800
From: Enze Li <lienze@kylinos.cn>
To: Huacai Chen <chenhuacai@kernel.org>
Cc: kernel@xen0n.name,  loongarch@lists.linux.dev,  glider@google.com,
  elver@google.com,  akpm@linux-foundation.org,
  kasan-dev@googlegroups.com,  linux-mm@kvack.org,  zhangqing@loongson.cn,
  yangtiezhu@loongson.cn,  dvyukov@google.com
Subject: Re: [PATCH 2/4] LoongArch: Get stack without NMI when providing
 regs parameter
In-Reply-To: <CAAhV-H5y2cbbzrWtPKPZtP-DwzAq+g=PvEExD=rru1PkQg37dA@mail.gmail.com>
	(Huacai Chen's message of "Wed, 19 Jul 2023 23:17:14 +0800")
References: <20230719082732.2189747-1-lienze@kylinos.cn>
	<20230719082732.2189747-3-lienze@kylinos.cn>
	<CAAhV-H5y2cbbzrWtPKPZtP-DwzAq+g=PvEExD=rru1PkQg37dA@mail.gmail.com>
Date: Fri, 21 Jul 2023 09:49:20 +0800
Message-ID: <87tttyf2zj.fsf@kylinos.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: lienze@kylinos.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as
 permitted sender) smtp.mailfrom=lienze@kylinos.cn
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

Hi Huacai,

Thanks for your review.

On Wed, Jul 19 2023 at 11:17:14 PM +0800, Huacai Chen wrote:

> Hi, Enze,
>
> On Wed, Jul 19, 2023 at 4:34=E2=80=AFPM Enze Li <lienze@kylinos.cn> wrote=
:
>>
>> Currently, executing arch_stack_walk can only get the full stack
>> information including NMI.  This is because the implementation
>> of arch_stack_walk is forced to ignore the information passed by the
>> regs parameter and use the current stack information instead.
>>
>> For some detection systems like KFENCE, only partial stack information
>> is needed.  In particular, the stack frame where the interrupt occurred.
>>
>> To support KFENCE, this patch modifies the implementation of the
>> arch_stack_walk function so that if this function is called with the
>> regs argument passed, it retains all the stack information in regs and
>> uses it to provide accurate information.
>>
>> Before the patch applied, I get,
>> [    1.531195 ] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> [    1.531442 ] BUG: KFENCE: out-of-bounds read in stack_trace_save_regs=
+0x48/0x6c
>> [    1.531442 ]
>> [    1.531900 ] Out-of-bounds read at 0xffff800012267fff (1B left of kfe=
nce-#12):
>> [    1.532046 ]  stack_trace_save_regs+0x48/0x6c
>> [    1.532169 ]  kfence_report_error+0xa4/0x528
>> [    1.532276 ]  kfence_handle_page_fault+0x124/0x270
>> [    1.532388 ]  no_context+0x50/0x94
>> [    1.532453 ]  do_page_fault+0x1a8/0x36c
>> [    1.532524 ]  tlb_do_page_fault_0+0x118/0x1b4
>> [    1.532623 ]  test_out_of_bounds_read+0xa0/0x1d8
>> [    1.532745 ]  kunit_generic_run_threadfn_adapter+0x1c/0x28
>> [    1.532854 ]  kthread+0x124/0x130
>> [    1.532922 ]  ret_from_kernel_thread+0xc/0xa4
>> <snip>
>>
>> With this patch applied, I get the correct stack information.
>> [    1.320220 ] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> [    1.320401 ] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_re=
ad+0xa8/0x1d8
>> [    1.320401 ]
>> [    1.320898 ] Out-of-bounds read at 0xffff800012257fff (1B left of kfe=
nce-#10):
>> [    1.321134 ]  test_out_of_bounds_read+0xa8/0x1d8
>> [    1.321264 ]  kunit_generic_run_threadfn_adapter+0x1c/0x28
>> [    1.321392 ]  kthread+0x124/0x130
>> [    1.321459 ]  ret_from_kernel_thread+0xc/0xa4
>> <snip>
>>
>> Signed-off-by: Enze Li <lienze@kylinos.cn>
>> ---
>>  arch/loongarch/kernel/stacktrace.c | 16 ++++++++++------
>>  1 file changed, 10 insertions(+), 6 deletions(-)
>>
>> diff --git a/arch/loongarch/kernel/stacktrace.c b/arch/loongarch/kernel/=
stacktrace.c
>> index 2463d2fea21f..21f60811e26f 100644
>> --- a/arch/loongarch/kernel/stacktrace.c
>> +++ b/arch/loongarch/kernel/stacktrace.c
>> @@ -18,16 +18,20 @@ void arch_stack_walk(stack_trace_consume_fn consume_=
entry, void *cookie,
>>         struct pt_regs dummyregs;
>>         struct unwind_state state;
>>
>> -       regs =3D &dummyregs;
>> -
>>         if (task =3D=3D current) {
>> -               regs->regs[3] =3D (unsigned long)__builtin_frame_address=
(0);
>> -               regs->csr_era =3D (unsigned long)__builtin_return_addres=
s(0);
>> +               if (regs)
>> +                       memcpy(&dummyregs, regs, sizeof(*regs));
>> +               else {
>> +                       dummyregs.regs[3] =3D (unsigned long)__builtin_f=
rame_address(0);
>> +                       dummyregs.csr_era =3D (unsigned long)__builtin_r=
eturn_address(0);
>> +               }
>>         } else {
> When "task !=3D current", we don't need to handle the "regs !=3D NULL" ca=
se?
>
> Huacai
>

So far, I have not encountered this situation.  I'm not sure what
problems would arise from extending the modifications with "task !=3D
current".

However, these modifications now are sufficient for the KFENCE
system.  I would suggest that we don't modify other parts until we
encounter problems.  This way, we can forge ahead steadily.

Best Regards,
Enze

>> -               regs->regs[3] =3D thread_saved_fp(task);
>> -               regs->csr_era =3D thread_saved_ra(task);
>> +               dummyregs.regs[3] =3D thread_saved_fp(task);
>> +               dummyregs.csr_era =3D thread_saved_ra(task);
>>         }
>>
>> +       regs =3D &dummyregs;
>> +
>>         regs->regs[1] =3D 0;
>>         for (unwind_start(&state, task, regs);
>>              !unwind_done(&state) && !unwind_error(&state); unwind_next_=
frame(&state)) {
>> --
>> 2.34.1
>>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87tttyf2zj.fsf%40kylinos.cn.
