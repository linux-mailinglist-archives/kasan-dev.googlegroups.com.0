Return-Path: <kasan-dev+bncBAABB74XQKTAMGQEEVGFX2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id A4B867628F8
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jul 2023 04:59:13 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-666ecb21fb8sf5588914b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 19:59:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690340352; cv=pass;
        d=google.com; s=arc-20160816;
        b=ocZSueKBlbC6oLANfq1YDB+R/Z/2MR28/tQB9TBoiQZdY66ZS2+uTeAw9qAAv2EiYP
         XqDZOxuPdU5VjjbZvFXoXytC5HKSMN/PcIYc6RelEwPegpFRVX904cTEBwZJIiT3ANNf
         +BKM7nu4Xi8LK/fMF23Oxav21HFCRxk/MAae1k3GT88Z9+ND8CRkFjQD6XyL6Wukmrcg
         GjPSDSzDBEHLTU4HdfVk4kf03QbcnnO4g8kLEKq3uo5mwycJM9iWorZL/xz2ZTogXYAA
         36fF1gGpKc86/KFgX6yCAjsPafJ1iSzyBzsTf2RfAyzUd2sR7KUuH/n28WRZDQU0U3UK
         RmXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=IzZByioVDdByQkkckcU5LAyPq2KV4aibn1VY1ol0ACU=;
        fh=vAoUTeYbtNJxKzC2wiwYJLWQPc3EFDg4lmCWR1m8p3E=;
        b=DERLGMzogJI94WhbBF7qLraEXq2jhbnXH+wArQ4rcrmBBfRoIFXtYyAZrHyUXi4XrU
         /5b8eeQWY2IuI2t/ANtKpRw1Kwze3rBgV/3oMGQNx4c85NZfw5Pj1IDaD3cc/pb0Kyzj
         /dme9HfSmQYXc3n0VetBR8zqJ2J5H66mGILwxqabfaXsPDAQxDrzCVkoxSJeoTbyQIHq
         R6HXskURuGTNXPSa5W8Xt5wOKuiQSBNhxMGQUHTR5u8B5XbKbHvInVKLiUQb6VG8HjCY
         /UASqAv6ag62tbH0L3mdts8IsjuVnMXulvHt3Xn+/AYkY9m4l2N0wkFHLWfZJ6KEx4qk
         bW/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hejinyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=hejinyang@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690340352; x=1690945152;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:content-transfer-encoding
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IzZByioVDdByQkkckcU5LAyPq2KV4aibn1VY1ol0ACU=;
        b=sbMHlN3RoQdd7pJ8OnnvvdSOQLXosR5xHhixlGOs7gg3h0omTdGh8GG0wttIdw/vav
         VzXX93NuBisZYmOQErWQR+ztmI8UBdz/9eeAUGIEUV+kwFmNSvlsOusuIiVH6+NISwhA
         KxlTqCtkI0M63aSRDd8SSbJAEIpJGeNEZu+OrRqEWWMl+3YXI59pXe9MUlu1pIn8CSR/
         MtoVFP00RQwh3AvL5d6ufEz5F7nsT/gXj3vUYvWuGo4YVZZu1doM2vhpDwI7XFUzhIo+
         zyDTxHO/tT/RGxCdTUvbQjUXZdNzYpfKG1NHv5GVreOIUKXynt7S80/Pja8blOku/Cwd
         +rng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690340352; x=1690945152;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IzZByioVDdByQkkckcU5LAyPq2KV4aibn1VY1ol0ACU=;
        b=eLcR9/Io+RuBHwlZb/6XefFLBIE+0LHBA2LWjHNprMcEDjKohKsXkucSiTrZdcostP
         XZSD2qKO0I/liyDiCdcX7ZajdbFQkzIze+pdzBWmtc1T5BZ6DwSx3oPctxou89NnyqPo
         ZV1kRojvor3Qzm0GCJ+smGZKlEb344Jx2+wOD+ElI8OHPS63eL4ExvnMhsBOapbNLSvE
         P4IdDhzIVwtT5tp7cE7eSZxYh7udwGbV6T6Lom2GsS+1/2TVH9HFgP5OS61YUBhg7/ys
         +mcFEeoPN6Fa1PT0qmV/93Ul5cA/YryDgXoHwZez7epSLyStX4LTLS+d9PmV9FHSqZkL
         pn0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaLO5PnrNGqXhGo1m1f/4mqSJDAk2RJtQLA33LKFTH8vulzTiUK
	IZkTbemAO0plUeihKG1JcVM=
X-Google-Smtp-Source: APBJJlGYnZN1Nt94rzExEVHREnptuaHE9+iow38YQxFKGG/lUzd0m9FUjXsIALGE25AfsWXDl1BLQw==
X-Received: by 2002:a05:6a00:1803:b0:67f:3dcd:bc00 with SMTP id y3-20020a056a00180300b0067f3dcdbc00mr1515178pfa.2.1690340351618;
        Tue, 25 Jul 2023 19:59:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9a11:0:b0:686:bbfa:92be with SMTP id w17-20020aa79a11000000b00686bbfa92bels532858pfj.1.-pod-prod-03-us;
 Tue, 25 Jul 2023 19:59:10 -0700 (PDT)
X-Received: by 2002:a05:6a20:9144:b0:138:60e:9ba with SMTP id x4-20020a056a20914400b00138060e09bamr856740pzc.29.1690340350705;
        Tue, 25 Jul 2023 19:59:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690340350; cv=none;
        d=google.com; s=arc-20160816;
        b=DJipI6IWrpcGmS27qBZpC4rcSv3jU6+wylMtQrzE9Mz8nNaY4SLEDqAfmZoEPQWdnh
         fmg9hcv9/AbCl688k0fT8PEuD8Go87Pfil8Y2ttHZ9Pp6uURzerX6F8HJ6vavEW8Emkt
         YZCK8yRtI3GifcKl/PrHSItMxfii93Z/PrR5/YWLWe6wdz4otk2Q0AwNzTgOCjeJcjAr
         Gw108JZR5M2Ecdmmx9sTjd2ilVpzIHmOqtuuONw8uS6cN0m4GqUK2bCbfE41DGbqD9pg
         6KkVNWWI7cIOzyYDsA2EtDukeTqtJ0RbYKcY38rk6clzzuMUTRjDKkuSrF9eDaYptYly
         HoIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=7AjcNNEMn+/GPN1Dc3n/ESxovlmarP5rKOHYISd4E8E=;
        fh=vAoUTeYbtNJxKzC2wiwYJLWQPc3EFDg4lmCWR1m8p3E=;
        b=Yz3U7K06tyC0gQfgqLSpsA5CatVaIOgYKJ6OaIsOBBHOSixpWOEpA3SJjNwwsn/fXk
         1VLqXuD2sakd/z4TXcJww2xzCpiODEHE+kPo2b/K/IpbFo760kZIIGSXNW7UNaDHREx/
         DpMTHOWl1AN8qjqj/UsgFcReLhlMqOU78PkH3NglC4/rAea3p2Zne50LdPRxMYWJOUqC
         xJSmHugZKsHn/+y4B9L8R18qFm/oCuTmOW579A503k/vXjLSrDWhy3bf2TbfnjrvBPYK
         NY2d3beFGQzcS/5xknz2xEiu5ASBmEVDlvmXP+snhK4bEvICiGK88Hpl3nzXzHIUQctl
         0RBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hejinyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=hejinyang@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id eb13-20020a056a004c8d00b00681597da9d7si902499pfb.0.2023.07.25.19.59.09
        for <kasan-dev@googlegroups.com>;
        Tue, 25 Jul 2023 19:59:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of hejinyang@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [111.9.175.10])
	by gateway (Coremail) with SMTP id _____8DxxPD7i8BksQcKAA--.25453S3;
	Wed, 26 Jul 2023 10:59:07 +0800 (CST)
Received: from [10.136.12.26] (unknown [111.9.175.10])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Dx5sz6i8BkwEY7AA--.7565S3;
	Wed, 26 Jul 2023 10:59:07 +0800 (CST)
Subject: Re: [PATCH 2/4 v2] LoongArch: Get stack without NMI when providing
 regs parameter
To: Enze Li <lienze@kylinos.cn>, chenhuacai@kernel.org, kernel@xen0n.name,
 loongarch@lists.linux.dev, glider@google.com, elver@google.com,
 akpm@linux-foundation.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Cc: yangtiezhu@loongson.cn, dvyukov@google.com
References: <20230725061451.1231480-1-lienze@kylinos.cn>
 <20230725061451.1231480-3-lienze@kylinos.cn>
From: Jinyang He <hejinyang@loongson.cn>
Message-ID: <e325ac53-ba3f-db7a-ccc2-5cfadf6462b9@loongson.cn>
Date: Wed, 26 Jul 2023 10:59:06 +0800
User-Agent: Mozilla/5.0 (X11; Linux loongarch64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <20230725061451.1231480-3-lienze@kylinos.cn>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-CM-TRANSID: AQAAf8Dx5sz6i8BkwEY7AA--.7565S3
X-CM-SenderInfo: pkhmx0p1dqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBj93XoWxZr45Wr1UGry5tF47Jw13GFX_yoWrCr1kpr
	Z7CFZ3G3yUZrWIyr17Jr1UXryYyF4vga1UuF1xCa4fGr43JryUt34jgFy5Xr1DCrW8A3yU
	Xry5tF1q9ws0yagCm3ZEXasCq-sJn29KB7ZKAUJUUUU8529EdanIXcx71UUUUU7KY7ZEXa
	sCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU
	0xBIdaVrnRJUUUv0b4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2
	IYs7xG6rWj6s0DM7CIcVAFz4kK6r106r15M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48v
	e4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Jr0_JF4l84ACjcxK6xIIjxv20xvEc7CjxVAFwI
	0_Jr0_Gr1l84ACjcxK6I8E87Iv67AKxVW8JVWxJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_
	Gr0_Gr1UM2AIxVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6xACxx1l5I
	8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87Iv67AK
	xVWUJVW8JwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lc7I2V7IY0VAS07AlzV
	AYIcxG8wCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02F40E
	14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jw0_GFylIx
	kGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv20xvEc7CjxVAF
	wI0_Jr0_Gr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r1j6r
	4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Jr0_GrUvcSsGvfC2KfnxnUUI43ZEXa7IU8czVUUU
	UUU==
X-Original-Sender: hejinyang@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hejinyang@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=hejinyang@loongson.cn
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

On 2023-07-25 14:14, Enze Li wrote:

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
>   arch/loongarch/kernel/stacktrace.c | 20 ++++++++++++++------
>   1 file changed, 14 insertions(+), 6 deletions(-)
>
> diff --git a/arch/loongarch/kernel/stacktrace.c b/arch/loongarch/kernel/s=
tacktrace.c
> index 2463d2fea21f..9dab30ae68ec 100644
> --- a/arch/loongarch/kernel/stacktrace.c
> +++ b/arch/loongarch/kernel/stacktrace.c
> @@ -18,16 +18,24 @@ void arch_stack_walk(stack_trace_consume_fn consume_e=
ntry, void *cookie,
>   	struct pt_regs dummyregs;
>   	struct unwind_state state;
>  =20
> -	regs =3D &dummyregs;
> -
>   	if (task =3D=3D current) {
> -		regs->regs[3] =3D (unsigned long)__builtin_frame_address(0);
> -		regs->csr_era =3D (unsigned long)__builtin_return_address(0);
> +		if (regs)
> +			memcpy(&dummyregs, regs, sizeof(*regs));
> +		else {
> +			dummyregs.regs[3] =3D (unsigned long)__builtin_frame_address(0);
> +			dummyregs.csr_era =3D (unsigned long)__builtin_return_address(0);
> +		}
>   	} else {
> -		regs->regs[3] =3D thread_saved_fp(task);
> -		regs->csr_era =3D thread_saved_ra(task);
> +		if (regs)
> +			memcpy(&dummyregs, regs, sizeof(*regs));
> +		else {
> +			dummyregs.regs[3] =3D thread_saved_fp(task);
> +			dummyregs.csr_era =3D thread_saved_ra(task);
> +		}
>   	}
>  =20
> +	regs =3D &dummyregs;
> +

if (!regs) {
 =C2=A0=C2=A0=C2=A0 regs =3D &dummyregs;

 =C2=A0=C2=A0=C2=A0 if (task =3D=3D current) {
 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 regs->regs[3] =3D (unsigned long)__b=
uiltin_frame_address(0);
 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 regs->csr_era =3D (unsigned long)__b=
uiltin_return_address(0);
 =C2=A0=C2=A0=C2=A0 } else {
 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 regs->regs[3] =3D thread_saved_fp(ta=
sk);
 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 regs->csr_era =3D thread_saved_ra(ta=
sk);
 =C2=A0=C2=A0=C2=A0 }
 =C2=A0=C2=A0=C2=A0 regs->regs[1] =3D 0;
}

BTW, I remembered that __unwind_start() deals with this issue in regs,
task and current. arch_stack_walk() is unnecessary to provide current
or task regs if we fix the unwind_start() skip its parent frame
(caller is arch_stack_walk). But the current state is better, I think.


Thanks,

Jinyang

>   	regs->regs[1] =3D 0;
>   	for (unwind_start(&state, task, regs);
>   	     !unwind_done(&state) && !unwind_error(&state); unwind_next_frame(=
&state)) {

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e325ac53-ba3f-db7a-ccc2-5cfadf6462b9%40loongson.cn.
