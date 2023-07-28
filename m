Return-Path: <kasan-dev+bncBAABBWWNRWTAMGQEGNY3ELQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 68B18766494
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jul 2023 08:57:32 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4039eff865fsf746731cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jul 2023 23:57:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690527451; cv=pass;
        d=google.com; s=arc-20160816;
        b=ClqgFHNqYFfOd7EIKv6F16MlBctWJDwr1CZD3NIhwQH9RI23yDHZxmg1D0Roz6UNwA
         swBw1eq8/pp2c9O+dAgfxhkwhrjcMI9QmSoc9kQCnPDdx5KRxAfcsEAIbjAviRy72g/d
         omKsEfQgII0oEC0UdQTwyBRCakTicd5YQLj/hkftdlQdbGElubZXThd5cGoUPKZTPyll
         WE7pq77oLaLpfDgQ2PPWdbz3nLBwgpsW9nd5a4z+fQ4K0LQwaBEijyC3DSpzs2sZNcTL
         4L2Qps4qOwmMQyy+jQRVCN/MUxfISAz4YFRWOAkJX7nDGmQHxUCLn0/P3UpILwsXxFqO
         eKww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=VNEXTMVSgekrJ0GWZgQLA7+hrt2KrMuIFTc0hpt9jnY=;
        fh=jDYuBkFg838PSUW/rvOmMfGTGpsOyGon+Kr8YrdvKJ8=;
        b=VNdOf3bznNdrMULVyQxqGy9xg8nt7LctQPMFmzfcVEwsUuStrqg3C15zN/feSEBq7j
         X294uCHR3C1/eZKbA7nYi7SMrr1nGyA6fkjHpLAWr2n2bqQENlYcAqAlUMOff/NXeH8W
         28lXtgDV5ym6rvasmRgaQOo1DhO0noy40rjCCp+Fe+hKT6WK8dkwWhe5d1Di5GfOdQ5q
         g+3vcoUYs9OyH/8xQ5hLVPVK7/yaQnMqruGGIeM35PgASGDAVBuaPx9JxfwxriSbEdgv
         w9jKI+rrBOejjM0Yz1+PX+LIJFy02ecT2TigMaAmxi3sQ2R9pWrdD23mZP1g1An1IpBZ
         nGng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690527451; x=1691132251;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VNEXTMVSgekrJ0GWZgQLA7+hrt2KrMuIFTc0hpt9jnY=;
        b=qBsmWsGrAfyg5AWTbejbG3H4ZQt3uLTCvEzCbTxltA9y4BXz22hG+ujWB1wj8KM/h2
         de4dRTg1gMBmut4O+TlVPvlYkMOzF95Qz4DwW8gljuIyfy2VwB7C0anNZPERKyXCCogM
         +PbxDQqC/J+kO3tGHvn5w8E517qlGlcho8xlBqgolLMTm19UhBMl/ZaiCVAPMIdLfIHj
         NNEK56m/kAQjz52R6zQxJlziy2Ku08gZPMAjlz6LstC/s/WDuMCAJKIWXlidGPB2Fp9H
         fgAKFxk5Fr0thnOr1JP7rKehI2uZw933B5YAPgrTucn2fvJmhcWFwOre/fVatb43F2zv
         BEpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690527451; x=1691132251;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VNEXTMVSgekrJ0GWZgQLA7+hrt2KrMuIFTc0hpt9jnY=;
        b=Eva84IvpLC1XkRNGOwdvie3WrsAPT1NGKI8Vu7LJWhi6FfqjkPGZGrzNHqfmcc+nVF
         D81keSqYMOHozEjqilow0Nr2mJTWsqYh5fqYKM/hNUemSN1IgXogj/0rYcxe+itJsV6n
         4F4m6yT2CRWcB1ba1A2+CAJD04OkWDm7meXfhCRI0mxD96b5bvxv2w+5g9tnaP4rCm1t
         nPDnZutAZMWPtisO9SHhC+wJK52DpqvvkBa46twAT9k3OxKaNia08FbV0NyAzby4/tqa
         zb+4fMWq9/2uw9dWqqDK+VUL0RWyhUBe9N4yMH8ewOlvR8PlUlQHgxLjOPDgpC7PZl9n
         pf5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYLUKx6Umalvnq1EgRpAseLcd4agdlpEU0OcyyzEu4x9uRCowYf
	ZqaA5HPfctvhYbvzdDRO5ts=
X-Google-Smtp-Source: APBJJlGBZb3NQ0vvZBsI+1BjuVmJLVfpY5kFxOIHsy/UL/H9aVS8vd6hSorZxuc6UQjXFnLUwcP3ig==
X-Received: by 2002:a05:622a:198b:b0:403:dcd4:b9b1 with SMTP id u11-20020a05622a198b00b00403dcd4b9b1mr195463qtc.18.1690527451234;
        Thu, 27 Jul 2023 23:57:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:cd07:0:b0:62f:fb47:5672 with SMTP id b7-20020a0ccd07000000b0062ffb475672ls639359qvm.1.-pod-prod-07-us;
 Thu, 27 Jul 2023 23:57:30 -0700 (PDT)
X-Received: by 2002:a67:fd4f:0:b0:443:5af5:8128 with SMTP id g15-20020a67fd4f000000b004435af58128mr1097581vsr.0.1690527450359;
        Thu, 27 Jul 2023 23:57:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690527450; cv=none;
        d=google.com; s=arc-20160816;
        b=irwwjnP9fgQfiRrajubI0/W8gp56jYFQ3g6i/eDofcfZeSmPmSUz5yH85LX+RccCWu
         58pf4ss0ml9gB1XUH5YCs1BifaRwJDTHyB0/UZ5r848IBInGzUtgIOa9vcqRyAqBZ/bl
         ETR9SawQOQ/gjZNpMn8yfoU750okLx5+bS1ByduaoLARn/NCUw0feXVYCm4BSoidKGhy
         pee8OTABiJ/9obclo6eGDDJNW0HT1duh1l2iQ4rOHsCsD+RxfIbZlgMnSVPXgZrV2Bu/
         uvL9NxZKDj3okmL11nCMy+DWDZyvkqbBQf5iL5NRkdiNr90KLIwaOCaH5JvHIVgqkx1z
         9YYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from;
        bh=zkKcKlDWBfzgHtqCr3ndv+FiHS1Av+omOji43ZX2V1k=;
        fh=jDYuBkFg838PSUW/rvOmMfGTGpsOyGon+Kr8YrdvKJ8=;
        b=EF3P0czn9Nr9jWhScINU+6sqgOuPkGY/z0IbeYdUXTAZOfOhfgCFOwkNw19VfvGtEV
         XxF0fVFHN481EUEmuooT/uBeTwjE3UYam3PeQfdp8cDPPMFQsig+UikMfdZ71azql9co
         AvnIkv7l8GteMoVdBadsYUbIIZJKjlX5e/R17bLgsEsGpB/qjeQRIqwMAgiQnNe8EQRA
         4nuY5pdN0uDepQXE++d1itWrpPQFOlW3gBTN++E1+qO+5BCBeWnY2pUtu+8lEPbc7C9M
         wKo5HwZ1IsOT9luVuJ9CR5uFn2iANVFROw/Ub0ZF6JiyjSxhfrV3pytS93kfekBu1e/8
         5JXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id x22-20020ab036f6000000b0079a2dd67946si113493uau.0.2023.07.27.23.57.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jul 2023 23:57:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: eefb8ffe66a04e8aa2bbd4540826a9fd-20230728
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:a4fd5e3c-7353-42fa-8118-c344962bb5e6,IP:25,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:10
X-CID-INFO: VERSION:1.1.28,REQID:a4fd5e3c-7353-42fa-8118-c344962bb5e6,IP:25,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:10
X-CID-META: VersionHash:176cd25,CLOUDID:fe548d42-d291-4e62-b539-43d7d78362ba,B
	ulkID:230728145721DEQA46GY,BulkQuantity:0,Recheck:0,SF:24|17|19|44|102,TC:
	nil,Content:0,EDM:-3,IP:-2,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OS
	I:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI
X-UUID: eefb8ffe66a04e8aa2bbd4540826a9fd-20230728
Received: from ubuntu [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1316808868; Fri, 28 Jul 2023 14:57:20 +0800
From: Enze Li <lienze@kylinos.cn>
To: Jinyang He <hejinyang@loongson.cn>
Cc: chenhuacai@kernel.org,  kernel@xen0n.name,  loongarch@lists.linux.dev,
  glider@google.com,  elver@google.com,  akpm@linux-foundation.org,
  kasan-dev@googlegroups.com,  linux-mm@kvack.org,  yangtiezhu@loongson.cn,
  dvyukov@google.com
Subject: Re: [PATCH 2/4 v2] LoongArch: Get stack without NMI when providing
 regs parameter
In-Reply-To: <e325ac53-ba3f-db7a-ccc2-5cfadf6462b9@loongson.cn> (Jinyang He's
	message of "Wed, 26 Jul 2023 10:59:06 +0800")
References: <20230725061451.1231480-1-lienze@kylinos.cn>
	<20230725061451.1231480-3-lienze@kylinos.cn>
	<e325ac53-ba3f-db7a-ccc2-5cfadf6462b9@loongson.cn>
Date: Fri, 28 Jul 2023 14:57:11 +0800
Message-ID: <87o7jwa5h4.fsf@kylinos.cn>
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

On Wed, Jul 26 2023 at 10:59:06 AM +0800, Jinyang He wrote:

> On 2023-07-25 14:14, Enze Li wrote:
>
>> Currently, arch_stack_walk() can only get the full stack information
>> including NMI.  This is because the implementation of arch_stack_walk()
>> is forced to ignore the information passed by the regs parameter and use
>> the current stack information instead.
>>
>> For some detection systems like KFENCE, only partial stack information
>> is needed.  In particular, the stack frame where the interrupt occurred.
>>
>> To support KFENCE, this patch modifies the implementation of the
>> arch_stack_walk() function so that if this function is called with the
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
>>   arch/loongarch/kernel/stacktrace.c | 20 ++++++++++++++------
>>   1 file changed, 14 insertions(+), 6 deletions(-)
>>
>> diff --git a/arch/loongarch/kernel/stacktrace.c b/arch/loongarch/kernel/=
stacktrace.c
>> index 2463d2fea21f..9dab30ae68ec 100644
>> --- a/arch/loongarch/kernel/stacktrace.c
>> +++ b/arch/loongarch/kernel/stacktrace.c
>> @@ -18,16 +18,24 @@ void arch_stack_walk(stack_trace_consume_fn consume_=
entry, void *cookie,
>>   	struct pt_regs dummyregs;
>>   	struct unwind_state state;
>>   -	regs =3D &dummyregs;
>> -
>>   	if (task =3D=3D current) {
>> -		regs->regs[3] =3D (unsigned long)__builtin_frame_address(0);
>> -		regs->csr_era =3D (unsigned long)__builtin_return_address(0);
>> +		if (regs)
>> +			memcpy(&dummyregs, regs, sizeof(*regs));
>> +		else {
>> +			dummyregs.regs[3] =3D (unsigned long)__builtin_frame_address(0);
>> +			dummyregs.csr_era =3D (unsigned long)__builtin_return_address(0);
>> +		}
>>   	} else {
>> -		regs->regs[3] =3D thread_saved_fp(task);
>> -		regs->csr_era =3D thread_saved_ra(task);
>> +		if (regs)
>> +			memcpy(&dummyregs, regs, sizeof(*regs));
>> +		else {
>> +			dummyregs.regs[3] =3D thread_saved_fp(task);
>> +			dummyregs.csr_era =3D thread_saved_ra(task);
>> +		}
>>   	}
>>   +	regs =3D &dummyregs;
>> +

Hi Jinyang,

>
> if (!regs) {
> =C2=A0=C2=A0=C2=A0 regs =3D &dummyregs;
>
> =C2=A0=C2=A0=C2=A0 if (task =3D=3D current) {
> =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 regs->regs[3] =3D (unsigned long)__=
builtin_frame_address(0);
> =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 regs->csr_era =3D (unsigned long)__=
builtin_return_address(0);
> =C2=A0=C2=A0=C2=A0 } else {
> =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 regs->regs[3] =3D thread_saved_fp(t=
ask);
> =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 regs->csr_era =3D thread_saved_ra(t=
ask);
> =C2=A0=C2=A0=C2=A0 }
> =C2=A0=C2=A0=C2=A0 regs->regs[1] =3D 0;
> }

Excellent!  FWIW, it looks easy to understand.
I've tested this patch, and it works well.  Thank you.

Cheers!
Enze

>
> BTW, I remembered that __unwind_start() deals with this issue in regs,
> task and current. arch_stack_walk() is unnecessary to provide current
> or task regs if we fix the unwind_start() skip its parent frame
> (caller is arch_stack_walk). But the current state is better, I think.
>
>
> Thanks,
>
> Jinyang
>
>>   	regs->regs[1] =3D 0;
>>   	for (unwind_start(&state, task, regs);
>>   	     !unwind_done(&state) && !unwind_error(&state); unwind_next_frame=
(&state)) {

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87o7jwa5h4.fsf%40kylinos.cn.
