Return-Path: <kasan-dev+bncBDQ27FVWWUFRBPMO3GCQMGQES4NBUPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 210C83975AA
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jun 2021 16:42:06 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id h10-20020a0cab0a0000b029020282c64ecfsf11672315qvb.19
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jun 2021 07:42:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622558525; cv=pass;
        d=google.com; s=arc-20160816;
        b=D+xPDDo1txCtnqdAuZSuAP0OT6JE9RNFyA+0tpsIIFYvSWPp0ecUwxy6faFACsYYzJ
         Hjz/fKOuz8kwJNc7vRqDT3hXaSBEytUwverT3FaaOjky2V78dzYDI24F4c/sDSJyJAtO
         UjTsmMjCBxBX/dj4pE0DClLiLhFrLBbnW72v+D1vtJSiQ1pAyMnREQ08hO4UST/eLdyy
         WPbC8mNXlMIuZ7qt+0c5o8iVOULuWSzE+S2zqabLGJZHnt0BfcuIg7NVYYFQs2FgxoP8
         c2BOyZwG+fmGw8fsvync2ZZAQh14CyuNcs/fEHMRa74VoYLzdGwYyDvKXvxfuMa09qBM
         OX2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:to:from:sender:dkim-signature;
        bh=WHjz/ZvZyylrJjurCzO/zSGfYtTwyUh47Bt9ZGNPCUg=;
        b=VbxhN8suoijhIX4R20PiZQB+aXY+O36sOYCI1C8upHGgytXtdXAsZwuh48/f5WYIWV
         Vah/lrrzjOvQ2iijPeVhFkYtlbhnJd+OGvPzHkZkzNAZrSy2ju2jSFn/0eePrwgwqOQy
         JgcAf9atnYh5fgsuLpuNFHDsfpuA8EHz3t4kRGKgt6RpM9WTyu9xclCZCQiekVZTI+t6
         VFmGgOvdrL8I3dYnZATtoMviev3rPf9zs+7E0jiBW5G9iFOmCO7z5R5iMq32v1TUoud9
         oUncBgDYUD90Bt0DUPO5n0I6d33NoPmmffaKS3K72Xcy8qDVq57Egvsqda+G/9q4gQwX
         58RQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XWES3O+i;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WHjz/ZvZyylrJjurCzO/zSGfYtTwyUh47Bt9ZGNPCUg=;
        b=f550gO06TuPdhERd2RoR4wdRb/qE2ImhfZCfZXmvNQCwlw1mdtYt9YrRiko3jffswD
         pGk+YGg6qFPYLU51gaU4hqSoBtkaXiRyeaGuKgr0shaFlY3VSMuCjyog8PG1nOunNtIM
         bGN9rURlH4X+dyp+BEQK9CBTMm15sz+vKntrXNlb0oD8WoQanvjOrRd50/aMVMj0X4r0
         TB3yUmAACkcnsk9cTfXKuVSyKQA3G7HzcJjhgux7YbYpwm41d2zUUOwBxSNGX5sdnIm4
         m+5YuPo4DHuIUcbRthRQ4PzrAaGQsCzXbLMiFsxm1RvQkUsJD5HuGFeWHyb3HIpG1nUT
         DNyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WHjz/ZvZyylrJjurCzO/zSGfYtTwyUh47Bt9ZGNPCUg=;
        b=f3Ifbmw+e7AauzL9+LinLq0O5sKPBCnLp+47mhw7gmXF83Xuts7LlvgkjmqKjoOdUF
         HvOqFxS06ZTeHIYHpP/cLpq7YvZZ5+3FzSn4ry7BullZFCzl9pA1joGnHcvdaEjOSE1y
         SmF8XawLYii+qcl356TRgLycFCDXcQvDav0g8a2ovmYSJGIQriRNsrW7MneGrzXN42Mh
         /YNnkJw46bwdJIu49aDaNxzT7LztBPW7ME/GY8D42qOGep3vua4iNh5dXzPYX+bDXdHL
         Que2reTgmmi4Y4uKiI3UhiCzox2r/mvF8pTJDpWqqdnIJyiZWc4GbXKWjROF0JXa7WY4
         70NQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Pfiaq0Ib/scRGfEFRhr0vi7am1DwcxSk29Q/8o+tOfCu5QC/G
	jlucySw+M5uS85AKgxkt/fQ=
X-Google-Smtp-Source: ABdhPJwTekxBsmxKUopI9qhe1lan05Py9SJ6mfuSSKvZIviIfHU+0Ykrqxk63GFPQPsuQft6JpSzcw==
X-Received: by 2002:ac8:5ac2:: with SMTP id d2mr19761532qtd.154.1622558525191;
        Tue, 01 Jun 2021 07:42:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ea15:: with SMTP id f21ls10991173qkg.7.gmail; Tue, 01
 Jun 2021 07:42:04 -0700 (PDT)
X-Received: by 2002:ae9:c110:: with SMTP id z16mr22534925qki.30.1622558524713;
        Tue, 01 Jun 2021 07:42:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622558524; cv=none;
        d=google.com; s=arc-20160816;
        b=rtlaB7rxSbMvItFjtBywcBwaFcga3TBFl9S3SZviqlv/AVN3Sr1iGx+XSiB1uKRBy1
         5ul7V1z4YFN5z87HZBYVpydusq6WqCtR8fz8WP1Z3awEaOnmvt9ui/Xuh2MJuuPh0LRn
         Mvexkm+jqOWjGATH0kS4OElrse1fMdXBBhLoiAMAnQK4NTWUQ0Xll9T3jT71Q9fCuhiW
         xcGG7uBsNDFfHKnCMg6uk/w2i1UcQDz1XycEwet7xbR8+SW7OOnUhs0KB1ft+uIq1O6P
         6Dp8K13cEzmEnGiWG0c/kJmOqS08+A5+kmN8HcrY5/eWZyeIeV96tlbo0PvKkaYFjyKg
         I+nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:to:from
         :dkim-signature;
        bh=g1SoAE64xXP0ozqgBwlWSdkAycLuZY+SSCoJ8hssJgw=;
        b=tcIM+BWbGL7IRk3PWtG1hSI2bcOplBhW96/4I8zpcDH4ZBkgEw77zZu5rnYlLbgyXs
         IQXyC2N1dWztf22ZgSuhj+K4PJQ/V6u6P9DvPFENSzfUpfnqJcPJKr5VRENtNZWR8UGT
         tmDISHrHGj03eGGPZdxn6pggJ9S+bmw11/SWkO3v2b+suB6RWLhzN4wXMU+51pGgbaH8
         l3kp9kk+rNsUGLfkU520xrUtIkhP1lmugh+ftTiDi8Y6dYUG/0UxvzbKHcrPUU5Y3qyf
         nED5wwxVa/TLFAYD10krDrHvK/5MUthgfKgv2IxYZDnEr5jOCQ6mTHcJDQXGFx26CBlf
         nLkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XWES3O+i;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id x24si1745052qkx.3.2021.06.01.07.42.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Jun 2021 07:42:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id e15so7002931plh.1
        for <kasan-dev@googlegroups.com>; Tue, 01 Jun 2021 07:42:04 -0700 (PDT)
X-Received: by 2002:a17:90b:689:: with SMTP id m9mr243555pjz.102.1622558523820;
        Tue, 01 Jun 2021 07:42:03 -0700 (PDT)
Received: from localhost ([101.178.215.23])
        by smtp.gmail.com with ESMTPSA id m12sm13586079pjq.53.2021.06.01.07.42.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Jun 2021 07:42:03 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>, christophe.leroy@csgroup.eu, kasan-dev@googlegroups.com, linuxppc-dev@lists.ozlabs.org
Subject: Re: [PATCH] powerpc: make show_stack's stack walking KASAN-safe
In-Reply-To: <1622539981.k2ctwb25pa.naveen@linux.ibm.com>
References: <20210528074806.1311297-1-dja@axtens.net> <1622539981.k2ctwb25pa.naveen@linux.ibm.com>
Date: Wed, 02 Jun 2021 00:42:00 +1000
Message-ID: <87y2bty7d3.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=XWES3O+i;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::62b as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

"Naveen N. Rao" <naveen.n.rao@linux.ibm.com> writes:

> Daniel Axtens wrote:
>> Make our stack-walking code KASAN-safe by using READ_ONCE_NOCHECK -
>> generic code, arm64, s390 and x86 all do this for similar sorts of
>> reasons: when unwinding a stack, we might touch memory that KASAN has
>> marked as being out-of-bounds. In ppc64 KASAN development, I hit this
>> sometimes when checking for an exception frame - because we're checking
>> an arbitrary offset into the stack frame.
>> 
>> See commit 20955746320e ("s390/kasan: avoid false positives during stack
>> unwind"), commit bcaf669b4bdb ("arm64: disable kasan when accessing
>> frame->fp in unwind_frame"), commit 91e08ab0c851 ("x86/dumpstack:
>> Prevent KASAN false positive warnings") and commit 6e22c8366416
>> ("tracing, kasan: Silence Kasan warning in check_stack of stack_tracer").
>> 
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>> ---
>>  arch/powerpc/kernel/process.c | 16 +++++++++-------
>>  1 file changed, 9 insertions(+), 7 deletions(-)
>> 
>> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.c
>> index 89e34aa273e2..430cf06f9406 100644
>> --- a/arch/powerpc/kernel/process.c
>> +++ b/arch/powerpc/kernel/process.c
>> @@ -2151,8 +2151,8 @@ void show_stack(struct task_struct *tsk, unsigned long *stack,
>>  			break;
>>  
>>  		stack = (unsigned long *) sp;
>> -		newsp = stack[0];
>> -		ip = stack[STACK_FRAME_LR_SAVE];
>> +		newsp = READ_ONCE_NOCHECK(stack[0]);
>> +		ip = READ_ONCE_NOCHECK(stack[STACK_FRAME_LR_SAVE]);
>
> Just curious:
> Given that we validate the stack pointer before these accesses, can we 
> annotate show_stack() with __no_sanitize_address instead?
>
> I ask because we have other places where we walk the stack: 
> arch_stack_walk(), as well as in perf callchain. Similar changes will be 
> needed there as well.

Oh good points. Yes, it probably makes most sense to mark all the
functions with __no_sanitize_address, that resolves Christophe's issue
as well. I'll send a v2.

Kind regards,
Daniel

>
>
> - Naveen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87y2bty7d3.fsf%40dja-thinkpad.axtens.net.
