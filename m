Return-Path: <kasan-dev+bncBDW2JDUY5AORBV67TSBQMGQEWWYBHTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B433352B9D
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Apr 2021 16:53:12 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id e36sf542796wmp.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Apr 2021 07:53:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617375191; cv=pass;
        d=google.com; s=arc-20160816;
        b=EnbP/nzxtFbHiQ96D9jRqFdD8SqKDgAKNGxeGKR5rJu/d9zVq7WM7/jR4KUFnyRo7H
         z0GKD+xCknVe3Q19mazwJn+nGD9EGBU5hpS+a6uYyDw5RO6pVkFntJ20XFvqI5zEtrSW
         yrHdM4Tr5ZbDJkEQF62RsCIYcck/lEIlwVcCFTKl+C1xymJxqz4H+P+MxzuSLEFcTdI7
         67VSeQ5xtarFvSJGm0+mv5uBse3MgbZR+LKFJIqGfQeyuEjoK09VOC92n1IEdW4tmoRN
         3U1D1jkBku0JyjqRmbXbSqTW3iAf6pOerNyKJLeGHzaNJe33LBbEVfmjHChsx6Pl4u7x
         FV7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=LN2I4E9ESPZDof8Jicudd3xiFOMgJQjBlba4KXguZ1g=;
        b=KSHKv05THmyS6S94xVw9HzpsuEFj373hn4kMEmtsovZiqfHbP3o0vOtgw92NgCgUiP
         wRGQg0nsGNsEXZpYTEgaNnWmUq13JOfa6TV41NTMCcq1TYou9EewKyHP/onq2EBcwJ7c
         u1L5WLMUEkYLGaoUD/ViwnhTJAr9p+leMf5DRfwMXV/Dbl42ThgsKGnm7BNG9VpbIoJ8
         /icT4JLpc0kSUatCWVTylwkhNTAR899A604l8ASH6WXYePih24X9GN2q5k76fBZGyvTr
         G0Ae3NxstM3vEOYxEHP/ZsoLHiDPdbIebhCLXbqOCCspP2Tj7Umzc+xxF6PYs/iTinwb
         2d8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="n8v/eyMa";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LN2I4E9ESPZDof8Jicudd3xiFOMgJQjBlba4KXguZ1g=;
        b=n1IB7pNHsfPSZ8QjBUFcM+iEAXCULKfpSEvCKVxYk2Lvg3i5J4hAa+21kPVyUTAd6F
         9Nh9ykMqIvr2NbE7LErV8+hUNWNeHT23RBNn3eiCRdc7yn/6E/6/5K3OVeFDJ2YFlR3q
         OqD73ucG612dcp56q2hJhbziJAPy3i6lq2coqGHfYafI2uLV9nYgJXpwsqgEemNmgPuq
         Ntfo7KsZBNPcv3eiSwLJnqP8UAkqpvfJEVa3ao/Ip/sCVIAQfUcnmAriZ1DW6K9+bJ7b
         jwFTCrcrJYwZK7uqFsZsIXsofkpVAsBijGTXD6LSdSmXNZb9xg5eYBYSrmTre8PaxWdz
         Lkbg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LN2I4E9ESPZDof8Jicudd3xiFOMgJQjBlba4KXguZ1g=;
        b=b7enLO4xWPy8Po/S5Z5bif2lSlbO+/Y6InOApthRhOhxEGvMxROajIlmK9FZZXlmpu
         q9rli2926HK9Ut8psNZ0tWwxqVgLc7IsL3TZhTaksZEdaot3Efr32WY4gIeeA7cg2rw1
         qBK5IKgghW7xdB2Xzh3fzM9QhyF6r2pi9F0Y2eW+nxC9jkwbzzoXbjUtyzhcNcR/SLwi
         x4I12YMDzI1j5hW4IizFC34+Gk6IblSkPCxYUCqWbAXJiBV5fcTtx5zZ2ZjJznltiWq5
         7uq54qLZEYbbNPtF0IfafMvc1dJ/LmpittvG48dYjhKpwjgsQCxm+N27yPIOr1ZrwLai
         +oJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LN2I4E9ESPZDof8Jicudd3xiFOMgJQjBlba4KXguZ1g=;
        b=hiAJWAwyqb/u3tz4e9YgevWBZidSwQow/4zTCBEbPbupoJ2cHVXpPgmmDWEO1BIN24
         1JLj++4u5bTILfnGFOl1mR+4KsBxksBYmr6PcTsfBgAun/PxLRNPbs1om5nB/szQuoRH
         e4HxyOlR+XXqEjUmagbWzIO9V0eRbLfhr/RTLDFgp7PxNWMHeRMG+q/eGJksrPeh52hp
         FC6UEIlSyHVqYpnaH2kpM7W7KxKN9lmG1Suxo9dBZYDsfJJJeun+WHfUqtmAGfTbg7iL
         e8SIMm7c7qp8ch6Zcr/GgcOa/dCpcpIhRrc1hDBQj14IDnZoVo8rdckNGAMKVwCu4eiz
         +kJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532sQbO19fVOpjbvBrfFpu7w4c50Bxo13HthD/oGAHMMrxLADSu2
	NYltSMfjnUePx7YOxWp6RDU=
X-Google-Smtp-Source: ABdhPJygWNgQ3wIs57oM1KPEcFrbI0LavBA10dJfVxiiIfdpWP3UqOQYh/8n9qW2ev56ku+rpphG+A==
X-Received: by 2002:a1c:f404:: with SMTP id z4mr13351424wma.39.1617375191786;
        Fri, 02 Apr 2021 07:53:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6a89:: with SMTP id s9ls157005wru.2.gmail; Fri, 02 Apr
 2021 07:53:11 -0700 (PDT)
X-Received: by 2002:adf:fb42:: with SMTP id c2mr15743150wrs.83.1617375190961;
        Fri, 02 Apr 2021 07:53:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617375190; cv=none;
        d=google.com; s=arc-20160816;
        b=lVxg/akMroFPmdlck8iq0x6YHLrPi8eqQo7lLy6JEAad2gxoSPltXTqANmxpOHahLV
         cXOV7DmDNX1V4qLF5Ep/tjy6MfBo6PGwTspP6wlbl3jc4ZBhty5/pIshMkFjfs8/R7LO
         dy2Mz+Sla2l3H3A1y9XP6WrzE6Tv3OubxP1TafQTv2mdTBY3ETzARN3Dp6BBOjuaFhOM
         bubBFat6t91CASLYy4CwrCk63vekQLFISLYosfMSP+/t3oLdlXE/0PVNO47eHTURkdtq
         9LmGZCAiPQ8JmcUB8tj8TboHTjtsZ4/ti8BP/5UeNAiKySrEBLTiLVIavnDntwcLL8kw
         NVAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A/1WuCFaVg2qZDoIsLGEvJzgk8evknJYEFhCJTn/Qj0=;
        b=UadicwRYh6SE8n2AWXvfpO5TwRnzX6Cm58m8o5O4/XzGKf51ScPKGLQ9OiRYbIFVbe
         rZXwRk2XyRQTZNdNgMIAEf5Mhay9kVF9bWrAD9/ayBkPkGvf0kdxloTl13Vh/0tzH+8T
         RQAxWoihQ1JYiz9zgKAyvgz7TGP2vDvNaqWtKf6Ih0ix7R+m4LvRYVBPXZi14+phTH+H
         a9EGcact18KHAkD4hKYlNXfaheNoPgu43UD0aFAFcNxLuVJkkdILkRLWnR2h1SoWjNdy
         4m1QepaxFFeaX56PrN8hCNba33u5cH2itjv8KJ+DXRMOpzYNUGY5OXjYAH5jvvekYNOi
         dRxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="n8v/eyMa";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id p189si796360wmp.1.2021.04.02.07.53.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Apr 2021 07:53:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id x21so5704261eds.4
        for <kasan-dev@googlegroups.com>; Fri, 02 Apr 2021 07:53:10 -0700 (PDT)
X-Received: by 2002:aa7:ce16:: with SMTP id d22mr15679489edv.95.1617375190744;
 Fri, 02 Apr 2021 07:53:10 -0700 (PDT)
MIME-Version: 1.0
References: <20210331063202.28770-1-qiang.zhang@windriver.com>
In-Reply-To: <20210331063202.28770-1-qiang.zhang@windriver.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 2 Apr 2021 16:52:59 +0200
Message-ID: <CA+fCnZd01XGoVVRwGZnNYDrVPxuWJ_yf7tuNcW-HXfG69fKTbw@mail.gmail.com>
Subject: Re: [PATCH] irq_work: record irq_work_queue() call stack
To: qiang.zhang@windriver.com
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, matthias.bgg@gmail.com, 
	Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, oleg@redhat.com, 
	walter-zh.wu@mediatek.com, frederic@kernel.org, kasan-dev@googlegroups.com, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="n8v/eyMa";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Mar 31, 2021 at 8:32 AM <qiang.zhang@windriver.com> wrote:
>
> From: Zqiang <qiang.zhang@windriver.com>
>
> Add the irq_work_queue() call stack into the KASAN auxiliary
> stack in order to improve KASAN reports. this will let us know
> where the irq work be queued.
>
> Signed-off-by: Zqiang <qiang.zhang@windriver.com>
> ---
>  kernel/irq_work.c | 7 ++++++-
>  1 file changed, 6 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/irq_work.c b/kernel/irq_work.c
> index e8da1e71583a..23a7a0ba1388 100644
> --- a/kernel/irq_work.c
> +++ b/kernel/irq_work.c
> @@ -19,7 +19,7 @@
>  #include <linux/notifier.h>
>  #include <linux/smp.h>
>  #include <asm/processor.h>
> -
> +#include <linux/kasan.h>
>
>  static DEFINE_PER_CPU(struct llist_head, raised_list);
>  static DEFINE_PER_CPU(struct llist_head, lazy_list);
> @@ -70,6 +70,9 @@ bool irq_work_queue(struct irq_work *work)
>         if (!irq_work_claim(work))
>                 return false;
>
> +       /*record irq_work call stack in order to print it in KASAN reports*/
> +       kasan_record_aux_stack(work);
> +
>         /* Queue the entry and raise the IPI if needed. */
>         preempt_disable();
>         __irq_work_queue_local(work);
> @@ -98,6 +101,8 @@ bool irq_work_queue_on(struct irq_work *work, int cpu)
>         if (!irq_work_claim(work))
>                 return false;
>
> +       kasan_record_aux_stack(work);
> +
>         preempt_disable();
>         if (cpu != smp_processor_id()) {
>                 /* Arch remote IPI send/receive backend aren't NMI safe */
> --
> 2.17.1

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd01XGoVVRwGZnNYDrVPxuWJ_yf7tuNcW-HXfG69fKTbw%40mail.gmail.com.
