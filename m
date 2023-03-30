Return-Path: <kasan-dev+bncBAABBFE4SWQQMGQE5RFG6PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id B56126CFF2C
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 10:53:41 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id j3-20020a17090a94c300b0024018f0656csf5623105pjw.2
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 01:53:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680166420; cv=pass;
        d=google.com; s=arc-20160816;
        b=ID9Kvwrcxr2Tl5hKb0YSqHLvrluqUTrMjZFIh0f+DBj9RV56QKhDg/NVLrgnjVczM5
         G38UZJRsYoLx6MQUv3aQ/m92fxs9m9nTXxQm5D5HNgHqTRsoQ83wcf3jVPf8oB6KHuNX
         hKyhiYwemzyHc0siV2PzYo0YJnH40D45qTFzj1X4KfJ1YrxvvHeIwgXqJUlDl6ankSCg
         a7OszwQdoBMq4t648kVxRMC9jBJGUaV/HyC8FfRexG0w81XLlSLF5nhmR9+J/xEZoafN
         iFjra9lnm+cCPtlL9Fa0mNAwhaC/FFvLIYdu+dKDlyaIYFc60elDdAH5u110wrsnfm51
         +Yxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=UrP06oBZx6hOmH4Ra6En6YfMSt7egFHNJzH8DFc2OR4=;
        b=ssIP1LI7EiaJcllNCkHhxKU+eG2YwfDRFFyVKGB2GTUhXXYtRkGeHUgWRwdqfGIC9w
         Q/LqueRIpxgGR1D2JWzxS5gp8yx9/FfsY2PyzAWloL1z0ADPk8ZtkFPAr1IYDhVheCUC
         RjKUWXWNgKQbjulr6YocTRR5ugA0kOK04oAkHeCfO7JFqMPG9IgN/geZ2L1G0g2jnBjU
         IRS1YMLgHRI1l5aiuREQJ1UDaAAkSV3TTyGSIhLeHr9QN7ULBePvPnlOf3X6di1CVkvQ
         8jfdB/oTIu40ngEOgRaJo5SVS8dr5sxGelKh18UNIouAj7hIaWN/T5ATQeTZT2A2I2a8
         srLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680166420;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UrP06oBZx6hOmH4Ra6En6YfMSt7egFHNJzH8DFc2OR4=;
        b=ebi/FvrVbv6wJS76Mgzbx3DCTy8y1UEOtcZ8hDGEbWy057wz9QHyF/h7VsW0riHuux
         z6ELNeKRIwDoP4XPDNrQ7lLEdQzTF4GsEj5EuvY8l46y8X+m3UroNUKDo/WRteqaMuk2
         fijV+m97pQe9/XdR+/YxSJooiX4DJwgRDraVfKhQoIUCBZwsmohyTLxTomwD9Ql/3tpU
         I/FZIaFHNwQOXsOouul92VR04Bxj8GPQ1TfA4ubBxz4stsD7aiqAGc46Hr1+bSRbkmoM
         +ib7HpiN2/xMdVcb3wrjsHka0GvR8Ie135lXoRo9Rsm5QQzicZZRo9q7RM5Ewh7zC+e+
         5GpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680166420;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UrP06oBZx6hOmH4Ra6En6YfMSt7egFHNJzH8DFc2OR4=;
        b=vnobSXBppL73Ru0t9c4QARHNluJZ6glQGi1YPJW9VCw3DMwVEjwQGn4yyKQMfBj0Tf
         qU8xj+le7GtgeDJFENjqhcNYfSVa3fgP2HXPIYTbu9oxiuECQ8XriF+Q2eyLCCRfj2m9
         HaxSkbqEYAaiw1nbcT5zSIW54fVJrEvmOvFlZcU2isrn8xUOvTgJSupza/sMw5UGjank
         Mpk3Fgp435aqeql8XZs8QncJyBlJ3J+GzviaubiAg9pR/FXttOFqrY/m1Jnzona1ENDP
         AWERT7BhlOqlL9gxIAnziEt2/1PisMkPoK8VbsSxL3s+Ytdrawe4Pepjr7YhM+AJyLoy
         6r8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9cHtKOVaVDGloMzk6/WbdDdIhHrtxSyIo2h/E+fnBVvab7BYqB0
	5Oug8OA5AEklIywedkVP7FQ=
X-Google-Smtp-Source: AKy350YVt5dYC6SkKzXtLXQg3FLh9bLhYPMoj+4fhxK19lW+9WR9I/ipgLF7mSF4VqXcUfBbTJ00ag==
X-Received: by 2002:a05:6a00:1804:b0:62b:f8e9:2a17 with SMTP id y4-20020a056a00180400b0062bf8e92a17mr10558307pfa.3.1680166420188;
        Thu, 30 Mar 2023 01:53:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2144:b0:5e1:f468:a30 with SMTP id
 o4-20020a056a00214400b005e1f4680a30ls476366pfk.1.-pod-prod-gmail; Thu, 30 Mar
 2023 01:53:39 -0700 (PDT)
X-Received: by 2002:aa7:96b8:0:b0:623:53bc:c9a0 with SMTP id g24-20020aa796b8000000b0062353bcc9a0mr19972710pfk.19.1680166419537;
        Thu, 30 Mar 2023 01:53:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680166419; cv=none;
        d=google.com; s=arc-20160816;
        b=Iw3KVShqYRpkf36xNBorFuVUwJRFuENosESiCsnH2id3mAgx1P3/xM8RvLuypYIfGf
         bNcH1mbqL6pOZhfTDiiG77bo3eSdVtEJz31aqstr7sK8wucauSiPbg7xWsO5I7oLptzw
         1qeR0WWs5RJGNKtSwn2f9Lzb9Ahgy8gqJuYvnskZ1TLDRUU7RWANCpQAJkyQv9Biyq3f
         qLV8pcCYVKJCUbLzB56FNo7k0tPFrIa7m4MwN/Ki78ydLsZZBoS0Q75CBmEdJcaS1kaJ
         +iQlZK3+0TJXCQkFUEZA1KS4qOtflAtnKwqZ5sjhgu+YUoePxohJIf7N1oR7TZ8xa/Yz
         9kQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=XiIFc/kJxGUgDO+jUaMUhtl9YzCpioTA0ikTFaf5d+8=;
        b=WgZwtl1B5esBc0SAvLmWaZLuGvdDwoOi9tpCKhowJbPAqLvntRvu/pi0pmA7ZkdJ2W
         pswwMzXO2cajFigg//inAPw4dd2CD+dUf7V9+YSqYXnKnw6VBGrHX05K3Ln9mE0lcBqE
         F63PzCijYgKwUnjiXtXUgArVnlabWc8zmRTpOQcH+W9YUelhCtquyi7dCZnGEJnRwC3B
         dOK1ag5tm/Iv4UQkVSXB6fDsRymkGrkaslfRqSFCL7bQhHrGgcolZKJ2FLX1C1UhG8Tj
         J+igdvXHgXkATwgAi3t+EAbVFvAWIy0oNy5pDiL7RMga4HDnT8iZYetI2ZWAuMKkuBNW
         Karw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id t29-20020a056a00139d00b005a8da742642si1358443pfg.1.2023.03.30.01.53.38
        for <kasan-dev@googlegroups.com>;
        Thu, 30 Mar 2023 01:53:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8Axz__zTSVkaE8UAA--.31292S3;
	Thu, 30 Mar 2023 16:53:07 +0800 (CST)
Received: from [10.130.0.102] (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Axnr7wTSVkvhMRAA--.43030S3;
	Thu, 30 Mar 2023 16:53:06 +0800 (CST)
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Youling Tang <tangyouling@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Jonathan Corbet
 <corbet@lwn.net>, Huacai Chen <chenhuacai@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org
References: <20230328111714.2056-1-zhangqing@loongson.cn>
 <4ad7dfe6-160a-d4a8-e262-1fb13a395510@loongson.cn>
From: Qing Zhang <zhangqing@loongson.cn>
Message-ID: <72bc516f-0ee7-fbf1-7814-8501335b4246@loongson.cn>
Date: Thu, 30 Mar 2023 16:53:03 +0800
User-Agent: Mozilla/5.0 (X11; Linux mips64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <4ad7dfe6-160a-d4a8-e262-1fb13a395510@loongson.cn>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: AQAAf8Axnr7wTSVkvhMRAA--.43030S3
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvAXoW3tF13JFyDCFW3Xr45Xw4rGrg_yoW8XFykJo
	W5KF13tr4rJw47Krs8Xw1DJry5Jr1UCrs7A3y7WryxJF1xAF15C3yUtrWaq3y3JrykGr13
	G3yUGryrAFy8Zrn8n29KB7ZKAUJUUUU8529EdanIXcx71UUUUU7KY7ZEXasCq-sGcSsGvf
	J3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnRJU
	UUv2b4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2IYs7xG6rWj6s
	0DM7CIcVAFz4kK6r106r15M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0
	Y4vE2Ix0cI8IcVAFwI0_Jr0_JF4l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Jr0_Gr1l84
	ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVCY1x0267AKxVWxJr0_GcWl
	e2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44I27wAqx4xG64xvF2
	IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_JrI_JrylYx0Ex4A2jsIE14v26r4j6F4U
	McvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvEwIxGrwCYjI0SjxkI62AI1cAE67vIY487Mx
	AIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr0_
	Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y0x0EwI
	xGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVWUJVW8
	JwCI42IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Gr0_Cr1lIxAIcV
	C2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7IU8I38UUUUUU==
X-Original-Sender: zhangqing@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=zhangqing@loongson.cn
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

Hi, Youling

On 2023/3/30 =E4=B8=8B=E5=8D=882:50, Youling Tang wrote:
> Hi, Qing
>=20
> On 03/28/2023 07:17 PM, Qing Zhang wrote:
>> 1/8 of kernel addresses reserved for shadow memory. But for LoongArch,
>> There are a lot of holes between different segments and valid address
>> space(256T available) is insufficient to map all these segments to kasan
>> shadow memory with the common formula provided by kasan core, saying
>> addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET
>>
>> So Loongarch has a ARCH specific mapping formula,different segments
>> are mapped individually, and only limited length of space of that
>> specific segment is mapped to shadow.
>>
>> At early boot stage the whole shadow region populated with just
>> one physical page (kasan_early_shadow_page). Later, this page is
>> reused as readonly zero shadow for some memory that Kasan currently
>> don't track.
>> After mapping the physical memory, pages for shadow memory are
>> allocated and mapped.
>>
>> Functions like memset/memmove/memcpy do a lot of memory accesses.
>> If bad pointer passed to one of these function it is important
>> to catch this. Compiler's instrumentation cannot do this since
>> these functions are written in assembly.
>> KASan replaces memory functions with manually instrumented variants.
>> Original functions declared as weak symbols so strong definitions
>> in mm/kasan/kasan.c could replace them. Original functions have aliases
>> with '__' prefix in name, so we could call non-instrumented variant
>> if needed.
>>
>> Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
>> ---
>> =C2=A0Documentation/dev-tools/kasan.rst=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 4 +-
>> =C2=A0.../features/debug/KASAN/arch-support.txt=C2=A0=C2=A0=C2=A0=C2=A0 =
|=C2=A0=C2=A0 2 +-
>> =C2=A0arch/loongarch/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 7 +
>> =C2=A0arch/loongarch/include/asm/kasan.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 120 +++++++++
>> =C2=A0arch/loongarch/include/asm/pgtable.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 7 +
>> =C2=A0arch/loongarch/include/asm/setup.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 2 +-
>> =C2=A0arch/loongarch/include/asm/string.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 20 ++
>> =C2=A0arch/loongarch/kernel/Makefile=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 3 +
>> =C2=A0arch/loongarch/kernel/head.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 =
14 +-
>> =C2=A0arch/loongarch/kernel/relocate.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 8 +-
>> =C2=A0arch/loongarch/kernel/setup.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 =
4 +
>> =C2=A0arch/loongarch/lib/memcpy.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=
=A0=C2=A0 4 +-
>> =C2=A0arch/loongarch/lib/memmove.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 =
13 +-
>> =C2=A0arch/loongarch/lib/memset.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=
=A0=C2=A0 4 +-
>> =C2=A0arch/loongarch/mm/Makefile=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 |=C2=A0=C2=A0 2 +
>> =C2=A0arch/loongarch/mm/kasan_init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 255 ++++++++++++++=
++++
>> =C2=A0arch/loongarch/vdso/Makefile=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=
=C2=A0 4 +
>> =C2=A0include/linux/kasan.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 2 +
>> =C2=A0mm/kasan/generic.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 5 +
>> =C2=A0mm/kasan/init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 10 +-
>> =C2=A0mm/kasan/kasan.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 6 +
>> =C2=A021 files changed, 470 insertions(+), 26 deletions(-)
>> =C2=A0create mode 100644 arch/loongarch/include/asm/kasan.h
>> =C2=A0create mode 100644 arch/loongarch/mm/kasan_init.c
>>
>> diff --git a/Documentation/dev-tools/kasan.rst=20
>> b/Documentation/dev-tools/kasan.rst
>> index e66916a483cd..ee91f2872767 100644
>> --- a/Documentation/dev-tools/kasan.rst
>> +++ b/Documentation/dev-tools/kasan.rst
>> @@ -41,8 +41,8 @@ Support
>> =C2=A0Architectures
>> =C2=A0~~~~~~~~~~~~~
>>
>> -Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv,=20
>> s390, and
>> -xtensa, and the tag-based KASAN modes are supported only on arm64.
>> +Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv,=20
>> s390, xtensa,
>> +and loongarch, and the tag-based KASAN modes are supported only on=20
>> arm64.
>>
>> =C2=A0Compilers
>> =C2=A0~~~~~~~~~
>> diff --git a/Documentation/features/debug/KASAN/arch-support.txt=20
>> b/Documentation/features/debug/KASAN/arch-support.txt
>> index bf0124fae643..c4581c2edb28 100644
>> --- a/Documentation/features/debug/KASAN/arch-support.txt
>> +++ b/Documentation/features/debug/KASAN/arch-support.txt
>> @@ -13,7 +13,7 @@
>> =C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 csk=
y: | TODO |
>> =C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0 hexagon: | TODO |
>> =C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ia6=
4: | TODO |
>> -=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 loongarch: | TODO |
>> +=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 loongarch: |=C2=A0 ok=C2=A0 |
>> =C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 m68=
k: | TODO |
>> =C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 microblaze: | TODO |
>> =C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 mip=
s: | TODO |
>> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
>> index 72dd00f48b8c..61f883c51045 100644
>> --- a/arch/loongarch/Kconfig
>> +++ b/arch/loongarch/Kconfig
>> @@ -7,6 +7,7 @@ config LOONGARCH
>> =C2=A0=C2=A0=C2=A0=C2=A0 select ACPI_MCFG if ACPI
>> =C2=A0=C2=A0=C2=A0=C2=A0 select ACPI_SYSTEM_POWER_STATES_SUPPORT=C2=A0=
=C2=A0=C2=A0 if ACPI
>> =C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_BINFMT_ELF_STATE
>> +=C2=A0=C2=A0=C2=A0 select ARCH_DISABLE_KASAN_INLINE
>> =C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_ENABLE_MEMORY_HOTPLUG
>> =C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_ENABLE_MEMORY_HOTREMOVE
>> =C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS_ACPI_TABLE_UPGRADE=C2=A0=C2=A0=
=C2=A0 if ACPI
>> @@ -83,6 +84,7 @@ config LOONGARCH
>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_AUDITSYSCALL
>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_MMAP_RND_BITS if MMU
>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_SECCOMP_FILTER
>> +=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN if 64BIT
>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_TRACEHOOK
>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_TRANSPARENT_HUGEPAGE
>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ASM_MODVERSIONS
>> @@ -626,6 +628,11 @@ config ARCH_MMAP_RND_BITS_MIN
>> =C2=A0config ARCH_MMAP_RND_BITS_MAX
>> =C2=A0=C2=A0=C2=A0=C2=A0 default 18
>>
>> +config KASAN_SHADOW_OFFSET
>> +=C2=A0=C2=A0=C2=A0 hex
>> +=C2=A0=C2=A0=C2=A0 default 0x0
>> +=C2=A0=C2=A0=C2=A0 depends on KASAN
>> +
>> =C2=A0menu "Power management options"
>>
>> =C2=A0config ARCH_SUSPEND_POSSIBLE
>> diff --git a/arch/loongarch/include/asm/kasan.h=20
>> b/arch/loongarch/include/asm/kasan.h
>> new file mode 100644
>> index 000000000000..582bcded311e
>> --- /dev/null
>> +++ b/arch/loongarch/include/asm/kasan.h
>> @@ -0,0 +1,120 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +#ifndef __ASM_KASAN_H
>> +#define __ASM_KASAN_H
>> +
>> +#ifndef __ASSEMBLY__
>> +
>> +#include <linux/linkage.h>
>> +#include <linux/mmzone.h>
>> +#include <asm/addrspace.h>
>> +#include <asm/io.h>
>> +#include <asm/pgtable.h>
>> +
>> +#define __HAVE_ARCH_SHADOW_MAP
>> +
>> +#define KASAN_SHADOW_SCALE_SHIFT 3
>> +#define KASAN_SHADOW_OFFSET=C2=A0=C2=A0=C2=A0 _AC(CONFIG_KASAN_SHADOW_O=
FFSET, UL)
>> +
>> +#define XRANGE_SHIFT (48)
>> +
>> +/* Valid address length */
>> +#define XRANGE_SHADOW_SHIFT=C2=A0=C2=A0=C2=A0 (PGDIR_SHIFT + PAGE_SHIFT=
 - 3)
>> +/* Used for taking out the valid address */
>> +#define XRANGE_SHADOW_MASK=C2=A0=C2=A0=C2=A0 GENMASK_ULL(XRANGE_SHADOW_=
SHIFT - 1, 0)
>> +/* One segment whole address space size */
>> +#define=C2=A0=C2=A0=C2=A0 XRANGE_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 (XRANGE_SHADOW_MASK + 1)
>> +
>> +/* 64-bit segment value. */
>> +#define XKPRANGE_UC_SEG=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (0x80=
00)
>> +#define XKPRANGE_CC_SEG=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (0x90=
00)
>> +#define XKVRANGE_VC_SEG=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (0xff=
ff)
>> +
>> +/* Cached */
>> +#define XKPRANGE_CC_START=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 CAC=
HE_BASE
>> +#define XKPRANGE_CC_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 XRAN=
GE_SIZE
>> +#define XKPRANGE_CC_KASAN_OFFSET=C2=A0=C2=A0=C2=A0 (0)
>> +#define XKPRANGE_CC_SHADOW_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 (XKPRANGE_CC_SIZE >>=20
>> KASAN_SHADOW_SCALE_SHIFT)
>> +#define XKPRANGE_CC_SHADOW_END=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 (XKPRANGE_CC_KASAN_OFFSET +=20
>> XKPRANGE_CC_SHADOW_SIZE)
>> +
>> +/* UnCached */
>> +#define XKPRANGE_UC_START=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 UNC=
ACHE_BASE
>> +#define XKPRANGE_UC_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 XRAN=
GE_SIZE
>> +#define XKPRANGE_UC_KASAN_OFFSET=C2=A0=C2=A0=C2=A0 XKPRANGE_CC_SHADOW_E=
ND
>> +#define XKPRANGE_UC_SHADOW_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 (XKPRANGE_UC_SIZE >>=20
>> KASAN_SHADOW_SCALE_SHIFT)
>> +#define XKPRANGE_UC_SHADOW_END=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 (XKPRANGE_UC_KASAN_OFFSET +=20
>> XKPRANGE_UC_SHADOW_SIZE)
>> +
>> +/* VMALLOC (Cached or UnCached)=C2=A0 */
>> +#define XKVRANGE_VC_START=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 MOD=
ULES_VADDR
>> +#define XKVRANGE_VC_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 roun=
d_up(VMEMMAP_END - MODULES_VADDR=20
>> + 1, PGDIR_SIZE)
>> +#define XKVRANGE_VC_KASAN_OFFSET=C2=A0=C2=A0=C2=A0 XKPRANGE_UC_SHADOW_E=
ND
>> +#define XKVRANGE_VC_SHADOW_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 (XKVRANGE_VC_SIZE >>=20
>> KASAN_SHADOW_SCALE_SHIFT)
>> +#define XKVRANGE_VC_SHADOW_END=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 (XKVRANGE_VC_KASAN_OFFSET +=20
>> XKVRANGE_VC_SHADOW_SIZE)
>> +
>> +/* Kasan shadow memory start right after vmalloc. */
>> +#define KASAN_SHADOW_START=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ro=
und_up(VMEMMAP_END, PGDIR_SIZE)
>> +#define KASAN_SHADOW_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (XK=
VRANGE_VC_SHADOW_END -=20
>> XKPRANGE_CC_KASAN_OFFSET)
>> +#define KASAN_SHADOW_END=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 roun=
d_up(KASAN_SHADOW_START +=20
>> KASAN_SHADOW_SIZE, PGDIR_SIZE)
>> +
>> +#define XKPRANGE_CC_SHADOW_OFFSET=C2=A0=C2=A0=C2=A0 (KASAN_SHADOW_START=
 +=20
>> XKPRANGE_CC_KASAN_OFFSET)
>> +#define XKPRANGE_UC_SHADOW_OFFSET=C2=A0=C2=A0=C2=A0 (KASAN_SHADOW_START=
 +=20
>> XKPRANGE_UC_KASAN_OFFSET)
>> +#define XKVRANGE_VC_SHADOW_OFFSET=C2=A0=C2=A0=C2=A0 (KASAN_SHADOW_START=
 +=20
>> XKVRANGE_VC_KASAN_OFFSET)
>> +
>> +extern bool kasan_early_stage;
>> +extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>> +
>> +static inline void *kasan_mem_to_shadow(const void *addr)
>> +{
>> +=C2=A0=C2=A0=C2=A0 if (kasan_early_stage) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (void *)(kasan_early_=
shadow_page);
>> +=C2=A0=C2=A0=C2=A0 } else {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long maddr =3D (uns=
igned long)addr;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long xrange =3D (ma=
ddr >> XRANGE_SHIFT) & 0xffff;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long offset =3D 0;
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 maddr &=3D XRANGE_SHADOW_MAS=
K;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 switch (xrange) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 case XKPRANGE_CC_SEG:
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 offs=
et =3D XKPRANGE_CC_SHADOW_OFFSET;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 brea=
k;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 case XKPRANGE_UC_SEG:
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 offs=
et =3D XKPRANGE_UC_SHADOW_OFFSET;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 brea=
k;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 case XKVRANGE_VC_SEG:
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 offs=
et =3D XKVRANGE_VC_SHADOW_OFFSET;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 brea=
k;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 default:
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 WARN=
_ON(1);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 retu=
rn NULL;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (void *)((maddr >> KA=
SAN_SHADOW_SCALE_SHIFT) + offset);
>> +=C2=A0=C2=A0=C2=A0 }
>> +}
>> +
>> +static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>> +{
>> +=C2=A0=C2=A0=C2=A0 unsigned long addr =3D (unsigned long)shadow_addr;
>> +
>> +=C2=A0=C2=A0=C2=A0 if (unlikely(addr > KASAN_SHADOW_END) ||
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unlikely(addr < KASAN_SHADOW=
_START)) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 WARN_ON(1);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return NULL;
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 if (addr >=3D XKVRANGE_VC_SHADOW_OFFSET)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (void *)(((addr - XKV=
RANGE_VC_SHADOW_OFFSET) <<=20
>> KASAN_SHADOW_SCALE_SHIFT) + XKVRANGE_VC_START);
>> +=C2=A0=C2=A0=C2=A0 else if (addr >=3D XKPRANGE_UC_SHADOW_OFFSET)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (void *)(((addr - XKP=
RANGE_UC_SHADOW_OFFSET) <<=20
>> KASAN_SHADOW_SCALE_SHIFT) + XKPRANGE_UC_START);
>> +=C2=A0=C2=A0=C2=A0 else if (addr >=3D XKPRANGE_CC_SHADOW_OFFSET)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (void *)(((addr - XKP=
RANGE_CC_SHADOW_OFFSET) <<=20
>> KASAN_SHADOW_SCALE_SHIFT) + XKPRANGE_CC_START);
>> +=C2=A0=C2=A0=C2=A0 else {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 WARN_ON(1);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return NULL;
>> +=C2=A0=C2=A0=C2=A0 }
>> +}
>> +
>> +void kasan_init(void);
>> +asmlinkage void kasan_early_init(void);
>> +
>> +#endif
>> +#endif
>> diff --git a/arch/loongarch/include/asm/pgtable.h=20
>> b/arch/loongarch/include/asm/pgtable.h
>> index d28fb9dbec59..5cfdf79b287e 100644
>> --- a/arch/loongarch/include/asm/pgtable.h
>> +++ b/arch/loongarch/include/asm/pgtable.h
>> @@ -86,9 +86,16 @@ extern unsigned long zero_page_mask;
>> =C2=A0#define MODULES_END=C2=A0=C2=A0=C2=A0 (MODULES_VADDR + SZ_256M)
>>
>> =C2=A0#define VMALLOC_START=C2=A0=C2=A0=C2=A0 MODULES_END
>> +
>> +#ifndef CONFIG_KASAN
>> =C2=A0#define VMALLOC_END=C2=A0=C2=A0=C2=A0 \
>> =C2=A0=C2=A0=C2=A0=C2=A0 (vm_map_base +=C2=A0=C2=A0=C2=A0 \
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PE=
R_PMD * PTRS_PER_PTE *=20
>> PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE)
>> +#else
>> +#define VMALLOC_END=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0 (vm_map_base +=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0=C2=A0 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD=
 * PTRS_PER_PTE *=20
>> PAGE_SIZE, (1UL << cpu_vabits) / 2) - PMD_SIZE - VMEMMAP_SIZE)
>> +#endif
>>
>> =C2=A0#define vmemmap=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ((struct=
 page *)((VMALLOC_END + PMD_SIZE) &=20
>> PMD_MASK))
>> =C2=A0#define VMEMMAP_END=C2=A0=C2=A0=C2=A0 ((unsigned long)vmemmap + VM=
EMMAP_SIZE - 1)
>> diff --git a/arch/loongarch/include/asm/setup.h=20
>> b/arch/loongarch/include/asm/setup.h
>> index be05c0e706a2..2dca0d1dd90a 100644
>> --- a/arch/loongarch/include/asm/setup.h
>> +++ b/arch/loongarch/include/asm/setup.h
>> @@ -33,7 +33,7 @@ extern long __la_abs_end;
>> =C2=A0extern long __rela_dyn_begin;
>> =C2=A0extern long __rela_dyn_end;
>>
>> -extern void * __init relocate_kernel(void);
>> +extern unsigned long __init relocate_kernel(void);
>>
>> =C2=A0#endif
>>
>> diff --git a/arch/loongarch/include/asm/string.h=20
>> b/arch/loongarch/include/asm/string.h
>> index 7b29cc9c70aa..5bb5a90d2681 100644
>> --- a/arch/loongarch/include/asm/string.h
>> +++ b/arch/loongarch/include/asm/string.h
>> @@ -7,11 +7,31 @@
>>
>> =C2=A0#define __HAVE_ARCH_MEMSET
>> =C2=A0extern void *memset(void *__s, int __c, size_t __count);
>> +extern void *__memset(void *__s, int __c, size_t __count);
>>
>> =C2=A0#define __HAVE_ARCH_MEMCPY
>> =C2=A0extern void *memcpy(void *__to, __const__ void *__from, size_t __n=
);
>> +extern void *__memcpy(void *__to, __const__ void *__from, size_t __n);
>>
>> =C2=A0#define __HAVE_ARCH_MEMMOVE
>> =C2=A0extern void *memmove(void *__dest, __const__ void *__src, size_t _=
_n);
>> +extern void *__memmove(void *__dest, __const__ void *__src, size_t __n)=
;
>> +
>> +#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
>> +
>> +/*
>> + * For files that are not instrumented (e.g. mm/slub.c) we
>> + * should use not instrumented version of mem* functions.
>> + */
>> +
>> +#define memset(s, c, n) __memset(s, c, n)
>> +#define memcpy(dst, src, len) __memcpy(dst, src, len)
>> +#define memmove(dst, src, len) __memmove(dst, src, len)
>> +
>> +#ifndef __NO_FORTIFY
>> +#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
>=20
> If we need to add __NO_FORTIFY processing, please add
> ARCH_HAS_FORTIFY_SOURCE in Kconfig, and submit a separate patch like
> 9530141455c9 ("riscv: Add ARCH_HAS_FORTIFY_SOURCE").

Ok, I will add separate patch in v2.

Thanks,
-Qing
>=20
> Youling.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/72bc516f-0ee7-fbf1-7814-8501335b4246%40loongson.cn.
