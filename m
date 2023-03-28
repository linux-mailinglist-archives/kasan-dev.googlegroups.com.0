Return-Path: <kasan-dev+bncBAABBAF3ROQQMGQE4SQEQCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id A91866CBF04
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 14:28:49 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id d22-20020a63d716000000b00502e3fb8ff3sf3226702pgg.10
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 05:28:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680006528; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z2xY0dPMIo8QsK0/vHfP0mATGd1q9/iNQx4c219F2V/ZiglG3BdDG8swMWpqV5WIQf
         OZZErv2Y7IgRBqTZFtLkbw86oDinUVBHYCYdB01jsSV3wdT43RNhCdv/CH/Fx+q4Cqsb
         bPScgAyUusqZ1eQAhlVGv/QW2nJS5IfFdsn8hVPHCj9kJI20UzA6SPaia8/xcCLI5OQ9
         5jDBrtcncPIKCARB6rOgfoBCLK1iWXYOiGRo+fBGJm15QDUlwuEmQuSXbI8fcnh2goxs
         GewaLq9zIpJh2aQfqzQ+dH7wNm2WjuA/KlorCfe5vl2idzaAdhSubpwDefYhQPrcAMdc
         RnPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=3u7MbP6aVMv4MofUetwWaJokPH7GXQjEyFdRJn1pS1c=;
        b=nala2LGkkQwJ7IIObM8ApCejjXr6V4AkjpEyCbS85Hw0hoTFOAsnomagV7/L0rt4bK
         R+LR2YikIuPUacHuytT5VZN/guPR4xnX5ajKcguI2dc0e8eRvXtlU7wtEy2SEW7AQFNl
         Tx9mOo64JPJavjduzoNS0S6TXOxPSmEtOkDhhf5gXh63Jw+SnhUdLR6L0b6Gz6hHu49m
         IG+bQLLeugmLYtgOaJLSX0Y2WflqhVkXgJ5mRCveoFWUgr8ousJf3acuq6KhlotU3sgr
         s3QJ/WlhFjgvLMRh0NnQ3Jls9O8FDadh/RMJRFNNfEk7zJRN91zU/f1fex7pembbkotp
         h7jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680006528;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3u7MbP6aVMv4MofUetwWaJokPH7GXQjEyFdRJn1pS1c=;
        b=pXDY4LfV9ip5/vlKDoeNzzakSiQIqPLhyzB98kHvptdoef+oQWVf2yg6Cf1kfnsOkZ
         ieuAbM+OdnTZr/+nIkIAr2vEYeXORWpW+LTpdOH/wByauq9WyeOA4L94sWGWeCPSMdu3
         hkhKMfbV2u74gUN3WbQa/L/IwhIpPVyOyKi8nh8ZMi9/y4+AhAJ3Hzi+GzbCNzJWPJXG
         2uo+Qtsf2cTOaopabS1dA7ppKAU9fTmMTTPlob0r0YBnbRJfuIyRiWKOEfL+Vx/74cnN
         2PvtO7RgrtLuGQAozc54+nODXfpQ/tL/08EtJ5Ljd8KHPW2SKuLqCmrXtY/6iW/6MPM0
         Uwbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680006528;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3u7MbP6aVMv4MofUetwWaJokPH7GXQjEyFdRJn1pS1c=;
        b=BiNmzsAq9DEH1a7V+IH2c6CRogYHLsiOpOaYkUkcpgC0FEFqd7Yl329EOI3Qbkg9/2
         DJ1I/mX9oeIbS6TNvO0ReKOUiMNsuLxE7jaJuADA6CLVXoK9GswMhO/DlMOm+bfwluVp
         4of5IJ/GtnaTLwGbcWr2DWnraWZHm2KveVvHm9dpc911zHkvizQGFamvzBZbzEY21yV7
         KVqnGX8hi2l6Unf9m0NWTKduvlHtuTc5nxCDHVpfjTalL8HFMjGx9eDOHIf2T0G3Jyj6
         r3kwDWmC4PuWu+l8qdfC3tlxZN+tMVIOQKd08CfJalHgWkjfXZ2zoat0Z5r6HH9uymgr
         yk0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9deh1zJBoZmBBv4PYLZ0xaFcnNzjp2/GsY4/HLkIbdvPPKJRAW5
	oecFRd/8Nyazae8GPfryirM=
X-Google-Smtp-Source: AKy350YBXmcTrndFJLSEm81Oek9jq6dIt29Q/fUBIk2G6g0j8M2P0FtX+Jxg2o77eLGCdYi6Lba+Jw==
X-Received: by 2002:a63:3c9:0:b0:50b:cc91:5534 with SMTP id 192-20020a6303c9000000b0050bcc915534mr4200205pgd.2.1680006528150;
        Tue, 28 Mar 2023 05:28:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1ca:b0:1a1:f67e:e4c4 with SMTP id
 e10-20020a17090301ca00b001a1f67ee4c4ls9927205plh.8.-pod-prod-gmail; Tue, 28
 Mar 2023 05:28:46 -0700 (PDT)
X-Received: by 2002:a05:6a20:3b88:b0:d9:250:665c with SMTP id b8-20020a056a203b8800b000d90250665cmr11138178pzh.15.1680006526038;
        Tue, 28 Mar 2023 05:28:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680006526; cv=none;
        d=google.com; s=arc-20160816;
        b=M54vtrVUp2aXmd4YVTONrz8uGfBeO7yTOUuiKCfFnBxZdq2zjxq6O4rWKSvbWm7/8r
         lfNvY6RuuxKhnmkoeTA4z4IW88iS16mEbMASXVfVZSkO4OGJ45JDSDSC7VQJLMUtm9Pt
         /K+ufSKI7hXiF9jZHCbFGz6Rb8o7LRgIhCZzqLjZNuMFtmAK/F8gHAjdtu72BOjIwetD
         G9+IFfo98HGbEF8Poe6YDHUfaBkLHJnkPjqo7TuhTrepLI+ZTwcExUn6ct3RFG5ynG0q
         x0IFHxkx9UGiu3/Yf2AWOud0YN1JhWkEO4dkfXm9/HgKBDmbosTkK7B+0JmKXctsRx15
         poqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=u33+q1bZBtEoiPob9+3IMnbiy0c7902NATlwHrp1ENQ=;
        b=t856HkGodYZCx8kQEEpYsbGBU9k3vNRWWtbyh5Tsp52s3/Lqek6k2dWuxpfoPSxbek
         f/YmwPihSf+LfhiSccu/yNeuU3w/wLWfPb5hOyu1y3XCY5MAYPglgRPnQXNd/C8dYbE2
         63BSFKEiWWWCxb9zUGP3nSu8JvG6G/g3tAY5p7XNBYNY90+hWANu23MbYeQMJkQq37Zp
         aTeHn5Ps5URK6q6ssRRd6vaJrGXVpq4tR49OGD+3yh+Nrp1hHJtXgcCUaG/tLm/vtOLY
         3YSKAgUxaUCOd7XFccwxYY12nn5PCr+A1Ed32ybGuo9WugWW6tLkCNuiNWZwTfHIYHSh
         E4RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id q8-20020a056a00084800b0062d7d718081si223489pfk.2.2023.03.28.05.27.44
        for <kasan-dev@googlegroups.com>;
        Tue, 28 Mar 2023 05:28:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8AxYeUf3SJk3xcTAA--.29441S3;
	Tue, 28 Mar 2023 20:27:11 +0800 (CST)
Received: from [10.130.0.102] (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Cxur0c3SJks2YPAA--.10821S3;
	Tue, 28 Mar 2023 20:27:09 +0800 (CST)
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Youling Tang <tangyouling@loongson.cn>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Jonathan Corbet <corbet@lwn.net>,
 Huacai Chen <chenhuacai@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org
References: <20230328111714.2056-1-zhangqing@loongson.cn>
 <4647c773-c68f-beb3-f61d-4c464259ddf4@loongson.cn>
From: Qing Zhang <zhangqing@loongson.cn>
Message-ID: <5ad9a177-e908-7105-252c-920753d992fb@loongson.cn>
Date: Tue, 28 Mar 2023 20:27:08 +0800
User-Agent: Mozilla/5.0 (X11; Linux mips64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <4647c773-c68f-beb3-f61d-4c464259ddf4@loongson.cn>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: AQAAf8Cxur0c3SJks2YPAA--.10821S3
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvAXoWfWw1fZr4UWFyUtw4UCr4kJFb_yoWrXF43Ko
	WUKr13tr1rJr1UKr15Jw1UJry5Jr1jkrsrJw17Gry7Jr1xAF1UJ3yUJrW5t3yUJry8Gr17
	J3WUJryFyFy8Arn8n29KB7ZKAUJUUUUr529EdanIXcx71UUUUU7KY7ZEXasCq-sGcSsGvf
	J3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnRJU
	UUBFb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2IYs7xG6rWj6s
	0DM7CIcVAFz4kK6r1Y6r17M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0
	Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Gr0_Cr1l84
	ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVCY1x0267AKxVWxJr0_GcWl
	n4kS14v26r1Y6r17M2AIxVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6x
	ACxx1l5I8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1q6rW5McIj6I8E
	87Iv67AKxVW8JVWxJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lc7I2V7IY0V
	AS07AlzVAYIcxG8wCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwCFI7km
	07C267AKxVWrXVW3AwC20s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r
	1rMI8E67AF67kF1VAFwI0_GFv_WrylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVW8
	JVW5JwCI42IY6xIIjxv20xvEc7CjxVAFwI0_Gr0_Cr1lIxAIcVCF04k26cxKx2IYs7xG6r
	1j6r1xMIIF0xvEx4A2jsIE14v26r4j6F4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1U
	YxBIdaVFxhVjvjDU0xZFpf9x07jz2NtUUUUU=
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

On 2023/3/28 =E4=B8=8B=E5=8D=888:08, Youling Tang wrote:
> Hi, Qing
>=20
> On 03/28/2023 07:17 PM, Qing Zhang wrote:
>> 1/8 of kernel addresses reserved for shadow memory. But for LoongArch,
>> There are a lot of holes between different segments and valid address
>> space(256T available) is insufficient to map all these segments to kasan
>> shadow memory with the common formula provided by kasan core, saying
>> addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET
>=20
> If you can provide a virtual memory layout (similar to=20
> Documentation/riscv/vm-layout.rst), it will be convenient for everyone=20
> to review the relevant code, and it will also better explain why=20
> LoongArch needs to implement kasan_mem_to_shadow() separately.

ok, on the way...
I'll add separate patches about the virtual memory layout document in
the future.

Thanks,
-Qing
>=20
> Thanks,
> Youling.
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
>> +#endif
>> +
>> +#endif
>>
>> =C2=A0#endif /* _ASM_STRING_H */
>> diff --git a/arch/loongarch/kernel/Makefile=20
>> b/arch/loongarch/kernel/Makefile
>> index 9a72d91cd104..0055e7582e15 100644
>> --- a/arch/loongarch/kernel/Makefile
>> +++ b/arch/loongarch/kernel/Makefile
>> @@ -30,6 +30,9 @@ ifdef CONFIG_FUNCTION_TRACER
>> =C2=A0=C2=A0 CFLAGS_REMOVE_perf_event.o =3D $(CC_FLAGS_FTRACE)
>> =C2=A0endif
>>
>> +KASAN_SANITIZE_vdso.o :=3D n
>> +KASAN_SANITIZE_efi.o :=3D n
>> +
>> =C2=A0obj-$(CONFIG_MODULES)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 +=
=3D module.o module-sections.o
>> =C2=A0obj-$(CONFIG_STACKTRACE)=C2=A0=C2=A0=C2=A0 +=3D stacktrace.o
>>
>> diff --git a/arch/loongarch/kernel/head.S b/arch/loongarch/kernel/head.S
>> index aa64b179744f..19d4be5c8381 100644
>> --- a/arch/loongarch/kernel/head.S
>> +++ b/arch/loongarch/kernel/head.S
>> @@ -95,13 +95,17 @@ SYM_CODE_START(kernel_entry)=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 # kernel=20
>> entry point
>> =C2=A0=C2=A0=C2=A0=C2=A0 PTR_LI=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 sp, (_THREAD_SIZE - PT_SIZE)
>> =C2=A0=C2=A0=C2=A0=C2=A0 PTR_ADD=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 sp, sp, tp
>> =C2=A0=C2=A0=C2=A0=C2=A0 set_saved_sp=C2=A0=C2=A0=C2=A0 sp, t0, t1
>> -#endif
>> -
>> -=C2=A0=C2=A0=C2=A0 /* relocate_kernel() returns the new kernel entry po=
int */
>> -=C2=A0=C2=A0=C2=A0 jr=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 a0
>> -=C2=A0=C2=A0=C2=A0 ASM_BUG()
>>
>> +=C2=A0=C2=A0=C2=A0 /* Jump to new kernel: new_pc =3D current_pc + rando=
m_offset */
>> +=C2=A0=C2=A0=C2=A0 pcaddi=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 t0,=
 0
>> +=C2=A0=C2=A0=C2=A0 add.d=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 t0, =
t0, a0
>> +=C2=A0=C2=A0=C2=A0 jirl=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 zero,=
 t0, 0xc
>> =C2=A0#endif
>> +#endif
>> +
>> +=C2=A0=C2=A0=C2=A0 #ifdef CONFIG_KASAN
>> +=C2=A0=C2=A0=C2=A0 bl=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_early_init
>> +=C2=A0=C2=A0=C2=A0 #endif
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 bl=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 st=
art_kernel
>> =C2=A0=C2=A0=C2=A0=C2=A0 ASM_BUG()
>> diff --git a/arch/loongarch/kernel/relocate.c=20
>> b/arch/loongarch/kernel/relocate.c
>> index 01f94d1e3edf..6c3eff9af9fb 100644
>> --- a/arch/loongarch/kernel/relocate.c
>> +++ b/arch/loongarch/kernel/relocate.c
>> @@ -157,12 +157,11 @@ static inline void __init=20
>> update_reloc_offset(unsigned long *addr, long random_o
>> =C2=A0=C2=A0=C2=A0=C2=A0 *new_addr =3D (unsigned long)reloc_offset;
>> =C2=A0}
>>
>> -void * __init relocate_kernel(void)
>> +unsigned long __init relocate_kernel(void)
>> =C2=A0{
>> =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long kernel_length;
>> =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long random_offset =3D 0;
>> =C2=A0=C2=A0=C2=A0=C2=A0 void *location_new =3D _text; /* Default to ori=
ginal kernel start */
>> -=C2=A0=C2=A0=C2=A0 void *kernel_entry =3D start_kernel; /* Default to o=
riginal kernel=20
>> entry point */
>> =C2=A0=C2=A0=C2=A0=C2=A0 char *cmdline =3D early_ioremap(fw_arg1, COMMAN=
D_LINE_SIZE); /*=20
>> Boot command line is passed in fw_arg1 */
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 strscpy(boot_command_line, cmdline, COMMAND_LIN=
E_SIZE);
>> @@ -190,9 +189,6 @@ void * __init relocate_kernel(void)
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 reloc_offset +=3D rando=
m_offset;
>>
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Return the new kernel's e=
ntry point */
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kernel_entry =3D RELOCATED_K=
ASLR(start_kernel);
>> -
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* The current thread i=
s now within the relocated kernel */
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __current_thread_info =
=3D RELOCATED_KASLR(__current_thread_info);
>>
>> @@ -204,7 +200,7 @@ void * __init relocate_kernel(void)
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 relocate_absolute(random_offset);
>>
>> -=C2=A0=C2=A0=C2=A0 return kernel_entry;
>> +=C2=A0=C2=A0=C2=A0 return random_offset;
>> =C2=A0}
>>
>> =C2=A0/*
>> diff --git a/arch/loongarch/kernel/setup.c=20
>> b/arch/loongarch/kernel/setup.c
>> index 27f71f9531e1..18453f8cb9e8 100644
>> --- a/arch/loongarch/kernel/setup.c
>> +++ b/arch/loongarch/kernel/setup.c
>> @@ -610,4 +610,8 @@ void __init setup_arch(char **cmdline_p)
>> =C2=A0#endif
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 paging_init();
>> +
>> +#if defined(CONFIG_KASAN)
>> +=C2=A0=C2=A0=C2=A0 kasan_init();
>> +#endif
>> =C2=A0}
>> diff --git a/arch/loongarch/lib/memcpy.S b/arch/loongarch/lib/memcpy.S
>> index 3b7e1dec7109..db92ef7bef3a 100644
>> --- a/arch/loongarch/lib/memcpy.S
>> +++ b/arch/loongarch/lib/memcpy.S
>> @@ -10,16 +10,18 @@
>> =C2=A0#include <asm/export.h>
>> =C2=A0#include <asm/regdef.h>
>>
>> -SYM_FUNC_START(memcpy)
>> +SYM_FUNC_START_WEAK(memcpy)
>> =C2=A0=C2=A0=C2=A0=C2=A0 /*
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Some CPUs support hardware unaligned ac=
cess
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>> =C2=A0=C2=A0=C2=A0=C2=A0 ALTERNATIVE=C2=A0=C2=A0=C2=A0 "b __memcpy_gener=
ic", \
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 "b __memcpy_fast", CPU_FEATURE_UAL
>> =C2=A0SYM_FUNC_END(memcpy)
>> +SYM_FUNC_ALIAS(__memcpy, memcpy)
>> =C2=A0_ASM_NOKPROBE(memcpy)
>>
>> =C2=A0EXPORT_SYMBOL(memcpy)
>> +EXPORT_SYMBOL(__memcpy)
>>
>> =C2=A0/*
>> =C2=A0 * void *__memcpy_generic(void *dst, const void *src, size_t n)
>> diff --git a/arch/loongarch/lib/memmove.S b/arch/loongarch/lib/memmove.S
>> index b796c3d6da05..a2dec5899f5c 100644
>> --- a/arch/loongarch/lib/memmove.S
>> +++ b/arch/loongarch/lib/memmove.S
>> @@ -10,7 +10,7 @@
>> =C2=A0#include <asm/export.h>
>> =C2=A0#include <asm/regdef.h>
>>
>> -SYM_FUNC_START(memmove)
>> +SYM_FUNC_START_WEAK(memmove)
>> =C2=A0=C2=A0=C2=A0=C2=A0 blt=C2=A0=C2=A0=C2=A0 a0, a1, 1f=C2=A0=C2=A0=C2=
=A0 /* dst < src, memcpy */
>> =C2=A0=C2=A0=C2=A0=C2=A0 blt=C2=A0=C2=A0=C2=A0 a1, a0, 3f=C2=A0=C2=A0=C2=
=A0 /* src < dst, rmemcpy */
>> =C2=A0=C2=A0=C2=A0=C2=A0 jr=C2=A0=C2=A0=C2=A0 ra=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 /* dst =3D=3D src, return */
>> @@ -19,27 +19,30 @@ SYM_FUNC_START(memmove)
>> =C2=A01:=C2=A0=C2=A0=C2=A0 ori=C2=A0=C2=A0=C2=A0 a3, zero, 64
>> =C2=A0=C2=A0=C2=A0=C2=A0 sub.d=C2=A0=C2=A0=C2=A0 t0, a1, a0
>> =C2=A0=C2=A0=C2=A0=C2=A0 blt=C2=A0=C2=A0=C2=A0 t0, a3, 2f
>> -=C2=A0=C2=A0=C2=A0 b=C2=A0=C2=A0=C2=A0 memcpy
>> +=C2=A0=C2=A0=C2=A0 b=C2=A0=C2=A0=C2=A0 __memcpy
>> =C2=A02:=C2=A0=C2=A0=C2=A0 b=C2=A0=C2=A0=C2=A0 __memcpy_generic
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 /* if (dst - src) < 64, copy 1 byte at a time *=
/
>> =C2=A03:=C2=A0=C2=A0=C2=A0 ori=C2=A0=C2=A0=C2=A0 a3, zero, 64
>> =C2=A0=C2=A0=C2=A0=C2=A0 sub.d=C2=A0=C2=A0=C2=A0 t0, a0, a1
>> =C2=A0=C2=A0=C2=A0=C2=A0 blt=C2=A0=C2=A0=C2=A0 t0, a3, 4f
>> -=C2=A0=C2=A0=C2=A0 b=C2=A0=C2=A0=C2=A0 rmemcpy
>> +=C2=A0=C2=A0=C2=A0 b=C2=A0=C2=A0=C2=A0 __rmemcpy
>> =C2=A04:=C2=A0=C2=A0=C2=A0 b=C2=A0=C2=A0=C2=A0 __rmemcpy_generic
>> =C2=A0SYM_FUNC_END(memmove)
>> +SYM_FUNC_ALIAS(__memmove, memmove)
>> =C2=A0_ASM_NOKPROBE(memmove)
>>
>> =C2=A0EXPORT_SYMBOL(memmove)
>> +EXPORT_SYMBOL(__memmove)
>> +
>> +SYM_FUNC_START(__rmemcpy)
>>
>> -SYM_FUNC_START(rmemcpy)
>> =C2=A0=C2=A0=C2=A0=C2=A0 /*
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Some CPUs support hardware unaligned ac=
cess
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>> =C2=A0=C2=A0=C2=A0=C2=A0 ALTERNATIVE=C2=A0=C2=A0=C2=A0 "b __rmemcpy_gene=
ric", \
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 "b __rmemcpy_fast", CPU_FEATURE_UAL
>> -SYM_FUNC_END(rmemcpy)
>> +SYM_FUNC_END(__rmemcpy)
>> =C2=A0_ASM_NOKPROBE(rmemcpy)
>>
>> =C2=A0/*
>> diff --git a/arch/loongarch/lib/memset.S b/arch/loongarch/lib/memset.S
>> index a9eb732ab2ad..b5cdbecba8ef 100644
>> --- a/arch/loongarch/lib/memset.S
>> +++ b/arch/loongarch/lib/memset.S
>> @@ -16,16 +16,18 @@
>> =C2=A0=C2=A0=C2=A0=C2=A0 bstrins.d \r0, \r0, 63, 32
>> =C2=A0.endm
>>
>> -SYM_FUNC_START(memset)
>> +SYM_FUNC_START_WEAK(memset)
>> =C2=A0=C2=A0=C2=A0=C2=A0 /*
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Some CPUs support hardware unaligned ac=
cess
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>> =C2=A0=C2=A0=C2=A0=C2=A0 ALTERNATIVE=C2=A0=C2=A0=C2=A0 "b __memset_gener=
ic", \
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 "b __memset_fast", CPU_FEATURE_UAL
>> =C2=A0SYM_FUNC_END(memset)
>> +SYM_FUNC_ALIAS(__memset, memset)
>> =C2=A0_ASM_NOKPROBE(memset)
>>
>> =C2=A0EXPORT_SYMBOL(memset)
>> +EXPORT_SYMBOL(__memset)
>>
>> =C2=A0/*
>> =C2=A0 * void *__memset_generic(void *s, int c, size_t n)
>> diff --git a/arch/loongarch/mm/Makefile b/arch/loongarch/mm/Makefile
>> index 8ffc6383f836..6e50cf6cf733 100644
>> --- a/arch/loongarch/mm/Makefile
>> +++ b/arch/loongarch/mm/Makefile
>> @@ -7,3 +7,5 @@ obj-y=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 +=3D init.o cache.o tlb.o tlbex.o=
=20
>> extable.o \
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 fault.o ioremap.o maccess.o mmap=
.o pgtable.o page.o
>>
>> =C2=A0obj-$(CONFIG_HUGETLB_PAGE)=C2=A0=C2=A0=C2=A0 +=3D hugetlbpage.o
>> +obj-$(CONFIG_KASAN)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 +=3D kasa=
n_init.o
>> +KASAN_SANITIZE_kasan_init.o=C2=A0=C2=A0=C2=A0=C2=A0 :=3D n
>> diff --git a/arch/loongarch/mm/kasan_init.c=20
>> b/arch/loongarch/mm/kasan_init.c
>> new file mode 100644
>> index 000000000000..fb3077f8d508
>> --- /dev/null
>> +++ b/arch/loongarch/mm/kasan_init.c
>> @@ -0,0 +1,255 @@
>> +// SPDX-License-Identifier: GPL-2.0-only
>> +/*
>> + * Copyright (C) 2023 Loongson Technology Corporation Limited
>> + */
>> +#define pr_fmt(fmt) "kasan: " fmt
>> +#include <linux/kasan.h>
>> +#include <linux/memblock.h>
>> +#include <linux/sched/task.h>
>> +
>> +#include <asm/tlbflush.h>
>> +#include <asm/pgalloc.h>
>> +#include <asm-generic/sections.h>
>> +
>> +static pgd_t tmp_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);
>> +
>> +static inline int __p4d_none(int early, p4d_t p4d) {return 0; }
>> +
>> +#ifndef __PAGETABLE_PUD_FOLDED
>> +#define __p4d_none(early, p4d) (early ? (p4d_val(p4d) =3D=3D 0) : \
>> +(__pa(p4d_val(p4d)) =3D=3D (unsigned long)__pa(kasan_early_shadow_pud))=
)
>> +#endif
>> +
>> +#define __pud_none(early, pud) (early ? (pud_val(pud) =3D=3D 0) : \
>> +(__pa(pud_val(pud)) =3D=3D (unsigned long)__pa(kasan_early_shadow_pmd))=
)
>> +
>> +#define __pmd_none(early, pmd) (early ? (pmd_val(pmd) =3D=3D 0) : \
>> +(__pa(pmd_val(pmd)) =3D=3D (unsigned long)__pa(kasan_early_shadow_pte))=
)
>> +
>> +#define __pte_none(early, pte) (early ? pte_none(pte) : \
>> +((pte_val(pte) & _PFN_MASK) =3D=3D (unsigned=20
>> long)__pa(kasan_early_shadow_page)))
>> +
>> +bool kasan_early_stage =3D true;
>> +
>> +/*
>> + * Alloc memory for shadow memory page table.
>> + */
>> +static phys_addr_t __init kasan_alloc_zeroed_page(int node)
>> +{
>> +=C2=A0=C2=A0=C2=A0 void *p =3D memblock_alloc_try_nid(PAGE_SIZE, PAGE_S=
IZE,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __pa(MAX_DMA_ADDRESS),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 MEMBLOCK_ALLOC_ACCESSIBLE, no=
de);
>> +=C2=A0=C2=A0=C2=A0 if (!p)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 panic("%s: Failed to allocat=
e %lu bytes align=3D0x%lx nid=3D%d=20
>> from=3D%llx\n",
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __fu=
nc__, PAGE_SIZE, PAGE_SIZE, node,=20
>> __pa(MAX_DMA_ADDRESS));
>> +=C2=A0=C2=A0=C2=A0 return __pa(p);
>> +}
>> +
>> +static pte_t *kasan_pte_offset(pmd_t *pmdp, unsigned long addr, int=20
>> node,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bool early)
>> +{
>> +=C2=A0=C2=A0=C2=A0 if (__pmd_none(early, READ_ONCE(*pmdp))) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t pte_phys =3D ear=
ly ?
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 __pa_symbol(kasan_early_shadow_pte)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 : kasan_alloc_zeroed_page(nod=
e);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!early)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memc=
py(__va(pte_phys), kasan_early_shadow_pte,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 sizeof(kasan_early_shadow_pte));
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmd_populate_kernel(NULL, pm=
dp, (pte_t *)__va(pte_phys));
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 return pte_offset_kernel(pmdp, addr);
>> +}
>> +
>> +static inline void kasan_set_pgd(pgd_t *pgdp, pgd_t pgdval)
>> +{
>> +=C2=A0=C2=A0=C2=A0 WRITE_ONCE(*pgdp, pgdval);
>> +}
>> +
>> +static pmd_t *kasan_pmd_offset(pud_t *pudp, unsigned long addr, int=20
>> node,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bool early)
>> +{
>> +=C2=A0=C2=A0=C2=A0 if (__pud_none(early, READ_ONCE(*pudp))) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t pmd_phys =3D ear=
ly ?
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 __pa_symbol(kasan_early_shadow_pmd)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 : kasan_alloc_zeroed_page(nod=
e);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!early)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memc=
py(__va(pmd_phys), kasan_early_shadow_pmd,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 sizeof(kasan_early_shadow_pmd));
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_populate(&init_mm, pudp,=
 (pmd_t *)__va(pmd_phys));
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 return pmd_offset(pudp, addr);
>> +}
>> +
>> +static pud_t *__init kasan_pud_offset(p4d_t *p4dp, unsigned long=20
>> addr, int node,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bool =
early)
>> +{
>> +=C2=A0=C2=A0=C2=A0 if (__p4d_none(early, READ_ONCE(*p4dp))) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t pud_phys =3D ear=
ly ?
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __pa=
_symbol(kasan_early_shadow_pud)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 : kasan_alloc_zeroed_page(node);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!early)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memc=
py(__va(pud_phys), kasan_early_shadow_pud,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 sizeof(kasan_early_shadow_pud));
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_populate(&init_mm, p4dp,=
 (pud_t *)__va(pud_phys));
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 return pud_offset(p4dp, addr);
>> +}
>> +
>> +static void=C2=A0 kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long end=
, int node, bool early)
>> +{
>> +=C2=A0=C2=A0=C2=A0 unsigned long next;
>> +=C2=A0=C2=A0=C2=A0 pte_t *ptep =3D kasan_pte_offset(pmdp, addr, node, e=
arly);
>> +
>> +=C2=A0=C2=A0=C2=A0 do {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t page_phys =3D ea=
rly ?
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __pa_symbol(kasan_early_shado=
w_page)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 : kasan_alloc_zeroed_page(node);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D addr + PAGE_SIZE;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pte(ptep, pfn_pte(__phys=
_to_pfn(page_phys), PAGE_KERNEL));
>> +=C2=A0=C2=A0=C2=A0 } while (ptep++, addr =3D next, addr !=3D end && __p=
te_none(early,=20
>> READ_ONCE(*ptep)));
>> +}
>> +
>> +static void kasan_pmd_populate(pud_t *pudp, unsigned long addr,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long end=
, int node, bool early)
>> +{
>> +=C2=A0=C2=A0=C2=A0 unsigned long next;
>> +=C2=A0=C2=A0=C2=A0 pmd_t *pmdp =3D kasan_pmd_offset(pudp, addr, node, e=
arly);
>> +
>> +=C2=A0=C2=A0=C2=A0 do {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D pmd_addr_end(addr, =
end);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_pte_populate(pmdp, add=
r, next, node, early);
>> +=C2=A0=C2=A0=C2=A0 } while (pmdp++, addr =3D next, addr !=3D end && __p=
md_none(early,=20
>> READ_ONCE(*pmdp)));
>> +}
>> +
>> +static void __init kasan_pud_populate(p4d_t *p4dp, unsigned long addr,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsig=
ned long end, int node, bool early)
>> +{
>> +=C2=A0=C2=A0=C2=A0 unsigned long next;
>> +=C2=A0=C2=A0=C2=A0 pud_t *pudp =3D kasan_pud_offset(p4dp, addr, node, e=
arly);
>> +
>> +=C2=A0=C2=A0=C2=A0 do {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D pud_addr_end(addr, =
end);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_pmd_populate(pudp, add=
r, next, node, early);
>> +=C2=A0=C2=A0=C2=A0 } while (pudp++, addr =3D next, addr !=3D end);
>> +}
>> +
>> +static void __init kasan_p4d_populate(pgd_t *pgdp, unsigned long addr,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsig=
ned long end, int node, bool early)
>> +{
>> +=C2=A0=C2=A0=C2=A0 unsigned long next;
>> +=C2=A0=C2=A0=C2=A0 p4d_t *p4dp =3D p4d_offset(pgdp, addr);
>> +
>> +=C2=A0=C2=A0=C2=A0 do {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D p4d_addr_end(addr, =
end);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_pud_populate(p4dp, add=
r, next, node, early);
>> +=C2=A0=C2=A0=C2=A0 } while (p4dp++, addr =3D next, addr !=3D end);
>> +}
>> +
>> +static void __init kasan_pgd_populate(unsigned long addr, unsigned=20
>> long end,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int node, bool ea=
rly)
>> +{
>> +=C2=A0=C2=A0=C2=A0 unsigned long next;
>> +=C2=A0=C2=A0=C2=A0 pgd_t *pgdp;
>> +
>> +=C2=A0=C2=A0=C2=A0 pgdp =3D pgd_offset_k(addr);
>> +
>> +=C2=A0=C2=A0=C2=A0 do {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D pgd_addr_end(addr, =
end);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_p4d_populate(pgdp, add=
r, next, node, early);
>> +=C2=A0=C2=A0=C2=A0 } while (pgdp++, addr =3D next, addr !=3D end);
>> +
>> +}
>> +
>> +asmlinkage void __init kasan_early_init(void)
>> +{
>> +=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_START, PGDIR_S=
IZE));
>> +=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, PGDIR_SIZ=
E));
>> +}
>> +
>> +/* Set up full kasan mappings, ensuring that the mapped pages are=20
>> zeroed */
>> +static void __init kasan_map_populate(unsigned long start, unsigned=20
>> long end,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int node)
>> +{
>> +=C2=A0=C2=A0=C2=A0 kasan_pgd_populate(start & PAGE_MASK, PAGE_ALIGN(end=
), node, false);
>> +}
>> +
>> +static void __init clear_pgds(unsigned long start, unsigned long end)
>> +{
>> +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Remove references to kasan page tables from
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * swapper_pg_dir. pgd_clear() can't be used
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * here because it's nop on 2,3-level pagetable=
 setups
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> +=C2=A0=C2=A0=C2=A0 for (; start < end; start +=3D PGDIR_SIZE)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_set_pgd((pgd_t *)pgd_o=
ffset_k(start), __pgd(0));
>> +}
>> +
>> +void __init kasan_init(void)
>> +{
>> +=C2=A0=C2=A0=C2=A0 u64 i;
>> +=C2=A0=C2=A0=C2=A0 phys_addr_t pa_start, pa_end;
>> +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * PGD was populated as invalid_pmd_table or in=
valid_pud_table
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * in pagetable_init() which depends on how man=
y levels of page
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * table you are using, but we had to clean the=
 gpd of kasan
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * shadow memory, as the pgd value is none-zero=
.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * The assertion pgd_none is going to be false =
and the formal=20
>> populate
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * afterwards is not going to create any new pg=
d at all.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> +=C2=A0=C2=A0=C2=A0 memcpy(tmp_pg_dir, swapper_pg_dir, sizeof(tmp_pg_dir=
));
>> +=C2=A0=C2=A0=C2=A0 __sync();
>> +=C2=A0=C2=A0=C2=A0 csr_write64(__pa_symbol(tmp_pg_dir), LOONGARCH_CSR_P=
GDH);
>> +=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
>> +
>> +=C2=A0=C2=A0=C2=A0 clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
>> +
>> +=C2=A0=C2=A0=C2=A0 /* Maps everything to a single page of zeroes */
>> +=C2=A0=C2=A0=C2=A0 kasan_pgd_populate(KASAN_SHADOW_START, KASAN_SHADOW_=
END,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 NUMA=
_NO_NODE, true);
>> +
>> +=C2=A0=C2=A0=C2=A0 kasan_populate_early_shadow(kasan_mem_to_shadow((voi=
d=20
>> *)MODULES_END),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasa=
n_mem_to_shadow((void *)VMEMMAP_END));
>> +
>> +=C2=A0=C2=A0=C2=A0 if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early_shadow(=
kasan_mem_to_shadow((void=20
>> *)VMALLOC_START),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan=
_mem_to_shadow((void *)VMALLOC_END));
>> +
>> +=C2=A0=C2=A0=C2=A0 kasan_early_stage =3D false;
>> +
>> +=C2=A0=C2=A0=C2=A0 /* Populate the linear mapping */
>> +=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &pa_start, &pa_end) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *start =3D (void *)phys=
_to_virt(pa_start);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *end=C2=A0=C2=A0 =3D (v=
oid *)phys_to_virt(pa_end);
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (start >=3D end)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 brea=
k;
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_map_populate((unsigned=
 long)kasan_mem_to_shadow(start),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (uns=
igned long)kasan_mem_to_shadow(end), NUMA_NO_NODE);
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 /* Populate modules mapping */
>> +=C2=A0=C2=A0=C2=A0 kasan_map_populate((unsigned long)kasan_mem_to_shado=
w((void=20
>> *)MODULES_VADDR),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned long)kasan_mem_to_=
shadow((void *)MODULES_END),=20
>> NUMA_NO_NODE);
>> +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Kasan may reuse the contents of kasan_early_=
shadow_pte=20
>> directly, so we
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * should make sure that it maps the zero page =
read-only.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> +=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < PTRS_PER_PTE; i++)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pte(&kasan_early_shadow_=
pte[i],
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn_=
pte(__phys_to_pfn(__pa_symbol(kasan_early_shadow_page)),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 PAGE_KERNEL_RO));
>> +
>> +=C2=A0=C2=A0=C2=A0 memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>> +=C2=A0=C2=A0=C2=A0=C2=A0 __sync();
>> +=C2=A0=C2=A0=C2=A0 csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_C=
SR_PGDH);
>> +=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
>> +
>> +=C2=A0=C2=A0=C2=A0 /* At this point kasan is fully initialized. Enable =
error=20
>> messages */
>> +=C2=A0=C2=A0=C2=A0 init_task.kasan_depth =3D 0;
>> +=C2=A0=C2=A0=C2=A0 pr_info("KernelAddressSanitizer initialized.\n");
>> +}
>> diff --git a/arch/loongarch/vdso/Makefile b/arch/loongarch/vdso/Makefile
>> index d89e2ac75f7b..df328cd92875 100644
>> --- a/arch/loongarch/vdso/Makefile
>> +++ b/arch/loongarch/vdso/Makefile
>> @@ -1,6 +1,10 @@
>> =C2=A0# SPDX-License-Identifier: GPL-2.0
>> =C2=A0# Objects to go into the VDSO.
>>
>> +ifdef CONFIG_KASAN
>> +KASAN_SANITIZE :=3D n
>> +endif
>> +
>> =C2=A0# Absolute relocation type $(ARCH_REL_TYPE_ABS) needs to be define=
d=20
>> before
>> =C2=A0# the inclusion of generic Makefile.
>> =C2=A0ARCH_REL_TYPE_ABS :=3D=20
>> R_LARCH_32|R_LARCH_64|R_LARCH_MARK_LA|R_LARCH_JUMP_SLOT
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index f7ef70661ce2..3b91b941873d 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -54,11 +54,13 @@ extern p4d_t=20
>> kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>> =C2=A0int kasan_populate_early_shadow(const void *shadow_start,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 const void *shadow_end);
>>
>> +#ifndef __HAVE_ARCH_SHADOW_MAP
>> =C2=A0static inline void *kasan_mem_to_shadow(const void *addr)
>> =C2=A0{
>> =C2=A0=C2=A0=C2=A0=C2=A0 return (void *)((unsigned long)addr >> KASAN_SH=
ADOW_SCALE_SHIFT)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 + KASAN_SHADOW_OFFSET;
>> =C2=A0}
>> +#endif
>>
>> =C2=A0int kasan_add_zero_shadow(void *start, unsigned long size);
>> =C2=A0void kasan_remove_zero_shadow(void *start, unsigned long size);
>> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
>> index e5eef670735e..f86194750df5 100644
>> --- a/mm/kasan/generic.c
>> +++ b/mm/kasan/generic.c
>> @@ -175,6 +175,11 @@ static __always_inline bool=20
>> check_region_inline(unsigned long addr,
>> =C2=A0=C2=A0=C2=A0=C2=A0 if (unlikely(!addr_has_metadata((void *)addr)))
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return !kasan_report(ad=
dr, size, write, ret_ip);
>>
>> +#ifndef __HAVE_ARCH_SHADOW_MAP
>> +=C2=A0=C2=A0=C2=A0 if (unlikely(kasan_mem_to_shadow((unsigned long *)ad=
dr) =3D=3D NULL))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return !kasan_report(addr, s=
ize, write, ret_ip);
>> +#endif
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0 if (likely(!memory_is_poisoned(addr, size)))
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return true;
>>
>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>> index cc64ed6858c6..860061a22ca9 100644
>> --- a/mm/kasan/init.c
>> +++ b/mm/kasan/init.c
>> @@ -166,8 +166,9 @@ static int __ref zero_pud_populate(p4d_t *p4d,=20
>> unsigned long addr,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 if (!p)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -ENOMEM;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 } else {
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 pud_populate(&init_mm, pud,
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 early_alloc(PAGE_SIZE, NUMA_N=
O_NODE));
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 p =3D early_alloc(PAGE_SIZE, NUMA_NO_NODE);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 pmd_init(p);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 pud_populate(&init_mm, pud, p);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 }
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 zero_pmd_populate(pud, =
addr, next);
>> @@ -207,8 +208,9 @@ static int __ref zero_p4d_populate(pgd_t *pgd,=20
>> unsigned long addr,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 if (!p)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -ENOMEM;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 } else {
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 p4d_populate(&init_mm, p4d,
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 early_alloc(PAGE_SIZE, NUMA_N=
O_NODE));
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 p =3D early_alloc(PAGE_SIZE, NUMA_NO_NODE);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 pud_init(p);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 p4d_populate(&init_mm, p4d, p);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 }
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 zero_pud_populate(p4d, =
addr, next);
>> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
>> index a61eeee3095a..033335c13b25 100644
>> --- a/mm/kasan/kasan.h
>> +++ b/mm/kasan/kasan.h
>> @@ -291,16 +291,22 @@ struct kasan_stack_ring {
>>
>> =C2=A0#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>>
>> +#ifndef __HAVE_ARCH_SHADOW_MAP
>> =C2=A0static inline const void *kasan_shadow_to_mem(const void *shadow_a=
ddr)
>> =C2=A0{
>> =C2=A0=C2=A0=C2=A0=C2=A0 return (void *)(((unsigned long)shadow_addr - K=
ASAN_SHADOW_OFFSET)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 << KASAN_SHADOW_SCALE_S=
HIFT);
>> =C2=A0}
>> +#endif
>>
>> =C2=A0static __always_inline bool addr_has_metadata(const void *addr)
>> =C2=A0{
>> +#ifdef __HAVE_ARCH_SHADOW_MAP
>> +=C2=A0=C2=A0=C2=A0 return (kasan_mem_to_shadow((void *)addr) !=3D NULL)=
;
>> +#else
>> =C2=A0=C2=A0=C2=A0=C2=A0 return (kasan_reset_tag(addr) >=3D
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_shadow_to_mem((vo=
id *)KASAN_SHADOW_START));
>> +#endif
>> =C2=A0}
>>
>> =C2=A0/**
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5ad9a177-e908-7105-252c-920753d992fb%40loongson.cn.
