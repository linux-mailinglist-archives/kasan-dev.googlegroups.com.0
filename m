Return-Path: <kasan-dev+bncBC7PZX4C3UKBBBWL23CAMGQEJNTSBJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B79EB1E319
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 09:21:44 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-55b760dc47dsf1259727e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 00:21:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754637703; cv=pass;
        d=google.com; s=arc-20240605;
        b=PvzVzwfXZzEXqEX7grXLMzKP1Q3V9GwDagP1jdQulqRwsdmJk2WVx6Kqn69iYZfR5t
         Ezc9hcYVhLeric6B6Pt+s7RbO59xcx5oF1aQDvQsXK5ZIoWuqUXqbbSB0t6VrO0ozKjF
         pJtSLDCf8mbhSV2CS0UUjPrfqSG1G3qgWGjz1hZyPvX1oDd3dqSCpXxou6HRvPDg4Nm8
         zfyh9NR3nUuuPl0uriGLCmmQ64xqz3KsPYRrGJ2q9AoaGIfbOHfkUDGp3UuWrJ+0gzH3
         hpnEtmHxV0/F4nERjGvUc6pxvY9/4LCuyrHi0cXuhry99Loy3j386M0OTetkRwEaEj88
         dMwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=KsMByUS3tCrrOrhomq8gOGWyYQOWMzTvCr0lsY4s+FU=;
        fh=rQCX9glAt18w8g0LaybQicx6OsH4lq36RnCMVedB5Ks=;
        b=PW3l/is4MuD9ssvRx/Oc++vnYSCAiRZ3ljYnbyjf/zfeMdOXERBzTLD6Vaxfy0KH2p
         7BsE4Fy/N8jqv56Udmp/lC+syF7MKlTiqzT9Hz5y7Ei3/Cry6N7hZYuHbTFrEW1wNMlA
         YHxiWWZDiP/td+w7nkKQPbD2DLAqnVoSvEZtK8mVcG+5YgcQggJX0jITKN4PyrgtMNM6
         mCcqfNnfos5CcQ9wM+IUO8beAjAESXP7yLEPfiDUa2iu/DziZTS908VTXue875yX0yRg
         b8CQ2ngetJU4vuuIB/zHiDXdW93mQsx0s82wSWHi0LZAWQlCKzqbVvQpfXoiwIgRXiPn
         NYzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::224 as permitted sender) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754637703; x=1755242503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KsMByUS3tCrrOrhomq8gOGWyYQOWMzTvCr0lsY4s+FU=;
        b=m39pCKQg4UU7kfdLYaRPiCMBuwSKIPjRhCxlIbqeLGiMSOImbZNmv+L7v0CIfrF3K5
         bdp6gn1g+5t7uwWqPOu5Nh5dJVohjE+ArWrvIUmb9ahRv78PerFGTT07HlAnS78n++ib
         Bq4MuPKdXki5d5QkzwSQqvmqIgPy2ybTfP9L2MGaP1v3w79u9eEbc3FhNMerWbOuV0Qj
         7+0Lg1rBFfu1K3HcbpgA0KKZr7l2rrXMfzQYSjb8Jj0XfXBZF9efcCYDwrqbYsXusn0y
         SDaJiEa0pPAsXUWJ0bZ53C1yFmK812dQg7xPXBkicEGJ2CnXk0nuCpttyvrRGKaMO33F
         hwgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754637703; x=1755242503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KsMByUS3tCrrOrhomq8gOGWyYQOWMzTvCr0lsY4s+FU=;
        b=C8esYAHTtCxp+0AAXA0BDxksIw4n9t6QBkleAYaAt/gESf+DeNlfwI8nMHkLuYcy8E
         vh23tmcsGlzmXwyO9dRnxNxSJSVb9N3nxqZ0r3S+TKfA7cidM7if4gMm2J/mzY1uvpv2
         ElH8JiwFOI0AIhwPf0Um2R3+4cBgxLquL1JqSTobE4eMQkZcw2x+YHATvsyoSMMsHN2m
         h/VtqQw3OrAyzoMcrL3pWLXe2iUCbwQgTn9SorgAYaLkb+DEdEHkhU2Wk4LLhkk+fjs2
         58HnYK/slajCj+CZYeUtaZqglEViLiHUXySUuL3JBEwqv6DnRfemfwb0u5Wcqp9MUWNW
         MK6Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWN/n68P4/dK7k3XDrqbJEIIGi94F7x5NGqOfgO6hs6MOKHbdK12Q3RJPZO6GtgqyFaedecLA==@lfdr.de
X-Gm-Message-State: AOJu0YxkcnLxSJTUMxliu5wJRS/JNtDJzYGseUk+z9uk5tUcOjLruGcq
	oxiCX9L+TzvljSz5ryw9CifV204laN2QpfVlSKvpBxaonFcwPoDc4Iki
X-Google-Smtp-Source: AGHT+IH78YELmQmL7NkuUmZz5RC+Su9YMUJqtetd8dO7aid8CgFr4Y1lO/a8rxInMEghilrpV4p4AA==
X-Received: by 2002:a05:6512:3caa:b0:55b:7338:f999 with SMTP id 2adb3069b0e04-55cc0094f66mr504093e87.7.1754637703024;
        Fri, 08 Aug 2025 00:21:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZesTaNgqm+NLk//0epVQRBFBRACeYld+XC3ORXdXX+LLA==
Received: by 2002:a05:6512:2397:b0:55b:72ad:e16d with SMTP id
 2adb3069b0e04-55cb5ea8e8els729670e87.0.-pod-prod-04-eu; Fri, 08 Aug 2025
 00:21:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAhSqO7hZ8Zd+FSuwST3Xjq6KF97xTsyh1uUg9D05vECWI/WhEU/UWK6KWf8d4lydsO57o7HS3BCg=@googlegroups.com
X-Received: by 2002:a05:6512:130e:b0:55b:842d:5828 with SMTP id 2adb3069b0e04-55cc01199ffmr516986e87.36.1754637699581;
        Fri, 08 Aug 2025 00:21:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754637699; cv=none;
        d=google.com; s=arc-20240605;
        b=OGpn0E0D/lPptqZNp4z79z2mjyAFm0HZ5Tyt2vHfi4RCF9/RtmYv2Tl3pUebGSxqS7
         sCngxr4rE/bPlvbuarzAP8+4yHpbq7vkAzuDN+mZ7hlEnNLU3A6JmqYTfInYmPfJLfFb
         cVpLZ9BEShLuX52oWPdJ/XDOVy2Lz2bv5amU3H6Km4J2161St6X93+TV6w9fDb94HtcC
         rJOx7CFEiFcCMwLy6HVEGA8jjx4ck6C0AaLDS8RxX04hPWhyc7ecdqipz8XJJdvnLoh/
         +mCYjlvMUyi7g5QWJqVRuNbF1MC+dTd/YDD2oVb7TGcDA3gyep2wV8jneMVC+6eyrT6A
         aeHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=4/QklETFhE/HaMV63Zcte41AoyA4FbhUpoG+hqiHyGs=;
        fh=8qekWCkfcHgmPqmFyZ+MvLq5FByYztWZB5BcNmBlw2c=;
        b=AWRRcXhh2zDNvbH4bzhqu9EB8VKbNjVKGWsMN/UyNFBaYxkEAlacAFGt0/rxSBokCT
         oDcUW1zSv7CNeDGN/BefRqBGGVHIyVGKlQYsArhuMEHhgoqF9zKGtRW/gzrNeeVJYaiV
         zktYwOX0cZYGIGM8cwKEZ2jQfmoQy2R9r026H8A1/w8Jih4zZKF4htuok3zhyVKEMyYP
         0tlsoqBE8z/0SoAktG7NYsqiJLcjo2Z866S5Xz7SbbHFPI4HxMbo+DQyBgAL3yesXsNF
         b8cuzwOlhvqntj2oy/ENHh2crOvTDPrFKjPP1aGBFYJgOecyaqBD2IJUnVym3ac6Poec
         h4FA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::224 as permitted sender) smtp.mailfrom=alex@ghiti.fr
Received: from relay4-d.mail.gandi.net (relay4-d.mail.gandi.net. [2001:4b98:dc4:8::224])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b8870e498si527986e87.0.2025.08.08.00.21.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Aug 2025 00:21:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::224 as permitted sender) client-ip=2001:4b98:dc4:8::224;
Received: by mail.gandi.net (Postfix) with ESMTPSA id 37190443D6;
	Fri,  8 Aug 2025 07:21:33 +0000 (UTC)
Message-ID: <7487516c-3eb1-46fa-aed5-6dc72600c952@ghiti.fr>
Date: Fri, 8 Aug 2025 09:21:32 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 2/2] kasan: call kasan_init_generic in kasan_init
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: ryabinin.a.a@gmail.com, bhe@redhat.com, hca@linux.ibm.com,
 andreyknvl@gmail.com, akpm@linux-foundation.org, zhangqing@loongson.cn,
 chenhuacai@loongson.cn, davidgow@google.co, glider@google.com,
 dvyukov@google.com, agordeev@linux.ibm.com, vincenzo.frascino@arm.com,
 elver@google.com, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-um@lists.infradead.org, linux-mm@kvack.org,
 Alexandre Ghiti <alexghiti@rivosinc.com>
References: <20250807194012.631367-1-snovitoll@gmail.com>
 <20250807194012.631367-3-snovitoll@gmail.com>
 <07ffb27c-3416-43c9-a50a-164a76e5ab60@csgroup.eu>
 <CACzwLxhahYWfRc5xKshayniV6SuFFnMT0NfHttippcASzZgtRw@mail.gmail.com>
Content-Language: en-US
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <CACzwLxhahYWfRc5xKshayniV6SuFFnMT0NfHttippcASzZgtRw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-GND-State: clean
X-GND-Score: -100
X-GND-Cause: gggruggvucftvghtrhhoucdtuddrgeeffedrtdefgdduvdefudelucetufdoteggodetrfdotffvucfrrhhofhhilhgvmecuifetpfffkfdpucggtfgfnhhsuhgsshgtrhhisggvnecuuegrihhlohhuthemuceftddunecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenucfjughrpefkffggfgfuvfevfhfhjggtgfesthekredttddvjeenucfhrhhomheptehlvgigrghnughrvgcuifhhihhtihcuoegrlhgvgiesghhhihhtihdrfhhrqeenucggtffrrghtthgvrhhnpeduffeugedvtdegleeuhfeuteetueegfeefkefhheffvdduhfegvdehuddukeffgeenucffohhmrghinhepkhgvrhhnvghlrdhorhhgpdhinhhfrhgruggvrggurdhorhhgnecukfhppeduleefrdeffedrheejrdduleelnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehinhgvthepudelfedrfeefrdehjedrudelledphhgvlhhopegludelvddrudeikedrvddvrddutddungdpmhgrihhlfhhrohhmpegrlhgvgiesghhhihhtihdrfhhrpdhnsggprhgtphhtthhopedvhedprhgtphhtthhopehsnhhovhhithholhhlsehgmhgrihhlrdgtohhmpdhrtghpthhtoheptghhrhhishhtohhphhgvrdhlvghrohihsegtshhgrhhouhhprdgvuhdprhgtphhtthhopehrhigrsghinhhinhdrrgdrrgesghhmrghilhdrtghomhdprhgtphhtthhopegshhgvsehrvgguhhgrthdrtghomhdprhgtphhtthhopehhtggrsehlihhnuhigr
 dhisghmrdgtohhmpdhrtghpthhtoheprghnughrvgihkhhnvhhlsehgmhgrihhlrdgtohhmpdhrtghpthhtoheprghkphhmsehlihhnuhigqdhfohhunhgurghtihhonhdrohhrghdprhgtphhtthhopeiihhgrnhhgqhhinhhgsehlohhonhhgshhonhdrtghn
X-GND-Sasl: alex@ghiti.fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::224 as
 permitted sender) smtp.mailfrom=alex@ghiti.fr
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


On 8/8/25 08:44, Sabyrzhan Tasbolatov wrote:
> On Fri, Aug 8, 2025 at 10:07=E2=80=AFAM Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
>>
>>
>> Le 07/08/2025 =C3=A0 21:40, Sabyrzhan Tasbolatov a =C3=A9crit :
>>> Call kasan_init_generic() which handles Generic KASAN initialization.
>>> For architectures that do not select ARCH_DEFER_KASAN,
>>> this will be a no-op for the runtime flag but will
>>> print the initialization banner.
>>>
>>> For SW_TAGS and HW_TAGS modes, their respective init functions will
>>> handle the flag enabling, if they are enabled/implemented.
>>>
>>> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
>>> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
>>> Tested-by: Alexandre Ghiti <alexghiti@rivosinc.com> # riscv
>>> Acked-by: Alexander Gordeev <agordeev@linux.ibm.com> # s390
>>> ---
>>> Changes in v5:
>>> - Unified arch patches into a single one, where we just call
>>>        kasan_init_generic()
>>> - Added Tested-by tag for riscv (tested the same change in v4)
>>> - Added Acked-by tag for s390 (tested the same change in v4)
>>> ---
>>>    arch/arm/mm/kasan_init.c    | 2 +-
>>>    arch/arm64/mm/kasan_init.c  | 4 +---
>>>    arch/riscv/mm/kasan_init.c  | 1 +
>>>    arch/s390/kernel/early.c    | 3 ++-
>>>    arch/x86/mm/kasan_init_64.c | 2 +-
>>>    arch/xtensa/mm/kasan_init.c | 2 +-
>>>    6 files changed, 7 insertions(+), 7 deletions(-)
>>>
>>> diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
>>> index 111d4f70313..c6625e808bf 100644
>>> --- a/arch/arm/mm/kasan_init.c
>>> +++ b/arch/arm/mm/kasan_init.c
>>> @@ -300,6 +300,6 @@ void __init kasan_init(void)
>>>        local_flush_tlb_all();
>>>
>>>        memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>>> -     pr_info("Kernel address sanitizer initialized\n");
>>>        init_task.kasan_depth =3D 0;
>>> +     kasan_init_generic();
>>>    }
>>> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
>>> index d541ce45dae..abeb81bf6eb 100644
>>> --- a/arch/arm64/mm/kasan_init.c
>>> +++ b/arch/arm64/mm/kasan_init.c
>>> @@ -399,14 +399,12 @@ void __init kasan_init(void)
>>>    {
>>>        kasan_init_shadow();
>>>        kasan_init_depth();
>>> -#if defined(CONFIG_KASAN_GENERIC)
>>> +     kasan_init_generic();
>>>        /*
>>>         * Generic KASAN is now fully initialized.
>>>         * Software and Hardware Tag-Based modes still require
>>>         * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly=
.
>>>         */
>>> -     pr_info("KernelAddressSanitizer initialized (generic)\n");
>>> -#endif
>>>    }
>>>
>>>    #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>>> index 41c635d6aca..ba2709b1eec 100644
>>> --- a/arch/riscv/mm/kasan_init.c
>>> +++ b/arch/riscv/mm/kasan_init.c
>>> @@ -530,6 +530,7 @@ void __init kasan_init(void)
>>>
>>>        memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
>>>        init_task.kasan_depth =3D 0;
>>> +     kasan_init_generic();
>> I understood KASAN is really ready to function only once the csr_write()
>> and local_flush_tlb_all() below are done. Shouldn't kasan_init_generic()
>> be called after it ?
> I will try to test this in v6:
>
>          csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
>          local_flush_tlb_all();
>          kasan_init_generic();


Before setting the final kasan mapping, we still have the early one so=20
we won't trap or anything on some kasan accesses. But if there is a v6,=20
I agree it will be cleaner to do it this ^ way.

Thanks,

Alex


>
> Alexandre Ghiti said [1] it was not a problem, but I will check.
>
> [1] https://lore.kernel.org/all/20c1e656-512e-4424-9d4e-176af18bb7d6@ghit=
i.fr/
>
>>>        csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
>>>        local_flush_tlb_all();
>>> diff --git a/arch/s390/kernel/early.c b/arch/s390/kernel/early.c
>>> index 9adfbdd377d..544e5403dd9 100644
>>> --- a/arch/s390/kernel/early.c
>>> +++ b/arch/s390/kernel/early.c
>>> @@ -21,6 +21,7 @@
>>>    #include <linux/kernel.h>
>>>    #include <asm/asm-extable.h>
>>>    #include <linux/memblock.h>
>>> +#include <linux/kasan.h>
>>>    #include <asm/access-regs.h>
>>>    #include <asm/asm-offsets.h>
>>>    #include <asm/machine.h>
>>> @@ -65,7 +66,7 @@ static void __init kasan_early_init(void)
>>>    {
>>>    #ifdef CONFIG_KASAN
>>>        init_task.kasan_depth =3D 0;
>>> -     pr_info("KernelAddressSanitizer initialized\n");
>>> +     kasan_init_generic();
>>>    #endif
>>>    }
>>>
>>> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
>>> index 0539efd0d21..998b6010d6d 100644
>>> --- a/arch/x86/mm/kasan_init_64.c
>>> +++ b/arch/x86/mm/kasan_init_64.c
>>> @@ -451,5 +451,5 @@ void __init kasan_init(void)
>>>        __flush_tlb_all();
>>>
>>>        init_task.kasan_depth =3D 0;
>>> -     pr_info("KernelAddressSanitizer initialized\n");
>>> +     kasan_init_generic();
>>>    }
>>> diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
>>> index f39c4d83173..0524b9ed5e6 100644
>>> --- a/arch/xtensa/mm/kasan_init.c
>>> +++ b/arch/xtensa/mm/kasan_init.c
>>> @@ -94,5 +94,5 @@ void __init kasan_init(void)
>>>
>>>        /* At this point kasan is fully initialized. Enable error messag=
es. */
>>>        current->kasan_depth =3D 0;
>>> -     pr_info("KernelAddressSanitizer initialized\n");
>>> +     kasan_init_generic();
>>>    }
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
487516c-3eb1-46fa-aed5-6dc72600c952%40ghiti.fr.
