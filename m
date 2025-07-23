Return-Path: <kasan-dev+bncBCSL7B6LWYHBBQFPQTCAMGQEE6BLXNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 27436B0F8B2
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Jul 2025 19:11:30 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-553cf748ae9sf13720e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jul 2025 10:11:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753290689; cv=pass;
        d=google.com; s=arc-20240605;
        b=QnDwgvKcmIgygRE2ij8ejFZb83dr5xLbkeHO6pRxTPn1AN8Bm5fA6Y9F9e91q8pilB
         CAFv1PDQRKcLTs1HYVH52A6FuHKF7ju+npCGp6X0lNTTUNS4H3Bg1Xl0QkXEepB2eUc6
         PUtZfl6iE1c+ubAgFyUjLcGL0yySAtvS9LikCGOYiIB1jap5Th01yeMI2NYa6YNsQUhY
         fpLsKSu9uJEknyo8dpq/qchS9h3MKyTcqhnVLfcPldmh7/eaZzh9bTMvJgw3ZRzltA5J
         2fH6vyL8VND6AR2b+NZ2/P/SKR966yRPI7+3h7zlz0dmP8AQjRd44rk2GqlwhT9jeC+6
         zyYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=N37KyPDWrhNzo//NX6eKQyxwVXo+osc/NvcZoa5kf70=;
        fh=IaU8e2gWy771ygujKo2gMU6gr5Ms1PwIYocYXuH/peg=;
        b=TYE/D6il/q3NhArS3wugyIoFBi9wO4T/+Z+ijsH7Yn2SAU5OwTBn4qxe6zn5xDdhar
         8mrexZ/P6d9BqA6hDNDEFamOz8TPtGtwumHcQa6bjNdD3HPCkhGxG8lqNNIdywsE9Yyq
         qR85t1KaaMVWP93yyu5itqZpKAFT5QaoXnCojROMFxMrLuQeL4Sr8mbgLEM80vizDBZn
         jUBsbXstC8e7fIKZj/Lmlr+mttmIT6b9CZJ5JQJhhj4kFTnrS3FEJu+dlhtAREpd4n3E
         brnh5GxVDFo/G1T147NgxeacwPDd6zG+pHOjxPMRjsnmIiqEpaffcM0hWrtLK/HvVTnc
         i7ug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HAB9op+2;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753290689; x=1753895489; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=N37KyPDWrhNzo//NX6eKQyxwVXo+osc/NvcZoa5kf70=;
        b=wfZE8/op4tZCVawKzy1eDO5N/u5VDLbj3rnluinqh4Z32TmTcoZ3TPxEGZGlqchw4S
         RDAqw03qtkr2oDWGhsSpNPkUIMHT93hpINTZWCApJYFTuImfQLI36afxWJ2L0UXar1wq
         AJM8ieodg9j2KH01a/wnf0eNvukprLYAxkRRFtkpZvnpPYLZQWFbnmQ8RvZAeG5+xcHV
         XXu9Sr9mXIrQ+wjpW9rGPjPfaIX17vu1yncim/VrFFO87ceShGxuTxUj5pxdWCfr3Us2
         zKZYwXWCeELnKLr88YNN68nRlgjDjzR4+fOhaht0WactluJuuAtN5FkcMdguOjrRBi78
         0lzA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753290689; x=1753895489; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=N37KyPDWrhNzo//NX6eKQyxwVXo+osc/NvcZoa5kf70=;
        b=M7f/IJASYqgoR7dCdTPBxY0Voy8k1dpDzsqBYMdn0Rbb8obY+WQ8hKw0AcKL/IEAr0
         LcJjht1EoM80IyCAy3q/PTlfDaarm4nrxnwsz/wx07ytmo5LCufDDQygMEw5aw1RmYeS
         cbrKEqJmJ6ett5/xGb+dRFLm7+efcfygvwybfPCNyaAevHRNR/CLECgqXmbYngMrVwIT
         44Q0dVdDo4HP/2h7L5kCSutSPJvUPseVGk318iS9D8RB2kRVKkKmLP/L7POjXJgEap0v
         qACffHCBAMZ+TPCQqFkT3uoFoBJ4PBWQw0vj6Z85urhH3Wk+ZeBQ7POOyKHvBjcrXi7c
         oAow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753290689; x=1753895489;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N37KyPDWrhNzo//NX6eKQyxwVXo+osc/NvcZoa5kf70=;
        b=Jl9vpB7l167VCn8PNQJn+xFzNOiaUqCI/1EvbgxwZsQdxJ2QwvdUACWagVBt+fCpY7
         nzVjfDNT2dyp5huuyKwKAHxPGW/Hcle8uu6K+XK1+es+YkeBUU1LxY/2tG/md1eq/CZT
         K+/cXuQVQYaV3TczbEFB92IUqcXieayrsK3vG+d4AjlRw6pmFmJrFpWh3PPBlpbR1Jp0
         IT+IBI/alH/nnvnRQ6+cZ+7Csjs4h4uQQ5v8DqXbYbyWSw5gorRolgKmJRD9WodIEtXq
         vpw3zuD0uKGo+phXuqkIAKcNBiBOwjveSmh4ePJwNUCiNkRLuuBWVqTJN/l41warL9DU
         we0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWSj4pli7jMZ+jaxGgF+UlxKaszeQ3pz1bY6/PURdoTdOX/HArY4hsFfxzGZuonLbdpOOz3kA==@lfdr.de
X-Gm-Message-State: AOJu0YwmDOQr4JvIjPh3NifbaBISkMddJmo0SVqoTdytJSI/mUpNplJA
	9GTHoQYxJZ4D7PWZawPP6dCnZfZlj/THPyg0flnD3+HBBcO2qp8lxy9w
X-Google-Smtp-Source: AGHT+IHTKByLdNtbiBjerkP5uJa/bd6kJnoRKMc+zTULRo0mr2ylDo+wUW3JTa36yI/BtDVDezhslQ==
X-Received: by 2002:a05:6512:2242:b0:553:2ef3:f731 with SMTP id 2adb3069b0e04-55a513feef1mr1250119e87.29.1753290688857;
        Wed, 23 Jul 2025 10:11:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdNYgN3Kfv6rmk35/3CiJm5fLlkZPMfToABFxjyWqdqwA==
Received: by 2002:a2e:5119:0:b0:32f:4b8e:a710 with SMTP id 38308e7fff4ca-331dd83d067ls160481fa.0.-pod-prod-07-eu;
 Wed, 23 Jul 2025 10:11:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlMQInl0VkkWjhEZnXYB9mQA/9xckg6vBVQc/cwX3XZq11xHDsWrLzdd/JrKEqAGM527B7WFGgTA0=@googlegroups.com
X-Received: by 2002:a2e:ae0a:0:10b0:32a:77a3:8781 with SMTP id 38308e7fff4ca-330dfd8618bmr8533631fa.30.1753290685585;
        Wed, 23 Jul 2025 10:11:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753290685; cv=none;
        d=google.com; s=arc-20240605;
        b=KhFPn0iwyDpCo1NfkPcAitqINuXLfEyTUt67nkVnK6R6Ha96UHtKC42Jn6e4ncBkcw
         qg3vn1XFdVsd7wfPwZx2UXruSHY7vneEq3It0PfiqXu6kIVYoYz4Tlw17S+dAG0snBLo
         gIV9TkQHwrYEalNWKmy0ud/3+ddY2h49QP/qQjlPc4/VCB56pKxPWzCmZddrcdPjqa0I
         UQYVQRKKOUHEV/zhLbYErUomA8+3K7HL/ZYiB07cw3BhqxyvxE5ILxE/IdEmYVJVfMFd
         DLdOtKzi94D1fVgCWPmWR7KHJRHqn6hoYeivhIjsYMio3ZBiAq44vi8zqL4Aeu3t8Yf6
         dgLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=h0LUnIOIz73OOlhKmDgw5NN8XNp7rSGUS+XkRlIQ8F4=;
        fh=Ixl0A1nb2syuWMADR6LoaKuqoyRq9Lsl9jMQbdS7t6g=;
        b=Rd1lOqY1YY9n24ofhLwyCWdXaoOLEd/7Gtno4ouYWmqAo+kapy+Z4LAjntTqaSsu8a
         z2RXdSoraCIAN5zbu9e4Qkb/kShRUJsZCrn0N5xRnW6ppDx0h4hz/YEXZ0SxG6NZ3Nk0
         w/za3w9qWCvjkmkX0E7XnannuPOZZYIGmfnH+MAglxx3U4ksV+BPbxsHjKtr0XPBcuQ5
         LCkK+QSslu126CfnYwkkGXmsMhaRi+Er7ab7XuIqvBUFdc3vWY0k+IHvovyEXflFDoI2
         iC9bEcQJ6l/pl8qBR91VR3+JTKJOHgpF3gFK+Jvj1muhjefnNrDcU/vdtLGZ4q/DAsTl
         Db/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HAB9op+2;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x230.google.com (mail-lj1-x230.google.com. [2a00:1450:4864:20::230])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-330a910369bsi4209921fa.1.2025.07.23.10.11.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jul 2025 10:11:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) client-ip=2a00:1450:4864:20::230;
Received: by mail-lj1-x230.google.com with SMTP id 38308e7fff4ca-32b4eb13e8cso51331fa.1
        for <kasan-dev@googlegroups.com>; Wed, 23 Jul 2025 10:11:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV+Kmev4Lg2hyACtViRnrD5+8u5YQGaC0SGFhrwtKukGtQhFNrHTUzjR+9JsczCNeUmP12StpgY+mY=@googlegroups.com
X-Gm-Gg: ASbGnctNE8vSNSO7EkOzv6MuiCMELCyPaWiuakWCH2v3/qMUxvPAvwYJ/KPdw7ZWshf
	soSuvISJ9WiCjrWHZC1EhepSby/o2Oz4SMK5ETJ2t59/uv37or4lrDI5M/N0UDhQdOnvwGrwiHj
	/9UjC/P+TN2H0VSHwdcEphgpzWC82SnoU8fJosOc920Jgt6lGIuaB+jtxsKjru2La3+GWiSlxaa
	858DVS+GNmz4hxDw+iChsCj+JRo3JyQrla1haGxK7W6Hn3OSgbvYY5tcQtTA0+wM4npV3zG0tl8
	w9hREC71A88NsQfmn92X+m4J0xCMLd6HrydNywYHWsJLvDUXnOtA58Ou0cRLXR4zASCiohQaMDV
	3bKQdRPs2G+ad7ftMIs4yFnnukrMv
X-Received: by 2002:a05:651c:f19:b0:32d:fd8c:7e76 with SMTP id 38308e7fff4ca-330dfd2d969mr3521411fa.7.1753290684563;
        Wed, 23 Jul 2025 10:11:24 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-330a91d9eaasm19869811fa.85.2025.07.23.10.11.22
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jul 2025 10:11:23 -0700 (PDT)
Message-ID: <4dd38293-4307-474f-8eb7-0e83f5d3b996@gmail.com>
Date: Wed, 23 Jul 2025 19:10:59 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 08/12] kasan/um: select ARCH_DEFER_KASAN and call
 kasan_init_generic
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com,
 agordeev@linux.ibm.com, akpm@linux-foundation.org, glider@google.com,
 dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250717142732.292822-1-snovitoll@gmail.com>
 <20250717142732.292822-9-snovitoll@gmail.com>
 <85de2e1f-a787-4862-87e4-2681e749cef0@gmail.com>
 <CACzwLxiD98BLmEmPhkJQgv297bP_7qw+Vm_icFhTiDYN7WvLjw@mail.gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <CACzwLxiD98BLmEmPhkJQgv297bP_7qw+Vm_icFhTiDYN7WvLjw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HAB9op+2;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::230
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 7/22/25 4:17 PM, Sabyrzhan Tasbolatov wrote:
> On Tue, Jul 22, 2025 at 4:00=E2=80=AFAM Andrey Ryabinin <ryabinin.a.a@gma=
il.com> wrote:
>>
>>
>>
>> On 7/17/25 4:27 PM, Sabyrzhan Tasbolatov wrote:
>>> UserMode Linux needs deferred KASAN initialization as it has a custom
>>> kasan_arch_is_ready() implementation that tracks shadow memory readines=
s
>>> via the kasan_um_is_ready flag.
>>>
>>> Select ARCH_DEFER_KASAN to enable the unified static key mechanism
>>> for runtime KASAN control. Call kasan_init_generic() which handles
>>> Generic KASAN initialization and enables the static key.
>>>
>>> Delete the key kasan_um_is_ready in favor of the unified kasan_enabled(=
)
>>> interface.
>>>
>>> Note that kasan_init_generic has __init macro, which is called by
>>> kasan_init() which is not marked with __init in arch/um code.
>>>
>>> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
>>> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
>>> ---
>>> Changes in v3:
>>> - Added CONFIG_ARCH_DEFER_KASAN selection for proper runtime control
>>> ---
>>>  arch/um/Kconfig             | 1 +
>>>  arch/um/include/asm/kasan.h | 5 -----
>>>  arch/um/kernel/mem.c        | 4 ++--
>>>  3 files changed, 3 insertions(+), 7 deletions(-)
>>>
>>> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
>>> index f08e8a7fac9..fd6d78bba52 100644
>>> --- a/arch/um/Kconfig
>>> +++ b/arch/um/Kconfig
>>> @@ -8,6 +8,7 @@ config UML
>>>       select ARCH_WANTS_DYNAMIC_TASK_STRUCT
>>>       select ARCH_HAS_CPU_FINALIZE_INIT
>>>       select ARCH_HAS_FORTIFY_SOURCE
>>> +     select ARCH_DEFER_KASAN
>>>       select ARCH_HAS_GCOV_PROFILE_ALL
>>>       select ARCH_HAS_KCOV
>>>       select ARCH_HAS_STRNCPY_FROM_USER
>>> diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
>>> index f97bb1f7b85..81bcdc0f962 100644
>>> --- a/arch/um/include/asm/kasan.h
>>> +++ b/arch/um/include/asm/kasan.h
>>> @@ -24,11 +24,6 @@
>>>
>>>  #ifdef CONFIG_KASAN
>>>  void kasan_init(void);
>>> -extern int kasan_um_is_ready;
>>> -
>>> -#ifdef CONFIG_STATIC_LINK
>>> -#define kasan_arch_is_ready() (kasan_um_is_ready)
>>> -#endif
>>>  #else
>>>  static inline void kasan_init(void) { }
>>>  #endif /* CONFIG_KASAN */
>>> diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
>>> index 76bec7de81b..058cb70e330 100644
>>> --- a/arch/um/kernel/mem.c
>>> +++ b/arch/um/kernel/mem.c
>>> @@ -21,9 +21,9 @@
>>>  #include <os.h>
>>>  #include <um_malloc.h>
>>>  #include <linux/sched/task.h>
>>> +#include <linux/kasan.h>
>>>
>>>  #ifdef CONFIG_KASAN
>>> -int kasan_um_is_ready;
>>>  void kasan_init(void)
>>>  {
>>>       /*
>>> @@ -32,7 +32,7 @@ void kasan_init(void)
>>>        */
>>>       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
>>>       init_task.kasan_depth =3D 0;
>>> -     kasan_um_is_ready =3D true;
>>> +     kasan_init_generic();
>>
>> I think this runs before jump_label_init(), and static keys shouldn't be=
 switched before that.>  }
>=20
> I got the warning in my local compilation and from kernel CI [1].
>=20
> arch/um places kasan_init() in own `.kasan_init` section, while
> kasan_init_generic() is called from __init.

No, kasan_init() is in text section as the warning says. It's kasan_init_pt=
r in .kasan_init.
Adding __init to kasan_init() should fix the warning.


> Could you suggest a way how I can verify the functions call order?
>=20

By code inspection? or run uder gdb.

kasan_init() is initialization routine called before main().
jump_label_init() called from start_kernel()<-start_kernel_proc()<-... main=
()

> I need to familiarize myself with how to run arch/um locally=20

It's as simple as:
ARCH=3Dum  make=20
./linux rootfstype=3Dhostfs ro init=3D/bin/bash

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
dd38293-4307-474f-8eb7-0e83f5d3b996%40gmail.com.
