Return-Path: <kasan-dev+bncBDXZ5J7IUEIBBCWLTPDQMGQEM4HK7OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id F06A3BC6CB7
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 00:28:40 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-77f5e6a324fsf1377697b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 15:28:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759962507; cv=pass;
        d=google.com; s=arc-20240605;
        b=O/0QDp51FlrqdNPOWwOf5osa0XoP1DKNtuXD3Ib8ulIgntU0KHMFUqqH/74C5tYAQr
         ZqnhOMlb4V10OyKSdQ/B0b4/6/m4VDe5KvgyLWRR8oBMXR2rZ81dTp1s+gsUfnNRr4Qo
         /b6NS94Z/Cqi1udmO5HrD7ArFllLToJ+Pp71vhNjGZjNAa9lS4TWC723rHvWONo0u6GS
         +kCtUT0UiOfjiTYDZhwN2/UZuQdVMyFyBcFV9kkVY/drH+L5X72uNphX5mToPa5whfbS
         ACvU/I+9GcVcoP4HcbnXE2nTxuLwgMlEZg0YYOxMRndzxD2f9w+RmE6rRKcXSNrWyg/1
         +QfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:organization:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=JmxQSN5PfTPXInf1EVaT6dSpjHYhVHys+GUg7GTfi4M=;
        fh=LXz+cZjHN9R9XLJCNRR6qksTfuc5zl4bVsW/bnnPQkc=;
        b=XcxPXI2ulEJffDlixwUJ7x6IYAEpfxil+MyuGnjqzXV4ePNksJyY8TJ7GXbH9kVyTG
         ks8KxSrLwC69P1ppmRhpHmre0tGBhn6CCvvu4UtJWdID883t4hbxVdjXQ80TdYcHb7cg
         gAE1Ol3MosqnLDm+ODdp8MeF675zYTEUnJ5GXda3L33q9aBoEvSxty/unY9yn5f+b873
         qDGfjObvWxVDTpH1TP9//En0YVc2HhJ/HPtXJFzyPtrxoxxAuL+2QAvFfvgz9PXuGlqb
         eU1XqHBhssMqfjj+thmLvk5RFt6Sl+jBbMGBGoiyy4fFzWH1t6A/poR7pLWctnjFmexW
         3vBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.216.51 as permitted sender) smtp.mailfrom=yskelg@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759962507; x=1760567307; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to
         :organization:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=JmxQSN5PfTPXInf1EVaT6dSpjHYhVHys+GUg7GTfi4M=;
        b=LIGzCt3qkxcY1zIhop+poA5B9eENegtzrMeFiVsbcPxRoKVGvR2uzhuIR9z+5ybML/
         HyIno/FJKeRBTqvq2IBlhAGE0Yay3LfAeIomZOaBy5oglH540bZNh6TwgmIO6iv+Jbrf
         D4zinNFa0XdNpL+EZbV0HBLQhfNRkC1xUpW2NAvsGwvYSLuXuOJ5aJQttY+HYr+cKb8W
         fSG/r7SFZd899j7HL2LSFAV1QuUKJsslfD9K50/Ihden5Zh9W7Ssgs5lczMsxCCZgNkq
         LISh4Kxif4WEsJ9HzbZt4nIIIeKZn5rVvM71JXLdUQ1h/URes9SfI/4SvDN9BB0Ddtg9
         DoZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759962507; x=1760567307;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JmxQSN5PfTPXInf1EVaT6dSpjHYhVHys+GUg7GTfi4M=;
        b=gOewP/uw5zoqlAUEqm3pbYRPzEOFfsFghLrQI5R0CnAp3w4whVhemEJq2pij4z1poT
         dHg2lIC+uvJanns+FIOVsZghWSovu7mGXja217k+pHqu9Sjohs4nE5vCpOr1uTJdT+Am
         V+E34WNLWzMWoez6q0pc+rEF1jSBEyH7tXKk9t9GufyAPtW6hDpx40mnsf/+1yjexNEl
         cgrgQzKjXenbmruKDN9WyKCh2lg1FbUVkd/YwmNct1jB4RDxvZrbqB6ZvM9mb0YrY4R3
         0STnujKHspCVTWjoBAa+N/YVrrA0zmVJ4pVWuVT7Fgs5tPz2drX+VtwEPlp88asBOy+H
         IIrw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWShuvOihbd4yMRKVaxcASWy7yQt3cWo/jrr/bYO5sKno6vPjv5FuotmADbgaY8wYDV7tZQlA==@lfdr.de
X-Gm-Message-State: AOJu0Yylj+KzGxr6LfZJtNj1/yGyUVFOH70dDs3FV3iS+HcXe2jRbLhv
	+l5aNW3ApjdNhkXwiEJsLFqZ9PBDDQ6Z9fufqTlTDBWNT8iLcg57hq+9
X-Google-Smtp-Source: AGHT+IHbolLayUaMPyiyJQI0uX1zpDqIrJwdCKEm+DrMmmUS1WcvqIu4pfiszJossTu7zotgrUjGwA==
X-Received: by 2002:a05:6a20:3d06:b0:251:1b8c:5643 with SMTP id adf61e73a8af0-32da845fdf3mr6801753637.50.1759962506924;
        Wed, 08 Oct 2025 15:28:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4QUi6CFQgI6yQq0gg3gUrd5U6u377fOsDYHoN+INU65A=="
Received: by 2002:a05:6a00:2b98:b0:77f:19a2:eb01 with SMTP id
 d2e1a72fcca58-794f33f7a55ls923410b3a.2.-pod-prod-08-us; Wed, 08 Oct 2025
 15:28:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3H2wIL0Whfz79oPSutR91uPBMynvu3/mMWIH0WS4C5HxILM0L/f2/SGO/dK9w68Zdptveffa3zZg=@googlegroups.com
X-Received: by 2002:a05:6a00:886:b0:780:f6db:b1bd with SMTP id d2e1a72fcca58-79385324e3dmr5912824b3a.4.1759962505606;
        Wed, 08 Oct 2025 15:28:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759962505; cv=none;
        d=google.com; s=arc-20240605;
        b=K7Lij+dYtmc7o5qz0Tl5JVbwTQ3G5ESMypJbRsgV/JBa5qmvqp86/wqb/JoQRH1Lvn
         gLqk1DvpaeXVfaCNi66vJ9TBTznHAU1G9ywm8g7DPWXYA2NpBb+DYQ9J5cKUIVc8jzDw
         xZJbGrUY7GW7f5v3NBwWf2qHUOC4S0KTBBu9KyIQmAdtDKVdIXWjgGa0O+8UxRQa6Lcr
         N6fejqDqpNLFYBMmcDmaDHnpHgH3zjiqNJ9n++FoXXzdZhkq/q5OkEbOCHNXVGDrqSSe
         GMyf9jDxMfkWfDmwbFym2nUFp93Ttfl9y/9pKFtlIJDOjRn2lRl1+ajqqhNxW4fZ+80U
         cBmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id;
        bh=m+FDQ7zQAPnlAXJ0xUMPhBN5Vu4l6pnGvG4mZcfsdHU=;
        fh=kaJT2dbmI3QgHS12CjXeOUMZKOFavxQZ2Gg0jX0Ifg8=;
        b=N07FUKNfe/krYJo2WJYA2KMac6jRGj7qqh3BVvBKjOYJ4vNkRXJUyQhRNoxfiioUrt
         IeBsnvZZ+9cVNtiUP1t1n09TDTKDinomjPn0FGOGZUQTt8u7/Ri0qkXnP4H8XX0pm0ob
         ZbvJlfhqWXh76H6H4JHI5SWrwiFxcGSDtpM2v4Gu85mzp3GupLaPDUptj9Uk6ZrOtPiv
         TT0QKDGgnKgEpYf4A8Wx22ZUYI5Q47P2k8mHsTbqziERS6R8I/E2+R5pNKiiiuM+zIBs
         o6Lb3Ipok9H1gB7BfLzOFaxUitw+mQ/C9s8WLMiFbpCFmYmphlyXj4ITs8jug8iaOFiN
         0MbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.216.51 as permitted sender) smtp.mailfrom=yskelg@gmail.com
Received: from mail-pj1-f51.google.com (mail-pj1-f51.google.com. [209.85.216.51])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-794e513e895si68244b3a.4.2025.10.08.15.28.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Oct 2025 15:28:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of yskelg@gmail.com designates 209.85.216.51 as permitted sender) client-ip=209.85.216.51;
Received: by mail-pj1-f51.google.com with SMTP id 98e67ed59e1d1-339d7c401d8so56409a91.2
        for <kasan-dev@googlegroups.com>; Wed, 08 Oct 2025 15:28:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWcJEFjPROceEPa8sOuDvTHqenZ5+lTWUFg/WvZjp3Ki9cE+ufYwT5NfyPJTz1U/SirX9aXfu2OCdE=@googlegroups.com
X-Gm-Gg: ASbGncvrur92XPPVQNQElLAQ4o0os6LHwZAktOdbCDDIU9OGTzXfHrj5lPled7tH81t
	EXTfVm46Thj0njDsJMAejWYapvXqOLUA3+Ma9YlO5YWCUAgRpMI7ady95SButlkJQ52NF06T1IE
	hJR0z9Jjv6ieq2VqbPHiO9yVJ0TQiqro1GyvgjV0sVN6F8rSpJ8XFWHxpzTgkE/HxKlP2zY5us6
	uiSN7BJHwbJE5tWw8yvK6qGCBCt5HSK5cD1XZj6hz60SFXTw80sQL0JrndP3YfFAx3hyzB3V0K1
	xRYfTm8LXboJqQ+myap0sOled+wdpjE2HGb5G66MH1Cwz+etro+wIk0eY0FoNeIbVeDypRAL2ZF
	ajyUuAAhtag/qHnBlFDMfiEB+qLnW+KVbjhapU6cfot2oAQr00woVvo0rRmirxUCBvTRyvTKQl9
	YE3palS7O2auuoAiB7LP60DVo8vBrwYaeNUiK+zyz9HQ==
X-Received: by 2002:a05:6a20:12c4:b0:2c1:b47d:bcde with SMTP id adf61e73a8af0-32da80da615mr3884733637.1.1759962505124;
        Wed, 08 Oct 2025 15:28:25 -0700 (PDT)
Received: from [192.168.50.136] ([118.32.98.101])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b62e3508744sm15811209a12.30.2025.10.08.15.28.21
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Oct 2025 15:28:24 -0700 (PDT)
Message-ID: <d0fc7dd9-d921-4d82-9b70-bedca7056961@kzalloc.com>
Date: Thu, 9 Oct 2025 07:28:19 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] arm64: cpufeature: Don't cpu_enable_mte() when
 KASAN_GENERIC is active
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 James Morse <james.morse@arm.com>, Yeoreum Yun <yeoreum.yun@arm.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Marc Zyngier
 <maz@kernel.org>, Mark Brown <broonie@kernel.org>,
 Oliver Upton <oliver.upton@linux.dev>, Ard Biesheuvel <ardb@kernel.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
References: <20251008210425.125021-3-ysk@kzalloc.com>
 <CA+fCnZcknrhCOskgLLcTn_-o5jSiQsFni7ihMWuc1Qsd-Pu7gg@mail.gmail.com>
Content-Language: en-US
From: Yunseong Kim <ysk@kzalloc.com>
Organization: kzalloc
In-Reply-To: <CA+fCnZcknrhCOskgLLcTn_-o5jSiQsFni7ihMWuc1Qsd-Pu7gg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: yskelg@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yskelg@gmail.com designates 209.85.216.51 as permitted
 sender) smtp.mailfrom=yskelg@gmail.com
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

Hi Andrey,

On 10/9/25 6:36 AM, Andrey Konovalov wrote:
> On Wed, Oct 8, 2025 at 11:13=E2=80=AFPM Yunseong Kim <ysk@kzalloc.com> wr=
ote:
>> [...]
> I do not understand this. Why is Generic KASAN incompatible with MTE?

My board wouldn't boot on the debian debug kernel, so I enabled
earlycon=3Dpl011,0x40d0000 and checked via the UART console.

> Running Generic KASAN in the kernel while having MTE enabled (and e.g.
> used in userspace) seems like a valid combination.

Then it must be caused by something else. Thank you for letting me know.

It seems to be occurring in the call path as follows:

cpu_enable_mte()
 -> try_page_mte_tagging(ZERO_PAGE(0))
   -> VM_WARN_ON_ONCE(folio_test_hugetlb(page_folio(page)));

 https://elixir.bootlin.com/linux/v6.17/source/arch/arm64/include/asm/mte.h=
#L83

> The crash log above looks like a NULL-ptr-deref. On which line of code
> does it happen?

Decoded stack trace here:

[    0.000000] Unable to handle kernel paging request at virtual address df=
ff800000000005
[    0.000000] KASAN: null-ptr-deref in range [0x0000000000000028-0x0000000=
00000002f]
[    0.000000] Mem abort info:
[    0.000000]   ESR =3D 0x0000000096000005
[    0.000000]   EC =3D 0x25: DABT (current EL), IL =3D 32 bits
[    0.000000]   SET =3D 0, FnV =3D 0
[    0.000000]   EA =3D 0, S1PTW =3D 0
[    0.000000]   FSC =3D 0x05: level 1 translation fault
[    0.000000] Data abort info:
[    0.000000]   ISV =3D 0, ISS =3D 0x00000005, ISS2 =3D 0x00000000
[    0.000000]   CM =3D 0, WnR =3D 0, TnD =3D 0, TagAccess =3D 0
[    0.000000]   GCS =3D 0, Overlay =3D 0, DirtyBit =3D 0, Xs =3D 0
[    0.000000] [dfff800000000005] address between user and kernel address r=
anges
[    0.000000] Internal error: Oops: 0000000096000005 [#1]  SMP
[    0.000000] Modules linked in:
[    0.000000] CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted 6.17+unreleas=
ed-debug-arm64 #1 PREEMPTLAZY  Debian 6.17-1~exp1
[    0.000000] pstate: 800000c9 (Nzcv daIF -PAN -UAO -TCO -DIT -SSBS BTYPE=
=3D--)
[    0.000000] pc : cpu_enable_mte (debian/build/build_arm64_none_debug-arm=
64/include/linux/page-flags.h:1065 (discriminator 1) debian/build/build_arm=
64_none_debug-arm64/arch/arm64/include/asm/mte.h:83 (discriminator 1) debia=
n/build/build_arm64_none_debug-arm64/arch/arm64/kernel/cpufeature.c:2419 (d=
iscriminator 1))
[    0.000000] lr : cpu_enable_mte (debian/build/build_arm64_none_debug-arm=
64/include/linux/page-flags.h:1065 (discriminator 1) debian/build/build_arm=
64_none_debug-arm64/arch/arm64/include/asm/mte.h:83 (discriminator 1) debia=
n/build/build_arm64_none_debug-arm64/arch/arm64/kernel/cpufeature.c:2419 (d=
iscriminator 1))
[    0.000000] sp : ffff800084f67d80
[    0.000000] x29: ffff800084f67d80 x28: 0000000000000043 x27: 00000000000=
00001
[    0.000000] x26: 0000000000000001 x25: ffff800084204008 x24: ffff8000842=
03da8
[    0.000000] x23: ffff800084204000 x22: ffff800084203000 x21: ffff8000865=
a8000
[    0.000000] x20: fffffffffffffffe x19: fffffdffddaa6a00 x18: 00000000000=
00011
[    0.000000] x17: 0000000000000000 x16: 0000000000000000 x15: 00000000000=
00000
[    0.000000] x14: 0000000000000000 x13: 0000000000000001 x12: ffff700010a=
04829
[    0.000000] x11: 1ffff00010a04828 x10: ffff700010a04828 x9 : dfff8000000=
00000
[    0.000000] x8 : ffff800085024143 x7 : 0000000000000001 x6 : ffff700010a=
04828
[    0.000000] x5 : ffff800084f9d200 x4 : 0000000000000000 x3 : ffff8000800=
794ac
[    0.000000] x2 : 0000000000000005 x1 : dfff800000000000 x0 : 00000000000=
0002e
[    0.000000] Call trace:
[    0.000000]  cpu_enable_mte (debian/build/build_arm64_none_debug-arm64/=
=E2=88=9A (discriminator 1) debian/build/build_arm64_none_debug-arm64/arch/=
arm64/include/asm/mte.h:83 (discriminator 1) debian/build/build_arm64_none_=
debug-arm64/arch/arm64/kernel/cpufeature.c:2419 (discriminator 1)) (P)
[    0.000000]  enable_cpu_capabilities (debian/build/build_arm64_none_debu=
g-arm64/arch/arm64/kernel/cpufeature.c:3561 (discriminator 2))
[    0.000000]  setup_boot_cpu_features (debian/build/build_arm64_none_debu=
g-arm64/arch/arm64/kernel/cpufeature.c:3888 debian/build/build_arm64_none_d=
ebug-arm64/arch/arm64/kernel/cpufeature.c:3906)
[    0.000000]  smp_prepare_boot_cpu (debian/build/build_arm64_none_debug-a=
rm64/arch/arm64/kernel/smp.c:466)
[    0.000000]  start_kernel (debian/build/build_arm64_none_debug-arm64/ini=
t/main.c:929)
[    0.000000]  __primary_switched (debian/build/build_arm64_none_debug-arm=
64/arch/arm64/kernel/head.S:247)
[    0.000000] Code: 9100c280 d2d00001 f2fbffe1 d343fc02 (38e16841)
All code
=3D=3D=3D=3D=3D=3D=3D=3D
   0:	9100c280 	add	x0, x20, #0x30
   4:	d2d00001 	mov	x1, #0x800000000000        	// #140737488355328
   8:	f2fbffe1 	movk	x1, #0xdfff, lsl #48
   c:	d343fc02 	lsr	x2, x0, #3
  10:*	38e16841 	ldrsb	w1, [x2, x1]		<-- trapping instruction

Code starting with the faulting instruction
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
   0:	38e16841 	ldrsb	w1, [x2, x1]
[    0.000000] ---[ end trace 0000000000000000 ]---
[    0.000000] Kernel panic - not syncing: Attempted to kill the idle task!
[    0.000000] ---[ end Kernel panic - not syncing: Attempted to kill the i=
dle task! ]---


If there are any other points you'd like me to check or directions, please
let me know.

Thank you!

Yunseong

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d=
0fc7dd9-d921-4d82-9b70-bedca7056961%40kzalloc.com.
