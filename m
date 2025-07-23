Return-Path: <kasan-dev+bncBCSL7B6LWYHBBYFZQTCAMGQE4ALDQLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D124B0F91B
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Jul 2025 19:33:22 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4563f15f226sf202215e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jul 2025 10:33:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753292002; cv=pass;
        d=google.com; s=arc-20240605;
        b=fxPEzWH3lhtxH8pVQI9tgN4jAjqd7E67/udxddx2Q1Nrt52+nP+rCJWbsl+LBvNnzc
         P3+u9wLUFjYt33xQtJM9Pg4taU4EbEUqiaYQsNqQRC4/sB/hdcbCXXGlPzk1NYMHM50L
         Dx4ZqRd0rR+SFeV9NL6FzpiNxbWXZtK5eUiGfjzQjkomjw8p4msDGBfsCLkDIGwaX14h
         Gs41SOIdkm3UJI+la2AtqGCrfbShpb5o/11wGUIHLWruvsfwJ8KGk/PxqV2TCwTUQsJm
         40OrWwY/iqcw/B+NNJSJIbpc0twVYBUBs8Wy40XoHkGo+4r7I3beKwx+v07BOKKc8YEf
         pXlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=/qVrGwjJB51zb6kGHpReKDGuqoftsPz5jdrBiUvhlPg=;
        fh=ekaljxEbLmAfTnx0aHXHrCvAjlfI2TGhColQSWYXXSE=;
        b=llY+dURuadUXxJe+azePgQHNfKpKZrQVI6coxDlOlrv9Sn41TD/afgsOOEMmatqqo5
         Lzru5GfW7FX6EgO02D0yFIGsrANvNx7G8zdzF/Cxsa49fK7A8m+v1nYmDk1O7sHIGb5p
         FJFsvd1cONsSWzbJLg/+rqVePsWhCiOFc0IqaByMGqz6trakTmVlKPTOX9w6dWtDH5yv
         ONrje+ccmk8zNAjlGT4dDmmBKfJ9xpgz45G34wuHZl2/ZpVXs0JV3SbYsiVmIXhMuDQj
         OOXHMYoAESeNFUfGR6jhN+eX9cIBFPOPOopsKvZUCFRcpR/mx/mKOu8q35WbLSClqi9b
         cvzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="B1y/gt35";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753292002; x=1753896802; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/qVrGwjJB51zb6kGHpReKDGuqoftsPz5jdrBiUvhlPg=;
        b=HMCUa2v4kgnX10SVcWb8BtLJ6dD7eqpNrkoQWcy5PMjPfQ5ctyWR1Pip/rB14l+3ac
         5j8/Ibo6Al1xanmyX/iy8yw/QjwoXQWCR6HIVShZ6MPd27Wm3vkVqAOy7J9b0i+yu8+W
         jP7sIExCzwsCGmf5BegiU2ZLbH8UcAjfqZpN1fu46oKXvV89x/S9GsUhDMPxzW4WF72p
         yWuubF6p4hNg2FrB9NaxwBOV234MeTR05f/LSiOfnImG4Edx4eVIw6tg495OJoP1n6ht
         gbQ4aCK8NLBbqKlt3wbDOl5q4EFnnbl5YCRUasVelrRGkefu72qXdHaq5lsTSuR3S35K
         ya1Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753292002; x=1753896802; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=/qVrGwjJB51zb6kGHpReKDGuqoftsPz5jdrBiUvhlPg=;
        b=b2Voy7+r+CoREPF5KyU3xGhAtsvpYNiMocRfbMIjB+Kc/WWI8HtgIb0pYZscYKYEry
         bprEokJ+MDraBRmHp394bkzazwZgFJUiK6zzgsY0EY+DerfXsoX/9fZhdh5Zz1+G7cDJ
         kHiDowxL2CiWH0MV4GNdp40BjV7Gsg8I/CmAxJ1+QmTqdEfHlSdVIoY8MDghfuekUbtn
         TELuGRMjy+kNOgb6skJc52s0poI1Ws5aQsDcjMM5+////yBNkfOBKotVae3na2O9Wx78
         1Bdu8DjT/LzI3PyvDzMmlIbkfqq7ITsCkKk4W0WIOVv0JkRvtzMoh+h/GvlwhhJAmOy0
         do+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753292002; x=1753896802;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/qVrGwjJB51zb6kGHpReKDGuqoftsPz5jdrBiUvhlPg=;
        b=h20NONe7FxFgjilZbGgsmGTiLuT+oy/XKBqqajMePMdgEf2G27da3ZaKYQ1EeuL9V+
         7GWIHTLVwSy48lVeFh+9kdkZKIrRMHZV3sbLFDXvAbP/tqo71J4XY4hpENT0lrtyK8Tj
         8dHumqj2uwyv72EN6xAmUed/VeIou8xJ5rFgzo6zijRY22ahd0MtXftGOU1WEdmY+8ew
         fImG3o8ZNWR3HiFOal4DRt/NYtnE+ArahleOETzrJWfvvndT/e4TxY8DMFwRGCsSNQfJ
         Ktw+OSimP5nJoYV80QrEJVdz1ou1IccShkAwkAT9fZEt4I9aPbLboMKgNefO3+9/xEZi
         nv2Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWXpxNzlOmQfjPtjEmuXBrGDFYMzMu+8e2hstUNnoq3ZlGiyE1eNZNMzVPTLZSDVlV1k08ZUw==@lfdr.de
X-Gm-Message-State: AOJu0YyrWGtpDJrqPQHxHr5DEE9jeahWyyOXudPOGQUsbauL3LcP2Aw+
	mu49/CosC9wtDWRxnB0s/ip5bSzrewehsiiKomZQT0h2UQjA0LWPqphP
X-Google-Smtp-Source: AGHT+IES5ybs8/p4kx983E9UfItq8aCq85qMZvQ7+h1iA4kyUMsafcVdIY1CTtQwbhLmrp8oD1zUtw==
X-Received: by 2002:a05:600c:8b10:b0:456:1121:3ad8 with SMTP id 5b1f17b1804b1-45868c9d357mr44545795e9.10.1753292001589;
        Wed, 23 Jul 2025 10:33:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdMpYrXPSdAx7tP6qcDgpP9p9AIrVQ24xayKAitOLdtuA==
Received: by 2002:a05:600c:358b:b0:456:241d:50bd with SMTP id
 5b1f17b1804b1-4586e8a575bls45365e9.2.-pod-prod-04-eu; Wed, 23 Jul 2025
 10:33:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbwQU81CUihx3sbBdTjQ7hiYzSGy+4cY1WqnVYvYcBxt4pEhwunhkkP492cbVSwp4FPE1dAuhfyUw=@googlegroups.com
X-Received: by 2002:a05:600c:c0d2:20b0:442:dc6f:7a21 with SMTP id 5b1f17b1804b1-4586a49249emr22369505e9.3.1753291998571;
        Wed, 23 Jul 2025 10:33:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753291998; cv=none;
        d=google.com; s=arc-20240605;
        b=AYF3uEg2pcvfDmQ1KBHL2mEo4ASczl9v5cyvld0m/hfrVkDsWKF1/8p81nZPtJihYx
         ZLMuRitmtsnOhOHqa+jZcicTNg5NXZMptskKKG81wlFU5UPW+92TBsfdm1FLjNb9+Gu9
         hqQ/RJI7BDj/qhblUSqG2kkUrujHcj3W7hTMYKswryTvd/21Nc1mPK+GC6ymiA80CaVc
         iVflqjUOBuVO6bkV7Fq0UOSfKAhkgyUkTutZktC4UF4Z1JXzROoq8jr0uLaQ1qlqCFDu
         zOvbhXIFkFcRm7txfvvi8sb9hIdFfTNux4Q4yhxBpwIXnOH9LLR8H190mRHYkip2BWZ9
         gNxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=KBM3XOa1GXkPG7AU5j/kIOwYcdf4HqHkAm2pQZ3zu3U=;
        fh=pMCJ95aSAlJOWT5Jd789DNQSMTJ2NJPD0KTUC4MebtI=;
        b=Qy+YWy+kaglwxoE8NBGJqWFDSaSW/eNOqTGiPtWzQ82Uj/nmCxDl2SgyVZX7kNr1JA
         jWCygMA/a7ZTzbJgBw/FsJvIf0zjsvbko0J5hdOOBxm56nNaNDIfrh5jN/o7n2Nb2iyA
         LKLj5uGexulJjY9EhFD8S3GSGfasnFeYdIJB7NXAt2azm7qrx9epxkoa93EgplMIaY4t
         hvFHWvmdpo95MZGVoqmROnFNnqIo45M6CBoIeeBXpLmO2TgcYWoQbhjBDBlHd+caIkdN
         KtBJQpmhrsZw2HwVbdQFj46Y04D1pmZ/z35ILpFiJBWQN8CsszRusmGNyDS4i9To68FF
         sYBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="B1y/gt35";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12c.google.com (mail-lf1-x12c.google.com. [2a00:1450:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4586e7d2ec2si33855e9.0.2025.07.23.10.33.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jul 2025 10:33:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) client-ip=2a00:1450:4864:20::12c;
Received: by mail-lf1-x12c.google.com with SMTP id 2adb3069b0e04-5550bb2787dso6628e87.1
        for <kasan-dev@googlegroups.com>; Wed, 23 Jul 2025 10:33:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUqgVluh2qQ2V7agQClKgF+SD9SDBCPRdriQcGNe6As3EsaHhhA1uj5SllgRsAXe5G8Mhf0SYnlAd8=@googlegroups.com
X-Gm-Gg: ASbGncuhOZRWSOH19eTvn0IlbsuXTEA2/FTUeFQJaHIZdzhG7Woez22qBQ6NpLjWGJe
	F/Y8scuKzG7yw/46w8zSIkN/bPgz31mdTKkoovE23RZxsPLzDzRW2EJSOAsDNTJY+DrABpTMWeC
	28iakjVISRk78M/083yRuthc0jRMNW/jvuncmxWtMyOORX6yqQQC8F6gIy6T3LZtVLMB9T0JB8k
	o8w6+nuLf5vXjbDOZ0GZHUPsGlPIk2AZt588VIbK5JgPU0x0NYLqRdrp6ZpOxQ3jldRKy+rYIEb
	72OAMR+bQZwnMqWYrBQk3f+sVFwMOxFvBNdJBVIRcLZFkm0EhP9Igf2qzLR3aijO13r836G42Q2
	FT/+ShoRB/uoM94L7Fko2dHyCjBnz1cu7IEdHQ5o=
X-Received: by 2002:a05:6512:3c8b:b0:553:24b4:6492 with SMTP id 2adb3069b0e04-55a5132157emr458860e87.5.1753291997236;
        Wed, 23 Jul 2025 10:33:17 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55a31aac980sm2396014e87.74.2025.07.23.10.33.15
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jul 2025 10:33:16 -0700 (PDT)
Message-ID: <f7051d82-559f-420d-a766-6126ba2ed5ab@gmail.com>
Date: Wed, 23 Jul 2025 19:32:51 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/12] kasan: unify kasan_arch_is_ready() and remove
 arch-specific implementations
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com,
 agordeev@linux.ibm.com, akpm@linux-foundation.org, glider@google.com,
 dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250717142732.292822-1-snovitoll@gmail.com>
 <f10f3599-509d-4455-94a3-fcbeeffd8219@gmail.com>
 <CACzwLxjD0oXGGm2dkDdXjX0sxoNC2asQbjigkDWGCn48bitxSw@mail.gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <CACzwLxjD0oXGGm2dkDdXjX0sxoNC2asQbjigkDWGCn48bitxSw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="B1y/gt35";       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12c
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



On 7/22/25 8:21 PM, Sabyrzhan Tasbolatov wrote:
> On Tue, Jul 22, 2025 at 3:59=E2=80=AFAM Andrey Ryabinin <ryabinin.a.a@gma=
il.com> wrote:
>>
>>
>>
>> On 7/17/25 4:27 PM, Sabyrzhan Tasbolatov wrote:
>>
>>> =3D=3D=3D Testing with patches
>>>
>>> Testing in v3:
>>>
>>> - Compiled every affected arch with no errors:
>>>
>>> $ make CC=3Dclang LD=3Dld.lld AR=3Dllvm-ar NM=3Dllvm-nm STRIP=3Dllvm-st=
rip \
>>>       OBJCOPY=3Dllvm-objcopy OBJDUMP=3Dllvm-objdump READELF=3Dllvm-read=
elf \
>>>       HOSTCC=3Dclang HOSTCXX=3Dclang++ HOSTAR=3Dllvm-ar HOSTLD=3Dld.lld=
 \
>>>       ARCH=3D$ARCH
>>>
>>> $ clang --version
>>> ClangBuiltLinux clang version 19.1.4
>>> Target: x86_64-unknown-linux-gnu
>>> Thread model: posix
>>>
>>> - make ARCH=3Dum produces the warning during compiling:
>>>       MODPOST Module.symvers
>>>       WARNING: modpost: vmlinux: section mismatch in reference: \
>>>               kasan_init+0x43 (section: .ltext) -> \
>>>               kasan_init_generic (section: .init.text)
>>>
>>> AFAIU, it's due to the code in arch/um/kernel/mem.c, where kasan_init()
>>> is placed in own section ".kasan_init", which calls kasan_init_generic(=
)
>>> which is marked with "__init".
>>>
>>> - Booting via qemu-system- and running KUnit tests:
>>>
>>> * arm64  (GENERIC, HW_TAGS, SW_TAGS): no regression, same above results=
.
>>> * x86_64 (GENERIC): no regression, no errors
>>>
>>
>> It would be interesting to see whether ARCH_DEFER_KASAN=3Dy arches work.
>> These series add static key into __asan_load*()/_store*() which are call=
ed
>> from everywhere, including the code patching static branches during the =
switch.
>>
>> I have suspicion that the code patching static branches during static ke=
y switch
>> might not be prepared to the fact the current CPU might try to execute t=
his static
>> branch in the middle of switch.
>=20
> AFAIU, you're referring to this function in mm/kasan/generic.c:
>=20
> static __always_inline bool check_region_inline(const void *addr,
>=20
>       size_t size, bool write,
>=20
>       unsigned long ret_ip)
> {
>         if (!kasan_shadow_initialized())
>                 return true;
> ...
> }
>=20
> and particularly, to architectures that selects ARCH_DEFER_KASAN=3Dy, whi=
ch are
> loongarch, powerpc, um. So when these arch try to enable the static key:
>=20
> 1. static_branch_enable(&kasan_flag_enabled) called
> 2. Kernel patches code - changes jump instructions
> 3. Code patching involves memory writes
> 4. Memory writes can trigger any KASAN wrapper function
> 5. Wrapper calls kasan_shadow_initialized()
> 6. kasan_shadow_initialized() calls static_branch_likely(&kasan_flag_enab=
led)
> 7. This reads the static key being patched --- this is the potential issu=
e?
>=20


Yes, that's right.


> The current runtime check is following in tis v3 patch series:
>=20
> #ifdef CONFIG_ARCH_DEFER_KASAN
> ...
> static __always_inline bool kasan_shadow_initialized(void)
> {
>         return static_branch_likely(&kasan_flag_enabled);
> }
> ...
> #endif
>=20
> I wonder, if I should add some protection only for KASAN_GENERIC,
> where check_region_inline() is called (or for all KASAN modes?):
>=20
> #ifdef CONFIG_ARCH_DEFER_KASAN
> ...
> static __always_inline bool kasan_shadow_initialized(void)
> {
>         /* Avoid recursion (?) during static key patching */
>         if (static_key_count(&kasan_flag_enabled.key) < 0)
>                 return false;
>         return static_branch_likely(&kasan_flag_enabled);
> }
> ...
> #endif
>=20
> Please suggest where the issue is and if I understood the problem.

I don't know if it's a real problem or not. I'm just pointing out that we m=
ight
have tricky use case here and maybe that's a problem, because nobody had su=
ch use
case in mind. But maybe it's just fine.
I think we just need to boot test it, to see if this works.

> I might try to run QEMU on powerpc with KUnits to see if I see any logs.
powerpc used static key same way before your patches, so powerpc should be =
fine.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
7051d82-559f-420d-a766-6126ba2ed5ab%40gmail.com.
