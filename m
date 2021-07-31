Return-Path: <kasan-dev+bncBD4NDKWHQYDRBJFUSKEAMGQESWT2KYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D94B3DC200
	for <lists+kasan-dev@lfdr.de>; Sat, 31 Jul 2021 02:32:37 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id w3-20020a0566020343b02905393057ad92sf6773764iou.20
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Jul 2021 17:32:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627691556; cv=pass;
        d=google.com; s=arc-20160816;
        b=pkxzv5BINEspR55cAiGYnIEqcN71XqbyPG6D3sE8O9gdVVT4JR6nBTx4CtuXAmeBru
         SB2ikD52cAtiegpVV+CaaWP1+U9UkvEy3XQWmtWZcz71SGWmrWJz2CkUOkSi/ceCP7NT
         QVTXsrcKDBi4CC+HzaYfTaZXrUGbXS2iF17hIcrFaKcnnoViKrKPBTRO0IBNRMII1vxa
         OGLZwEGRSi/FrS3G2pPlzfxGZrWsyxnQnPaJ2DoUcyuMvrvV7Rcc7SdUNiOOHQbdB6YR
         ZfMQ+9/x/Mc6edZ7jeASKyoJH3oByWVLN2Fj+VpfJiuQrD11DfjFMOZflxA2n/DZvMd6
         uogw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=4pr6V6I5Q38xM39+Op5ZTX0PI3l7MNMgx/MWXZYjTC0=;
        b=AuB9joSjGnwwXzf7Zi1UCrz8dG+kWMrgkhx01CIBgBvgkGaDhZ+WdhyUFFVWK6TCk/
         zfqpRQCAUuNrsJyF2aGL73/D72FqWY99Hf+iQ69femcTUpUqcY/5nJI2Z+hBvhcPXyWz
         xhrAN7Q1/JuHYcVlbU9tD9ImSVzsoNbJ0f8pinNrF8sEFw1t/jtZw8l5TRXbu3j77KfT
         qkeHUTF5Khw3qX5fH4C44St5aZJG/nnO3Xz63Uzs1acJS+ySocZiTRmfQv79U15vV+o1
         p+BVb3BR0iuBWj5wg4UlL7t4hyTtOKG31tAjAoOjkdj8uRaInEa6mtuVQrhXweWuMZbC
         Td/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Fob9LrC7;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4pr6V6I5Q38xM39+Op5ZTX0PI3l7MNMgx/MWXZYjTC0=;
        b=io9FQkr/a3CpyYFWMg/HniwEjV/9COdYiYqw611HBJkGpQB2HSxF1ipZh3RLY+UW+I
         vi0qlMjj0HSlfhkdF8L2wVBX5KzxK0PboT1rlduXHNA/GieHQHC5Frt/ssKHn5+mCDE1
         UChx4NQkkE+oJIYGzDrdhtmShkXnHZ+yUPOruW05Sv77dY1EZ5eG6cysiqKpwfinm+WO
         +2Bj78TH5c9uLPrjPKZEgHq7lAIIIOqguZE2jlfDEXEE45eUVoSBz5G0o6Eih4iw2bNL
         ga4h2gDzop2GZa6lnebgmnuDWiB94ddJUV5mE2oYrExWnozmrX7VVXJbpO7AETdWSNE6
         pifg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4pr6V6I5Q38xM39+Op5ZTX0PI3l7MNMgx/MWXZYjTC0=;
        b=EdDxy3jnJkxwxNWiHXsVJyTaKIKhuF7HmmPxgl7FktZRr5fe1H6GnEgg5jEWKwEEom
         v12WtIy8Z1E54b7aOJkC6DQc3ibPQCL5XumfKujySmC4ccfftWIHsxSlnaqgG867BMNV
         aVZYIFG1exuGkOHtfNlLGmarueEnzn306Avv4S6WuCYPJ0X2CJLCdDBYpK6dhXlkkFPA
         zcLi5RmSkdjg+iHJoD3rvacVJ+Hao54bZDmqKs1Kc19RIAUCuStctVFaPu+NHjToczDn
         z3yDqiOgCZUWnrMdFfUhsQswiJf/QL0xzv5XdMCGPEW3l2WA5oy7/CRWxv8opkJmz2Zz
         ky2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tS+n+W8HHsQ0jdl3OnnKiVNovUEUrKE1+Rpm1jILCKRjqD8xW
	PR6foA4iAZN0eRJThOQqWPY=
X-Google-Smtp-Source: ABdhPJx3r8Z7HdQugOr61c1vWyYrE9peMXSik6mAVgtb2QUH4EiARUdnrxaAsmEqsRkJ99ebBSPc9Q==
X-Received: by 2002:a05:6638:2107:: with SMTP id n7mr4203987jaj.117.1627691556473;
        Fri, 30 Jul 2021 17:32:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:f710:: with SMTP id k16ls531935iog.4.gmail; Fri, 30 Jul
 2021 17:32:36 -0700 (PDT)
X-Received: by 2002:a6b:490d:: with SMTP id u13mr4399531iob.176.1627691556088;
        Fri, 30 Jul 2021 17:32:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627691556; cv=none;
        d=google.com; s=arc-20160816;
        b=sjXTX4GTixUzZSrkRnmQ5v4Qav/ireX/Z3odsOe1J/Q6Tlf57p279NxXYiEXhh3VNI
         /uhxVmJnoUcy0k/qLbaMQDe8hNej8YF3L5h4GQXD/FoP0DVqclIHnQWoLLx+Spshbyoh
         pXCcQY0qAitP0ZY5U9nvVidatjCC0hCAmz4+PeVETrw7AvJxLu6DOZkCj5FH92M7cH6N
         lczQVp/vkURvdSs7mF7eiX9UYzjuiLBSdUXBKiRn6sgFEvGrMjv5+vcnXDuHk7hh1anh
         C8ItUBpep34uA/ZwbRV35wFnse0rEv14lNhlK2SoV31zFu88PyaRvGh7QRyIR7qFCFgY
         oLOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=BfrLQHN2E9bM7oTxBZbgAR5WOEvY8Bj1JCo88Xnr2Pw=;
        b=eNAWV2DZSywrOXemId+ovtZiAD3ChqKjIRXxD8gCZQBJ47KjZVLPomEK/hEGLJFLZY
         hDhfRvDj0IxYOxxHUVqh1KjJ4plxC0GnbJPDMlaEfBkmCBBdabSvMUZX73OiyyKNydYQ
         91/mFmihqgROHPQ/t4q5DdTfrPOBGhOURmQSk9q/a5xyXj6qf/9QYeFPBtfo7vIZbX62
         41ddpWbqirgzoVmP7QzIBT+YkihipYoBpSCLAhtQl0qB0PXj8GvTuShwUPcl+HlBgd0V
         8nF+Y6aDw8alH2p88YKiDzUWpHfHMK9xAYnAOcW3sR08QM2Cjvhd2r8ClqHc5IwkepQt
         r0uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Fob9LrC7;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q12si208569iog.2.2021.07.30.17.32.35
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 30 Jul 2021 17:32:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7E0A260FE7;
	Sat, 31 Jul 2021 00:32:34 +0000 (UTC)
Subject: Re: [PATCH] vmlinux.lds.h: Handle clang's module.{c,d}tor sections
To: Fangrui Song <maskray@google.com>
Cc: Nick Desaulniers <ndesaulniers@google.com>,
 Kees Cook <keescook@chromium.org>, Arnd Bergmann <arnd@arndb.de>,
 Marco Elver <elver@google.com>, linux-arch@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 clang-built-linux@googlegroups.com, stable@vger.kernel.org
References: <20210730223815.1382706-1-nathan@kernel.org>
 <CAKwvOdnJ9VMZfZrZprD6k0oWxVJVSNePUM7fbzFTJygXfO24Pw@mail.gmail.com>
 <20210730225936.ce3hcjdg2sptvbh7@google.com>
From: Nathan Chancellor <nathan@kernel.org>
Message-ID: <baf67422-8662-02f2-0bbf-6afb141875af@kernel.org>
Date: Fri, 30 Jul 2021 17:32:33 -0700
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.12.0
MIME-Version: 1.0
In-Reply-To: <20210730225936.ce3hcjdg2sptvbh7@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Fob9LrC7;       spf=pass
 (google.com: domain of nathan@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On 7/30/2021 3:59 PM, Fangrui Song wrote:
> On 2021-07-30, Nick Desaulniers wrote:
>> On Fri, Jul 30, 2021 at 3:38 PM Nathan Chancellor <nathan@kernel.org>=20
>> wrote:
>>>
>>> A recent change in LLVM causes module_{c,d}tor sections to appear when
>>> CONFIG_K{A,C}SAN are enabled, which results in orphan section warnings
>>> because these are not handled anywhere:
>>>
>>> ld.lld: warning:=20
>>> arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_ctor) is being=20
>>> placed in '.text.asan.module_ctor'
>>> ld.lld: warning:=20
>>> arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_dtor) is being=20
>>> placed in '.text.asan.module_dtor'
>>> ld.lld: warning:=20
>>> arch/x86/pci/built-in.a(legacy.o):(.text.tsan.module_ctor) is being=20
>>> placed in '.text.tsan.module_ctor'
>>
>> ^ .text.tsan.*
>=20
> I was wondering why the orphan section warning only arose recently.
> Now I see: the function asan.module_ctor has the SHF_GNU_RETAIN flag, so
> it is in a separate section even with -fno-function-sections (default).

Thanks for the explanation, I will add this to the commit message.

> It seems that with -ffunction-sections the issue should have been caught
> much earlier.
>=20
>>>
>>> Place them in the TEXT_TEXT section so that these technologies continue
>>> to work with the newer compiler versions. All of the KASAN and KCSAN
>>> KUnit tests continue to pass after this change.
>>>
>>> Cc: stable@vger.kernel.org
>>> Link: https://github.com/ClangBuiltLinux/linux/issues/1432
>>> Link:=20
>>> https://github.com/llvm/llvm-project/commit/7b789562244ee941b7bf2cefeb3=
fc08a59a01865=20
>>>
>>> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
>>> ---
>>> =C2=A0include/asm-generic/vmlinux.lds.h | 1 +
>>> =C2=A01 file changed, 1 insertion(+)
>>>
>>> diff --git a/include/asm-generic/vmlinux.lds.h=20
>>> b/include/asm-generic/vmlinux.lds.h
>>> index 17325416e2de..3b79b1e76556 100644
>>> --- a/include/asm-generic/vmlinux.lds.h
>>> +++ b/include/asm-generic/vmlinux.lds.h
>>> @@ -586,6 +586,7 @@
>>>                =20
>>> NOINSTR_TEXT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>>                =20
>>> *(.text..refcount)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 \
>>>                =20
>>> *(.ref.text)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 *(.text.asan=20
>>> .text.asan.*)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>
>> Will this match .text.tsan.module_ctor?

No, I forgot to test CONFIG_KCSAN with this version, rather than the=20
prior one I had on GitHub so I will send v2 shortly.

> asan.module_ctor is the only function AddressSanitizer synthesizes in=20
> the instrumented translation unit.
> There is no function called "asan".
>=20
> (Even if a function "asan" exists due to -ffunction-sections
> -funique-section-names, TEXT_MAIN will match .text.asan, so the
> .text.asan pattern will match nothing.)

Sounds good, I will update it to remove the .text.asan and replace it=20
with .text.tsan.*

>> Do we want to add these conditionally on
>> CONFIG_KASAN_GENERIC/CONFIG_KCSAN like we do for SANITIZER_DISCARDS?

I do not think there is a point in doing so but I can if others feel=20
strongly.

Thank you both for the comments for the comments!

Cheers,
Nathan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/baf67422-8662-02f2-0bbf-6afb141875af%40kernel.org.
