Return-Path: <kasan-dev+bncBAABBDHSVDFQMGQECXQR66I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id D2D7BD31954
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 14:11:42 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-3832fbb70a1sf11268001fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 05:11:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768569102; cv=pass;
        d=google.com; s=arc-20240605;
        b=UikVnfbMHykt6h7oNtO0+lF7YbZuFjkJkcvlPFmmWy1ztt9lxSSQW240NLK7lRkXJu
         hSGTyJvaxZ0RKsnnq8+RxywU+auApnpqti9uEyUlsabIhhKFeikMakzv5BsCcuL4+Q/c
         D7G72uQoE9NwNu7UXAdtXscMeCvKOTVCVSBcMnjL35JNTjNm5hWfTVGGj+kAlwxRXgyI
         GLJLsBlVAmRUjVo9hzNRIdCCqCT9lXromqCrFzzGTcv3W60WWlqNvy0EkyVZdkgZSGzs
         7Zpk0mSSr/OuEinWIwwVGL0GVU68HgwP/ItaqmBCa9Iog6SojQFI3uVpCkgVgzShcUPM
         UnxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=CYmI+VDJXPMl8X8GCLmzRKKyO6RJ9SBONEgdjsxbM/E=;
        fh=gkMUu0WX92rWEltKiA/M3w72QIzfDKU/+NEMlTFHkZ0=;
        b=VIOts/aX5qu8LLzMBDfIkE7X+KUYtGPERZWmW2wFtcSrWDrjOONPqAeOlur2SF5HNc
         uSb5kwFbBHRqNNhXzDxBm6yGJsn3VQ2ixJQuy4iDjcW7O/+OvlpxNvJeCRUImuSTBBCO
         jCgDpLi28ID9kksYqUHVvnur+5GMt1O2RoDgf1CxSvQul2lETKMDASom/x0ZpNwLgQTc
         ri7g9D7fVYztGqLbF/eZj6k0sF7pAPM9Yb+z5mqoDbJw5v7nnNA4i5VJZcJjy9K9Rm0i
         bi6B8lOCXNr2jB/KioWd9PYJjKWWhqQ1YhB1cQVRFydANNRh6RAQXExaqnBiBpCa0/+4
         sxPg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=NsW4vNWI;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.103 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768569102; x=1769173902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=CYmI+VDJXPMl8X8GCLmzRKKyO6RJ9SBONEgdjsxbM/E=;
        b=pRrxVVhrJQwQ1oehk47GbZJUfkkHtSb/x2aGC5+T+uCqo+iguodgHK/6OtZD9qooGs
         5WxvNUMIjzHSRki+urEvf4w3pVpMXoO6huUD/7cIVmOQLM2ezFHcu4a5b2N5cO00/drX
         JXA5xCGCswLGghvUwEipHzU7RGv1r17q9zQaSpDMneArHcU5qg8LBAHWTRlCAbCRJIH9
         Aq+LQlGOLOsri4LHSf2Tv2RbiQ2e0z3NRQKQvkjSU0glCJWv9o8rIbFKiQ8TbOFQ0nin
         CO+GkWAAAD36s9zCZsov31RYPf+EifvzA5USuI8Zp9/akvTPBhFUB4QGaNHvxEsmbjnk
         dRZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768569102; x=1769173902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=CYmI+VDJXPMl8X8GCLmzRKKyO6RJ9SBONEgdjsxbM/E=;
        b=IJegkB9P40KW+UoIeJLJVWWzcJN5zS5xAuLwxZPyU+vgQscwSk05+BtBnY1AlVhLhn
         h6lf16wAEtEwiO/wo30zDfT1ZmwvHs+//7zedcK0XicZ4SoLSqzpHu0YI4nWsXp32qn8
         +TKAU5s6xuzhLMYrnDmPw5cfJkb6QMK133KbdaF3gbUcy4Mhims6vLc7h1pLGDgWgusQ
         AjtkA3SSkQed2SmeXwTNeE3XUQegAsQHpOsr1J944xwrmYBQw+ZuDuvOGVySl1AXB5/Z
         eSqV33JPAwogwLWjOwttnJXXsldFUaHP1dYnoXKC5hNYM7OBKExlLawH76Q0NjgqIlYB
         kBJQ==
X-Forwarded-Encrypted: i=2; AJvYcCUsydKICY4GYdV/Pq5nIk4nEuPJtzb6yvHaSc+uO8hbteBgjmibIGC3N0sPQTgIZI42UWyV1g==@lfdr.de
X-Gm-Message-State: AOJu0YxnHw6owZ5W1NVDwUYVHo1UpSFOQ+NmZvHZQAY77lev9rEsoRM6
	0TTJHBYcN2PYU3UZ7kUp9XhV6C7yEfYN55X3iNFzI69aT/HY1cTdwpvP
X-Received: by 2002:a05:6512:2252:b0:59b:701e:c75a with SMTP id 2adb3069b0e04-59bafdc130emr866818e87.15.1768569101508;
        Fri, 16 Jan 2026 05:11:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EEO67+6bP+L65qA58Yq94teTSQfJJnumlcEL5wD5B21g=="
Received: by 2002:a05:6512:31d2:b0:59b:7bbc:799e with SMTP id
 2adb3069b0e04-59ba6b4b064ls765541e87.1.-pod-prod-04-eu; Fri, 16 Jan 2026
 05:11:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWAsXDuYz/liVt1IgN/ReaVTBU6/E6Zb4NykQ830fD2HYo3F4kbUwh+HEfxLcwt2TVm96RS4ZGvaT4=@googlegroups.com
X-Received: by 2002:a05:6512:2c94:b0:595:7c47:cd47 with SMTP id 2adb3069b0e04-59bafdb5454mr743945e87.2.1768569099393;
        Fri, 16 Jan 2026 05:11:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768569099; cv=none;
        d=google.com; s=arc-20240605;
        b=B5jV1GVVaVhxQKlVArOth0GmOrYbyZTwmSNSmHpSMugipu4jOV1dkLcaUy/7YLXIMp
         qYOId6U6AXMNCogcf+ZiYM6a2pfbLIS6qjULqKmG5z2tKa5b2C6hG/BxO44NnuuxuBVe
         yeZf9LWa49ZqGkJ6DN6v88KP0yc827Zm+eKHF4zSPVIUnUhVSGlNb5s8BFF73xZhFjsQ
         zWf7LAsvm7zYCL0Lc4ON1ZBXcQrd+7rtvLBPYxIbjVmCyTn1JK/kicc0Ap04zvqHwoCC
         1pQN4asu3VcH8iNWjYoPSSJIza+7vo3OUAOldkiuFJyxduse6pmcSve5JQg+NLFrjXW9
         WgTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=VUy6Z0nl3UN06uLRlgqbdTzfRq3/0KilXmceKHyT+FA=;
        fh=5fPtkNbNe79niuQswbjC0Rjam1MSXdsDhVEZDqUvzT4=;
        b=DRex+UsZEonAF6+MoguQ4/SFUP+tZj/VPMkD3MSdcwxoBFe/Qrk7B9tXjXG3lsHU0Q
         UIzRS015qc9IyDy5gDzL0h88QZlOWrvL2QAatIGUOpyKj8GDclVVNCu+kt8/LkwKH7sC
         b5Z81+ul0LHV9pZTzjumiI9PnLzs0W9WGDe4W/ows5a9XU2x3AEQ5aY5f69lmFXfpG4+
         RHZts2NXWLSncQzXwSHaaTeQKIir7Wlj/5DM/0m4K8aI9OsXgoiAJv2E6zC0ZfJqLfZJ
         MZET18BCNcVFck/mN65Rk81WN8qzGOorQJIG8MP91vyH8ngKHsbE0YCDufh+MbyrrR5o
         8Mfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=NsW4vNWI;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.103 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-43103.protonmail.ch (mail-43103.protonmail.ch. [185.70.43.103])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e27d7bsi378821fa.4.2026.01.16.05.11.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 05:11:39 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.103 as permitted sender) client-ip=185.70.43.103;
Date: Fri, 16 Jan 2026 13:11:32 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Jonathan Corbet <corbet@lwn.net>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Jan Kiszka <jan.kiszka@siemens.com>, Kieran Bingham <kbingham@kernel.org>, Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, Samuel Holland <samuel.holland@sifive.com>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, llvm@lists.linux.dev
Subject: Re: [PATCH v8 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
Message-ID: <aWo31aytvelldfiE@wieczorr-mobl1.localdomain>
In-Reply-To: <2592f303-05f5-4646-b59f-38cb7549834e@gmail.com>
References: <cover.1768233085.git.m.wieczorretman@pm.me> <4f31939d55d886f21c91272398fe43a32ea36b3f.1768233085.git.m.wieczorretman@pm.me> <2592f303-05f5-4646-b59f-38cb7549834e@gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 3ed341666d06b561ea7c217cda5b5d4311dd5d20
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=NsW4vNWI;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.103 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

Thanks for looking at the patches :)

On 2026-01-15 at 23:42:02 +0100, Andrey Ryabinin wrote:
>
>
>On 1/12/26 6:27 PM, Maciej Wieczor-Retman wrote:
> =20
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index 62c01b4527eb..b5beb1b10bd2 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -642,11 +642,39 @@ void kasan_non_canonical_hook(unsigned long addr)
>>  	const char *bug_type;
>> =20
>>  	/*
>> -	 * All addresses that came as a result of the memory-to-shadow mapping
>> -	 * (even for bogus pointers) must be >=3D KASAN_SHADOW_OFFSET.
>> +	 * For Generic KASAN, kasan_mem_to_shadow() uses the logical right shi=
ft
>> +	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values (on
>> +	 * both x86 and arm64). Thus, the possible shadow addresses (even for
>> +	 * bogus pointers) belong to a single contiguous region that is the
>> +	 * result of kasan_mem_to_shadow() applied to the whole address space.
>>  	 */
>> -	if (addr < KASAN_SHADOW_OFFSET)
>> -		return;
>> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
>> +		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0ULL)) ||
>> +		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
>> +			return;
>> +	}
>> +
>> +	/*
>> +	 * For Software Tag-Based KASAN, kasan_mem_to_shadow() uses the
>> +	 * arithmetic shift. Normally, this would make checking for a possible
>> +	 * shadow address complicated, as the shadow address computation
>> +	 * operation would overflow only for some memory addresses. However, d=
ue
>> +	 * to the chosen KASAN_SHADOW_OFFSET values and the fact the
>> +	 * kasan_mem_to_shadow() only operates on pointers with the tag reset,
>> +	 * the overflow always happens.
>> +	 *
>> +	 * For arm64, the top byte of the pointer gets reset to 0xFF. Thus, th=
e
>> +	 * possible shadow addresses belong to a region that is the result of
>> +	 * kasan_mem_to_shadow() applied to the memory range
>> +	 * [0xFF000000000000, 0xFFFFFFFFFFFFFFFF]. Despite the overflow, the
>                  ^ Missing couple 00 here
>
>> +	 * resulting possible shadow region is contiguous, as the overflow
>> +	 * happens for both 0xFF000000000000 and 0xFFFFFFFFFFFFFFFF.
>                                  ^ same as above

Hah, right, thank you!

>
>> +	 */
>> +	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) && IS_ENABLED(CONFIG_ARM64)) {
>> +		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0xFFULL << 56)=
) ||
>
>This will not work for inline mode because compiler uses logical shift.
>Consider NULL-ptr derefernce. Compiler will calculate shadow address for 0=
 as:
>      (((0x0 | 0xffULL) << 56) >> 4)+0xffff800000000000ULL =3D 0x0fef8000.=
...0
>Which is less than ((0xFF00...00LL) >> 4) +  0xffff800000000000ULL =3D 0xf=
fff800...0
>So we will bail out here.
>Perhaps we could do addr |=3D 0xFFLL to fix this

I suppose it should work; tried it in a python script by shoving various
addresses into this check. Pushing addresses through a logical shift
memory_to_shadow normally would return early as you noticed, and after 'add=
r |=3D
0xFFLL' it seems to work as expected. And I didn't really catch any incorre=
ct
address slipping by this scheme either. Thanks, I'll correct it.

>
>> +		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
>> +			return;
>> +	}
>> =20
>>  	orig_addr =3D (unsigned long)kasan_shadow_to_mem((void *)addr);
>> =20

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
Wo31aytvelldfiE%40wieczorr-mobl1.localdomain.
