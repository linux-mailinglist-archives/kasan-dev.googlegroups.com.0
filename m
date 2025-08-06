Return-Path: <kasan-dev+bncBCSL7B6LWYHBBYPEZ3CAMGQELSTQL3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F6B3B1CC9C
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 21:52:03 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-70f92ed6c95sf21133917b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 12:52:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754509921; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ilh5LG8E3zWq3CPGGd8lm4OgqR3WMEpAvMpzN/opEsa/eUX4Zoornd2Dr4O94Mr1dt
         JThszpcu10x9QX0YXrf9AIvpGRiv0685E090bPWPwtogD7lYzG/CqD2vWzRXjDIDUSwC
         RIECCXGtmZujidAqrV3vbOAQTjTsmAqgT9G4ss4N8aGDh4ht2jNUSMTNhPvm/+AWT/Jj
         ZLKlAaeKbWr7S0NGNFORUl22989hrX5540iT4gAHR0J6EipYAuVHpaOhE3vgJ/UbGyhi
         SV14hOCotMZMUTpEA8TIXfqlU8p8c4/wFKBjkmKj7d3RZ5HA6aBTPSRLOKrtgVJIcxG7
         14KA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=8kdM/6CcTmwvUnVjT10a9weM8PuOwZGTMUFSI+lbH5E=;
        fh=ZIYb+evb8vYKfA9lYaBIrVgZ7BlmEQGlJ4vTfIu2j4k=;
        b=i7YXVRs6LTzbAHofY5Qh2nzGhxch+UDYRvHjMpNP0aV7LBk/NEj/iz2FbBprxLhqEo
         NkxAYPf8X2jbq+IBcZQamVFNFJapMfhs0G8BySrT0Nosn5q7rhxrphvd3gvKGRtg8Id/
         gq1HIBGBZZvXfs5WCT3zYBicN61bjxz1ebtefX7xaZNqCGm7qF9SA+zmqWyEnsiBwRqV
         ZONe3l9yHoRQCFA4B0XOjt0WgWwxq2IsgBJa2xGHfyN6sHKmHg5blSLnDQEJ4dvN13eY
         D3rsNmAIwAqsriQiA4rFPnY5gMk3T8rGFpC2jtvym8HBNHENTwMOvty4JRDo6GM5CVJa
         nlVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZafsGo97;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754509921; x=1755114721; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8kdM/6CcTmwvUnVjT10a9weM8PuOwZGTMUFSI+lbH5E=;
        b=CCRH3AHwlsIwsQir3VfI3SaQGr9t3O+pcn9eWiroJSi2LMoBOo1F8dr+1mZHf02WBz
         LuiNv8kzymoaLvgbu07HFN8mQVEYgi65LW9QOOpiOc1+1MDIoAsr3AiSN6f71r1Lzq/R
         oOGxVu3lwyV/pmPrUqsUHJBUJakD6sQc8oG8evm01aexB6z6OegUJedtmDeYe6UDErXv
         cBccq8lgRL0AmhPgR/m/B3h4v5weVThAvw7D0ymHWOKWI1cgZFROforPe/yXooyCDBOR
         Ojs9dKaBkiEwwhjs0xm+nF+g2iTWPNv9TW2OuI49tdbrfQUKqTrCQpJK6KT+yz3Py/Dc
         /c/g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754509921; x=1755114721; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=8kdM/6CcTmwvUnVjT10a9weM8PuOwZGTMUFSI+lbH5E=;
        b=YkPdiiTQ/pzQAXNNjnSy46wTBfXonGt2WMdnpk7jpIVjZ18XEc8uoRtplnunLWuCk2
         mUN9MkxWGqqApoHO88Ch6Hz70ACyowOZC32H9GKf0wBWb3YgyVn3JhIh2nWcscr2dRWR
         2j0C66bSqtFAS3BkeReySavY959Ka4LWQHzGE1FqzP0K5Yf4ZJHM273kPz0wnExP7ryo
         WXXtBTRIAU/ect5z5rRJHEO8hWfWI5N76D5Yy2BRu6LXXZexNQ7XojR5j2Rtzji82s95
         ontSxkj1NUgFEZgQYgNwPZ5K9z8EYPj2gfs8ERKGIEPG9eGZM5s0FagZuDIQoiPtGrmF
         Gs9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754509921; x=1755114721;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8kdM/6CcTmwvUnVjT10a9weM8PuOwZGTMUFSI+lbH5E=;
        b=mwhPC1bmWbNNVi5gqSxgn0gQ0d1rV/7MMI8vqxWTL27/ix0jPsoP9PGE4r1VOm6SBX
         U7rZsVXYu16b/M37Af1whAPcmUicWzm7KwoFIrmwS9Paml0YXB17UmHruNYueeED3INW
         a7UVPABmMPDY2e8qt8lMwTcdegsD5OF86jpqdPcrilDCTxf3YhbgrAVMJ2I/U2X3pTDc
         IaUYyZhuXUwtO4zh7qm3mcE2rrdoocXdDeBdjhkXFO3yUDGta4fca8TWXgDP02RMu/Uk
         FuaHfLAvApJQk8yCtqKPomlHvyjPKx+fsGBigDApOt8cpWG3aCbTcrzoQ7rNUdVK3XbD
         IQVQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU8vFA4M3lWvUd588GS+stO0LXVNx8Zh4I2fTla/KKrJZe9wxYHo28AzeRqCkvjvHwdLrp7IQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywzkv8ctAFbFHA7TOEraBMozCc4+tlMRTOQpBChJdcudxw6j1bP
	d65j5GFi6Ut9E6ECD633RK3eIpJpfM1RIEYn8ASXdK17xu++taeLYqpZ
X-Google-Smtp-Source: AGHT+IGenmcvheAET5N+vTklpUhWDt5K11tDEqCYSq7FN8BbiFfVOLvU9EJPqBsBZDjvQh1WClfKSA==
X-Received: by 2002:a25:d64d:0:b0:e8e:d61:a665 with SMTP id 3f1490d57ef6-e9038cdd8a3mr1024414276.5.1754509921318;
        Wed, 06 Aug 2025 12:52:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf7VCwO+mBj4B/CedIYUN5qnj8HAlYyggzFtrx6va35+A==
Received: by 2002:a05:6902:1101:b0:e8d:a1a4:9cae with SMTP id
 3f1490d57ef6-e9031545596ls512545276.2.-pod-prod-00-us-canary; Wed, 06 Aug
 2025 12:52:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXgWN4GWpANYrASRA4/8Vx9WmNpOHv2Gxclgfv/+WLa8hD3s9N3HECc/pS3De32lWjxQGiFsMtPbE8=@googlegroups.com
X-Received: by 2002:a05:690c:3585:b0:71b:7085:f14a with SMTP id 00721157ae682-71bdae9e417mr12512377b3.3.1754509920126;
        Wed, 06 Aug 2025 12:52:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754509920; cv=none;
        d=google.com; s=arc-20240605;
        b=Wg2VoMKHyw1Lqr1kBZeWRcJ+2uz8i5jcWdjORYBJV+f37EeOekMm3swFSwWYBaPeAk
         XHLuculEsJ5bQvhihXDhoXSUKh9ewYHLNmWvQjZ89ky1bfqbIE0CKAM77ZzBtDOErF2a
         XKauP3J+9aTzM+yOZ7UWiwYJMc3A2vUaq9iKUB5OAIJV9RSwEIMqVUw2JOs4/gdYjT93
         TreM8BpPwsdytiEhGSGfBanIdkOVAJkoe6ChATCXG/9tlGSWCsfwAs7D+9aJYwjAgqHy
         OCkg1gWZxQCBYq2EwkmLKutBN2IaWraPvUbL+6csqXRPrnKtFh1nCP/cb0u+sQu1T8P/
         Pcjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=jOJUufvksrkNMkhUfUMzFksoWwIudiaNrjydPYTPe/E=;
        fh=8dbnHnhQrmemZxc66TZ2XbGby2G8zNp85GThQVPqx1U=;
        b=gdRYemc0LNx7uNpZ7/Sl4bYnj2S4VVmZK+O8x9V2vkWB4TdPonPIh+jc5nRIfVamHJ
         ycO+74MckDUdfPqHpuxpyZJGtuozjFhrgQDOO/fkterKIfFZ/kT1pXwgAFkid59/YvwU
         7Xu8d8jKGq5rRC4fiACHVISIMZVqn22LeHU+CZcUvPEqZ0Eg0Q75YwG8E/ykLq8n7T6p
         Ml55e6zaJJTSYP95JpCTGRLM3MDlU0Lr89HV9GdEMF+gFiDl3ra6MM4CDiACZH8uQu/4
         c7KEHTF8LsI0Me5o4IdTjPCUq9+JZZVOKFN49ayViatSCssWGmtLYQiXDfyiEugiyXM3
         RjKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZafsGo97;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71b6ad06c2fsi5987067b3.4.2025.08.06.12.52.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 12:52:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id af79cd13be357-7e665fd4e90so1451985a.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Aug 2025 12:52:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXo9lyr2J/fJ7Zm1J3Vx3UhUivLaTvwFCo42UtwZN6WPOWJkDW9SO5PgLUB67oZ+HxFulz8N9PGmjg=@googlegroups.com
X-Gm-Gg: ASbGncsPWfF7KmGcqqfNbJqpngrZhdzbVsav2BUOoNk5C1J+TIkV8WBY/AUdRocMJ6r
	c2S8r9NQ2wtibwT+Lw7yE6O80C8UHTfL6sKlXTK2nBISg+mAtgTh77cZYINLBzCAv1C5dga+Im9
	C13Xu5f93NBRSycDFPwjTAV06l17nXCZ48na3t1kXssgz2igM0XEc0tFQQ+U7dea5QSYljeNe9w
	i+2uzI+WodzsX6iYyRJ1ermIgv/U3hJJAPos+tvB5EHrKdMabTSGGn8+6SmP+8DH0Nun2iPD1KS
	hH26cbwMcgJrHoqVzrKpr2pq8CDYfBrtNyueC12sGvu/9TooXuB8jGBa6xPDxejaYfKjpfYB/fj
	t/FVCfXNntFu6JT3kbgqqhqMHIu+6Mmf6IaQGBSQQmRAHa5VqZx4Xw+FKC9FVH/wy4+H+
X-Received: by 2002:a05:620a:1a04:b0:7e2:6be2:38eb with SMTP id af79cd13be357-7e814d64573mr316228785a.4.1754509919359;
        Wed, 06 Aug 2025 12:51:59 -0700 (PDT)
Received: from [192.168.0.18] (cable-94-189-140-132.dynamic.sbb.rs. [94.189.140.132])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-7e67f5c55a2sm866617085a.36.2025.08.06.12.51.55
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 12:51:58 -0700 (PDT)
Message-ID: <dd25cb14-5df1-4b2c-bff7-0ca901dfd824@gmail.com>
Date: Wed, 6 Aug 2025 21:51:07 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 1/9] kasan: introduce ARCH_DEFER_KASAN and unify static
 key across modes
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com,
 agordeev@linux.ibm.com, akpm@linux-foundation.org, zhangqing@loongson.cn,
 chenhuacai@loongson.cn, trishalfonso@google.com, davidgow@google.com,
 glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250805142622.560992-1-snovitoll@gmail.com>
 <20250805142622.560992-2-snovitoll@gmail.com>
 <5a73e633-a374-47f2-a1e1-680e24d9f260@gmail.com>
 <CACzwLxg=zC-82sY6f-z0VOnmbpN2E8tQxe7RyOnynpbJEFP+NA@mail.gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <CACzwLxg=zC-82sY6f-z0VOnmbpN2E8tQxe7RyOnynpbJEFP+NA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZafsGo97;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::731
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



On 8/6/25 4:15 PM, Sabyrzhan Tasbolatov wrote:
> On Wed, Aug 6, 2025 at 6:35=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmai=
l.com> wrote:
>>
>>
>>
>> On 8/5/25 4:26 PM, Sabyrzhan Tasbolatov wrote:
>>> Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures that need
>>> to defer KASAN initialization until shadow memory is properly set up,
>>> and unify the static key infrastructure across all KASAN modes.
>>>
>>> Some architectures (like PowerPC with radix MMU) need to set up their
>>> shadow memory mappings before KASAN can be safely enabled, while others
>>> (like s390, x86, arm) can enable KASAN much earlier or even from the
>>> beginning.
>>>
>>> Historically, the runtime static key kasan_flag_enabled existed only fo=
r
>>> CONFIG_KASAN_HW_TAGS mode. Generic and SW_TAGS modes either relied on
>>> architecture-specific kasan_arch_is_ready() implementations or evaluate=
d
>>> KASAN checks unconditionally, leading to code duplication.
>>>
>>> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
>>> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
>>> ---
>>> Changes in v4:
>>> - Fixed HW_TAGS static key functionality (was broken in v3)
>>
>> I don't think it fixed. Before you patch kasan_enabled() esentially
>> worked like this:
>>
>>  if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>>         return static_branch_likely(&kasan_flag_enabled);
>>  else
>>         return IS_ENABLED(CONFIG_KASAN);
>>
>> Now it's just IS_ENABLED(CONFIG_KASAN);
>=20
> In v4 it is:
>=20
>         #if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_T=
AGS)
>         static __always_inline bool kasan_shadow_initialized(void)
>         {
>                 return static_branch_likely(&kasan_flag_enabled);
>         }
>         #else
>         static __always_inline bool kasan_shadow_initialized(void)
>         {
>                 return kasan_enabled(); // which is IS_ENABLED(CONFIG_KAS=
AN);
>         }
>         #endif
>=20
> So for HW_TAGS, KASAN is enabled in kasan_init_hw_tags().

You are referring to  kasan_shadow_initialized(), but I was talking about k=
asan_enabled() specifically.
E.g. your patch changes behavior for kasan_init_slab_obj() which doesn't us=
e kasan_shadow_initialized()
 (in the case of HW_TAGS=3Dy && kasan_flag_enabled =3D false) :

static __always_inline void * __must_check kasan_init_slab_obj(
                                struct kmem_cache *cache, const void *objec=
t)
{
        if (kasan_enabled())
                return __kasan_init_slab_obj(cache, object);
        return (void *)object;
}



>>> +#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
>>> +/*
>>> + * Global runtime flag for KASAN modes that need runtime control.
>>> + * Used by ARCH_DEFER_KASAN architectures and HW_TAGS mode.
>>> + */
>>>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>>>
>>> -static __always_inline bool kasan_enabled(void)
>>> +/*
>>> + * Runtime control for shadow memory initialization or HW_TAGS mode.
>>> + * Uses static key for architectures that need deferred KASAN or HW_TA=
GS.
>>> + */
>>> +static __always_inline bool kasan_shadow_initialized(void)
>>
>> Don't rename it, just leave as is - kasan_enabled().
>> It's better name, shorter and you don't need to convert call sites, so
>> there is less chance of mistakes due to unchanged kasan_enabled() -> kas=
an_shadow_initialized().
>=20
> I actually had the only check "kasan_enabled()" in v2, but went to
> double check approach in v3
> after this comment:
> https://lore.kernel.org/all/CA+fCnZcGyTECP15VMSPh+duLmxNe=3DApHfOnbAY3Nqt=
FHZvceZw@mail.gmail.com/

AFAIU the comment suggest that we need two checks/flags, one in kasan_enabl=
ed() which checks
whether kasan was enabled via cmdline (currently only for HW_TAGS)
 and one in kasan_arch_is_ready()(or kasan_shadow_initialized()) which chec=
ks if arch initialized KASAN.
And this not what v3/v4 does. v4 basically  have one check, just under diff=
erent name.=20

Separate checks might be needed if we have code paths that need 'kasan_arch=
_is_ready() && !kasan_enabled()'
and vise versa '!kasan_arch_is_ready() && kasan_enabled()'.

From the top of my head, I can't say if we have such cases.

>=20
> Ok, we will have the **only** check kasan_enabled() then in
> kasan-enabled.h which
>=20
>         #if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_T=
AGS)
>         static __always_inline bool kasan_enabled(void)
>         {
>                 return static_branch_likely(&kasan_flag_enabled);
>         }
>         #else
>         static inline bool kasan_enabled(void)
>         {
>                 return IS_ENABLED(CONFIG_KASAN);
>         }
>=20
> And will remove kasan_arch_is_ready (current kasan_shadow_initialized in =
v4).
>=20
> So it is the single place to check if KASAN is enabled for all arch
> and internal KASAN code.
> Same behavior is in the current mainline code but only for HW_TAGS.
>=20
> Is this correct?
>=20

Yep, that's what I meant.

>>
>>
>>>  {
>>>       return static_branch_likely(&kasan_flag_enabled);
>>>  }
>>>
>>> -static inline bool kasan_hw_tags_enabled(void)
>>> +static inline void kasan_enable(void)
>>> +{
>>> +     static_branch_enable(&kasan_flag_enabled);
>>> +}
>>> +#else
>>> +/* For architectures that can enable KASAN early, use compile-time che=
ck. */
>>> +static __always_inline bool kasan_shadow_initialized(void)
>>>  {
>>>       return kasan_enabled();
>>>  }
>>>
>>
>> ...
>>
>>>
>>>  void kasan_populate_early_vm_area_shadow(void *start, unsigned long si=
ze);
>>> -int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
>>> -void kasan_release_vmalloc(unsigned long start, unsigned long end,
>>> +
>>> +int __kasan_populate_vmalloc(unsigned long addr, unsigned long size);
>>> +static inline int kasan_populate_vmalloc(unsigned long addr, unsigned =
long size)
>>> +{
>>> +     if (!kasan_shadow_initialized())
>>> +             return 0;
>>
>>
>> What's the point of moving these checks to header?
>> Leave it in C, it's easier to grep and navigate code this way.
>=20
> Andrey Konovalov had comments [1] to avoid checks in C
> by moving them to headers under __wrappers.
>=20
> : 1. Avoid spraying kasan_arch_is_ready() throughout the KASAN
> : implementation and move these checks into include/linux/kasan.h (and
> : add __wrappers when required).
>=20
> [1] https://lore.kernel.org/all/CA+fCnZcGyTECP15VMSPh+duLmxNe=3DApHfOnbAY=
3NqtFHZvceZw@mail.gmail.com/
>=20

I think Andrey K. meant cases when we have multiple implementations of one =
function for each mode.
In such case it makes sense to merge multiple kasan_arch_is_ready() checks =
into one in the header.
But in case like with kasan_populate_vmalloc() we have only one implementat=
ion so I don't see any
value in adding wrapper/moving to header.=20

>>
>>
>>> +     return __kasan_populate_vmalloc(addr, size);
>>> +}
>>> +
>>> +void __kasan_release_vmalloc(unsigned long start, unsigned long end,
>>>                          unsigned long free_region_start,
>>>                          unsigned long free_region_end,
>>>                          unsigned long flags);
>>> +static inline void kasan_release_vmalloc(unsigned long start,
>>> +                        unsigned long end,
>>> +                        unsigned long free_region_start,
>>> +                        unsigned long free_region_end,
>>> +                        unsigned long flags)
>>> +{
>>> +     if (kasan_shadow_initialized())
>>> +             __kasan_release_vmalloc(start, end, free_region_start,
>>> +                        free_region_end, flags);
>>> +}
>>>
>>
>> ...> @@ -250,7 +259,7 @@ static inline void poison_slab_object(struct km=
em_cache *cache, void *object,
>>>  bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
>>>                               unsigned long ip)
>>>  {
>>> -     if (!kasan_arch_is_ready() || is_kfence_address(object))
>>> +     if (is_kfence_address(object))
>>>               return false;
>>>       return check_slab_allocation(cache, object, ip);
>>>  }
>>> @@ -258,7 +267,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache=
, void *object,
>>>  bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool in=
it,
>>>                      bool still_accessible)
>>>  {
>>> -     if (!kasan_arch_is_ready() || is_kfence_address(object))
>>> +     if (is_kfence_address(object))
>>>               return false;
>>>
>>>       poison_slab_object(cache, object, init, still_accessible);
>>> @@ -282,9 +291,6 @@ bool __kasan_slab_free(struct kmem_cache *cache, vo=
id *object, bool init,
>>>
>>>  static inline bool check_page_allocation(void *ptr, unsigned long ip)
>>>  {
>>> -     if (!kasan_arch_is_ready())
>>> -             return false;
>>> -
>>
>>
>> Well, you can't do this yet, because no arch using ARCH_DEFER_KASAN yet,=
 so this breaks
>> bisectability.
>> Leave it, and remove with separate patch only when there are no users le=
ft.
>=20
> Will do in v5 at the end of patch series.
>=20
>>
>>>       if (ptr !=3D page_address(virt_to_head_page(ptr))) {
>>>               kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_F=
REE);
>>>               return true;
>>> @@ -511,7 +517,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsig=
ned long ip)
>>>               return true;
>>>       }
>>>
>>> -     if (is_kfence_address(ptr) || !kasan_arch_is_ready())
>>> +     if (is_kfence_address(ptr))
>>>               return true;
>>>
>>>       slab =3D folio_slab(folio);
>>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d=
d25cb14-5df1-4b2c-bff7-0ca901dfd824%40gmail.com.
