Return-Path: <kasan-dev+bncBDW2JDUY5AORBMGAZW6QMGQENWKTEKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C032CA388E7
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 17:13:38 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-5461c19d32csf816508e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 08:13:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739808818; cv=pass;
        d=google.com; s=arc-20240605;
        b=XfgoCoGvIHS9/vGNp7b080YSSs2e2Fc864Df6G0AS6YKX7b6t3hyxDLteGoOGwMsdy
         7gOm6cKEwHrJND5pUHmIUAO3XY85qOzQbDsiGdnxDIRi5/nhtOKR+rFvR2t4NIBbM1an
         DPvKSW4z0a3/hm+z6lqFkn8EpC4ibZjCMH31kyBO6p1btKHZiyF2bG51gjAlyzPEGtS1
         W3EGm2aPCFrxltw4cflvWOxBlh/H38ohF0lQo+UTzfKRIVv8lPmN+D01/N3/jiYlmHvV
         NK61AZRpX1RHYLTQ2M9TjxQz5wnE+GAAFGvgxqrduxkajdxe3c3i5pxJLdkfZGYd6Oq/
         C1cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=xrDKvKcg7dNiq8If+Z/akApjTtIpZVftZWAp4pN2uv0=;
        fh=aPCfAVw14MnuAs1RS+RsLqvVpgo+NgEs+kajAtkaWic=;
        b=Fcy8XB8BZeoYbBf3NGwMpRZEihyayQKBH8LnBAPPelNvN4h8Byq46nyGwv0Ps868ZU
         /yDh7P+HQ4IfAo+ZvCwgw9ZxV9DaPSGN4XvuS/c3fVTFVgAmRPXO5+XCHwPD4IgbdPNL
         lMUK3k8sZDvsp/Om2X6lIuDjnAf4+/KDuPLU+It7H51PR11yLevzQBz6lePx3cD/9SR2
         LYemxGXr7A5RSErgZixiRQjPPXV3PlYSKU8uWWSOxfmz1Z2aByPnQ6FuSXG6FOd/PY5X
         OmW5Is5MuBTX18NLNR0jgIaC8PS4ZYJYIqMjwVib5lVF6VQDinoZm8LT0D34islXHNdX
         g5Cw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jiA9Konm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739808818; x=1740413618; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xrDKvKcg7dNiq8If+Z/akApjTtIpZVftZWAp4pN2uv0=;
        b=RhgZEYDRGFXziutTaJqxBLa/pq/6yMFn8gblRvqxqn1BXMe9yLiJiDfmvstVCeyHF7
         tKCUpGt+dxuJ5B5JwoSRnAbWZGg/bXzCuBF8Mk7wBlHX0P/y5msZAhpsyaNURxSCIqHe
         iTf5HSpRsmDEfegKiItP25oSXLdRdeYUKCAp9G1deMnfy5VeVj0f+td9Ce3gnQDTFZUQ
         e412j8pjgHlVbwTqvs5e+PujNn6nCbqCYD2QAW1xX9A2VMWN1L/CKUz/f2I9X0eIfcMM
         Pg9bV8THZxH0FAkwW4jwFP5H5tYNE7J7CF3LM8FHrt+JE/0u5kPNeV+RoOF378yCXKE4
         NvRg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739808818; x=1740413618; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xrDKvKcg7dNiq8If+Z/akApjTtIpZVftZWAp4pN2uv0=;
        b=BySM/Mi08uBGNwKZzcBj+lLPXzQk7YPKUfkBr09GGxV4ds5B3Cic778UE/WTBqBKE3
         4Gmg0LVyToCe8tmg7HdVQBI21rdqMzcMYD89fXB+8R2nh41lukDCuEYF/jVWe5Rt3knr
         XBM1mQR26tLW+ftmVXVqkKtTAANvSwwpZhbbNluLRPvtnn0Ahjfne1jd/UeqvsrzhZlg
         Uuj2ALCeD+LHBHGkm9A+EeL814OxN05RodZaMsNyg/QOHsVh1xS9B2rNiq4SR6Do4d+2
         erigsEhSywf/NYdlNdA5uUMH4ZlMugFsTSdHwywTNmgFcc1sG0V1AD43yX2klhD/Dxcr
         CR/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739808818; x=1740413618;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xrDKvKcg7dNiq8If+Z/akApjTtIpZVftZWAp4pN2uv0=;
        b=Az3Lsdj5P9cKbm0EOnJmpcegPIVghWIUpTw718+VtUx1FEkcd2BCqyQqN0NiGsvIz2
         WKg/MUMoWA8wFjzkKiNvJfcBkQoXRM/yGX7XPXgvm8cCbpkZISZ2ll3N6b3Ortic1CQN
         Ohie/VTcb7UebavjbAb4Acze2dZVKiuDrzoFCbZy3DBYIdbuiAj+Nzy6XLy5M3mkmmRr
         6pRWUjs+NgiQuUjNg2bqmajNrik+MbtPq4JdMOjVYRu2FzyPb/ll2UCwikv6rR1OLQyg
         qgKkWnsJ742Qqz5KPFcczCxjn2V6kNKLx4mclfztwRDvZ7uV0pP31STHFYgAAmG1NhZm
         dLyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnPyLcpAEOYiDvSDNGRWTCn0or3SfjIhgN90mXN96LNZcg71yxnx2KMRN5oEimDK3ElAt36g==@lfdr.de
X-Gm-Message-State: AOJu0Yxps9DUe//WuSFpa/uncJ+1/W+/VuU9thpLr6cqe13WEw/3qE8i
	FfxHT3UDmFQBH/YS6ho2Ch68GOYAjHs8Z9/JYyfINWf9ARnUf4lN
X-Google-Smtp-Source: AGHT+IErfMyPpXzX6YFDhBV+W/FrjdXLnSpA3gwTwMCJjylEKuarTqyZU6KZF33btH+YyJtFnRjBJQ==
X-Received: by 2002:a05:6512:33d0:b0:545:ebf:145f with SMTP id 2adb3069b0e04-5452fe95fb2mr2527081e87.53.1739808817404;
        Mon, 17 Feb 2025 08:13:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEd5uZv3IGrbdbaIG9nGIWqIqrAVxjkFgI0bmawnlhqbw==
Received: by 2002:ac2:484d:0:b0:545:375:b59c with SMTP id 2adb3069b0e04-545247963f3ls110279e87.1.-pod-prod-07-eu;
 Mon, 17 Feb 2025 08:13:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUb6SxDjCME+f89uYMnD4for08/QNkCaENDC3SwvcND8thE8tCG+QkUs/qamL5dYttjTYFxZS54eAw=@googlegroups.com
X-Received: by 2002:a05:6512:2398:b0:545:aa5:d451 with SMTP id 2adb3069b0e04-5452fe3a8a9mr3637235e87.25.1739808814907;
        Mon, 17 Feb 2025 08:13:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739808814; cv=none;
        d=google.com; s=arc-20240605;
        b=XNkM6VxPvFgsqxEzYyWYzT/SSpwdIvmAhGgkiTnM9DHVFk/KHgGXAqQf8wGpya/kZK
         M5EbEp7KVsYOWLUIQYwRoK2iKTtfPzDiC4YzxYkfMMIV0i6ZBYS3u8p4S0FEsnSd75tj
         vb4KQzsFjvv1zU4JMxChAcW3JH9X5xPuhaA7/2MmPQPSgp8pIFk1QPqh4pLBeBfPAzoA
         j1dvrvJjNm7+ndjLkssPCvSUxtSTa9wlMVWvvYQdWepWdAfh/zH3bdi5OMRJg1m6WBwB
         KB7jPjsNRYkjU5jhRcQ+B7v0hWY2ovth/U1qQs7qy6rusjRiuwb9rVPXZoamsPJ/LwEV
         fX/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1KxbE/LUi+pBeXrp6r1WoRsJN4gZHatc3HSxCggqAc8=;
        fh=Q5rv0ly7E5WNZwz5GC7JSnjwVxVAx6yJvcP4J56eqOQ=;
        b=dLqNm36+xW7UWW/JyemvvghPAXEsiqN/Sx6t5Ilp65uQo/zPh76uLIv4o6MWWd54cU
         D7ZoJVhdWPimzvOrgL29hmOZaxeuYkIAx6+XZaBzeNoPwFIprlOu3ezx0bCH5wJLD+yx
         wn+aSN/XnZ5H5hfV5lu8xnnZBauZO1XtVEKMBR69CUbhopPeu9wudhfUm3SOOPkE2kuE
         Weul6n/2r33O+lHXQ075t/nEQr+l/m46n+n58bZxtP6/LRoLK8VJyde6CtZp7pxwTQhw
         kfYrI2xlvCJstWu08zoD7GmEjqYOFxclSXneTycnORJj6FHbAdbWyOJWMBqxSN0bjOaL
         Nfmw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jiA9Konm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5451f130563si100333e87.8.2025.02.17.08.13.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Feb 2025 08:13:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-38f32c1c787so1899180f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 17 Feb 2025 08:13:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU+V0S0Kg69lCtL/aWQjdBFcdjK9fbQ0Qzaq38dMcgGT0WgccD5m8ZeAxs+mkLrWY+sUp5pMREgeco=@googlegroups.com
X-Gm-Gg: ASbGncs4Pz7QTLD4UO3vAZoOw1vAKR8+boobL+kCxEcY1dZdQWRMb8u1SfQImo/fyoy
	CfsQC9zweHrkw6N1YCa7abfqFnH/JG/pYJonBMcla5yJtdTaJFP4uVMPlBWVImAMBOqgViyYqFy
	o=
X-Received: by 2002:a5d:64cc:0:b0:38f:4fa6:bb24 with SMTP id
 ffacd0b85a97d-38f4fa6bca3mr698753f8f.39.1739808814051; Mon, 17 Feb 2025
 08:13:34 -0800 (PST)
MIME-Version: 1.0
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
 <20241022015913.3524425-2-samuel.holland@sifive.com> <CA+fCnZeBEe3VWm=VfYvG-f4eh2jAFP-p4Xn4SLEeFCGTudVuEw@mail.gmail.com>
 <e7t5yzfw3dq5stp5xjy5yclcx6ikne4vwz7d6w2ukfw2b7gr6t@oomoynf3b2jl>
 <zjuvfdbl7q76ahdxk3lrgaznk7vjj43f5ftzfgrnca6dqtcd5x@5qj24womzgyq>
 <CA+fCnZfySpeRy0FCFidLdUUeqp97eBdjAqQyYPpz1WxYwcsW9A@mail.gmail.com>
 <aqhm7lc57srsfuff3bceb3dcmsdyxksb7t6bgwbqi54ppevpoh@apolj3nteaz6>
 <CA+fCnZdjTkreTcoo+J8wMhwDuAFM4g33U5BFy0OPtE0UCvyJbQ@mail.gmail.com>
 <CA+fCnZcoVdfXVN8VBFLx835cV0eGAT6Ewror2whLW761JnHjNQ@mail.gmail.com>
 <sjownmnyf4ygi5rtbedan6oauzvyk2d7xcummo5rykiryrpcrt@kasomz5imkkm> <tuwambkzk6ca5mpni7ev5hvr47dkbk6ru3vikplx67hyvqj2sw@rugqv7vhikxb>
In-Reply-To: <tuwambkzk6ca5mpni7ev5hvr47dkbk6ru3vikplx67hyvqj2sw@rugqv7vhikxb>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 17 Feb 2025 17:13:23 +0100
X-Gm-Features: AWEUYZmQ1uvVHZE607fk9A3oqamhim11vzns-dfPoe7sFHHzYYWlnLIpBeOBi1A
Message-ID: <CA+fCnZcHnWr0++8omB5ju8E3uSK+s+JOFZ3=UqgtVEcBzrm2Lg@mail.gmail.com>
Subject: Re: [PATCH v2 1/9] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: Samuel Holland <samuel.holland@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	linux-riscv@lists.infradead.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	llvm@lists.linux.dev, Catalin Marinas <catalin.marinas@arm.com>, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Alexandre Ghiti <alexghiti@rivosinc.com>, Will Deacon <will@kernel.org>, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jiA9Konm;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Fri, Feb 14, 2025 at 9:21=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> On 2025-02-13 at 17:20:22 +0100, Maciej Wieczor-Retman wrote:
> >On 2025-02-13 at 02:28:08 +0100, Andrey Konovalov wrote:
> >>On Thu, Feb 13, 2025 at 2:21=E2=80=AFAM Andrey Konovalov <andreyknvl@gm=
ail.com> wrote:
> >>>
> >>> On Tue, Feb 11, 2025 at 7:07=E2=80=AFPM Maciej Wieczor-Retman
> >>> <maciej.wieczor-retman@intel.com> wrote:
> >>> >
> >>> > I did some experiments with multiple addresses passed through
> >>> > kasan_mem_to_shadow(). And it seems like we can get almost any addr=
ess out when
> >>> > we consider any random bogus pointers.
> >>> >
> >>> > I used the KASAN_SHADOW_OFFSET from your example above. Userspace a=
ddresses seem
> >>> > to map to the range [KASAN_SHADOW_OFFSET - 0xffff8fffffffffff]. The=
n going
> >>> > through non-canonical addresses until 0x0007ffffffffffff we reach t=
he end of
> >>> > kernel LA and we loop around. Then the addresses seem to go from 0 =
until we
> >>> > again start reaching the kernel space and then it maps into the pro=
per shadow
> >>> > memory.
> >>> >
> >>> > It gave me the same results when using the previous version of
> >>> > kasan_mem_to_shadow() so I'm wondering whether I'm doing this exper=
iment
> >>> > incorrectly or if there aren't any addresses we can rule out here?
> >>>
> >>> By the definition of the shadow mapping, if we apply that mapping to
> >>> the whole 64-bit address space, the result will only contain 1/8th
> >>> (1/16th for SW/HW_TAGS) of that space.
> >>>
> >>> For example, with the current upstream value of KASAN_SHADOW_OFFSET o=
n
> >>> x86 and arm64, the value of the top 3 bits (4 for SW/HW_TAGS) of any
> >>> shadow address are always the same: KASAN_SHADOW_OFFSET's value is
> >>> such that the shadow address calculation never overflows. Addresses
> >>> that have a different value for those top 3 bits are the once we can
> >>> rule out.
> >>
> >>Eh, scratch that, the 3rd bit from the top changes, as
> >>KASAN_SHADOW_OFFSET is not a that-well-aligned value, the overall size
> >>of the mapping holds.
> >>
> >>> The KASAN_SHADOW_OFFSET value from my example does rely on the
> >>> overflow (arguably, this makes things more confusing [1]). But still,
> >>> the possible values of shadow addresses should only cover 1/16th of
> >>> the address space.
> >>>
> >>> So whether the address belongs to that 1/8th (1/16th) of the address
> >>> space is what we want to check in kasan_non_canonical_hook().
> >>>
> >
> >Right, I somehow forgot that obviously the whole LA has to map to 1/16th=
 of the
> >address space and it shold stay contiguous.
> >
> >After rethinking how the mapping worked before and will work after makin=
g stuff
> >signed I thought this patch could make use of the overflow?
> >
> >From what I noticed, all the Kconfig values for KASAN_SHADOW_OFFSET shou=
ld make
> >it so there will be overflow when inputing more and more positive addres=
ses.
> >
> >So maybe we should first find what the most negative and most positive (=
signed)
> >addresses map to in shadow memory address space. And then when looking f=
or
> >invalid values that aren't the product of kasan_mem_to_shadow() we shoul=
d check
> >
> >       if (addr > kasan_mem_to_shadow(biggest_positive_address) &&
> >           addr < kasan_mem_to_shadow(smallest_negative_address))
> >               return;
> >
> >Is this correct?
>
> I suppose the original code in the patch does the same thing when you cha=
nge the
> || into &&:
>
>         if (addr < KASAN_SHADOW_OFFSET - max_shadow_size / 2 &&
>             addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size / 2)
>                 return;
>
> kasan_mem_to_shadow(0x7FFFFFFFFFFFFFFF) -> 0x07ff7fffffffffff
> kasan_mem_to_shadow(0x8000000000000000) -> 0xf7ff800000000000

I'm a bit lost with these calculations at this point. Please send the
full patch, including the new values for KASAN_SHADOW_OFFSET (do I
understand correctly that you want to change them?). It'll be easier
to look at the code.

Feel free to send this patch separately from the rest of the series,
so that we can finalize it first.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcHnWr0%2B%2B8omB5ju8E3uSK%2Bs%2BJOFZ3%3DUqgtVEcBzrm2Lg%40mail.gmail=
.com.
