Return-Path: <kasan-dev+bncBDW2JDUY5AORBLESWW6QMGQEIDQOC6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 857AAA3348B
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 02:21:50 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4395f1c4366sf1390565e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 17:21:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739409710; cv=pass;
        d=google.com; s=arc-20240605;
        b=SIYZEEflg+eo0DVixs8JqD+GsnaA27knF0JCXf9jTTSHxMQliFm+yXrvKHKdtCkemo
         KFHw5c8N2M6uZ7hgmS5ixx9tlrlh82OGDQCeDULJQLeeil4zgSFCS0NCmsTDY5lT7RkH
         YWLYTEpwyYdyJiCx+zHs4NNnDzwYY9fMf4ZbP+7FhV67vHCBfRMO0AfAxQNPrz5c7Cnf
         MDCTs6hKm/3sS8Uqw63fnwdtxvGjMwXxJDLq9zkIctqwWyzyE7dbM7EvnZn/0YRPUAt/
         G/F1+weCkvz6i5p+FNhU57cFMh/OiLUXaQVwhmU5L+YSYoJii/6mTwzsyzU7os2RSp/V
         L6xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=UI+l3uC5cV2knowUgIRfTuO/NRpB7aDiux/Tqs1C0/w=;
        fh=br68NKTXWjuYaT9EdIL6jdgRdRMg5QlOgJ1xI/QmGqY=;
        b=YmnEyQGoLLJXsmDP/NSfr03Pu4EUgaGefeHiZSo3HjgQFkrBvRbLM1c7e15yQDPa+k
         d8g8BzKvoB8HKNCgo9Jme0jK00yVK08Di3zDhJimmx7YD30UfGK1SY2mBjqdnvcfb+JP
         Qp7rp8vs7XNKBnRYUOAT/NqLHRXQQi5cYD+6uKyZadESrQ+WUaLz/gbrxBfS6zhnP1tw
         5bhEOYZG5wUAN1f7/PftUHN1r92TCQM4Hx60M1eNcgILVTznfQpqafpCW3qhxOFLOw3P
         yQgrXJqRqBbT9oBq80Nfjfsld6iPkPXl3jVojO+O2qKJV6U6oM1z3ej6qa8MDw63h445
         Boaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="e9V/3z+3";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739409710; x=1740014510; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UI+l3uC5cV2knowUgIRfTuO/NRpB7aDiux/Tqs1C0/w=;
        b=sMxE2+EWhZMT38B/OnVMl42bAESsx7qLBY3iTWnC1XIbH9jEfLMsDzQJcAQ76n4+uR
         UedK78OHGQkERiuxRKiuPsy2lu0ngpCyd3WM2lDPXkrF3GXmFCq71Wo+mM1husR3MleJ
         4BYLYr/3H6RLq6Gz4l+b5XKqPdWoXNqhZLpJifE1H2U/E9RbQHzY8x2gWl+q8A78qxxl
         YOHjgATH3zvnZPTFyAFV4rAbkyGXVAYAqFZccoIK0pwv54Nyr8p2ImhMxcpc2olJcYJC
         xhEDjGAl9BVQQ+Aa7yePhBJjQHBpRkaSSdulKsBmTaLy1T5c4yym5MW9eCstUqwKzkZg
         IwSg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739409710; x=1740014510; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UI+l3uC5cV2knowUgIRfTuO/NRpB7aDiux/Tqs1C0/w=;
        b=fI8+PVo52SxQIxhFdtNRWTEungF8lvYZ3Kb7IT+90yxRdWyfDU7oaCcORpdgl8MZ2J
         vQqG+2uAL1cPgFZ6qZHQjwRHdhodktKi97jAYLOrfNvxW41dYNQM/2Ah/b8meh5RzYtp
         g3B4+sli4K9eMs9qsj5/15APZJgXejnKrox0OyDuRvwQ3aJ1tqy7GVNnaWGOEBVMuz1I
         k+GLRhutEBP1oaAO2iJal/l50I6VFUIlkTiQzgxM5inv6qUdkJ7zkMsy59RlPISunZzu
         rkCKX8CzbgwK4sp+wP+vaL/KuKrWuNHaROxyLNBRa0fOg103aI4124+P9Ss/pYAJyl8K
         EvAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739409710; x=1740014510;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UI+l3uC5cV2knowUgIRfTuO/NRpB7aDiux/Tqs1C0/w=;
        b=vXU0SzE3WOhIo9+mGbbMflKryM3ZIwYQbB2aSyAyeP1GL2zp9XG1jZ0ikwcV7ScDw7
         18wizrsbhL3DVk3hYWr6EPlVpQTHo1u/nkvzhYMVvVs1Gh4PWLBRSjKkCQwkJUrtfo9a
         3AH/D6pj/JSbMHb4CVvmJinzwJFVhwOjoi5rmtSvUESt2bmb5sLjk0Cmc62/mO/Ybyds
         3ErK6MJKYRO3MpHKyKATMmqDK8uDm8pkPKDmM+6cN8zOnCJ8DTBIeddR3uOhuzM5wcOy
         bIeTBvJBmGMWlFNU0Q6gqmB7OojlLNGiR1XyTsazJH5AD4hfn0z8Qn+M66ijJtKbKMKm
         00xg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWUPwYDWY4OG+wgIc2am8EQLiNUGhDkex+IVUaS+em+p6jYqlUOmsIrIVE3+nS6z2oG1df2lg==@lfdr.de
X-Gm-Message-State: AOJu0YykaFD/9nM+TDsl6CRurW0D+QZrRG5lDB/VbfHK6ZdVFM4NLJ4v
	qkD6avP1xc43jVzTUpX1EW9aKNuRuVlZtOojy0tLnIQpti/V+c9B
X-Google-Smtp-Source: AGHT+IEA2i//IxdRryn7CHT0IkhJgc2b61FJEgBvKEqtKPJvPgISEcbkNh7n43JYWGv4G3Eghp31XA==
X-Received: by 2002:a05:600c:1ca6:b0:439:4470:55d6 with SMTP id 5b1f17b1804b1-439581bfc7fmr47803135e9.28.1739409708419;
        Wed, 12 Feb 2025 17:21:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEqWpi3tSYQbxAOQuXoIqee/xCKosnjmwog4InAq3qxqg==
Received: by 2002:a5d:47ca:0:b0:38e:f923:e191 with SMTP id ffacd0b85a97d-38f245c3fd1ls240171f8f.0.-pod-prod-08-eu;
 Wed, 12 Feb 2025 17:21:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWvX2+yUlDV9L0JDi8yen213MvUjhDNWEWHh0uGzno3uN2a+ip8WsjFO9w/g5vbImAw0kaoP1TnK3k=@googlegroups.com
X-Received: by 2002:a05:600c:ad5:b0:439:5f1e:bd6b with SMTP id 5b1f17b1804b1-4395f1ebe9cmr24482625e9.23.1739409705367;
        Wed, 12 Feb 2025 17:21:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739409705; cv=none;
        d=google.com; s=arc-20240605;
        b=eqK9xiiY51+FuKE5ZmGEYqtktYMr23RvJoKe+dc24LOPDXLQxOUzMO6cpY5VUfijJQ
         z5UCH07HRig9tayu+FN5LSYbC1WTWHFK+s0qLk2bTQfZawWiivL17oKfjXk8Ukxl1tSs
         17U3FeI0y3kBSlsJ0FTPFJVKQEjeur6qf03WvXW2s1mXU+dsYfjI34eKh6cg2TdiYa0B
         b6brkJMoVSIsePXovuric506tyn+xsBnQQI64skLXox1uIGZjBbSF8TztwJ12saA0Tuc
         oVFjd1KahzQEj54A2I9PujhMg2011sw5UNrjQA7+5pQH6M8NwUMhAgHiai53UJg5swnK
         aMaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=q+nCXvcuGbP6lZuLocKajT0ORe5EGrF6T3/N8VpC8fs=;
        fh=UOyAqR8MM97igH1S527JwNUMPdfbt2cBXeHtHmu3Ark=;
        b=SX5SIHQ8vlJOhShY/59DtMwzwHcdFgTKOoz1bwx8FAhMCgX35/MlasMHjGRJSW9ljO
         P8ygZQkajKU6245yEEDZXyGOxVOSWqMHzgSy3BtbSq9kW2O38PxMhbN6Nu6jt4fcOuJP
         RVsOriVP5aBsDvXIkRZRQZruMi7g6PPx3rp8LiVnRK/PEsyu10afPLBTjknzGmlJygHw
         eC2W3kljWUo/nhViXOdQda3v+0UlhMOBqRSdnpnZCJJxW2/JsO8hKN8GzNwmWQSgYd6q
         tsjdZzoACRe/zemNLn609iToTtkZHr0YFBVlToTzYiELet3VMspvXD3S6OfLUKPOZJuu
         ICGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="e9V/3z+3";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38f2590e484si11557f8f.3.2025.02.12.17.21.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 17:21:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-4394036c0efso1991525e9.2
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 17:21:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXb+PiYs2Lwo8eZTN6pRwS1DGj5HpzI6Idyylelil0H4VxHaNLlluFLma1CLvqK07eRmnTLArF3o68=@googlegroups.com
X-Gm-Gg: ASbGncvzL3OJHOlr/0Nf1ASJUFytEqazd3XgzQr+0mDGK3wWLkPMM9pnAWj3gUWhat4
	80vNOQ7qgo2ubmuqGuGbg6me5liG8EbPC4yagipzNEnPdl5wCs4IB5kLBRCkZXhs57aelbGSQmC
	E=
X-Received: by 2002:a05:600c:198b:b0:439:60bc:71b3 with SMTP id
 5b1f17b1804b1-43960bc744emr6893225e9.25.1739409704648; Wed, 12 Feb 2025
 17:21:44 -0800 (PST)
MIME-Version: 1.0
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
 <20241022015913.3524425-2-samuel.holland@sifive.com> <CA+fCnZeBEe3VWm=VfYvG-f4eh2jAFP-p4Xn4SLEeFCGTudVuEw@mail.gmail.com>
 <e7t5yzfw3dq5stp5xjy5yclcx6ikne4vwz7d6w2ukfw2b7gr6t@oomoynf3b2jl>
 <zjuvfdbl7q76ahdxk3lrgaznk7vjj43f5ftzfgrnca6dqtcd5x@5qj24womzgyq>
 <CA+fCnZfySpeRy0FCFidLdUUeqp97eBdjAqQyYPpz1WxYwcsW9A@mail.gmail.com> <aqhm7lc57srsfuff3bceb3dcmsdyxksb7t6bgwbqi54ppevpoh@apolj3nteaz6>
In-Reply-To: <aqhm7lc57srsfuff3bceb3dcmsdyxksb7t6bgwbqi54ppevpoh@apolj3nteaz6>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 13 Feb 2025 02:21:33 +0100
X-Gm-Features: AWEUYZnQToSGphLmBmZFBpfuiZIg1iWlon9vHp3PXB7Fk9evMSAokOcZX5tZFRE
Message-ID: <CA+fCnZdjTkreTcoo+J8wMhwDuAFM4g33U5BFy0OPtE0UCvyJbQ@mail.gmail.com>
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
 header.i=@gmail.com header.s=20230601 header.b="e9V/3z+3";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334
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

On Tue, Feb 11, 2025 at 7:07=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> I did some experiments with multiple addresses passed through
> kasan_mem_to_shadow(). And it seems like we can get almost any address ou=
t when
> we consider any random bogus pointers.
>
> I used the KASAN_SHADOW_OFFSET from your example above. Userspace address=
es seem
> to map to the range [KASAN_SHADOW_OFFSET - 0xffff8fffffffffff]. Then goin=
g
> through non-canonical addresses until 0x0007ffffffffffff we reach the end=
 of
> kernel LA and we loop around. Then the addresses seem to go from 0 until =
we
> again start reaching the kernel space and then it maps into the proper sh=
adow
> memory.
>
> It gave me the same results when using the previous version of
> kasan_mem_to_shadow() so I'm wondering whether I'm doing this experiment
> incorrectly or if there aren't any addresses we can rule out here?

By the definition of the shadow mapping, if we apply that mapping to
the whole 64-bit address space, the result will only contain 1/8th
(1/16th for SW/HW_TAGS) of that space.

For example, with the current upstream value of KASAN_SHADOW_OFFSET on
x86 and arm64, the value of the top 3 bits (4 for SW/HW_TAGS) of any
shadow address are always the same: KASAN_SHADOW_OFFSET's value is
such that the shadow address calculation never overflows. Addresses
that have a different value for those top 3 bits are the once we can
rule out.

The KASAN_SHADOW_OFFSET value from my example does rely on the
overflow (arguably, this makes things more confusing [1]). But still,
the possible values of shadow addresses should only cover 1/16th of
the address space.

So whether the address belongs to that 1/8th (1/16th) of the address
space is what we want to check in kasan_non_canonical_hook().

The current upstream version of kasan_non_canonical_hook() actually
does a simplified check by only checking for the lower bound (e.g. for
x86, there's also an upper bound: KASAN_SHADOW_OFFSET +
(0xffffffffffffffff >> 3) =3D=3D 0xfffffbffffffffff), so we could improve
it.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=3D218043

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdjTkreTcoo%2BJ8wMhwDuAFM4g33U5BFy0OPtE0UCvyJbQ%40mail.gmail.com.
