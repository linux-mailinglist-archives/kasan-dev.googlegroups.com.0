Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6X2U2AAMGQENXZKUFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B6312FF238
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 18:44:27 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id a22sf1211532ljq.4
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 09:44:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611251067; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z2a0Bsv4zIcWcVKYs94BMs6g2ZM79MOKXdmPc+jdSC/ZvgoI/rH2fB4OtA3/PLm4a2
         MhyKCuPmMbZPLUlo4LUpeb7wZqNBeIoVSrlOEiNyTjnhWxyZsO9baJPIxofS3q6ZzEGK
         wLg2ex5qWT7AdKfUxEcghtl0dyiXY95MWZh4/10SVmmKaXrEZcbyyg+tfhFRL822jigO
         HUu0kGr+1haw5OfVvGoN3J6yCY/BqKzGMoF0qjBirvxez58Ui39TlLgESx2IJZkd6Qvp
         EJj2g3GRK11DL9a2rWH8EffZWT/Tg7Y9aMxhPHnMyFWiobCO7A0SJMnXATHG55VvZB0X
         Jn2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+a9yUH/Ro+maHJj7GX61wy5mM4fjQR0OXl7jJr8rFY8=;
        b=MXiIaogRly8BwA7UE7iL2xMeMPCiEvCHWf5jPWolFEzY/wbrUnZefaV4aoSZnj0HUv
         dg0Jfc/HZkkG5ZNxrAHTeQXC5sL8yFVr1nGLvA2zvt27tLVNUXnxWlKdMaLSEmEEDd4i
         VMCq4LTo4uwEOejR6j7hKde6CmfeiJ8E0TTs9h3EKqAjTxvX1d6DaTCk889DZ8o2fQl/
         FqbKAgKPNgP8U6zjyM7Hm9p1VzFqNKFWv/3zDjtJWKQxoe8+URzFbWUYTzughBZXsmyZ
         ZLcOuqvUS577Ph2pgWWfZwcKgmMXJJZ0iTmMnGPW9bDzgXNLDiX9mZ+8a6oV2yhNIoX2
         Jhvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J12Eeog0;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+a9yUH/Ro+maHJj7GX61wy5mM4fjQR0OXl7jJr8rFY8=;
        b=m63Yp1z5DNn/Rni1niyUJqwIqNNikus7caRlFRlCTX3Zg0sMtWUnJ/3lFKVjEw2c7I
         obCWV+iSTqEyVAjGtIdBvY/jKoyuuQ41Ax9i9W5OdKbqDTyPBn3EJiowxbzNYUHmXrac
         y7yw80ak6u1Xj6eU9Ed1uOj9ehHyYlRS2KVv791LWZi2kYhVsj9ZxalZkqFXzgMMYLZK
         HfnfFj7axXtuCK+HSlXcRzbo5G0w4Yjz3WhFsDHJyrrOyHRrB1TYcQoVdAoILBNmQ2Ab
         uEMrW/hRU40/vsF1TZlf+abSKLGEYnlyaCGHcweHX/W5z195vRywkippxA6iKL7QT7eE
         iKGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+a9yUH/Ro+maHJj7GX61wy5mM4fjQR0OXl7jJr8rFY8=;
        b=QAuoWr4gnaxTywPVtdHf40qAy6Jum9I5GcZSgcifCxO7N2i9yDotwAi0vfe/BAIG2P
         nFSZyym4eJVB/osekDvKA9Hn7UFZF+O2BYuFUhceeNBDpJOEpE9CwD4Yc5Slkryj+Q38
         MoOpaAmrFBvRaikQ5CznsSp/XLSXe5vt9tz9job5ttcoMnslbz09lbb7QA1LBFYSTCAc
         JQCVFNOhcqAlijiuTd85NgNi2smGne8E4t4NxhPEfoYNkMc1HhgRf/aj8BdVIxYKhb56
         eAY2KiZyRrLydp4va2FfS9k6jW7VFyrT7FpWpHeErMOR2+rAiRlDN1R/Og+I1wG/mO0C
         buHw==
X-Gm-Message-State: AOAM532TflTVr2mmI+pmGdd6ZAjuL8LU16aN08yju/8lZfzJCo1paU9m
	EYSG1ZkZKzS2FWJ+BX3YLcM=
X-Google-Smtp-Source: ABdhPJzOpdBC0IjYxjtDbeiL6Z/RujeL4vvE8zflSAMipXUSTy4BhlvhNHXXxqfH0m71gcK8uToJrA==
X-Received: by 2002:a2e:984a:: with SMTP id e10mr224906ljj.179.1611251067092;
        Thu, 21 Jan 2021 09:44:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:51c4:: with SMTP id u4ls464891lfm.0.gmail; Thu, 21 Jan
 2021 09:44:26 -0800 (PST)
X-Received: by 2002:a19:5043:: with SMTP id z3mr148285lfj.429.1611251066016;
        Thu, 21 Jan 2021 09:44:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611251066; cv=none;
        d=google.com; s=arc-20160816;
        b=r6bKz9mVZ8M+vP1WHS7j5nOPUSTQHkcMpmsgrroO0PmGgKymoyTIcJirQwGddWtjVK
         brki2hWPobPrwc3Xaz/PSa+vjmoPiKCr4E2eyqcCRqpsNkhZ9fjneX9KL/kdarDj/hdJ
         lrxptvPonq4DWnDsb/ex2mf8q125pxIRKVgV2dIM6OXkixevhHsEX2h+3W5mkj1XgAfe
         rygTjdZXWUEZ+YTztVUOxRLZ7vhnIbFV2JNCrxbivmqifnQ6r2xO5KNPifSk5GC+zhct
         4k6DeUDmFid41lsobSRx4GjljWqv4DJVa8xYlRTUhLH8BAIFHZyfOFVNfPY2oO8VClVD
         L+pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PGFFrNGI7jcGt2Ckr0yJXz+AGAE1X7qRw3reHpjfkCo=;
        b=nFW2yQyt7HLH4jMA5bv/edZTPBZn3FH43fNyNTVR21HaWm0bj8IrHc0H+mQp7jaeRW
         S9G1Zc0RWiv+YHUG7eijpVG1sBCGmilwdi72gZ2XPTGLtQ6AQ1bbZl5Yk2ZYJy1B4nTT
         ZSsZZR0vlgbFHb9Z9Fy/nmg9yL9maC90UInacSwZAdoz5J5/k78zMzeqrOFAW1UBM7U3
         Bv7KT0nQwO3qOoPpFaKC8ciTdAFZiVEmN3t1EEiwcitgtaXEpUCzUYA75k3Uh3AeWZk1
         9mdVmOBndU6U2LcL8nNechwrnd6jxSbw0/FS2hVYzAL+2ZVl6ZhG1/oaHNTeL5e3cRCD
         QjPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J12Eeog0;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id j15si284238lfk.12.2021.01.21.09.44.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jan 2021 09:44:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id v67so3721076lfa.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Jan 2021 09:44:26 -0800 (PST)
X-Received: by 2002:a19:434e:: with SMTP id m14mr162866lfj.73.1611251065593;
 Thu, 21 Jan 2021 09:44:25 -0800 (PST)
MIME-Version: 1.0
References: <20210109103252.812517-1-lecopzer@gmail.com>
In-Reply-To: <20210109103252.812517-1-lecopzer@gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Jan 2021 18:44:14 +0100
Message-ID: <CAAeHK+z3oYx4WqX7Xor7gD=eqYkzW0UBS4h4is00HnfNnNkpDA@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] arm64: kasan: support CONFIG_KASAN_VMALLOC
To: Will Deacon <will@kernel.org>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Dan Williams <dan.j.williams@intel.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>, yj.chiang@mediatek.com, 
	Catalin Marinas <catalin.marinas@arm.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Mark Brown <broonie@kernel.org>, Guenter Roeck <linux@roeck-us.net>, rppt@kernel.org, 
	tyhicks@linux.microsoft.com, Robin Murphy <robin.murphy@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, gustavoars@kernel.org, 
	Lecopzer Chen <lecopzer@gmail.com>, Lecopzer Chen <lecopzer.chen@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=J12Eeog0;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::12a
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Sat, Jan 9, 2021 at 11:33 AM Lecopzer Chen <lecopzer@gmail.com> wrote:
>
> Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> ("kasan: support backing vmalloc space with real shadow memory")
>
> Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> by not to populate the vmalloc area except for kimg address.
>
> Test environment:
>     4G and 8G Qemu virt,
>     39-bit VA + 4k PAGE_SIZE with 3-level page table,
>     test by lib/test_kasan.ko and lib/test_kasan_module.ko
>
> It also works in Kaslr with CONFIG_RANDOMIZE_MODULE_REGION_FULL
> and randomize module region inside vmalloc area.
>
>
> [1]: commit 0609ae011deb41c ("x86/kasan: support KASAN_VMALLOC")
>
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> Acked-by: Andrey Konovalov <andreyknvl@google.com>
> Tested-by: Andrey Konovalov <andreyknvl@google.com>
>
>
> v2 -> v1
>         1. kasan_init.c tweak indent
>         2. change Kconfig depends only on HAVE_ARCH_KASAN
>         3. support randomized module region.
>
> v1:
> https://lore.kernel.org/lkml/20210103171137.153834-1-lecopzer@gmail.com/
>
> Lecopzer Chen (4):
>   arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
>   arm64: kasan: abstract _text and _end to KERNEL_START/END
>   arm64: Kconfig: support CONFIG_KASAN_VMALLOC
>   arm64: kaslr: support randomized module area with KASAN_VMALLOC
>
>  arch/arm64/Kconfig         |  1 +
>  arch/arm64/kernel/kaslr.c  | 18 ++++++++++--------
>  arch/arm64/kernel/module.c | 16 +++++++++-------
>  arch/arm64/mm/kasan_init.c | 29 +++++++++++++++++++++--------
>  4 files changed, 41 insertions(+), 23 deletions(-)
>
> --
> 2.25.1
>

Hi Will,

Could you PTAL at the arm64 changes?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz3oYx4WqX7Xor7gD%3DeqYkzW0UBS4h4is00HnfNnNkpDA%40mail.gmail.com.
