Return-Path: <kasan-dev+bncBDW2JDUY5AORB74U77BAMGQECZ3LRYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 09133AEC698
	for <lists+kasan-dev@lfdr.de>; Sat, 28 Jun 2025 12:57:07 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5533439602bsf1935537e87.2
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Jun 2025 03:57:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751108225; cv=pass;
        d=google.com; s=arc-20240605;
        b=LV+TVveFUl3O1O+37+4hm5qZfPJDTSK4vDr1nv+DlreKdc4tp0D0Tq49gQXH6skIfH
         OaalZxeRzuDbm6//iDqjb6kXvNuoUwT1Oi6behmDKIJT8AK9bwhCAMciHw6naBEhYq7o
         9FBEgm/Q4syLmP+hzzaRV1kVT42bQHb+NnkDeNQgJmqwlsZOT2CPK6/k/2EqqFJB0r/F
         aEb3V78ZjO7cr2Wc+bqt87PCTC2XoWLRIrfacZ0I0SfSLD1b+jh7O++TKJTlQ1Kgl2zH
         cZijoOOG8FxP2oQlin4NtGdsqcIr176BwlkMcSi6sP4Znj50KYUKz3aEaCzCE4K54jra
         oC9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=PuZh5HqL+9wSfv6fYXfRZvwl4o3LKgp3NwvAvTzfSdE=;
        fh=Yg47jG+wIsIL9w29AL2lrsGuvU4YN+PVvlRGBZQs/yc=;
        b=F9gO1ZNcbjWzaac9NS3t+sHa9rTqxL62eKiWR+p0wptKU/RCRPoKyGOgfIJ1zdyjQH
         YcIR6YyPehNXNMmhFUZ18OuvkW0HDudMFS+W/rrNiDenRVW/BPJ2LFampssvBAOe1HCx
         x2LZA3bKus8qAfLSux10BokCerhscTiE9w8uwobu+trwEIIBufmGvoXE0vLklBwb3bAl
         Stsvxv1CmLgnhBbrZ6W8vnZX+MnV+3Eo9vWq1gos4CBKikYHrUOON0vYq+cGWPuDZcRH
         82cMrMBcbM72etK58UM5GPK9tFUDsQ0OWaAYl2lPyVMt+9McScH+sitI+loKbhYj5g2Z
         NDwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q9SwDGkw;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751108225; x=1751713025; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PuZh5HqL+9wSfv6fYXfRZvwl4o3LKgp3NwvAvTzfSdE=;
        b=PQrb8IVUlT4MPVuT0Soosny+p/DTzyXE/iVy8zrMZd5/K+/A1A//AB7p3P6DLkTRDo
         /Ms5jxuDHk3SSVrdNU45LN/uUwaHSw4vKvldMIddRyEI17V7p04nmPfLRyedEx4ilLha
         xS3oB9di0Z2HQuid6FESH2c7BzkeDkQ65OvimwzuHg1/3vpfBjD5ueTvklZHtrx4IFRt
         7IxPPuwvyGJJ9hmNBD7VanXPjHn56vQGfDJhcUI5tid+q36ojgJzkStVL9X0vTpNGgVv
         D196u74EUFtiZxa0oSihJRmFXyIzM5O2fo6NXaG7uz5QSzi3sF2TfYiQAMxH8hmlDaoU
         wFXg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1751108225; x=1751713025; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PuZh5HqL+9wSfv6fYXfRZvwl4o3LKgp3NwvAvTzfSdE=;
        b=dcX2eOWHT77m7iuxVEcpkORpmhX7jn3dR0VNo0TYQCcqpLjt90/gWoF4fcF8tU3c56
         G5iC0hMTG1SyiqMgyW6Z/66QJ23VUTJfmrJVUcq9kffQBmxYtxXIXCaEH+x5WDT3y8d7
         g80mRgilD11xZEPGsSdWtL1Dj1eOCoI9xAud5PTTeA/AxhUZxPOQHaID0AmB9zPMgL/O
         7VIySniA1SniZCVXxUbQENdHB152hoNN/KiT+OkOo8T6oRvxQ174n6MUYFOQ6YWjfeHY
         kJmDlZxl/VWkyCMRTGv+kYc6JptR1QxL9w8GLfx8lRi8bwF25T90lvTaoeCy6v1uNWHD
         hiNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751108225; x=1751713025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=PuZh5HqL+9wSfv6fYXfRZvwl4o3LKgp3NwvAvTzfSdE=;
        b=f2uoIBXsGmYFL4l+1FQX1WAp+2Ujxt8X2DoUtpvyw1z1kR8mMR2v99p8mAa9zBpf55
         RW4yPdNQXxGXRGQYqRqgr/EPSvmHEFc7w/opBxd1BohDloWgGd6mOKmDU88J9/ewiUKd
         sivQfwe6vvSuHD7FwPV9s9VQ5OKLHhXVTGFykW4QQN+O0k/IDcanKKAfJPpZtjhQiOla
         BhBhmMgAES9sL4BUbCBtNGD9zBe6JVB5nsqxfqMYvxeTY2e0XAtHSjMcVciPoU8DdXjy
         H7SKk3p37mRtn0RTTWhYP/zcpn7cDndKqNobUgCF/jMl2LuxHqFlWR5xZ7h+cjQnFN9D
         rTlQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVF+UtAkUELQUH7wjDsVIjhAzYc6/xIe8a36rUUCEeLJqjNdph2yUCidtoQ4NSTkn+OaBcuRQ==@lfdr.de
X-Gm-Message-State: AOJu0YwJtFt0cx+WWYeJ/M42Y/DCviqHmo5g5Na/7Hvss+ohBEgAx5lX
	75uywIFcMAXj3CSqUcZm0/WmsZSnrDVM3jrzS0plFV2el1uWQ6pMSUtF
X-Google-Smtp-Source: AGHT+IHoVWnA6c8hGVfQcBH7hw1jiM37QfUVLhwBcxz7UkwQUwYksvA7IhQXLLwFTG9E6+r5wMAVhQ==
X-Received: by 2002:a05:6512:2c03:b0:553:a80c:3adf with SMTP id 2adb3069b0e04-5550b7460fbmr2699402e87.0.1751108224502;
        Sat, 28 Jun 2025 03:57:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeIIOKypnqQ2XPmlm+FcE1m5fxmkPWL/z+MDxazFV7nIQ==
Received: by 2002:a05:6512:114c:b0:553:ca9e:dc63 with SMTP id
 2adb3069b0e04-55502c9613bls966441e87.0.-pod-prod-03-eu; Sat, 28 Jun 2025
 03:57:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUUC0llmZQJmJ+/bZ+1jcMV644dCMXRdAHnuBlFMtx2M+nTSqIv3RGzv2wXKOf2HROmHSBUXjhwlkw=@googlegroups.com
X-Received: by 2002:a05:651c:40cf:b0:32c:a097:414b with SMTP id 38308e7fff4ca-32cdc519b2cmr15780661fa.19.1751108220206;
        Sat, 28 Jun 2025 03:57:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751108220; cv=none;
        d=google.com; s=arc-20240605;
        b=i3PUlw3Gou2C600F9G2TZoZvNIluBh8FeHFWFDnmRQBeWfsApjuttG18F2pUqNSlfS
         +yS2/LK+JjMsZ6U7UcNsLsejhuKj28WE1z+aOtmVygKNz15HfwTQcQp3+zOBAdPBqdKL
         5cHEMFbiqIUHHLCQGQqy6gbjZUrCsIFY1PwY/Zsa11RU4o272IwcZz3kc0weW85BwhfF
         xBEr0R0oQ04/KPrb+46AU9lthx6UTvISSvZi6TwQFuDSWj5KXo1o8HOoWZOcX1jYawZY
         wgvgbmPrAb8HkfmeTZ0vi7MeMLwgr/5qfJljFZZH9E8J+RJSRxeFyubUgpUf/+493rek
         l7rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WW5Xm1iyi3UCGUGi1nrA70AfDCSuOC/overmp2OZ2oI=;
        fh=pSaleD1eoTEznT9Js74CsgiHh8tuWxEsBDD10zQahhc=;
        b=lAYjHKuMUW74Ra9DT0boT5jVxmjXZCFwxNI15PvldlWIHHunCULRkXbHQlmi4Zmc65
         1IXFC0QwVkCqDP6bimGHM6zUgv39AVouvNXhdkS5rVwSrGNFaOtAeTIUR80oAmOxD++k
         Vahf/rkV6YmZtk7viH1WAds9VyV8NwRStSYLsY1Ecrt7S1q4Fub8bVQJu+h6Y8Np4lmg
         GVgf4QFz9mVhbaQs9qQa2AkqyzolxCBVlVkK/137A8v07jX6TogOq+z3PPmgvDlt+WVY
         vcbg6Xo9rNR8RKQisqzq845wmDNKV7I4qaNT3WSCxHZgXMnWpbP/awACXQC1FphDns6S
         Jb5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q9SwDGkw;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32cd2e927d8si2758231fa.4.2025.06.28.03.57.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 28 Jun 2025 03:57:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-451d54214adso20568955e9.3
        for <kasan-dev@googlegroups.com>; Sat, 28 Jun 2025 03:57:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVbV9oXyYtbwntfMSy4VVipmaGViOxICjbl/xTrUXSKPKbT7qxtZwj216RsxqPU7ZxLTEQuan8AdJ4=@googlegroups.com
X-Gm-Gg: ASbGnctDavsNwarMA0hnxZiG4KvawjI9k4TTmJBf3zpYtv1JPaSHhAC/zxkz/4H8VAI
	BJ1Pu9xBu2uUV17h0cBsJFpVARacc4+a4LrXz2GO905Wl/BgHjGiy02YLuFJAwDEvF10FLWCx9P
	OYoC2PqlGiMvuKqhi5S/IJd6lK6um4UrinKRoyuPe8d9VcX0C9C4XXD2Mp
X-Received: by 2002:adf:a1cb:0:b0:3a5:3b14:1ba3 with SMTP id
 ffacd0b85a97d-3a90b8c99bdmr4338216f8f.49.1751108219175; Sat, 28 Jun 2025
 03:56:59 -0700 (PDT)
MIME-Version: 1.0
References: <20250626153147.145312-1-snovitoll@gmail.com>
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 28 Jun 2025 12:56:46 +0200
X-Gm-Features: Ac12FXzas27xdNkixqmlGojlaGpK_Gh1QoVs4xiB8K_jsjOjMmn0UG8i3tUlU1Q
Message-ID: <CA+fCnZfAtKWx=+to=XQBREhou=Snb0Yms4D8GNGaxE+BQUYm4A@mail.gmail.com>
Subject: Re: [PATCH v2 00/11] kasan: unify kasan_arch_is_ready with kasan_enabled
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, linux@armlinux.org.uk, catalin.marinas@arm.com, 
	will@kernel.org, chenhuacai@kernel.org, kernel@xen0n.name, 
	maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com, 
	christophe.leroy@csgroup.eu, paul.walmsley@sifive.com, palmer@dabbelt.com, 
	aou@eecs.berkeley.edu, alex@ghiti.fr, hca@linux.ibm.com, gor@linux.ibm.com, 
	agordeev@linux.ibm.com, borntraeger@linux.ibm.com, svens@linux.ibm.com, 
	richard@nod.at, anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net, 
	dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, x86@kernel.org, 
	hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com, 
	akpm@linux-foundation.org, nathan@kernel.org, nick.desaulniers+lkml@gmail.com, 
	morbo@google.com, justinstitt@google.com, arnd@arndb.de, rppt@kernel.org, 
	geert@linux-m68k.org, mcgrof@kernel.org, guoweikang.kernel@gmail.com, 
	tiwei.btw@antgroup.com, kevin.brodsky@arm.com, benjamin.berg@intel.com, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, loongarch@lists.linux.dev, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Q9SwDGkw;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331
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

On Thu, Jun 26, 2025 at 5:32=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> This patch series unifies the kasan_arch_is_ready() and kasan_enabled()
> interfaces by extending the existing kasan_enabled() infrastructure to
> work consistently across all KASAN modes (Generic, SW_TAGS, HW_TAGS).
>
> Currently, kasan_enabled() only works for HW_TAGS mode using a static key=
,
> while other modes either return IS_ENABLED(CONFIG_KASAN) (compile-time
> constant) or rely on architecture-specific kasan_arch_is_ready()
> implementations with custom static keys and global variables.
>
> This leads to:
> - Code duplication across architectures
> - Inconsistent runtime behavior between KASAN modes
> - Architecture-specific readiness tracking
>
> After this series:
> - All KASAN modes use the same kasan_flag_enabled static key
> - Consistent runtime enable/disable behavior across modes
> - Simplified architecture code with unified kasan_init_generic() calls
> - Elimination of arch specific kasan_arch_is_ready() implementations
> - Unified vmalloc integration using kasan_enabled() checks
>
> This addresses the bugzilla issue [1] about making
> kasan_flag_enabled and kasan_enabled() work for Generic mode,
> and extends it to provide true unification across all modes.
>
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D217049

Hi Sabyrzhan,

Thank you for working on this!

One aspect that is missing from the patches is moving the
kasan_arch_is_ready() calls into the include/linux/kasan.h (this is
not explicitly mentioned in the issue, but this is what the "adding
__wrappers" part is about).

Another thing that needs careful consideration is whether it's
possible to combine kasan_arch_is_ready() and kasan_enabled() into the
same check logically at all. There's one issue mentioned in [1]:

> In kasan_cache_create() we unconditionally allocate a metadata buffer,
> but the kasan_init_slab_obj() call to initialise it is guarded by
> kasan_enabled(). But later parts of the code only check the presence of
> the buffer before using it, so bad things happen if kasan_enabled()
> later turns on (I was getting some error about invalid lock state).

And there might be other callbacks that should be executed even before
kasan_init_...() completes. But then for the HW_TAGS mode, if
kasan_enabled() is off, then we don't want to execute any callbacks.

So maybe we do actually need a separate static key for
kasan_arch_is_ready(). But even if so, it still makes sense to move
kasan_arch_is_ready() into the __wrappers for the affected callbacks.

Thanks!

[1] https://lore.kernel.org/linux-mm/CA+fCnZf7JqTH46C7oG2Wk9NnLU7hgiVDEK0EA=
8RAtyr-KgkHdg@mail.gmail.com/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfAtKWx%3D%2Bto%3DXQBREhou%3DSnb0Yms4D8GNGaxE%2BBQUYm4A%40mail.gmail=
.com.
