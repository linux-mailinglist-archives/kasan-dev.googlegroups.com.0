Return-Path: <kasan-dev+bncBDAOJ6534YNBB6OGZXCAMGQEDPUECRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A6DFB1C774
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 16:15:23 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-615ad109dadsf5245966a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 07:15:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754489723; cv=pass;
        d=google.com; s=arc-20240605;
        b=OmCxhp7dDS+Zy0K2tyXYbLtk90Pt79z14NBlW6VMH81NB5W3j9z4dGrRjl7Il2kbKJ
         OaKSkrrL16YCEvQs3+9+el6wGSA23Lc9Ca9OoRjaZHLeH43DSeHLwZim0q4wWRnOY7VO
         qvA+fLtGPr0fbz9p7id1BnIDKGITmcUFg1W/hhTeJvK/ffHKX3Q4Dbg40ZF6ObIRC5Zt
         VuNT9JeBR7nYZgYyT87aQYx9+av2igog1bC5PveNBUiG19CeP3RCR1fzQ/rotIBRh2XW
         VsfmjqR73fjCuBfLrMNqhm108Ocm1xZGSeeANAi+/nrch2C+PTjoLFeRPz6RchVK0eqV
         e0vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=t9te+7VdWw/8uE8RhskgznV1m4iaMJlRNA2O+k4WgZE=;
        fh=ze+aIFBiv0RnShR92p3bnx3CAtuO+ZpUwPCcFzCBzbk=;
        b=LBjxoJLX9GDx5KpPC16ZW7nqu+t8M4gLfuuJCB3VT7mkIRmomrZVwXPHgT+N5C8/eA
         kV8upYdO+IL6PEoB9fbLv5eiV84MQ5yEO2EX30m5FfaVavxglrhr9ddyjG71MIL0Cdm5
         enjd6sg2TrWUIz5reEhCOvIgeIph4o2JRDfSpUXMf92TyTA0yDq9LeQrEQ1Ox0OzA5XY
         ZfskwxGH0inGQZW2zk1ZRRpudhiu9ldrt/xAEL652F63jvGeUQkILR+JO5fJYplhivAH
         bH7TWr6dKoYvqXQq0dWVbkwFIzFJUpfRPSBjj8e8XUhbYXYZ2U3Nlslbgs/nEf990C1Z
         SANw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HvmGx1Yw;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754489723; x=1755094523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=t9te+7VdWw/8uE8RhskgznV1m4iaMJlRNA2O+k4WgZE=;
        b=A3/NrW41/EBy4tRN69sptl/2MtnWBBo/Bfhg1N4W/l/bmbV9J9HkcCczvRs/LewefI
         ow12p5xelL9H+YKNSkvZeJvYNSJyGfWn3x3seH8ZiNgYat6IhZrBJYyJw5djeVX3StnK
         kr1DWTX8IgMhyAt8kfBteky4TX4Gb7/eS2yTSRyV8kcGUXMTAlM10y0z+w1kn8FctrE2
         2O0o97klfegXwEfXRz7NCs47fNCFYBvRP7aa+q5qmSv/3g/jk9OYyBaBmc2I3I1Ds+zB
         R+jvrgPUMidcqc1nR+E+JedzRlQ1180ymeW2Yi/pla1IEbKcEfJcmvuq/YM9xahDHbUR
         bRRQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754489723; x=1755094523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=t9te+7VdWw/8uE8RhskgznV1m4iaMJlRNA2O+k4WgZE=;
        b=YmIqUtZXpvgrHNUHkaDIEhgKnEV+fZQ+GCEgQaZXN/mSbSsPc06CtNk3edwUo5snq2
         H1U8jG8ETLWjSgSUHp01eVAals15JZYivzGI9diWxRRI9mvR4jkZfU9jh1+Lahm8iDl3
         Aa8Ed9v93lnt+NiPzALm+qvhLT2F3diNaUr7KjU3dcwbQPlgNZ716x5O/1QlUdD1rZcM
         m2TAIs3KqYi/bSdnw5ZLj4CWZnnVIr2lUuQDsCx2ypyDIXPP8Jc3yZ1dSM0ASsexDGV7
         SXiHHqfQrfHxA6a/OrOZRSwCybHBy4E0RqmW3b5ELN9qw9/H9cP/oSIcA5aZrPIHglPU
         KZDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754489723; x=1755094523;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=t9te+7VdWw/8uE8RhskgznV1m4iaMJlRNA2O+k4WgZE=;
        b=hihnluSp660PDa3wmFgw2tOY9Ziary+j5ajDv4wCnuiVRUqhyViTm9IHLcaX5Sh3Lv
         hwYidR2w23LXIDot8Lol9CODtEWtAvE3wmnZoeSqoVXiWkytL/QZbTPZV3/nHkjBnUUs
         zqwBmC3qDVongmxNuD4DypA83E6oZONpoHat9GptrYxLTTtE8lnqwR03X1bdpF+SinM6
         ym9P+1x13I5Lf9SW4hMxwhj1xKUZD6qI+alQO3RmhRmeWJBx7iYX0gULeVR14kAosjM3
         sLdT4ml0TuJB+I805Lokt1mU8c6vMptCO3LaXzZNv0etyecpbXMAlUKC/sv/VvEV3v8+
         UP4g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZ+U3SmvW5AH42SvwRVxKoJXygdsgrAug47OxuWrhyQrKYlbWn46eqr1/42+KcsKQQbtn1hA==@lfdr.de
X-Gm-Message-State: AOJu0Yz1x5I1rjy9DLa2q1+tJ/kh11zhNg9UuTzl61osW1sQ94xycVko
	oyd/sz6k15ryPFf+4TXR8J4YvbdCsNdoyRNxdBOHrj4bGdigGRwesPtZ
X-Google-Smtp-Source: AGHT+IGV/GS9ipqghFCFE11Yq1IQN3XReYxecIjxHBdxROCd/h/QggujSipM8GPBc3jDKEHMH8RxEQ==
X-Received: by 2002:a05:6402:13d1:b0:612:b552:5a4d with SMTP id 4fb4d7f45d1cf-6179615fd97mr2529585a12.17.1754489722313;
        Wed, 06 Aug 2025 07:15:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdZGKNGFsOlydmyFzS3JTMZ21VYRujuciCuXRxFg0ub5w==
Received: by 2002:a05:6402:2115:b0:601:d62c:7601 with SMTP id
 4fb4d7f45d1cf-615a5bf830bls6500147a12.2.-pod-prod-01-eu; Wed, 06 Aug 2025
 07:15:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXOx/LK0T0Ut/mdWAR1pyObJjo9ANiyY5MIOovREBubcXl6oXnIdyZZnZ0Fgnlb6yKvs2RI/S4wlwU=@googlegroups.com
X-Received: by 2002:a05:6402:44da:b0:60c:43d9:d075 with SMTP id 4fb4d7f45d1cf-617960dc31fmr2506473a12.13.1754489719166;
        Wed, 06 Aug 2025 07:15:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754489719; cv=none;
        d=google.com; s=arc-20240605;
        b=KuilBtID4Z+R02V3FgrftQO4ZtLtKdDBDd00Xr9NcREmG5VDzoEYKg3HhjTu+durON
         ZXcudZuVFT49kIP62vlGlLzMUztZe/Zr68U9aRDwGySbqwtLTiCa9L35q/6ckInOw94N
         kU/vStOHLZeMestu0YkU+Uk+C78m/SZgQyNlKFNrA9CEWmeAa2tIhtOlDDGhv8rYvL/E
         2IZO0kKyQfVSFa47gCDmpb4ainRJO9c55vXN3NiYkHuOnTQXZYBt/Ojmsmpihe9zE11V
         Bz5GLsyfBdrXL3DgqXXh+YEh0L3eMvnWOQ1n7TbQRDz2vlFaCTVbDNd14dAq8up+Cede
         iC0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HHHtXBq5WO+vvcc0f+jtGoFoRXRDF9tjNLE6vwGhp98=;
        fh=dGxVPYPFKQtaU6Zm/ECdtTfWj3Pe6Qsiy6WYs723bkE=;
        b=kSNHg6nPs5HIkwFq0hQQMAoVDxNe8OpY/rmC3/Lam30vYKl0SVnMnyya+gjGTmWYD3
         1wDzDTGBGacUUsGQCpHB47pNU0DP5azgsp9uVuqjVen9usfffjpZbOnwBJ3aVibKvVg7
         h8+TMnsqu9aIPJhA9C1n5M4wJqYSiIxmTzE1Ramccy0/Xq3RvSYQguSXsKCKY/0Q0lYI
         DDFzBKKxVsWfgV2P4lOMfRWSq4equoJb7H+0P+sVhqAqjxpE8zDRd98O7iuh6GgNI527
         HVjAsqUF5/UJzadTqK28jkDryVMoKv1iXBSN0AxKssQxKtdovdPEoHSoeq/uRLX1ktmd
         a+aA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HvmGx1Yw;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-615a8f80accsi394192a12.2.2025.08.06.07.15.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 07:15:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id 2adb3069b0e04-55b7e35a452so8322518e87.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Aug 2025 07:15:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU0Bmidz5Mufkdz+t01AUFzNG1CwmImeh9hPNUqS2VaiOlmDLNMzHvAtVh8Be/nhxJMzmruqv8/Ss4=@googlegroups.com
X-Gm-Gg: ASbGncvzrMSN9o5tA1Go0vdYnZ3Dibd4/RC2/YaIrcHn/dmne97qPhuLN4hXldNKw0V
	EuNsQXGaHRg2kP+sI63lG4KmRHDffHCPUeKEE8OAa8HJjKTntkr14FZZzCaAo8pGmDIcZflKs/z
	0ZA765Ipn4slzrCpmi0gcpiO6ImO6dfL8O0bufdq5kIIf1kiIn34k/0YsWYQjV7mLhXkIuQg4on
	WDy1hWyrzqR/Dadvw==
X-Received: by 2002:a05:6512:144c:10b0:55a:90b:7a37 with SMTP id
 2adb3069b0e04-55caf3b36c2mr652245e87.50.1754489718011; Wed, 06 Aug 2025
 07:15:18 -0700 (PDT)
MIME-Version: 1.0
References: <20250805142622.560992-1-snovitoll@gmail.com> <20250805142622.560992-2-snovitoll@gmail.com>
 <5a73e633-a374-47f2-a1e1-680e24d9f260@gmail.com>
In-Reply-To: <5a73e633-a374-47f2-a1e1-680e24d9f260@gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Wed, 6 Aug 2025 19:15:01 +0500
X-Gm-Features: Ac12FXyPyQ2NShErRdFgyvw5rZUg2mPvtAtIHmw2QjkFVe_vIUdzA6ST_4dfZTU
Message-ID: <CACzwLxg=zC-82sY6f-z0VOnmbpN2E8tQxe7RyOnynpbJEFP+NA@mail.gmail.com>
Subject: Re: [PATCH v4 1/9] kasan: introduce ARCH_DEFER_KASAN and unify static
 key across modes
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com, 
	agordeev@linux.ibm.com, akpm@linux-foundation.org, zhangqing@loongson.cn, 
	chenhuacai@loongson.cn, trishalfonso@google.com, davidgow@google.com, 
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, loongarch@lists.linux.dev, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HvmGx1Yw;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

On Wed, Aug 6, 2025 at 6:35=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail.=
com> wrote:
>
>
>
> On 8/5/25 4:26 PM, Sabyrzhan Tasbolatov wrote:
> > Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures that need
> > to defer KASAN initialization until shadow memory is properly set up,
> > and unify the static key infrastructure across all KASAN modes.
> >
> > Some architectures (like PowerPC with radix MMU) need to set up their
> > shadow memory mappings before KASAN can be safely enabled, while others
> > (like s390, x86, arm) can enable KASAN much earlier or even from the
> > beginning.
> >
> > Historically, the runtime static key kasan_flag_enabled existed only fo=
r
> > CONFIG_KASAN_HW_TAGS mode. Generic and SW_TAGS modes either relied on
> > architecture-specific kasan_arch_is_ready() implementations or evaluate=
d
> > KASAN checks unconditionally, leading to code duplication.
> >
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
> > Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> > ---
> > Changes in v4:
> > - Fixed HW_TAGS static key functionality (was broken in v3)
>
> I don't think it fixed. Before you patch kasan_enabled() esentially
> worked like this:
>
>  if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>         return static_branch_likely(&kasan_flag_enabled);
>  else
>         return IS_ENABLED(CONFIG_KASAN);
>
> Now it's just IS_ENABLED(CONFIG_KASAN);

In v4 it is:

        #if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAG=
S)
        static __always_inline bool kasan_shadow_initialized(void)
        {
                return static_branch_likely(&kasan_flag_enabled);
        }
        #else
        static __always_inline bool kasan_shadow_initialized(void)
        {
                return kasan_enabled(); // which is IS_ENABLED(CONFIG_KASAN=
);
        }
        #endif

So for HW_TAGS, KASAN is enabled in kasan_init_hw_tags().

>
> And there are bunch of kasan_enabled() calls left whose behavior changed =
for
> no reason.

By having in v5 the only check kasan_enabled() and used in current mainline=
 code
should be right. I've addressed this comment below. Thanks!

>
>
> > - Merged configuration and implementation for atomicity
> > ---
> >  include/linux/kasan-enabled.h | 36 +++++++++++++++++++++++-------
> >  include/linux/kasan.h         | 42 +++++++++++++++++++++++++++--------
> >  lib/Kconfig.kasan             |  8 +++++++
> >  mm/kasan/common.c             | 18 ++++++++++-----
> >  mm/kasan/generic.c            | 23 +++++++++++--------
> >  mm/kasan/hw_tags.c            |  9 +-------
> >  mm/kasan/kasan.h              | 36 +++++++++++++++++++++---------
> >  mm/kasan/shadow.c             | 32 ++++++--------------------
> >  mm/kasan/sw_tags.c            |  4 +++-
> >  mm/kasan/tags.c               |  2 +-
> >  10 files changed, 133 insertions(+), 77 deletions(-)
> >
> > diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enable=
d.h
> > index 6f612d69ea0..52a3909f032 100644
> > --- a/include/linux/kasan-enabled.h
> > +++ b/include/linux/kasan-enabled.h
> > @@ -4,32 +4,52 @@
> >
> >  #include <linux/static_key.h>
> >
> > -#ifdef CONFIG_KASAN_HW_TAGS
> > +/* Controls whether KASAN is enabled at all (compile-time check). */
> > +static __always_inline bool kasan_enabled(void)
> > +{
> > +     return IS_ENABLED(CONFIG_KASAN);
> > +}
> >
> > +#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
> > +/*
> > + * Global runtime flag for KASAN modes that need runtime control.
> > + * Used by ARCH_DEFER_KASAN architectures and HW_TAGS mode.
> > + */
> >  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> >
> > -static __always_inline bool kasan_enabled(void)
> > +/*
> > + * Runtime control for shadow memory initialization or HW_TAGS mode.
> > + * Uses static key for architectures that need deferred KASAN or HW_TA=
GS.
> > + */
> > +static __always_inline bool kasan_shadow_initialized(void)
>
> Don't rename it, just leave as is - kasan_enabled().
> It's better name, shorter and you don't need to convert call sites, so
> there is less chance of mistakes due to unchanged kasan_enabled() -> kasa=
n_shadow_initialized().

I actually had the only check "kasan_enabled()" in v2, but went to
double check approach in v3
after this comment:
https://lore.kernel.org/all/CA+fCnZcGyTECP15VMSPh+duLmxNe=3DApHfOnbAY3NqtFH=
ZvceZw@mail.gmail.com/

Ok, we will have the **only** check kasan_enabled() then in
kasan-enabled.h which

        #if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAG=
S)
        static __always_inline bool kasan_enabled(void)
        {
                return static_branch_likely(&kasan_flag_enabled);
        }
        #else
        static inline bool kasan_enabled(void)
        {
                return IS_ENABLED(CONFIG_KASAN);
        }

And will remove kasan_arch_is_ready (current kasan_shadow_initialized in v4=
).

So it is the single place to check if KASAN is enabled for all arch
and internal KASAN code.
Same behavior is in the current mainline code but only for HW_TAGS.

Is this correct?

>
>
> >  {
> >       return static_branch_likely(&kasan_flag_enabled);
> >  }
> >
> > -static inline bool kasan_hw_tags_enabled(void)
> > +static inline void kasan_enable(void)
> > +{
> > +     static_branch_enable(&kasan_flag_enabled);
> > +}
> > +#else
> > +/* For architectures that can enable KASAN early, use compile-time che=
ck. */
> > +static __always_inline bool kasan_shadow_initialized(void)
> >  {
> >       return kasan_enabled();
> >  }
> >
>
> ...
>
> >
> >  void kasan_populate_early_vm_area_shadow(void *start, unsigned long si=
ze);
> > -int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
> > -void kasan_release_vmalloc(unsigned long start, unsigned long end,
> > +
> > +int __kasan_populate_vmalloc(unsigned long addr, unsigned long size);
> > +static inline int kasan_populate_vmalloc(unsigned long addr, unsigned =
long size)
> > +{
> > +     if (!kasan_shadow_initialized())
> > +             return 0;
>
>
> What's the point of moving these checks to header?
> Leave it in C, it's easier to grep and navigate code this way.

Andrey Konovalov had comments [1] to avoid checks in C
by moving them to headers under __wrappers.

: 1. Avoid spraying kasan_arch_is_ready() throughout the KASAN
: implementation and move these checks into include/linux/kasan.h (and
: add __wrappers when required).

[1] https://lore.kernel.org/all/CA+fCnZcGyTECP15VMSPh+duLmxNe=3DApHfOnbAY3N=
qtFHZvceZw@mail.gmail.com/

>
>
> > +     return __kasan_populate_vmalloc(addr, size);
> > +}
> > +
> > +void __kasan_release_vmalloc(unsigned long start, unsigned long end,
> >                          unsigned long free_region_start,
> >                          unsigned long free_region_end,
> >                          unsigned long flags);
> > +static inline void kasan_release_vmalloc(unsigned long start,
> > +                        unsigned long end,
> > +                        unsigned long free_region_start,
> > +                        unsigned long free_region_end,
> > +                        unsigned long flags)
> > +{
> > +     if (kasan_shadow_initialized())
> > +             __kasan_release_vmalloc(start, end, free_region_start,
> > +                        free_region_end, flags);
> > +}
> >
>
> ...> @@ -250,7 +259,7 @@ static inline void poison_slab_object(struct kme=
m_cache *cache, void *object,
> >  bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
> >                               unsigned long ip)
> >  {
> > -     if (!kasan_arch_is_ready() || is_kfence_address(object))
> > +     if (is_kfence_address(object))
> >               return false;
> >       return check_slab_allocation(cache, object, ip);
> >  }
> > @@ -258,7 +267,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache=
, void *object,
> >  bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool in=
it,
> >                      bool still_accessible)
> >  {
> > -     if (!kasan_arch_is_ready() || is_kfence_address(object))
> > +     if (is_kfence_address(object))
> >               return false;
> >
> >       poison_slab_object(cache, object, init, still_accessible);
> > @@ -282,9 +291,6 @@ bool __kasan_slab_free(struct kmem_cache *cache, vo=
id *object, bool init,
> >
> >  static inline bool check_page_allocation(void *ptr, unsigned long ip)
> >  {
> > -     if (!kasan_arch_is_ready())
> > -             return false;
> > -
>
>
> Well, you can't do this yet, because no arch using ARCH_DEFER_KASAN yet, =
so this breaks
> bisectability.
> Leave it, and remove with separate patch only when there are no users lef=
t.

Will do in v5 at the end of patch series.

>
> >       if (ptr !=3D page_address(virt_to_head_page(ptr))) {
> >               kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_F=
REE);
> >               return true;
> > @@ -511,7 +517,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsig=
ned long ip)
> >               return true;
> >       }
> >
> > -     if (is_kfence_address(ptr) || !kasan_arch_is_ready())
> > +     if (is_kfence_address(ptr))
> >               return true;
> >
> >       slab =3D folio_slab(folio);
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxg%3DzC-82sY6f-z0VOnmbpN2E8tQxe7RyOnynpbJEFP%2BNA%40mail.gmail.com.
