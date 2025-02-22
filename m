Return-Path: <kasan-dev+bncBDW2JDUY5AORBN6Q466QMGQEXWDCCPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CD77A40959
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2025 16:07:37 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3cf64584097sf27779145ab.2
        for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2025 07:07:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740236855; cv=pass;
        d=google.com; s=arc-20240605;
        b=W59p7SFLaEgcgWA8voVWY3UR73JpvDiqGBmtE3UYbUme8E/RQ3AIGHjC9G5udBqfhs
         BwsBkDu5bNnCVTDfzx4knEuDY5pBY7rLEoZ1D1zuo2OLAE6VeXUi7B2cMc/p/bcUmS86
         +zqlTrR5EEGwTrfea5NxE2tSAdARgEkPiHhxmK7cdkXOD4wD/NuBAaJFatc3BNw/eGmp
         s3+PGzLFI5Zbxh+uR4GYZAIeg7t772BGfSERNgGa1MWrvInd8mUHRM3VKPsYOBj96Ce5
         0ctpjZpU9gpcw0qOQpB9ZbKbJKJJH3QoOLwoWPXeOAPF7zTSPNJVdtqkMSpaFlRofXnA
         gLGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CrIeolSv6AQv2k7xnes+Wp+/HGbUGWAYuxbp1UNJhxk=;
        fh=wD8wHG2xMP5D4+WiU7kJF/eqFLGCul4XfgEBkWdlWPM=;
        b=MbpQIk3+1vER5QrN6rKH7AhGoMWuWe9pA+YgNKu8OUHBv1K0zzk4nDvOIyL2k3qc20
         gIcA7f1dt1IP5hDbYhoBFdSXG/Rm686w+fgz7kIwwyuwjBhoa2lomVtkMGWnfn0mr9Rg
         +VW6Fx4QmhZq+D5voNQtluaMdZ8jOvBEnlQl0ucvgFXYkaStWqyoZC2ag3ScV9KafgKq
         rYl9GdNnN+/w96jRxkvvjYfBRtaRitvmEXGPjn6Oba35JxkrsMWR8n0JHOU8S5sT5uDv
         c+lBUgHWzRM/EM666hk0pqbc64XfSDQOTzdoSgK7psfXEpkLnLP4Lujqsp1TTRy1TAwR
         E1Vg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Cuehv0co;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740236855; x=1740841655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CrIeolSv6AQv2k7xnes+Wp+/HGbUGWAYuxbp1UNJhxk=;
        b=Ce1/yOnxpAHgRzP+eJYDSm+YNmSZc+gUm/Js7yDOHaiXKEN7xc7taOjnCx5yTx0jss
         i6ObLNpX3bdOkIntlY6dNXjp4N5GZ3MrDMH5QL/vypWt/vONKwZTsJ4lyF5i0CJXlPM3
         qXYykLVgSzgtJl8G7u0J7r1SRQyNve0QMyx/sipIsEqrQZWX3WmxiYPuW31NDqj5fLS3
         9NE9j2wQdetb0QqELsccUFCQetjScEzOJTLfWQKdwgQUQ88kZ8YWyUaLkZggYj/88VRD
         RrVmJDwbwZKR+X/kgpneOmGMVPGNHYDj9UZ5FvHM28jRa84yj6Y2v+k+CV/xVOfraBr4
         NDew==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740236855; x=1740841655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CrIeolSv6AQv2k7xnes+Wp+/HGbUGWAYuxbp1UNJhxk=;
        b=JDTaTfhvepbGpyReV4iMVW10hA91VLhU4hPLqGyLiQ2PInoCsX+9UlogykkqOCrZhX
         vVax1ihXzIKwcGChaisfO/3ENvO2ao9q2gsjVWBjkz3d0WqACJtiZpc26bu47/FTat1Y
         bfAMJGs2hR6oEugF9jFWXQW+dDKkgnTfYCVIWqoXTpZWgD4ujXfrXd8/bNEa+yPzREkX
         9c9KEC/uaI5wmhI6dl7fdzTetmtAsxGmEGkuaAsi/3Of+LZxJZK2OYyEEZqsP3ulHlTj
         ojjiQj3PmIlDQbftkYnRg69M1JNNJ1P61fqxcHzABg8w9cDkrp7PkHui/XhW2Raam/wG
         mS9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740236855; x=1740841655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CrIeolSv6AQv2k7xnes+Wp+/HGbUGWAYuxbp1UNJhxk=;
        b=h0my7lE1W5G8aO02nQlUT7xUVDKQuFCzNC0joFnnp153EhsZ4jNwDHQuoxJcvnvBve
         hfVnIyAy/l4CDARjaVBu7fmmqxFlrtQNoGlWpgGTzoGTzlltJ+ynKmYp2ASY+/OZlGaI
         SvYuMqNwyu6SRypDJNalQPYg3z0fSYg9F1Z4JNKvzYqhZTUdYjrf/+ZiEgsk051kTPJl
         oTirApkaR3WsCFUpxFd/sVIuzj3LnDpozOWIo1xwCDmbAIM4px7YZjNPfMmozQZJWa6G
         xnEwyP+VmXYhGiC8CP3HKVYWflY4oV0V30bArTfl+N5Pn7s1XMwjuvIC9KQyqPDbj0H2
         kMgA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKHXpMi6VW7THZprp+9dA6EL89Xd/gDJbvSzw7hHO2DU1rz6CAuingFfkjbu3OC5Cj6H//WA==@lfdr.de
X-Gm-Message-State: AOJu0YyBFeRnpskTghvVqL8OOmH7mf1qdwEh5dMk8QZonlJdxhMCpcT1
	FB5zF2E68uqOkOq1yeGOS473N+/x8fYk8mlaKmUe8VFFtbezZxdp
X-Google-Smtp-Source: AGHT+IHeScSpY7k7OV7fagn5uY/o4vwcu5Pvk8xLnmM2n/wKNdwUDzRy26d5yHPF5YmqBuIjKrD5dw==
X-Received: by 2002:a05:6e02:1d89:b0:3d2:a5a0:8afa with SMTP id e9e14a558f8ab-3d2cae691f7mr67432365ab.6.1740236855613;
        Sat, 22 Feb 2025 07:07:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHvu1yLaM6rW5k6vEFnSpUpEgU41BH8Hv0VdT4SMjxoew==
Received: by 2002:a05:6e02:3083:b0:3d1:9c39:8f7e with SMTP id
 e9e14a558f8ab-3d2bfd04215ls13249335ab.2.-pod-prod-07-us; Sat, 22 Feb 2025
 07:07:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX6i6apFlPlgRSMVgPGKmM45aqif6xH0Q/st5Qa/1dREgC0nyI+4BTSHmJPaG9a1FVClHf1cUO8xiE=@googlegroups.com
X-Received: by 2002:a05:6e02:1d1d:b0:3cf:bc71:94ee with SMTP id e9e14a558f8ab-3d2caf00c0amr58450695ab.14.1740236854765;
        Sat, 22 Feb 2025 07:07:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740236854; cv=none;
        d=google.com; s=arc-20240605;
        b=a+Vcabfp7czYfOlMy0QNBaxMEAKdeavu8xQE0JQD6iK7wUMsCYYBgBnE8U9HW9s8PF
         eeAbbfHOa2o7ybjBbVdg+5nqyFwMWzmtvwzQP5njYf5onj8y/V+VDDQbBYHa7lo1BznF
         pxKYeGiQOBbbsKhfF5MxEARPapJrKJvXiy6Q/CAte8jrtg7dU1taUCy09m8xWsAfHo/g
         kZIZUWbFK0XuTrbro/yl/lBsa2sROF0PGQxU3/HQfWbkbHdDxy7DYURcBN+B/VTiD7mS
         n6TP0gXbAJYHNHtJl9j91DwSspclRmxf8B2g5Kp8fpB3kvnZht5i2NVI4lRl9McUbvOO
         ij5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=70pD9gnFNEV46q1yL+XWGZJhvCSgCKDZIGACepg3f1I=;
        fh=mJng2kMGEXnI1aqZBUxsjAKIOOMSW3xSPGJl0+NOv3Q=;
        b=MT2iOMSU71ZnbVPssdGapOwiD7CUI6RGrJGagwX2TcHHwzusgGzbIBSSIGOb+AZHz0
         t2GzYeZW2rm1169MlXjWck8g0adiTyuZ+9E4wWqHBX4d4+y9OldRoHb2kVHyWYhnvkRG
         mIofIEwu+jg2Tq4kJDJiCOqJZwIcA0JGBPO+cjXTpySFm2zYWbX3MHfaO36S9yWqNrQo
         nun2vQ/P4FtcoD+edVywmADfFKxaY1lVwHPTtzmjSyL2q7RphaPzsbIdtFnsYYLIskcA
         TCAJZbXco8EO9nbGnELYW37/6yTYG+8ThCFLlCuqXBgyk72e4wgeoe5i2/TXsPGnok4u
         2yJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Cuehv0co;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ee893ec68fsi746772173.4.2025.02.22.07.07.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 22 Feb 2025 07:07:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-6ddcff5a823so25319706d6.0
        for <kasan-dev@googlegroups.com>; Sat, 22 Feb 2025 07:07:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV5gu2D0EumaX3egQ6SMMDsRo336W0ruiR/6/wdzBIx4glO5muIhMuLYWZ14l5K3tnKPBh2CaTlhJE=@googlegroups.com
X-Gm-Gg: ASbGncvyLc41srjwk6DOHF9/e/CXiowTJ496bP5mjmY/NcKQCQVQM34a9wBz9ee5uBx
	GMTuyl33zzQf5A1vwZKZVXz1i8GIVEOon+zbQF1JSYMxhX3vO8VNnrZeYQzO36g0xnq/BGY61GV
	+flPATorzAoQ==
X-Received: by 2002:a05:6214:daa:b0:6e6:5cad:5ce6 with SMTP id
 6a1803df08f44-6e6ae7c9f82mr95965996d6.9.1740236853223; Sat, 22 Feb 2025
 07:07:33 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com> <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
In-Reply-To: <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 22 Feb 2025 16:07:20 +0100
X-Gm-Features: AWEUYZlkmxeF6xgXCl21B3APEThb1gNkBITR5DJujsdnWalnykrR9HY2cVqQu30
Message-ID: <CA+fCnZcOjyFrT7HKeSEvAEW05h8dFPMJKMB=PC_11h2W6g5eMw@mail.gmail.com>
Subject: Re: [PATCH v2 13/14] x86: runtime_const used for KASAN_SHADOW_END
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	ndesaulniers@google.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Cuehv0co;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f2b
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

On Fri, Feb 21, 2025 at 4:11=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> On 2025-02-20 at 00:31:08 +0100, Andrey Konovalov wrote:
> >On Tue, Feb 18, 2025 at 9:20=E2=80=AFAM Maciej Wieczor-Retman
> ><maciej.wieczor-retman@intel.com> wrote:
> >>
> >> On x86, generic KASAN is setup in a way that needs a single
> >> KASAN_SHADOW_OFFSET value for both 4 and 5 level paging. It's required
> >> to facilitate boot time switching and it's a compiler ABI so it can't =
be
> >> changed during runtime.
> >>
> >> Software tag-based mode doesn't tie shadow start and end to any linear
> >> addresses as part of the compiler ABI so it can be changed during
> >> runtime.
> >
> >KASAN_SHADOW_OFFSET is passed to the compiler via
> >hwasan-mapping-offset, see scripts/Makefile.kasan (for the INLINE
> >mode). So while we can change its value, it has to be known at compile
> >time. So I don't think using a runtime constant would work.
>
> I don't know about arm64, but this doesn't seem to work right now on x86.

You mean it _does_ seem to work? Or otherwise if runtime constant
doesn't work on x86, then we shouldn't use it?

> I
> think I recall that hwasan-mapping-offset isn't implemented on the x86 LL=
VM or
> something like that? I'm sure I saw some note about it a while ago on the
> internet but I couldn't find it today.

In LLVM sources, ShadowBase gets calculated [1] based on
Mapping.Offset [2], which is in turn taken [3] from
hwasan-mapping-offset [4]. And then ShadowBase is used to calculate
[5] the shadow memory address.

All of this happens in the common code, so this should affect both x86
and arm64.

[1] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tran=
sforms/Instrumentation/HWAddressSanitizer.cpp#L1305
[2] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tran=
sforms/Instrumentation/HWAddressSanitizer.cpp#L761
[3] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tran=
sforms/Instrumentation/HWAddressSanitizer.cpp#L1863
[4] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tran=
sforms/Instrumentation/HWAddressSanitizer.cpp#L171
[5] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tran=
sforms/Instrumentation/HWAddressSanitizer.cpp#L899

>
> Anyway if KASAN_SHADOW_OFFSET is not set at compile time it defaults to n=
othing
> and just doesn't get passed into kasan-params a few lines below. I assume=
 that
> result seems a little too makeshift for runtime const to make sense here?

Sorry, I don't understand this question.

If hwasan-mapping-offset is not set properly, then in the inline
instrumentation mode, the compiler won't generate the right
instructions to calculate the shadow memory address.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcOjyFrT7HKeSEvAEW05h8dFPMJKMB%3DPC_11h2W6g5eMw%40mail.gmail.com.
