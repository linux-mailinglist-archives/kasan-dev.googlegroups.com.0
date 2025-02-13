Return-Path: <kasan-dev+bncBDW2JDUY5AORBN4VWW6QMGQEIV5E2AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id E4479A334AD
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 02:28:24 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id a640c23a62f3a-ab77dd2c243sf45437066b.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 17:28:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739410104; cv=pass;
        d=google.com; s=arc-20240605;
        b=MnDp5fraBV4TTQIHpRXy9X5hVSua4VtApqEM+KwjZQe68QbzLLg//aZkpyA1CumSlW
         ThrpdrM+WABgZIOmFijkbzfGTRUgSWVmcWJUSgIsGI+v2bREU+ZmpdrAi5bS3veoQnkj
         qxc8G6z4Vu3wniadznlRqlqpFaNLIRMOVvFusjhcJ/4ES5BrH+uOv0wqEaZtSp9uKInv
         qUEllmKpFUwrsXIx+Px0OL05vPKnJoZfwOHw8zoeRA7fpYJ3o/CruoXda7qerrR3eJyR
         zdU9UHaVpsodivAV85o7EAxaXBsaVaF52PqD/JJ8G2+Zc80OFZ9kPNSpk9HNG7+c1Cua
         6Yow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=0YDm1GrGBvdCZU0DGHNnLJD+SKnwM/degqrEQl24qVI=;
        fh=J08sqI1LWW2D61jlvcqqFc5axcdCCqxcAKJQLAjgPtY=;
        b=c7L1rkxdFtWpgi1vlK+ECcaNcZLeNwq1YPFPm8KGffLclHnphuAAjeifkcHgzMNkP/
         q5T7KOPlkMxl8KE704VW+DrtRqb4u5QMe1sPfZAHpx0XhyEA9orOwETWnAXweEsog54u
         w+cHwhPYVqJtWWgrHx5XRiBETLScsuXPJVJM2MpvBdxLOu/saH8xGAmWFWXoqaliacEl
         Ssf0Blb7xVxuADOwPcjgTluDGEIwzwOar36kTGOd41PSw38CjA+u2lvEWc6uOh1XWjMP
         5p3jXjcCx1pLYORiDlof31oBnz1yucv0JraoSCoR+Kt25c3U2xCGeoG5cXDfdB/nz77E
         S7Yg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cr8DXd62;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739410104; x=1740014904; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0YDm1GrGBvdCZU0DGHNnLJD+SKnwM/degqrEQl24qVI=;
        b=bjyPO5u87+mDDQAlMhn2503cK/YAtGMJ138vNFuGUPb92bkBaaAsW/sjS2YigUBdP+
         GN2x8Fo3HsFHQs3QacKPnqE5wzS6Yd7a+0DxM/SsW51KHQETWCMy8cnHuCBxT9vpug9F
         cSDAoq8/OKq0M7L6Yn87oZurRuNlx5fafrO87qbytriN+23OiPAYw3owVdLNJnFYSAbq
         qBvO3BF5W+871EglkjyeZpfOURjzM/t5a+/6D3gbxR3RT3PPM9Kbz3V0fulRZYOx0Zpm
         pv7FcQ0Gm4Z1wfqz2kuMFz+FJwQqqIihvmSJ98rSFA7/OFmPxPJthi3Iqg071khxjy88
         RGPg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739410104; x=1740014904; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0YDm1GrGBvdCZU0DGHNnLJD+SKnwM/degqrEQl24qVI=;
        b=nqGK3kr/tRa5gquN4GAlCh8HDVQRvNSjz7d/C31k/b5N5O/iySxmh9CBe58xiUanbv
         sdGNG0U1O676K7LaeW1PiSWJyQoilkViKZd5vI/2u9EvEHBxo/tEcrBlwy+1Njkaypkw
         zI2DCZttuD1A/szfJSZg/LjZqoz14esDc7Re1VygXEB+Vaen+f3LkxyxyS9PMRcrsp/N
         sRDsYZcBHQlgVJojn3RmG0TZh2wyUAMT1DkpQ0VrzGWA+3yhgMsSWq+GtKpZ0ie/NBBs
         kQUAvai8u60RuEZ7vEmrrwASiwmvQiGRaj+9zP7ey9a7nWbhG1DaYwmTZfiblJWZ9BYH
         mfYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739410104; x=1740014904;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0YDm1GrGBvdCZU0DGHNnLJD+SKnwM/degqrEQl24qVI=;
        b=scGBKP+664rhGxutpcR/0NoslHZ4Ssy0v7Idg5YpsBEM8RRtsP3u5Ue7wkEH6oMr42
         mzHIZ8GjPBza7ab/mhipSGWFUqaaSJlC64sEumCTwH/7EKk0sfJ7sHazZcjQoJgZQJNO
         4ohuUju3l/9Bsnt7GZHKwiJUTN4+O14CjgPe2Kzcc1kdg9Uv7AmDrjwLjZz4NYqC46fY
         804ynyauAZGD52D2FAGDgXpV3BjO4INTfTMUx1BhyfktcWxz5/IEb0RV8SB8o1zh2yCh
         QqEjXEOGzkyRFLV73PXhIA/9MNUbS/zno2Se8aeSMrtUJTBZqTNn4zMnb78egKEkARll
         AudQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWhVUjWgbVpp9tsrFC42LqlVQYIgDuVdHXjKM3Y68FS69oRe7RN5vCPt42gbGtyx7t/RhFo6g==@lfdr.de
X-Gm-Message-State: AOJu0YwAnhHZQ3zKuJ+cXkS52WuIrJP4emE36vMSAUjVo5KPJ32kyR8V
	a+XKgyYLGiiIIfnS8tbbbFNhgkNODMifePtzDGqfsp1iqDl56ivH
X-Google-Smtp-Source: AGHT+IFj6lhMUEsrZPyUo3/C6CWUMtQ6qsUBc7m4nE9kV2SvOLCHBgEKLAlLQQczgO3lJTe0zOJjSA==
X-Received: by 2002:a17:906:b845:b0:ab7:d916:4fe4 with SMTP id a640c23a62f3a-aba4ebbdac8mr95759166b.24.1739410103722;
        Wed, 12 Feb 2025 17:28:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEYyb+Fy/iOhrdsw9qzxuQsQ1rLDA5FMbYLRGtwUVpzpg==
Received: by 2002:aa7:d6da:0:b0:5d3:e99c:a4c9 with SMTP id 4fb4d7f45d1cf-5dec991e664ls100a12.1.-pod-prod-06-eu;
 Wed, 12 Feb 2025 17:28:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV0xbUBiV27mMcg1mdFcIGN/7zjpDZPHpZz+xkjgDHw7RkA8lk/caLfAp1F5a1oCfKrU2g6Uq4A81Q=@googlegroups.com
X-Received: by 2002:a05:6402:3507:b0:5de:42f5:817b with SMTP id 4fb4d7f45d1cf-5deca011e8bmr814816a12.31.1739410100068;
        Wed, 12 Feb 2025 17:28:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739410100; cv=none;
        d=google.com; s=arc-20240605;
        b=hI0UTy5WRQddxFWfiBu2yynhIXpwG9YikEgr4v5AB6AGQTlUYLxsKd3NSg7fYKCWEN
         5mhB5jmEsM5/CDmBdrjNchSm8t061R8AVXsy/4I3mFlaj6LFHwJTxk2HjxvVq8gt/D7c
         dIj1mWBjG2sgrteeVjhqzNGuUUn0ms6bE+i+JH09jned0ssVnF/qLfNa8MniTqZTse09
         8gf9c6A9cIEg3Xidk+MdmgNBKzzM6riohW6hGVN/WypbtMgNo3ghA8V9dqRklRqqE5iS
         R4TGiE8mYBu8qGDbjtNFxPhd2bn9HLJa+wC4cx7pvRt02bFybciHAtE1AMJaZrYcyjLC
         FMaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FnnVExe7d6QVUJNp8Nm3NF0K0bg0bBBcU3T/4AzgGYI=;
        fh=4U+YX82Dn1nTYcw2O4WJYUl/Wl9YDZ/f9LgwhZ+wzR8=;
        b=f1YLnf24XUR2WH79drw3gF1BFGYr333hJSokhQUZkEOSSoFOo6NyAAUkEYUl09zTHu
         F8kUBS4K2jSNXDWL2mMZTUGCI/lfHaC92Ram7DYcbmP6sEdkMIhtNpLO0roKMSoEjjJo
         WfFE2CtTT4nfYD9zEh10l15pQU5wWRvaYuyIv1cA8YnRX+Jp7+JB66fibaJUWwz1igj6
         F44SBQhVqvhhrCUtuXIzplFcHDW47FW9jdyriDQ0n0RMK0iE1pZmUOaA5rKOABX4EaKI
         DcYosXK14NASqtpuPEyIOavMQkgN186UiGlH4BP6yWp+a25GHd/ihyleurTWavZVnDR/
         /4gw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cr8DXd62;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dece1c644asi6553a12.2.2025.02.12.17.28.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 17:28:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-4394820123dso1824235e9.2
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 17:28:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXvdJdSOAajjpkByZaSYp7sqZq4KnONfjnDYZ5camOsIiA0miwmdWXCt4yScoDLBXFqMQ4K04Xt7pc=@googlegroups.com
X-Gm-Gg: ASbGncuLWm2HYBoSi+O0kbV9XmYLCse7mQTxnLcP2ovoqJD49GwaVbHNwpekiAzlQLW
	d5SNvFAv+mX3yBHvzvd+vJeG3vfcc0oycCx//MuduF4rFJXjCngEbEC0dkFslju71ZLJRwwILsM
	0=
X-Received: by 2002:a05:6000:144f:b0:38f:227e:6ff2 with SMTP id
 ffacd0b85a97d-38f244df054mr1302880f8f.14.1739410099435; Wed, 12 Feb 2025
 17:28:19 -0800 (PST)
MIME-Version: 1.0
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
 <20241022015913.3524425-2-samuel.holland@sifive.com> <CA+fCnZeBEe3VWm=VfYvG-f4eh2jAFP-p4Xn4SLEeFCGTudVuEw@mail.gmail.com>
 <e7t5yzfw3dq5stp5xjy5yclcx6ikne4vwz7d6w2ukfw2b7gr6t@oomoynf3b2jl>
 <zjuvfdbl7q76ahdxk3lrgaznk7vjj43f5ftzfgrnca6dqtcd5x@5qj24womzgyq>
 <CA+fCnZfySpeRy0FCFidLdUUeqp97eBdjAqQyYPpz1WxYwcsW9A@mail.gmail.com>
 <aqhm7lc57srsfuff3bceb3dcmsdyxksb7t6bgwbqi54ppevpoh@apolj3nteaz6> <CA+fCnZdjTkreTcoo+J8wMhwDuAFM4g33U5BFy0OPtE0UCvyJbQ@mail.gmail.com>
In-Reply-To: <CA+fCnZdjTkreTcoo+J8wMhwDuAFM4g33U5BFy0OPtE0UCvyJbQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 13 Feb 2025 02:28:08 +0100
X-Gm-Features: AWEUYZn2XkAKpo5fHBIg4DaefcDCWc7cwclFMrZ0d3cOTpLW86BXbO6cjB81ilc
Message-ID: <CA+fCnZcoVdfXVN8VBFLx835cV0eGAT6Ewror2whLW761JnHjNQ@mail.gmail.com>
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
 header.i=@gmail.com header.s=20230601 header.b=cr8DXd62;       spf=pass
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

On Thu, Feb 13, 2025 at 2:21=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Tue, Feb 11, 2025 at 7:07=E2=80=AFPM Maciej Wieczor-Retman
> <maciej.wieczor-retman@intel.com> wrote:
> >
> > I did some experiments with multiple addresses passed through
> > kasan_mem_to_shadow(). And it seems like we can get almost any address =
out when
> > we consider any random bogus pointers.
> >
> > I used the KASAN_SHADOW_OFFSET from your example above. Userspace addre=
sses seem
> > to map to the range [KASAN_SHADOW_OFFSET - 0xffff8fffffffffff]. Then go=
ing
> > through non-canonical addresses until 0x0007ffffffffffff we reach the e=
nd of
> > kernel LA and we loop around. Then the addresses seem to go from 0 unti=
l we
> > again start reaching the kernel space and then it maps into the proper =
shadow
> > memory.
> >
> > It gave me the same results when using the previous version of
> > kasan_mem_to_shadow() so I'm wondering whether I'm doing this experimen=
t
> > incorrectly or if there aren't any addresses we can rule out here?
>
> By the definition of the shadow mapping, if we apply that mapping to
> the whole 64-bit address space, the result will only contain 1/8th
> (1/16th for SW/HW_TAGS) of that space.
>
> For example, with the current upstream value of KASAN_SHADOW_OFFSET on
> x86 and arm64, the value of the top 3 bits (4 for SW/HW_TAGS) of any
> shadow address are always the same: KASAN_SHADOW_OFFSET's value is
> such that the shadow address calculation never overflows. Addresses
> that have a different value for those top 3 bits are the once we can
> rule out.

Eh, scratch that, the 3rd bit from the top changes, as
KASAN_SHADOW_OFFSET is not a that-well-aligned value, the overall size
of the mapping holds.

> The KASAN_SHADOW_OFFSET value from my example does rely on the
> overflow (arguably, this makes things more confusing [1]). But still,
> the possible values of shadow addresses should only cover 1/16th of
> the address space.
>
> So whether the address belongs to that 1/8th (1/16th) of the address
> space is what we want to check in kasan_non_canonical_hook().
>
> The current upstream version of kasan_non_canonical_hook() actually
> does a simplified check by only checking for the lower bound (e.g. for
> x86, there's also an upper bound: KASAN_SHADOW_OFFSET +
> (0xffffffffffffffff >> 3) =3D=3D 0xfffffbffffffffff), so we could improve
> it.
>
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D218043

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcoVdfXVN8VBFLx835cV0eGAT6Ewror2whLW761JnHjNQ%40mail.gmail.com.
