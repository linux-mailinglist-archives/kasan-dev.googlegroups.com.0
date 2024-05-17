Return-Path: <kasan-dev+bncBDW2JDUY5AORB4VKTWZAMGQEOFWBB6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id AF9698C86E8
	for <lists+kasan-dev@lfdr.de>; Fri, 17 May 2024 15:02:43 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2e6f31e5909sf31296981fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 17 May 2024 06:02:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715950963; cv=pass;
        d=google.com; s=arc-20160816;
        b=lPH7rRL+v7VvMmw/OQXW3i9V9n4h7+iP/fkZeCrgQKkoZJokdihejg5D+Eb5X0WUho
         6pEwlozVZO6kHr2/gyD9MhqNgJP2s3ClRRzotJp5pp0XDehWN4y4Osw2VdaLDWxtxBqf
         hklf/sGJfSnwmXuKeKVdcREhBInfAGFQS87hRHVj4Y+71wKzYjKElurnbC3itz0bIOI6
         d8006qmFNqEzsOIda/MWiMGu7TFX12Rz8V+iVf9PiSEgBCWGdFWZrJYP6CfZTZr14C4O
         dob5wiqTPEur1NVKoh1UVToxGMEBIUZFtGGS5gTl2MHc/au/T5I6aRQGV46z9cp0yEEF
         0iJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=NoNdQQbQZPLuh79GlwR2KEAdJ4N1qErRUVYG6a5hrR0=;
        fh=FWRodFGtdsJz64ylVv1Lo/SqqC772FLNbzknstoW17k=;
        b=kSj/yIp5PDEL9KP9kUa2ctTIB7f7wtbC29a6wZDeIUCFYso6DIgAGrkej4c9rEBB+X
         MAKUkFsmPDBEuwS13tL7Vs3RJjuT9OMEY9QhsMtv+0u2v6H9k2TQYoblhYupARmhLYrH
         0yIQfhYp/x9IK3CCUvS0j1Ykazrn09AdsLih2x6Xx9zC1ZqV86InDhDze5Y0xvEhATiG
         RU3Hk/0Zo6PneSrvXGshZ07K/Si0Cssfm5NQ+TpC3TaSm9LZczspcwwkf4vn075llpC5
         CEn55c+4C+xOsf49g27oCghKL1s5JxF2b3gRp6agtFKBhm4XdO2qu7ZaYLhnCmwKWr2W
         xqjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="TYaP8HW/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715950963; x=1716555763; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NoNdQQbQZPLuh79GlwR2KEAdJ4N1qErRUVYG6a5hrR0=;
        b=CGWlVPWHw/P1g5RAswILncSF1XGBpYu+L6skXgNVjD8O+0gbBDg9W2eypy0NtIxJZ0
         t1nAynn2OFL/3YR3bT2KDuJZHZnrru1shv6xTipT72YZDudpq8X/bYrTXYwBE7FbJHai
         TJ9h3dIRuI3R0gfur3rhzgvDAzc4hHHg2Z/+ka/0S9wT2a3bylq0NaTawS5osrodph9v
         G2CcNR6BIRdRNFUgZUtqofe4GWrJxmQ81bF0Q2uaqpvNGpmJG/5Oyn3GxN/baigCnDZN
         m2Krq06CFLl2Am5bqcpt+mZrfsCgHZp9HnH6jYUdSny5Y8KEj3idtlhjsrkTVPrxZd9U
         oUeQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1715950963; x=1716555763; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NoNdQQbQZPLuh79GlwR2KEAdJ4N1qErRUVYG6a5hrR0=;
        b=K3KVS48C02Vy/kWXxo1keYs/SQoG3dALqH0EzECBrSs/HqIBmRzpjeqTDva4KFXelz
         u0T97gP1v7W1ZZOO5duiPxz1A6RHfDGXr35BerhI3r24sE05pg+fBdVUNkybCk2rvxgr
         QzYCbCa+iiJ7I+kaRIgmwByq1QH+cMgWDu/trd7G4V8yKbHuhN6kGXnxYfjPBnbv3LlE
         3s0Lf3HEgb9Xcy97wonIdQFdZhkaMff/p4RGNdjyNVARufirmIfDlZqiIsg6IV0HhOl5
         eSPrWFQPbcKjETd4YGlwXDHx69jlGQnWBdK9MXbPohR03Ijce0Gm67tgxlm0cswtwuqZ
         bJGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715950963; x=1716555763;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NoNdQQbQZPLuh79GlwR2KEAdJ4N1qErRUVYG6a5hrR0=;
        b=GaAszwWn7L9qwOUxA++PqGZauXDR1aInm9Wgw+R5qfrq0JmkPhCtXLTjU/84CRp5my
         kthZDbC2xTMzvaDDEqFyGw7v0ez4xnHFNnv3nmkKC6/Ir7deKF+MJxRBOIUHS0gx5h5V
         AY28GWGVU5yPV05ZJdHdWNXM8owIjs0F4pxWp4hbilCCwqrDQWaxmca9jhttp1pXz39V
         mzSO/y/LLCRKBAX73SSYCLRGd5ycDrlN2kQsUetTjupFmOmrkJwLskmZy6oNdnhvTtFo
         qz71eSneL1n1BlAEIveuTD6N3M8HOqqAYPPkTe6Mb6JJk/rKCtXRuGhAJM+J7VrMnyk/
         xW9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZFcCunPRK+N3AiBhuLWfzFE1dl1/MYkEJ1AAm0tSBZC0hjlsUNCajn6QHw+lzqxY9x3oghWdGVuvYmVKGlWX8oLGOd94/Qw==
X-Gm-Message-State: AOJu0YwyDoYBPQ3niXg9LbMATQz49LlwE1Ex90QiN6asLc4p5QpW7R6m
	yJPnjIRaw4lHdj6pmrF31I310uagTGFAEBGtrh2NUp47s6iemPgu
X-Google-Smtp-Source: AGHT+IGDUfgYM8Cgghpiff755MhBV/4zaBdoBkCwQ/Skw9+kxHd7BcdQtUoDHpFSinTQWfQ7IrZ5nA==
X-Received: by 2002:a2e:6101:0:b0:2e0:c689:f8cd with SMTP id 38308e7fff4ca-2e51ff6013emr156581311fa.29.1715950962713;
        Fri, 17 May 2024 06:02:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b16a:0:b0:2e6:fc88:7866 with SMTP id 38308e7fff4ca-2e6fc887c43ls9653121fa.0.-pod-prod-07-eu;
 Fri, 17 May 2024 06:02:41 -0700 (PDT)
X-Received: by 2002:a2e:8788:0:b0:2d8:654e:7027 with SMTP id 38308e7fff4ca-2e51ff65bd3mr163873721fa.30.1715950960852;
        Fri, 17 May 2024 06:02:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715950960; cv=none;
        d=google.com; s=arc-20160816;
        b=XaZb+X/un2SejPATh+F1KCvO/ANzqI/phvz3ksBQOhrG2JYrmrfTJZLcwg2aAfLVnN
         GbQIm4ZBZlpeMQaBokJaXfLx+0rcZilStAv1eD/ug/3yMcZpFncCiUa3Kg7Y6Df8X+0w
         F6mk+RSgWwxHPzilbpndU025QYEsFSjqltVIJRFutYM8Pl4XfJs/RLd3wbsJeERJLpgC
         rerFm4G8W+gJdYGO+aiu1w0lnsmdz/HpZcsYnFL3SQL/bHIrh3j7eeTyjLkO9q0QsGh5
         HvxaMb5H/YC9T64irJ3TN1g4hpQQjSTecdxKdqCsHmYcz9kUOyMHZVn5Qee5heFtrLcZ
         3Xhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rrQk/zOuwoZ/gTNLgUZwce7uWfKFbQWp+MK1UVbA3u4=;
        fh=hGdLAAmsqbUdr//3SoG+7JuQe2+1p2JRT2MVj5ojByc=;
        b=TVlTUHlxZB67odTDnVwDSNWaCVwZpDeqvnUbCQ+XqB77La5Uv0wd7cW1ybJo2C24hg
         CIGD5Xdn/Y9vvsjMrD0CS1jg3ZYqUbvgGjiSJyqLb99KNvRn/jkQWyTMIuh1bWLToKV2
         I8Ps5jTOLm4kWNmnHw6E4RH9i+k/W/Lp3cPsnIUVuwMenpaFAf86Y4OVIPkwtaBsJLTL
         mt3famZuwrUnw7/kRh3yLPJURY5kmF6Ac6/IsmW5fODVaXXWZu9n/Lr+3RONJ26kLzeY
         tYZhBa7fe3voXD7d3RFgpWv4iShljjC12hpBmGtDduzMso1i+CAn5yOtxYapQz2Jgp44
         Smfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="TYaP8HW/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2e4d1836a6dsi4736271fa.7.2024.05.17.06.02.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 May 2024 06:02:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-4202ca70318so786345e9.1
        for <kasan-dev@googlegroups.com>; Fri, 17 May 2024 06:02:40 -0700 (PDT)
X-Received: by 2002:a7b:c40a:0:b0:41b:d4a3:ad6a with SMTP id
 5b1f17b1804b1-41feaa42ce1mr205732115e9.17.1715950959914; Fri, 17 May 2024
 06:02:39 -0700 (PDT)
MIME-Version: 1.0
References: <20240427205020.3ecf3895@yea> <20240501144156.17e65021@outsider.home>
In-Reply-To: <20240501144156.17e65021@outsider.home>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 17 May 2024 15:02:28 +0200
Message-ID: <CA+fCnZdNBEekgcfaGafJKmpb-A7R6rBuL5QojOhpqkHZvz1nKg@mail.gmail.com>
Subject: Re: Machine freezes after running KASAN KUnit test 21 with a GCC 13.2
 built kernel but runs tests fine with a CLANG 18 build kernel (v6.9-rc5,
 32bit ppc, PowerMac G4 DP)
To: Erhard Furtner <erhard_f@mailbox.org>, Nico Pache <npache@redhat.com>
Cc: kasan-dev@googlegroups.com, linuxppc-dev@lists.ozlabs.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="TYaP8HW/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, May 1, 2024 at 2:42=E2=80=AFPM 'Erhard Furtner' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Sat, 27 Apr 2024 20:50:20 +0200
> Erhard Furtner <erhard_f@mailbox.org> wrote:
>
> > Greetings!
> >
> > Building kernel v6.9-rc5 with GCC 13.2 + binutils 2.42 and running KASA=
N KUnit tests (CONFIG_KASAN_INLINE=3Dy, CONFIG_KASAN_KUNIT_TEST=3Dy) on my =
Dual CPU PowerMac G4 DP always freezes the machine after test 21 (see attac=
hed dmesg gcc_v02). Sometimes the G4 is able to reboot, most of the time it=
 just freezes:
>
> Turns out this is not a ppc specific issue at all, happens also on my AMD=
 FX 8370, tested on kernel v6.9-rc6. clang18 built kernel runs and passes K=
ASAN KUnit tests fine whereas a gcc13 built kernel freezes or reboots after=
 test 20 (ppc after test 21):
>
> [...]
>     ok 16 kmalloc_uaf_16
>     # kmalloc_oob_in_memset: EXPECTATION FAILED at mm/kasan/kasan_test.c:=
566
>     KASAN failure expected in "memset(ptr, 0, size + KASAN_GRANULE_SIZE)"=
, but none occurred
>     not ok 17 kmalloc_oob_in_memset
>     # kmalloc_oob_memset_2: EXPECTATION FAILED at mm/kasan/kasan_test.c:4=
96
>     KASAN failure expected in "memset(ptr + size - 1, 0, memset_size)", b=
ut none occurred
>     not ok 18 kmalloc_oob_memset_2
>     # kmalloc_oob_memset_4: EXPECTATION FAILED at mm/kasan/kasan_test.c:5=
14
>     KASAN failure expected in "memset(ptr + size - 3, 0, memset_size)", b=
ut none occurred
>     not ok 19 kmalloc_oob_memset_4
>     # kmalloc_oob_memset_8: EXPECTATION FAILED at mm/kasan/kasan_test.c:5=
32
>     KASAN failure expected in "memset(ptr + size - 7, 0, memset_size)", b=
ut none occurred
>     not ok 20 kmalloc_oob_memset_8
>     # kmalloc_oob_memset_16: EXPECTATION FAILED at mm/kasan/kasan_test.c:=
550
>     KASAN failure expected in "memset(ptr + size - 15, 0, memset_size)", =
but none occurred

+Nico, who also encountered this issue.

Mailed a patch that should fix this:
https://lore.kernel.org/linux-mm/20240517130118.759301-1-andrey.konovalov@l=
inux.dev/T/#u

You can consider disabling CONFIG_FORTIFY_SOURCE for now as a workaround.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdNBEekgcfaGafJKmpb-A7R6rBuL5QojOhpqkHZvz1nKg%40mail.gmai=
l.com.
