Return-Path: <kasan-dev+bncBDW2JDUY5AORBU4IVK6QMGQE4AWVGHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 60637A2FDE4
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2025 23:57:25 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-5da15447991sf4291983a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2025 14:57:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739228245; cv=pass;
        d=google.com; s=arc-20240605;
        b=EKerSuhTYWRXph9IJS7TMTMzzeZRA4rjLukedN47HdozYmIGLHFEDNqBV+u27FU+Sm
         /syR982ZRlBp5qw9DIjD/OB0VviOg2aKrTZqlDLTQipM3Nt2C/jxsrEmQscu8oTCC7b6
         OHrj0/3gUrD9cu4J4oQKwXBWzOXNUcsFvC4GtW5byux3Pxr65hum6wnGdHgo+BG7Eebg
         I9/d0iZDTrRq8x/2le3fR+5amQ66Y9Fv/qBZaP1rbyz1Gv/c2/p3A1HIbgpjz56NJ7p1
         V2Y0bNzW9C9gUZ9ktIybIF5LZvexb2f69h4A+9GBnHJFtGNOoISFSi+e7mxndnXOKXZ/
         eDuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=IK4DXu+N23NTbfhg1tu+nr4XbEq/pppGFgsGXugX28k=;
        fh=/5AtJfoRNqWONp8mE3DqPPWUqnYZq65U37qv2rlwW1M=;
        b=ATBatDczITx7KiSAhe6V8rdMXRYSafp4n0osnsCRgowLZOBPMbNG76wFhZ/Pg8NPWr
         Xp9Gbh7NKgWRYT5V3Yf7VeLsdXZuI7Dv2fHAorq4sDBWe0RFKbYFFafSDQLfeGhPI1ge
         b2cZsdg0dHY7GX2NEUPgC+AXoyaMeRWh73c5C5h1dY6gHyjyJbf/gVhoF2F9daxBU0vJ
         AqxN5vwcPgPaomeOrFhhaH8oD5j6FpKcQr7Nwjq9PBqeE0bbf+/Fvv21ZhSBZXUwp/94
         4WjclZDnrnqJgUxLPh0pq9TQb1gHK7xRDdTyPTSHX/B1BcNOT7jPImDPmzC1FCSWrTwy
         AncA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=maY3IpCQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739228245; x=1739833045; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IK4DXu+N23NTbfhg1tu+nr4XbEq/pppGFgsGXugX28k=;
        b=DjP08T3FGO0ajJjUvC2024RxxgLTtj/+nrk8m3bb0O7yf92ZdZYz+xMg0CHgmpi67T
         T9QiMiCk7Nu0gxj2CTXvhjuaPWEK26FHfRRAofRw1oVtjywpdUDgP5sLkjJ/8flmgqjx
         AmUa8K71JOV/yG+tDmKuCsonDCKdBaPfJT+RJEDehERub2N0DCXwC5gzKJSCkjRk9JV5
         w/ernZTg0ItKJ4PrtJGsMBl8p8622ofd7RQIHyZSNF2SS83wMI75XFCihdCmqmeKdqfN
         VrbW2iFkmgv9/DiQXDsxaBu2FgT+ztb0Ikf0Vw50MNQtYpkkx7vrZpbn3vrrD55schfQ
         wodA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739228245; x=1739833045; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IK4DXu+N23NTbfhg1tu+nr4XbEq/pppGFgsGXugX28k=;
        b=goyHuQJCLl9l5/wQeYCCn54MrmQ4EnEy55gRriRFIhskgUikdDqI0hElUmRUFkbFI/
         v9IcYXV6u9I8rI+8Eo6IzQk2B3KadqqfiFE7+bLsloV7jcsl6vW5/I847insbWF0la6v
         OmydlvhTFSpbenGBgTc+Ht7lA8fpWHht7BqzFtULrZgHoMIjRJs4DDV0XC0wQJwhaEY7
         8cSLayzS5nGJrNSxuf9iXreFwxbJ3a1AK4Xq8LllgRjk2kMF98iWHDP+UoJaOaO8yWK1
         bKVP4pk8kyChWTj0DESl9F59n3SDsihaeigE8jnO7HLTQDtIHQ96RD6f6TSiluhTLpW1
         FfBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739228245; x=1739833045;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IK4DXu+N23NTbfhg1tu+nr4XbEq/pppGFgsGXugX28k=;
        b=uaoVie43FRz1t5sVh9U6f++0AwLc6av4Kq9OSPcLOZ+h0RGDMSF+yi1v+MhdGL70Yb
         YisT0fTs4H89MTKJ2oh9JSe4wKhDwiL6jYvVfB4MoFJvnvpa3cunj7XqZEvnwQ4PJorN
         CyVegyiYkvF4eemr1/EhZJt82CqProyjPEFYKdHAyzKUd1oPFhOTG1JL7IfySLkCUg8b
         wyfpVg3oLJVjh1ln3WpFRxKNw6ZPmN2ACrpo7uWe6uN4RZi5DhjgTnvPERTraLA91tcF
         aYYpi+TKkWFG//5qarqu2G1x1Jax4sPSZLglL6h1CeDG+3RKL6fJVc4HvjYINY8ouZKm
         cLpQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWWqWWJc7V0MYlqbNMW7zyec3jqROMjT2lCyTLUe1QYXLZ2MrBn3e6HblNpaYEmvaku4jCU3A==@lfdr.de
X-Gm-Message-State: AOJu0Yy2oo8sqOZ1jI2rUK/dlxarp/JEeYH1Ja736GlehWUlIqVH/925
	50W4HWkewelO+s4mNkpWTLYbZ5QDOxbXprMS6ogPC/WJFv9TKlUL
X-Google-Smtp-Source: AGHT+IGITALjpYRKV4Q/3hGID5GGCJwScuxdJMgnZDtwfz1MnWNDceQ8mizgRtAWHnp2T0EMnUtzzA==
X-Received: by 2002:a05:6402:5290:b0:5dc:ea7e:8c56 with SMTP id 4fb4d7f45d1cf-5de45070792mr38337641a12.22.1739228243491;
        Mon, 10 Feb 2025 14:57:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c885:0:b0:5d0:e410:4698 with SMTP id 4fb4d7f45d1cf-5de9b6e5609ls175856a12.1.-pod-prod-05-eu;
 Mon, 10 Feb 2025 14:57:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVnCfkNHB5oD6r7mMZfj2s642votREK41tGPfv9pT01u3lfuw1zwJc8t/pCVmcU8Woc8K6G5xwsjuU=@googlegroups.com
X-Received: by 2002:a05:6402:4607:b0:5d0:9054:b119 with SMTP id 4fb4d7f45d1cf-5de450706d0mr32272699a12.21.1739228241366;
        Mon, 10 Feb 2025 14:57:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739228241; cv=none;
        d=google.com; s=arc-20240605;
        b=QAxLu8BvQUNNyI8rF1Laqxqwxsgl4rtQJwmH2BQNGFgE/UtYu0x2ROO4DbaxiPKrSL
         AhVq7ZKCZmCKixjfrYnWpKGP4gBd6lwxkffg0wHRWXZGD/IWwju11gOUTq84wYncPsap
         vsLl2ANM3im2uX5AE8I2EZTNnMVJNnX1+w73xxthmPlrIjbaVJbNiSal2i3xndj59Yce
         GWJ/6SYlN7kCh2Mmz71Seip5d0uIha9w46VvxvBE9p41uWXglxKFlMJ8rk1rSQ2eWRt3
         Wk4two1QpevZfyfQRQ/CQdO+FxZmiFE4zZkUQfsld9ICE6nDQeorKBEKEH+Z6RF0d0pQ
         yLXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RNWayjBWWd58FYF2aoHGNPi8TO+bWh90xjxqLfz1DXo=;
        fh=2ak+9n9xyuz7nXcO9bSIOVdBJdMMjmC5s3+Im0s3rDA=;
        b=Bp653t80+YDCOMDXzqjU1x/zdijVhT8CkJJdWff2hLLW070GrtIVecLg689bV2S1Oj
         3YIetngIsaAvZxp8W0jESv9K6l5Y5vEsQ6iwy4RmJiMyyQ4CpdylygX8SLZbhM3DQ2Sb
         LYSsUE2HfHhDuQ9nq8OShGwmDxcXu8IkCVQpgVrDkxUD1cre3svT1XaY8JsGQqnt5Pzf
         Hqr8+YbpCxw2yQZyXO1xq1sk5fQVTlsxSW5ZNr2DG8/rBt1F8dZ4OiaiJXOgsnFvO8pV
         A7TiBeNtneoy97elpwS+o7THvMTphHnZnNi9MOLP3FAIlkXLQM5o3q2B9mIvIseVVdaD
         btkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=maY3IpCQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dcf5d1bfcbsi276815a12.3.2025.02.10.14.57.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2025 14:57:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-43932b9b09aso26186565e9.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2025 14:57:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVH69xDGHq0m/z4J7gHicJP5/Sbu2F85X51Zf4u6up6+L2j/Y1zqb4Q7R/sVgAjcTRGA1kLxPJb/ik=@googlegroups.com
X-Gm-Gg: ASbGnct6gDbiGVnlFuv6z/IydDb1WwJ5P+wvuvsQzSzgMKIpTcLgFseQVtLN++i9vWA
	AV6VVq2QyPARPrRVJ5oAyPXkSnkFtn5zVMzXMmzvnh5FDJWc7xjQ+I511scWkFZYdmZZp8JwLvw
	==
X-Received: by 2002:a05:600c:83ca:b0:434:f4fa:83c4 with SMTP id
 5b1f17b1804b1-439249bcfc5mr154560525e9.29.1739228240742; Mon, 10 Feb 2025
 14:57:20 -0800 (PST)
MIME-Version: 1.0
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
 <20241022015913.3524425-2-samuel.holland@sifive.com> <CA+fCnZeBEe3VWm=VfYvG-f4eh2jAFP-p4Xn4SLEeFCGTudVuEw@mail.gmail.com>
 <e7t5yzfw3dq5stp5xjy5yclcx6ikne4vwz7d6w2ukfw2b7gr6t@oomoynf3b2jl> <zjuvfdbl7q76ahdxk3lrgaznk7vjj43f5ftzfgrnca6dqtcd5x@5qj24womzgyq>
In-Reply-To: <zjuvfdbl7q76ahdxk3lrgaznk7vjj43f5ftzfgrnca6dqtcd5x@5qj24womzgyq>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 10 Feb 2025 23:57:10 +0100
X-Gm-Features: AWEUYZn_arFHbmdvgRzow88RfNbJeiY3tjTfw66TROSp7YjMhPMT9KN4C9hXEgM
Message-ID: <CA+fCnZfySpeRy0FCFidLdUUeqp97eBdjAqQyYPpz1WxYwcsW9A@mail.gmail.com>
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
 header.i=@gmail.com header.s=20230601 header.b=maY3IpCQ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333
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

On Mon, Feb 10, 2025 at 4:53=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> On 2025-02-10 at 16:22:41 +0100, Maciej Wieczor-Retman wrote:
> >On 2024-10-23 at 20:41:57 +0200, Andrey Konovalov wrote:
> >>On Tue, Oct 22, 2024 at 3:59=E2=80=AFAM Samuel Holland
> >><samuel.holland@sifive.com> wrote:
> >...
> >>> +        * Software Tag-Based KASAN, the displacement is signed, so
> >>> +        * KASAN_SHADOW_OFFSET is the center of the range.
> >>>          */
> >>> -       if (addr < KASAN_SHADOW_OFFSET)
> >>> -               return;
> >>> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> >>> +               if (addr < KASAN_SHADOW_OFFSET ||
> >>> +                   addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size)
> >>> +                       return;
> >>> +       } else {
> >>> +               if (addr < KASAN_SHADOW_OFFSET - max_shadow_size / 2 =
||
> >>> +                   addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size /=
 2)
> >>> +                       return;
> >>
> >>Hm, I might be wrong, but I think this check does not work.
> >>
> >>Let's say we have non-canonical address 0x4242424242424242 and number
> >>of VA bits is 48.
> >>
> >>Then:
> >>
> >>KASAN_SHADOW_OFFSET =3D=3D 0xffff800000000000
> >>kasan_mem_to_shadow(0x4242424242424242) =3D=3D 0x0423a42424242424
> >>max_shadow_size =3D=3D 0x1000000000000000
> >>KASAN_SHADOW_OFFSET - max_shadow_size / 2 =3D=3D 0xf7ff800000000000
> >>KASAN_SHADOW_OFFSET + max_shadow_size / 2 =3D=3D 0x07ff800000000000 (ov=
erflows)
> >>
> >>0x0423a42424242424 is < than 0xf7ff800000000000, so the function will
> >>wrongly return.
> >
> >As I understand this check aims to figure out if the address landed in s=
hadow
> >space and if it didn't we can return.
> >
> >Can't this above snippet be a simple:
> >
> >       if (!addr_in_shadow(addr))
> >               return;
> >
> >?
>
> Sorry, I think this wouldn't work. The tag also needs to be reset. Does t=
his
> perhaps work for this problem?
>
>         if (!addr_in_shadow(kasan_reset_tag((void *)addr)))
>                 return;

This wouldn't work as well.

addr_in_shadow() checks whether an address belongs to the proper
shadow memory area. That area is the result of the memory-to-shadow
mapping applied to the range of proper kernel addresses.

However, what we want to check in this function is whether the given
address can be the result of the memory-to-shadow mapping for some
memory address, including userspace addresses, non-canonical
addresses, etc. So essentially we need to check whether the given
address belongs to the area that is the result of the memory-to-shadow
mapping applied to the whole address space, not only to proper kernel
addresses.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfySpeRy0FCFidLdUUeqp97eBdjAqQyYPpz1WxYwcsW9A%40mail.gmail.com.
