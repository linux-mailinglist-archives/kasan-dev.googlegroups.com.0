Return-Path: <kasan-dev+bncBC7M7IOXQAGRBFNJ7PFAMGQEF7MOPEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 132B6D0038E
	for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 22:48:08 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-c52ab75d57csf400522a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 13:48:07 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1767822486; cv=pass;
        d=google.com; s=arc-20240605;
        b=gWldaD99tjJiEZtAzNxnA9waMUQ0+v987Rys0oVcjcCM4Rn0Dmp58ui8Q/xQPGTlQ1
         j6Ym5VvwlBj2QfeEr1zC0wudMxj2O0zr7LYaSGN6Myaodjnt3rj3NvH3DvdAqRMKjXim
         ziVFcZdFyEMDLlraWXdPkV1sUt6cF7zm273t7djGRXSZZdiry3ruXUB6GlgYY1cVtJrq
         GpmeHrX0v6F4FSIT2xQdwRtIH8DE6fL6+cdzjmb03fxxCr+mJhC9os5c6hlhNiIjsSbO
         LWPywvm73x5wk8sFcfMySa/2Hf7T8Zp4SmhTNzHqyLo+AU+pT/WJCpCDLGO10nL0keWr
         SiPQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bQk+quZqEmkw3oHWadgBfhjLeHnML9T04dM4tOWvclo=;
        fh=kVupOzLmXETZjo3iOyWo3cZFcFKJshoxBkglk8oFr6A=;
        b=DJhVxvq0A1aIJITqdiZiVgpPbO6Q02YdHqIjEN3dSbeU7/n4OYeMw0x2RRlBRfgUKP
         0CFUa9EpSDnxI64QhtQV7OQ7SFNx5EzswKKK5aqLIKoqa8cx+dxekc8hTe2JcXWDbLIs
         alZH6P2xKLezn4v8H5ptlu9HKleM8iyr3uaXR4qd1cJzVVcpKbcbGTzIpCjokrbhFFOy
         RTRz0/EHv/d6KORmWkp0vJm2k6ObU+tjOuf3Uxk/U0xZaJkuVBxsMAZAf427hnBpbpn2
         qLwJMi4hleou3Ymd6hxg/9hAwt/+MeySbzWgSQgUChwbB7ShFtHmshxvjr/2uF0seyyl
         JlPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v9FSfKkt;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767822486; x=1768427286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bQk+quZqEmkw3oHWadgBfhjLeHnML9T04dM4tOWvclo=;
        b=BzQ2WVFdGCYXXlTV9JGxq8nXlQivrsHeuU+wVbaTH/06a2yHgkzQfyEKMgIBu2YDif
         34sDrwLP4fC3lAAP+YcOK0oJ737P8rpzyXAz6MWX7YpV0wkxkzpa3yIj37iewgrPPBDZ
         j7Sz4m5cMBJln2UI3iPKXJzpe6YHBY21/oR6Oa54d5wttuaPP+Qy4wikRh2KhsamZCme
         +AT1eo5GwekBNapnIVf58Z7PGnJfS2/FUQy/eP1BWextMyWrKinpHSm0JO+ANjBzUrG4
         qVARJyiGBjFnx9tkHF7sWcVtdte4qojomWaV4DcYhzdBulcwKUF0z+89ZbOYDByN2Dkd
         dfEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767822486; x=1768427286;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=bQk+quZqEmkw3oHWadgBfhjLeHnML9T04dM4tOWvclo=;
        b=X2Udf/mwc2ZSc8iRIL5+QemGt0fo0eoVwELYujXsUQ4cQ//OpCYuSbHwHOPC059pe5
         KbQ4IBBK29OLjXBRROy/B/mU7DAUHmJbiOOwHAq/a4JEnHwjDg62/tX/vZ5ul6qrDw7C
         PFVUyhHyoexW0vww36ReWlw24C2wDNQ2ZQN3J+BXlq89aV0zkLe5VqnCRjo41pV0LjwU
         +ZRViXKuqCNyPnrPssjYRMBmYjy4cU2ukmdbmnKkV4RbTDqe420CPuH7mQV3EnpHY8KC
         ZOOlXQWrHoPkTzzkl9oDnGiBuuKcQamLjRzDfdlcW+S5EP6anjhAnVYgAlNzpbyms4ZX
         PtIQ==
X-Forwarded-Encrypted: i=3; AJvYcCWHmhD5m6HolOv/oJjlRn47j9AYk68Dqkrog5psPEkl9LNbPWQHt2H7BzTpk4MlnN/qHXIs8A==@lfdr.de
X-Gm-Message-State: AOJu0YyjkAKjMhgeYaewmSybpjc+sGp870uBxfrPWE7Qe/nsQn8MuYHB
	/7qV+Wa8MXWZ2Sf634oj24wYQT+HB6hCa0uvh978W5TqL4zGO7JphrkB
X-Google-Smtp-Source: AGHT+IH58GZMFiRlZKIqM2P0nrqCZvEAckrYw9LV0huRXRHjw4M2xN+ryWX/i3AeIzxCqKjn2pi29w==
X-Received: by 2002:a05:6a20:6a1b:b0:366:14b2:30f with SMTP id adf61e73a8af0-3898f9cd56emr3406578637.66.1767822485861;
        Wed, 07 Jan 2026 13:48:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa8C0l9AQYG/fnQgtFNHAOkRqaGSUARWoRUGygrmT8H1A=="
Received: by 2002:a17:902:e84a:b0:297:e6aa:c4bf with SMTP id
 d9443c01a7336-2a3e29258c6ls28015025ad.0.-pod-prod-07-us; Wed, 07 Jan 2026
 13:48:04 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUXDSRnHYpUjPHadLiW+TmvBv3UKQ/Uvx3245AE/AFqjgvlo/SGl1YM0EVt9YJkzmwtbs6M0f1u85A=@googlegroups.com
X-Received: by 2002:a17:902:db05:b0:2a0:835b:d17f with SMTP id d9443c01a7336-2a3ee4ab681mr33369235ad.54.1767822484257;
        Wed, 07 Jan 2026 13:48:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767822484; cv=pass;
        d=google.com; s=arc-20240605;
        b=egYt/OP27DbXyAEYtYkAbLgA/T/dvsAGSKFFBfM8oKp2r9yp36b+n4VLnFjhuihWYT
         Avg/JuZIM56rnUta6XpSUSp0923cRgC3IzJIKztCrZ/o4LIMgb1bUAgaO0ynU2gICFi7
         Ub2Y1sUVGAUdpiIZ3ttSbFXRdh+XJbTX/9adv5XmNAXgPYlC63zONqG00KuEnS0Xyr4E
         2YSr0ygXHjJCjGbUvQeuJEteKW3mGXAZJzev/ppR3RiKAIft8FIqD8R4MAemV7i6G2id
         jCqRCQDKoB2FmTDQAlq8chlv3AfkZ2KwLLVbU7zuz4JUOvZfeL+5m8kI1GS52u3ToFWI
         RYTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2Xuw3GyJneoJXhtItWJQfrXCpjg3jylhpc8+LuV20Gk=;
        fh=9N8mNus5WdOthEBybLoKJBA0bys7xkc3vJ39bUeX9PE=;
        b=AaFXjVb81qlR6kO9D2JI7bPerOZxolnUxkAokqj+NcOfB5m1ZRz0wLTUMVkavKJdsA
         Ldj3mDT9f47TLdFRwDgwhkEAdKzr1BU1RszddGHNY4sR2tUPUG9RcWjQSKqf4saPefJ0
         9YFj7/d0yYqwlkoNUfzY75N9MylHzNXocSoKRxS7liDqjo4emTHUaBlEbOcFFaPESs2g
         a4m6sWUeoydctBMmn9Tx978GT4eRnk2ATw1V1tPnRaXTCsIb4WIenKNZ2EKqp6ia5GqE
         kj8iVFaomJceb0LguHcVAFgxX7evUMH0UPYhfc0KEtlNqZqXV1fsRYlFtiMMOCqk3oTT
         2nCA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v9FSfKkt;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a3e469c7cbsi1377625ad.2.2026.01.07.13.48.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Jan 2026 13:48:04 -0800 (PST)
Received-SPF: pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id d75a77b69052e-4ffbaaafac4so411331cf.0
        for <kasan-dev@googlegroups.com>; Wed, 07 Jan 2026 13:48:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767822483; cv=none;
        d=google.com; s=arc-20240605;
        b=O5hzYba7nNo+795koXEpW3NzyVLzc2EASVwpUTUvBAORKetaDbeqLJ+MpsuMx5KbiZ
         /et3l+w67m7aQOIZjoWRW+ufBIdD38JgAbB052t84gtKTNxcWPm0PL/CWmTrzkKvlCfR
         /cINKHTjxYPoezcQ16GJmg2dvm6IQ7113wFAWFN8jB2n0FXs/4DyhNtQMBTdqVJhl3Ye
         oXA+xcFO5P20lUauDeuEYia4Ecq7Gau/BUAZosOPa/jUrJj7nOYPkQeel0BkrHXv+F+n
         DM505vIl0vI0XYinObX4h2BsurL5rXCVDl/0+1B23go5B/19zTjYiB6/NJyRSUf7r1mb
         3QKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2Xuw3GyJneoJXhtItWJQfrXCpjg3jylhpc8+LuV20Gk=;
        fh=9N8mNus5WdOthEBybLoKJBA0bys7xkc3vJ39bUeX9PE=;
        b=STilXF+AMOl2w+STgr9C2NZjyTMkwZQpd8ooYzzSNtdtGyTSFW2DKoJNESDPmZzPka
         alnu8BOuPIsNHLmpLQtWRmLQd0HI8VKKvbS0T70lFv7cYTYqpchvjzloAbSu9zFHkT5p
         +VbRTvhtYGaOQEJUVXsUw5ZlXiYukBa6RQRs+En6sFjN8xGy5H4f+d8Gw573B0u34lPH
         OwCS51gFbCJEfjWOPvcLP01pMfzMCGsVmhQaFo2L1S72Q5D/Raq4RIplQecDI7wyeyPe
         VZQ/YdjM9eMUOe336pDlIFI3hslLGfzAl5IOO+6psNgZxqFMqKDf1jStDyHOIg29Pmeq
         RTGw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCX4xEZThMT9cW8G6kdZoEZRWN5SYd2hj7N1oQqsVuu6c8Z861hW6pIgDBBk5Ka9UTrBlWG+pExls+A=@googlegroups.com
X-Gm-Gg: AY/fxX5VdvNgsLTN3jAEGyIwDKMyKDHga1YXVmwsk4aElCTsmbdvrAohPYPZTaNirQL
	q30G/JAqZbXh/kItwsdfBL4U6riymtTVCrlwE9W/ryYHT/B2fm1pJVQvn+YSsPAuGDsBllgAwae
	WS+R/SItGO5WUvhvafyOrODgT58G6FoBDJAJrd+ClmmZw8vbDcwBd3m80U35M7b3tgO8bVpgBNx
	4CbCIVmzyqpZKZ6gHXjt78/eBCQNb5bsI7nCqDf2Q01+f3ZSwozk6X6WAPxZMflxA9Y0fGE64Nt
	YUIXj5CoWrHpKhi0+ct+JytRGXR61lftKSTEaBs=
X-Received: by 2002:a05:622a:146:b0:4e8:aa24:80ec with SMTP id
 d75a77b69052e-4ffc0974a7emr382701cf.14.1767822483032; Wed, 07 Jan 2026
 13:48:03 -0800 (PST)
MIME-Version: 1.0
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <202601071226.8DF7C63@keescook> <btracv3snpi6l4b5upqvag6qz3j4d2k7l7qgzj665ft5m7bn22@m3y73eir2tnt>
In-Reply-To: <btracv3snpi6l4b5upqvag6qz3j4d2k7l7qgzj665ft5m7bn22@m3y73eir2tnt>
From: =?UTF-8?Q?=27Maciej_=C5=BBenczykowski=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Date: Wed, 7 Jan 2026 22:47:50 +0100
X-Gm-Features: AQt7F2oLlltuoY9YvVgls7adU_ueUzLWJwptnTTXOpaTyMJmGfkWuXu7CND03a0
Message-ID: <CANP3RGfLXptZp6widUEyvVzicAB=dwcSx3k7MLtQozhO0NuxZw@mail.gmail.com>
Subject: Re: KASAN vs realloc
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Kees Cook <kees@kernel.org>, joonki.min@samsung-slsi.corp-partner.google.com, 
	Andrew Morton <akpm@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, Danilo Krummrich <dakr@kernel.org>, jiayuan.chen@linux.dev, 
	syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	Kernel hackers <linux-kernel@vger.kernel.org>, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: maze@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=v9FSfKkt;       arc=pass
 (i=1);       spf=pass (google.com: domain of maze@google.com designates
 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
Reply-To: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
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

On Wed, Jan 7, 2026 at 9:47=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> On 2026-01-07 at 12:28:27 -0800, Kees Cook wrote:
> >On Tue, Jan 06, 2026 at 01:42:45PM +0100, Maciej =C5=BBenczykowski wrote=
:
> >> We've got internal reports (b/467571011 - from CC'ed Samsung
> >> developer) that kasan realloc is broken for sizes that are not a
> >> multiple of the granule.  This appears to be triggered during Android
> >> bootup by some ebpf program loading operations (a struct is 88 bytes
> >> in size, which is a multiple of 8, but not 16, which is the granule
> >> size).
> >>
> >> (this is on 6.18 with
> >> https://lore.kernel.org/all/38dece0a4074c43e48150d1e242f8242c73bf1a5.1=
764874575.git.m.wieczorretman@pm.me/
> >> already included)
> >>
> >> joonki.min@samsung-slsi.corp-partner.google.com summarized it as
> >> "When newly requested size is not bigger than allocated size and old
> >> size was not 16 byte aligned, it failed to unpoison extended area."
> >>
> >> and *very* rough comment:
> >>
> >> Right. "size - old_size" is not guaranteed 16-byte alignment in this c=
ase.
> >>
> >> I think we may unpoison 16-byte alignment size, but it allowed more
> >> than requested :(
> >>
> >> I'm not sure that's right approach.
> >>
> >> if (size <=3D alloced_size) {
> >> - kasan_unpoison_vmalloc(p + old_size, size - old_size,
> >> +               kasan_unpoison_vmalloc(p + old_size, round_up(size -
> >> old_size, KASAN_GRANULE_SIZE),
> >>       KASAN_VMALLOC_PROT_NORMAL |
> >>       KASAN_VMALLOC_VM_ALLOC |
> >>       KASAN_VMALLOC_KEEP_TAG);
> >> /*
> >> * No need to zero memory here, as unused memory will have
> >> * already been zeroed at initial allocation time or during
> >> * realloc shrink time.
> >> */
> >> - vm->requested_size =3D size;
> >> +               vm->requested_size =3D round_up(size, KASAN_GRANULE_SI=
ZE);
> >>
> >> my personal guess is that
> >>
> >> But just above the code you quoted in mm/vmalloc.c I see:
> >>         if (size <=3D old_size) {
> >> ...
> >>                 kasan_poison_vmalloc(p + size, old_size - size);

I assume p is presumably 16-byte aligned, but size (ie. new size) /
old_size can presumably be odd.

This means the first argument passed to kasan_poison_vmalloc() is
potentially utterly unaligned.

> >> is also likely wrong?? Considering:
> >>
> >> mm/kasan/shadow.c
> >>
> >> void __kasan_poison_vmalloc(const void *start, unsigned long size)
> >> {
> >>         if (!is_vmalloc_or_module_addr(start))
> >>                 return;
> >>
> >>         size =3D round_up(size, KASAN_GRANULE_SIZE);
> >>         kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
> >> }
> >>
> >> This doesn't look right - if start isn't a multiple of the granule.
> >
> >I don't think we can ever have the start not be a granule multiple, can
> >we?

See above for why I think we can...
I fully admit though I have no idea how this works, KASAN is not
something I really work with.

> >I'm not sure how any of this is supposed to be handled by KASAN, though.
> >It does seem like a round_up() is missing, though?

perhaps add a:
 BUG_ON(start & 15)
 BUG_ON(start & (GRANULE_SIZE-1))

if you think it shouldn't trigger?

and/or comments/documentation about the expected alignment of the
pointers and sizes if it cannot be arbitrary?

> I assume the error happens in hw-tags mode? And this used to work because
> KASAN_VMALLOC_VM_ALLOC was missing and kasan_unpoison_vmalloc() used to d=
o an
> early return, while now it's actually doing the unpoisoning here?

I was under the impression this was triggering with software tags.
However, reproduction on a pixel 6 done by another Google engineer did
indeed fail.
It is failing on some Samsung device, but not sure what that is using...
Maybe a Pixel 8+ would use MTE???
So perhaps it is only hw tags???  Sorry, no idea.
I'm not sure, this is way way lower than I've wandered in the past
years, lately I mostly write userspace & ebpf code...

Would a stack trace help?

[   22.280856][  T762]
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   22.280866][  T762] BUG: KASAN: invalid-access in
bpf_patch_insn_data+0x25c/0x378
[   22.280880][  T762] Write of size 27896 at addr 43ffffc08baf14d0 by
task netbpfload/762
[   22.280888][  T762] Pointer tag: [43], memory tag: [54]
[   22.280893][  T762]
[   22.280900][  T762] CPU: 9 UID: 0 PID: 762 Comm: netbpfload
Tainted: G           OE       6.18.0-android17-0-gef2f661f7812-4k #1
PREEMPT  5f8baed9473d1315a96dec60171cddf4b0b35487
[   22.280907][  T762] Tainted: [O]=3DOOT_MODULE, [E]=3DUNSIGNED_MODULE
[   22.280909][  T762] Hardware name: Samsung xxxxxxxxx
[   22.280912][  T762] Call trace:
[   22.280914][  T762]  show_stack+0x18/0x28 (C)
[   22.280922][  T762]  __dump_stack+0x28/0x3c
[   22.280930][  T762]  dump_stack_lvl+0x7c/0xa8
[   22.280934][  T762]  print_address_description+0x7c/0x20c
[   22.280941][  T762]  print_report+0x70/0x8c
[   22.280945][  T762]  kasan_report+0xb4/0x114
[   22.280952][  T762]  kasan_check_range+0x94/0xa0
[   22.280956][  T762]  __asan_memmove+0x54/0x88
[   22.280960][  T762]  bpf_patch_insn_data+0x25c/0x378
[   22.280965][  T762]  bpf_check+0x25a4/0x8ef0
[   22.280971][  T762]  bpf_prog_load+0x8dc/0x990
[   22.280976][  T762]  __sys_bpf+0x340/0x524
[   22.280980][  T762]  __arm64_sys_bpf+0x48/0x64
[   22.280984][  T762]  invoke_syscall+0x6c/0x13c
[   22.280990][  T762]  el0_svc_common+0xf8/0x138
[   22.280994][  T762]  do_el0_svc+0x30/0x40
[   22.280999][  T762]  el0_svc+0x38/0x90
[   22.281007][  T762]  el0t_64_sync_handler+0x68/0xdc
[   22.281012][  T762]  el0t_64_sync+0x1b8/0x1bc
[   22.281015][  T762]
[   22.281063][  T762] The buggy address belongs to a 8-page vmalloc
region starting at 0x43ffffc08baf1000 allocated at
bpf_patch_insn_data+0xb0/0x378
[   22.281088][  T762] The buggy address belongs to the physical page:
[   22.281093][  T762] page: refcount:1 mapcount:0
mapping:0000000000000000 index:0x0 pfn:0x8ce792
[   22.281099][  T762] memcg:f0ffff88354e7e42
[   22.281104][  T762] flags: 0x4300000000000000(zone=3D1|kasantag=3D0xc)
[   22.281113][  T762] raw: 4300000000000000 0000000000000000
dead000000000122 0000000000000000
[   22.281119][  T762] raw: 0000000000000000 0000000000000000
00000001ffffffff f0ffff88354e7e42
[   22.281125][  T762] page dumped because: kasan: bad access detected
[   22.281129][  T762]
[   22.281134][  T762] Memory state around the buggy address:
[   22.281139][  T762]  ffffffc08baf7f00: 43 43 43 43 43 43 43 43 43
43 43 43 43 43 43 43
[   22.281144][  T762]  ffffffc08baf8000: 43 43 43 43 43 43 43 43 43
43 43 43 43 43 43 43
[   22.281150][  T762] >ffffffc08baf8100: 43 43 43 43 43 43 43 54 54
54 54 54 54 fe fe fe
[   22.281155][  T762]                                         ^
[   22.281160][  T762]  ffffffc08baf8200: fe fe fe fe fe fe fe fe fe
fe fe fe fe fe fe fe
[   22.281165][  T762]  ffffffc08baf8300: fe fe fe fe fe fe fe fe fe
fe fe fe fe fe fe fe
[   22.281170][  T762]
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   22.281199][  T762] Kernel panic - not syncing: KASAN: panic_on_warn set=
 ...

> If that's the case, I agree, the round up seems to be missing; I can add =
it and
> send a patch later.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANP3RGfLXptZp6widUEyvVzicAB%3DdwcSx3k7MLtQozhO0NuxZw%40mail.gmail.com.
