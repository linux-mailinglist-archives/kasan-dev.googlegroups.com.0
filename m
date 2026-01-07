Return-Path: <kasan-dev+bncBDCPL7WX3MKBB3UD7PFAMGQEX442QJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x1237.google.com (mail-dl1-x1237.google.com [IPv6:2607:f8b0:4864:20::1237])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A095D0002C
	for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 21:28:33 +0100 (CET)
Received: by mail-dl1-x1237.google.com with SMTP id a92af1059eb24-121adbf76c3sf2438152c88.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 12:28:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767817711; cv=pass;
        d=google.com; s=arc-20240605;
        b=lYGMxJt30kgbLdxM4Ke4I0ikfA8zyQhzYho1GmUREOhkq8x5itmhaPP/+IsOWJrXRA
         wzdvPVZb3PLLDyzPD4Qqs3WCnoqSGPNdFVtrvAzFJOLDV0aHoEECUvIbBvF1qK2ZfNjq
         orZ998pDqBpf5gZvB6wjNZDW+VOX6hQ50gHBcha29+kJsIgZAVU3ZFEycbtnjlL5WJUX
         cUwWj0zq1ZcaBcTyNdwgPkfRHaw/8lqfRgCWnspuI46BXu8MLAmoLc0Sg9eJWT3CPN99
         2ecyHtyzbHhCohTF/8GGkTRhjreQ4BkBgqA4TrcIBpHPbn0Wm26/sdMcYnWUtgO8cPSk
         2YEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=PcwGPwvJKhvpjZfdGErT1W3Ca9iR3w5xC0WweRsqM2w=;
        fh=ZqGVoH6+PSyW83jC7O4Pdu/eFLaLdFTvnXEngYz2hGk=;
        b=bOEUEuGpg6znbeHsdQ6sRLPBRtMGs7OuhTCb3zMEtiTCB19npv104W4wrQwkMkZkoR
         xyU4gviXF24Dy1qzgYkPmFACFuJkLSdoAwgUcOHgaGjJAmHwfyn1ciCrwkmBKwrOAWXp
         tsL7M7LOr9YD3/dzucblrpwZ0AEuUHLU0mJ280pFtkYu7qEzgBrtfAbfTzqUSwKGYhw2
         nKr3XArduleiRbFs9eK05lBsrEDcMApVCPkBhL2wunpQySxhb49rtfoj6ZcmbLeIV5Sd
         5JDXKU+4G8bvtT9tivx3ppY2a0/frst9QhdkBW66Br3NzbYV22uCTBgUgnsxaHb1w/bS
         Mo3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=E5IRqCmm;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767817711; x=1768422511; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=PcwGPwvJKhvpjZfdGErT1W3Ca9iR3w5xC0WweRsqM2w=;
        b=I5mZjjKUfzC6ATJravfoiEx87wy+189Bi5XWxLNyTN3xlej23KJL83kgcmhYQFR5Dm
         uaFOcd3vCc4jecbNVFTd5vvzKdP3QKq8iwpHRK4CQqLIif8cplkSMZNd7ZZCsmpvvm9h
         TuO4VPjesWd0zQfps4iMGWlz6vozuLcn0xPsQPAPaWZ7SyeWJ4/qPHba/u9a996g/62H
         X5yhrChSiiLYCWApMJwJp2yKroaLZ2DggV/OswgucNGlXwD/jWA+/RvXO3OpeHXsVQAv
         q9J84wlzGSg6JH+2ITqjzI8lg/xuaJnIG8ArilKsICgxiPtecnXff3OOT8nkD5h9CV38
         XATQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767817711; x=1768422511;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=PcwGPwvJKhvpjZfdGErT1W3Ca9iR3w5xC0WweRsqM2w=;
        b=j4f/7rI1QFzLa3sC5Jr8hHHn3w54WM3uLQ2OFmw4W0EGEVwpsobXRnvvXLWeZlmSTR
         fFMDkq0ahCVAVUbDxygtvk5tO2/7r25Od7S2YyU3Eyyhm7n69L6GTUycOjiAMXRJo7Gw
         0KNPWf/8gBB4Imj6R8dE1BLjs2f35Ohkk0L9QCfdwaecj9ArlDYyVnCqgOxFTfRS5Vv1
         f8Q9OmrESPrbUVm+YpjJVijwnTuZSl9Qm3kJt4OWkScnbm5NKMrsDsBJXEOS3Ww++efr
         txabgVXdEy3DRpHSZPsgFPxVfoVS0goXAHYNZju08TcYtLibmE52Y/Kbb/2rmxpb+bzI
         LKkA==
X-Forwarded-Encrypted: i=2; AJvYcCUE9ZT0zEn/6g0y4Y+zIqts7StJptZjnu3y4Xlh74Gxm7lIGXLBPMpdAsrBVeppuTEJw5TK9Q==@lfdr.de
X-Gm-Message-State: AOJu0YxbokOrz9gy3G4CWy3vmlRIII1jdy1WH9Q4sWXRcqbX8CYf0VAg
	iEC+X1FsGm4bMNyE2U9BNwLhJPaymROQFJMg6DS/G2MBCF3ml0xNtvAg
X-Google-Smtp-Source: AGHT+IGPVEIF0enfQYTCqNR+OtmvxAX8Sr0QtGGJkQ9lq3t0F0MVPmKyaoK26r/AH6BLyA9yNCtppw==
X-Received: by 2002:a05:7022:113:b0:119:e569:f626 with SMTP id a92af1059eb24-121f8b7a9f2mr3166095c88.31.1767817711367;
        Wed, 07 Jan 2026 12:28:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYcnvhXX1iVsiGYIGmMWESsztLy66PlLCgKB1PymWbwUA=="
Received: by 2002:a05:7022:428e:b0:11b:50a:6266 with SMTP id
 a92af1059eb24-121f138aa43ls1471290c88.2.-pod-prod-06-us; Wed, 07 Jan 2026
 12:28:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUDq0AgU0x9QqfyBN00pu+p95jx5AHQjd4NIllTqJWqqtyZYGyU3AGxX18YiJFWz+jv/8251mUHEP0=@googlegroups.com
X-Received: by 2002:a05:7022:1601:b0:119:e569:f61b with SMTP id a92af1059eb24-121f8b152c8mr2642899c88.20.1767817709889;
        Wed, 07 Jan 2026 12:28:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767817709; cv=none;
        d=google.com; s=arc-20240605;
        b=D2RLmeZIw3VK1C0m55FGzcYucz/5UnGU58koayoeta3w4Am19SS1QwcaLo/mLOuuo8
         wG0WqI5liDKQ1R6Qzcat7IKaovgFjLUkQqAv7h9bUCiLpwWc0rBQ1/FTE5xL6sMlGS6M
         p+cT2Z0dHPZtCI9So3l5y3riZ2+86YlPRGwzVgTkty/tVQMNTwDlpSoQZB0xVjyrZ9/6
         zqcHr2e6dyH6kajXeCzsQ88aW1vSb6zWJ+SjcSUHJLD6K5JVL8TOYBO80kSYrRH/0/yF
         UBdNNZpKklCXm0WSpZaJAjf8N5YFjyGytNorPvnOYuQLF0XncWB3QTP6u4QLi0buBnlR
         2fQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=E1HLKRJudO06EHz5daCWcSK6ZEDuvgp2UnlllgnfcWY=;
        fh=sETtWYGdAxXUiX3f8J2o1UfVqN6amYNJ4vtD3jS4O/E=;
        b=YCFFM3ILM41U4WWm3KxHuvMqaGqLp23svA5ut+qxHjW5wqd1T7Zmt1eI5vsiABgJOc
         MuQBUsOerIalNL9jZrCRpktr77xibPfWz8sUnihWnyk9H9SVUy0brQFn/kuC5x3D8vdg
         29YWGBVCOZ7QiSWHmr4R67MgnjlcYNAWKfC1brKKOwxM9G2LTs4zj03TrBP8N8i/EkrS
         VRH+Nvf5i8DDI6AHQ8ZYm7IsrRTi1ixhYuEzh9veuc8B+O/0K1kzSBBBQ1EZLXWOrvwz
         /vJUHSKG2ONaUj8TjlxbtzrfhEd8l1SFVeTCSxacHlYsSUcoMkfi5QuqClXDx5YUDSvq
         Af3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=E5IRqCmm;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-121f28b7f96si176201c88.0.2026.01.07.12.28.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Jan 2026 12:28:29 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 88AE56000A;
	Wed,  7 Jan 2026 20:28:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3867EC4CEF1;
	Wed,  7 Jan 2026 20:28:28 +0000 (UTC)
Date: Wed, 7 Jan 2026 12:28:27 -0800
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Maciej =?utf-8?Q?=C5=BBenczykowski?= <maze@google.com>
Cc: Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
	joonki.min@samsung-slsi.corp-partner.google.com,
	Andrew Morton <akpm@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Danilo Krummrich <dakr@kernel.org>, jiayuan.chen@linux.dev,
	syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com,
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
	kasan-dev@googlegroups.com,
	Kernel hackers <linux-kernel@vger.kernel.org>, linux-mm@kvack.org
Subject: Re: KASAN vs realloc
Message-ID: <202601071226.8DF7C63@keescook>
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=E5IRqCmm;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Tue, Jan 06, 2026 at 01:42:45PM +0100, Maciej =C5=BBenczykowski wrote:
> We've got internal reports (b/467571011 - from CC'ed Samsung
> developer) that kasan realloc is broken for sizes that are not a
> multiple of the granule.  This appears to be triggered during Android
> bootup by some ebpf program loading operations (a struct is 88 bytes
> in size, which is a multiple of 8, but not 16, which is the granule
> size).
>=20
> (this is on 6.18 with
> https://lore.kernel.org/all/38dece0a4074c43e48150d1e242f8242c73bf1a5.1764=
874575.git.m.wieczorretman@pm.me/
> already included)
>=20
> joonki.min@samsung-slsi.corp-partner.google.com summarized it as
> "When newly requested size is not bigger than allocated size and old
> size was not 16 byte aligned, it failed to unpoison extended area."
>=20
> and *very* rough comment:
>=20
> Right. "size - old_size" is not guaranteed 16-byte alignment in this case=
.
>=20
> I think we may unpoison 16-byte alignment size, but it allowed more
> than requested :(
>=20
> I'm not sure that's right approach.
>=20
> if (size <=3D alloced_size) {
> - kasan_unpoison_vmalloc(p + old_size, size - old_size,
> +               kasan_unpoison_vmalloc(p + old_size, round_up(size -
> old_size, KASAN_GRANULE_SIZE),
>       KASAN_VMALLOC_PROT_NORMAL |
>       KASAN_VMALLOC_VM_ALLOC |
>       KASAN_VMALLOC_KEEP_TAG);
> /*
> * No need to zero memory here, as unused memory will have
> * already been zeroed at initial allocation time or during
> * realloc shrink time.
> */
> - vm->requested_size =3D size;
> +               vm->requested_size =3D round_up(size, KASAN_GRANULE_SIZE)=
;
>=20
> my personal guess is that
>=20
> But just above the code you quoted in mm/vmalloc.c I see:
>         if (size <=3D old_size) {
> ...
>                 kasan_poison_vmalloc(p + size, old_size - size);
>=20
> is also likely wrong?? Considering:
>=20
> mm/kasan/shadow.c
>=20
> void __kasan_poison_vmalloc(const void *start, unsigned long size)
> {
>         if (!is_vmalloc_or_module_addr(start))
>                 return;
>=20
>         size =3D round_up(size, KASAN_GRANULE_SIZE);
>         kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
> }
>=20
> This doesn't look right - if start isn't a multiple of the granule.

I don't think we can ever have the start not be a granule multiple, can
we?

I'm not sure how any of this is supposed to be handled by KASAN, though.
It does seem like a round_up() is missing, though?

-Kees

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02601071226.8DF7C63%40keescook.
