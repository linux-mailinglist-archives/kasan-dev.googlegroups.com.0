Return-Path: <kasan-dev+bncBAABB6MM7PFAMGQEALS7DGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B1C4D000D1
	for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 21:47:55 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-656b7cf5c66sf5063928eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 12:47:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767818874; cv=pass;
        d=google.com; s=arc-20240605;
        b=lFOrwsDp/uRh7WWlmNIVPHWAfdT/jZ//Ycz3Lz6i9MaodJKkPP9qJxZOsUzyK3VnUf
         XK83kAJ2pCl6o0J9OoyH/fv+nM3Jmw5WVkJPX8w33TQQl0mP/UYd3MWT5bCxyVuiWmM1
         yQh0lQPaQc2g+ozsHT+irZc6FlC9iJjJI+YJowylavQIN1KFyUOdF1vRHd6IbyYrhES7
         rZc4g2DGq2UY0B/FDalt1CrIByFyrQcQo8au0zsY4STUPM957PEnnxiZQs49yRYln2VS
         UeBligSkz6KdNCAK/qM2Qkc5MGVuLJqU54wl8rxC08DCZR61MzChtgBZFYlwgOozOvRo
         xXWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=7ucmeglCLqBTusdOH82OMJs6XFMnBiovundgwmYxF/k=;
        fh=2ImOsuW6mO+lCv1VXtvspBKA5UXPCtspE3o5lAJW7ao=;
        b=Y0ECWkGwIm56iAd0qaXRUbnA+Nzs3mSaQQIrOQqTaI5BvoT4jgk8lLc/aLbK4z3LzL
         yG5vNfvnZ90rFxuK1uIaGPUWA4F6yrcnsaioTKDupeF4KCcNUOhZLfHkY+OhsIvXR/Bl
         Cz8BEFNhdYeLpcqiN1pX3agRTdqWK8pG451lzl4jsNrAVbi0tKlVtHAfXvMMkR2sgg4U
         FntMK4tE8lrhIzoQR9QXZi8KMDx5yhoUHqw/6V+Gdy0DbY6lLmrm993DUGzuOxvXL1i/
         pYUPTwBSa1ch9Kc6ZHcNEAFUvhcquEkwu27tWPrF3Crp0EKHJukBsKqw+4t+Yu0CYhor
         v6iQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=HrnCPams;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767818874; x=1768423674; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=7ucmeglCLqBTusdOH82OMJs6XFMnBiovundgwmYxF/k=;
        b=LJiCZKhwiWukDHMhjxuXZ0pM0lZkAnp41vxU3CpSC6rbmqxnu3z/VIP10h24MXCHfh
         ibSYWjF0LM3uIrZdZkr78qcxFeOrGEfWwKOTfMtwjVTGyXybLPcFUYQcRPJrZJhIL9nQ
         uNCL/m7FPihPW4zev1hY9waZyoCyIYP7+d7d6d0h9lYWl3ifVS2Oi8KJyFYJ3RIBW7Xb
         HScI1/DAFqmQw2yvOB+1RpwAdOQlHRS7wlXcNPXsQTmp1DJ4P3gXo+ZNZaX7snKg80lH
         kTZrPfAcQ/z5xKgSbd1lhSwHNWIpWEF5SNJrcFt4PrEYXP7voLVVPisPbAZSxDqdtmxu
         UMDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767818874; x=1768423674;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=7ucmeglCLqBTusdOH82OMJs6XFMnBiovundgwmYxF/k=;
        b=wxp+apuLHgcNZJcx08in8CgZvy/KSEmiuZ8gAryg+dZ6I8kvhRl4ptexKksrhdn38K
         ahmC21EfEQRTb+85MIw6etRSfyjgxBzdnJ70lH92NPzr78RzCbpRctht+UZl2na1CfXg
         /kKv7rAAVsmQH3yiPd436qJkfKqtZlFg5EgRnQOWMRy9dxyIP3yl3zWWfboXtn4FKvpy
         9WxiwlcoxB1hYgF4NwMYH+NGxW8rgf0LAlotvtOskdBfMczkxcKhDVT4gUr8uAla/nQz
         0rTpion5M7lLcENYwYfyAVVG0zFJqyyFvIdq/q50d2qGc1frdmtvSSut3W67JHOSn45S
         fSIA==
X-Forwarded-Encrypted: i=2; AJvYcCWpnXig2+U9n0TLDUWOx8+NHQY9wf5C+3As+z4LABM2zeRJtsNid8mpccSgiIN3mI5llUsobA==@lfdr.de
X-Gm-Message-State: AOJu0YwdQCxp8/aB3CsfCZjmXs0uRxqa+0jzctHum3tNxrm8uLzyZP5p
	byE9ID+ayYBgZLEDdlEPT1GojySBiaYMnR19RXVXPJTMiiAdPB0LUSfR
X-Google-Smtp-Source: AGHT+IGHeD2sREr0BoF6fomhZbRdJ2e2k4FT1BvPtMsj9vL23jPXTqg1Ypg1TJBfvFW3XD9CwAr3kw==
X-Received: by 2002:a05:6820:1c97:b0:65c:f363:fe17 with SMTP id 006d021491bc7-65f550828bfmr1637513eaf.45.1767818873940;
        Wed, 07 Jan 2026 12:47:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbG/Ph3fX+AosEqsyh6PIUsX0Yyidb6nX9/tkszsMu6xw=="
Received: by 2002:a4a:b408:0:b0:65d:414:bdcc with SMTP id 006d021491bc7-65f474393c1ls1387768eaf.2.-pod-prod-07-us;
 Wed, 07 Jan 2026 12:47:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUDy3GopFMoUDJnQjT03UkBWj+Y+2/9vjY8uD+AzKt7OX3mwAS74dTBb0tNs4cSRQzeu8dlkHvoGkY=@googlegroups.com
X-Received: by 2002:a05:6820:622:b0:65d:1c:f39e with SMTP id 006d021491bc7-65f550ad71cmr1836862eaf.70.1767818873147;
        Wed, 07 Jan 2026 12:47:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767818873; cv=none;
        d=google.com; s=arc-20240605;
        b=KQ3xkVPEGiS6rdI9bG/ROvVjvBW9iUAnmN2H15qS6S1MFG8puZRcm0BEWtRZtGnz/X
         8ckUg00KE86vpWVdUr8HkTYeaQtHrLmvmEYxiP7118i3qSNJ14vLsScF4a2wYnqHJsC4
         U9tdO+H5DTozF0yf30upEv0xToG3EgsCKD8lmnGD0acgYEpn5TwesDAX8ruY3BflkkUE
         /QKKbpkAcm6S7V0+11ov6qBnzsdh6gGeCLDZtkkzBwlgoEnquOlu09YYqw0aKDQKnUzv
         OQYK5O6y2hkf6+2KAER2a4zFou6TTU1LapAyruBGMSKY9nKvtNg23RQIV15QQaitGSXg
         SgGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=eso9ElNo5qBp7Bizk6jVYXP8Y8WMkmD3C4PN6vDbFik=;
        fh=gJVcZJZpzQ0MDOQik6ezUkmdUsfhLCR8T+/zUYC8cn0=;
        b=Fc+q2Sc1ITXDfFMekcutYS6kpbD5UYXJLxFXBJcs+xSU6bu1buM9xzu7maOWUwZuit
         ZLhVeG5UTRt2G5ZNxwNgmtH2CbbL6KbPcq4JeSjITxW4Gi5ihChUNcK7rokObTsMJpRF
         BovvFrhKktupNbJPbGa/9v6OvZDxK+YRK+mJjT0A4ytNW6iQ6rdKXBgiKQAcIEdhpN+n
         a3ZEivkyjKz98cMnPqvbbPLzH0hbHpD/LFizoCjzNIHZ5S5FrLFvdpoT7nS/Gd0Ibxv2
         HEhza9eBClkV5WR9CKRawWD4J0rl/L/b6JsgyJBHlJ3sTSaer+5CnySIa9GxF1BI4BXb
         qPOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=HrnCPams;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24416.protonmail.ch (mail-24416.protonmail.ch. [109.224.244.16])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-65f49693677si298377eaf.1.2026.01.07.12.47.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Jan 2026 12:47:53 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) client-ip=109.224.244.16;
Date: Wed, 07 Jan 2026 20:47:46 +0000
To: Kees Cook <kees@kernel.org>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: =?utf-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>, joonki.min@samsung-slsi.corp-partner.google.com, Andrew Morton <akpm@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Danilo Krummrich <dakr@kernel.org>, jiayuan.chen@linux.dev, syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, Kernel hackers <linux-kernel@vger.kernel.org>, linux-mm@kvack.org
Subject: Re: KASAN vs realloc
Message-ID: <btracv3snpi6l4b5upqvag6qz3j4d2k7l7qgzj665ft5m7bn22@m3y73eir2tnt>
In-Reply-To: <202601071226.8DF7C63@keescook>
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com> <202601071226.8DF7C63@keescook>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 653d54c7561a9f7268c6702e5a88189d6c4a52ac
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=HrnCPams;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

On 2026-01-07 at 12:28:27 -0800, Kees Cook wrote:
>On Tue, Jan 06, 2026 at 01:42:45PM +0100, Maciej =C5=BBenczykowski wrote:
>> We've got internal reports (b/467571011 - from CC'ed Samsung
>> developer) that kasan realloc is broken for sizes that are not a
>> multiple of the granule.  This appears to be triggered during Android
>> bootup by some ebpf program loading operations (a struct is 88 bytes
>> in size, which is a multiple of 8, but not 16, which is the granule
>> size).
>>
>> (this is on 6.18 with
>> https://lore.kernel.org/all/38dece0a4074c43e48150d1e242f8242c73bf1a5.176=
4874575.git.m.wieczorretman@pm.me/
>> already included)
>>
>> joonki.min@samsung-slsi.corp-partner.google.com summarized it as
>> "When newly requested size is not bigger than allocated size and old
>> size was not 16 byte aligned, it failed to unpoison extended area."
>>
>> and *very* rough comment:
>>
>> Right. "size - old_size" is not guaranteed 16-byte alignment in this cas=
e.
>>
>> I think we may unpoison 16-byte alignment size, but it allowed more
>> than requested :(
>>
>> I'm not sure that's right approach.
>>
>> if (size <=3D alloced_size) {
>> - kasan_unpoison_vmalloc(p + old_size, size - old_size,
>> +               kasan_unpoison_vmalloc(p + old_size, round_up(size -
>> old_size, KASAN_GRANULE_SIZE),
>>       KASAN_VMALLOC_PROT_NORMAL |
>>       KASAN_VMALLOC_VM_ALLOC |
>>       KASAN_VMALLOC_KEEP_TAG);
>> /*
>> * No need to zero memory here, as unused memory will have
>> * already been zeroed at initial allocation time or during
>> * realloc shrink time.
>> */
>> - vm->requested_size =3D size;
>> +               vm->requested_size =3D round_up(size, KASAN_GRANULE_SIZE=
);
>>
>> my personal guess is that
>>
>> But just above the code you quoted in mm/vmalloc.c I see:
>>         if (size <=3D old_size) {
>> ...
>>                 kasan_poison_vmalloc(p + size, old_size - size);
>>
>> is also likely wrong?? Considering:
>>
>> mm/kasan/shadow.c
>>
>> void __kasan_poison_vmalloc(const void *start, unsigned long size)
>> {
>>         if (!is_vmalloc_or_module_addr(start))
>>                 return;
>>
>>         size =3D round_up(size, KASAN_GRANULE_SIZE);
>>         kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
>> }
>>
>> This doesn't look right - if start isn't a multiple of the granule.
>
>I don't think we can ever have the start not be a granule multiple, can
>we?
>
>I'm not sure how any of this is supposed to be handled by KASAN, though.
>It does seem like a round_up() is missing, though?
>
>-Kees
>
>--
>Kees Cook

I assume the error happens in hw-tags mode? And this used to work because
KASAN_VMALLOC_VM_ALLOC was missing and kasan_unpoison_vmalloc() used to do =
an
early return, while now it's actually doing the unpoisoning here?

If that's the case, I agree, the round up seems to be missing; I can add it=
 and
send a patch later.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
tracv3snpi6l4b5upqvag6qz3j4d2k7l7qgzj665ft5m7bn22%40m3y73eir2tnt.
