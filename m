Return-Path: <kasan-dev+bncBDW2JDUY5AORB3FZYHEQMGQECVHUMZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 87964C9FB06
	for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 16:53:18 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-37a39ed76c8sf30333931fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 07:53:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764777197; cv=pass;
        d=google.com; s=arc-20240605;
        b=TdZcnl6509AUTOuvjSsOoq3HoeExOFIqgQIOZFxEMnV25SzebsmTe/UmcQBkMGsTlG
         W+9XffZ6xHmcu3stZKEeesimT85uzYKc/Akn3exIngnxhVVy6aFI2FP6o+5KKVGzBuvh
         aavcYc1gF9PRFNMupUdEdjQsdVwR46V24gzPmgYExLDTEtTu+CMY4obD4Iaf1M+kdUhS
         n5jSul54ymECvLNXAUCIFq9GbNttOgP+d18iXCOw0DiVVP6ow+vuHcgqvFHpKUecOTzd
         YWKVhO2SgVP7s4S7mEn6OPChySu5iAf/iKv7CpFSr5XKIEjmnRHPrGo5Oz2slXBZ/Msb
         kBrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=wUv89VGhC56iBZpOOLJ6h+vCNhjgzv3vIe5tHDKQ/aI=;
        fh=c3T+4xvESZUY+WvEau5dRKrHDpwjkvyaay9c3Wa1vPY=;
        b=kxvOJM7hOvWVj/aLmWTlkMRGIaLcHz4MwM4+dX3kBFf2lw/IUikaTY2HacZFWjVDXh
         4CmQv5mKtY2SW/esEnsyZAv1PXBImWb31XZ1UXwIHF9BnPJbejLJx7XPb9ttigHLG8nf
         +M4cSRTVBqJ0JCrkKh4Csznkp8FYd+7kcXG0HHeyFpjHX+Yt6coCRyqK7fjTvfTUNBTJ
         t6eQcfjb9qXZdVCQLrR3mwec8yICUGl2tug7o1UHzZM/Dg733xoKSqXjLaoRcC6i30IO
         6kQzJ1MMDfCrPkXU+nS/XWpb8tKToOTd9nhle8PiDlIosx16smFM22iUSaSaDoOcjcjs
         CnPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TXcHLzbz;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764777197; x=1765381997; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wUv89VGhC56iBZpOOLJ6h+vCNhjgzv3vIe5tHDKQ/aI=;
        b=M1mIfTZmnyfHyngnw7pkCK7GrAe7ntTuRc8VAY48DBtKmrU7Bp+v/p3fqEUHNUwHlj
         GAijx38o6Gd+9ekqoiYY2PQfqDAtO1WLRCqTbisFYpmPvAj4mVuIrxDiU9ONDdttJyUX
         3ykXP+9rw02KOG+myAl3NKUWf/Q1+m+rCwPYFLcRG/mmP/tRULK/FdyCmfHhyHktUytC
         geem+r7XzJbf+WPw09etpvzH5obner+H78uJDti0u9ln7B4oQFL3bmU/fXLlqP7wbPsi
         IAL8JANHOSgT0O+f1eVfns+mf4BwKyCQGsy/SgvfK6NvCCzsX8hUIeHGCWfcdev4kNcM
         NZTw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764777197; x=1765381997; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wUv89VGhC56iBZpOOLJ6h+vCNhjgzv3vIe5tHDKQ/aI=;
        b=UhP1MOrPjf2ZXPXmrMwkPV4u8gjb31dLB63t/thfjfRe6GjucC76zaBRKphdhOv+1W
         oE81M4JLxqcR4I214STZPA3TPxCA1vrS15DR7w7CmfOMyeG8GA8EWirkVqWg+o7nJNbC
         B6QBfDKLMRJIaKRAibmDvl2fBPysp02e+iOUKceDbl0jQvbLjzU2tuFDzXfiTC1Egt3z
         REptkPKpPWD0Hw6J31Lhl7BA7fWeicP/e2bHIb9OeX3MF+q7pnASlcQSBH7M0C9a1HVL
         M15cyaqkVFbpE/++dHAcjD2Z8HaSr/AyThaRehJT3bYyuSfAdexpg3cHTZE0mxUTgNUj
         /jog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764777197; x=1765381997;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wUv89VGhC56iBZpOOLJ6h+vCNhjgzv3vIe5tHDKQ/aI=;
        b=hWOcBmic/ttrJux1LH9paNuHEZiTX4fB1TUqKl39H7G6SmcxsKISEvLs5IWBHO7V5Y
         2O/q1FhjlUOhX26fx7iJ7pLG8jP0LxW6OUQC0MmTe8NJMMrrc0DzBxU3Ov6BNxpQgMLf
         VlnXPziwOn1+/aOLlPlnhclaN2egVDKtZDMgZ4SXheYQoI1VsYgU2Uxorw1fcMeH6D9Z
         tW9aVjsmjegKYBisSM5375QajaoSgtT5HXBSZzn/Phw/dhCYHQklPUzS6MgjBroEfX4s
         3mvwlQUx8zPhe0RR1U/KGuCey7hDhFGTEsYl3dAtz3tix71MU8w01NHvOk+fHj5gj/yf
         wwFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLXS3aHyCpOi1Oajl/iGCTOQzpvgDynS1IlE2hVsEvoHuW9w43HmNwNJqiMbJddj2OLHZHpw==@lfdr.de
X-Gm-Message-State: AOJu0YyOZWraxHH2GwYHiP/67/pfkPiJj4RTsFSapY9LA0Yh9+4HN2Xb
	1jYURyyn3IkjfAIuyQ+erBcwSWFffQ/citod3c/7zYYPXUNqLmx3DmeI
X-Google-Smtp-Source: AGHT+IGUN++kWAQgRLCjNrHJiYxZu2whTMcZZxyBLrMPURohQsxWy9WiF8Dg9UFkBOukjCiYsi/5+g==
X-Received: by 2002:a05:651c:441c:20b0:37a:421c:cc50 with SMTP id 38308e7fff4ca-37e63938ec2mr9954011fa.33.1764777197345;
        Wed, 03 Dec 2025 07:53:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aHmAIMRwP7yn75jNQaW3nwAmRIK40/vFCz6FlZ7heCcw=="
Received: by 2002:a2e:7214:0:b0:37b:9692:7e83 with SMTP id 38308e7fff4ca-37d1ffb00cbls10300531fa.0.-pod-prod-06-eu;
 Wed, 03 Dec 2025 07:53:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVvcW/3e2qCz9Q3Z+czqxwE4uwHJNC99HcXfk68v7LrQioze7lRIcsurQjGx7aO2TnZIR/5srTsbhA=@googlegroups.com
X-Received: by 2002:a05:651c:440e:10b0:37a:7d5e:db58 with SMTP id 38308e7fff4ca-37e63915f8dmr8375051fa.21.1764777193839;
        Wed, 03 Dec 2025 07:53:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764777193; cv=none;
        d=google.com; s=arc-20240605;
        b=XTZ3EUN56Bo+bx3mMZXeN8ywDIcH7saOQ+WpN1gejFNVLyAJ5xbx0l48DXbHYfYSZJ
         POuRtazgex8aCRAKjh5RfUdcrc7ysZPGR5EpSfDwo5jzvIKXUyCUIDJqbZE1lTtnwjNc
         FZY2dZyjTyxR9jrbktdrickcl99b8xKckRaf46KefUpGfF510upOyH6WmtbRTFohIC2v
         nvdqxqHWjh3uvFQ7A/i3e97VXmkTB7DyRwfpOj9KuRg6NiK6XFuV+7qkJsOvwc1DtNCJ
         k3iRnvJw+OFW+sPFi4BMo8tGSJhvbO5rcHxGqIQQ98abhQLWXeKtBF7S+25J33bonam6
         TxNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2crlSn5K87P6BhIOUFvHVg2OvJtF8ySKOKkXTHnicII=;
        fh=3lWEwOrV3jLFzPqhW6/lzjiTn2HnxWdze7e7jLc8dKo=;
        b=WA12BNEyi/7yFPRLbz9YLoCF58ZRMyN4pcOZyN3+NDCaJGp9h6V6DjJ4bOBxEEiVj1
         YvB4qh6zWoQ5RE8OyKBSQDjCwfyWs9ZQtuVM8kX83WnRJpZ/T99O/NX52uUGBBjfi3Rm
         KeM9ILK/Q1KgfYEpyn49PCwPp9Tbc2KqJwThgn4T61XUor4o/Io36wVlZldoQ+NjC8Hh
         kJL1kGJmni7z3FJF4UNQU/otTAiz5tkVFewWeW7H4myDAuW32u96okVhE2s7tKbNul7O
         Oi0j+YcCWh/7CBW1nOw1/+0MTwXgHsmwwkRy0jTJQckXIZ8M5Ds0oGUT6P+6ZqJAaNjf
         9rRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TXcHLzbz;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37d236f7748si2797271fa.3.2025.12.03.07.53.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Dec 2025 07:53:13 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-42e2e445dbbso1906862f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 03 Dec 2025 07:53:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXzX3vaAINvSCleALH0Q2DYyB29EarkZLNek2y14NN+uxebDq2hRV9u8GwLFWi1qBGBJlmMOyJZNAA=@googlegroups.com
X-Gm-Gg: ASbGncuH3EDiFtFoUgDKT/l0hLU//XrIlido4Aype+IKOrmrNcJa15i96LPCu8YWc8u
	Wd79kINugiuA5URmIEGCNUhNNmGO6ntI76qQJGVv8+WMWczn0e3pSxsecmHTTF8VMvW4AFcweT5
	PJ5fX+u+RHEJwMPPuA0fDXID2i1jzwbM++Ls8ZcRO2D2OELx2HNSw2DVqgKMpj0DGqdGl9RDAIs
	Y5amGOwEsUqb5qYTPTyw5t2Eyn75IbCJbHcH/xaHpDHoN2WTQdeZLHZFH0HplGwGAsYhq35OOsn
	tPNr+AYlMdM2WqSoxaPFg3Zejxh1jK5wZ/p70120SYv6
X-Received: by 2002:a05:6000:2407:b0:429:66bf:1475 with SMTP id
 ffacd0b85a97d-42f73171fe9mr2836344f8f.3.1764777192950; Wed, 03 Dec 2025
 07:53:12 -0800 (PST)
MIME-Version: 1.0
References: <cover.1764685296.git.m.wieczorretman@pm.me> <325c5fa1043408f1afe94abab202cde9878240c5.1764685296.git.m.wieczorretman@pm.me>
In-Reply-To: <325c5fa1043408f1afe94abab202cde9878240c5.1764685296.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 3 Dec 2025 16:53:01 +0100
X-Gm-Features: AWmQ_blDuVtndNbheCozTAbytnRMB29Z6p9yQJJRwDXdD-0EGYk1gIR7FCpOkvo
Message-ID: <CA+fCnZdzBdC4hdjOLa5U_9g=MhhBfNW24n+gHpYNqW8taY_Vzg@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] kasan: Unpoison vms[area] addresses with a common tag
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, jiayuan.chen@linux.dev
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, stable@vger.kernel.org, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TXcHLzbz;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e
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

On Tue, Dec 2, 2025 at 3:29=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> A KASAN tag mismatch, possibly causing a kernel panic, can be observed
> on systems with a tag-based KASAN enabled and with multiple NUMA nodes.
> It was reported on arm64 and reproduced on x86. It can be explained in
> the following points:
>
>         1. There can be more than one virtual memory chunk.
>         2. Chunk's base address has a tag.
>         3. The base address points at the first chunk and thus inherits
>            the tag of the first chunk.
>         4. The subsequent chunks will be accessed with the tag from the
>            first chunk.
>         5. Thus, the subsequent chunks need to have their tag set to
>            match that of the first chunk.
>
> Use the modified __kasan_unpoison_vmalloc() to pass the tag of the first
> vm_struct's address when vm_structs are unpoisoned in
> pcpu_get_vm_areas(). Assigning a common tag resolves the pcpu chunk
> address mismatch.
>
> Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
> Cc: <stable@vger.kernel.org> # 6.1+
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v2:
> - Revise the whole patch to match the fixed refactorization from the
>   first patch.
>
> Changelog v1:
> - Rewrite the patch message to point at the user impact of the issue.
> - Move helper to common.c so it can be compiled in all KASAN modes.
>
>  mm/kasan/common.c  |  3 ++-
>  mm/kasan/hw_tags.c | 12 ++++++++----
>  mm/kasan/shadow.c  | 15 +++++++++++----
>  3 files changed, 21 insertions(+), 9 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 7884ea7d13f9..e5a867a5670b 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -591,11 +591,12 @@ void kasan_unpoison_vmap_areas(struct vm_struct **v=
ms, int nr_vms,
>         unsigned long size;
>         void *addr;
>         int area;
> +       u8 tag =3D get_tag(vms[0]->addr);
>
>         for (area =3D 0 ; area < nr_vms ; area++) {
>                 size =3D vms[area]->size;
>                 addr =3D vms[area]->addr;
> -               vms[area]->addr =3D __kasan_unpoison_vmap_areas(addr, siz=
e, flags);
> +               vms[area]->addr =3D __kasan_unpoison_vmap_areas(addr, siz=
e, flags, tag);

I'm thinking what you can do here is:

vms[area]->addr =3D set_tag(addr, tag);
__kasan_unpoison_vmalloc(addr, size, flags | KASAN_VMALLOC_KEEP_TAG);

This is with the assumption that Jiayuan's patch is changed to add
KASAN_VMALLOC_KEEP_TAG to kasan_vmalloc_flags_t.

Then you should not need that extra __kasan_random_unpoison_vmalloc helper.


>         }
>  }
>  #endif
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 4b7936a2bd6f..2a02b898b9d8 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -317,7 +317,7 @@ static void init_vmalloc_pages(const void *start, uns=
igned long size)
>  }
>
>  static void *__kasan_unpoison_vmalloc(const void *start, unsigned long s=
ize,
> -                                     kasan_vmalloc_flags_t flags)
> +                                     kasan_vmalloc_flags_t flags, int un=
poison_tag)
>  {
>         u8 tag;
>         unsigned long redzone_start, redzone_size;
> @@ -361,7 +361,11 @@ static void *__kasan_unpoison_vmalloc(const void *st=
art, unsigned long size,
>                 return (void *)start;
>         }
>
> -       tag =3D kasan_random_tag();
> +       if (unpoison_tag < 0)
> +               tag =3D kasan_random_tag();
> +       else
> +               tag =3D unpoison_tag;
> +
>         start =3D set_tag(start, tag);
>
>         /* Unpoison and initialize memory up to size. */
> @@ -390,7 +394,7 @@ static void *__kasan_unpoison_vmalloc(const void *sta=
rt, unsigned long size,
>  void *__kasan_random_unpoison_vmalloc(const void *start, unsigned long s=
ize,
>                                       kasan_vmalloc_flags_t flags)
>  {
> -       return __kasan_unpoison_vmalloc(start, size, flags);
> +       return __kasan_unpoison_vmalloc(start, size, flags, -1);
>  }
>
>  void __kasan_poison_vmalloc(const void *start, unsigned long size)
> @@ -405,7 +409,7 @@ void __kasan_poison_vmalloc(const void *start, unsign=
ed long size)
>  void *__kasan_unpoison_vmap_areas(void *addr, unsigned long size,
>                                   kasan_vmalloc_flags_t flags, u8 tag)
>  {
> -       return __kasan_unpoison_vmalloc(addr, size, flags);
> +       return __kasan_unpoison_vmalloc(addr, size, flags, tag);
>  }
>  #endif
>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 0a8d8bf6e9cf..7a66ffc1d5b3 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -625,8 +625,10 @@ void kasan_release_vmalloc(unsigned long start, unsi=
gned long end,
>  }
>
>  static void *__kasan_unpoison_vmalloc(const void *start, unsigned long s=
ize,
> -                                     kasan_vmalloc_flags_t flags)
> +                                     kasan_vmalloc_flags_t flags, int un=
poison_tag)
>  {
> +       u8 tag;
> +
>         /*
>          * Software KASAN modes unpoison both VM_ALLOC and non-VM_ALLOC
>          * mappings, so the KASAN_VMALLOC_VM_ALLOC flag is ignored.
> @@ -648,7 +650,12 @@ static void *__kasan_unpoison_vmalloc(const void *st=
art, unsigned long size,
>             !(flags & KASAN_VMALLOC_PROT_NORMAL))
>                 return (void *)start;
>
> -       start =3D set_tag(start, kasan_random_tag());
> +       if (unpoison_tag < 0)
> +               tag =3D kasan_random_tag();
> +       else
> +               tag =3D unpoison_tag;
> +
> +       start =3D set_tag(start, tag);
>         kasan_unpoison(start, size, false);
>         return (void *)start;
>  }
> @@ -656,13 +663,13 @@ static void *__kasan_unpoison_vmalloc(const void *s=
tart, unsigned long size,
>  void *__kasan_random_unpoison_vmalloc(const void *start, unsigned long s=
ize,
>                                       kasan_vmalloc_flags_t flags)
>  {
> -       return __kasan_unpoison_vmalloc(start, size, flags);
> +       return __kasan_unpoison_vmalloc(start, size, flags, -1);
>  }
>
>  void *__kasan_unpoison_vmap_areas(void *addr, unsigned long size,
>                                   kasan_vmalloc_flags_t flags, u8 tag)
>  {
> -       return __kasan_unpoison_vmalloc(addr, size, flags);
> +       return __kasan_unpoison_vmalloc(addr, size, flags, tag);
>  }
>
>  /*
> --
> 2.52.0
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdzBdC4hdjOLa5U_9g%3DMhhBfNW24n%2BgHpYNqW8taY_Vzg%40mail.gmail.com.
