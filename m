Return-Path: <kasan-dev+bncBDW2JDUY5AORBQHBZDEQMGQE72WQ32I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 427DDCA5CA5
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 02:09:22 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-42e2e5ef669sf1506438f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 17:09:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764896962; cv=pass;
        d=google.com; s=arc-20240605;
        b=FNQfKUhQIOkHYsUhpHWeH4V7pvaW4+OyxRZAcVk3buR+Cig0YciiV3cbVX7kFVR190
         TW/e5gcLoAggUB+mPHI72O1G5AEp3yakhocYGPMxorNyj/uy4NP46RJVTOHohCttNSxg
         6nNcPOE54Gio90Mic2VNHnBFpaQx18rACVrgoVYzTtA/Z+tNNTF54ewMPfrjuDhDVy4H
         VXs1W9xSh4+xSMLMQ2nNkLm1uk8oNIdxrUEaKdR62ZA4O0IuHeBcnDGPbzdszlfy7E2X
         itdrkZ1nekOHXDVwKmR7AUbfAwtEfCPDJo9xDQ4nOCEzZLdxNejjVKVbpbfxmvFCnL9Z
         hpGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=zJZC1Eto7sgxdTOqsJZxFCgKyK6n7JeYH9AgDtNWxlA=;
        fh=ONd5rAv5v/3zAr3z0NJNcVOW4Kssw9ygfGoaUxOthI8=;
        b=YYaUk6ShqSKQ8AOBRWL3WmiFNRuqRrgxJ9v4yAyfDcuGy3EIHjD+4sT49MaZ9RwuMQ
         4mbqF9T4V9a/4bGhWdXx2VBjjuHGGBcharTDiKtqCVFP/ft+HfO9PlRltlJmEPv4gE6E
         2QIGT2c5irVofmdQEc8R6ib7j4G75y+0ZX5i++BgnTXyOzEalJ0I+1HsSdW9Ek1Gt7ky
         JMGPuzRGqT7EGE5IuJhZZ0MNq/gDP93BfRYwHp0N9PkdhmotVtPa7FM+J4FUPzeSv3vJ
         MsnFJnN3GihpMXQLHC/vorhKciyNPHHg+9RaGWQzjjojlcb/M1rA06uFxwKNHvtYajyS
         YQMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TOqbjk9L;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764896962; x=1765501762; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zJZC1Eto7sgxdTOqsJZxFCgKyK6n7JeYH9AgDtNWxlA=;
        b=iHQR8L+iZPrKyJHEaZcXKqQAg4SVigweiAxOLFclSxwsNxCAcrqREdMNRbeGQGbUW9
         2OfJWeC5MI1lAG1e+SkIB/fMfgoo3Ig57Xiaa5CrgmxoNDTpuMCxET69j2Bn7vyZVk3p
         0PriF44Ln/1k8sTLYLtKON5QwbFJ3iVCM+xZLkTlplMSIhJyJPZ421sZsasUX0UpuKVV
         yo+Z4Q7Et7KnG82RauQ/7jE7yTUuDzuwgul2X6ts/LemgxSgaGbY1zd811QI+8/ZPn6s
         D9sqURCPJwfc79V0GiO5GWHURvgeCpvVcDJJMsdPjhK7XdkkDXn4LH0g1lleUS/dFJ+X
         n/8w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764896962; x=1765501762; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zJZC1Eto7sgxdTOqsJZxFCgKyK6n7JeYH9AgDtNWxlA=;
        b=lozqXB/vhDC7BHbVNyUh1tL7u/L/DBTQZBZs6+06y4DIvYB2S/8yxj+hQ4Htx0DssV
         /tiInKJ5dHa5r+Pwt7/lSmsZiftm0P1lrb4IuEiDn5kqjsPCO6qp5vTzzXuMqo4wqHeT
         IjhfhcPpTB4iUy1qdUi2CVH/R+GdSJU4eZZK6bjdMq2+4qh7zRRupX8HTHvqTkLkGuR+
         krLc/ori1tIzAWuLxGAGZj3L/pzCjzGZ9ybwU6QOhcRLstHpoV74VVsnFMNffbbWKwpx
         LPB4U6IPXtrYK5F8VMfzYtWu2FaKDZmzFMNIVLA1B1FXfNch3D7R1m9oGU985zkV6Nn5
         iMMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764896962; x=1765501762;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zJZC1Eto7sgxdTOqsJZxFCgKyK6n7JeYH9AgDtNWxlA=;
        b=uz0QcZVV+VLYvfFqbLY8GLQ052bKIb12LqXQKGClXrOgYoF3ZD2nXkTYNvs+23Ob0l
         LcNztVgCqbTnMVvIG0nviCMikHoEaxltHzNkN0C6paNFSLPQxc+m75LPgmka3eJYpGZf
         0RiBYtv0ne+xpa2XOQsKjU8xbNuNCpnR+Kn6LDGN4LsmEgrk5lBeFBhGbkqWmK8g3oUJ
         Rdc7LyIQpYPH45uF7LHE9mzcUu9be0NlGwYuJGO79lTu7qJvvaS9xZqzlIIyq70noqlU
         RJDcmjNTutQgQxyWU1idS5/4wauY8R9oE1cNqiq9GSZXdu1OvZcKQ4UP7YkGqZhklFyR
         vTyA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWFVKm6RNi7Zacm+g/qYB9w/7YgS0/S8YtohbwoDURqbMfr6WLH3DLj7H6DEIXC9X6PpphpbQ==@lfdr.de
X-Gm-Message-State: AOJu0YyqgA1zHKyNuZ38/KZpI2DCv8iPH8AZJYUOOhu54lPr9Ll+zLjP
	L+u/iismL0op6WCd7mi3fJ9ESLSEkNBbZqjr6WBBNdA2hG+Dd8mYfsPG
X-Google-Smtp-Source: AGHT+IGunPyWVoph1SXkyxMKxFBXappI0bnNt5HoxgyDjioy6qngARtPGdUK1CtWOoAVYNS9R4Ffsw==
X-Received: by 2002:a05:6000:220b:b0:425:7406:d298 with SMTP id ffacd0b85a97d-42f797f98b6mr5036911f8f.5.1764896961542;
        Thu, 04 Dec 2025 17:09:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbMGFpYqPzLG4G4Z+imDgDayr9CAi1+jhcx5qaUc80Kvg=="
Received: by 2002:a05:6000:2901:b0:3b3:9ca4:d6f3 with SMTP id
 ffacd0b85a97d-42f7b2db0d8ls1193049f8f.2.-pod-prod-09-eu; Thu, 04 Dec 2025
 17:09:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVJuQF7pT9ZhLWsC3ByZDNPwEHKYIKFB43iVfMEo7UK/J1m2dlHJ5gUNIwQX51RtuVMwmGYszougnk=@googlegroups.com
X-Received: by 2002:a5d:5d86:0:b0:42b:3907:a38b with SMTP id ffacd0b85a97d-42f79855e9amr4949455f8f.44.1764896958770;
        Thu, 04 Dec 2025 17:09:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764896958; cv=none;
        d=google.com; s=arc-20240605;
        b=LNntG9ruhpvYzR55SPAtUIlj1MC3XNpUaO36sWpVCRy7/5tKtwiuGODnGY8cYD9WGz
         WyGqY07/TON0eMLUqAkzWNJ00cVpF/DNVJ0nC/tFk45fgWLyjbzjzc1f0IhagLOawoqK
         85z3VP2Ksx+EDRjArgDTuU/MXTna+YUuqSkCGOApKFogYzRz6eaLcRE/WhaDuF8LxuEz
         TmKh7bV9FNm1r90388oilJX3Nt/vp0HEPGZ4NxXNC/CDajwg8bkJQTfAp0R9cQBqc4AI
         R78B0r7V1LIWqGuFsOSYw/Eq/OQQ3PrCaKaXh7jFayaoaTZ9ZagfoI6V6hInmcvjiWMY
         6FUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=P1CMGYCKUig7gpcSJTE0d5scwAdKO9yGMHIMC90eJ0c=;
        fh=xAFAggLezTITuOgJ4LqEJLgyPDKVzLMopgD36Qq4yR4=;
        b=JVsXUAgdAdf5qtxUy7zd8VnVRbg3P51vlEo6yk586geId3JN0VUcBj/vJ0nFbpz6y7
         HtK5+m3HQsoJsHpchvVVEmj4+f+O/2b5AL9GCT83MMCgv2L4thb08c56NcDM8oLc4quB
         +cqxgtWM2TvjjQhO+aS3cLkOP0I5ngsuVYUm3ORisOyDiM9ROaJoOOUbdYrP9Wbgfp3A
         579qdFjmoyo+0G6ZlqdWV5/7XGUjyXE2SqwKEzAz71O786fQbi2664HuPSTXx+GkvXCC
         nbdLmpTEexnQUEstenPu0aVGYEXp8BuNG2lU0iths0mCg2nlPQZ0ziN+IY/o97u5jKC8
         1j7g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TOqbjk9L;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7d21e315si58672f8f.8.2025.12.04.17.09.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 17:09:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-42e2e77f519so1182937f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 17:09:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU5cQOlVLlw9TXSuYebuB2eYoNR47XLy+nz39lc2ucxJp4/5Z+AzcoDni8rQBy2aoAgwBkUugqDCok=@googlegroups.com
X-Gm-Gg: ASbGncv3SMp0VRtUAQXboIcQz0Pj+SvCy3hvXNpvkHYyB6x+PSYZogA7UXpL+O5W6+a
	cOwMeThp8EfIKrCNaoEIFdIXAxto8/j5wZpLP/AZ2Adgn1oz2oBRFNnopwYnLBjl7MkYVSebnX3
	ZhG8d5PDA5Cn1tQnhBL43QFzLX0e8QlCMnZJ2AYMEEtOYcn8r0dDn87Zo8SEauPxHtAC1KmTxZq
	jBn2CeZmcIrZbqcQE7kZYSHGQ+kfyvFGM2W5UJqriDoC/y6fHIwZriNc/z7z3qiT19sAV4aISdL
	pqDE9luUIlxk9aMdp4R6NetH5bkhejnEWHesSJgrgCs=
X-Received: by 2002:a05:6000:2893:b0:42f:7601:899c with SMTP id
 ffacd0b85a97d-42f7985e948mr4707442f8f.50.1764896958124; Thu, 04 Dec 2025
 17:09:18 -0800 (PST)
MIME-Version: 1.0
References: <cover.1764874575.git.m.wieczorretman@pm.me> <873821114a9f722ffb5d6702b94782e902883fdf.1764874575.git.m.wieczorretman@pm.me>
In-Reply-To: <873821114a9f722ffb5d6702b94782e902883fdf.1764874575.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 5 Dec 2025 02:09:06 +0100
X-Gm-Features: AQt7F2pwGQslVbX98n-X35KQ99_jXpXs5BPWa6Oqbo-7MPEh__0kv49yZSFAeOY
Message-ID: <CA+fCnZeuGdKSEm11oGT6FS71_vGq1vjq-xY36kxVdFvwmag2ZQ@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] kasan: Unpoison vms[area] addresses with a common tag
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, jiayuan.chen@linux.dev, 
	stable@vger.kernel.org, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TOqbjk9L;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
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

On Thu, Dec 4, 2025 at 8:00=E2=80=AFPM Maciej Wieczor-Retman
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
> Use the new vmalloc flag that disables random tag assignment in
> __kasan_unpoison_vmalloc() - pass the same random tag to all the
> vm_structs by tagging the pointers before they go inside
> __kasan_unpoison_vmalloc(). Assigning a common tag resolves the pcpu
> chunk address mismatch.
>
> Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
> Cc: <stable@vger.kernel.org> # 6.1+
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v3:
> - Redo the patch by using a flag instead of a new argument in
>   __kasan_unpoison_vmalloc() (Andrey Konovalov)
>
> Changelog v2:
> - Revise the whole patch to match the fixed refactorization from the
>   first patch.
>
> Changelog v1:
> - Rewrite the patch message to point at the user impact of the issue.
> - Move helper to common.c so it can be compiled in all KASAN modes.
>
>  mm/kasan/common.c | 23 ++++++++++++++++++++---
>  1 file changed, 20 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 1ed6289d471a..496bb2c56911 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -591,11 +591,28 @@ void __kasan_unpoison_vmap_areas(struct vm_struct *=
*vms, int nr_vms,
>         unsigned long size;
>         void *addr;
>         int area;
> +       u8 tag;
> +
> +       /*
> +        * If KASAN_VMALLOC_KEEP_TAG was set at this point, all vms[] poi=
nters
> +        * would be unpoisoned with the KASAN_TAG_KERNEL which would disa=
ble
> +        * KASAN checks down the line.
> +        */
> +       if (flags & KASAN_VMALLOC_KEEP_TAG) {

I think we can do a WARN_ON() here: passing KASAN_VMALLOC_KEEP_TAG to
this function would be a bug in KASAN annotations and thus a kernel
bug. Therefore, printing a WARNING seems justified.

> +               pr_warn("KASAN_VMALLOC_KEEP_TAG flag shouldn't be already=
 set!\n");
> +               return;
> +       }
> +
> +       size =3D vms[0]->size;
> +       addr =3D vms[0]->addr;
> +       vms[0]->addr =3D __kasan_unpoison_vmalloc(addr, size, flags);
> +       tag =3D get_tag(vms[0]->addr);
>
> -       for (area =3D 0 ; area < nr_vms ; area++) {
> +       for (area =3D 1 ; area < nr_vms ; area++) {
>                 size =3D vms[area]->size;
> -               addr =3D vms[area]->addr;
> -               vms[area]->addr =3D __kasan_unpoison_vmalloc(addr, size, =
flags);
> +               addr =3D set_tag(vms[area]->addr, tag);
> +               vms[area]->addr =3D
> +                       __kasan_unpoison_vmalloc(addr, size, flags | KASA=
N_VMALLOC_KEEP_TAG);
>         }
>  }
>  #endif
> --
> 2.52.0
>

With WARN_ON():

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeuGdKSEm11oGT6FS71_vGq1vjq-xY36kxVdFvwmag2ZQ%40mail.gmail.com.
