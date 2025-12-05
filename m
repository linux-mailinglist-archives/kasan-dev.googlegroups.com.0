Return-Path: <kasan-dev+bncBDW2JDUY5AORBPHBZDEQMGQE3X7ZZPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id EE39DCA5CA2
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 02:09:17 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4779b3749a8sf11322255e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 17:09:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764896957; cv=pass;
        d=google.com; s=arc-20240605;
        b=BcOxqKJvCcjCaZzN4ti/EE6ml3I5nWd+AmPMBh+1TX4Jz8IVtdk5w6YiwA4tZOG+uo
         QZ1ZoXcyYdurD8mCol4Ww7dP8ebiWSavSWRgwU7doYX2gR6/pBgNoIQqJ3hjahF1oaU3
         qaaLZ+oAbOFuX++xvS8BS3rsl68CoYtIvLwBUduee8XmwA+Q5uFqRupfS6nsMHpLR9WT
         ACHOi30LrZei6I6bJS+84hgBY5uYV9ydcdAAewRRXtb9cBwH75SahPEuNmpzt2fM59rf
         r3oNfUAW5k/aTdA6lWD6fawlIvkyM83kC5Z5d1rX+GEy70fHHit5ipm6TqhJ9BTH+64e
         F2PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=kT4xfOVfKAuo52cKrrZIW+7FTPde3uNVN1xX6xpkvv0=;
        fh=g024YAeocfZGgJIROgtsMOIQ7NnyEjIbGfLFV/6G38Q=;
        b=BhBpfrtTc0M113LoUV1mRjZV1SeEMhtDQvn6+d0n6X48HMtJ+OyW6+ojSsObg0AzVI
         MMycd9eIVQwpYo84i+AbFT4v69DAPeig/7y+wIFh/Ob1UHzOPWNus1YVdxsF2afaP+0P
         sLJuPc+TDRaLfz6qcKS5Stu+Y3b5I1ONBxeExHE8Ndw9x8b/H9lL0IAYgbun25uIxixm
         zCV4Ou6/hJc3i/jbPyE+eNVFKD+6n3bABq7vss1X4ic1jXf9nIG8kxbujxu9CEOE717D
         VhzcS83UZbG+gkswcsaIjt9TEWzHekFc8J2o8HQ1Kukt9+g+51+lA47fIxBpaV1ETWrU
         mj0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XSedSKSt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764896957; x=1765501757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kT4xfOVfKAuo52cKrrZIW+7FTPde3uNVN1xX6xpkvv0=;
        b=AQBzj/Wc87agf8GgDLUA8THwueDKwEXEWV4d2wMPAYTgH2ilnxFymrSK3+G3HbWQPi
         LZd/Psrac96dYUCfGWMAPw6TP78/BndOTVr0lCiQYV+/vz00fED23UfRnd+kAQC6xl34
         +X1LLyvZKw+3u6CRiAdIC62clVnDkrkvMh2a94SnCWKhtlLn/AcCsujPvrmSIAjq+fKj
         O90Q3gn/zsVyg7fCIatwIG1dmHcvCn5Sobn7C8DM9Ba30kyjqMgTzQU16/SNJFeSzNhF
         DC2AkWQZm7j7nnEjGDmSdlzurM93dOC+jWvMpWBJLFK1kkxhd6PrN78vMDNQyqpphQfH
         990g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764896957; x=1765501757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kT4xfOVfKAuo52cKrrZIW+7FTPde3uNVN1xX6xpkvv0=;
        b=aNYBPzbWY+D4Tdo05k+MZrVNSHLOKCJsj02xZYlLltecM9Uy28oJipspUeRk+nAkcm
         nJuOa2KQcgPvCQBQZlZ4r5ZMFAnK3A0uiyQj2XjotIP0ac7aMxFVp9b0JXNKo0tnftuV
         KT7nGBjBRqfdfEGxfvOlMR5J+ks0LSUg6yhf1I4rwqDHyTOXjnGYZmWmWk1+pTIqZs4e
         603Ys2hRHZ0uith0mKAT9MU6S007+yFicjTm8++2VnDdLpUPszG9HPwT0gfpioP7fvF2
         p2Bq0695jlAa6VtV51y1rN0jZccgIDKCWLD1qtxCCdxiMNzqDLRsnzoob7F/3ekvV/UP
         Ds1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764896957; x=1765501757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kT4xfOVfKAuo52cKrrZIW+7FTPde3uNVN1xX6xpkvv0=;
        b=WTUTRDjFsu2mpZJ96ULGVlm8GZv/cK6fT1yDRNgEcVp1jqTCXMUkkHrggEb9tlz5eY
         PKPQYM5eBw88Ur6xLhkj9cWl5sEI9qgMX6zPrQODiuzQiA+Iv94CtlAx3Snf2V3FEVgP
         lAavyRjQr4EM/6fRn2/PfZ2p/10ihSVU54QhGNWb1BHkM87crpHvop4yeR2M5EJ/QO1n
         36QDsFI4yHXHnCd4eSJpY+5uZ0IbrDcpvXU1EJvfgMoMqMWcjUtgTsCcKt0kk3+hZ10S
         +K4mqQfKitUWZpZX5BHQtgyFfGeYz54uP1jnlR/PsuCswBjxzP7qvL75CD+dIcv2EJR3
         0iTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXQ6McyOtRjSaxY6BQSND9b5W3gVDO3Gn23eS6oQZiWor+TxScfyRyQ3PmsI/zDPjt4XJBlOA==@lfdr.de
X-Gm-Message-State: AOJu0Yw/U6bfurKcM5/Yji+uWsH1RKM9D0vfnENZZr/VovpJVxAbWVL8
	kvXv7vLQwOg9mcd0ZYdEJvCfH8xMwpiN8BHi8Mijqs1BHlgUCxbsL80L
X-Google-Smtp-Source: AGHT+IGd2g1sJ0L5qS5njo6wRzxjEc3A3HMSJ2lb9G+e4JnHZUlNtHBfYENnFWseovHpmaLrDqjhzA==
X-Received: by 2002:a05:600c:45ca:b0:46f:b32e:5094 with SMTP id 5b1f17b1804b1-4792af5e38emr90740435e9.32.1764896957166;
        Thu, 04 Dec 2025 17:09:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+axyYFvZ62M5Dhaz+e2ayTiu3hmabl4Qo4zRmtafTB/zw=="
Received: by 2002:a05:6000:2006:b0:426:fef2:c9f0 with SMTP id
 ffacd0b85a97d-42f7b035582ls701444f8f.0.-pod-prod-01-eu; Thu, 04 Dec 2025
 17:09:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVuiPI+Blci9Me1mi3JbbaeaerQLUbWifwfSCUOnRMYgJwKjiwr1Nel+lCVm8ST8lU/F24pVgBJnb8=@googlegroups.com
X-Received: by 2002:a05:6000:381:b0:42b:3aee:429e with SMTP id ffacd0b85a97d-42f731ed943mr8659314f8f.56.1764896954408;
        Thu, 04 Dec 2025 17:09:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764896954; cv=none;
        d=google.com; s=arc-20240605;
        b=WCOHm3+IYEsV+JEBHns6QVXqQh2Vwdyy/l8XZWJtQJXKv9bwoHM3l+jqealOnjVx6P
         1k5OSYzeMzuWflRk8HfZ61tvL55z6MVHrf5NPppD8Sm2CEYziSfR1n8nF+74Sg04zPI+
         5//gCWh+1SzDIJCP4JhG5uEB8DPbTDrbmST5VPIQouqLXQRZb88zMTD3P9yipvaoJL4k
         yCTrTVOuvyhdaUMAP3RnnIC/Dw0Iwtd3vbwF5hmM9AUXtFLx5rsnt6zv7mwJiQvDUH60
         vPqCPZPEngsLHoO22MER2QA+IchenmzILLdAu60yXgGtOCzAJtgIx9o8vEmZdELwxrdH
         hcCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=m+mF3Gja/Pth6t91/XACwIVYUz7EioOwwJ2M/LMKxqY=;
        fh=lp8Ocw+0nguSYv4bOLsM42yshOTN/8Xqvgk3857LVxg=;
        b=gLqsmRc2JajJWeljaAMssgmNI0z9ZtFYyTWPpypbORSNlJkgury93ijjkVMgHaGoMO
         dEmfaUQDNfTRHO3Kx3E6x/3oMmvviRa4FF4DCLLfTzI5FFwRxoohNpYXyWKGqlzauHLs
         0hoglCwWG9FcMGA9Yff9r/dl71XE8GNcfOL/NhqKg2ZRryuxhB81Q02lvbLtyxBhImAY
         pN+fcvFSKQzSvGsvWxfSRufDc2brwKB1+kv0IAdjVAmU++zF9w2oCxydOkg7xrNSQUQx
         t3f/tA0KQw/WwNW0brat4Xe4TeOyBq9w3lvVcJS4kdM2+MBS0sEwld3o56h3YLW5aBnS
         OXPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XSedSKSt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7d32542bsi62578f8f.10.2025.12.04.17.09.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 17:09:14 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-42e2b80ab25so767545f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 17:09:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW5c7NK1PGI9ab3L/mquRPq/8F85bfgWkxEIGerJr0Xt/cAtjTEZDsqit2yEEwNrowJo4UIu/Jxbus=@googlegroups.com
X-Gm-Gg: ASbGncsBiVuc2tw0l4xbtoYr3G10XSyL6/2IY6ECMw8iAJJzvRkhE+c3e5CGnzROfRA
	Qx5enjCSNX5Hw8Atba2kGMSsknHZS+JWuraO84ZeNivQ4i2ytqz+xJmUY6OFwwu9emF+GRC19ED
	O6QwUqjjnLHlAqPyh45dCBEMPOYUdl+hjQbQ4ISKjJN1p/E7t9+TkA0HLEB6WhhHzrNby7W3BEU
	WUFthIcMHAZpOcItRxLmygBwCRTwzmpsuU0K2gxVcDBMEL+0pVrAQM4n80+kzqM/fRAV9JUtD8p
	6sYD07MUrN4jR3LqL1oFGzVVibSoVRCw
X-Received: by 2002:a05:6000:1887:b0:42b:2f90:bd05 with SMTP id
 ffacd0b85a97d-42f731c3290mr7979343f8f.45.1764896953705; Thu, 04 Dec 2025
 17:09:13 -0800 (PST)
MIME-Version: 1.0
References: <cover.1764874575.git.m.wieczorretman@pm.me> <eb61d93b907e262eefcaa130261a08bcb6c5ce51.1764874575.git.m.wieczorretman@pm.me>
In-Reply-To: <eb61d93b907e262eefcaa130261a08bcb6c5ce51.1764874575.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 5 Dec 2025 02:09:02 +0100
X-Gm-Features: AQt7F2q4Ra3kjpdEcyDMUb7m8yHahuZhZTyWN3KMRPGCVySA_YBmuHFHNlC1cSE
Message-ID: <CA+fCnZfRTyNbRcU9jNB2O2EeXuoT0T2dY9atFyXy5P0jT1-QWw@mail.gmail.com>
Subject: Re: [PATCH v3 2/3] kasan: Refactor pcpu kasan vmalloc unpoison
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	Marco Elver <elver@google.com>, jiayuan.chen@linux.dev, stable@vger.kernel.org, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XSedSKSt;       spf=pass
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
> Refactor code by reusing __kasan_unpoison_vmalloc in a new helper in
> preparation for the actual fix.
>
> Changelog v1 (after splitting of from the KASAN series):
> - Rewrite first paragraph of the patch message to point at the user
>   impact of the issue.
> - Move helper to common.c so it can be compiled in all KASAN modes.

Nit: Can put this part after ---.

>
> Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
> Cc: <stable@vger.kernel.org> # 6.1+
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v3:
> - Redo the patch after applying Andrey's comments to align the code more
>   with what's already in include/linux/kasan.h
>
> Changelog v2:
> - Redo the whole patch so it's an actual refactor.
>
>  include/linux/kasan.h | 15 +++++++++++++++
>  mm/kasan/common.c     | 17 +++++++++++++++++
>  mm/vmalloc.c          |  4 +---
>  3 files changed, 33 insertions(+), 3 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 6d7972bb390c..cde493cb7702 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -615,6 +615,16 @@ static __always_inline void kasan_poison_vmalloc(con=
st void *start,
>                 __kasan_poison_vmalloc(start, size);
>  }
>
> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
> +                                kasan_vmalloc_flags_t flags);
> +static __always_inline void
> +kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
> +                         kasan_vmalloc_flags_t flags)
> +{
> +       if (kasan_enabled())
> +               __kasan_unpoison_vmap_areas(vms, nr_vms, flags);
> +}
> +
>  #else /* CONFIG_KASAN_VMALLOC */
>
>  static inline void kasan_populate_early_vm_area_shadow(void *start,
> @@ -639,6 +649,11 @@ static inline void *kasan_unpoison_vmalloc(const voi=
d *start,
>  static inline void kasan_poison_vmalloc(const void *start, unsigned long=
 size)
>  { }
>
> +static __always_inline void
> +kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
> +                         kasan_vmalloc_flags_t flags)
> +{ }
> +
>  #endif /* CONFIG_KASAN_VMALLOC */
>
>  #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && =
\
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index d4c14359feaf..1ed6289d471a 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -28,6 +28,7 @@
>  #include <linux/string.h>
>  #include <linux/types.h>
>  #include <linux/bug.h>
> +#include <linux/vmalloc.h>
>
>  #include "kasan.h"
>  #include "../slab.h"
> @@ -582,3 +583,19 @@ bool __kasan_check_byte(const void *address, unsigne=
d long ip)
>         }
>         return true;
>  }
> +
> +#ifdef CONFIG_KASAN_VMALLOC
> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
> +                                kasan_vmalloc_flags_t flags)
> +{
> +       unsigned long size;
> +       void *addr;
> +       int area;
> +
> +       for (area =3D 0 ; area < nr_vms ; area++) {
> +               size =3D vms[area]->size;
> +               addr =3D vms[area]->addr;
> +               vms[area]->addr =3D __kasan_unpoison_vmalloc(addr, size, =
flags);
> +       }
> +}
> +#endif
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 22a73a087135..33e705ccafba 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -4872,9 +4872,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned=
 long *offsets,
>          * With hardware tag-based KASAN, marking is skipped for
>          * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
>          */
> -       for (area =3D 0; area < nr_vms; area++)
> -               vms[area]->addr =3D kasan_unpoison_vmalloc(vms[area]->add=
r,
> -                               vms[area]->size, KASAN_VMALLOC_PROT_NORMA=
L);
> +       kasan_unpoison_vmap_areas(vms, nr_vms, KASAN_VMALLOC_PROT_NORMAL)=
;
>
>         kfree(vas);
>         return vms;
> --
> 2.52.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfRTyNbRcU9jNB2O2EeXuoT0T2dY9atFyXy5P0jT1-QWw%40mail.gmail.com.
