Return-Path: <kasan-dev+bncBDW2JDUY5AORB3VZYHEQMGQETWIYBLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 02673C9FB09
	for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 16:53:20 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4779edba8f3sf46747165e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 07:53:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764777199; cv=pass;
        d=google.com; s=arc-20240605;
        b=E5lfWUAmrGw7JQI/h6ul57L+K0H078JIq5jvSTKaFWFKVN/G+LF2J6DVSmQy97AZ/A
         EweLbrz0hnBfot4Hzmk4JqBdjUuDNmnimHdhunFQaGzXr8z13dEvouNmeYpLmOWaH6b2
         yjzpirkZZDcVtZ/z4YTz/vkNGnnXTddYPltscf5pg+Uie0+Oj6si31okLMUP0o4Rq0VT
         OaP1f7q30z7/JzLo2hmnJW2MRW0xYbYxRzAX7kfVfZX8VA9NCFn1OE6fmizXj2fmFXJg
         6DlMNP6uQURmF5mjwqhLrkXNuagUeee22lt3yaHDl8ipkvDftT0TqPGDUcZ4+HHV5hZG
         325w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=+f9AyY0yfNd4RingbwG9Eadjii7Xfse3ScmQNF7X8vU=;
        fh=MCM2DeNo2P333dFe20dekTeMt8MwlLJ37XxPjT5+k4I=;
        b=LulPNS7ttQ2dvjMNsa37WThVhTo5aAP+EKTKInWxghzGWVky6vrdlvCU4ws5IAyyv2
         gmZi3Llw/psu+4N6N3RsNb0OZxO/r5o1JAW43DK4HjYMjM/dLZOATmHMZ6n6IDq04LMs
         QbelcMquBtbvLuiOuxShN6YDoqppx1S8YzrT4fqQ2sGTEg1u9e/syeC2TNx73dGaWQsV
         BWePBG3N1hMqhP2LccJDbwnVWqUX16JxgNZtIA/MstLBthVyCEk844pmI0KRGhNt5SCO
         s7ZTBuG0jzpDQvGiEc/HWKT2QDFkBnUSrldPkKo3xG7lmg/gQyfSR/hkReCkH3JFUUos
         ocDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YWXbNUPB;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764777199; x=1765381999; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+f9AyY0yfNd4RingbwG9Eadjii7Xfse3ScmQNF7X8vU=;
        b=aLUCoOXPe2tyjAyir6dIouwY0+IWbpbB+Bfc7Auc90ybl9pN8boFl7IxAvVQSssG7h
         wGpFqvx0SG9eF0uhfiK6vS8bw0M2dhBL3AP1S3lJL+8fpFrCAJLpl9YLAev8mKkJw1W7
         zL2VDwKiV57BKzwtr0NI44ZcRuRNHGBfK//rFmkyQoQASVFcv+DJ83FxYfqpYOsI0pFr
         30ETm28AKVzxxVUmYkCMbQWMoAP6jZJWxryYuZeUoqpqC6rbU4qilsozVx64CoHGR4tW
         vPk9XOkKFhYAG3bg1+k1Uz4b4jDToRxmTNN5UeT0XFYiNWr/zjiCrZJ360inMCRMNrNX
         YtvA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764777199; x=1765381999; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+f9AyY0yfNd4RingbwG9Eadjii7Xfse3ScmQNF7X8vU=;
        b=NEXCbKi5jHkVZqreKdtyt+2U9FEA8K4jNqnesWx/5E9jb05TLfnfpz68jVGVCQyEjz
         X7FEoHgZUjF4Ay03zmKqiGBlBAc7domvOJ+mzn6c+KpOyarkkS0XTf7scE7QSmcyakLo
         uoZycMizEvNnFjuUjAEL9778C5g+B8PoO+8eTC/VnHNxwp6Apk3Wnn2HBAOhxjbKAqXw
         3IEAaEeDtq2gMgzzHI9EdgArxfYCarPdPAdpxw6QV9FoHcXfEMhYn4xqAxepm1KxOAsW
         KkXA+zkLfAdWf8KB6hdWHOfshMNo3A6hyIgIvu4Zzup8W/sjsQI0MvG6NbWPimpIPYu2
         GlfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764777199; x=1765381999;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+f9AyY0yfNd4RingbwG9Eadjii7Xfse3ScmQNF7X8vU=;
        b=Z8TNfAXJb4sjSEhM+xTYhWCvQVkTxi8AFRr7JwO4rxXqJRKGwEHnNqpOWuvmzYVuhA
         xTI2NFJVeluLaIhsguYp5ErL4rgDNtXl0sHgttTqm+9zmG/AaJzbRIbQF7yexqz8dtg0
         3bnyyr0XyKJZip1JaL9LnDwDvkf5+iRlQdnN0xAyndcL3KXQ9DEp2BJv/EwAPpOrPBMP
         LM7u8F19t3DVgDJ3Zr3jQ1beQJM6Qxduuh9Y1Oq4kMLac3YYVz4a0tGTA+Gz48JXxZ+7
         AwvsKv4DgvF0M0aDg8P2FBN1jgH1o+H1gMg/UV5q1wRVMUaQTSwAAhdJpAvxJ8jQW9b6
         jcDA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXpfgilbdDQ3IViuWFwEaO69DANnxSwoq85GxSnAuUultTcSkFmQfPHv8IApyYvah0oxZMa6w==@lfdr.de
X-Gm-Message-State: AOJu0YykUZq2wXfCY9Xu1glM+WAHbIZxxMn/q4/mIIOiGYku8nzp7jsF
	Eq4EEJSXLFtUnPqXuhuoQzupT54aU46Hm9HXr66y2mCA5k+l22yuJ8Iu
X-Google-Smtp-Source: AGHT+IE4ExBh2aQbe1385/fWFN01Ylr3GPWVSv1tUx1hqdnCmdYZW9acXHBda7xcUSNXeWI/ZxLotw==
X-Received: by 2002:a05:600c:19ca:b0:477:94e3:8a96 with SMTP id 5b1f17b1804b1-4792af30f85mr30214815e9.20.1764777199229;
        Wed, 03 Dec 2025 07:53:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZhxfNvSGhMGcdU9B5pz6Vdd6uzzZ+XSmqOTReC0FUyTw=="
Received: by 2002:a05:600c:5297:b0:477:5582:def6 with SMTP id
 5b1f17b1804b1-4790fd73f19ls27655235e9.1.-pod-prod-03-eu; Wed, 03 Dec 2025
 07:53:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV0Yr+G6bY568P8TOOY0vO7eoWOle8+6mOnnEfYoWWTTlpebxX3u8mrWv9mP7mhYpMgh6hQmkjY0H8=@googlegroups.com
X-Received: by 2002:a05:600c:3152:b0:477:6d96:b3c8 with SMTP id 5b1f17b1804b1-4792af3d888mr26652585e9.23.1764777196321;
        Wed, 03 Dec 2025 07:53:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764777196; cv=none;
        d=google.com; s=arc-20240605;
        b=GLwxTItR0MHfjbkfeAClgcRAcr2f017uWB64QonYS/WeQ7jqCM3Y+pyt3v4f5bAuI9
         8dsmy3eN7xHSdsAnN//EvViN0lWZAg8BlLAZPKO5zB1V7RBFmMH+g5tduHP6IPMvRjqH
         OxwMURN0oUF0BzjMGT3vOjVH1ErDlF7yesFuOSIGwVp5rwjSgQLjjcpz+IRzbOSy5n5C
         vSqdVQzmqbFeMLgo+VVcXfNiH59m7HnTEJx3IRFdo5HAKTVUZkRCo3Ix1GVZyZKViGpP
         gcXJBBy0rJUTMMG3wX2gzRC3h3t3gDddbtXxfVEBf77B4pXhpBQgAPPYTUaMABesx8rs
         9uRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UbCXDQ9SqAkNCyhh2J6cLNmuXbzuNKSafExnU4lsLPE=;
        fh=oTpWcbl/SeBBtu4kEuxYUFmS1ZZYa89IJfl+vqFGhK8=;
        b=XR8vskVXwdAtkbvYCDmXx17NxeNgVLCkiTAoQqFp2qfPujrHLVsoa9G+1IkmOPYudB
         ycANEX46HBVCPULOIg12o4sK31ORzuRuaaylCMYFQseut9XMnjsajXLNrUoDvQqSu1LE
         RUTQV5+OC+i2/0nZmtjiKMtDdn80zdl4OqXtvKzjf2HUH8/izXwmZQe5pziqlzP5Q78h
         4C72hKYBexOjTJHLznjHKEi8w+jVowgwmpGW/B/6rOAImrnrJlFXsFcmpFTHCpqhLpnf
         f+KQ9QmQMppcdcmeBBzK4c2bsBEsclh113RkNwVZufkCSxawdF22iXR7GEF7fMG+Pdle
         evyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YWXbNUPB;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4792b02beedsi187175e9.1.2025.12.03.07.53.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Dec 2025 07:53:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-42e2d52c24dso2165286f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 03 Dec 2025 07:53:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUzH/SSmWiCqBcIxP4TegFbnL00NSyT1DpqVROZLcxerMnI7rSkjjPbgwpv55voLOElMvTQpNV7OvQ=@googlegroups.com
X-Gm-Gg: ASbGnctPSV5tZhnouEtrE7KIEkVyar3fSrzEkVuOXWia9PukFqNE0y7LlKVl+x8lAAI
	JrnRmZqwzqtq24CWDtrGc7+7HOtUyIV0zM2RlnxX9cl9XCqeEJsv+k4W1PgARoRwBsmxYTjFDG4
	isDhqynynSECrWSfBjtwIHz7n7QSmB+sPetP8l2ZLdKfcyRSmd/ybHib+593tU+sRYp0j3tGE/P
	UbposbizbclqVAEFGTwy+VSqOfegIRGUn0OfXHEyCL1xHnFLqa+uTLezzLwYkGlQmNqdNBkgE6Y
	lkt5k+tIajrk8mYfBAFc2LJIpH+tyLe+mg==
X-Received: by 2002:a05:6000:1449:b0:429:d170:b3d1 with SMTP id
 ffacd0b85a97d-42f7320bea0mr2896527f8f.59.1764777195326; Wed, 03 Dec 2025
 07:53:15 -0800 (PST)
MIME-Version: 1.0
References: <cover.1764685296.git.m.wieczorretman@pm.me> <3907c330d802e5b86bfe003485220de972aaac18.1764685296.git.m.wieczorretman@pm.me>
In-Reply-To: <3907c330d802e5b86bfe003485220de972aaac18.1764685296.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 3 Dec 2025 16:53:04 +0100
X-Gm-Features: AWmQ_blEBUtF_kyhGwNBKkD8DFVrkg1o4JirX5I6i5HJ0Jf545_FnpPgl_CXx1E
Message-ID: <CA+fCnZcNoLERGmjyVV=ykD62hPRkPua4AqKE083BBm6OHmGtPw@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kasan: Refactor pcpu kasan vmalloc unpoison
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	Marco Elver <elver@google.com>, stable@vger.kernel.org, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YWXbNUPB;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a
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
> Refactor code by reusing __kasan_unpoison_vmalloc in a new helper in
> preparation for the actual fix.
>
> Changelog v1 (after splitting of from the KASAN series):
> - Rewrite first paragraph of the patch message to point at the user
>   impact of the issue.
> - Move helper to common.c so it can be compiled in all KASAN modes.
>
> Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
> Cc: <stable@vger.kernel.org> # 6.1+
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v2:
> - Redo the whole patch so it's an actual refactor.
>
>  include/linux/kasan.h | 16 +++++++++++++---
>  mm/kasan/common.c     | 17 +++++++++++++++++
>  mm/kasan/hw_tags.c    | 15 +++++++++++++--
>  mm/kasan/shadow.c     | 16 ++++++++++++++--
>  mm/vmalloc.c          |  4 +---
>  5 files changed, 58 insertions(+), 10 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d12e1a5f5a9a..4a3d3dba9764 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -595,14 +595,14 @@ static inline void kasan_release_vmalloc(unsigned l=
ong start,
>
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
> -void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
> -                              kasan_vmalloc_flags_t flags);
> +void *__kasan_random_unpoison_vmalloc(const void *start, unsigned long s=
ize,
> +                                     kasan_vmalloc_flags_t flags);
>  static __always_inline void *kasan_unpoison_vmalloc(const void *start,
>                                                 unsigned long size,
>                                                 kasan_vmalloc_flags_t fla=
gs)
>  {
>         if (kasan_enabled())
> -               return __kasan_unpoison_vmalloc(start, size, flags);
> +               return __kasan_random_unpoison_vmalloc(start, size, flags=
);
>         return (void *)start;
>  }
>
> @@ -614,6 +614,11 @@ static __always_inline void kasan_poison_vmalloc(con=
st void *start,
>                 __kasan_poison_vmalloc(start, size);
>  }
>
> +void *__kasan_unpoison_vmap_areas(void *addr, unsigned long size,
> +                                 kasan_vmalloc_flags_t flags, u8 tag);
> +void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
> +                              kasan_vmalloc_flags_t flags);
> +
>  #else /* CONFIG_KASAN_VMALLOC */
>
>  static inline void kasan_populate_early_vm_area_shadow(void *start,
> @@ -638,6 +643,11 @@ static inline void *kasan_unpoison_vmalloc(const voi=
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
> index d4c14359feaf..7884ea7d13f9 100644
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
> +void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
> +                              kasan_vmalloc_flags_t flags)

kasan_unpoison_vmap_areas() needs to be defined in
inclunde/linux/kasan.h and call __kasan_unpoison_vmap_areas() when
kasan_enabled() =3D=3D true, similar to the other wrappers.

And check my comment for patch #2: with that, you should not need to
add so many new __helpers: just __kasan_unpoison_vmalloc and
__kasan_unpoison_vmap_areas should suffice.


> +{
> +       unsigned long size;
> +       void *addr;
> +       int area;
> +
> +       for (area =3D 0 ; area < nr_vms ; area++) {
> +               size =3D vms[area]->size;
> +               addr =3D vms[area]->addr;
> +               vms[area]->addr =3D __kasan_unpoison_vmap_areas(addr, siz=
e, flags);
> +       }
> +}
> +#endif
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 1c373cc4b3fa..4b7936a2bd6f 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -316,8 +316,8 @@ static void init_vmalloc_pages(const void *start, uns=
igned long size)
>         }
>  }
>
> -void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
> -                               kasan_vmalloc_flags_t flags)
> +static void *__kasan_unpoison_vmalloc(const void *start, unsigned long s=
ize,
> +                                     kasan_vmalloc_flags_t flags)
>  {
>         u8 tag;
>         unsigned long redzone_start, redzone_size;
> @@ -387,6 +387,12 @@ void *__kasan_unpoison_vmalloc(const void *start, un=
signed long size,
>         return (void *)start;
>  }
>
> +void *__kasan_random_unpoison_vmalloc(const void *start, unsigned long s=
ize,
> +                                     kasan_vmalloc_flags_t flags)
> +{
> +       return __kasan_unpoison_vmalloc(start, size, flags);
> +}
> +
>  void __kasan_poison_vmalloc(const void *start, unsigned long size)
>  {
>         /*
> @@ -396,6 +402,11 @@ void __kasan_poison_vmalloc(const void *start, unsig=
ned long size)
>          */
>  }
>
> +void *__kasan_unpoison_vmap_areas(void *addr, unsigned long size,
> +                                 kasan_vmalloc_flags_t flags, u8 tag)
> +{
> +       return __kasan_unpoison_vmalloc(addr, size, flags);
> +}
>  #endif
>
>  void kasan_enable_hw_tags(void)
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 5d2a876035d6..0a8d8bf6e9cf 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -624,8 +624,8 @@ void kasan_release_vmalloc(unsigned long start, unsig=
ned long end,
>         }
>  }
>
> -void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
> -                              kasan_vmalloc_flags_t flags)
> +static void *__kasan_unpoison_vmalloc(const void *start, unsigned long s=
ize,
> +                                     kasan_vmalloc_flags_t flags)
>  {
>         /*
>          * Software KASAN modes unpoison both VM_ALLOC and non-VM_ALLOC
> @@ -653,6 +653,18 @@ void *__kasan_unpoison_vmalloc(const void *start, un=
signed long size,
>         return (void *)start;
>  }
>
> +void *__kasan_random_unpoison_vmalloc(const void *start, unsigned long s=
ize,
> +                                     kasan_vmalloc_flags_t flags)
> +{
> +       return __kasan_unpoison_vmalloc(start, size, flags);
> +}
> +
> +void *__kasan_unpoison_vmap_areas(void *addr, unsigned long size,
> +                                 kasan_vmalloc_flags_t flags, u8 tag)
> +{
> +       return __kasan_unpoison_vmalloc(addr, size, flags);
> +}
> +
>  /*
>   * Poison the shadow for a vmalloc region. Called as part of the
>   * freeing process at the time the region is freed.
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 798b2ed21e46..32ecdb8cd4b8 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -4870,9 +4870,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned=
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
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcNoLERGmjyVV%3DykD62hPRkPua4AqKE083BBm6OHmGtPw%40mail.gmail.com.
