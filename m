Return-Path: <kasan-dev+bncBDW2JDUY5AORB3GKUHFQMGQEZSGJ6QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 00B7CD2255E
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 04:56:29 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59b6a320b35sf481080e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 19:56:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768449389; cv=pass;
        d=google.com; s=arc-20240605;
        b=AoLKCl0Ad2LaPPjh5JCyuU4O74vnuwPbYPX1aq51OkEiWm3nXywdrllwtLOg6/j74R
         fScU+GSg2QzXK07xLXvWRY+BI9YbOpJx0FAJmuQLlcVm+15vQ3zFojk8QNk1UpEBQGl9
         9g67ETqEFkyXMBe2aReC80wEXZgyB7qqXlnpd4TeEymT5XjNnLXoQTmFQpkir3eDHOWi
         dMX0d8iPxPFWqeQUF1epjq89v5wW6+x+u/Xfj8cnEY8VDz9nBzsaUfuhBWi1b4YVtj4b
         //6ggQSs3SPNEprqxJHi16qObO5L8RaLmzhTmIqzUi0JoAxUa5lmDIJFCjedlL2iKyaE
         FF/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=9tS63GlraVQbs8oIPJuHDS+JwCWK3rN+AabTxK3AGGQ=;
        fh=+SLw3GKEXieyKCr+L7DqCBg39eTwPyxZmd3aZDZeYjY=;
        b=Kz1GzUCe/A8N65adW9nuTWpstcr/0dKH5HTLggH74eABHVUHmJXyYyWyBJQVcKkS/r
         UERIibZS1hZcbW/4HqsTkWVXQlkR9n2gdmzXguvnl0gRYmoSQGjmBqqw+zqoQW+b23Dz
         4ygXaVuGuTcU8mpuXR4aoeP127jyI6IX7OjF9Izx6H9icUpoRsNn06tNqk6y7TX5dCD3
         QZRH2o3IA5eCFdt2CRdFYyETy1J9wDm5gfN+qVFvhc83pxhyTo32EFAA3whacUk1VBFe
         XGmvSI7mFbqSoBNAJnMSMsIhC6jm8Z51tZWLXd1becr8CVX38DuEhM5vOr94ecw773aA
         zq/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ak4DmLOW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768449389; x=1769054189; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9tS63GlraVQbs8oIPJuHDS+JwCWK3rN+AabTxK3AGGQ=;
        b=nG/Nn9VWlyAIfNzSCrlhoOE0HRcEYXH9WIIpkuGpFnE/eIQ1K+H+rwZAK39bUaxhck
         /PA+bOaS83+7zqAjX0oOcIake0eckCCQtVY0J1wBSdYceFu0JpawnJKIRKJA0dyZr70W
         /nOzr0oRRqeKzzl0aHRRb5a+tODWxO5YGxKrph0fzSjTfALItw5hE58HZhreLHtUi4k+
         9VRxTFtCDqkmfmMeqzCqZ2sPjOCqIKO4HMnW7RYh+w7JIvhoRu8vBLyzxL7ytHXI88/7
         ORddYMHAwvqCZxkqA+/xPlu2b8x2b2XHYHX1ukrdBQtpdu6Dg/XbWtUtEMG5oZq/JBZa
         sNyA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768449389; x=1769054189; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9tS63GlraVQbs8oIPJuHDS+JwCWK3rN+AabTxK3AGGQ=;
        b=dggj3djyp87ktshw49ycrRCejE30l9UG0oTpTnC9b1ED0+1ohAQYNhiXYIIUmBGOPi
         6fDsCsqlAf4JRLDrkZw36nu63i6uw1RmducP//fyHnjahSuRKEyPeep7eB5PCW1CI6Iu
         h2Umww2/R6jsHo9UDxulaQ+DPIc3rePm7cHCc3tRYHhN1qpFhtJFuz8jLWmVz4C0Qs5e
         6XxrC27+etPQRBeb1oppZiYIGVTEXvBDxqnpqGCxNO5SzgXeVhh0T873gbPFxjsSi5vK
         tvA98qqOiQSdUCDp2bjTHtWxlbGFT2PBDkzXV62+hMqnk/tyB60YBciTalCVepxzhY4R
         KcPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768449389; x=1769054189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9tS63GlraVQbs8oIPJuHDS+JwCWK3rN+AabTxK3AGGQ=;
        b=knWJv36KpVsL2cxbAoG/xh8BuhI74SKfw26sHw+5gFWgiswYHrDWI+U2RrysDGyT7R
         Un6ynBCcCFg5f4RM8WvW8BsEH/WT8O4p+H9aTZcuE3APzVsxHbV77p53lKaBkmPwyceu
         z7Vyq+Gm2HuOYwy7UHrFHf2PFpCprQoFfFMeq3/CvHM+ysmDgAjkC7mr22Zl4dt0V3hv
         iIK33/Mjm81GQfPTtFstj45ZwznjXcGamhajP3hljZAWn4w5EbcgoM6Rok0Ta/pHrReo
         EatZxjIZXseXVHcJ39KptXPJ9omqHBlG2TWc9a/QA5e7jv9TxCKOHY1Zxc+fZ5WZoeRm
         QkBQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhFYq462TOBTHcrlPojRqLPxk7LIi6+c/GI9eZ6oBHYxsnF/VVIbqGefRWkV6IbkOqqV6OGg==@lfdr.de
X-Gm-Message-State: AOJu0YyR0SEMbQxJFVvU5YXSp+Roy691lJLyMs29p3+YtOHJg5pRDNmx
	+sQuEMhLj9/r+c6Cp4/wwf4nGxkbniGke0Fdl4FgpsG9z7dhpCZRQf2+
X-Received: by 2002:a05:6512:3d2a:b0:59b:572e:83e8 with SMTP id 2adb3069b0e04-59ba719cdafmr527693e87.24.1768449388700;
        Wed, 14 Jan 2026 19:56:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GFfrenkU5cmcNuCLfzyRzgal06VJoHZs0BxUB5ctsN4w=="
Received: by 2002:a05:6512:b9d:b0:59b:8bd6:838 with SMTP id
 2adb3069b0e04-59ba7185cabls219725e87.1.-pod-prod-00-eu; Wed, 14 Jan 2026
 19:56:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU7mvWr5A6ICGgebxWpNZRcX/PyXYezPoERO8/JZffmUYOwI9rNPrJP3DxDendcOWAiCF+nHElFObc=@googlegroups.com
X-Received: by 2002:a2e:7309:0:b0:383:145:b09a with SMTP id 38308e7fff4ca-3836f0caa05mr4190341fa.19.1768449385965;
        Wed, 14 Jan 2026 19:56:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768449385; cv=none;
        d=google.com; s=arc-20240605;
        b=Yp7DGJMYbX1dXUI+OaRr03N2uoytrb4XQ7MkYoYHkxPxTQ0Tq0MH5pobN13VQyZey0
         rmDDchERF/Vn+m7uCtKJFcOQnGRglpmagpk5tCuHUI91xiUQYiL03GO1V/M6SgYhta+w
         R/4Xs3q0o5tTG84XCM2vrXbtvSOZHwJiX0NfDoLF5vyeNYB1J3UgwiR2OZxrFF0VzAQf
         /gJkEGMkIHwb2TTD3Iga/JwTer/bbYi+CZcDO1tUFjAwJ8qf/EovlmZO77AuUUFJbvw5
         NDgIJAvzjPkwX+oO/rsdEipWxcqSDfLKDqFjgk286Wz7WMWWFvxPBWO5lUtMkxYA5DdV
         Wjbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Z8h4CNT/vCdwT2WHgzViB1V6HoWHqUEOSKi1RhGen4M=;
        fh=jasKiYXB2Ne3eBXy8R66eoqKHUD0r0iQ3yGo76G05DA=;
        b=S3EpTmR/LCxANUrPPQPWlTzwxXrlGFoIP9LSc0/BUpEYWtCXB5Rj//yyIk6cqg34G/
         dBQwcnYt6RDe9JSV9xvbdMGf6604A03sJqeMe7z+Z60fjERxKRn0cg3JWlVsB9w7SHzO
         pn1OOvr6xl1GrkGlUudN4i6ROkZX/TuRm7JwikbecwopfkXYx3M/g6Pik4EJ6ttEtN+Q
         OMCm7i7T2gKiJCK1Qg/p1smSLV0f5I+f69G9xpfrRC1GwupHQsXKegrAtZWoW/1MuBVK
         /mcwCiPR6ijhxXxmNZsVf+b7Qu7/7dTialqyJw+yQLwY04/4Ppj3jgq/McMhXDqBTbG2
         f6Tg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ak4DmLOW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3830647c24csi4732211fa.4.2026.01.14.19.56.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jan 2026 19:56:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-43246af170aso199066f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Jan 2026 19:56:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWt2fq6cSTqy9AkvjOfHJE4eDFt90sOkK4/+wifvjCg45HZGlyeu8c/hNcw+6FV2lKXFcLTwYEfWzc=@googlegroups.com
X-Gm-Gg: AY/fxX6M7X3YPlo0wW7jes+9N3rdPeOZ9rqDqBpre9TjlEUnpUEbZtKJ0dmioI+ABGW
	XeN/nVOnfN6PwOHztkU83WHaH/LUP2Y9qIS1LmBpWLy43thLgOXT3EDPSuHHwT2ng57Jy1YvXdE
	QdkMSOHP1Mlm1U5IyYdYXSvzQjOGaQKzLPS0Ads7XzxejFYdhE+oQ1R/5/x9bCQRiC/Y0en5ka8
	gvRIPGYFCcHj1y/ps1e0iZjEXbHmGeryGQrZh7XXtedxaPht+qy2RiN/fRrwFwTeuXvK526Q7+k
	SLG/DoFqlkSsbuww238x6iYeos031g==
X-Received: by 2002:a05:6000:2f82:b0:431:1c7:f967 with SMTP id
 ffacd0b85a97d-434d7580e3cmr1957942f8f.17.1768449384919; Wed, 14 Jan 2026
 19:56:24 -0800 (PST)
MIME-Version: 1.0
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <20260113191516.31015-1-ryabinin.a.a@gmail.com>
In-Reply-To: <20260113191516.31015-1-ryabinin.a.a@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 15 Jan 2026 04:56:14 +0100
X-Gm-Features: AZwV_Qj2HFEg_msWenRDyDr9jlnYYzEBrAIjJPlBfTu53BTl1ZMgAQjnko_IfdI
Message-ID: <CA+fCnZe0RQOv8gppvs7PoH2r4QazWs+PJTpw+S-Krj6cx22qbA@mail.gmail.com>
Subject: Re: [PATCH 1/2] mm/kasan: Fix KASAN poisoning in vrealloc()
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>, 
	Maciej Wieczor-Retman <m.wieczorretman@pm.me>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Uladzislau Rezki <urezki@gmail.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, joonki.min@samsung-slsi.corp-partner.google.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Ak4DmLOW;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
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

On Tue, Jan 13, 2026 at 8:16=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail=
.com> wrote:
>
> A KASAN warning can be triggered when vrealloc() changes the requested
> size to a value that is not aligned to KASAN_GRANULE_SIZE.
>
>     ------------[ cut here ]------------
>     WARNING: CPU: 2 PID: 1 at mm/kasan/shadow.c:174 kasan_unpoison+0x40/0=
x48
>     ...
>     pc : kasan_unpoison+0x40/0x48
>     lr : __kasan_unpoison_vmalloc+0x40/0x68
>     Call trace:
>      kasan_unpoison+0x40/0x48 (P)
>      vrealloc_node_align_noprof+0x200/0x320
>      bpf_patch_insn_data+0x90/0x2f0
>      convert_ctx_accesses+0x8c0/0x1158
>      bpf_check+0x1488/0x1900
>      bpf_prog_load+0xd20/0x1258
>      __sys_bpf+0x96c/0xdf0
>      __arm64_sys_bpf+0x50/0xa0
>      invoke_syscall+0x90/0x160
>
> Introduce a dedicated kasan_vrealloc() helper that centralizes
> KASAN handling for vmalloc reallocations. The helper accounts for KASAN
> granule alignment when growing or shrinking an allocation and ensures
> that partial granules are handled correctly.
>
> Use this helper from vrealloc_node_align_noprof() to fix poisoning
> logic.
>
> Reported-by: Maciej =C5=BBenczykowski <maze@google.com>
> Reported-by: <joonki.min@samsung-slsi.corp-partner.google.com>
> Closes: https://lkml.kernel.org/r/CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm=
08oLO3odYFrA@mail.gmail.com
> Fixes: d699440f58ce ("mm: fix vrealloc()'s KASAN poisoning logic")
> Cc: stable@vger.kernel.org
> Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> ---
>  include/linux/kasan.h |  6 ++++++
>  mm/kasan/shadow.c     | 24 ++++++++++++++++++++++++
>  mm/vmalloc.c          |  7 ++-----
>  3 files changed, 32 insertions(+), 5 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 9c6ac4b62eb9..ff27712dd3c8 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -641,6 +641,9 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, int=
 nr_vms,
>                 __kasan_unpoison_vmap_areas(vms, nr_vms, flags);
>  }
>
> +void kasan_vrealloc(const void *start, unsigned long old_size,
> +               unsigned long new_size);
> +
>  #else /* CONFIG_KASAN_VMALLOC */
>
>  static inline void kasan_populate_early_vm_area_shadow(void *start,
> @@ -670,6 +673,9 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, int=
 nr_vms,
>                           kasan_vmalloc_flags_t flags)
>  { }
>
> +static inline void kasan_vrealloc(const void *start, unsigned long old_s=
ize,
> +                               unsigned long new_size) { }
> +
>  #endif /* CONFIG_KASAN_VMALLOC */
>
>  #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && =
\
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 32fbdf759ea2..e9b6b2d8e651 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -651,6 +651,30 @@ void __kasan_poison_vmalloc(const void *start, unsig=
ned long size)
>         kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
>  }
>
> +void kasan_vrealloc(const void *addr, unsigned long old_size,
> +               unsigned long new_size)
> +{
> +       if (!kasan_enabled())
> +               return;

Please move this check to include/linux/kasan.h and add
__kasan_vrealloc, similar to other hooks.

Otherwise, these kasan_enabled() checks eventually start creeping into
lower-level KASAN functions, and this makes the logic hard to follow.
We recently cleaned up most of these checks.

> +
> +       if (new_size < old_size) {
> +               kasan_poison_last_granule(addr, new_size);
> +
> +               new_size =3D round_up(new_size, KASAN_GRANULE_SIZE);
> +               old_size =3D round_up(old_size, KASAN_GRANULE_SIZE);
> +               if (new_size < old_size)
> +                       __kasan_poison_vmalloc(addr + new_size,
> +                                       old_size - new_size);
> +       } else if (new_size > old_size) {
> +               old_size =3D round_down(old_size, KASAN_GRANULE_SIZE);
> +               __kasan_unpoison_vmalloc(addr + old_size,
> +                                       new_size - old_size,
> +                                       KASAN_VMALLOC_PROT_NORMAL |
> +                                       KASAN_VMALLOC_VM_ALLOC |
> +                                       KASAN_VMALLOC_KEEP_TAG);
> +       }
> +}
> +
>  #else /* CONFIG_KASAN_VMALLOC */
>
>  int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 41dd01e8430c..2536d34df058 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -4322,7 +4322,7 @@ void *vrealloc_node_align_noprof(const void *p, siz=
e_t size, unsigned long align
>                 if (want_init_on_free() || want_init_on_alloc(flags))
>                         memset((void *)p + size, 0, old_size - size);
>                 vm->requested_size =3D size;
> -               kasan_poison_vmalloc(p + size, old_size - size);
> +               kasan_vrealloc(p, old_size, size);
>                 return (void *)p;
>         }
>
> @@ -4330,16 +4330,13 @@ void *vrealloc_node_align_noprof(const void *p, s=
ize_t size, unsigned long align
>          * We already have the bytes available in the allocation; use the=
m.
>          */
>         if (size <=3D alloced_size) {
> -               kasan_unpoison_vmalloc(p + old_size, size - old_size,
> -                                      KASAN_VMALLOC_PROT_NORMAL |
> -                                      KASAN_VMALLOC_VM_ALLOC |
> -                                      KASAN_VMALLOC_KEEP_TAG);
>                 /*
>                  * No need to zero memory here, as unused memory will hav=
e
>                  * already been zeroed at initial allocation time or duri=
ng
>                  * realloc shrink time.
>                  */
>                 vm->requested_size =3D size;
> +               kasan_vrealloc(p, old_size, size);
>                 return (void *)p;
>         }
>
> --
> 2.52.0
>

With the change mentioned above:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZe0RQOv8gppvs7PoH2r4QazWs%2BPJTpw%2BS-Krj6cx22qbA%40mail.gmail.com.
