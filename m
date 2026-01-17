Return-Path: <kasan-dev+bncBDW2JDUY5AORBZ6FVPFQMGQEIN6PZ2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id B0324D38B0C
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Jan 2026 02:16:24 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-64d1982d980sf3514645a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 17:16:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768612584; cv=pass;
        d=google.com; s=arc-20240605;
        b=K3K9p8ep96VzFcvKD3amElR2RA2At8LRrD588+wAVq14yzAmvjCv4A9G6VS8z6bbHB
         s/3VC6Cn1KGuJyDJV00AY1Ymvzds4e6qBEfAFjOR6mlsJmYl+ZJbbZupb4r41oa0NC3e
         lOZhULUvMxFTviX+QE2gHpSxISF8HinYkI8NLlTKXdk+2bh9AeMHHEVl/1TyxhUMOrhT
         cRrTLVy1K5gFyuPW874YEI9qw8EGnmWFtgSBydTt9XAeb3yHI8ez8+7AiK9rz+pLw0bO
         r+0s2rVlXVSdyIL2MXZeH13Ez0Cd+fcJQXy+0l6kl5RWxiPNrP9DXPQebcDQqXTRpGto
         dRSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=9SIsb2JJmCMgyWSSosuW1X5IN/8A2ej0M1ibPqBOfBI=;
        fh=4hFIdVcASJI+zjYkCJY4lcrjD8w7XDQQEndOFMNivPA=;
        b=UU3MRm922HERRObI8twFQXu6b2PcJVpBNvjZN5M3uvSw7UcVLSjDTxsotPxiAG2Xgt
         lEop5519xpir/nl/Dnb0TvNY6qwwPXl8thaDMRePnzHNNVLG+G48cGF10ZvFyje98tz3
         rjhTtN2KVQt8aduOI/93AP242ym1wh+b4yntIJBfkq+FDcg+ZKqRXyfS/1Qa3Aie+zTN
         wgB8ogG8waB5OcZ7b+x9R6JbUS1Vm9AwR+cvJM9lU+Dwcxain6nVKA2WeuRdiU7Qm1ku
         JFwsj3v1ZavbqbaYOazZAVMi1Q2rX/epv0jB7IzQiedZ0JdGXoyJeGB0TKA53hgJQGzr
         lZFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CNiQFlHT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768612584; x=1769217384; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9SIsb2JJmCMgyWSSosuW1X5IN/8A2ej0M1ibPqBOfBI=;
        b=V1xypONRTcL1uohaJccvTCSdTkV0NZVo1rkURkeq1MP5nbSYEOJqoAmNY2g7gyzlxx
         9FGB3qqq0pm70aJ0ZdXLVHvJHVxZro/1A9ymJzO8frVAehH1AaMPR6iyso+2ZynqqYOs
         E5Nxef+pyNoUT/VDo7QAXR97fkLPmhJqwuDgGIuOYKz+3aG8aKdSfDdRS7No4FfAV+i1
         YxDKZDAhuV5yUC3pW1GzNOC8iGO37f0S7mNb4HwXuwIQhrEUQTYFpFSfAmVwXXz1Nfh8
         kHS/XKA5U2qI36+L433UXF2cHad1qZrpD7Rupw23dvw0I9Vnkp0NSbpOstQ8FYiPwBPz
         JfZw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768612584; x=1769217384; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9SIsb2JJmCMgyWSSosuW1X5IN/8A2ej0M1ibPqBOfBI=;
        b=ePevTEe33ACuIytKZXvGchzF+nokabojpDh1C+0bzyFLVug7pea3XIzSw5PKbwcfj8
         nTCUXCV2Llsh3QjCUCmL6pXabhPa0FfcTQtH9UJ1D/01/EDhNwA4CUcYfyshWbwIvp+c
         a8tdQb4nq+E1uV8blYO31zDritQxq+JpeAyqYPwbskFkLv45/Z+auidpzMYyfnNSNIYs
         e41Pp7MfJOzFpfus6rr3eqjIexMg6TVh4piZU2vpWA14VFbU0UCdfcZgPu1EExYWjGhm
         jLpjY8VxoCICoz9Apsrux2b7Vs/B5A9AjWCiNasexXTxyJ4dB62aQO/R4FliLFZOpVbX
         XxLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768612584; x=1769217384;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9SIsb2JJmCMgyWSSosuW1X5IN/8A2ej0M1ibPqBOfBI=;
        b=Ua7fm4HI193hTUjCV28GtZAd/NCHyD6a61l98p9MAffBMqFliwBpEXFPtJ4jAYawDw
         RBmKUAkkzYrkeGijzsjYnKfI5vaTZd7ectOEQDaywSam1XT3/GSbd8kWY96bZk54akrY
         WdBKWovCgOMEpL8sDuACfYE6Wm+5da56W+7y1bytxVHBmSq1klULvtxo7j7QvP5f17l/
         yLFkCbv3tZKeUq/Q6Y8/Zikcf20tSNlhmrv0SxnyzUa/WFDoR+75IgiqghHBi/2tSWMJ
         D1mo/9Sck4f9zpS4D4cF6mhyKNIjEmLHEJZfeFH0mm9SZNs17oskUaisR8PTtE2kJihh
         USmg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUkMoss8f5zvxnBi5pt4wGbglaviGdTC7qCQJCTFS93OiBSEWluIlGSh8I/6NSomH0ZLhfV4Q==@lfdr.de
X-Gm-Message-State: AOJu0Yxz4pU+5FVY3whIVIffrtgCX9pxUrcOYZ8FaAK/0SKEOVgp57dz
	iL6In1xolR74MSpAMWzgcaTek12Ks3ojXXhlxHgcy/oCJ4ZfdZQcG2dG
X-Received: by 2002:a05:6402:370a:b0:655:c395:457f with SMTP id 4fb4d7f45d1cf-655c3954878mr2150289a12.33.1768612584137;
        Fri, 16 Jan 2026 17:16:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H8q8j8Tc67u+wqAS5rcxGpeLQhqOPhMIs4Pz00wi7lwg=="
Received: by 2002:a50:bb26:0:b0:64b:6a4a:52d1 with SMTP id 4fb4d7f45d1cf-6541c5da4c1ls2133538a12.1.-pod-prod-05-eu;
 Fri, 16 Jan 2026 17:16:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV/z6ann63pNZPr50Jhkw9DNLdJP5QvC+tzSHJBZJ7f3yscS7AflA5XP3qSmeHPjyfI3CtoLYDKU9o=@googlegroups.com
X-Received: by 2002:a05:6402:399a:b0:64b:58c0:a393 with SMTP id 4fb4d7f45d1cf-654bb61abd3mr2382376a12.30.1768612581871;
        Fri, 16 Jan 2026 17:16:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768612581; cv=none;
        d=google.com; s=arc-20240605;
        b=Gbd3QbQLuLk9O66b+CYw51h9iPcYZERscoCvo0u3RC/LegM73arCgDtwBE4ii88v2+
         DUgqQ1j3GCawuJCIlF3CNI4hSqr9+1qXMp782OTfP5KrY4G4NA34iy4N0WCAJJLkuVnS
         Guga8/ma694XvZZZMoI2WnkE4h9GXPeXvEdS7wizD/pLYc6cNovfnuo0xse0NxlGsGW3
         hbb/nvi6MmUYilw/CiwuPcprWVpHDQZx7zXLR5eYY/2v5LvahMh1LgNxnLTDXyCE7FVL
         xi6EjN9aTbpV+tqHZ2Amlp5A8XjLrd3q0QlPTN8KwxJW80iZtLYpZb/RU/BCqz+TLT2x
         SIiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8jacRTGEGX5vlMnwDO2iTbDAhG4zdHGWsi458RG2c5M=;
        fh=oYKESVTVrSiEZGUVvT7idYlPenw0V2Kb0TLdJIWLwxk=;
        b=WTKdqqYCNWgI7vIFHV0BxZoV5R7i6M+0VKzKxTJDyYa+Y67pgZE41SHKSchUqx/x/1
         UcdtS9cF5o+yAAdOmWRJgxsHK1N+KbgxeVAT4Rc9uuLCGObUGdABJE+mYUbBYwCebGj8
         6boVh3CeLxdpX6sf8mcKlXMjYxmKWbMZ/bARJi34N0w33e6htW2t6JNyXZzzGSyk82Wd
         i8pPoZz5EYoBoyM3Ge3zRG23hkqoZofb9fZ2f0+uSuKi5NU0jgHrvW/hn/tmMjCkL1Fo
         250NWSOmXiHaoD0xyUChyldH+3zj1YFjqpUXRiBIKcIidLgjOD8vJyxoVkRDozLGuLQC
         6akA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CNiQFlHT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654532d75d9si96790a12.8.2026.01.16.17.16.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 17:16:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-47ee301a06aso23110005e9.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 17:16:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUw9DgHZQhJHB5EsXU0aSu+Kkn/MbZ3mC7q5ilXfuN65CxjE+da4ATBdoNVuIdjxcsc4UqEupW/TVY=@googlegroups.com
X-Gm-Gg: AY/fxX5yxYy90QwEb1JWqmSdHZ/Z9mylIQsyD7xz2uZWXvbHn18xCeSu9OEogVdYSPp
	nGLLw1YL1zSRREpwKFxm4ph83TzyYBPyFrFG2+jUUQfF2Z3op0tXDKa2j1D0/TAREDiRXvRXM5m
	tILBExxvqu3zB00QxnoE34fKXGs9hJrooudQgnJuMxXu8eZ4CpsRxUM+iuClKfPSSTdHyXiknVK
	QRLqGFJOzPLw8F0IqGfqQ/LZfjGi0PR1lwWqswl1ukG90Rwr0XkxQhAOJCbsTP82GIKTPERxiwB
	bYCq9+oj7nnjDSBAPUxND1g/w4J7
X-Received: by 2002:a05:600c:45d1:b0:480:1d16:2538 with SMTP id
 5b1f17b1804b1-4801eb03358mr43804885e9.23.1768612581229; Fri, 16 Jan 2026
 17:16:21 -0800 (PST)
MIME-Version: 1.0
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <20260113191516.31015-1-ryabinin.a.a@gmail.com> <CA+fCnZe0RQOv8gppvs7PoH2r4QazWs+PJTpw+S-Krj6cx22qbA@mail.gmail.com>
 <10812bb1-58c3-45c9-bae4-428ce2d8effd@gmail.com>
In-Reply-To: <10812bb1-58c3-45c9-bae4-428ce2d8effd@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 17 Jan 2026 02:16:10 +0100
X-Gm-Features: AZwV_Qgw2efsxw5nCGxgrSSMx3DQz0LNWwfRwrPgK6uICIY1gvifMYqiZzjGO_4
Message-ID: <CA+fCnZeDaNG+hXq1kP2uEX1V4ZY=PNg_M8Ljfwoi9i+4qGSm6A@mail.gmail.com>
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
 header.i=@gmail.com header.s=20230601 header.b=CNiQFlHT;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c
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

On Fri, Jan 16, 2026 at 2:26=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail=
.com> wrote:
>
> So something like bellow I guess.

Yeah, looks good.

> I think this would actually have the opposite effect and make the code ha=
rder to follow.
> Introducing an extra wrapper adds another layer of indirection and more b=
oilerplate, which
> makes the control flow less obvious and the code harder to navigate and g=
rep.
>
> And what's the benefit here? I don't clearly see it.

One functional benefit is when HW_TAGS mode enabled in .config but
disabled via command-line, we avoid a function call into KASAN
runtime.

From the readability perspective, what we had before the recent
clean-up was an assortment of kasan_enabled/kasan_arch_ready checks in
lower-level KASAN functions, which made it hard to figure out what
actually happens when KASAN is not enabled. And these high-level
checks make it more clear. At least in my opinion.


>
> ---
>  include/linux/kasan.h | 10 +++++++++-
>  mm/kasan/shadow.c     |  5 +----
>  2 files changed, 10 insertions(+), 5 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index ff27712dd3c8..338a1921a50a 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -641,9 +641,17 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, in=
t nr_vms,
>                 __kasan_unpoison_vmap_areas(vms, nr_vms, flags);
>  }
>
> -void kasan_vrealloc(const void *start, unsigned long old_size,
> +void __kasan_vrealloc(const void *start, unsigned long old_size,
>                 unsigned long new_size);
>
> +static __always_inline void kasan_vrealloc(const void *start,
> +                                       unsigned long old_size,
> +                                       unsigned long new_size)
> +{
> +       if (kasan_enabled())
> +               __kasan_vrealloc(start, old_size, new_size);
> +}
> +
>  #else /* CONFIG_KASAN_VMALLOC */
>
>  static inline void kasan_populate_early_vm_area_shadow(void *start,
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index e9b6b2d8e651..29b0d0d38b40 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -651,12 +651,9 @@ void __kasan_poison_vmalloc(const void *start, unsig=
ned long size)
>         kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
>  }
>
> -void kasan_vrealloc(const void *addr, unsigned long old_size,
> +void __kasan_vrealloc(const void *addr, unsigned long old_size,
>                 unsigned long new_size)
>  {
> -       if (!kasan_enabled())
> -               return;
> -
>         if (new_size < old_size) {
>                 kasan_poison_last_granule(addr, new_size);
>
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
A%2BfCnZeDaNG%2BhXq1kP2uEX1V4ZY%3DPNg_M8Ljfwoi9i%2B4qGSm6A%40mail.gmail.com=
.
