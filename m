Return-Path: <kasan-dev+bncBDW2JDUY5AORBUHMTCGQMGQEBKXP6LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FCC04636C3
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 15:33:54 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id u197-20020acaabce000000b002a820308b14sf13958917oie.12
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 06:33:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638282833; cv=pass;
        d=google.com; s=arc-20160816;
        b=DmBYyjpulG6lgXd9uWqxGUgMHzf5skpny4fY68GsK9xdE5dN7fGJ5at1aNGAEP9yFZ
         zOo655XNxp4p3MjMJLrOgPWvmn99yJQN017xDAl1ViYcWFe/ubK6YNOG1ofQ98K3gA9n
         yFQ+w5aqkMlJPfC/JB2rNYFCyT76lUV9wrVvRgA+uwu3DKBD8pt5G3UtKMWRYZ3wEqFK
         iIq/EY09iOUQ83XC6ygVcw//UtUBr8cv8niCtPbJFJod/rhW7sYdFvVI6JuDAVqlOsw4
         4hwOWBsKvz+iuoBf6d+ydO1vkMTNHKrIUhpUd6P6yK+IE0Z5p2lBA9PH2VoZbVbbtQWH
         vIiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=/xBXQsVb06Mi3xXhpAqbPyY/g81VEUeJUtavISN++9M=;
        b=GtXmYnPabjihZ/OYF8/Ur8OvwsdIpGoMy0y3mIl2s56kFgej7HeRI6O1WT/MIv+A9F
         7y7Mu61s94hzOIjysmxJA6dE9NgPLwFIqZbd7dgMUEWTKZ830NhOOpmMXQFWMmAavB8W
         19AFc26kZoN2ggTzCwpvSRg80SL1CaSNLLOT/vJ0Yv2Sv/pqGqThJOnFGY8VQ4Mst6v0
         QjDZ+tYS6uGiWTp4ZJ317vk7bLIziky8n6cMrHmGNkDyGdHW+1kR1Q3Z3RxwlJXxRIHr
         OwapIw4IWaN9uYVDb67B5q1Ki54lOqPpKSohXjwrGG6qsiVnWNOiVrM5KOKrZIiO1nr8
         7vzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=DTpy4LJX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/xBXQsVb06Mi3xXhpAqbPyY/g81VEUeJUtavISN++9M=;
        b=erVIFWLHe7dUmtUKtydI9WiSu4VpXbmMkdxtymzvajwhfvRYCowpOLtgZ13mbJFRua
         7vttSVI9lmI4MfSCAdI8uo8pf10A+fV5kAMFeHArQl+P25srjIl+d7GijRAQTZ/AfeaX
         HxNB85QCPxPWffGy5DQ3D+9cUIiB6enDYYPelBsfPe4aYmj45DRl8OD7JlcR+S0ugEpy
         a73OCZBJIS5HpxJN7bATbiAdRn+g/W9lZzK+sEGsbmwFdVpwebB8rXJodznZr57LEtKR
         UWIH2VqWvWUWMqaj+iHN/h9DwbZvPIZrPFa/NW3XhAYXQzGumG4TUVOxWHLL5fQM8W+m
         4pvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/xBXQsVb06Mi3xXhpAqbPyY/g81VEUeJUtavISN++9M=;
        b=V8wDFdwP+uDDc38mrTWxFY26ti4jW81z/87aO+IpJQ9UgjgiUrpqL5d3RJlXuMV6T7
         xaQbgv08mOu9JJj32I4DLK6GgcMOS2EilIg2nz63vCu5DzgJLBd5SPPimyyQfAR61lKt
         FKkOfMTBzcBasZvDMXP5Iwp3JirKpyYl43y7ZFtyOlXIo5pgEcXpKjKy1O+SSBw7XlbM
         y907gexUct/oYNyJR2V+kLZAc+CnWi80KnmhFBk759YOHSL1L3G+/DeAUzCHxt7gw5hD
         IuhoKk2iPQCpnHslkOAjfjmmr2/T32ypJ3tmFqQVMwKyJtuL0r2Txjd5pu2XijRARZQz
         eYEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/xBXQsVb06Mi3xXhpAqbPyY/g81VEUeJUtavISN++9M=;
        b=aG5sDSS/3yhss5fvCFzx2Uf5d0U2Xz9W9Ywfl6ZLI4GIbEj1ozbyo0gUI58HiVF6ld
         VXSfks0vxEIn00fhZYOTOVaqJDxJDLGzMuEQu47ch+2hZxsqDv96e2qlnIz426iEJOXn
         7xAl5YfAwRVzPjLA3Qdmom/i2yLNgLfyD8UVHllOB0W244KUcOgLOORo2MHtxIydDroH
         YtWzLoQ1Bkt8wjmcX2rzgR1Gr/M6laRAqxmTC3/uaOn7348Ff2owWXuu91wmAYvvfBoj
         UdikqSNC3sAAqlkgx00LGQeSut1JS2qEk5VKqWNgOTzR7Fk5n9qJEmUFdPPODR+s+1+I
         oYXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532f84Htjn8h7HLEtGregE7kuIXdlCUzrUr5li8JQF2lmdXI6/6/
	yCnu/myY0bMci5attRmQU/g=
X-Google-Smtp-Source: ABdhPJxBiVyew0mXEPBjXika6KNd2lLXCTNXHIjgwe1bHMBotGo7UUyJ2f/R3X1dNEjbJsXWklmxEw==
X-Received: by 2002:a4a:b20c:: with SMTP id d12mr17998664ooo.87.1638282832905;
        Tue, 30 Nov 2021 06:33:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:58c9:: with SMTP id f192ls1077834oob.6.gmail; Tue, 30
 Nov 2021 06:33:52 -0800 (PST)
X-Received: by 2002:a4a:bb90:: with SMTP id h16mr35248454oop.20.1638282832544;
        Tue, 30 Nov 2021 06:33:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638282832; cv=none;
        d=google.com; s=arc-20160816;
        b=Y0X90f0/QlYiFubsdmM40Q3Er5eEV+iEG319dkGhzfYLXlOZFWAFgUXHh2N1V0CEz9
         m91rTiaGIumDeB6lIiuFtOMf8iPYvnVKDeHHJ6bMP4JNPMh4jR0LVT3aOuCeC+j5ZHwA
         YT1W2CdfHfu2635I1dph9BREvmV1pONZ8O6j+7vQE/oen08yXNd19+cTDNPpVGhxk7Va
         K8zlYJb7mslEsMoaBgm4rqON7FsmAKNgEtHQmp0ZKd/A8MU6a25i8KIie3f8j5O0mqt2
         BYxRUqCVbsj/zsbOgzta6wwkmyhD2Rd+Qd7AQ7YvfwWOQb5KeS2QQyzEsY4xuiNGhDB1
         KHCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KvFvndBl4Bydux7YEgvSu6yBLgLtvHPAwDkKBUzy3MQ=;
        b=DYlIPHgNExYwPsjEeigBM24i6HqP8t80jPryBbNFwPxR6vKpsiiIq0IctE04repllW
         3qXgkhKYn3Fat2gtmWTaPquWY74nTEJXvsoV8cfyWIZ6Ug7TJa/boyGnp65hZkj5quvC
         ig4xJmaMO1sQOFUdoseldnvhUS50dbM92fqygTXjJ87vgoYQ0GI32SdVlVzfHMdnf44S
         MH2MiOCDvO29k2UCYF30YTIP+KCGMHu/q3210bCrlDsDQi1/IfIKn9tbXGdVeUVtgV5F
         Ab+9YvqhxQ0pvyIHAUxhfQ/dOQE8uCcy/9oqWpOF4WMUvA/hCKW7O5gZbfLYd6zCk8ol
         MtbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=DTpy4LJX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd29.google.com (mail-io1-xd29.google.com. [2607:f8b0:4864:20::d29])
        by gmr-mx.google.com with ESMTPS id be25si1027196oib.3.2021.11.30.06.33.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 06:33:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) client-ip=2607:f8b0:4864:20::d29;
Received: by mail-io1-xd29.google.com with SMTP id c3so26302085iob.6
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 06:33:52 -0800 (PST)
X-Received: by 2002:a05:6638:2257:: with SMTP id m23mr72343928jas.17.1638282832252;
 Tue, 30 Nov 2021 06:33:52 -0800 (PST)
MIME-Version: 1.0
References: <20211130095727.2378739-1-elver@google.com>
In-Reply-To: <20211130095727.2378739-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 30 Nov 2021 15:33:41 +0100
Message-ID: <CA+fCnZdO4OqLqUyCJ6YQbpgAOpDk_BQrUBgP87KQmw7qv7zTZQ@mail.gmail.com>
Subject: Re: [PATCH] lib/stackdepot: always do filter_irq_stacks() in stack_depot_save()
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Vijayanand Jitta <vjitta@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	Imran Khan <imran.f.khan@oracle.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Chris Wilson <chris@chris-wilson.co.uk>, 
	Jani Nikula <jani.nikula@intel.com>, Mika Kuoppala <mika.kuoppala@linux.intel.com>, 
	dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=DTpy4LJX;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Nov 30, 2021 at 11:14 AM Marco Elver <elver@google.com> wrote:
>
> The non-interrupt portion of interrupt stack traces before interrupt
> entry is usually arbitrary. Therefore, saving stack traces of interrupts
> (that include entries before interrupt entry) to stack depot leads to
> unbounded stackdepot growth.
>
> As such, use of filter_irq_stacks() is a requirement to ensure
> stackdepot can efficiently deduplicate interrupt stacks.
>
> Looking through all current users of stack_depot_save(), none (except
> KASAN) pass the stack trace through filter_irq_stacks() before passing
> it on to stack_depot_save().
>
> Rather than adding filter_irq_stacks() to all current users of
> stack_depot_save(), it became clear that stack_depot_save() should
> simply do filter_irq_stacks().
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  lib/stackdepot.c  | 13 +++++++++++++
>  mm/kasan/common.c |  1 -
>  2 files changed, 13 insertions(+), 1 deletion(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index b437ae79aca1..519c7898c7f2 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -305,6 +305,9 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
>   * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false, avoids
>   * any allocations and will fail if no space is left to store the stack trace.
>   *
> + * If the stack trace in @entries is from an interrupt, only the portion up to
> + * interrupt entry is saved.
> + *
>   * Context: Any context, but setting @can_alloc to %false is required if
>   *          alloc_pages() cannot be used from the current context. Currently
>   *          this is the case from contexts where neither %GFP_ATOMIC nor
> @@ -323,6 +326,16 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>         unsigned long flags;
>         u32 hash;
>
> +       /*
> +        * If this stack trace is from an interrupt, including anything before
> +        * interrupt entry usually leads to unbounded stackdepot growth.
> +        *
> +        * Because use of filter_irq_stacks() is a requirement to ensure
> +        * stackdepot can efficiently deduplicate interrupt stacks, always
> +        * filter_irq_stacks() to simplify all callers' use of stackdepot.
> +        */
> +       nr_entries = filter_irq_stacks(entries, nr_entries);
> +
>         if (unlikely(nr_entries == 0) || stack_depot_disable)
>                 goto fast_exit;
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 8428da2aaf17..efaa836e5132 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -36,7 +36,6 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
>         unsigned int nr_entries;
>
>         nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> -       nr_entries = filter_irq_stacks(entries, nr_entries);
>         return __stack_depot_save(entries, nr_entries, flags, can_alloc);
>  }
>
> --
> 2.34.0.rc2.393.gf8c9666880-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdO4OqLqUyCJ6YQbpgAOpDk_BQrUBgP87KQmw7qv7zTZQ%40mail.gmail.com.
