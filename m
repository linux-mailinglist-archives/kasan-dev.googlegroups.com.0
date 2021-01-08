Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJGH4L7QKGQE5VHIEMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 94DBC2EF746
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 19:25:41 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id r20sf11083761ilh.23
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 10:25:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610130340; cv=pass;
        d=google.com; s=arc-20160816;
        b=GI3WNaxxMEsLXoORRYdAgak9dP8BTsh6Hpjl7LzYDsW2wQU23tYmO/cXRqc0XDtm6N
         2pmP7VA+DghvlPQ0SjvDeXgETPe4pEDp3GfRVo3F+9blpQreNKaulm7I6XdrKrMc3iLM
         UYdeJK5z37f86yUls9Egsl7XeIkvNPMRmMVcLwW04GQ4re8gOnklH3VPlHmCdidLdcoC
         klqH1VIg0UQYMTm+LYbVXmwElsUJ7GkItXmWibPgM2v7fyNtsHuoNxLPAipJTGddSK/Y
         mkCjDnbwnZzReHJbbEwQopaA5Kd+rQdJITS78KB+HrolUblZeulAQQHhgkgghkV48bFM
         sK+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EgOFi65AhhjPppObJuAVfxr6ZGvGIROVpIwehzQrQLk=;
        b=acgnJfiAHxeizXK0vUWO6esjSeBHsDQrtG1WyXcUFPk5NF6ih/X5Lh6ppCseWc7LzW
         q8aUGWcY7kbKhDLgxiLO1EGnB7Wk01SMQedOglYcv+RICe2b/epLOgWChlf8vzLs5hMl
         jkDrngqrASe19ogzH9tO2drSOIT52FLssNdJ4Nu26V1zu3jJHAieVe39KpqF101sUvEP
         0OW3Tt1PPCd8uVAOKQZ/NtHGcQZPljPdQkhanhyjhkJXm00MtjuakXDkuKIlxn2DXSlG
         7D2HHeFd0hu+r57ECp8t3TL66Cx3i+SnbheYMQ9rHcgrD/SzAdRDd2kahbvXonrctQTi
         5oXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d+L+HGQn;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EgOFi65AhhjPppObJuAVfxr6ZGvGIROVpIwehzQrQLk=;
        b=cdczjOJxCDLnRX+cbmzDcPCHgnfbpw9LKpCa1oymFLo3rj89sdB/lIXZOlmYj+5TvP
         kzRb3xK/QuDiAisiPgtEjqgsIvqMCAuyj930e8ZCbrHhw18MgkQj3abBnw/WnTy8h3Qx
         a37MRweUp9P5uv9tLkQgPNIPeYMUHBHipA5yjMIfsLJiMnSrAjn2FdTwEZH/rww6UCV9
         Uh1srgWToX2Jd5JUIkTUctfalzAJ7UWn0KNsvcauyERqnHznRYJzPWfkGPbCdB4M5k67
         SEiCeW7KQMvNQS3jGaNtmsnCu1/vus9rmeKPXBQbYmefh3M9FCNe2pSSChpI//tNGgqw
         JzLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EgOFi65AhhjPppObJuAVfxr6ZGvGIROVpIwehzQrQLk=;
        b=PYpqRwYxcnHCwmNC/dnfZ6RQ0WLId8wbzBt2NWWd8/CNgmHe5TIEQMUFf8N6ThVBSI
         UdP98JnopB+RktKmsoFqqHKIrwdYupsWNF9Ff2Wgb2VmNNqOzdeRKKSVBOFcWioXexlk
         FFppalcfPSmDoIZvcqOoKC9AT+MGCHHNo+/X9jzNZjMyY0B70h40grGB8SvieqOyD+zb
         VBFrlM1AXcFmkw6oAz0AlSmwWt9Ihzs+s6rAHtcG3amfT+85gUNBH6CYoZOteaiq8Jyg
         FO8LRLq/8bdY5qjLv8Zb6VWduUz0sXqb+JRufLBHn591K5v6ZOrzolmZLM2Tdrbksunf
         gtMA==
X-Gm-Message-State: AOAM530WF6btUvDIlCgAt+zCjkJmCYH1/8buOEZuCQmmAOxALmRd6I4p
	ZsXDE93k5HP83p60uZ+vhl4=
X-Google-Smtp-Source: ABdhPJwIuai1REuYFwR8K4B/VGQuqFT1dwSxH5yMyeje2V0cuecFREreSLe1EwmV8NQ8qyZL8rOA/w==
X-Received: by 2002:a6b:3f54:: with SMTP id m81mr6245552ioa.113.1610130340631;
        Fri, 08 Jan 2021 10:25:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8c86:: with SMTP id g6ls1894327ion.0.gmail; Fri, 08 Jan
 2021 10:25:40 -0800 (PST)
X-Received: by 2002:a6b:7704:: with SMTP id n4mr6426697iom.159.1610130340346;
        Fri, 08 Jan 2021 10:25:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610130340; cv=none;
        d=google.com; s=arc-20160816;
        b=a1O3G6dKK+UajzR9wYJiFpsOiF4V3HN9yPltJelnEsXLgdAYrK65CqyEd5ONmYVp6E
         kUbLyOMU2zM0hVAYIf6wfDZq+keV5WpJTqroqTlX+N19++7aTdebOTB7GStUMIW1Bi/b
         g9IaNc8z2YF9GsepYVd/cN22/Rp35BixJMh7yy4PQKoE7HxO7+3MBKhp2eL/MmQo2Fhj
         yesn2mF/gXkfUAqirsNZ8QIVFQvjaC9Lz2g017IfQDq4JMIDupDDLBTKI3Del51ci0hZ
         IIzzGGjlFONL61H6rzM8LFRmgjlO3jQUofYExnJXkFmdKMQGgBv2a0L4KbCGP1U72e7b
         3+8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TvvXV7bEAAhRZbN5Xzp/cblWdK/NVPGWOn4od85Z6/w=;
        b=vtbK63zKQCgZdLXrk+XmveYVp2jMWkiukZMTP0smWUL2AAeDv6+45E9wzxC9QhAhd+
         u8VS3PIsfnSi6NuzPVKPe1AkeuBCo+VTAJ06YmsdXsqNjhN5IG4qjCxOIQQD3G12LlLb
         1g1ZcGVqLJTTRHCOqzQGDKHGEvWQUwrPzblraHh1y7RaLHVwh25BaRcQF60p4FXA2O2C
         cLxUNE6eS9dkXLljr4N2sKu7OBzjnmvOR1cn5G0hGyVmCRexEOtxZ56bOmJ+k26qnKtS
         zr2vd6FAlH2zrCB1yNPWrofglKbVW5dapr8Fx+PqVY6otj2P2Q8KuHlRVV6oAuk0k9XE
         B52Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d+L+HGQn;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id b8si1394156ile.1.2021.01.08.10.25.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Jan 2021 10:25:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id l23so6640064pjg.1
        for <kasan-dev@googlegroups.com>; Fri, 08 Jan 2021 10:25:40 -0800 (PST)
X-Received: by 2002:a17:902:9009:b029:dc:52a6:575 with SMTP id
 a9-20020a1709029009b02900dc52a60575mr4902482plp.57.1610130339630; Fri, 08 Jan
 2021 10:25:39 -0800 (PST)
MIME-Version: 1.0
References: <20210103063847.5963-1-lecopzer@gmail.com>
In-Reply-To: <20210103063847.5963-1-lecopzer@gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Jan 2021 19:25:28 +0100
Message-ID: <CAAeHK+z_+sgoJbi8ULJYKdcNoB9WET8pRbkD7MvK+yp6k5sk4A@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix incorrect arguments passing in kasan_add_zero_shadow
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dan Williams <dan.j.williams@intel.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mediatek@lists.infradead.org, 
	yj.chiang@mediatek.com, Lecopzer Chen <lecopzer.chen@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=d+L+HGQn;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Sun, Jan 3, 2021 at 7:39 AM Lecopzer Chen <lecopzer@gmail.com> wrote:
>
> kasan_remove_zero_shadow() shall use original virtual address, start
> and size, instead of shadow address.
>
> Fixes: 0207df4fa1a86 ("kernel/memremap, kasan: make ZONE_DEVICE with work with KASAN")
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> ---
>  mm/kasan/init.c | 3 +--
>  1 file changed, 1 insertion(+), 2 deletions(-)
>
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index bc0ad208b3a7..67051cfae41c 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -481,7 +481,6 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
>
>         ret = kasan_populate_early_shadow(shadow_start, shadow_end);
>         if (ret)
> -               kasan_remove_zero_shadow(shadow_start,
> -                                       size >> KASAN_SHADOW_SCALE_SHIFT);
> +               kasan_remove_zero_shadow(start, size);
>         return ret;
>  }
> --
> 2.25.1

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz_%2BsgoJbi8ULJYKdcNoB9WET8pRbkD7MvK%2Byp6k5sk4A%40mail.gmail.com.
