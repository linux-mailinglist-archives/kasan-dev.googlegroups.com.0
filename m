Return-Path: <kasan-dev+bncBDW2JDUY5AORB4GL52WQMGQEFPU6UIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id CA5D28459A5
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Feb 2024 15:08:49 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-40ef7c10b29sf916265e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Feb 2024 06:08:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706796529; cv=pass;
        d=google.com; s=arc-20160816;
        b=FvTgII8XaJDXOuuxIQ6gB/5vEokPEzlJ8nQigTtH+JQV3MJDN5KJiBaUUYQihp4Le4
         H6y4NJuBGh0k1qBXv8swD/3ByEbJDsXy7ctECKi2NanKP3bzEyoA01/o/QOdMYhBK2ov
         KgBU2Fv9Znd5tj7gPa8scMZpPDLAauBkYRCKcDrHPcOv2c1wx5I9x85BukE6iOs5wXAO
         k2XBQ4kYx0jQdF7cXAVTIgcifTZXi5bQ/e6uekaTVJeE9R2admk/CjWm9/+A4Fi5OEHO
         FaM6gNYK9NGzH3fBZetOXF/+rGoBN2R9xBjg7dInHWNH1tKv6y5azLt3AwILtzehm8Ct
         GD5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=hYP+Qv8czrckJ+L91jDkwLxLprR1WaHTSqKDpPPI1rA=;
        fh=DC0kwcSJY1O+Eo72Gmvef8UcOyzJ6gxtbcdv4/DlMyk=;
        b=0PkB0kuy890h2Fc748eLla2o7eFGH8xDLYCtMUDoBpiRTb/pKAlVNPU/099uPWEExm
         V4ozmH+U++asIL7Xb2WIH2n2KXVyvcnIV4aq0NMcyE6ID+v+4HNRNI1vaONm3WZQMXkI
         yfL0BG6fgRrUc0lbCYyH9QxyKLc3zG3O+OVzCYgCQzIzTMRXopuwGaGnhv0f2B1MsN7k
         j8k2YIgns1epkM3NABts2dJtuLH/aoZxEwkxzPviwcIjMkDqCLJHVVh/U+5vrh6aRCfV
         njSwclJo2dVuU2sjdm93wO/vPBggZRBZ6IQ0BkP0knzkPLGP5mIz3sj1iVXAL2e61zFD
         zzcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Sy+HVbub;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706796529; x=1707401329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hYP+Qv8czrckJ+L91jDkwLxLprR1WaHTSqKDpPPI1rA=;
        b=ru9Z6crykYpvhKqwDThc5XGkBetKwai8YHdnhDNdzR9Jb9iphPNl4bFdtAuuTx5A7f
         fmdEsYIwLoYPNl7T99jy++t5laeVQuyCGJX8F+59qxChN84YIYD7anVlzsMbgYM+GaV0
         a34FJlLA8/9TWblp+p88/qxKTKKBSOALbZI/btH1YQf3WX2/Nh9OyfGWQjvmoNux111Q
         Aqdk/dQreWsMc4ucxaWBSe6SIo4VyQtDo9f3m25TCOAXbSwnBNqPDb5PVjDsGGRIQKOH
         qUZ5YqbM9mqgFIoG8e67gyAUfKhEmkltFuysmO63j+xI941LpTHSZvZ1wUgiBJY0Uy6O
         NjTg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1706796529; x=1707401329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hYP+Qv8czrckJ+L91jDkwLxLprR1WaHTSqKDpPPI1rA=;
        b=FbDqcFfzL/HpWQQuVkyUfdyGWSphA6IN0BW7r574+tleRlNECJHxD/uVg/ts8dlctS
         RvwNemUNMn0jwO4mKRyXqBTlvXURn56lvTjuSXcG7KTVaXVSkP6GAOro36WnF8ETXGXa
         l6yBia7WY3y047MFzDvyGtiTQwojng+hsvLb1QkOUMAXzTrMNBhuRMnsuZXcO6Eu4uiN
         WKuiRWK6qaDTkFTz3o98l4X/ifGwX+3zUq4ZLyiy53ulblrQAaVAWxwniZiRCYClU//6
         4QUohgIzFxizS+0Mq9+RxWTp+Iv2R34rdqsj6SetuMjPjh1er7JHO1kw6ANz6J/J65vA
         l2MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706796529; x=1707401329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hYP+Qv8czrckJ+L91jDkwLxLprR1WaHTSqKDpPPI1rA=;
        b=aI8M4l1LjU4FnFpazRmQjK3lOSzZ9YzvMrl5c2HcFuLs1zPHeuEm5ULX9E50iGCexb
         k0OSXbJUZD3RLIp0R/NLzNYFgFH9JevlSbTZZf7SGjapb9/lNyZIgV7yFIq/L0DmpAir
         MJxTsbidRubqW7o/vpZ0m94aNwPBFpfJ7FOj/sZJCO5KmTVgjuodCGWCAZ9HK0Oc6WxM
         dGvOeG4EjILwyNuZgYJSEajBRLTkhW0/TfzMVDHAmlgQQzQ7ksqd2tpODpEFbPfqwreS
         NVlmz6++9TbrmUhsxwuQx26i6tWp9adHMDIXtnQIl9eMZbJYwxPDCsXjpm8WDQHsr+ZU
         S2iA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yypv/McnlVqoefk2RNcuRqvKfer42WTe5MZ38C0T+DSBLXRDEOD
	SHCQ96fvI0QRfT2gE0LdxddUF+znTeMtLQlYTuOal0mGgBxZQUY6
X-Google-Smtp-Source: AGHT+IHK602jn9wtYHNFLPPWQfp6UhC0dJOl9fa0H7ch6P3EWQQnC6PE/7HolR8IUuub2j4Bouxu2A==
X-Received: by 2002:a05:600c:518e:b0:40f:b642:1919 with SMTP id fa14-20020a05600c518e00b0040fb6421919mr112781wmb.5.1706796529004;
        Thu, 01 Feb 2024 06:08:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dd89:0:b0:33a:ff6a:1782 with SMTP id x9-20020adfdd89000000b0033aff6a1782ls173016wrl.1.-pod-prod-09-eu;
 Thu, 01 Feb 2024 06:08:47 -0800 (PST)
X-Received: by 2002:a5d:6744:0:b0:33b:12bf:9c52 with SMTP id l4-20020a5d6744000000b0033b12bf9c52mr1582268wrw.18.1706796527149;
        Thu, 01 Feb 2024 06:08:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706796527; cv=none;
        d=google.com; s=arc-20160816;
        b=a/umnYKOeMWGMcgPjosGXusoQDfCS/v0XOJtk0bLjeETKfnec/qJgFbXaAEaiJvP3C
         Ec/P2Ci9XJ9bjleExA+fxM5W1wbKV+ovPDbpkZEI+OvakFmEmQiAtKUdhAZx9WsIZGbO
         Mh2F3+Sn8qfjpI4k3/qDEi9W53OtBhB9YPn3fjnESw8EktcrHE7q41x2ve5c38DQftnv
         NFSX5MOS6ZxRDUGXW9ZIxBbIKz+2YNtRA6AXVO2AVbrXybabISP403wDpy1axVazJJF8
         EjaLB77HqDUgXIym2ULJZ6lKW3xOLMzbUoa1VX+ji57qNqpVuw8msDfeRgb7DRC8Zb7C
         iWAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RXTNG0NGaTKBhOKJjgCQmT3vvlhWCnQV7wCDhgjDYvY=;
        fh=DC0kwcSJY1O+Eo72Gmvef8UcOyzJ6gxtbcdv4/DlMyk=;
        b=MqxLnZwdo4koK5A/I7Vds8B1ZpFOUXAGLAVCvJ/xk534DpFBR2fOAQrStEqEryvMhD
         vl6E0+gDWFDmd+79Ukt9S9ZQRQTW4mytqY+N/ecKwp4fEUSHE0sEIBAfTc5InD3xUb6s
         FOL1zt0y7lLT5s2RK9tYy52eJ+Z3i2z2eHXnTpsEFVlqafxHHZyFuO+qze3OJHMjPKIx
         ukk1V7pIoO2yhDyWI+oenIN1un+nMd68D6hv4pfPMWRn56Ld0OGE1Ibex7laCOY8atNg
         0tbMDC1me7ToGoA1SfNrN1MojEx1wrXNiCI741wTX4qPW+asceCrciuR1XIN9rJMI15j
         fduQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Sy+HVbub;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
X-Forwarded-Encrypted: i=0; AJvYcCWb+JPRlyIVh+KzZ5JwClKjMvZh4in2/rNqVGX/2gpcsrjpNuds4vAH07wQqBVQSkwcIW1SC3B+6DTrcfhELzCizROkJH7XfAhJ+w==
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id w3-20020a5d4b43000000b0033b1ad6701esi20624wrs.7.2024.02.01.06.08.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Feb 2024 06:08:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-40fafae5532so8801595e9.1
        for <kasan-dev@googlegroups.com>; Thu, 01 Feb 2024 06:08:47 -0800 (PST)
X-Received: by 2002:adf:fe48:0:b0:33a:f321:5ae6 with SMTP id
 m8-20020adffe48000000b0033af3215ae6mr3848112wrs.35.1706796526366; Thu, 01 Feb
 2024 06:08:46 -0800 (PST)
MIME-Version: 1.0
References: <20240201090434.1762340-1-elver@google.com>
In-Reply-To: <20240201090434.1762340-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 1 Feb 2024 15:08:35 +0100
Message-ID: <CA+fCnZchOw9Eg3uBPF6Xej+vXnxKD8Jzp2V_o5qZGFM5MDo_AQ@mail.gmail.com>
Subject: Re: [PATCH -mm v2] stackdepot: fix -Wstringop-overflow warning
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Sy+HVbub;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334
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

On Thu, Feb 1, 2024 at 10:04=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> Since 113a61863ecb ("Makefile: Enable -Wstringop-overflow globally")
> string overflow checking is enabled by default. Within stackdepot, the
> compiler (GCC 13.2.0) assumes that a multiplication overflow may be
> possible and flex_array_size() can return SIZE_MAX (4294967295 on
> 32-bit), resulting in this warning:
>
>  In function 'depot_alloc_stack',
>      inlined from 'stack_depot_save_flags' at lib/stackdepot.c:688:4:
>  arch/x86/include/asm/string_32.h:150:25: error: '__builtin_memcpy' speci=
fied bound 4294967295 exceeds maximum object size 2147483647 [-Werror=3Dstr=
ingop-overflow=3D]
>    150 | #define memcpy(t, f, n) __builtin_memcpy(t, f, n)
>        |                         ^~~~~~~~~~~~~~~~~~~~~~~~~
>  lib/stackdepot.c:459:9: note: in expansion of macro 'memcpy'
>    459 |         memcpy(stack->entries, entries, flex_array_size(stack, e=
ntries, nr_entries));
>        |         ^~~~~~
>  cc1: all warnings being treated as errors
>
> This is due to depot_alloc_stack() accepting an 'int nr_entries' which
> could be negative without deeper analysis of callers.
>
> The call to depot_alloc_stack() from stack_depot_save_flags(), however,
> only passes in its nr_entries which is unsigned int. Fix the warning by
> switching depot_alloc_stack()'s nr_entries to also be unsigned.
>
> Link: https://lore.kernel.org/all/20240201135747.18eca98e@canb.auug.org.a=
u/
> Fixes: d869d3fb362c ("stackdepot: use variable size records for non-evict=
able entries")
> Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Just switch 'nr_entries' to unsigned int which is already the case
>   elsewhere.
> ---
>  lib/stackdepot.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 8f3b2c84ec2d..4a7055a63d9f 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -420,7 +420,7 @@ static inline size_t depot_stack_record_size(struct s=
tack_record *s, unsigned in
>
>  /* Allocates a new stack in a stack depot pool. */
>  static struct stack_record *
> -depot_alloc_stack(unsigned long *entries, int nr_entries, u32 hash, depo=
t_flags_t flags, void **prealloc)
> +depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 h=
ash, depot_flags_t flags, void **prealloc)
>  {
>         struct stack_record *stack =3D NULL;
>         size_t record_size;
> --
> 2.43.0.429.g432eaa2c6b-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZchOw9Eg3uBPF6Xej%2BvXnxKD8Jzp2V_o5qZGFM5MDo_AQ%40mail.gm=
ail.com.
