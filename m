Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXMIT26AMGQE3QVU3PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 40BAAA11E7F
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 10:48:15 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-6d87d6c09basf93812156d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 01:48:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736934494; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nu6MP5xVfcqFCJ/IayrYWpfZ/5zwf4pkqqUwhYUKT+++sBbQ/CvCbQGbwgEDY3poC8
         Grf3ChOxeugYOqV6wvJt7lqrl3TKF7HXhNl0hWgO02sJT4bSUgtGtrAtVodF3Xw8UFtk
         FQybaaz1KDZtgH4poKs7yVTi3ctG4/BujNpv+2xv/Bgsm/CCsGcaZkF66r689wnRfzOw
         mqu7HvGp3AE2x7KhY9gO6C0R9K6Rd+KPI+SiVzyp1KFHI640ah2gR/+0AiCdfLyk3wXA
         t+JFuPX+CA6wOsKhrtpvHlNhxgz3VEEwbUhbj1NSh7nUGmf9w9J6vfPga+biaRkV32Ox
         lz2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ban8jieBGgK0zzCqskGXngH/+U+whGAz5fGHZPj+m3A=;
        fh=M59pTjvpm6RTAudK73M1A9SvhNAS1R6+ocXB8Ah0vAQ=;
        b=M5qYvJ2Zs132goYV79EqCBkbb3Sj9K7s9O4WQadEICuw3ZCLgv7p+zLavQznBkvBUn
         AwWSZWe56+XOIRAQcjL0xqqQC+ppOEt0k1bpD0O3xJA5hN3VjigCKrR+jVIf5qPpN/vP
         TTIJY7s/dRNJrG8kjqCiqrhPenclUP5pfUobSg/9jWSwx88hZJta0M4EfnpimtWYIqVG
         xENDiV6Tg5hKVL3uZ0mZpBXXOS3cjIrUEpyZJww0gFmgAArVkKKU9P8LoIq1cupNtGZV
         Bfx7PjPVMs0GFzuInAJVIAna4NddKmQqw71+hBXHndRWWNtNZsvO3a/jRhQsfWR8VODZ
         gpoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YJkIIfQh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736934494; x=1737539294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ban8jieBGgK0zzCqskGXngH/+U+whGAz5fGHZPj+m3A=;
        b=E2CLrh7tXpICdgya/1Tr3218xwAw1rx7WdG7YZoMUBuY2nopDLdBt2lvIgYfykp6Cl
         k+25tD7p76+Vzfwg6Jz6oTPi2PE94jI8gpg6vn2wmoBPsJ/DTrbEnxAJzq8i/C0e9dAB
         ESRlN60rzpK+/8LuNONqIkzeKzXUxR4hjWlc2npjS36/pdK4IX6NoRd+mOjVQ5zEOQUN
         2MZSc+YiFxDQRZ/BuDZ00ATvmnh65ZaD6PqxQLtXhpUuVy4XoZ+SF5u5QEI0J4rOsz8P
         qypbR3WFF8lClmJBmrP1afGdOw7/hv/Do2R/GIkEquTPSY4EHe/QrNCjhaXh5VuN1AXR
         sghQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736934494; x=1737539294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ban8jieBGgK0zzCqskGXngH/+U+whGAz5fGHZPj+m3A=;
        b=a14U4PCwajljA2IWGCw0JrhboY9JjJDYNsr8fYzE62CwaQQN4DtzPpnk7l2AzatuPq
         MOe+B5NcZ8VyGnA4ts/L/1ZkRKfmX5Ea3NCy2TVD8GJ+7179hxeT0dw8awL87EArypjL
         9jtaGDZaHB08y4jIot06ltS329pCgZCpAO0ljPEWPrBCBYsiO0k8FKcDmaatbrzCnVK+
         35edm4Ts+RaRY6Fb3hOioJCiVPWCAdGGhxRyDEQhGiNB9940CUMwFYLx8qg0QeMY/66x
         FWsEmQzoT4ZNLFbK3U/dMy03jCLxyvLKrVC0OUNoqMdRLXjRskUsGB9eVG8T1OpBamSK
         OdcQ==
X-Forwarded-Encrypted: i=2; AJvYcCU5kYjyvcmCF6QRqSTLxA6SaaPCV9ZDVdJffLATV/N5Tz24+3gA1sky32tD/K881ZVcSWmrJg==@lfdr.de
X-Gm-Message-State: AOJu0Ywbsvbaypz4WHxHmXo/KoV6zfmuFcQpMrn7umA/z7jGnum+8/tj
	uSKOvA+0rfDURxM/aBtOywSYGC3QcBTYkULHX8KKvlrpJLuMhxb1
X-Google-Smtp-Source: AGHT+IG6W82L+huud/fwjJ6xPeHlF0p6GOocWWyroe0suXm7Ptdo81d4cmcOn4yYuILg7lE5MUPSpg==
X-Received: by 2002:a05:6214:dcb:b0:6d4:1530:a0a3 with SMTP id 6a1803df08f44-6df9b1d1df7mr429790126d6.6.1736934493851;
        Wed, 15 Jan 2025 01:48:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5706:b0:6d8:ee03:1a2d with SMTP id
 6a1803df08f44-6dfa37a3934ls124429656d6.1.-pod-prod-01-us; Wed, 15 Jan 2025
 01:48:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV/IfbG73sRbDSyidYS36+Zkw1wwHSbh59PhB34qqqFsvk84I0Oh6pdSctE9CD8pKISpy4wMSr+Sb0=@googlegroups.com
X-Received: by 2002:a05:6122:7d1:b0:517:4fb0:74bc with SMTP id 71dfb90a1353d-51c6c430ba5mr24974822e0c.3.1736934493157;
        Wed, 15 Jan 2025 01:48:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736934493; cv=none;
        d=google.com; s=arc-20240605;
        b=FRry+k2KiR0lY0Heg1FStY0KdgcU98XEDyHPlm4mYyHtg4fXPH/ohHKl9IkT7SW5s1
         eBsv2kyxTtyWw9FaRIo1SUch8H4QYo0jUNY2m2BYz3eRZNLJqpOrYACtnczrHiid59uX
         0nWhn6idcjnpEKuI++lfDgz3AEmL9ZCRC7xQR2ScGhqc0+MXGzaKR0sxiaf9eE/oesmS
         +ZzISVoDdbrXr3wIsypq9RWVlITmf2fQjqM5vecULWwumbMfeK3DlhAe3pdkrGTIJjqm
         nHxei4A0PavE0F3TLzGFuoO9MwZgF3rTkxALXCKXUClFUMRMye1OO1ychnxuEsutKuVq
         Cjvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=s3jfONnwbYBavfwqwjYW7TKQLCTKaMO0wDpfiGKHArM=;
        fh=AmuxZ610YQ0W43vxKsHXqviO5hGNz5eMhkxVBbXhcMc=;
        b=cpKzVi7LL64P/GkZ3kipOm6NzHUAmzW+KtUHNvDRwRZrqx9XEnfRoaIaB9Id82j2fz
         IDilmPWARO7DblWECKS2bFtdj4Qu9kPtU+faU0I8gqisMdgrnAm9fqgONWraFZpyLZ23
         TLYGXfc2VT5crfhwJPkDzDcSazESJ614xRxo05dziggFsgZB1eF2qh+wJvklTIQISEhL
         XnSg4vPyw+4CfZRaqAeSlEtVz5dGkI16PiyiykFldNHpznyzvt6yQm7yIvzGzkIAXXqX
         nWwnQsiLXOW4rm/hE1X9T7iOIrx2O4ZiFhSHiorRseNP1SAgCYvG2MDAGL6IskpCWJWW
         MJLA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YJkIIfQh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-51c7fbb1222si451213e0c.1.2025.01.15.01.48.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2025 01:48:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-2164b662090so112821065ad.1
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2025 01:48:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXFC3Bc/zyucAl+FKZf02OvvZvf0MRnlqsGQ7ghxxEmSRWrRwv8tJVNs8s9poAC6NuT64He7XO1e0Q=@googlegroups.com
X-Gm-Gg: ASbGnctjMcuGJ0zQxnfaGHdx9XYnYk2YwoT8/kC6zPj2anAY7TFLcYnEJgRVZAYXenP
	Bh4TxsZk52bn9kHto3Mj8/y4K9wFSdfLEJNzSztQ1qIAk071+qC7dVeVv2cPP1V7ALBU=
X-Received: by 2002:a17:90b:258c:b0:2ee:f687:6ad5 with SMTP id
 98e67ed59e1d1-2f548ea5b95mr42258470a91.2.1736934491985; Wed, 15 Jan 2025
 01:48:11 -0800 (PST)
MIME-Version: 1.0
References: <20250115090303.918192-2-thorsten.blum@linux.dev>
In-Reply-To: <20250115090303.918192-2-thorsten.blum@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Jan 2025 10:47:35 +0100
X-Gm-Features: AbW1kvY4BndOnAABBFjjdCNbS5eXARCMsrlemA1tLX3CWVG4AcGszK_WeqGMxJg
Message-ID: <CANpmjNOO3TgBg+LACvWH0+6W0+N1eUmDsoQUt0MT3X+UubBSgA@mail.gmail.com>
Subject: Re: [PATCH] mm/kfence: Use str_write_read() helper in get_access_type()
To: Thorsten Blum <thorsten.blum@linux.dev>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Anshuman Khandual <anshuman.khandual@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=YJkIIfQh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::630 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 15 Jan 2025 at 10:03, Thorsten Blum <thorsten.blum@linux.dev> wrote:
>
> Remove hard-coded strings by using the str_write_read() helper function.
>
> Suggested-by: Anshuman Khandual <anshuman.khandual@arm.com>
> Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>
> ---
>  mm/kfence/kfence_test.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)

Why only change the one in kfence_test.c?

$ grep '"read"' mm/kfence/*
mm/kfence/kfence_test.c:        return r->is_write ? "write" : "read";
mm/kfence/report.c:     return is_write ? "write" : "read";

> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index f65fb182466d..00034e37bc9f 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -20,6 +20,7 @@
>  #include <linux/slab.h>
>  #include <linux/spinlock.h>
>  #include <linux/string.h>
> +#include <linux/string_choices.h>
>  #include <linux/tracepoint.h>
>  #include <trace/events/printk.h>
>
> @@ -88,7 +89,7 @@ struct expect_report {
>
>  static const char *get_access_type(const struct expect_report *r)
>  {
> -       return r->is_write ? "write" : "read";
> +       return str_write_read(r->is_write);
>  }
>
>  /* Check observed report matches information in @r. */
> --
> 2.47.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250115090303.918192-2-thorsten.blum%40linux.dev.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOO3TgBg%2BLACvWH0%2B6W0%2BN1eUmDsoQUt0MT3X%2BUubBSgA%40mail.gmail.com.
