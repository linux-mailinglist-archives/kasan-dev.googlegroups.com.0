Return-Path: <kasan-dev+bncBDW2JDUY5AORBINWUW6AMGQEHGT5OIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id D80B3A14222
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2025 20:16:51 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-3022741859esf7309521fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2025 11:16:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737055011; cv=pass;
        d=google.com; s=arc-20240605;
        b=IX/0GIsYwOsHcLjAMBD8IyUqCM74o9szFStXVgba0w3eUBJYbrSBMGgdmfBlzSFEgT
         W8RM2NbjRv+b4CJq2srGc1ufqifgtxKnuo8t6fP5mhzc4TkxNRC2e/I7r1m7B1+YM7ro
         VuS7vScbOKqvZkBAiGHJmtADRJ6FTRk/5ThX1rCCiNdlw673dGzHqbZk+OA5JLaGMAJ+
         xbKyxZm1at+1f9oN23SR9criaU+XunncTj4NH2MWoRgK8VYH4py9PdmE5tNvIzQloNJt
         rqh1CteOXXH9Rg5OYAewnO5DpXVOt3FHtzyEabGCem4JJ6VE/CfqIe9D5RB6uefECFmk
         yjaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=urNH1Xld4YIJ8T4HSLwzYyOeJpqSXlWh3fle/fFUbmA=;
        fh=uTm8WhLWCRwG6RdoRhdEmWzK+SnFr/vsYLuiTbDOv64=;
        b=i7FfjdXD0cHslwwxpXpg16qdUZ/KTg8rG34u2r6yTp2nZhIbSb252FrtgwyePCDvQj
         MMwM3trN8/VhJMrbsWD/+FITgEv4qexyir0asTjWdckQQs8UuOTsgG6SSC6TSdyITabm
         rvli7SjCRHXmfjuvvAH/O4w5YDb6aDWWxPMx10z3ruObr9IpsYq6kFVJaNIonAgIa0gY
         M/ssop1y4wQAUf5w9ZkO1PEcUzgj+nd1Y4CJAfQQhCm8rg7jec9BtcPNi9vAEDpz49W+
         xRqu0+3+NfiVZ5D8pfJR5qMD2Bm+5qe2iiSwCt2LbjgMvqSsR482b9zUVYQZlV0nGDXj
         jAiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CG1P00yh;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737055011; x=1737659811; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=urNH1Xld4YIJ8T4HSLwzYyOeJpqSXlWh3fle/fFUbmA=;
        b=bZfv/kgtKXlKtgpQI7eMl8gWNhrdSGiLefAgEKScjRGxXXXhIYFpZ1utXMpMFqwzKr
         pcQnqEEOQOllEnoxrs+rmwhDMYPcOFaCgn6Q0YVkHzPxZsz6ZRMIp0eAcyfBmu2B31j8
         dEhYutyGWPPHqjWCkaTcjBWt2+ozw9tx03eHjycFnn85RWD7gj6wqvlDfhQqytSDAy1V
         FNNAyCDwtDEqxOj+qYJZ0e4T/6oBcYvSeSHQIXmaGeHM5wPfioVPlPgDP4d+cZHUxNx4
         phyKHS6Mf/ShTYhhaNMic9OY4H2Xcatl1u0PLr9zwbMz5lImYfmmi/y0meLGuIMuE1GP
         RRfQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1737055011; x=1737659811; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=urNH1Xld4YIJ8T4HSLwzYyOeJpqSXlWh3fle/fFUbmA=;
        b=VcnYfDavwPVnURvPfngQuc89gCTEuS3p+VrlJw/BX9kbsF2B0Fermuojz17DkLoCWx
         4fRi+90jrl19WvVIUNn5JWo59POFRzeo2s7/glS79iJy7pCt2QBP2aqeewFzpQq0KU8E
         zRsrd0SfLEh/ycKNZ3LwjvaiaXph/8eSAQutw1dTNZl8oMXgtaW0qqqvz38x1/IdrNPT
         1CS0SIiHLJ4GGveuvYIxFkgQz01gDgUmS6L3xvjNrJyyLHV//hDdCXROZKtImu/UpEO4
         P/15pzKHIXQ33LYLkupRMZfB4a224aGqZNyG9FUKsI2TmLt1v4Y7h03XFlsngG8iuf16
         kHJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737055011; x=1737659811;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=urNH1Xld4YIJ8T4HSLwzYyOeJpqSXlWh3fle/fFUbmA=;
        b=SubzTF4bw8Li26NwrjuJOK2zgs0OuGL3rmWcEyrrZBZCeP+eCDbBhHtbAcYLm8nLTl
         eafGP7XedImn3W038FXrGFIbNYWe80hHPs74vpq41FnTQlAxvMuiAwZUhu1P7ylYRSGa
         PFTsIW/6ev8SzfQpAKjhy2RTuQ8/xpEZyuIXamAOvVJ8GYTD5GVnv2gBWyjUA6V137P5
         uNdg4AbtApyMmKibKDIMIvnto+fr9ewEnd/Fgympv5it73hp3IzAvluftfUHmMWqq7Vt
         ibcEXxSrZt2+2cd9MhqtpCBfTxrc6f3dqR7qPTRO7vwzSPP5AzBGbfX0aS8pJLSk716L
         DJcQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXXdKGlRtkiCaBmiXO8DSsG2LDdsdO7HnIUDDyVOn9/uVDasGJSChrO3GQO+SRSUnWFibTXA==@lfdr.de
X-Gm-Message-State: AOJu0YytUWOlivTNuLKmEdlLeQkq78paTR8L31ERFN0Qs7ZC06SwhCGC
	JXp/2TFd3GxgPc3LPGv0We22EVehur6g46m+Q+CRqyqIEhj1+u4H
X-Google-Smtp-Source: AGHT+IFKPEoc0ze3mRaGtPwx6FYJb1nIVK3OL+vjL9HJ9fw6Do6byWig3Jl0xPcpkSmWOkDSKE+CjQ==
X-Received: by 2002:a05:651c:4ca:b0:2fb:54d7:71b5 with SMTP id 38308e7fff4ca-305f45a1f8emr108326061fa.22.1737055010407;
        Thu, 16 Jan 2025 11:16:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:780e:0:b0:302:4050:ed2e with SMTP id 38308e7fff4ca-30637e42d3els3480731fa.2.-pod-prod-01-eu;
 Thu, 16 Jan 2025 11:16:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXRloxw54Gh9lTnreERHgMI7ovSIC/AnXnaNeoJz5Ato4QccrZ0eYdpmL7j5LJ8cH+nXSsvym5AwkM=@googlegroups.com
X-Received: by 2002:a2e:bc0f:0:b0:302:5391:3faf with SMTP id 38308e7fff4ca-305f45718f9mr119958731fa.17.1737055007209;
        Thu, 16 Jan 2025 11:16:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737055007; cv=none;
        d=google.com; s=arc-20240605;
        b=F8Dc/F0//uJuO5vlGkMAycoL2FHjVob6N3Etrk6tFgSxyW6hUckY1adWQDS0OVFQcd
         aQHNO4DVuqHJcecynElNd/QmKibPx5IBVXQouPt6qJy14HpVWgUbAtJqBdQuP2W4kc2N
         kJn8Jc/LjfCF5YkNswWQGUG+RIC5OCRQEB0S4rtg0J9cenQlmj3+kcZNRT42cDr6r862
         DlaboRd+trGIx0HTBimCCmXN2Vj9H6qkdVns7d+x3FkHtqQFxQIGPN+5XSBnxUgoVXbA
         QI98s2KxanIfV69U4aNf+JZXxvx/FrR0Hd8wIKPASnRuzoXPrTcLQf89j0vHwB+PjEIU
         rIdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fxEXl8+g5LwoZnSgSIO6iwq0ws9GZxr6F7mGjKX9OjY=;
        fh=AmnhdjbmQvKAvN/B3OJMK14Y4mGure1V0sisWeAuIQo=;
        b=eGeQ4qBtezxXRKDT/rXlKkAo8UhaPVbEvHyhX6zSwD1ArmOYEkfXZQ/xOeGVNEQvB0
         w70mumZEVhtIrOiv7em4xKrRK7VhCDFRuknfkkmFch8RkopR3ZYoyWKcbQ5LnbjQBdcV
         xi19YaaG3HAufyGqiQk6KHfyBWTufrSyBT3SVdtvtK9M5QJ1JKiBSOLulaOXq72jkNUV
         tCkdt7Wl+ft/rq4LN0S6Tu/CnYhb2TtBPH3rMWdIKupqDtlauRUFc5myZwNxXdGL2F1c
         DAYDwMFKr13huD8OwZmtguQ//Xv9DRenj03H82b+wLB0o9nsWj22EeCcd+ihYfHd6gjP
         FT4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CG1P00yh;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3072a331e55si121551fa.1.2025.01.16.11.16.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2025 11:16:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-385dece873cso791727f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2025 11:16:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXpTfL7Yq5Ipp8cE38CbCWE8DhzoTCiLdvehlWsTSGSzNXgSc4mzQORsz/JpPi9OyYnc3R8VjUwbMg=@googlegroups.com
X-Gm-Gg: ASbGncs1ov/664KHUEEJSjJopawK+KTjXmXhIoR9wT0pCqPM+KI5HLN6qLABmfpvHPJ
	WKpvI6Bq7cXhpVcjfNbpBML6fTCQfkFmNDjf0QI1p
X-Received: by 2002:a5d:648a:0:b0:38a:4b8a:e47d with SMTP id
 ffacd0b85a97d-38a8730ac0emr29702774f8f.26.1737055006251; Thu, 16 Jan 2025
 11:16:46 -0800 (PST)
MIME-Version: 1.0
References: <20250116062403.2496-2-thorsten.blum@linux.dev>
In-Reply-To: <20250116062403.2496-2-thorsten.blum@linux.dev>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 16 Jan 2025 20:16:35 +0100
X-Gm-Features: AbW1kvYx2BWTuOi1__7Q_bouYtTV5B6qSUEJxXxHQ_ChT-FL1MlESv_pCdPCpmA
Message-ID: <CA+fCnZfy-HyV5mCfoXdHMRhvJ5Effgkgct=J=YhEmnsTSU5+NA@mail.gmail.com>
Subject: Re: [PATCH] kasan: sw_tags: Use str_on_off() helper in kasan_init_sw_tags()
To: Thorsten Blum <thorsten.blum@linux.dev>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Anshuman Khandual <anshuman.khandual@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CG1P00yh;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c
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

On Thu, Jan 16, 2025 at 7:24=E2=80=AFAM Thorsten Blum <thorsten.blum@linux.=
dev> wrote:
>
> Remove hard-coded strings by using the str_on_off() helper function.
>
> Suggested-by: Anshuman Khandual <anshuman.khandual@arm.com>
> Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>
> ---
>  mm/kasan/sw_tags.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 220b5d4c6876..b9382b5b6a37 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -26,6 +26,7 @@
>  #include <linux/slab.h>
>  #include <linux/stacktrace.h>
>  #include <linux/string.h>
> +#include <linux/string_choices.h>
>  #include <linux/types.h>
>  #include <linux/vmalloc.h>
>  #include <linux/bug.h>
> @@ -45,7 +46,7 @@ void __init kasan_init_sw_tags(void)
>         kasan_init_tags();
>
>         pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=
=3D%s)\n",
> -               kasan_stack_collection_enabled() ? "on" : "off");
> +               str_on_off(kasan_stack_collection_enabled()));
>  }
>
>  /*
> --
> 2.47.1

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfy-HyV5mCfoXdHMRhvJ5Effgkgct%3DJ%3DYhEmnsTSU5%2BNA%40mail.gmail.com=
.
