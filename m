Return-Path: <kasan-dev+bncBCDO7L6ERQDRB2U33CZAMGQEA7GL3SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id F3D5D8D221D
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 19:01:31 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2e95abc0d8esf8757821fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 10:01:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716915691; cv=pass;
        d=google.com; s=arc-20160816;
        b=QV0a8HwW3xlGEuWIjJRJZ+pJbhBgCIhjRiHwrkpPqiKjxxnb61JRmKPsISNVAFpK2W
         28hw+YnrskuUoG5v9yE83PMTrAtkkJaf4rgUVkKUBDsfAdJbP6h+N4ftJme8Wahb/BB/
         mXr6ZE0ZisWh2gAKMhlZmTzsUxFp9J1MUwILp4wBpTXOAhiDeriVkVulkHEWuvK4F/vK
         GeKa4y5QVlbM+n5kbrhimkx8IQ0gMZdFJMeyAbyOGzS3YEmLRiHef4MbVxPImCT94K1j
         W64q4g6KS15yKcveh9NZbyDUFS6q1W20XZA9zOEDOa0bLtLCZEpL0ACkFtdm1OPdMLdr
         Qm4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=QZWtoxpumuTEP1YmeDev4sKIDy+AMH5yw/L+ylctWLg=;
        fh=ghg63NVQCQMLHETYXSctF2qMq7pg1hWtsq+kFh1QuG4=;
        b=bN5NGmYezuTNSuzvTdl5re6eJtJmsGlL6QYW9huxmSdEPMLp8KwFkj82C576171vMI
         IputNmo8+zcytJGqYeEasQKNluZZHvJKLyQbS5aE9kuAfjBTliEzTugr4pqH9Jm0JY5T
         /jrn34kc5Yq70VOqDGaj67zfGh1VbFbrjiMhkR8b0J0qsj4VAv3jK4+iJlHgPSSxVA3F
         7lFpkKPWroibx1iczlB4F6E5KYd/q5sXzaA3MEhN0GXSwTBpddJ+aclpQq/kRbtvsUCl
         vGfrH861AP3NgJou42nAcWBd5+Ogf78saXnTxouA/30vixHt0xd7Pmv2ZdxRnSt93sz6
         bB0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Bwebdnxh;
       spf=pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716915691; x=1717520491; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QZWtoxpumuTEP1YmeDev4sKIDy+AMH5yw/L+ylctWLg=;
        b=PM5Fw0CiGUV1OTdhGUaCvT+tmj3JiTte43n7awPyUoRbjuO0p3L+dn8sVJRrpZDWcD
         HM+3wmZCsbBrTAgp/US9BaSBUl7czGVNCp+iX7IQzCNbTI4SAaqQAmKxugLxYB4oMzgN
         hJrKug0DwyB/yYEYb8xqOSY4OFvMvaMTA+pE7cn5R8ppI5/A4G3XuFVhTg1cCbe0VrgU
         1l71z29GL2dK0pQK4BYlPlknLk9u9Oyr/xaad+eC0DnqnHQgMsHhTWTU1aYKuzH5I8Rz
         wbXA+lmS8LeGbmpyTS9/hjBbLPW69u7vMDlKoLRa7Nu8Rtfb4zgfo9MFbJ5wiH7STMGh
         jmZQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1716915691; x=1717520491; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=QZWtoxpumuTEP1YmeDev4sKIDy+AMH5yw/L+ylctWLg=;
        b=Zzaj5uyPMGxQb0cwpwXOhmndGHV1nPfe0nv4Dx2OrlslJbml59+3/m6JmY9D4ldePb
         nDOY7XKDtOYgpX2XOHXU32B5v+SEWmEqL4pM7Bbq6Rn06xoBe9lbgTf48+WvSRi05tnf
         VUD/uWN70r/AJnehK7UMe7zUkCBCO2D+ebXh9zoFGLuKLMDc44wq7qalcrbz7IbaG7eh
         RmWsrcO73Y9KcHcpKWBoWMkUp0VcZVOHntkYBVtI9Q8oScnXXnm8jzLif+oQpffRzAVV
         TKtWyk2dIxBeh/FDT7wIdIsH18BQJA/3DKRCzsQ0eSGrFczVUmh0iJHq+DIc8wR6loBB
         MxVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716915691; x=1717520491;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QZWtoxpumuTEP1YmeDev4sKIDy+AMH5yw/L+ylctWLg=;
        b=Tb4TEjtHg1ihruOt3ZXFr2Ef7/u8XrawMCWiNl4EBDPPnRDw+wVouJIthBurpd+9Uj
         J/J7RiR8xoa9ZH4HXaJd6OWX+asWJc359qDtR1MPhw19Y05pV/5dRlX/3cAl9Or4T2XW
         kWPHAOdYvdYNoZRde0mbU/y+1OmZ7ccLDpZ3luGMiVXK3NMAkucjd8s/HRDseCpyGFPZ
         kiR8X9YTQlxgvisv+N+6xLwI32ecJpTb34skVDX2w0FX1+lYiKu4xhnZA6i6JaE2j+kl
         FwEgq+Q7T1fcuF6R98/W2Ijp2GTM3WmxUT2tnYWkjJzNeItb2QJAYS4cE2F3uh8SJQxU
         l9uQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU+r204vwYWl8pPSJFEhQBcjU2H+ZaTNtzHxcA0XENTU4WpyNZDrxyjXbd1NMh3XCpFFBeRC3hx2hYtEt0rFHBqxLHVWzxVpQ==
X-Gm-Message-State: AOJu0YzAwe9zIz7AFYpSdeEXp7YJHSMluIvgxVJCtTJh0212Pb/P4OVO
	MGzB8AK9myJ8Qwhvwi13GZJ9OvvRVnbnt8FvpBKhyywnzlYPIeGM
X-Google-Smtp-Source: AGHT+IFIQ+nbTUFEg7Tl0P87xG9hHLl2Wc3pzSO7kqYpLXvEZj5oHXHV8GfE98xLZezSmIHUsjmFCg==
X-Received: by 2002:a2e:8e8d:0:b0:2e0:da20:2502 with SMTP id 38308e7fff4ca-2e95b27b0b1mr93275561fa.49.1716915690711;
        Tue, 28 May 2024 10:01:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7207:0:b0:2e6:fe9b:db1f with SMTP id 38308e7fff4ca-2e98685e201ls5065181fa.2.-pod-prod-05-eu;
 Tue, 28 May 2024 10:01:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzVAfX/xxrOEMTXujpEia2Rwf227S8A45Nmrtg4WftYPLTeGuR64bBn+YWsLYY4Npa8KyDIdUjCR4MKhAgnsPTDn7fjUm+jANJDA==
X-Received: by 2002:a2e:6a02:0:b0:2e5:566:c752 with SMTP id 38308e7fff4ca-2e95b27b11emr105312131fa.48.1716915688627;
        Tue, 28 May 2024 10:01:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716915688; cv=none;
        d=google.com; s=arc-20160816;
        b=JOA0fhEKKX6k3HFZ5pFqNXmiNFrDNU8dFTYwd2pgfpEkSiC/tDKK9JcX99hifdLk73
         sNP9XnS0rfOkJ5ZuEw8FBs6TLdTVekvIENi+MkBsIpkCP/Zr/VoS+h5Iaoser4n7hleG
         8HgwnnJDgTPxv4jKCdtuplMRuWIQ6oMqblhvOCzGcbNa/KgAUR4BalkEPzMArsjUdOBU
         MK/onEoW+LiGPG4FaNWcwYqMPgkVbHWnwvajCzASVxrqtUg1Bybbud6EyNrW7qRzIymY
         5sSqr3PbQY/b/lUrGvoDGg+4MK7XK1mBEbVSrr9xrh0nQFYWdIsWn8zD2ZvktX/aTyl1
         LEmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=j6Kwp0ELgxMwtCubVN5m3j9ZXGTcZalcurbZoa6Jlk0=;
        fh=ebkWUksjC9ZwDZu4hk14cbNlrfOuZZN0K3ACZVRcaFA=;
        b=XKBIlOxwNG9qTBb7jW7K2MSYHYxAXSaDr/BlOTnEZQiqap47pdEVUm/GKQ1QdWb8VU
         5cEReGDLRga7YtmYLyf4Z+68VMD/Xn2uyRjIQtgeMuO7jJihs6AK1BtuPx4uXuODU7Fq
         ttrlFr+pxy0m/emPvkEoCEriPcze5pLKJ4iSxAWNx8H1yVcbIFn42epqb8+0zdUINwXf
         t8iF9Bi4OEqJyzVRWaWRK/ho41hDquu+Y89BaPOCNImWOysGyGucvE3cVN0nbyCA4Rfb
         2EgTmkuzlIjXG2uioljsEYdlhCwDTgfupQ24Fc7N3pJ1bhOlTpJsVBbm2MpxlHY8B2vt
         2Y0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Bwebdnxh;
       spf=pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62f.google.com (mail-ej1-x62f.google.com. [2a00:1450:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2e95be1a6d8si3136131fa.5.2024.05.28.10.01.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 May 2024 10:01:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::62f as permitted sender) client-ip=2a00:1450:4864:20::62f;
Received: by mail-ej1-x62f.google.com with SMTP id a640c23a62f3a-a6268034cf8so52230866b.3
        for <kasan-dev@googlegroups.com>; Tue, 28 May 2024 10:01:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWgO5Vi7NAi3ed+YC7C2LeV0EiZD++sErcvNrwl6u+sRlkK3UXpxrrWeREmlBTb3nY78mha2K1DeM9AqESuWkXfOMKr3v0ZKozM2A==
X-Received: by 2002:a50:c309:0:b0:578:6c08:88fb with SMTP id 4fb4d7f45d1cf-5786c088c0bmr6799260a12.12.1716915687602;
        Tue, 28 May 2024 10:01:27 -0700 (PDT)
Received: from rex (lab-4.lab.cs.vu.nl. [192.33.36.4])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-579cd4c85c7sm3793847a12.20.2024.05.28.10.01.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 May 2024 10:01:27 -0700 (PDT)
Date: Tue, 28 May 2024 19:01:25 +0200
From: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
To: Alexander Potapenko <glider@google.com>
Cc: elver@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH 1/2] kmsan: do not wipe out origin when doing partial
 unpoisoning
Message-ID: <ZlYN5Wh4zDgRIrAx@rex>
References: <20240528104807.738758-1-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240528104807.738758-1-glider@google.com>
X-Original-Sender: bjohannesmeyer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Bwebdnxh;       spf=pass
 (google.com: domain of bjohannesmeyer@gmail.com designates
 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, May 28, 2024 at 12:48:06PM +0200, Alexander Potapenko wrote:
> As noticed by Brian, KMSAN should not be zeroing the origin when
> unpoisoning parts of a four-byte uninitialized value, e.g.:
> 
>     char a[4];
>     kmsan_unpoison_memory(a, 1);
> 
> This led to false negatives, as certain poisoned values could receive zero
> origins, preventing those values from being reported.
> 
> To fix the problem, check that kmsan_internal_set_shadow_origin() writes
> zero origins only to slots which have zero shadow.
> 
> Reported-by: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
> Link: https://lore.kernel.org/lkml/20240524232804.1984355-1-bjohannesmeyer@gmail.com/T/
> Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  mm/kmsan/core.c | 15 +++++++++++----
>  1 file changed, 11 insertions(+), 4 deletions(-)
> 
> diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
> index cf2d70e9c9a5f..95f859e38c533 100644
> --- a/mm/kmsan/core.c
> +++ b/mm/kmsan/core.c
> @@ -196,8 +196,7 @@ void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
>  				      u32 origin, bool checked)
>  {
>  	u64 address = (u64)addr;
> -	void *shadow_start;
> -	u32 *origin_start;
> +	u32 *shadow_start, *origin_start;
>  	size_t pad = 0;
>  
>  	KMSAN_WARN_ON(!kmsan_metadata_is_contiguous(addr, size));
> @@ -225,8 +224,16 @@ void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
>  	origin_start =
>  		(u32 *)kmsan_get_metadata((void *)address, KMSAN_META_ORIGIN);
>  
> -	for (int i = 0; i < size / KMSAN_ORIGIN_SIZE; i++)
> -		origin_start[i] = origin;
> +	/*
> +	 * If the new origin is non-zero, assume that the shadow byte is also non-zero,
> +	 * and unconditionally overwrite the old origin slot.
> +	 * If the new origin is zero, overwrite the old origin slot iff the
> +	 * corresponding shadow slot is zero.
> +	 */
> +	for (int i = 0; i < size / KMSAN_ORIGIN_SIZE; i++) {
> +		if (origin || !shadow_start[i])
> +			origin_start[i] = origin;
> +	}
>  }
>  
>  struct page *kmsan_vmalloc_to_page_or_null(void *vaddr)
> -- 
> 2.45.1.288.g0e0cd299f1-goog
> 

Tested-by: Brian Johannesmeyer <bjohannesmeyer@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZlYN5Wh4zDgRIrAx%40rex.
