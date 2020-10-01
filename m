Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKM73D5QKGQEBVCWQVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A65A2804FE
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:19:38 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id r6sf2073509lfn.12
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:19:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601572777; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ru5tRVih+EHyrN/J//ilKj+fIfqWsoEuhBOUyt5D2ptz7IX1OP1D3HYn3KpgZj8+Ee
         +sUR2YqXxLrrXuGtbs25jmEd+7aQxMkED0jYMSSP94iQ3iSVYxd3+dx37HyAh9lrbxdo
         gI/cyK0InUHRc7qG41WUJX9hCtDCmQiS6cg1JOOsE+soZoZSSZO5XJolIU0SOgePTQ/D
         nlUtjebNvBKGK/7kW1tdV8mAX35LZxGcEoYWAWTBpqY0OS81VgRhRtEmKBqy+ZrIicrd
         KZeIZANB7H7Bhz0tttivRvOK9IBQxSQjWHkAMBS3ciqaMnJCxu4VneP0oBEkB0gc8ujb
         Jhkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=0GbJCgboZgXChk8vahOfffdFlEqRzSr57eQ/bG6ov+Q=;
        b=wsBj3hTLhw/ZGygk/POwYeu/UqAZgyiAgCc2fGwPe3s5jx8hM9AxnIz9aEwKfkhf3j
         BKWl03y/GGWdoYPavfhwnUZ4c/MCPNOYy6hU4bfxLKTSOKubYy4AmKkoOfHRFZJif5rm
         vpcHCGFfZ4SG4SAZx1LMupmwB+7ppYrSNu+r3NoZXs9Q1uBWmwTS7AAA9hYuDCy9fW/L
         i6d0qEMShw2GQF1D6RM5LoX5i+/dHEv4AhcaBnqswc9BVRCNbPGzgtY4kQ8i6C9I1a4w
         7ZCKFG/v7sQQEGicSX7CDbsyGK3O+flI76MpIVcny02n9YbzgxMH2icGVtoJ60qrEEGt
         iaAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gYcO3CjT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0GbJCgboZgXChk8vahOfffdFlEqRzSr57eQ/bG6ov+Q=;
        b=YTt13aINhqUAFDqTPwS5rB65/gLlzEprm3/DUU/LFYOezueYDdtc9nRE9yBYgxgb5d
         E7E8GMITmV0sSiKOfsXpq4Trajr6ZvHnqUSwe6/QUytmfW5NArHn/nGsxdNM8mqO34xU
         V3/iSchTK7UWX01eUCWej6mEjW2D6+4OqFRXdM/RP1IcDnsHthXGqYuCsqtcUgdlsgmb
         M3Te1f4XXYerKgLZq6fdRLq4Tx1LA8Jyp6EgxETrmNafIaKVkwaDuNo/D8ObjED3Ol66
         02Iex1zzC7GV6JQdsoL8g/oPFdoikpJmmYHkM11Zh+koNlNgwXa48v4eQ29Ylz/HNIYi
         ZvUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0GbJCgboZgXChk8vahOfffdFlEqRzSr57eQ/bG6ov+Q=;
        b=FctGhNydBtgrXrY5f3uYsejSZ/W4FS4qcAkEizg2snjvnymZ8LRfw/8fAZ20M1kTPv
         fYCZ28bSqOFja1uhH+dswS8ZQ9rUtbS36rf6e60MLZyd8tVWOzJh9O70OsmXn5vcQSR6
         geFl1AcjlQzeBpwChl7MyIXigJz9GPfWSz8171TbgVKtwZGanoBeCDfmWOrIgSypLfm6
         MBTM+ndzfZZV8ZBYEco0GzCugF2SKJ0FxMqiU8mmZitxyXDAef8hrRqhXgxuscvoKkfP
         B0I2nOjhR9EIjRT6YOH25L9DRXxU3Mt62QfkBtEQ3PvqCo4x4WKSKiUMKET8/oDUIavW
         D9+A==
X-Gm-Message-State: AOAM5317fxy+VrZOIRNAzygs29+1sG6ZV7/9PWPAXT8D3Grx3oGOHGS1
	XyD6PKh7GhYpTlj82g4sTSk=
X-Google-Smtp-Source: ABdhPJz5E3EErxopiiHWvvVH+bdaX20bemkbjRDpeAqRHE+oP7scKKJhJgWQoif8PXhVF/f06PlGPA==
X-Received: by 2002:a19:480c:: with SMTP id v12mr2792426lfa.195.1601572777653;
        Thu, 01 Oct 2020 10:19:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a556:: with SMTP id e22ls965753ljn.9.gmail; Thu, 01 Oct
 2020 10:19:36 -0700 (PDT)
X-Received: by 2002:a2e:5d2:: with SMTP id 201mr2498880ljf.73.1601572776366;
        Thu, 01 Oct 2020 10:19:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601572776; cv=none;
        d=google.com; s=arc-20160816;
        b=qs7ESo9WXeYdBlivgQXz2H85jc5D1mQBKHxqGluVEco7Gd17d1svHEWzNmnHVxhiue
         HRoke9giV4Wsb4CrruCUGzMcUhDfhBnO6W2yCz/ZEgDXUYIw8XXgoKwP9+mZ7vZtHcnZ
         ryGhSPTr7iw0lP97e4pdmkJVSJ5NwgrPnGUZHiarjWdI4zLGHqncuof1ies9kRXhNHB5
         8z5ygJGyivmTT1eohTmNvay4rHuoTCXJLeZw2D2C2kqNCC3h/Lqi/f/8HGyjTVbssf1W
         0WIm4TER1GalnJ9fjZFYQMqTK5x5Qrj/6SlAZSjxmAzz9AUUNXnxqKj31VZISTCe9dnt
         bvyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=841G/mTiLV3Ld9kFkAJj5hFI/sTrvUOlTE4BhfWwZTU=;
        b=xgmf1QLe8MQEMSZD5RBXRUjHvyg4sGE33f1/Q6Dz4ZJWOy8eMgBMDVRHWtTmLVUoVV
         ax9xUlIHVY0O43daPQw/DgC61Ul54kyqnc1CLgXhtjhx/RfT7eM8JwbJ1riYP7Q6pPQ2
         fKgvDRYGGl7tnWxTOICRMI4+L9wbXuer64+nxYeQQ8lvnzw374XAqEsXgaZwB5TznKxK
         Efy0+JZNtpGro86kdRgelNP/UFpWJwYh8EvLjurwRIrjTOrppbPCpYnvigNvpAcafGA2
         OISpC4FT2pkqJ+fAdd5syRaLbgQ1G37JcPZ8u6neqkxvR/qQdn6S/Sp383vvLiFWLqln
         d7KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gYcO3CjT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id f23si196772ljg.8.2020.10.01.10.19.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:19:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id s12so6707649wrw.11
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:19:36 -0700 (PDT)
X-Received: by 2002:adf:f802:: with SMTP id s2mr9774230wrp.328.1601572775654;
        Thu, 01 Oct 2020 10:19:35 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id v2sm951415wme.19.2020.10.01.10.19.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:19:34 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:19:28 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 02/39] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
Message-ID: <20201001171928.GB4156371@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <bc98612aeb00e3ffad45a103fdbfa4fc383b3d0d.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bc98612aeb00e3ffad45a103fdbfa4fc383b3d0d.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gYcO3CjT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> Currently only generic KASAN mode supports vmalloc, reflect that
> in the config.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I1889e5b3bed28cc5d607802fb6ae43ba461c0dc1
> ---
>  lib/Kconfig.kasan | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 047b53dbfd58..e1d55331b618 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -156,7 +156,7 @@ config KASAN_SW_TAGS_IDENTIFY
>  
>  config KASAN_VMALLOC
>  	bool "Back mappings in vmalloc space with real shadow memory"
> -	depends on HAVE_ARCH_KASAN_VMALLOC
> +	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
>  	help
>  	  By default, the shadow region for vmalloc space is the read-only
>  	  zero page. This means that KASAN cannot detect errors involving
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001171928.GB4156371%40elver.google.com.
