Return-Path: <kasan-dev+bncBCRKNY4WZECBBTO62GAQMGQENTSV6FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BCCD322450
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 03:58:23 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id y15sf9132633pgk.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 18:58:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614049101; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ae4jkH1hKRMU3OqkVb2gYKO1JL7+5cdSMpd8eMJCydQ4UvMfENQwKEcmu6Jiqxvlh0
         E9pwCwWZAKYGuv0dQKEhrSw+jFLRDGUTP5C5Rv5r83u0h20/riQKa7D3rWTSfcEtFR70
         osUpGJGBjABfD5XVNEdo4bI3FH2EGEclUSbXpl6JvaKP3EPGVdDgqSJl2erBZz/q/8lK
         cgzYPycwwxMpJSzGtz/56dEAYJHpwy3UDXa/11a6xOawaZGG+0I4Ma+zsKK7VaDA/BS5
         YVtwmaqnvcZ9ZLNLfqu3WSPI4bRfFgNbXb9RPWVeBT+Ss62rr2SZsfwG/JLAvsn8XJwP
         VyJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=O8pSsBpzWsf+JL5JD0Jz0WpJD69rxJnEjvt436WzHkA=;
        b=qteF/ZwRrIEhNIsQeUa8B+QAlIVEvBDmPfhdfo8yg1zNP6gXUXiLk0/gtph99cmkq+
         a/djSgO5H1iC82l65bHCBjAytU9rzCMWx6dyoUKN3AtdF5SgKRF6XIowKZSwZ4JHM4C3
         KckjMPyfRcpp55U5VXOqaZeSvuhWEkeSgmrJM/N7KQtwK4mNm+Xe+g4QCPqAbsWWwwA3
         IXVg24NhdaBe8i8BuNe9sBSu3V9uOgunGMDUUU1ucwHTqao9LkyoYjjRs0ajscQ7+D1z
         mOcYQ7fpaERao3nUeAfU6p9jNF86YTsjt64kxbdFhwxfSVtosXpb6TISnZ9Dc9rXPMqX
         jpvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=fTW6i4gd;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O8pSsBpzWsf+JL5JD0Jz0WpJD69rxJnEjvt436WzHkA=;
        b=PoB3F4XCCf5S2Ck0gWhzZkhpL+KvLQB/fyqOZXpo32WvmHuik85wYXvH9pa9SZc/a5
         hb7I7wI5hhVLYbJJS95WR9nNhsDViajip1D3iUr1lGM8CPeKgwH6Rbei+5/dBJEqWXNW
         g4oiHJJdFLfnSCzOz+RuimDQPps2TifH3HwmdTJESmcLRLJvr2pU+RgIMY6XTNThy22E
         IcERVYFP5yvXuBKnitb0l15c0/92yCze4ElTlXTlLXWULDBy7/FilbGv6WiAmITItkCw
         EnD0lNgBDGdZLZzge83EDk7QY500jGxviXC4Oy+6b4pCs9hUIt3ws+evcf9mQrXGHsr+
         pN4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O8pSsBpzWsf+JL5JD0Jz0WpJD69rxJnEjvt436WzHkA=;
        b=pUZzZNaSbBu5hHB8usbO9UCZZXI5m5vhDxHoUiqz0bfj1WMKlYI2qnqmyzlZmcvx8U
         bWKWkpOidgnPNsOiZAfOLFYsFnRi14R0/3IArRd4Xj9C9cW+C0gxb4vW+7qWVgdbPFZ/
         kRHbMOesnssA8jV9ELWm2umz+a12baoLU6FTti1Q3g1hNZvYM7xHp5XSpmIX68w50KMJ
         ISw0P7EeIWPQM68wRfVID/Hg+SxMoYg+qEg4muV0ewmVNAGLWfgvejl1wYymG52OKHNe
         KUMA6+rmSaWDpaVoBdqbuImntjonhaelC5G1KWit8lcLz5mHk4zrENgc1wRF3OWBULvz
         Yc1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530GN2H3QycrFnuyz4I8rlkRMv3dwgql7IgdOdPQLWpCLfJCerww
	raWgaS6AgawxR7js7Bfy9wc=
X-Google-Smtp-Source: ABdhPJwAwn1L22DV6lk8KiLi1ncJdHRhdTCGJwATYZTsGdRqf2lETdzJvAfQuyhc7suu3dGCy2ku2A==
X-Received: by 2002:a17:902:c24c:b029:e3:f6cf:36c7 with SMTP id 12-20020a170902c24cb02900e3f6cf36c7mr378968plg.60.1614049101719;
        Mon, 22 Feb 2021 18:58:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:78a:: with SMTP id 132ls2491745pgh.4.gmail; Mon, 22 Feb
 2021 18:58:21 -0800 (PST)
X-Received: by 2002:a62:e209:0:b029:1ed:c415:3a86 with SMTP id a9-20020a62e2090000b02901edc4153a86mr269487pfi.19.1614049101077;
        Mon, 22 Feb 2021 18:58:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614049101; cv=none;
        d=google.com; s=arc-20160816;
        b=BIj8azy3YJNGdrKv2mK23xcNdW7cZu+1hvwlPeQZ7O2d8DzmTbDE9jWWc6rEmgWvjw
         5w7j+ngyfOaKx1xpsJ2iFw8v8JpcSydq4PERAocAtDBxPfIqJgf3pig+uiMbs9Wk50x0
         Y+KXcZw+vIfhME2Meo76BFMPOy3YjUy+Rl/2h/9X79+EpXFMSChlm29p1y6BnFJroAri
         TrqqllFCOBd4PZpx2ocJC3gYOPrfW8Q7BglUMPkgMjBUblZL5z/yXJ+uiAWFELuIokea
         nq3QUcRsfnr87AybJt+pdIB8jsQ5gA5t5KgujJcfQlBPccSvX4T/he85ECOemf83HYE8
         G63A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=CjGqwkyVdOUjMU+Osg0oifDQj76K6GurWtUd7NJehmk=;
        b=PXx32qyh/caFSC6hRpHajBn+199K2X+o4cSdYjEwW/Y2MaB19S9e+WVRzUzSreldMM
         tOPT7AlMFja+NnlSK+kxFwkHab7OR8PE90aV4xGYRZ/736IqJPVZANON0j4Iwa0gFZ8t
         XQRxnnC1oyV9EeW1RErhK0eri3OuNUoTRf0E3ZDnL9rp9eD9j+Z7ZqdKye7L/+Ls054k
         i9BJ/E2yEDo1xOjkJJzQyCNtVw5h99xHy2Vq8QUBtvH349tMcgnaOSllPJgw/a4FxYSZ
         IE2B3Zv/T7K6WdqeMPC9Nvmfa/Zsjobyp/P0WDE8sx/ubY6Y+E4qVkyJMN5ay2IH9Qqa
         mY6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=fTW6i4gd;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id z5si72564plo.1.2021.02.22.18.58.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Feb 2021 18:58:20 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id cx11so873260pjb.4
        for <kasan-dev@googlegroups.com>; Mon, 22 Feb 2021 18:58:20 -0800 (PST)
X-Received: by 2002:a17:90a:8c84:: with SMTP id b4mr26336255pjo.21.1614049100590;
        Mon, 22 Feb 2021 18:58:20 -0800 (PST)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id j26sm20162062pfa.35.2021.02.22.18.58.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Feb 2021 18:58:20 -0800 (PST)
Date: Mon, 22 Feb 2021 18:58:20 -0800 (PST)
Subject: Re: [PATCH] riscv: Pass virtual addresses to kasan_mem_to_shadow
In-Reply-To: <20210222080734.31631-1-alex@ghiti.fr>
CC: aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
  Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, akpm@linux-foundation.org, rppt@kernel.org,
  kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, alex@ghiti.fr
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-ed9c69f4-96ab-417c-90da-4c03a48d1268@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=fTW6i4gd;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Mon, 22 Feb 2021 00:07:34 PST (-0800), alex@ghiti.fr wrote:
> kasan_mem_to_shadow translates virtual addresses to kasan shadow
> addresses whereas for_each_mem_range returns physical addresses: it is
> then required to use __va on those addresses before passing them to
> kasan_mem_to_shadow.
>
> Fixes: b10d6bca8720 ("arch, drivers: replace for_each_membock() with for_each_mem_range()")
> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
> ---
>  arch/riscv/mm/kasan_init.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 4b9149f963d3..6d3b88f2c566 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -148,8 +148,8 @@ void __init kasan_init(void)
>  			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
>
>  	for_each_mem_range(i, &_start, &_end) {
> -		void *start = (void *)_start;
> -		void *end = (void *)_end;
> +		void *start = (void *)__va(_start);
> +		void *end = (void *)__va(_end);
>
>  		if (start >= end)
>  			break;

Thanks, but unless I'm missing something this is already in Linus' tree as
c25a053e1577 ("riscv: Fix KASAN memory mapping.").

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-ed9c69f4-96ab-417c-90da-4c03a48d1268%40palmerdabbelt-glaptop.
