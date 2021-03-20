Return-Path: <kasan-dev+bncBCY5VBNX2EDRBZVH2WBAMGQE5ON7MNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C33A3429B2
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Mar 2021 02:46:16 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id e34sf23339113pge.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 18:46:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616204775; cv=pass;
        d=google.com; s=arc-20160816;
        b=TJv4PKPcIgsRgNpb2Y7EUPvmePtvRGE+U0EEJ8/0475y0MXivXo1/lXs/qIZcv/7VA
         SFGSOhyzXUWN5fkUajb4FXU62ktMMAYFOQJUXJy/hzhkGlP/ALl9XTO1ywUEdkRZ54Nj
         bT9w91Lbj+wbrfCwjOJN8UZV6RlNVMSQj6/YH1zFKRX++KcPGgVzfdrgcjWzrUhlWSaq
         D+IJaIfYgjXTBYU4yrd7efrw0U+J5vJjXMXAz2mGbLPRZOfqtzUm/ofXncPDVav+iClz
         M5vxe9aHPmjkB5HCGuh118IHhPR8Nc3McSRMMIpm4oe8v7kT7yB/p9rZar2G+DSrzTQ9
         FyyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=Zad7Hn5k0KGtHbieDz47cLV+232gQDEmyG+hN5XnJ7o=;
        b=FfsIzokYrbXS8QckY76kWbseYlBTRzpakRirRSiOwrujXLuQNHjFwcBAnginlYlTUB
         lx7cQhuhyesqa/lYjLwPbJC2P4UkmWCwaWs+Wqdu4a6KiV64rz5ZjnxUnfwj4SNTypDr
         9dvGMxZ7ktnRnOZpoKqx3tB4AcFQpcPQz/aIxf/ptJjGN0f33yGNa/UAxjbnVlXeNM3h
         +EWgMGF5Uh5fycGEeJs7i0q1eW1xyDOr40w5zHKrL0UNbrn6Jf6K53Ic4A8LX3wdffa+
         8bREIpjhHw/ol/nYk33XyeevZwDQvAZJu3YmZNE44tvQAUu2Eid6Czl/cQ9GFpLOBgGa
         A4zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Xdpq21dU;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Zad7Hn5k0KGtHbieDz47cLV+232gQDEmyG+hN5XnJ7o=;
        b=ZwoPvjvdQKif7B2rMUaYek9TBYv8YuWkF3pk4RbOMd+mCPLKANVNCxk5eaRBtBpIka
         EevYNYnYBFSJ40lNEXLgVsFGs+lDwbCELEh3CmPB2yt6kkFm86XR6d/rd8MvmzfybGyv
         O569xCs8AEG0aqlBtcgGO1BR5YCxz8f1/12sAcXjVw6N4eUpP3U3TniwNfcwSM05yWOz
         w6j3TYeTjwaxBwSouAlNjBcO9Tj/AI1mCllOTZodaQKVfNbOPWVisbED9HcEH3Ne4EyP
         2hlKPYRflNhEiHnwJ9tFimhEY5zLvo07AfNOflw3B1yuCyebPJRqEa1lbicpevILIGI5
         IB/A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Zad7Hn5k0KGtHbieDz47cLV+232gQDEmyG+hN5XnJ7o=;
        b=lRApJasIPlPssPUXjvT7gpvDJjKDKZ53OM0vfvWF7ZeYnJ/wIR46hX4wFyxTsCIgb5
         ScnGWi/RYyhxT8tFMUMpxUu2V7QdAchERGE+MAhLKiJpdkCy7aPndNmGg3lXCEuQWvGz
         r+hQPRNPQLP8vH00E2Ljtb8dvGJqrCe6JM3IbqHRjiJdPgYBX9FJiirkNfCea/9IQMqz
         IzhLXvlEBxJ53+bRIPWgK8I/LTPmjYHosAfMmjNnPuD8bMoKsH/NpiWmfH0oYbn1A4Bo
         N9UMkT4HkywOVyQ5krQ7qXnR5USvb8vOzkWYejygP+OlQrjTr6DZhHwHBIdwUg1Ik1CN
         BJeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Zad7Hn5k0KGtHbieDz47cLV+232gQDEmyG+hN5XnJ7o=;
        b=NabACslUcnE4JXJZg09McWSR8NdpXd0fezTN8VIJwy8BvriPfDxSj6ZhP/NA7Y6fcb
         EGrQY5JlYTanX4ilz7Dn3zgGKJIu/Gxj5sUMzoC7Nj3OGdwd4kH5DFYk8lTXf5cwKTFk
         3mrLUoXXiXJF5r/LpD3jjLNCe516tEG/klU6V0hYClZoE292M3HpmTTzj9vaV+0TrBhZ
         Xi56T4QQTpoJojwZekEkqW7FdLs6/eE3yTxEnKXD1IWu8VfBcsZHq0S9VDHKyYrvc2/j
         mOURJK1m6JGQF+XT2J+BqTUubj3J+c5dihxOUg8vbfh0sPEmVCuYEgkY/nJXjI3+6HMU
         Ar9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NzFYgUpGObsjVMzo9oRpLqkMQv/ofHDxikE7Ie2rXsJyghDJN
	wWiuJL6y9htQ0T43WPm88oI=
X-Google-Smtp-Source: ABdhPJy0SHami52QDN3iR2/EECLWSLXmZjHkz+6XyCpVRE7ICmfsbh0Uwl/glgfr1uIEfo2QtXDo/g==
X-Received: by 2002:a17:902:7407:b029:e4:9645:fdf6 with SMTP id g7-20020a1709027407b02900e49645fdf6mr17074295pll.19.1616204774878;
        Fri, 19 Mar 2021 18:46:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2138:: with SMTP id n24ls3079004pfj.1.gmail; Fri,
 19 Mar 2021 18:46:14 -0700 (PDT)
X-Received: by 2002:a63:5f0f:: with SMTP id t15mr212526pgb.225.1616204774326;
        Fri, 19 Mar 2021 18:46:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616204774; cv=none;
        d=google.com; s=arc-20160816;
        b=zL+rmIkyFTOrL50zwlLEvI4qs6f/kRstgN4PUoSMNGoiiGR1PzPepgaU08KxOxJ/+l
         xbAgLxd2wM4vfjwovbilL/oCp6luhiFfyHTn/0UYzIWZgA4QkV/Y+KDr9tyabH17k8F5
         r5hISZcitBxQhJ7V3FZL7KOVTI31zOmcNnswRacI8yAYnw1Cugo3Ozj7t9tmm7Wl0Fv2
         5UXoAFouiDfQJo4XicT8yZfBdNHrT4vuf4OmXXRwh1EXhcwJ0LCbbxE76gpwUCQPTVtm
         NCwz53XtiflSEu+BvILTi5fbVJPOqhjoak7DNQtOOgDQN6ppKuvvEGWlRi1khSf3O4fA
         BYQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=uQvJ/OVGn44ohP4ik8L4ZCZvo4WeHXCrQuFyrKsQHDw=;
        b=WlF+ZMnFmbtjd2DxiuWvcDZmtwGnnsLgY22PxQ9uNxIeid1EVXmor5uzb2akN+88xO
         tjmbnp9TtP1ATQm739g68oCA3eqwsfGCoVpW1m0GiRygvBQrg/67V9v9wdyrmfDe7qR8
         yEDECI6gy5iSeg4elVXTPw2Z+zsGf0ZQZc0fhHOdb1wi5hK5LIht09zHRZQYyaiLx7fO
         VJMIZJBFJt1OAXsgW//Cr/BYbtcJwhUiilY0yCS9iqXCNrizfjOyPykaiODp6hwYEmuD
         odDiuA4F/X9MadfPb6jNqB7Q2O1uwaZYS6Tg0g7+7IvfI4j8/jE4tLynuc+nIgZx+2eT
         ls6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Xdpq21dU;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id y17si383650plr.4.2021.03.19.18.46.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Mar 2021 18:46:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id u19so4858856pgh.10
        for <kasan-dev@googlegroups.com>; Fri, 19 Mar 2021 18:46:14 -0700 (PDT)
X-Received: by 2002:a65:6a44:: with SMTP id o4mr13646992pgu.312.1616204774010;
        Fri, 19 Mar 2021 18:46:14 -0700 (PDT)
Received: from localhost ([103.250.185.142])
        by smtp.gmail.com with ESMTPSA id p11sm6305703pjo.48.2021.03.19.18.46.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Mar 2021 18:46:13 -0700 (PDT)
Date: Sat, 20 Mar 2021 12:46:06 +1100
From: Balbir Singh <bsingharora@gmail.com>
To: Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu, aneesh.kumar@linux.ibm.com
Subject: Re: [PATCH v11 1/6] kasan: allow an architecture to disable inline
 instrumentation
Message-ID: <20210320014606.GB77072@balbir-desktop>
References: <20210319144058.772525-1-dja@axtens.net>
 <20210319144058.772525-2-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210319144058.772525-2-dja@axtens.net>
X-Original-Sender: bsingharora@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Xdpq21dU;       spf=pass
 (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::52a
 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;       dmarc=pass
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

On Sat, Mar 20, 2021 at 01:40:53AM +1100, Daniel Axtens wrote:
> For annoying architectural reasons, it's very difficult to support inline
> instrumentation on powerpc64.

I think we can expand here and talk about how in hash mode, the vmalloc
address space is in a region of memory different than where kernel virtual
addresses are mapped. Did I recollect the reason correctly?

> 
> Add a Kconfig flag to allow an arch to disable inline. (It's a bit
> annoying to be 'backwards', but I'm not aware of any way to have
> an arch force a symbol to be 'n', rather than 'y'.)
> 
> We also disable stack instrumentation in this case as it does things that
> are functionally equivalent to inline instrumentation, namely adding
> code that touches the shadow directly without going through a C helper.
> 
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  lib/Kconfig.kasan | 8 ++++++++
>  1 file changed, 8 insertions(+)
> 
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index cffc2ebbf185..7e237dbb6df3 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -12,6 +12,9 @@ config HAVE_ARCH_KASAN_HW_TAGS
>  config HAVE_ARCH_KASAN_VMALLOC
>  	bool
>  
> +config ARCH_DISABLE_KASAN_INLINE
> +	def_bool n
> +

Some comments on what arch's want to disable kasan inline would
be helpful and why.

Balbir Singh.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210320014606.GB77072%40balbir-desktop.
