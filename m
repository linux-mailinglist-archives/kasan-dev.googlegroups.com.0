Return-Path: <kasan-dev+bncBCF5XGNWYQBRBKVMROYQMGQEIBQVKEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id B0CA28AB60C
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Apr 2024 22:38:04 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1e85099dd23sf366975ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Apr 2024 13:38:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713559083; cv=pass;
        d=google.com; s=arc-20160816;
        b=t/wjv8dJKi+TChumto7U0Q77q0BBFQu1jiI+6kkYQw6C9oaxffCIyVKT5VHPs3owZD
         5Eybif8zLObrHvMQsxHA8QGW3PvuEU4iuvzbPeVcR3vr4Z8fD02iNujMOjE1vEL1K02K
         Kkbxv/QN6gRgv6y8JLnWoxmIQEwuO1zrUozGQKN148qmjkBinfJN6ilBHDW0NJ3ICH71
         n0rNk65zWZxNuBBo8V9hce98riwJbPNSbhfhM28QwvsHnNtRu16VL4d0U/auTEG1z4Ot
         A98SvBrZg/Rj7PsecJDi1F5/NNcz+iBIYkCxMW+cAh0CHaA3LdfmziG+R0g1if8mmyph
         oIyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:to:from:date:sender:dkim-signature;
        bh=1FEla+hTGYNb1EAxxO7ZvAHgYrw6y4m1kw0SRi3DkZE=;
        fh=/oNr2bZAf3/de7oHl6PFZp3XoGPsgX/PgvpSUeswh/E=;
        b=ByjH6nXMJW+ipmgKyWWt5DyNQaL0VptKKvBMxeF/Pccqd3sC81Lgfez4uQ2X/BteYC
         RB8n2eX+iQgmoSDnvawKK6Cw/s14U8bVy5Yxw3aG0W7kXcUoQaFVT76+tVJzGRLnoEaj
         QVH8PyArxP8ZmLZtYiGxJFHWf50hrN6y64zlj8tFoHpnJZJKdsMu8RoL8hbUbweLszyo
         D8WO+qfz0BlzqZYSl6Yvalp/TMD/imSctRYM1ypq7p/NxhoZcIWUXgGKRYPB6sGu1xmX
         lIINFlVz/4mqYzt1ePdGpIc/PkPlPYmslJNoV93QGj6ONzKU2QZepRg06r9XCEAK3Y+F
         pcSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Ra+JKD0K;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713559083; x=1714163883; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1FEla+hTGYNb1EAxxO7ZvAHgYrw6y4m1kw0SRi3DkZE=;
        b=EPweDi6P/yeNE6xpErR4kSRXiuTeWv4AuTsg4kjvfUIi5zQDyTHZfigoGElVxOU96+
         hgT4ObeO9bldNna8aYM1QkpRRnqZNmmCAy0aqaXFC56/dsqYgamlSySnr9Tf6lj5AasW
         cWbaXN5m1ZGZpA7gc2eofvRDDqLaKOUz54+wQ2Zpo7dJN4Lgp/rCIJRlLlWVUT9bP7Ye
         ezB3Mpynw/VYsjFFUtt9ObmBNRRqPEaP6GvnDdmKOvkysAA1YUOK+vkjAGbPR6bNvGhz
         Mc05/ibUhsFxSp9sKx9UHqVhwmV60Ph1iCvntTC5SJatkDpFMXXCzGwy2vFJboGxQWPa
         PyPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713559083; x=1714163883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1FEla+hTGYNb1EAxxO7ZvAHgYrw6y4m1kw0SRi3DkZE=;
        b=BiT6nisqyITalDbcFzjSlVS+Wi0jJjdd2ndrR5Zd1DefXY2AvvuNOynimO51Ehe8Oi
         jrAlu4NN+3FC8j1LUJSsEB9591gc/xML+QHD+senc9vIzoONdtY02FaaRMrffZM2wOB0
         y2Yv+3Eu98NZiKApdb/oaTtMFluDp764wyqR4F2kdCxhck6w5FmjtuA8Kx9QKg2ZWMee
         wG74QDy4wnTodwI/4JIx/0LPYg9Y00xF3iNN5kZgtRlb8SpMcrIBjqwyM4UBd+cyUdxp
         0BFruhmQsBQSjfsQenPvrlWBfW/RvM0btjp+O1HX3V5sSdw59T1DNo0XTvQTPS5kFujB
         Bp/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXgfFPzr9selvdgcB1gJ8g4kFx3i66qdue6BGP9dqv8PT7b+9BhUwDsWEVPs0NvzwBfuBofZQYdjHhzh3hOjkkI8tm2aRMt/w==
X-Gm-Message-State: AOJu0YxZeLyVLFCvXS/8DfzwjkLEclz0KTnSJguXs48lRAKZqJ33iQz6
	Ck3oLmnbclBN5gzTeYvJ5upHkg1kapEtTPAf7bP4N4qiFVPrwu3Q
X-Google-Smtp-Source: AGHT+IEMOpAoYujr7/kQKrRvJ1VkciCFlUgs6Q1yEVaTuWE85y9eqYIvhkd6sgk8l/I/G1iD3fT03A==
X-Received: by 2002:a17:902:db04:b0:1e0:c571:d652 with SMTP id m4-20020a170902db0400b001e0c571d652mr6289plx.1.1713559082793;
        Fri, 19 Apr 2024 13:38:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9a8b:b0:2a6:f288:53de with SMTP id
 98e67ed59e1d1-2ac46606cd0ls662586a91.0.-pod-prod-01-us; Fri, 19 Apr 2024
 13:38:01 -0700 (PDT)
X-Received: by 2002:a17:90b:1652:b0:2a2:c2c4:9d28 with SMTP id il18-20020a17090b165200b002a2c2c49d28mr3437354pjb.8.1713559081554;
        Fri, 19 Apr 2024 13:38:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713559081; cv=none;
        d=google.com; s=arc-20160816;
        b=ZCXinHQGDYvDDAwHEch9mRa1kLcVCz6gF7m8xbtBD7SdRns0CS40wMAX2GpJ9S4gQf
         XOmHhLjmmrd9T17weNF7iznIUncUaEifsep42zctPdy5MUjErtjNtzzpfhmtr8IjqoV5
         +8XZv7FpNLXrhEaWeMS79qk0i3iywMqByNmBjkfADGJVtDOshXrPTD/zpC0ItFnwA6Lo
         dehM4sf1V5b/0Bhg9S0SwAQQ6sN3mgCjLhlVKgISO9rT35m6+N3f1HKRqNVbVzM2WJxN
         LJLKaR2Bg8glg5sFVBq20LLFrCaF5qRLMidjPvhdDyEbugu1AIm6RlLc9yLsSKHW/DEe
         hUwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:to:from:date
         :dkim-signature;
        bh=MhYydZW7e2Y/xUEQ+9qkB4rAGAVXiOoXK68nWmS2eFM=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=bN/T1f9I6bpsrO65O/mcxyLjuro3TAU51CUTCYyTJLvYGHaAoi89dhdrIt3sHYsFkL
         fUxgwKQ4QWjoqrfH/ny2gsm7fHoqcO3u1OIW/PCs8F75+OG477UVC5p/zUevc+Z/GNIV
         KKe0pxNbPygezrd6NDXPlz4Aljid8Sufpjs/lerAPRJVmMAivlHYDtf2+aOG3I2HMGtO
         H73+mN/bckPhJg9urz/re+L5L93qQIoFPMXZYOxL0/9d0UK2Mh1iSVwKENGzThBn/gMZ
         fcLmRQF92QyEN30qpl9ELTdPQkRRYM61etrdBoUTVgvVIzeWeVEGuz4j5X0qlHcQo/dh
         wYew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Ra+JKD0K;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id o5-20020a17090ac70500b002ab49d40dbesi415585pjt.2.2024.04.19.13.38.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Apr 2024 13:38:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-1e3f6f03594so20483365ad.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Apr 2024 13:38:01 -0700 (PDT)
X-Received: by 2002:a17:902:8214:b0:1e3:e022:1dd9 with SMTP id x20-20020a170902821400b001e3e0221dd9mr3008628pln.40.1713559080991;
        Fri, 19 Apr 2024 13:38:00 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id q17-20020a17090311d100b001e904b1d164sm655987plh.177.2024.04.19.13.38.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Apr 2024 13:38:00 -0700 (PDT)
Date: Fri, 19 Apr 2024 13:37:59 -0700
From: Kees Cook <keescook@chromium.org>
To: kasan-dev@googlegroups.com
Subject: Weird crashes in kernel UBSAN handlers under Clang on i386
Message-ID: <202404191335.AA77AF68@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Ra+JKD0K;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Hi,

I've found that Clang building i386 kernels seems to corrupt the handler
data pointer. I'm not sure what's going on, as I'd expect syzbot to have
seen this too (but I can't find any cases of it). I've documented in
here:

https://github.com/KSPP/linux/issues/350

It seems to be present since at least Clang 17. Has anyone seen anything
like this before?

Thanks!

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202404191335.AA77AF68%40keescook.
