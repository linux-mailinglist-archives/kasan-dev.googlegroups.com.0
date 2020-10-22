Return-Path: <kasan-dev+bncBCMIZB7QWENRBZF5Y36AKGQERVIZR2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 76A4029615F
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 17:01:58 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id p17sf1265839ilb.5
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 08:01:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603378917; cv=pass;
        d=google.com; s=arc-20160816;
        b=WUzywbJPd5Qnc67kE6VE1qzlH4NF9rGdPHrbt9Tsgf0gwXNKvk0BgBQNnDbjAbRGxP
         jNekdK3bMQl8xmr5l5SWVk56Swky+ZKxDRWV+WOsquctMBgerKc+4HWVhwHIfU32f+i8
         2uxNnUTuKZZqHdyyhfQdi1la0EVlvY0kiyCBdhL35Nudgj9o3uqQDJQHtpwaLVIpsLvg
         adfP6yyOrfhMRjWRxnVz36B5OrY1f2KAhSlFb35bJbvb5L5m+XZQ8FUClZbyyQ3vdat+
         tfFsUTxxPbvs0DhNGASLtKYjj040vUX8xT4VsS+s522ROBpHi+rR4j/XzcExM2Pci7ZR
         tHRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rbsO/n48jNV4HwOk/ar/+2mhDbnoR2+qdkCINxqc+G0=;
        b=vH9f35HXiDhV+MGK/IJSdKI3UoBEqRpVW7+pWSzzwVv7N9KsbTc4rl9p5e7hoH4hEf
         EPny6K4jzFEu87bKXnPGRktJ+D/vLc09zgV2d2GQ4C4pb4gDvSYwoAzr6Er1A+xjzakG
         avFduxVWocYPYSNPq8gFQu/cWRD22RMK2gu8ddLNfYZujBdsHQrFPshiGQUCMBGDenPs
         aZTiEc5MoT02qXEKy7PWsKfnR/BS2l43GqEBrAVBcE54UHfzFf3kfEpnzc7rH9flLPjc
         whjznUcUfKJNGqDAJw3bi1WmxSU8WtMnhaqOOA504eLBeaIaILn08/itGaDtYe2ZebD+
         NZoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="BLx+jh/d";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rbsO/n48jNV4HwOk/ar/+2mhDbnoR2+qdkCINxqc+G0=;
        b=LoEIR/wQxrHmb3p8mnq6PSaSuBzc0+xQEfBwoWAXKEzGOL9Le7ek0UaoihXsbmlQ8G
         BnrqL25BXUZPgmhjPfJWUPDpiLbJ0Y+mnPO2GWQOf+eiQDZRtA7uUpmQ7+8waap0QKYL
         ZU0rzDPbX24wjFTBxVDXZFGEJmu1l8OAiwDt29uLfzpL2w3/eR9zMtveOvSSdHw3uhwG
         t8fyp7aopdCWd6QN9j8IEDEFHfjfNhDJEl82Rx0zoOTo6OlNzYE5G3pDm3Yx17XEGqh2
         gCqwD676dh/zqnqqsW4U2+lFkee6XIfywq2pKct3BByejyoXa2uBMYcugOmTEwlHVBxE
         PQKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rbsO/n48jNV4HwOk/ar/+2mhDbnoR2+qdkCINxqc+G0=;
        b=orqgaFzIaY5hpj0emY3Lh6a6WiMamUfUQqOe+gPk+9JQ2RYZxq08Ep5roaD5uQg2Qf
         fp19sbvvtL2jLmOT214zWiQOuPg6J4QktxbVmM4+ccL/AE6wzh0p1z5FulESYprXru2d
         hUAWmGrUm15KtKw7hI3gssGFQYr8v71hrjyeAPzHabRLlwtSsE2zp2lzN6Y1bFC3NoQ8
         Y3zpn7TgDA5jDqw70J+zisan2t7X8tWFdj6Ai/VwV8SDZmywUFOossYXxz57PErF5YxK
         77FNqNkv2kno9s/H1r8WTiO53jgvxum5QA73SXBJ2FG4Je1d3GocpswGcnDbkka/cX2d
         YcTQ==
X-Gm-Message-State: AOAM533uSCwwbdPhIu5pEk61F27PZeO+H5nFK/jntqYkFaXePXAHVehm
	SGqRZ5rQCebQO31hI1su7CE=
X-Google-Smtp-Source: ABdhPJzyrC9BdjNL5An+ryF5Q3OzFqH7fBt9dFIbI2WQAM8WAJqwYm0+j+HdqzhgLaR7mV5YMZDv6w==
X-Received: by 2002:a92:1f19:: with SMTP id i25mr2280147ile.198.1603378916522;
        Thu, 22 Oct 2020 08:01:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1805:: with SMTP id t5ls264720ioh.0.gmail; Thu, 22
 Oct 2020 08:01:56 -0700 (PDT)
X-Received: by 2002:a6b:4e16:: with SMTP id c22mr2198345iob.26.1603378916109;
        Thu, 22 Oct 2020 08:01:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603378916; cv=none;
        d=google.com; s=arc-20160816;
        b=lhIHpvhGN/hUdvceq1Mz0xIvzK5PVal3/+SlBNjgtuCds5xzahlnG5474bHh0EWeUp
         t8fwJ+t7tLC8PwhkLRGM7B4/Y7BuhLEkliyILY//rvPl6kEYF9cAk/z1hgy+cBtJ+uqA
         wa5dzkN2IxVSmimok95WmoP5uOCfo2WYqDwCAs6YyATi4f63vxmRmNavE2O3C7eBNV2W
         3LS+vfdJ2IYIBgILarks5mKv6D/nT767WcOdnSvecwyIMYespAld2z4BgjStugSdiDku
         OTyLq6BOiwwgXf8Pe7VFkodxviavCz+2zgaw9psgeTpVRlhgO0HRnQSgmcRTmDp1mOv/
         dj1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZW7ZoAt++RoH2KNzOMUfkR9nPDRVg42jI1rqms4LUto=;
        b=XSXphXStahfsxUJixEAfecmcrhfq4k7ZEeOEl4vO7sLSGZKqPWMbGV/+/8z8bFipvw
         gcmUE+UIlPvb6GrZGHoakbuOSFj3YLLl/OaquxDhD+Ogcoka3L1CZ2wu/1mpOe0dVBci
         PDIKYi6Vdv9srt1DUVgvrjo81IZdNQ8o/jmw1H68cnkM+f20G+Eko0MTQjZNsgE7hhbK
         xfHx6mlPMmLLSIw3IC1RvMEQMGZc1ELqoVUBB4tsxhh1mUJWhn0xbqrMjJm5zrBGZ9J0
         qPFdDtpEo+ULQLf082Evsw5hcb7qSoyvrqPqPdOcBQR4+wY7jnbB9OeyRXJT50r+i70N
         MNLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="BLx+jh/d";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id e1si97596ilm.0.2020.10.22.08.01.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 08:01:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id t6so988381qvz.4
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 08:01:56 -0700 (PDT)
X-Received: by 2002:a0c:b741:: with SMTP id q1mr2828937qve.37.1603378915161;
 Thu, 22 Oct 2020 08:01:55 -0700 (PDT)
MIME-Version: 1.0
References: <20201022114553.2440135-1-elver@google.com>
In-Reply-To: <20201022114553.2440135-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Oct 2020 17:01:44 +0200
Message-ID: <CACT4Y+YEa+mAH_RcYGRx=H=nk_VDB223_sKg3ZV7CHbm2ftiqw@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kcsan: selftest: Ensure that address is at least PAGE_SIZE
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="BLx+jh/d";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Oct 22, 2020 at 1:45 PM Marco Elver <elver@google.com> wrote:
>
> In preparation of supporting only addresses not within the NULL page,
> change the selftest to never use addresses that are less than PAGE_SIZE.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v2:
> * Introduce patch to series.
> ---
>  kernel/kcsan/selftest.c | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
> index d98bc208d06d..9014a3a82cf9 100644
> --- a/kernel/kcsan/selftest.c
> +++ b/kernel/kcsan/selftest.c
> @@ -33,6 +33,9 @@ static bool test_encode_decode(void)
>                 unsigned long addr;
>
>                 prandom_bytes(&addr, sizeof(addr));
> +               if (addr < PAGE_SIZE)
> +                       addr = PAGE_SIZE;
> +
>                 if (WARN_ON(!check_encodable(addr, size)))
>                         return false;
>
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYEa%2BmAH_RcYGRx%3DH%3Dnk_VDB223_sKg3ZV7CHbm2ftiqw%40mail.gmail.com.
