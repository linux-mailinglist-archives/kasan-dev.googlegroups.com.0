Return-Path: <kasan-dev+bncBAABBLE32HXAKGQE5Y2YLEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D1344102D5B
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 21:16:45 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id f21sf17626696pfa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 12:16:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574194604; cv=pass;
        d=google.com; s=arc-20160816;
        b=y2xvcol2OJ1t/bSMM7t3IkwCe8767Rs9wP/+hRkajQ5vequUSnBg7I22f0c8V6i637
         Vftuhx6cszAPqt5kaCEp0YXfvCVsAuoSVxPkaUOiOOtqGpxKcKEScWBfiafAWhVC807X
         KZukyxcPeAQPWk0hjCyA2/zeDmNc/R3OsDcxIyEigQ+2o+9X46/CquIBkBKqwGAMmvOM
         HkfSbN6bXWRSRct0R69rzI3E68qBnqqN4RJ/K7V1dhH4XHiJwsi63ajDAgweR5hbZ9/X
         IrkylFubbSsMf40SktXxdj4we4EjUDuX/z0qvxk7gFv1gK4dAzTPqiXHSQTO/WFsoomD
         hqZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=qTloklgYrzxCSGFRSo6pyt2bFD5A7pGAHz1jxaKu6fc=;
        b=t+7a+WWTgns8uxJkmk+3JRQ4hMxO44EptwUgEjCwebm8dYoFMNe0Le2t8BrGGtmpdi
         iHYaQK/ShDLYkJ/BS1kYbtKCjVAawYmARdh8T3iDfEuz3WIVA4aiI/jYChgTrW7z2uhW
         QrylW1WVRDiCW32dPf7PE/VOrtThPYI1O02rUYDYU8EV/V1OgRkPxTb1G5RVsfL1clzx
         LH5+u6E3/s72LFIyGRd3Ll49dDBX94yKkb9eCWSrdcsKRS8CTA1vVMZlCRbvMziB9OWr
         GAbTxWkY6eLPSYo1YCdIuY6+We2ZY8bX4w2ptOgzy+Lb8xu4x/Lk3I0gy1bUvMYZPUet
         ZVmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DFheVwMw;
       spf=pass (google.com: domain of srs0=yygb=zl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YYgb=ZL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qTloklgYrzxCSGFRSo6pyt2bFD5A7pGAHz1jxaKu6fc=;
        b=dF56x4HO5jAs1LWfolfm44FzOwqnwm1PgrSwrZjjszNIWNTh2kkIddPhbGir4PRu23
         sU1k0rrMYISSLh+rZRW7LKDsICeC/E7i/6y64Y3pnKWh5tLpH3ut7Aoawk1WXZeA25I7
         QEUSFqhgHmDPpBwY3Yg3YS/IXg2QbUD5a8gqC/vqQ7trwda6ySbQjlzKVp1FTAXd02JW
         jFgo/Hg/7j8/pogEenrGx5hVsPjSh2gqP8uHHQf8dzalQWgFR1HqP8iv3pyMMLRD0DFm
         8JVcJyaWyzbfQbbP3QsQbNua4ut9UtYJ9LmwTmLBfiH9MGbnrungzXxaTCwr32/ekVfg
         eGBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qTloklgYrzxCSGFRSo6pyt2bFD5A7pGAHz1jxaKu6fc=;
        b=ma7ruIQoks47NQOflWm4211hZKgTKgM99tdjcVIAzh3a2dnb/Zb1pagQclVOD6si4E
         RimrdLniLbfMNucOA7e0N3PeQ1UNWc4K3qzQS+CjBYuJIp6rArzUbu+HrquQByo4YLu2
         bDtyk7k5FIiIsaJyqWj7Q/K69pX9yt26adhv8W+RNwXRECYhdw63LsLoj8vWGfsUv0wK
         8ZB/dnjqwgqu0WudeQVV8Ca6lSSEFHXBHrbXp+XuKmdPpr/jHf639/P5fMRqzrvcR1zI
         hbxkpk/w5rLiHemUStSlAGqYzoOy2WVoaLcTa/N31bGr1y2jQ+1W4A9qvNbK+RJG3I5J
         Y2Lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVbrTJ5L4xWFZsyKY7C364X9eirnTRRrl49C1+KefDEDSBFKn+t
	xaicC1WEIHHJ436fpWl7Pb8=
X-Google-Smtp-Source: APXvYqzqQPg672EFXikdvxGlnqPNpvZaWBHNhveFlYkUNM83Zq5LXeV5I//lAq7tznzvhxhjg464xQ==
X-Received: by 2002:aa7:9a86:: with SMTP id w6mr7833959pfi.169.1574194604506;
        Tue, 19 Nov 2019 12:16:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6c87:: with SMTP id h129ls5172745pgc.3.gmail; Tue, 19
 Nov 2019 12:16:44 -0800 (PST)
X-Received: by 2002:a62:5585:: with SMTP id j127mr3129121pfb.236.1574194604235;
        Tue, 19 Nov 2019 12:16:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574194604; cv=none;
        d=google.com; s=arc-20160816;
        b=vuzRqzNqQ0NiUIFSznjuXpCN71n/4W3AD71UXEUU/WSLOJ2/k53o5sMhMSQi7flEEH
         /uqL3XLZqb4d32aLih+I4wE/srhblow2ao0mSmBgqrDdJODfDFv5DXyrbNpiSMDHze0n
         4i0QMU+bD1gz5MWYX7RPvUXMoEozaKemvoT3mJ1O+fwgZvKY+ZRKjuV8O5tlT0ovTJ6S
         h/l8qzJApfe7ZzGFtNvS5eMOuMy01TGOW9/XHz+BKzM9fi9+nLoCeYHtCkU/YsMFNwCF
         XThQ6WH783YZw6zu/s3uru8IgmY9IBPz3stMG0Ucloa5ehgvYGxfSmBrgKCkURdzCcJ/
         GGtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=roG7lESYjaXHD7+cjkBZGV3vgBrBVAMTLku9pSYsP/g=;
        b=kaMsRTSCuXTbFKIjK3jhdLrCh38U/TLguGXP8a8E/5XEmvjx78qP+YpV+ugzZzoAAa
         H007QW692QUS3OpzmrI5ya6x93c/oKsXQIpN7/lZvv8KKUhAlsP6g4WBy3Bdphwc+OmL
         PRtYrvlf6byqLRNxHO6yfU0DdfdZIB9OcyFvK8wSUd+1f0m/EkKIRmQ/2zmXKmCzprWk
         ithMqqbopCyFKcuV2iiv+18iMP6Fu2n404l8Q0KcIIZ9tOYO3b2VSAlmxs+Lb62XWcF7
         3SW/rcZUEbk3cW3m90QQe3TVn7V4rwgacni6vT2jBf7K7sdYQAC6VQOOgP/qcAL9Qv9h
         ZEow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DFheVwMw;
       spf=pass (google.com: domain of srs0=yygb=zl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YYgb=ZL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j12si151462pje.0.2019.11.19.12.16.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Nov 2019 12:16:44 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=yygb=zl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.135])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 005F622317;
	Tue, 19 Nov 2019 20:16:44 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 8F9FC3520FA7; Tue, 19 Nov 2019 12:16:43 -0800 (PST)
Date: Tue, 19 Nov 2019 12:16:43 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Randy Dunlap <rdunlap@infradead.org>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Linux Next Mailing List <linux-next@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH -next] kcsan, ubsan: Make KCSAN+UBSAN work together
Message-ID: <20191119201643.GF2889@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191119194658.39af50d0@canb.auug.org.au>
 <e75be639-110a-c615-3ec7-a107318b7746@infradead.org>
 <CANpmjNMpnY54kDdGwOPOD84UDf=Fzqtu62ifTds2vZn4t4YigQ@mail.gmail.com>
 <fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org>
 <20191119183407.GA68739@google.com>
 <20191119185742.GB68739@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191119185742.GB68739@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=DFheVwMw;       spf=pass
 (google.com: domain of srs0=yygb=zl=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YYgb=ZL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Nov 19, 2019 at 07:57:42PM +0100, Marco Elver wrote:
> Context:
> http://lkml.kernel.org/r/fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org
> 
> Reported-by: Randy Dunlap <rdunlap@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>

Applied and pushed out on -rcu's "kcsan" branch, thank you both!

							Thanx, Paul

> ---
>  kernel/kcsan/Makefile | 1 +
>  lib/Makefile          | 1 +
>  2 files changed, 2 insertions(+)
> 
> diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> index dd15b62ec0b5..df6b7799e492 100644
> --- a/kernel/kcsan/Makefile
> +++ b/kernel/kcsan/Makefile
> @@ -1,6 +1,7 @@
>  # SPDX-License-Identifier: GPL-2.0
>  KCSAN_SANITIZE := n
>  KCOV_INSTRUMENT := n
> +UBSAN_SANITIZE := n
>  
>  CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
>  
> diff --git a/lib/Makefile b/lib/Makefile
> index 778ab704e3ad..9d5bda950f5f 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -279,6 +279,7 @@ obj-$(CONFIG_UBSAN) += ubsan.o
>  
>  UBSAN_SANITIZE_ubsan.o := n
>  KASAN_SANITIZE_ubsan.o := n
> +KCSAN_SANITIZE_ubsan.o := n
>  CFLAGS_ubsan.o := $(call cc-option, -fno-stack-protector) $(DISABLE_STACKLEAK_PLUGIN)
>  
>  obj-$(CONFIG_SBITMAP) += sbitmap.o
> -- 
> 2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191119201643.GF2889%40paulmck-ThinkPad-P72.
