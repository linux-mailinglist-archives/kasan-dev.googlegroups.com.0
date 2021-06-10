Return-Path: <kasan-dev+bncBC7M5BFO7YCRBBEPRGDAMGQEJDTSU2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 841A33A31C3
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 19:10:31 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id 205-20020a3707d60000b02903aa9208caa2sf10362920qkh.13
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 10:10:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623345030; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZO8/c+poOZbxuqt+wjWYhSHQVLEaui/r+I/clRTZRGf/0bWAZbYj2kJlJdhOssCkMI
         uXDd4x8DTbwR0AOMWFprAb406QVZFomOyf9sMPFbCp7V1QJ0vx3BCEnnkXSedSrFaADS
         RsEDCbWS4WdbJ0m/Xh/rbJJy4uea6DRj/QoJm5xlwgYAXOjC9PnNv68LE4bBpEWNe8qw
         shoDNNmngFLIggw5eMbdwzR3fBaey4lZ04epYP/QV2zOWsvf9GMbNPA463RIuyeVU7NS
         d2sqtGJlyFK4K699vpCA+TRoMHF1ZcApHTJZ0kgbiQUYGQnchfHGcwYSfKXzQ4BTHXin
         la1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=fgUoE0BJrc7yutiP9sv5IaI5oT0mrM5PjhvhskYz3HA=;
        b=ZaqPnzfAqhWHjSq/7LcuVv3FZUzayjka1hdbeJBS+4j+u5KyLKG8m7+6Qs5aqfqZRB
         gawWSaWnxeRYl0mwRasMqwJOWp+2V0EUBZUi6v4BdbxoIcGaDwLOaEaPzUwYHDvpIeyY
         q4P9F6b0Azdgqh9vaXZ/P3Qmq0GBHpTRdWRni7WVOn5cPFYaVuLD9gjJgvalbEJ9ub0H
         B5GDsvEPH3zh8/WNy7D7XPE73aSwxX+5PXaJ/rEoEo1ixoCahU9lIV89F7+fZkFBPt4w
         A/+vsMoEd5Ezj7fnuh2n7lVFxQ9MfVQSmRa9QyJJ1sTg/9q4NZTMLtbAFVQMEnKKjuez
         SP7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=IRdg245k;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fgUoE0BJrc7yutiP9sv5IaI5oT0mrM5PjhvhskYz3HA=;
        b=JIlvXDIoSGxAVJrXukelGhv4gKx0XeyqZO8k3NnGBIWya86e6xeAldIv8Z7BaRR/N6
         5TR/cHtfSaXdYEqOanEuCtuo6JatYTiN+QJjL53ZaHl+xLsV3eNoGMdzyV8Gq+rasw8S
         2sAbcrHadev605Uve2shbt3imLETYoWwG69i1Er/Qs4jver/QAWuQVRTzXYkK9CXsGA8
         ZPJTKJa31a71TJ1tK2ggNQZ8ro5bDUBvjFR2P7Ysx4//F6QD//WfuBBNMIduXpUdnAlr
         9CY23SMJBYBrxE+zCkW1uupO2r+H2Zzj/IHhw1FLH/k8X2eQFz2dpwuX3vz1EoqdfufL
         HDcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fgUoE0BJrc7yutiP9sv5IaI5oT0mrM5PjhvhskYz3HA=;
        b=cdKEmhmgE7+JXeW6DdTeVv5JteCFdjQkKzF7+4mQyvAomw6MK6/z0MhuwyzmA1Uorf
         nJV8ETN/9410p7oiq9DYEwq2sCipdZe9DIdZm87MCUA7ajs1epdWrTDei4TjD7opgyjQ
         MieuTiM1Lde80fKd13oLew4mD+WyDoZwvezaixHHKYIxj5N2a0ULtvlZIFDElaQ3Y+Zz
         vXps1wDsBholUum7EjAvP0Hx0rGwUYzThvSo24dRrn6s9pLVQLKChBtafyzzX+D1P6tg
         ey+AR4nciSvEhCah276p0gAcyuRfmi+OuiO59ScbSBTeVcSHUfDW0qco0Thk1wSDmKxX
         JagQ==
X-Gm-Message-State: AOAM530GqodLSXQ64xQKSEPAD0IFkGANC/msyWcT01PDi/eb4ooZaJ0c
	mrEXbA+mScIo2BfGREIvjSw=
X-Google-Smtp-Source: ABdhPJyhDufERkH1w+UAilJhN0SOGGCBVwIcz8VhaIk6CDRtA3TMqFYaRGUeUYP/mH6K9jUh2y/Uig==
X-Received: by 2002:ad4:478e:: with SMTP id z14mr635714qvy.52.1623345028346;
        Thu, 10 Jun 2021 10:10:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:351:: with SMTP id r17ls3104675qtw.11.gmail; Thu,
 10 Jun 2021 10:10:27 -0700 (PDT)
X-Received: by 2002:ac8:4650:: with SMTP id f16mr623654qto.377.1623345027806;
        Thu, 10 Jun 2021 10:10:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623345027; cv=none;
        d=google.com; s=arc-20160816;
        b=palGb1sLWZDNChG0szAAvC0GniHyg1HeWyn3JR8SL3BqwXuqHbsqzHZfPPxfT+Fh8z
         GNVFGjQY8PjiLtgs9ksFzjO20KxamtYLryR/IN9SAQ7ox9ALF7j1TEh19X+qsXbOqg30
         0ldY4OrVUvFznvOjxx7pC1hAX7fl6MBc6Fr6nO8JADQzvbvzTtlqTsVDxmTAeZyNyJp3
         pQBUGR/I9VCodl2mO3JV60L6ITsSQm8I4O1SX6OC4F9MKMGrJeNQcPXXtHukL5VHiU5Z
         Cei/LlYYS6CBmQgnLb5mjtdpmo7WimFYIdmCQ0+SU/sfuXINqt9vUOP6foDpRzHfeTZW
         XmPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=UEldWJV1cPWL8Nx8+B0VxRHw0WvFlQxd1i6CoueNSPg=;
        b=y4X6yUYuAxf9i+pjizo9DCLcW85Hl2pA5gwOW7QTgpI+7rR7KsTX6bkP8mU9fCiRz4
         YBpLVytJvRsuuh+AV8ZoyIEiAWTnw35RlmQ/e8DOfH55lxXueP6rToMkoYivzDHk5mkC
         /quVFr4Rapp1YKwFV1nZN6/PeFXOses9UZ9p1M8TlVzwOz7jUY7aNqWglbfbKNh3iNk5
         X8NUmQZY9rTwZn7mM+NYzJ6Xf74K4rEfrRZVpg5WOmqZryWJMsJzr9NG6yjfLCm/PdvN
         ImA0pyjgc+3LffFQS/o9UVoqFrDroggQfjSgl/JoszFDGGjgQ8zza62ED0wMVGpA6qyh
         Azdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=IRdg245k;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 85si425862qkm.5.2021.06.10.10.10.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jun 2021 10:10:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id j11-20020a9d738b0000b02903ea3c02ded8so399304otk.5
        for <kasan-dev@googlegroups.com>; Thu, 10 Jun 2021 10:10:27 -0700 (PDT)
X-Received: by 2002:a05:6830:2684:: with SMTP id l4mr3378035otu.294.1623345027254;
        Thu, 10 Jun 2021 10:10:27 -0700 (PDT)
Received: from localhost ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id t18sm706988otl.80.2021.06.10.10.10.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jun 2021 10:10:26 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Date: Thu, 10 Jun 2021 10:10:25 -0700
From: Guenter Roeck <linux@roeck-us.net>
To: Andreas Schwab <schwab@linux-m68k.org>
Cc: Alex Ghiti <alex@ghiti.fr>, Palmer Dabbelt <palmer@dabbelt.com>,
	corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>,
	aou@eecs.berkeley.edu, Arnd Bergmann <arnd@arndb.de>,
	aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
	linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v5 1/3] riscv: Move kernel mapping outside of linear
 mapping
Message-ID: <20210610171025.GA3861769@roeck-us.net>
References: <mhng-90fff6bd-5a70-4927-98c1-a515a7448e71@palmerdabbelt-glaptop>
 <76353fc0-f734-db47-0d0c-f0f379763aa0@ghiti.fr>
 <a58c4616-572f-4a0b-2ce9-fd00735843be@ghiti.fr>
 <7b647da1-b3aa-287f-7ca8-3b44c5661cb8@ghiti.fr>
 <87fsxphdx0.fsf@igel.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87fsxphdx0.fsf@igel.home>
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=IRdg245k;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::329 as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On Thu, Jun 10, 2021 at 06:39:39PM +0200, Andreas Schwab wrote:
> On Apr 18 2021, Alex Ghiti wrote:
> 
> > To sum up, there are 3 patches that fix this series:
> >
> > https://patchwork.kernel.org/project/linux-riscv/patch/20210415110426.2238-1-alex@ghiti.fr/
> >
> > https://patchwork.kernel.org/project/linux-riscv/patch/20210417172159.32085-1-alex@ghiti.fr/
> >
> > https://patchwork.kernel.org/project/linux-riscv/patch/20210418112856.15078-1-alex@ghiti.fr/
> 
> Has this been fixed yet?  Booting is still broken here.
> 

In -next ? riscv32 doesn't even build for me there, and riscv64 images
generate warnings and/or don't boot (but that doesn't seem to be riscv
related, at least at first glance).

Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210610171025.GA3861769%40roeck-us.net.
