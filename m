Return-Path: <kasan-dev+bncBAABB3VD5P2QKGQEOO7OJMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F4F51CFB1B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 18:42:24 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id s12sf3116991otq.16
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 09:42:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589301743; cv=pass;
        d=google.com; s=arc-20160816;
        b=J+CnLAMxvTFBeuX9TTr7VYURBp1W8By/okgMKfAGWcscNjDfu03GGwq89atcx7uQLt
         Vxycpl+17bl2LdoIgCZTmg1jFnNXAb9mZPMZNLtlcin1LzuRlPNshTMNRNMKQ06Q2uDs
         n/L9V1CVqXnY5NoO2xBJiYRK16V+a1WcevZbMzNk91EWUJ5CGDuqEZZ3vgzJIuIt0W+4
         fd4Akf7+iJGQkO8hXYAO4qmvgWK1J5olit4lr7UoTJHugAna54KL7pf6kBxqvJLPMzdD
         sbfdNtmeZ+1aWBGDpVeuuF5alEUFfbDbxJJvz+4Ee0Xz8SHWbO49CUv0VIeiAgavvt2v
         x1PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=v5D2yatIsgaD0j8iGP7+zyzn8vZ4qo/o7pl3fWwZnZ0=;
        b=0WNwLTlzo+Ey9g+DDcq5cJYAam0js19ALWD4AegQ/VKSRIJMEBzbYTcwomXvQxtMyW
         dR738RcX5HcglnVo1CtZzwlKMYTNFox7J5KOEABTmGvHcRivjGJXkZALBm8JqWoO3DEV
         8V0jOO6mygouToERfVz94dT2ObJfVdIQrrQ3Lmiv5UmvVhj9R2vf5e2LX9VVnyr05xxa
         7H6Frr2xlZLjvaKOWg1NkqpDfJqdOVm14c+Xm+IIEoRQE4pGcSDv5m4Nxz7c2r4hgAYe
         LveW2tjNZ6PtNHbP1vR1GyiYxOBXi04ZJbEwHmdfmkVEiZH+BdfFIPXqm2sLjQzt/36V
         APhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hQlbhx2i;
       spf=pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=v5D2yatIsgaD0j8iGP7+zyzn8vZ4qo/o7pl3fWwZnZ0=;
        b=AwbEZ/6pIRt5SYB8ed2P92iydTCAjcAOXQCimlxBxUdq3Pmo1E4oKpfj/8XwthqXdg
         5hFjqtyd3mzf1jjxeON2XP2k1CUXCDmupFkEvvMHRO8nBIk64EA/Hk7lQNVhjcwt23aP
         Y4q9Gj1evGv9Ya80fpsua9HNj+qb3H+rX21R6uH0jeIgqmJbhDhM+DYiFgmwE0fQQ+86
         ZyMKQAmQWNw+GK+vzMdVyDNBQmOHrXYaodYWpxDQliffX5jb2KVfPO4QEhL+95TgCC0j
         cKLk9oxENWHzyBp0YVOvfgMSLcGuMGJqHcm9rj82CNZJbwQ9GDLdqMPhHTeLPfI/O3qa
         xjBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=v5D2yatIsgaD0j8iGP7+zyzn8vZ4qo/o7pl3fWwZnZ0=;
        b=Y85/HHDLJ3n/y+bLNB1StbaFhuWpSMCUefvdr0QCq1pcg88bP09grLUfI9zsPRMvDx
         AkQS7cwZpdMh0DlPndxcczax2FGLV4DJ/AJgIK1n05uARz6B07j4daZzsibQ3LEdMmVQ
         4ro4xieWUjNkwn3w2rvr3MZfH5CRPjZKPUg5EvxoYqjKJwdHpgm9CbJYF9aOZ/R3e00r
         TpTQ9/piYvjTkk/dxT6ELQQDdhZZzSeaLLK3iqCPz30eQtXg5NUmrYbjwvhEhRb5ercy
         4w1GeRPoc7d1yugnLVpmgBxfsIWwZotqkcIsUGpYoxsctVRXr4MiiJDy46sYpby78Vrp
         f5rA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYYq2Bs7zcLRPAQb0spI5dVJ1rJE7/ZATj3rMco5/nHB0hqCOXk
	tsJr0aQkaTJ737xjR0b10hM=
X-Google-Smtp-Source: APiQypKo8INEAukHihANrakRD2Ym0kIZB/5+NB8elkxUxGiMR/tPg5maGOmg58KvapzyU1qixYDUQg==
X-Received: by 2002:a9d:12e3:: with SMTP id g90mr16769122otg.247.1589301742927;
        Tue, 12 May 2020 09:42:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1de1:: with SMTP id b1ls821551otj.9.gmail; Tue, 12
 May 2020 09:42:22 -0700 (PDT)
X-Received: by 2002:a9d:e93:: with SMTP id 19mr12121243otj.371.1589301742609;
        Tue, 12 May 2020 09:42:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589301742; cv=none;
        d=google.com; s=arc-20160816;
        b=YKjKjEfV9jEsocvdyWW+VfY48aUfAGpZrTp51nO0oaKWlwkzu0MCSnqrgSNwBWK9Cr
         AmjIicz6XVgQEZ+0le/S1fTDr6HoYaHuluT1XrQywpNxzVX+CoYL6+EXchD0uNn+MLbo
         PyKqoCfKd9nHzxtURS9wCPFPblPo0SQPR/ts/CuRaYInEncBSzivV3tTo267f9B0Ai/4
         ur8LE8sbq5Fw6H5bjfuIdWwY3NMPuEGD6lYxORuo6i1zEO0ZMKmVgFx+r31fJ5a20N1z
         a7W00572YGYT393w1uBDuyYQyloxer1BqEEZUHD6w/epEAi1aYWulCR/liFfTCKjvAAJ
         1p9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jO9+x7rswZT5Cscqpf2ds+v6upSR+IBEcU7vuauwdKg=;
        b=l7ZK3h/QTXquWEfdIERTx9beSnFrq+qnaeCovENfNVLFbkna9DGrTgeta0sDvyr5Ud
         QBH0t/H50WnVAob2cCwA2WASykDa/f+zMVVoQlOiT9/JrndqU4oVfu9fAQZKY1uAYiIp
         WtZ3L/nnb2apf3F/+/R/KHpGh96WNg6U2Trk3qdwTP/Q+Qgt5Q1nTKN1FPuTMABvXl+8
         YzUtHVnATuey42QMiCircB9cWkOXg/HnuJvS4KaFqcAvt6Lran/Gt66HUchdIqpR82ZD
         Lz2f4al5MY3qiZCz+OLMUiN+Hz9SiX9JCxxrhrYF4rtzlIiuesvPtPNCmOWlAiQeTXUl
         1hLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hQlbhx2i;
       spf=pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f197si706898oob.1.2020.05.12.09.42.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 May 2020 09:42:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (unknown [213.57.247.131])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 059B8206CC;
	Tue, 12 May 2020 16:42:20 +0000 (UTC)
Date: Tue, 12 May 2020 19:42:18 +0300
From: Leon Romanovsky <leon@kernel.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/3] kasan: move kasan_report() into report.c
Message-ID: <20200512164218.GN4814@unreal>
References: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
 <78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl@google.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=hQlbhx2i;       spf=pass
 (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, May 12, 2020 at 05:33:20PM +0200, Andrey Konovalov wrote:
> The kasan_report() functions belongs to report.c, as it's a common
> functions that does error reporting.
>
> Reported-by: Leon Romanovsky <leon@kernel.org>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/common.c | 19 -------------------
>  mm/kasan/report.c | 22 ++++++++++++++++++++--
>  2 files changed, 20 insertions(+), 21 deletions(-)
>

Thanks,
Tested-by: Leon Romanovsky <leon@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200512164218.GN4814%40unreal.
