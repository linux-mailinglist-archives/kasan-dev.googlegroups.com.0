Return-Path: <kasan-dev+bncBCSPV64IYUKBBYEN7SBAMGQEFDUP5YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-f63.google.com (mail-ed1-f63.google.com [209.85.208.63])
	by mail.lfdr.de (Postfix) with ESMTPS id A63E934B60D
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Mar 2021 11:20:16 +0100 (CET)
Received: by mail-ed1-f63.google.com with SMTP id a2sf5841326edx.0
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Mar 2021 03:20:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616840416; cv=pass;
        d=google.com; s=arc-20160816;
        b=xY/x2TI1Q5dDqgEymP/Bxxd6P3MXu6K/Jx2895rGh3OQfQCMHT/tCnDq8rwvC2uvqG
         gK/Vqzr/uhwGZV0Y8M2Jupmys0xmj7rneW5MReKxpmQTAkA22Bylo1RBEig6NcrR9ZVD
         EmAguha00OSmWmmMw53p1lmA1vZQ7pEAe5G04EKPfB0MfNrVk9awdpXEnmJaG/OaE5sT
         Q/VOc0go4acAIK8rQTssqPv5twddhoWb8rWWUNo3arQ+Zuq22NFG3C50PltfApH2M/SR
         yFGCjaRtCluifLgX8gr9mlgDiuGJjbsgQ7lKPGHfR+kCw0rETDz3LXkAyY/ZFnPd/GR5
         HJEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=AbduSftMsiCu4Hzos05bM8Eimnk4VfNOjEwTg6ZAi4A=;
        b=AFsBEgFT1SBJ+sz+dCU3AqUouA4c4ls9xL4vr/srrJXkHx2/YhDuf8hkAql13PVedM
         uI1FMC9ue2Afen6iL71oe4MGglBcXPnEvsK3k7UBreKJcdS3ah+YOtmWIPaZv3QIbTvS
         NIUAxTtZpeEhiIVaaSNLNxO1LBg7/BkOdLkSPv6ZBMGJuHnP816+pxgxQjseoUWs/5Ja
         G8uKjcIJVIDfvrDJENy3dAUwbFkKmy30f1Zj30xFY0CQCcTsQXGkLIRwmI1NcJxuQKPY
         87GXjG4CCN9cAZhtn2R1L5LGbUkNxzZ9vwhej764PFaOJ1nAh5xkGENzKzUzJlJChmUa
         roRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=RWob4ATB;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AbduSftMsiCu4Hzos05bM8Eimnk4VfNOjEwTg6ZAi4A=;
        b=lYitm0YzhEAlBxsEtTpFE7CKtZDTtc7Wu0c4QuMZXpkPF9yjxicHM+CHRB6uwkELsp
         2XD91/LjT5CP+F15Ft9+VALX67Ch84TPwePZVcuNs8Hm0o/u/rukD0H1cee70P6/CaEc
         G/TNoFPDMkAai9IwcWs4ZPVHwWE18z1s3ODM0UUl3CIEWoxsTRllgYwV4+R0K6szbMxU
         sPXbq8KrqoYblblr7U52kOTA1OVB+qGhK7iuQg8DvF5uKBui+BfqkIi7Bqhpwtk/mFbj
         uO5mKTco3BPGTLNFPripGq6mgtpaZZLfEQ/XuRu6w+ob4hjhY7DH0dWNRQQ7EFh9bm7H
         yQdQ==
X-Gm-Message-State: AOAM5336d21Pyf15wi7d53/Z2lhYLhoRBXaRNHlJfEzdP4cnTZNnmQVf
	fKiUBFwOYFGDrbcWdrnB34A=
X-Google-Smtp-Source: ABdhPJwNzeTum/H0tCUlbprQaWzJRo1UsxMHXQYnJMNTxUeQWfkSFL37/axeug8thliLqpxb1kd5jw==
X-Received: by 2002:a17:906:71d3:: with SMTP id i19mr20110656ejk.347.1616840416447;
        Sat, 27 Mar 2021 03:20:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:97c6:: with SMTP id js6ls6364911ejc.2.gmail; Sat, 27
 Mar 2021 03:20:15 -0700 (PDT)
X-Received: by 2002:a17:906:3c46:: with SMTP id i6mr19996806ejg.80.1616840415650;
        Sat, 27 Mar 2021 03:20:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616840415; cv=none;
        d=google.com; s=arc-20160816;
        b=eta8A2mWUpDfbk2tDTkEEhlCsEAFcW0owP0xK914Xd0cyDw3JMvE3gWgspOiZRDLJ/
         15LmPKlRsZvRAPKW2GtpohofCWFwCaEv6324IKJXQvIS7jLtrp9yYMiV6Gd7DK5J4RdT
         p6+RbGR7svGXF62XVIX6juUA37fviVmP92IkmopnsRsoWVcApe3TLOukUyUGploUN4Uh
         YLx03tSvwz/57Vcl1Tg8+RuEjd6oOKLtW3jbEpZAA6/PjZeCL5TyQ7JskFirwk+HnpNP
         IJdCR9yEzOTESlQho/W2XvXXdOfsGmtfh3CD/yzWzMriYl0HYtf91v1QPuLedYJ9esXk
         4hLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=DVjYSyWQdbWu0/nbG+Yl381iPzwCZZyDqilArg4nupU=;
        b=WF43KNrSxv+mNA82a/jNAvqXH0LbSxMOMmmjXEbRj7v4b8gedr8RodKoQ1Z6UBr3PK
         MwoDZwFESNWmkPEvro2KLEpLara8/5rlqC4Pn9VRF2zKIkmiHadkkS0QaXZfhn0D/A2Y
         hOD4Ls8t6sM6gE1OY5QMQjckB2sdpL8tjDx5FIcHpiGeW1T+3neB1+c1Db8lhQO9SGRZ
         ozVtne/fAxhwgmm9L8U+6ypwglGEJ4sGJZ4zxWCxdaNmsCY3p5TRNmJgtVW6wGimV+Eu
         8pR+KDHjZzJ6rz0ADyDWD4rKZudNrg5pZvIVVz+LhOpSoLkQ8DJgIYPvvolaC+qfSgEq
         /Qhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=RWob4ATB;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id sd27si353911ejb.1.2021.03.27.03.20.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 27 Mar 2021 03:20:15 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:51866)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1lQ63B-0006Pg-TG; Sat, 27 Mar 2021 10:20:13 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1lQ63A-0007xU-VS; Sat, 27 Mar 2021 10:20:12 +0000
Date: Sat, 27 Mar 2021 10:20:12 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Shixin Liu <liushixin2@huawei.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] arm: 9016/2: Make symbol 'tmp_pmd_table' static
Message-ID: <20210327102012.GT1463@shell.armlinux.org.uk>
References: <20210327083018.1922539-1-liushixin2@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210327083018.1922539-1-liushixin2@huawei.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=RWob4ATB;
       spf=pass (google.com: best guess record for domain of
 linux+kasan-dev=googlegroups.com@armlinux.org.uk designates
 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
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

Why do you have 9016/2 in the subject line? That's an identifier from
the patch system which shouldn't be in the subject line.

If you want to refer to something already committed, please do so via
the sha1 git hash and quote the first line of the commit description
within ("...") in the body of your commit description.

Thanks.

On Sat, Mar 27, 2021 at 04:30:18PM +0800, Shixin Liu wrote:
> Symbol 'tmp_pmd_table' is not used outside of kasan_init.c and only used
> when CONFIG_ARM_LPAE enabled. So marks it static and add it into CONFIG_ARM_LPAE.
> 
> Signed-off-by: Shixin Liu <liushixin2@huawei.com>
> ---
>  arch/arm/mm/kasan_init.c | 4 +++-
>  1 file changed, 3 insertions(+), 1 deletion(-)
> 
> diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
> index 9c348042a724..3a06d3b51f97 100644
> --- a/arch/arm/mm/kasan_init.c
> +++ b/arch/arm/mm/kasan_init.c
> @@ -27,7 +27,9 @@
>  
>  static pgd_t tmp_pgd_table[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);
>  
> -pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
> +#ifdef CONFIG_ARM_LPAE
> +static pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
> +#endif
>  
>  static __init void *kasan_alloc_block(size_t size)
>  {
> -- 
> 2.25.1
> 
> 

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210327102012.GT1463%40shell.armlinux.org.uk.
