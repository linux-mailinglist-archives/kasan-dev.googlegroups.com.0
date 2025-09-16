Return-Path: <kasan-dev+bncBDAZZCVNSYPBB5FKU7DAMGQENA575GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F428B5A3D6
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 23:24:06 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-31d8898b6f3sf8096451fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 14:24:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758057844; cv=pass;
        d=google.com; s=arc-20240605;
        b=kQGxnDynDsDnvCIIn/MPI8Ifpwf/8q4AmpkC/JOoTPjzrMKeStYu7V7qwP0gEED4Gw
         Nhfv0PSYN1LGAzN56/rlauKrqA7B7VZ5OrkEsN4rhB+ZAdJ+AezosorXJbtXmG/LTgDw
         MWDwT4bOVumtxnw5CN0POOZXiN6j+epEEPYeOs1rIR9gut5Zul0MS78jJMF8HfS/xH6M
         8Lnl4LZoWVmxWVB+64hDkxVa4g2j4tCLAiyb+gREh7tfHoJhOrQ9XJtRNqcyU/g13yDd
         E3nAj0W5URmSAIi2/RCvvP2yk73YYV8ukl4rOu8FAhSrKzTcbmAmzoPmT6jmzuDRbV9x
         nO+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=51QYZXLPx7jj7DeYnHTcD/HqTVM+MjZWhsVO0CwR/2M=;
        fh=sqU3caOwgHLomnLqO9VPOuzOHIgRgzoZkY5q/QM30NU=;
        b=NetThoPqix2ifM6R1jTzTHsJyIWbYofMMII0YvHADHyeTEtoyOOeoRhc5YtWt63ZIk
         auGy386nULJjB+3wZ5J4LYcPiSR9CmFnPwkB84lyUtQ+J1VttpwDhZuWtuKy9H0zd0GU
         9LwYPpyrJNaVKaRPAyUf86jFBVMGCKfVS9StEPGywHRy091jtuGTDmGx9ay3LeBgXpUx
         0fKRf+dIX/wakYx91cVBnJWiM16o1FX0jrgSTTAnvJTHbbsxEexzy1Yr0H3Z36jet1ON
         zENmCV7aHcPZwM/v1W+92EyGPFEUVsxvL/TeGKFsJmRI2miMRYhTh4vPFgG0VO7VzFla
         aybg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Qyml6Vna;
       spf=pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758057844; x=1758662644; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=51QYZXLPx7jj7DeYnHTcD/HqTVM+MjZWhsVO0CwR/2M=;
        b=XMdbaUiQnFug6dF6YuqQKIGR8L/h8vvut6OT0lEyTEhxmmbVAg3+fJo+RdNGb+/n+E
         UVLR7BUUzlgS5XgCQJtVlJsZlSouZ6Kcd96A2ZpgPhwWV//9A14lleA135bwH2VSGLKR
         vZvKF+1lmFblawdslJX0WLPrgmIasJy0LzSQAzFAaa3m1OBR8Df/yFejRB9ZZS1XuuLZ
         nujRj3l3ce1qeq9V3CRZkNqEgn/WbgwqSo9p8MQwVEStoPrIcTrl/pw15ZVnBEhLFcKe
         L1GNCwx5wJMmzghTpRdjbJ7PauJaiHVfFKiaWB4Cc7SErnOlo3rYLvfRsVRJIkn1huCM
         2jhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758057844; x=1758662644;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=51QYZXLPx7jj7DeYnHTcD/HqTVM+MjZWhsVO0CwR/2M=;
        b=Ogv6nQuXyDnGQiFGJ5XrJoHMunX3tix/uEOpqBaei8npcPWB2O9CRQLeCGMD6/CB+c
         gM3LlMFNBgFj73LZlbxNOboKC7X3efh1IHXYznsReNCxwfdTxKl2asZqXewT7ulDML7b
         XUwELIkbHVL1TQ+pD1hkazTdIuDXQUkpbFjlobvND1rYe0vOk2egam91xsuH/5HRangW
         2R6rw/hsrRt1zqjiNBuhOSO15zsI825qpjGRPzN9noeE0K52Eo8jbIsI7ld3fBYJnjhz
         2+mWQ6/Hp+Zs6EVviUWmYJoA7yJOim4WGex0OVE/vkUrU874B8IwF7FI+vcW5xx3RBfW
         9cVQ==
X-Forwarded-Encrypted: i=2; AJvYcCUP+hW1o5vRfYw8RCaUHmkRIEVRQnNw/WLuzXR5talfoGVjKOw4g6CgsSvG2NURG04j62cDsg==@lfdr.de
X-Gm-Message-State: AOJu0YzqnU5YTf80REEpbDLBYoJ+T6Ll43yQcqJc0QRfBQPY526K77nA
	EL1XuBCgGNpIJuR2RNj4uyHYsAz2HKQuAPz2ZMYTHsM/E3NEVgivkVYo
X-Google-Smtp-Source: AGHT+IHNjK8cEQK+Ru3JfCWJPrDhdg2zKKr0ZMwpVejnAOsHh274DZPbMGKG6Ek2E3aQIIclaStwKQ==
X-Received: by 2002:a05:6870:9109:b0:315:887d:b9c9 with SMTP id 586e51a60fabf-32e579fa781mr9452258fac.36.1758057844507;
        Tue, 16 Sep 2025 14:24:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6QknVkh2rqLMTiXRMsSUtSKgxClshrMUeKYlc489k2Fw==
Received: by 2002:a05:6871:260c:b0:30b:c2b3:2130 with SMTP id
 586e51a60fabf-32d06213b3als4521900fac.1.-pod-prod-05-us; Tue, 16 Sep 2025
 14:24:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJtiCUwlPqTamG5P6Kdl5ZkXK0clpmDauii8NXcLazaoB43JjnfRGoBI6gnaV6qXUV+PWbpXg9XQk=@googlegroups.com
X-Received: by 2002:a05:6808:1a2a:b0:43d:20f2:2e26 with SMTP id 5614622812f47-43d20f253d6mr5738732b6e.10.1758057843588;
        Tue, 16 Sep 2025 14:24:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758057843; cv=none;
        d=google.com; s=arc-20240605;
        b=LVK4dmDeAuYXseIdbdnVrS6pznulhAbYbo2Ux/98MYcWN0zN1F2rqjUkCs00/GcSqe
         JN+T4tYKlt6+L9F43M2iX1UUUFnKgLflU8hAKyWIm2HArpE4Y0gVGJL1t4yl17Hg9LCz
         YAwOtRIS7X7vAs6zCuAyE0L1Jld4/Ed8rsizsUcubJ3eq3xbxi1eB5YzuZiEUHcTRHCv
         FVA1TLAPXy2dasq3fciu1SyAz4Lyz8chKsXc0zBoVBTqnW2M4oGPHI88KiSIDvL1DfmP
         wc2XvcgU+XbtB9EINqc6oeCOoFMa3dvlbhYh3rzlSdObREVHDWfTvXYtPUKHibCS0FSA
         88gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=NrK6H5TeIHD81mFHQs75Jltr0eszG6u3DdurAUYQRw8=;
        fh=w2ZV6jCvet0xyt+7iiHaphknVWnpo8xfeOrr3xOJ5r0=;
        b=QgAmjfYWirSq/Jb6G5SsQPGVOtNohfMlPQ10UgOyH1LyuO97S5e7/B9NrDudZ/iTYZ
         64llXavJxERtXW1+BBPSabu5uoE92duMJz+2QL9o1ftoXfNSqYNt4ff3rPrfk6o8yjaX
         MmbNZl2VhA5eeI/N6k8y935jZpPX8P9C9XR5BP2hi3rWBTLvbZekYhm2EBUlnR5VUoMn
         kdynknyD3tiX8C61y6Ozs3QbiJxObcC6OMzB3ZwFlvGNXOlRydsxx020lNfyKCMTpdaG
         0Pet3fd3L90QQpJLdt5qQ91XPc+mftlrZHrqUvKBRr5S8S41dAD/n6nvanx9c7T4I1bh
         TdlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Qyml6Vna;
       spf=pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-32d32b42ac7si645987fac.2.2025.09.16.14.24.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 14:24:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id BE09A41928;
	Tue, 16 Sep 2025 21:24:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DA7D9C4CEEB;
	Tue, 16 Sep 2025 21:23:57 +0000 (UTC)
Date: Tue, 16 Sep 2025 22:23:54 +0100
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
	catalin.marinas@arm.com, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v7 1/2] kasan/hw-tags: introduce kasan.write_only option
Message-ID: <aMnVarvAvQuJCWXy@willie-the-truck>
References: <20250903150020.1131840-1-yeoreum.yun@arm.com>
 <20250903150020.1131840-2-yeoreum.yun@arm.com>
 <aMm69C3IGuDHF248@willie-the-truck>
 <aMnGUr9zeutyPpAg@e129823.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aMnGUr9zeutyPpAg@e129823.arm.com>
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Qyml6Vna;       spf=pass
 (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

On Tue, Sep 16, 2025 at 09:19:30PM +0100, Yeoreum Yun wrote:
> > On Wed, Sep 03, 2025 at 04:00:19PM +0100, Yeoreum Yun wrote:
> > > +	switch (kasan_arg_write_only) {
> > > +	case KASAN_ARG_WRITE_ONLY_DEFAULT:
> > > +		/* Default is specified by kasan_flag_write_only definition. */
> > > +		break;
> > > +	case KASAN_ARG_WRITE_ONLY_OFF:
> > > +		kasan_flag_write_only = false;
> > > +		break;
> > > +	case KASAN_ARG_WRITE_ONLY_ON:
> > > +		kasan_flag_write_only = true;
> > > +		break;
> > > +	}
> > > +
> > >  	kasan_init_tags();
> >
> > I'm probably missing something here, but why have 'enum
> > kasan_arg_write_only' at all? What stops you from setting
> > 'kasan_flag_write_only' directly from early_kasan_flag_write_only()?
> >
> > This all looks weirdly over-engineered, as though 'kasan_flag_write_only'
> > is expected to be statically initialised to something other than 'false'.
> 
> For the conherent pattern for other options.
> Since other options manage arg value and internal state separately,
> I just followed former ancestor.

I'm not sure it's the best option to blindly follow the existing code
here. To pick another kasan "mode" at random, 'kasan_flag_vmalloc' is
initialised differently depending on CONFIG_KASAN_VMALLOC and so
allowing for the default value to differ based on the kernel
configuration makes sense.

But that doesn't apply here.

I'd recommend starting simple and just having the 'flag', especially as
you already made a small mistake because of mixing up the 'flag' with
the 'arg'.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aMnVarvAvQuJCWXy%40willie-the-truck.
