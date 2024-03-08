Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBNUKVOXQMGQEGGXTKRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C4E9875EEC
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Mar 2024 08:58:48 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5132027acc8sf1433484e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 23:58:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709884728; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ec82iVqZW+Z5wvGUJ3EURt14ZoQEhPFA5wIG7g/MAtc/eaKawZ4FoA5dcWn30bJQJo
         bVLrgctVRy5NIuyykZrSZlyIwnMfZx0kXeWHR2t88847N7tEOaLUdTFTyZ8J+rG6mvZz
         INGig3wzK6IVE/INC4I2UD/2XogTooGgzsktbzQEOQq90D/rnDQt00rt4NTtPVJrkZPO
         5Imn287+6Q3trM3Rv44GbDLmR7drfXJc5h3hYq260WBflaRIgpwWkr7QtizGWYp//TRK
         iE0uuIXKdpXNAM1JXZvb3WbUZe/sJh8W5iclJpBD+pXWlb4H+nrsd1YJ+0d36bF9Sg7U
         heyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MgRC/O2VLtthgtL7gG2gMNF9ASY/sS3c95lDp41QOKk=;
        fh=Hb5Qum+I+CMtmgpDNZP5ayapl6M/xNPZJuh4OCK5yjI=;
        b=FjymnAcKKYx+9teqnxzJZfq/Q8aRWkSNBKRNdIsUZgRY/11hc4GUi5+cZLI/7IkdT1
         LohMaLVzxKaZZQiuSgEiqMQ4lAp2dssPwZcZpsjmFWOfuSD3E4Z5yByykggP2mpmEmBs
         2JQP4mwf7oMEw/IiBGW0WSxMK2IjFQALKVbaQvOGLV4DsaE0FX9aHZZsUPlnW6tYp62S
         jYZVvWfwYvYwvg+gZESCfQAXn50thq7T3dGDEDKa7IcJ/PfRivOKXfrpRM754LnKLRl8
         o3r7MYSW1dWJ/GzVg4q7hPc1K/iQYhwQ5AElZpAIkrxoELO1B0fg+NLI9/iuHvqTGwjD
         60Lw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=TsVqNNY2;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709884728; x=1710489528; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MgRC/O2VLtthgtL7gG2gMNF9ASY/sS3c95lDp41QOKk=;
        b=k877waHW0FRKMaRMGXtMknGih/t5m/d7EHjudHkeV52rDhpuPaw3ebZ/SUL5+pp7Zh
         K281JVGOI3xkxfCzIpur0D4DAAnvavzC5ZL+agSATxO/51isthI4nHmtv4nNHBZLwNOW
         Ki1EzX+c8HPbHi5ICp5FQEJ4VjMYc8WGIMNDryFVtfy/vUxeh2rP9TzMd6PiQnJvVfgc
         MRKxkqHKLx+UJFyui0bdRFZ+SrnLUCArALFwNdL0m1207oWgjSp6rVeY0BCVbnYXxfws
         TkBYd+srYquSuKhSpppg5mO+8CQQhXpNWCDqVm9G6p1PlaP3nNyTfwpCmxZxdYlIidgz
         moKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709884728; x=1710489528;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MgRC/O2VLtthgtL7gG2gMNF9ASY/sS3c95lDp41QOKk=;
        b=O3rC4G30uN6dFa5gTjO7fme7RdsX0YUhodfaN6j5MtWC43MR5bV7f2TfLLaO+7rfIi
         qVoNLmHuquGTqDIQrFrkTO29cYEpCUUYJAP4074b3pypJ4Gc8B6ZBMGoCSKw+Z21TGMi
         owFZDBxH4UHfXASzGKajn4cnIYzi6jjyYLb+A8p+5RtVDpj0Ycvl01nNY34YnBa/NEoz
         v9r+FeM7tR6L5mgYgABu18fXdVplqrrGdeccJMTfpi1HKJ1GoOOZTmFm2ADLRiisRSsW
         exJeENSaYcsHztO4XfLNa4ezARWUf67DkRUMQugNgb2+6K3kUJr1G8u2c1usIsw1HtJr
         roEw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWMhtTuNo+95t4hDfGazAjkKpBCH1M68+IR4oSpbNKknH/Ac+NpPt16zSgi8TW6zBgTKXHxW355Q80aSrJJL/IYV5aew024YQ==
X-Gm-Message-State: AOJu0Yy6lYDq0pFY/xXmhxaJAij1mc8ATfQmd0HXtMLOdXmET/TjGpgo
	0Co3cEHlISKAJSolGLTO8bwgM5x2g3RayhFa2ZPTlgW1gnhm6niP
X-Google-Smtp-Source: AGHT+IFiTV7pX/EOwDzc032XaQk1xPBxJnkvu5PHo/ibL4jar+S8bGOO4c0J3StDWgUtsc2JySt1cQ==
X-Received: by 2002:a05:6512:202e:b0:513:5a09:abc6 with SMTP id s14-20020a056512202e00b005135a09abc6mr2450429lfs.19.1709884727146;
        Thu, 07 Mar 2024 23:58:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5282:0:b0:33b:37f5:f41a with SMTP id c2-20020a5d5282000000b0033b37f5f41als502166wrv.1.-pod-prod-09-eu;
 Thu, 07 Mar 2024 23:58:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXap5O0ZfS/vOcN5pS1HioRLlliclK5XC54NiGYrRE00uNh3ZHH//k2d21r3NjK/kF+YmFuetiChzqUPqUpBBXvmI08it7qvCGsWQ==
X-Received: by 2002:a5d:530c:0:b0:33e:79dc:1867 with SMTP id e12-20020a5d530c000000b0033e79dc1867mr27471wrv.29.1709884724918;
        Thu, 07 Mar 2024 23:58:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709884724; cv=none;
        d=google.com; s=arc-20160816;
        b=fOAmqubokfGTElDBjco86qPup/rLhAm3vXFDid0Ql6Id9PXKqo8ANM336A/99lHJbz
         38NESUKhcbYIWiqs6oukoYs/IHACV4q5HDUqX0sYRpcJ8ULs9WhftJzSpaCAZCeosGLt
         9Dcv5Hw6SOirl9qoqYTG6d3/HTsvbqXK/BCffLtkiexmrsgC6BsfIBB67AItuutQVTlE
         aU/FpXEuDNX4TN2X3p6bDhoiB7zoNkmGai7ExWyRZRoGsNyUWZ9YwqZBrLT0NNx008s+
         7r6Z0Usrz1PI3oxWB4vkM9XSdwBNYihh575lDyAnZ6nd8+p/xAZj2cClzCoWNY2c70Uy
         2kmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nKhcv7FveFX6Vu+YlDQrid2ZodAGgZyK6pa9YPbkzFo=;
        fh=5cWROVSDVwlBaAlq/8EZKga8LJsbHzvdbp7itep/MGI=;
        b=h9sp8cgRp9Zsbu2kOOOc80JeggbZxOiooTAqHC8ajHzqYWw9cfoBJ5VKiM1BVZZ8ti
         rCdKaTI5gtXpWa6X758K2Yo18Fl3yIVO2TsFhDreua7TWXoZl+jjYZ2i4ulB3K610Lky
         vxdfT4ia6ZsmGfYZQItia/CUyewjY3cuFjkvAsKSUYA4WGkPg3YUs8N6rGByk1Y9GNq2
         Zs/o61HxAx/37Ukz94xrRKujWgABNzzxya7BvpFav21ZU4kPEiHxtc/c+IDr9j/2z10G
         NpDN0OCNBbZzbtBzhvf3YINjCTvWrgsvyOK01slQEX0pSqesR8AgPnStM3ci/4P+9z30
         fBaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=TsVqNNY2;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [2a01:4f9:3051:3f93::2])
        by gmr-mx.google.com with ESMTPS id q6-20020adfea06000000b0033e68795288si95563wrm.4.2024.03.07.23.58.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Mar 2024 23:58:44 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) client-ip=2a01:4f9:3051:3f93::2;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id E595540E0185;
	Fri,  8 Mar 2024 07:58:43 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id ju0MZu6CsHgd; Fri,  8 Mar 2024 07:58:42 +0000 (UTC)
Received: from zn.tnic (pd953021b.dip0.t-ipconnect.de [217.83.2.27])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 57AC840E0173;
	Fri,  8 Mar 2024 07:58:29 +0000 (UTC)
Date: Fri, 8 Mar 2024 08:58:23 +0100
From: Borislav Petkov <bp@alien8.de>
To: Changbin Du <changbin.du@huawei.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	Andy Lutomirski <luto@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH] x86: kmsan: fix boot failure due to instrumentation
Message-ID: <20240308075823.GCZerFH9Q-vl3FgY-l@fat_crate.local>
References: <20240308044401.1120395-1-changbin.du@huawei.com>
 <20240308054532.GAZeql_HPGb5lAU-jx@fat_crate.local>
 <20240308061054.54zxik32u4w2bynd@M910t>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240308061054.54zxik32u4w2bynd@M910t>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=TsVqNNY2;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Fri, Mar 08, 2024 at 02:10:54PM +0800, Changbin Du wrote:
> find_cc_blob() has instrumentation enabled and panic when accessing shadow
> memory.

Thanks, I was able to reproduce. With KMSAN enabled, a 5sec guest turns
into a 2 minute snooze fest. :-)

Oh well.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240308075823.GCZerFH9Q-vl3FgY-l%40fat_crate.local.
