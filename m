Return-Path: <kasan-dev+bncBCCJX7VWUANBBQER6CAAMGQEUXIC67A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B31330F54F
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 15:46:26 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id a22sf2136528pjs.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 06:46:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612449984; cv=pass;
        d=google.com; s=arc-20160816;
        b=bPToE5z4QV8SCk6HgR3YQ5VrfwNAtVSgsgpE82iE9CQHdRnMqUIdklk9ICsqa66tZz
         bg0fC49vZ8v4xAQE9FBceoTgavyuTK35Z5J6e5p6DKG7KYvrxYjIP0VqIOq3VpWYaMd0
         2bzZy2qwTxmNTGO0phP6TmYvC+pv2SmVPG/kYAgA2Uiay/c8HlVamaLCenGurFfmylT/
         3tA+lzQbxrWqcr7cm+KC9TFtwdmkEWsot7FJNVj/02EE8kguk2SnfwjhVh3xI3DgSbPD
         ocmy3wkPtHkgDnvjthdITotoQs4E8WRQkRxe6/S0O74ypsW+QmeXGLGUiYWc4h+2gYF5
         +n8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=sASVAPiPR4g77nmyHiKTgaRI/qBAg00w2CfvweuzR0k=;
        b=TLHer3pWYzXvVo702ryD9aDGoIKxRWSKz/ipJ7d2DSDEOhaNswI9etZkS9vtj1zu/T
         zfx8AY1zONTgr9ImoHNS+decuOktVyLwdLqDkTJhDVNndSoMmUPaB3NQ7WeInQFjh/PW
         U9eizaSFIyuZLTfUHRvdEnj0BXfi4lHlbIGh8hRfJnPBTsUHPAfbcKWj6ILJJc1mWHhh
         FZE7QISXkGNd6Q3GmJNdgZ55HJXASfcGs/G37fUGGTIVaaTbtSI3pXDPLkPxP6ZK4X0I
         gCdJ8sHf3Drq/JCSzx3vCi+NvuNxvwDU6Te9O2Xgkk3It8GVxw3YGsT9JzJ+BSd02SOH
         p88g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=JvJ1qeNf;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sASVAPiPR4g77nmyHiKTgaRI/qBAg00w2CfvweuzR0k=;
        b=Q5cyYuPmqcMhmlPiZzvq9HPNN93nxdVoIT/rbB3uyMJb3toPbmIHHIxjr3DA3T4xQS
         8WTXufYzoembe0e23bPxckcBTOctAN9ksX8b8cmaseizGt7bMXYAyH1BuUWnf/XSXMbL
         0ZsB1s8Hj7Dzms6GZxeE8PJoSJ8tp/jzCbuSWE3ZXUPiuL93vWhGErDb3slueyEi47Ve
         mEdmBXSLrTbeJ8XEBcpKJUgdSH4IRiyg2ZHSRpgziwqfl1t0l2Hjcc3Q7YPWGqqNaspe
         PEnxQhdRwgO5t5iL4/dEkK1dTL1mVEWM+2dwB5CzrBH92G2bR1oQ0qu3m1v5ZnCdouPG
         srHg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sASVAPiPR4g77nmyHiKTgaRI/qBAg00w2CfvweuzR0k=;
        b=YMAFIlgwv+tyGAdTTeR8KvEDlYjinC5RgayFin21eQv+DzFMQtHDQIIloMJLJ//Hb7
         ncKFgiL/AFWpq1giPkzOtwn1Or2nvXTpdbFmBmN1x0hcTyIKJn81ZT/q4AvGZnxMrA61
         gry5OzKPe1svomwC6sfmmKYtRY9uXWbWtj6evq4dte6Jfg0dwL/2whrDPBVcL2yXrQUh
         +dPb25laE1ozjFJmuGYBwLxQlSbadVGWHAVcpiYjOb8HlmeDY0SgxAZ/qKYsHgKsCTUw
         /58rRWQCeik1w6xK0fsk+3Cir8fkcunOpBV0eZkIx9+gThbFxMcXPMw3PDaaNZKeghAZ
         idkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sASVAPiPR4g77nmyHiKTgaRI/qBAg00w2CfvweuzR0k=;
        b=E9RHmildHb2NJ2uG/dJRJb6djPTDhEmpA58oi4QGMhmpxFZIuOIEpBSgXn+Lyx2WvU
         kYS5U62bT+cRtcaRkkOdefe5g/yFAxBhhuDPhYjzMK+bDY2t2T/bpXmLlLqyHBK5cIJo
         Cmg/Jl/s/kUaHjydjP4+H5sA0XrGhMUIunBHUfRgl8AecvLRztS10k536Fhi1KUN42OO
         vMHfY8zL3IndrHuQpAnT/DSckMhWFUPOawU5uOkv9lqxSbu5nNUuMcvOkFOV8T4Nsjnc
         I+CNcRPkjsJe899RrLZvvVWmB1gsp7og31NTZkkkDwlraz7RUkGUpQ0JbdrsmRDEwLBi
         bYjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530hHGivlseXp/CzyOBoQt9j+9aX6kvys0RPd2dbn+W/9QOk6t+F
	wrVvv8jbZv4P/Y6R9vXUQQw=
X-Google-Smtp-Source: ABdhPJxEWKvK7CVKRtFtn6E4vXI1xsdpS+xFE6N63qn90F4/QkRHeLBfZXHKlaL1L9l6wboSez0Sgw==
X-Received: by 2002:a17:90a:517:: with SMTP id h23mr8954977pjh.108.1612449984445;
        Thu, 04 Feb 2021 06:46:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1c1:: with SMTP id e1ls2807904plh.10.gmail; Thu, 04
 Feb 2021 06:46:23 -0800 (PST)
X-Received: by 2002:a17:90a:470b:: with SMTP id h11mr8816121pjg.186.1612449983818;
        Thu, 04 Feb 2021 06:46:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612449983; cv=none;
        d=google.com; s=arc-20160816;
        b=oN2IWnw7Iv6eOCdNX6yA1uLVYU09asW0jKaAdyeDhD/aa0IaHhrpGGUjkCjWddgaJl
         6T5a6BLHaWFr8Jjsf1l6BlUAyGe2fh1dNPRyqZnl90oHR0dCdp8XkylOjq0w8awli2tR
         a0mIOGTdGh2kRXCbaAYSx5tl+C9LVUcdEQWGfQy+cEAcOxlUJe3+v1bLH6ubZHNySdiO
         T1uuNYXn9IKUvuvU6kcBMH0S1OTY3dnBPILkFGlOeeG3+cRwv+ABse5w5GZqTBz6ku/W
         b4YNrNUZUOlPAl8GhbqBnfOGxjAHSaYmgspWPlFWAtYjMXF36ok8xDUhqhS1geJitgzp
         xMCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ONy/oQQmnX5TrrjNFytVoLv75B7UXC2fqKWnMIXbGzs=;
        b=OS6Y2BbvOknYsQcS5PJabRkltQs0SURj4TFuOU4stg83bbD9Bszc0k8oSjd5/YeIn6
         Suew82haabNehcXvKv5xFKFQsTXOjqt8znw5G1yop88MPEGTzJrcx2DEwzgpwMyMqd0d
         mMumKn+s6CvUpHPzIHbvI3nqeXDVlzuaTRDnq5tYfoFeQCzLILucfYjuYfVI61OFbP5O
         d2JmQV8EjxTnkXwAYNBD8nE2tefj0dE+KlLyQWbuL7Wpmu2Rp6sJi4ToRB0tCyx5Tpg0
         61lGjfsTX05LEJTjn+APPzs3/KhE9H30hPKOpPSUkR0yHYqyBCDWmkleym0YdUWy68mY
         HewA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=JvJ1qeNf;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id l8si117383plg.2.2021.02.04.06.46.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Feb 2021 06:46:23 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id c132so2252567pga.3
        for <kasan-dev@googlegroups.com>; Thu, 04 Feb 2021 06:46:23 -0800 (PST)
X-Received: by 2002:a62:a108:0:b029:1c1:119b:8713 with SMTP id b8-20020a62a1080000b02901c1119b8713mr8565016pff.74.1612449983550;
        Thu, 04 Feb 2021 06:46:23 -0800 (PST)
Received: from localhost.localdomain (61-230-45-44.dynamic-ip.hinet.net. [61.230.45.44])
        by smtp.gmail.com with ESMTPSA id z2sm6382878pfa.121.2021.02.04.06.46.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Feb 2021 06:46:22 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: will@kernel.org
Cc: akpm@linux-foundation.org,
	andreyknvl@google.com,
	ardb@kernel.org,
	aryabinin@virtuozzo.com,
	broonie@kernel.org,
	catalin.marinas@arm.com,
	dan.j.williams@intel.com,
	dvyukov@google.com,
	glider@google.com,
	gustavoars@kernel.org,
	kasan-dev@googlegroups.com,
	lecopzer.chen@mediatek.com,
	lecopzer@gmail.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	linux-mediatek@lists.infradead.org,
	linux-mm@kvack.org,
	linux@roeck-us.net,
	robin.murphy@arm.com,
	rppt@kernel.org,
	tyhicks@linux.microsoft.com,
	vincenzo.frascino@arm.com,
	yj.chiang@mediatek.com
Subject: Re: [PATCH v2 1/4] arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
Date: Thu,  4 Feb 2021 22:46:12 +0800
Message-Id: <20210204144612.75582-1-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210204124543.GA20468@willie-the-truck>
References: <20210204124543.GA20468@willie-the-truck>
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=JvJ1qeNf;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::536
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Content-Type: text/plain; charset="UTF-8"
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

> On Sat, Jan 09, 2021 at 06:32:49PM +0800, Lecopzer Chen wrote:
> > Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > ("kasan: support backing vmalloc space with real shadow memory")
> > 
> > Like how the MODULES_VADDR does now, just not to early populate
> > the VMALLOC_START between VMALLOC_END.
> > similarly, the kernel code mapping is now in the VMALLOC area and
> > should keep these area populated.
> > 
> > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > ---
> >  arch/arm64/mm/kasan_init.c | 23 ++++++++++++++++++-----
> >  1 file changed, 18 insertions(+), 5 deletions(-)
> > 
> > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > index d8e66c78440e..39b218a64279 100644
> > --- a/arch/arm64/mm/kasan_init.c
> > +++ b/arch/arm64/mm/kasan_init.c
> > @@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
> >  {
> >  	u64 kimg_shadow_start, kimg_shadow_end;
> >  	u64 mod_shadow_start, mod_shadow_end;
> > +	u64 vmalloc_shadow_start, vmalloc_shadow_end;
> >  	phys_addr_t pa_start, pa_end;
> >  	u64 i;
> >  
> > @@ -223,6 +224,9 @@ static void __init kasan_init_shadow(void)
> >  	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
> >  	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
> >  
> > +	vmalloc_shadow_start = (u64)kasan_mem_to_shadow((void *)VMALLOC_START);
> > +	vmalloc_shadow_end = (u64)kasan_mem_to_shadow((void *)VMALLOC_END);
> > +
> >  	/*
> >  	 * We are going to perform proper setup of shadow memory.
> >  	 * At first we should unmap early shadow (clear_pgds() call below).
> > @@ -241,12 +245,21 @@ static void __init kasan_init_shadow(void)
> >  
> >  	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
> >  				   (void *)mod_shadow_start);
> > -	kasan_populate_early_shadow((void *)kimg_shadow_end,
> > -				   (void *)KASAN_SHADOW_END);
> > +	if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> 
> Do we really need yet another CONFIG option for KASAN? What's the use-case
> for *not* enabling this if you're already enabling one of the KASAN
> backends?

As I know, KASAN_VMALLOC now only supports KASAN_GENERIC and also
KASAN_VMALLOC uses more memory to map real shadow memory (1/8 of vmalloc va).

There should be someone can enable KASAN_GENERIC but can't use VMALLOC
due to memory issue.
 
> > +		kasan_populate_early_shadow((void *)vmalloc_shadow_end,
> > +					    (void *)KASAN_SHADOW_END);
> > +		if (vmalloc_shadow_start > mod_shadow_end)
> 
> To echo Ard's concern: when is the above 'if' condition true?

After reviewing this code,
since VMALLOC_STAR is a compiler defined macro of MODULES_END,
this if-condition will never be true.

I also test it with removing this and works fine.

I'll remove this in the next version patch,
thanks a lot for pointing out this.

BRs,
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204144612.75582-1-lecopzer%40gmail.com.
