Return-Path: <kasan-dev+bncBCN7B3VUS4CRBX6RVSIQMGQEGN7DTGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EB344D600A
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Mar 2022 11:48:01 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id lp2-20020a17090b4a8200b001bc449ecbcesf7774501pjb.8
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Mar 2022 02:48:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646995680; cv=pass;
        d=google.com; s=arc-20160816;
        b=fA+NOf1/HPoQLCrywYaYOWHo/ORnHUVZzwpu8wW7/fC/y730aCZbVCGmWHbyxJxOAi
         oaibELd31GyKLHftwfF/6xhGogMfcdL5DZ7oNoEmCjm3whTBpgq6W78KbVqS2iKI4KwO
         igjEglD6mKjmtENjddgi3cThiR0M6CH0eWM5N3gFHOYVAP0lcqb8i21dHb3EiAccfoNc
         ieFuTVsP7QiQo+pfMVUuNN1tK3gGQYyp3ZootyYT9B4OTMAnbym6y7sk/8rUbPaLTRRn
         Jg16s30m84W79Y9rdOVh6Lvba6P1g4BeLdKdwnk1pMaoRo1yPxmIRUkLa6MCxThW+SgN
         /lJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=MKqgMRmGj6Iok3tSg9DOJIz2peQrsWT3ZYNeIVBVqkk=;
        b=lzhg0HFL6IdYGHS466ye51EkCwfquwVovvGpZPoFoL3ABy6o5IS/Yb4/lB0AHf1xOM
         B/68wyF7KW2apjRd/u//VMX8HR5/ecQzmuZtKG72KGcheN/gpqt1kLFQalwfjXQ3avFa
         VTXetLMe2xpO2+VWLrJbP9LoJwcn1tOcyqOGteAtIgnC7wU9gT6J6XCpKAasWFA7A1Wg
         ISbGe4PRi1faChZfX+avX6t4tMsmyX20zO+G2sIowBWuI5lx/LPE8aBWgthP9YgdDpi+
         u4Iz61Yvzvx8Yq0OOAgKvcDHr9w1U4RJO3f+yq2nKHQmbSpWuVV7qzPtYT+osEpaMgZ4
         OFnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MKqgMRmGj6Iok3tSg9DOJIz2peQrsWT3ZYNeIVBVqkk=;
        b=JF/mEh6ly1ut5Be3pLA/zfsi7z3ZYoPni8IUULtqYv4idc+XF6KiPHL5UCAeGW97dn
         v0EUe8MVgONuA0pn0xO5uCsFodGc9mcS1f6igkIoc9RMtHmA2G+4j9eHkucrG6Fehx/n
         YcQRSI/3t491Wpc+LwQAbjfBww2ngQeddp25P2mnQtoVOt4I8+wmL/noR/SaSDlhiDI9
         Cmo/dOpnFGfHpawk+jNXTgg/CnKYoH95mAMwQvP1XFGjXjqQHpCWem0BRdpRxUkbmrS+
         fQEeJRWgkOtlwbczOW6tHgxuRxvsNKBKbsuZ5hp4k7mHFpX6fog0JmrvHk73Fr0+Vllk
         js8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MKqgMRmGj6Iok3tSg9DOJIz2peQrsWT3ZYNeIVBVqkk=;
        b=ZQXOQaowzZ5dXxybG0Vi5TdW/Ep74PH4hocSNZjs/4zDqHkbsEADqV4cKnHfu2QXz5
         Opo2GB+SYMYNQ2Gb0Z7O7OjweE8B+aBERXpIKEfoJkDW8107tIp/f7CuRNtVhZU+zLD+
         LR0t1t6RCNSDn66sVy/rsijSvtCBvgERY1zJRoCJzHKYqIcjd4uGd2r2fd52Ce3zfFh7
         INzKRIRa7Cd/xIMq+qHuDioQeNItNmbxNHYHqM9vMDX8NTKvCfeg44IaehSigS8WBQY5
         JbetTwuK2//1cKELjJr5wAgOwXh4zFULgY5ruY2ejL2K5xu/ib8P8GNdgBveARku1F+8
         9D1g==
X-Gm-Message-State: AOAM530//ouYE8i3ZIjZLlmCA/HAVx4dVAJd/PoQmNL/Xk8bA5mRAuOo
	WRkmPVH9W3Nsvjl82kf6V6A=
X-Google-Smtp-Source: ABdhPJwtwWtux1cl/6upbdFLhWYmKjHfj8duc3DVF7mlksE6bUfaUc4CSkyKiIz0536KnCwOwNOxEQ==
X-Received: by 2002:a63:213:0:b0:37c:5bba:1f9 with SMTP id 19-20020a630213000000b0037c5bba01f9mr7916785pgc.617.1646995679900;
        Fri, 11 Mar 2022 02:47:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ea92:b0:151:e731:3527 with SMTP id
 x18-20020a170902ea9200b00151e7313527ls847698plb.1.gmail; Fri, 11 Mar 2022
 02:47:59 -0800 (PST)
X-Received: by 2002:a17:902:b406:b0:14f:bb35:95ab with SMTP id x6-20020a170902b40600b0014fbb3595abmr9610744plr.140.1646995679217;
        Fri, 11 Mar 2022 02:47:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646995679; cv=none;
        d=google.com; s=arc-20160816;
        b=XiCglrApIwUR/nP45Ffg4fDCTl0Uy99onwBubxv0Lnxn7/Wj50q7LeyZzIHREZquND
         lKMTgY3OH9rDpc5JnbeoDx2FHWvtv78FkOADRa16C6SuTALKa3aw71jhXd+3UX3cgecl
         nP/sFbec/U0ui1/NP6/lGcWHZVHreqYn88HOivrWS7JWDYY5gq5Prkgvb8M//5zSfjz5
         de2FyNV53IoYjMHixPjWfHBprMmSQiMwsK49SjpQ0K3IfRzTxt/P5EANrRVqvQRz1jH+
         761SkG4/nukojSEh1GSdRETrF6Rb5oruBk7vq3/pnTnr0pNvO3cUzkfdhv4628OmXa6T
         UGWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=zTCemsJkUwDNfcQF42s/TBikxeXrIy5ctmFFkjhau0w=;
        b=e41te+2GZLSokL7afcvhIeN1aIZqTuQ4YYKWjY5JWJt2UPh8SpdQt03yIurkBUg481
         CHz8EGT7sJjJBQ4GNY7qTE1FI0C5N03HfvLUhmEzAvl9gZVQ73OgAOgYj2AJrXjucMFG
         jEoaVTwJ5L0wlalgjNvtcmZNwAQQK7RqD+dTKfldZdEpjnyhCzymK5xLSmiKIXlxQgGg
         f1nhqSVldSTvjVXUqgXakdj9D33cR+ptgWgjmuAUu5ZNliUu0+8mRMlPJ9WX10uHOfXg
         VY/CVCQPRmVYdStoy+Jcwa4H+7XoVsiGySQm0axxJHAV/LgzQZrlzByKlMlr0iIhZtiK
         2iRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id k5-20020a170902e90500b001517cf05af9si307324pld.8.2022.03.11.02.47.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Mar 2022 02:47:59 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 26ee146925a34e8983401382666511be-20220311
X-UUID: 26ee146925a34e8983401382666511be-20220311
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 768871941; Fri, 11 Mar 2022 18:47:54 +0800
Received: from mtkexhb01.mediatek.inc (172.21.101.102) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 11 Mar 2022 18:47:53 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by mtkexhb01.mediatek.inc
 (172.21.101.102) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Fri, 11 Mar
 2022 18:47:52 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 11 Mar 2022 18:47:52 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux@armlinux.org.uk>
CC: <andreyknvl@gmail.com>, <anshuman.khandual@arm.com>, <ardb@kernel.org>,
	<arnd@arndb.de>, <dvyukov@google.com>, <geert+renesas@glider.be>,
	<glider@google.com>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <linus.walleij@linaro.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<lukas.bulwahn@gmail.com>, <mark.rutland@arm.com>, <masahiroy@kernel.org>,
	<matthias.bgg@gmail.com>, <ryabinin.a.a@gmail.com>, <yj.chiang@mediatek.com>
Subject: Re: [PATCH v3 1/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Fri, 11 Mar 2022 18:47:52 +0800
Message-ID: <20220311104752.2616-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <YislvzIg3Tvwj2+J@shell.armlinux.org.uk>
References: <YislvzIg3Tvwj2+J@shell.armlinux.org.uk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Lecopzer Chen <lecopzer.chen@mediatek.com>
Reply-To: Lecopzer Chen <lecopzer.chen@mediatek.com>
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

> On Sun, Feb 27, 2022 at 09:47:25PM +0800, Lecopzer Chen wrote:
> > Simply make shadow of vmalloc area mapped on demand.
> > 
> > Since the virtual address of vmalloc for Arm is also between
> > MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
> > address has already included between KASAN_SHADOW_START and
> > KASAN_SHADOW_END.
> > Thus we need to change nothing for memory map of Arm.
> > 
> > This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
> > and provide the first step to support CONFIG_VMAP_STACK with Arm.
> > 
> > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > ---
> >  arch/arm/Kconfig                 |  1 +
> >  arch/arm/include/asm/kasan_def.h | 11 ++++++++++-
> >  arch/arm/mm/kasan_init.c         |  6 +++++-
> >  3 files changed, 16 insertions(+), 2 deletions(-)
> > 
> > diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
> > index 4c97cb40eebb..78250e246cc6 100644
> > --- a/arch/arm/Kconfig
> > +++ b/arch/arm/Kconfig
> > @@ -72,6 +72,7 @@ config ARM
> >  	select HAVE_ARCH_KFENCE if MMU && !XIP_KERNEL
> >  	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
> >  	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
> > +	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
> >  	select HAVE_ARCH_MMAP_RND_BITS if MMU
> >  	select HAVE_ARCH_PFN_VALID
> >  	select HAVE_ARCH_SECCOMP
> > diff --git a/arch/arm/include/asm/kasan_def.h b/arch/arm/include/asm/kasan_def.h
> > index 5739605aa7cf..96fd1d3b5a0c 100644
> > --- a/arch/arm/include/asm/kasan_def.h
> > +++ b/arch/arm/include/asm/kasan_def.h
> > @@ -19,7 +19,16 @@
> >   * space to use as shadow memory for KASan as follows:
> >   *
> >   * +----+ 0xffffffff
> > - * |    |							\
> > + * |    |\
> > + * |    | |-> ZONE_HIGHMEM for vmalloc virtual address space.
> > + * |    | |   Such as vmalloc(), GFP_HIGHUSER (__GFP__HIGHMEM),
> > + * |    | |   module address using ARM_MODULE_PLTS, etc.
> > + * |    | |
> > + * |    | |   If CONFIG_KASAN_VMALLOC=y, this area would populate
> > + * |    | |   shadow address on demand.
> > + * |    |/
> 
> This diagram is incorrect. We already have the memory layout in
> Documentation/arm/memory.rst, so we don't need another set of
> documentation that is misleading.

 Ok, should I send a v4 to remove this?



BRs,
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220311104752.2616-1-lecopzer.chen%40mediatek.com.
