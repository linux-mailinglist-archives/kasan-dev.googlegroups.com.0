Return-Path: <kasan-dev+bncBCCJX7VWUANBB2X76CAAMGQEVNSA7EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3278730FBB8
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 19:41:47 +0100 (CET)
Received: by mail-ua1-x93f.google.com with SMTP id d9sf1183230uaf.18
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 10:41:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612464106; cv=pass;
        d=google.com; s=arc-20160816;
        b=pwUZ/Fo2eKPgrsPvjICZ/w6WOIl00fOLxl9t5O3PXeXOM03rgeVpgWdTo1YjTPRhIG
         jlXUyLWX5Avci6KHPjJBVE5DAA+fTrGG3lM82QlfHsyAhVd3qXN+hJvve2VK8iL4qd6n
         TojMHNOEDocMEE/M/ErpstcDNhlqK8ucCkDC58wixA54NWmcqjsm2qIcPtLzCW+6hkYR
         EUfbPI5k09JgyoOYzlUhd9E4Kj7z+tKP0p04FdYB4QthQ0peAMXyZ9+ZmWue4aeMzf4A
         2eHG+xidb2UUIG20RMzydAAp/ddqq3TruQQ9Q6WTnVBwPjtaaPmv2gzOQZxdASrq1yeV
         kjFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=75QDOCpoax1aIjjuCY/mncnwzbpVxW4KAOeSuDrW1IE=;
        b=HtP/ply6+/fM9a5/mM3Fw8YQ4U/1jq7twU1F0+dn+ApR5/OBfpH2JDlDlbH1FDQYXv
         dPiRr7f4TEyVYxIZWEVivqn9vR3E4BK5+yxZM3G+9bL3hgcW2kdAxZxA6ptOFoDLSUCR
         pHXs+cJ3oDXqp3lA8m/4gkzE56gY+XJvlqljC76sMXYXf9sUoJ1xp2ZDB8zurMqa7kBV
         4bUCimTIzXcIOWJccI3NW9CGdbZ/XiqldIi3UsNFov3BSvIJgtGv4n5tI/H+cPIeA3AQ
         4SFrEZHlDeop/wikTXOtuilxBJrB/mVVTuAPfevmT0IPGHVUCSRFuyoHnBYmr0ZQVbgB
         kikw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=hZEBnFad;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=75QDOCpoax1aIjjuCY/mncnwzbpVxW4KAOeSuDrW1IE=;
        b=Yh8tAM+Kj1VCjHrB/wzfKo8ZKqC1UwbBr7eIS6/L6bwf6ZXIzYAOcpOPSdgkHM++Fx
         nlK4+TwigoLey+QU75oFZQKMl1R1QJVhl1C1ORxndOqCADqrfcx3mJj+sF362fX5+dtw
         GImvCIZtcLaJOELLt97m0+O1LbxFPqR3Y53/TiHCxTqG0q/s7W1nCjqjD4zjvVGJPFss
         iqtGeDx/NpD/oUjG2lDxyEaMfjowod32j7fetZIXKafw5swfqa9yNXj+nPuzNZe9pphS
         /s/osgR+K6CLuAwlI/pldAQp9yEMLdSoAVkDh8wu0+VHxf9anN+T1yK1ID89f3o2AJ5X
         RRnA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=75QDOCpoax1aIjjuCY/mncnwzbpVxW4KAOeSuDrW1IE=;
        b=gSAJ1mT/MlUNkvBvChQzb8YhROmNy0fNGXvIK/nzZzfVoAz9iV2DYZMBnAbC0I0Zxj
         YGEScnKgVU3IGlmhJvNHF0DGdJAsBafbVy3JvCp1e4liPe1Zb/BskzawIOEsWYNBaAlj
         zBcI3/nPeNbe2AhJCTViIo/g2D7fHRyUuYfT6wE3vilO3Bby9ohCjfAGyV+O0Wty2Ez9
         IYD5ni60M4BiSCWuUXE5e36jknZW6CQBJa6bVr+7kNLxnjgD2s5ovMv/lFOKG+EyUbRo
         sZQ5OYLFj4YhVsF5QwJd6hKwZiMigc+2XAl3JaqqqyYfGwzmnCWFybNwMu/kw7J2RMmX
         QkJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=75QDOCpoax1aIjjuCY/mncnwzbpVxW4KAOeSuDrW1IE=;
        b=BUy6GwPNXwStwNfOkpnX4Ct0YYWj9STHqZ+ummJH/G3xAsfDbtOPwuVzVJhirxbqSD
         8zZewrlgfz7zhY2IIYXKbnI6nMRPLbm6dngoMbzkf+UIp9SC7RmHruVdxeRbJFyt3An4
         L2obzyaiKgufTCy4rcausA74XlppokhLuomDjk8RPk7g34NDlXGFMW9iLkTk3smgbzN5
         IQZe/PE51oA2Anh0AipEmHjzjxQfSah58iM/Xr+Kw90huaudKjL/IOk9dHlFZiUIBHsE
         9MARlsfjwCpmGI+i0Y7u3yvnaCwyOxelKDNueWiyQgtfTMGcR2iGOt02hQSwF8dmV0HR
         NlXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530wNk32ngX42oB3/LYNsGxOzGATFCqqlcu8079l0ZrDZbZqWOAP
	weaQwrSCr93II0tZiFdIbtc=
X-Google-Smtp-Source: ABdhPJwTMsuc2gVcHNJFb8bQEOHBT17GPhWDKt0RNTeuYGd3F9eB4+IXj3IkJwnNQ2aTEtpFKBwVUw==
X-Received: by 2002:a67:ecd8:: with SMTP id i24mr522827vsp.28.1612464106316;
        Thu, 04 Feb 2021 10:41:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f898:: with SMTP id h24ls840097vso.5.gmail; Thu, 04 Feb
 2021 10:41:46 -0800 (PST)
X-Received: by 2002:a67:73c2:: with SMTP id o185mr751142vsc.16.1612464105929;
        Thu, 04 Feb 2021 10:41:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612464105; cv=none;
        d=google.com; s=arc-20160816;
        b=mdKYtJjgTit7l8d6o3FA8GBTL44FXAimM1NJ3vqZjSspBmjaZ/0bWg4/OKkoRolvjJ
         auEP77VmSicK8sYkVyL5IOfpPf1AKN7jMbKsHkVjD9YRpfGzgAfZNzOKGJUxX7ob997r
         kelpdx3WpSbUwxbDUGHitMaDvv3OAjP/rdFWzz2oBcEpdpaQDS8rlslHRsoEjZ659l59
         I/jVRbu6B6JGT4CxdxYjppS9k5XD2eWIRgDbZTAzU2u2G36G5SrQlMfJVI/bYiguQnuV
         GgBK8LCQEunMUcb0KT760ntVlBLahFOev3/OyPWfbgCTxnasRav7tXz9LUhx4jPkFujr
         1yqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xPJcixL5B72ONNeQTUrd/Ds+3cwL/OzxhJxazJOwdWU=;
        b=PrbInLoIeygsDXQGj2JhrsQksLZmqfNfzyGgNF0SYa8n2NnQKgv9UMR/kZ3Z/X6Uhu
         Nga9fCWaV3hQvMW2bJXFCfgLfIgWUh/XCRtnpdyyXVXZiXQog/UOSw0i6OVX1C+kOQKb
         qVeEJzZM3Gsw5UUDnjRLYcCf1dra8E0d4oR4IMYyatRh3L4f9BCZAmAgrxPOw88wbOxO
         zZ1w8f9FsCexOC3EMC+1wKhTRK0973vdHJMOGqPNFn4Z/AXcta0vrjs3ZDbU9cEuZmSC
         WgXyGAaiLuv7XAeBl1GgDGLMn5ashR2NkzpNuOZmUOydUuNPj1ALGizy+kWpTQikmyYW
         qSDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=hZEBnFad;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id h123si326664vkg.0.2021.02.04.10.41.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Feb 2021 10:41:45 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id y10so2227798plk.7
        for <kasan-dev@googlegroups.com>; Thu, 04 Feb 2021 10:41:45 -0800 (PST)
X-Received: by 2002:a17:90a:7787:: with SMTP id v7mr298480pjk.81.1612464105539;
 Thu, 04 Feb 2021 10:41:45 -0800 (PST)
MIME-Version: 1.0
References: <20210204124914.GC20468@willie-the-truck> <20210204155346.88028-1-lecopzer@gmail.com>
 <20210204175659.GC21303@willie-the-truck>
In-Reply-To: <20210204175659.GC21303@willie-the-truck>
From: Lecopzer Chen <lecopzer@gmail.com>
Date: Fri, 5 Feb 2021 02:41:34 +0800
Message-ID: <CANr2M19xc+9UE3dZB5UA8HvgTGAcoSLOPAkeepExcUrKkNHt+g@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] arm64: kasan: support CONFIG_KASAN_VMALLOC
To: Will Deacon <will@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, ardb@kernel.org, 
	aryabinin@virtuozzo.com, broonie@kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, dan.j.williams@intel.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, gustavoars@kernel.org, 
	kasan-dev@googlegroups.com, Jian-Lin Chen <lecopzer.chen@mediatek.com>, 
	linux-arm-kernel <linux-arm-kernel@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-mediatek@lists.infradead.org, 
	linux-mm@kvack.org, linux@roeck-us.net, robin.murphy@arm.com, rppt@kernel.org, 
	tyhicks@linux.microsoft.com, vincenzo.frascino@arm.com, 
	yj.chiang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=hZEBnFad;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::62b
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

> On Thu, Feb 04, 2021 at 11:53:46PM +0800, Lecopzer Chen wrote:
> > > On Sat, Jan 09, 2021 at 06:32:48PM +0800, Lecopzer Chen wrote:
> > > > Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > > > ("kasan: support backing vmalloc space with real shadow memory")
> > > >
> > > > Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> > > > but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> > > > by not to populate the vmalloc area except for kimg address.
> > >
> > > The one thing I've failed to grok from your series is how you deal with
> > > vmalloc allocations where the shadow overlaps with the shadow which has
> > > already been allocated for the kernel image. Please can you explain?
> >
> >
> > The most key point is we don't map anything in the vmalloc shadow address.
> > So we don't care where the kernel image locate inside vmalloc area.
> >
> >   kasan_map_populate(kimg_shadow_start, kimg_shadow_end,...)
> >
> > Kernel image was populated with real mapping in its shadow address.
> > I `bypass' the whole shadow of vmalloc area, the only place you can find
> > about vmalloc_shadow is
> >       kasan_populate_early_shadow((void *)vmalloc_shadow_end,
> >                       (void *)KASAN_SHADOW_END);
> >
> >       -----------  vmalloc_shadow_start
> >  |           |
> >  |           |
> >  |           | <= non-mapping
> >  |           |
> >  |           |
> >  |-----------|
> >  |///////////|<- kimage shadow with page table mapping.
> >  |-----------|
> >  |           |
> >  |           | <= non-mapping
> >  |           |
> >  ------------- vmalloc_shadow_end
> >  |00000000000|
> >  |00000000000| <= Zero shadow
> >  |00000000000|
> >  ------------- KASAN_SHADOW_END
> >
> > vmalloc shadow will be mapped 'ondemend', see kasan_populate_vmalloc()
> > in mm/vmalloc.c in detail.
> > So the shadow of vmalloc will be allocated later if anyone use its va.
>
> Indeed, but the question I'm asking is what happens when an on-demand shadow
> allocation from vmalloc overlaps with the shadow that we allocated early for
> the kernel image?
>
> Sounds like I have to go and read the code...
oh, sorry I misunderstood your question.

FWIW,
I think this won't happend because this mean vmalloc() provides va
which already allocated by kimg, as I know, vmalloc_init() will insert
early allocated vma into its vmalloc rb tree

, and this early allocated vma will include  kernel image.

After quick review of mm init code,
this early allocated for vma is at map_kernel() in arch/arm64/mm/mmu.c



BRs
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANr2M19xc%2B9UE3dZB5UA8HvgTGAcoSLOPAkeepExcUrKkNHt%2Bg%40mail.gmail.com.
