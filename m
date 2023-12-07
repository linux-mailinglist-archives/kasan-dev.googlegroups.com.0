Return-Path: <kasan-dev+bncBCILLLGERUHBBJGRY6VQMGQEJ25VHHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A494808C20
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 16:45:42 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1d0af632728sf1180705ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Dec 2023 07:45:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701963941; cv=pass;
        d=google.com; s=arc-20160816;
        b=FIMQkJj3lyHq9tdo34S3AJcBv62lNIMrNQWvjLCPGqd+xjGKkZ8B2opC4Yy8nb9BT3
         i1q7mEmDrqT8iCnjgw2m2sQvHo5LLeezsFO92nTdr7tzR42OubSqvCBV4l4gejKXpfA8
         jTJ1f76jCptlMMtqyDw9kKqHi7hfaZlBbtXo4hJgbzfm+t8UZpHGML3aYdHbUXBCNrzw
         b1FdhiJRzm/SrorQmmm8uXXgtEDR0os0WRKiCv7nt1txmJTl6JOato8Rd9t1w3Uz+5hq
         fggFOSwYV30Lp3dRvuRo352qsjwT2oPz/Cbb7VunTADnOgqcit+6igBE0SWA0OIUKem8
         30Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=n3iWm38I4YO1yVJEy3uA9NizKXXgZWrJQchxobiYJsY=;
        fh=116og8lalqa6MU202T7/3P4Ee7fswQ+6jT5BOccLZNk=;
        b=MLXM2J8iN81EUmCNrKAaCaYuAXJaLo/pNrhJEBuf3b5DkDBjtdrKW2Xei7rBSQAIAQ
         rA6V40EmtZ4+PE4o7I8n1iYmUywdhN0T5VssJCI4NuCkAo0vklcOBNQVV5YHmnSfDUGk
         nzpj6SCELAfQ1tUSaCxPSuxGLlUWXfMCT73aGWR5UgPnhNDLgNA8xYM4pvJ3FpqUnVL5
         z7fgQ7pCDuAk0OUULI/EgbaGkxA9wTscvschCugADOMcs2SF+hKe3LcEyZBU7h0/HyQS
         /o8SxnochrL30L8ydUxuwfPh2GAZfWPGqdVvwU3ROz+3uSTLxj9LNA/Vxht7ZPJh1lGo
         Ekwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dennisszhou@gmail.com designates 209.85.214.170 as permitted sender) smtp.mailfrom=dennisszhou@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701963941; x=1702568741; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=n3iWm38I4YO1yVJEy3uA9NizKXXgZWrJQchxobiYJsY=;
        b=V0bCtARi9RBogwbNQk8+4qEdI9+iV9Km2bniY9KIzbbvZU22HVDDriihjRCSrrEIRl
         Z8tZepleA7GJzMdy0/usFjhvXLBP71b4ZTk+sHpNojxvmvu/N5JmnT6bKqX2wkA9hqbv
         4FPcAJeWy28aRx0HGlCSqOZ7d95h5dJUFKzxmH3AIh17+9BEN0NXhEWmbktxiRWG38qM
         PBGBLR0f/eYvgI3ayd1mp8spF3tJ21IN5si8RlSpBcC62cF/6FpjxCTO5+AhJyfJaJ9H
         37/Q+s4YI9TZ9dAN/6fFemhaOan5kYkLy2Oo7zkGnkhqFxZxxMhJn+hohr6Zsk8oQg0R
         kgyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701963941; x=1702568741;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=n3iWm38I4YO1yVJEy3uA9NizKXXgZWrJQchxobiYJsY=;
        b=d8UXUmbynVQHpyHXOin13FpKHGQIwi0quDIllgZzQkxg9FWotiG1uFFA4Vi0en0TEP
         gxaWx6ZtH7kLrNKNs5pYitbqIWJ4vu0sKQKjiemACatIQCckuw+RAayym4LG5qwu/vDU
         r/HI1dTP3geqK0/lEJnm3mI/o/NiGjETxB1isKZEhjDXAD/TUBulwDMAA38uKEo/YzWV
         T6O+DK93g2MWou/xJSqAfPuLPSXLiP8oYhMr4Owacq//YdYZOf4OIn6kec9SjG4qWFIA
         ZSThGSJHaxLyHj5LnHPRzZsX1RihFaT/nzqIrX8+E2sLLDbHODkCZzq4KjxW7GAorE19
         mG9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyS98uJ8hccLtW8dRIK/rLh9AYYRy2V0g9IcjoGBJylDl6XgGNG
	Aky0Fp6ii4+el4M2VBIucDk=
X-Google-Smtp-Source: AGHT+IGt8nt6XUaFjlHerB5A2Dwr/UDL+qiq5+q39P5BoYKTnXGRdlbVR+LmiY3PBYIZDjg4k9K0mw==
X-Received: by 2002:a17:903:2641:b0:1cf:ccc3:c9ed with SMTP id je1-20020a170903264100b001cfccc3c9edmr497828plb.7.1701963940755;
        Thu, 07 Dec 2023 07:45:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:602:b0:58a:758e:d0b5 with SMTP id
 e2-20020a056820060200b0058a758ed0b5ls1506444oow.0.-pod-prod-06-us; Thu, 07
 Dec 2023 07:45:40 -0800 (PST)
X-Received: by 2002:aca:1011:0:b0:3b9:e48f:d642 with SMTP id 17-20020aca1011000000b003b9e48fd642mr375247oiq.4.1701963940353;
        Thu, 07 Dec 2023 07:45:40 -0800 (PST)
Received: by 2002:a05:6808:1784:b0:3b3:ed04:dbd0 with SMTP id 5614622812f47-3b9c65809d7msb6e;
        Wed, 6 Dec 2023 21:46:53 -0800 (PST)
X-Received: by 2002:a05:6871:2b1b:b0:1fb:75a:7797 with SMTP id dr27-20020a0568712b1b00b001fb075a7797mr2283209oac.72.1701928013396;
        Wed, 06 Dec 2023 21:46:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701928013; cv=none;
        d=google.com; s=arc-20160816;
        b=n/sEHuOHqSoWiV89Tpds0msZDHk+tzVozZwdRYcgFPnTnZQ+xBiLhI0ftfEkP6kO5l
         7VYOGLaOJViS4L2fZx5aBn9hTMdx7v+9CicmbmLyiJ1l65l9RDJLpiCnbv2N04hhsQT1
         fMnNTpHzPAGzk7UeSxDHUkpwy/+83h2KMbI5W8AJRt0GqSIjrRI6r/E1oC8CoJO2hxaJ
         2l5No5YldGMHr3Zo5qKBixMiom73I3a5c0jYIfu5neqQdI2jCM15ZIapg+0tTjFgxkNV
         TH7Sj2JysRALT+ui27SgLTH+B7WekyhC9+6FQwP8SdYJdMj+vH/OH7DbDxSgcjHtnaXP
         VABg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=egxxoHFyDqeCA/LxlDg8JyWMVYkStRh8cbZHikRDbS0=;
        fh=116og8lalqa6MU202T7/3P4Ee7fswQ+6jT5BOccLZNk=;
        b=OfzPR29tuzw9r/qj+uiNJ+Qd5I/N+YiOV3YtTRLvTZ+fRJzO+keHJ+gJSW/wuBegpA
         sqHpX+m6hXqyq82MPmH8mBcSs72jsBQ2iVjzgGg/NqmarUD9ta1wvoOtv3gQcZVthTMc
         gPPb4d00AikNWdgFDyCSVbzSTmE5uR+h7d5ITAtcTg/E4yvclqRD/UyD9dKTsaOigeKQ
         ma2RnjtS5aL6m56uRxnVL+08cyyo3s22/Q91jgXmgS/YmfWNVPCzDneuz2uNqECl+Guz
         pp2kgRSpUHZ4FyZBvK6CjKhzAdQRAIElfl70VGDzCzXDBHkUWsF98Nh/pabDTpceIe/r
         wsPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dennisszhou@gmail.com designates 209.85.214.170 as permitted sender) smtp.mailfrom=dennisszhou@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pl1-f170.google.com (mail-pl1-f170.google.com. [209.85.214.170])
        by gmr-mx.google.com with ESMTPS id gb25-20020a056870671900b001fb4d96efc3si98083oab.5.2023.12.06.21.46.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 21:46:53 -0800 (PST)
Received-SPF: pass (google.com: domain of dennisszhou@gmail.com designates 209.85.214.170 as permitted sender) client-ip=209.85.214.170;
Received: by mail-pl1-f170.google.com with SMTP id d9443c01a7336-1d05212a7c5so3905625ad.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 21:46:53 -0800 (PST)
X-Received: by 2002:a17:902:c101:b0:1d0:8afd:b28c with SMTP id 1-20020a170902c10100b001d08afdb28cmr1453916pli.92.1701928012478;
        Wed, 06 Dec 2023 21:46:52 -0800 (PST)
Received: from snowbird ([136.25.84.107])
        by smtp.gmail.com with ESMTPSA id x5-20020a170902ea8500b001d08e080042sm431944plb.43.2023.12.06.21.46.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 21:46:51 -0800 (PST)
Date: Wed, 6 Dec 2023 21:46:48 -0800
From: Dennis Zhou <dennis@kernel.org>
To: Tejun Heo <tj@kernel.org>, Alexandre Ghiti <alex@ghiti.fr>
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Arnd Bergmann <arnd@arndb.de>, Christoph Lameter <cl@linux.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Subject: Re: [PATCH 0/2] riscv: Enable percpu page first chunk allocator
Message-ID: <ZXFcSEzalzl790bO@snowbird>
References: <20231110140721.114235-1-alexghiti@rivosinc.com>
 <f259088f-a590-454e-b322-397e63071155@ghiti.fr>
 <ZXDEyzVcBOPUCCpg@slm.duckdns.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZXDEyzVcBOPUCCpg@slm.duckdns.org>
X-Original-Sender: DennisSZhou@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dennisszhou@gmail.com designates 209.85.214.170 as
 permitted sender) smtp.mailfrom=dennisszhou@gmail.com;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Hello,

On Wed, Dec 06, 2023 at 09:00:27AM -1000, Tejun Heo wrote:
> On Wed, Dec 06, 2023 at 11:08:20AM +0100, Alexandre Ghiti wrote:
> > Hi Tejun,
> > 
> > On 10/11/2023 15:07, Alexandre Ghiti wrote:
> > > While working with pcpu variables, I noticed that riscv did not support
> > > first chunk allocation in the vmalloc area which may be needed as a fallback
> > > in case of a sparse NUMA configuration.
> > > 
> > > patch 1 starts by introducing a new function flush_cache_vmap_early() which
> > > is needed since a new vmalloc mapping is established and directly accessed:
> > > on riscv, this would likely fail in case of a reordered access or if the
> > > uarch caches invalid entries in TLB.
> > > 
> > > patch 2 simply enables the page percpu first chunk allocator in riscv.
> > > 
> > > Alexandre Ghiti (2):
> > >    mm: Introduce flush_cache_vmap_early() and its riscv implementation
> > >    riscv: Enable pcpu page first chunk allocator
> > > 
> > >   arch/riscv/Kconfig                  | 2 ++
> > >   arch/riscv/include/asm/cacheflush.h | 3 ++-
> > >   arch/riscv/include/asm/tlbflush.h   | 2 ++
> > >   arch/riscv/mm/kasan_init.c          | 8 ++++++++
> > >   arch/riscv/mm/tlbflush.c            | 5 +++++
> > >   include/asm-generic/cacheflush.h    | 6 ++++++
> > >   mm/percpu.c                         | 8 +-------
> > >   7 files changed, 26 insertions(+), 8 deletions(-)
> > > 
> > 
> > Any feedback regarding this?
> 
> On cursory look, it looked fine to me but Dennis is maintaining the percpu
> tree now. Dennis?
> 

Ah I wasn't sure at the time if we needed this to go through percpu vs
risc v. I need to poke tglx and potentially pull some more stuff so I
can take it.

I regrettably got both the covid and flu vaccines today and feel like a
truck hit me. I'll review this tomorrow and make sure it's taken care
of for the next merge window.

Thanks,
Dennis

> Thanks.
> 
> -- 
> tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXFcSEzalzl790bO%40snowbird.
