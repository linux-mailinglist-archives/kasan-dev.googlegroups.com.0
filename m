Return-Path: <kasan-dev+bncBD4NDKWHQYDRBUUMW6YAMGQEKVEHWDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 546CB897A6E
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 23:12:52 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3689a0abf52sf2260955ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 14:12:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712178771; cv=pass;
        d=google.com; s=arc-20160816;
        b=piBnN6VBYaL4H+rtkBc5oevjuf8EIWMlLLywor6TpG3AxTS4wczyskk0hJZlPd81T4
         Ffryoj5qxy5f0WNQgvMxC50MiA2sFAelkWpu0dLZEsQaSQcdU0H+JF1NMlhSzVBznsZk
         mPAdJqUt4jklWHWjAfZFdHCUHtEkMqzOPF8QzdZjwIt1tx/zE8D7DjowotM4fhHwl6Zh
         X0XdU6+oCW3roni0h3ZwIkbWdzaSMaiaH3c2PwD1GsXuvx8VLymSfmOv3yWXacCaHp4n
         Z6Q5tHebBVMVr+m0G88VHTRkijaZDPSCaP6BCyX2Hc/qbZY0q+UuGOzAsGHq+s2KwCAX
         sqvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=I9XIvTPA8hv62XYGPsWr/w1Hl4RgOd+2W0xhRDsasks=;
        fh=4NH2iC/RcoNAW+gX6mQADA6pfYN+puVt5O+JSu29S5o=;
        b=oOdqaBhy1UgsymGHQ6jCLX4XEnC6SFAfLYO54GXlAnwnUREoDfsBBwyqJc61QNqndF
         ovTJhyUE+9LRonA+02WZ/2MWioD5sNDTof8PmhWIVYT+Zs/y1t0tQkgvORYcGMYHadbV
         oqNNpwdfRqSpoVoY/Fq0R+4NzpbN38DrF36D5MW3HEIGGnWC/lcmumz6a/Nsh+jH0+wh
         1bx7YqPKh317lbAC6Qg2ZQbW7LIrQl1kDw6TErg1TjWiOlmYRkMrrK6FrST0T2xjcsJT
         xcF/ekSHaHmFp81KX4fm+rhSBC2YG6LRdOnW9nqetMnsPHMT/y115sYuGrvxcwe++9mz
         LGcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AvVi8LMC;
       spf=pass (google.com: domain of nathan@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712178771; x=1712783571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=I9XIvTPA8hv62XYGPsWr/w1Hl4RgOd+2W0xhRDsasks=;
        b=Bmnvh1XoVomxHkP9RWO8mq16I5XOX5Gf4y//EgH24agu2OLYYftGH/MSH2EQiPe99z
         OEnYdzcMJFkZViE8NbwjKUwe45aUxL5wcLTaBh527aFlx3uRPYg6FDqvlkYOpVPkXH7T
         eezv2pJTl3j4qkK+DwYgwU7I3Pn9Iff6oloO8pHpkQBTHp/8rFMvYSFP8oD/21kEUORb
         72Kh6zCRyfeH+XgkkXC3R1fJz5fD8Ez0FTLJDWQ6uW/6tvQwxLmN98UzTKhGPtbBOI7M
         ztkGP3yg2Lj/cBU9iHFlgh2X0ukBiuIjuEtsCV87wF2/KXmerIIwU+74DzP5OlH1Ph+9
         ypyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712178771; x=1712783571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=I9XIvTPA8hv62XYGPsWr/w1Hl4RgOd+2W0xhRDsasks=;
        b=xRmVqmTQNirvKRJw32za8V0EilRA89PAz6Km4XSZoVoMPtPrsnmTn5JXL3CySfTr0+
         fyTRWV/6KL1YSg65pJ6wb3WSU0T+OtunN4WKsEcXktaj0xYVL38F1k1PR7hwWHunR5vM
         ChMwvfOvQlBya+V4Hh3/iTVB7zxNvVGulnMgnyZXC08uiY4Ufc0XQY+nUAA+ZqBhBRI+
         uM09d9i5s8is3lyE8cTyCYGPTXlNhyeu7Kx8X5XE4qxSARwUShiUz4AghHIkS5YPp70+
         jDYitITo/cQSff1DUzTXMzQcr1xfSwO5t3cLcgf7I4Ty1gsIvZoasitEJ4A/m6hFpmoH
         nUaA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUyXGUnLjNXx2IUrBL9WGf3z7tmaaKdQFQ2XwUmlWwPi6Iw23EfvIXYjY3ZBQ9muGi2WSR2k3LRDl0mZVRpUrNsfC+TIA4I6A==
X-Gm-Message-State: AOJu0YzAxYcNzoFjDVJJo9ErDk5YVgOErCgSKMoCUQraOyIs4cbe+bnB
	NOtzAG8SY5BPwAmQQjYGLI5JyhnyeySkWR9WdOZZmJ5DF996oetm
X-Google-Smtp-Source: AGHT+IErr+Y81zbNNYbvB6sx6mGv0bxpY8HAWu4kc2Z6t5bfia9+njHNi3G8UkTjrzJLhSx3e+XdBw==
X-Received: by 2002:a92:cda3:0:b0:368:efa4:be0b with SMTP id g3-20020a92cda3000000b00368efa4be0bmr948293ild.24.1712178770608;
        Wed, 03 Apr 2024 14:12:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:318f:b0:368:886f:87a3 with SMTP id
 cb15-20020a056e02318f00b00368886f87a3ls362330ilb.1.-pod-prod-02-us; Wed, 03
 Apr 2024 14:12:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXy22wV60HvV4hxnS70g7JXAGTGgqVOxOHo8KQMYxzTCHlbofAGJ/j8xyGoC3qT7V4Gg4sC8JKoVqxm1+/HrKidaKIc+4DwMUDnKQ==
X-Received: by 2002:a5d:93c6:0:b0:7d0:b3ed:5673 with SMTP id j6-20020a5d93c6000000b007d0b3ed5673mr920476ioo.2.1712178769721;
        Wed, 03 Apr 2024 14:12:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712178769; cv=none;
        d=google.com; s=arc-20160816;
        b=NGbnWPzJgF+7rdq1xdW0GAqsD0caLgmEW3c46by9MBXXAmqzRlpvDjfrI1qoVneizL
         MF2aem7u9KJekrZGjqD7Sn+ZUESOnoVcwSYNVlnq+0RssDJh601dmHH6zAXEqDb52Iqq
         h0glYyrHJNNAS8BzX2CpLcAwMgGz3iHx+27BVSsnYVms4iFquZ+ejatvQlb+UKvW55Lb
         gEq3Gzr0fzqwHSqubT7ie9G6dUpqSQj89oT+CUpFKf6m3gDnKzRwHpwBQ++jy58e/rZ5
         ZHiE4syeX/jenXGUQPH5GK11vDzR5XDl/rKuhrxnnu8W+axt1huz6/IViqRXj48RKV4t
         6KOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OhewUsTCeDFq8xyIu5MjA9BruMTOLLNvnjeXU/NxsuM=;
        fh=e8CjBQZcZ1P67n5aQsP4MPpG68e6TsTXWLKiZg6H88Q=;
        b=tGUWofzVykGvhdPtGBTFCfxPrRkYHYds0YQwSGgrMp1sC9wnRyi/uIyYgd8zOGDREJ
         51yhCWypWOCFAGTgD8/DomwfnsR6ZMtQGMzcehmGJG7NUmAwiUuBI8YtwgRkmhc9iiBi
         +cEGnJGEAyCflIIlF6pHnpBoF4wg3A7dBl0Nlv7P0epMdeDrgwfIJGVWsAMgCgpYqXm0
         QzELGmpE2mIRmZsFKzNDVYe8aL5GC3vmxxg9rkXEa+1M5odkdXLIt4C7+DG7Oza19ZFs
         +yb3nmgzxAIBLTOaH2z0J+LBg5H5lZQ1fjmVUSqEsMXeUJFtl3JNXZ60mQUQDo83ikPb
         6saw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AvVi8LMC;
       spf=pass (google.com: domain of nathan@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id h30-20020a05660208de00b007d0cd1d9ae1si468246ioz.2.2024.04.03.14.12.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 14:12:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id C23FACE2C17;
	Wed,  3 Apr 2024 21:12:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E15A6C433C7;
	Wed,  3 Apr 2024 21:12:41 +0000 (UTC)
Date: Wed, 3 Apr 2024 14:12:40 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, songmuchun@bytedance.com,
	jbaron@akamai.com, aliceryhl@google.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v6 01/37] fix missing vmalloc.h includes
Message-ID: <20240403211240.GA307137@dev-arch.thelio-3990X>
References: <20240321163705.3067592-1-surenb@google.com>
 <20240321163705.3067592-2-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240321163705.3067592-2-surenb@google.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AvVi8LMC;       spf=pass
 (google.com: domain of nathan@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

On Thu, Mar 21, 2024 at 09:36:23AM -0700, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> The next patch drops vmalloc.h from a system header in order to fix
> a circular dependency; this adds it to all the files that were pulling
> it in implicitly.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>

I bisected an error that I see when building ARCH=loongarch allmodconfig
to commit 302519d9e80a ("asm-generic/io.h: kill vmalloc.h dependency")
in -next, which tells me that this patch likely needs to contain
something along the following lines, as LoongArch was getting
include/linux/sizes.h transitively through the vmalloc.h include in
include/asm-generic/io.h.

Cheers,
Nathan

  In file included from arch/loongarch/include/asm/io.h:11,
                   from include/linux/io.h:13,
                   from arch/loongarch/mm/mmap.c:6:
  include/asm-generic/io.h: In function 'ioport_map':
  arch/loongarch/include/asm/addrspace.h:124:25: error: 'SZ_32M' undeclared (first use in this function); did you mean 'PS_32M'?
    124 | #define PCI_IOSIZE      SZ_32M
        |                         ^~~~~~
  arch/loongarch/include/asm/addrspace.h:126:26: note: in expansion of macro 'PCI_IOSIZE'
    126 | #define IO_SPACE_LIMIT  (PCI_IOSIZE - 1)
        |                          ^~~~~~~~~~
  include/asm-generic/io.h:1113:17: note: in expansion of macro 'IO_SPACE_LIMIT'
   1113 |         port &= IO_SPACE_LIMIT;
        |                 ^~~~~~~~~~~~~~
  arch/loongarch/include/asm/addrspace.h:124:25: note: each undeclared identifier is reported only once for each function it appears in
    124 | #define PCI_IOSIZE      SZ_32M
        |                         ^~~~~~
  arch/loongarch/include/asm/addrspace.h:126:26: note: in expansion of macro 'PCI_IOSIZE'
    126 | #define IO_SPACE_LIMIT  (PCI_IOSIZE - 1)
        |                          ^~~~~~~~~~
  include/asm-generic/io.h:1113:17: note: in expansion of macro 'IO_SPACE_LIMIT'
   1113 |         port &= IO_SPACE_LIMIT;
        |                 ^~~~~~~~~~~~~~

diff --git a/arch/loongarch/include/asm/addrspace.h b/arch/loongarch/include/asm/addrspace.h
index b24437e28c6e..7bd47d65bf7a 100644
--- a/arch/loongarch/include/asm/addrspace.h
+++ b/arch/loongarch/include/asm/addrspace.h
@@ -11,6 +11,7 @@
 #define _ASM_ADDRSPACE_H
 
 #include <linux/const.h>
+#include <linux/sizes.h>
 
 #include <asm/loongarch.h>
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240403211240.GA307137%40dev-arch.thelio-3990X.
