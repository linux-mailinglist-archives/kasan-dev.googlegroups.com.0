Return-Path: <kasan-dev+bncBCS2NBWRUIFBBX7CXKXAMGQEGEG2L5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id CF8F48572D1
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 01:50:40 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-411ee70f3a5sf8313535e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 16:50:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708044640; cv=pass;
        d=google.com; s=arc-20160816;
        b=B6LVvWgh7cZvrHJY3cWJUKeN0KQQ/obUtozZhBstHYnfWDhM3Iqj9PqzoeueGaM9gs
         q7Odsq1ujveJ8XIa2pkNoZoOeFFNdGYT6KqOuIp1++2h5c6i0RLoNBtemiVk67Xyo9yd
         UjmgbaiRNdIyK8/SYANxItTx6BDUcZ4/wEiO+xE+5Z36MRmCJoiV8AdLTPjL9ahuuh5O
         8fDMaqfebopLlsPAMF6QIJb3yrDKj7T/cdf+kPZJL0S20NBjhVrfKcP5ndMA1LQ7W8Qo
         +dzvb3BktPlUOXUbV/vMgcLCVGTq3yqk+dKQwG2XjXu9+CWTttNxjIZsCmWl+aiRMrGM
         Wd+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=//vmC6cRjz/piRXa+NTqCdBPokCe481ki40cOWY3NvE=;
        fh=d4HJQu4oPx0luJW8/EhuKfnAkCOu11efYkgJKEKrpOA=;
        b=rCjV8g03WD87SlR98ioguD6g6c586IRbh/hXyMWeZLD0HMdT/cqky2gn5d+3CRS2b5
         GpqR3a09nZP2w2Dsr26gtnH4z0hDepaLc1s0lHgZUyBdAfNNiVwO8onNa+RqT7pKYHsD
         8eoiPvaUVSwtACut6E65mzOKt6PrfSDRpL+W3WA34gL6GmMFhHPftPTXSWZ+191be0tW
         sL8/3iXOtPckwByCu4Zoz7WGHLUFaoeRhyWAiuZadF/63AsRSyN2dwB0dY/7nbvFME3l
         yf21/n/MCXaZ9sZuSLQwsUvQeucf8o+FUT9Ask/97pL47TRqEkhRiuqk4s/R4x7x5gBf
         1Sgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VQv3k7CK;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708044640; x=1708649440; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=//vmC6cRjz/piRXa+NTqCdBPokCe481ki40cOWY3NvE=;
        b=FOJfCjluXTlFnwlCxpGolAiQJzsWZ6HFYZJxWH37P0ftSt5vW42FJdFMYb4nuKXCxm
         OhBKNftc5xh01IaqcZAJTciISUtxBFQR3givumEKg51DkdLDKYcC5wFGe2o2Ev7YtwAE
         31gOorvgf1nScFffWfA2KnJ/IcntI50mlFsiYieug8nlZMKmRR1/T1Oq/3wOD0MGubop
         GMEZwgYRQjWgMzdkoAyyeHOyuRb2sk6x3GFHVk3vQEI64Re20JFxMa3pqnPtKSpzEHZW
         iN2depCCtjlSMA35q86VKZbMWVXN8SZhbwqRzWgkmufOhvtxqQoOziPeGBXg2HTeEQ5E
         z4Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708044640; x=1708649440;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=//vmC6cRjz/piRXa+NTqCdBPokCe481ki40cOWY3NvE=;
        b=ZZF9flCdFv8ltWXSdpDnK5PA7h7aEs/zr6GYfRYUrx5VnmFziULJ3/JmkypJMZro/D
         P8cDvdJ0/NOfhBXpscKH0TlmEK9btnE8tpwUH4sPeYX1n+roSKQfRGePG+8FGAc8Godu
         hEXCLvwaskQOhkEg19kumIDRUiXBxHw2n3v2he5xOzeBxw46aPfxDeEb/jsC87pT46p9
         UA98+y+fgHrVg1fvu0V0DxPaRBiB5SA8UFQNOR0Adxm8ZBK2AP6e7yW20dVFc+qD1EYX
         AY5xMOTZtauYxyWb/sz2Ic+hfS/0Hj9orNqQcJ7a/tG/v6MWEsOS/paP0WJYZbm9bSvk
         payg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVl3nhOC/ZMyXn7W/LpcXpJy2Le7eeLgZ6q5BoxwwrSCsVmZMcQ/WQsrethgkYAezkYIcShNpCH7aBt6uEj1yOXhQThumMW5w==
X-Gm-Message-State: AOJu0Yz/bMT1GkK6+x/vzm3P96Lg8kVODanqKF+jQsBEnLsua2TGNDOm
	O1SaNbgqUeCFNnAII9Fohs99/iNrngdxwUM204OgBe8Jvz5Wwei/
X-Google-Smtp-Source: AGHT+IHbDnnkKCzmPYyKAKcJipiZRb7U2uFKs+FK9u4BCs/KV3HGwvAjYCFV4skTrdqE6bVFgT/Gvw==
X-Received: by 2002:a05:600c:4f0d:b0:410:7428:1fb5 with SMTP id l13-20020a05600c4f0d00b0041074281fb5mr2354324wmq.27.1708044640137;
        Thu, 15 Feb 2024 16:50:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6006:b0:411:d273:90ea with SMTP id
 az6-20020a05600c600600b00411d27390eals145200wmb.1.-pod-prod-09-eu; Thu, 15
 Feb 2024 16:50:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVufHbcjMEIRdm2a/GDXCwF8wlPvZwAG0Kjsly02QuM9wguRu2kSTbKojWygbB0ulOkuCQY6IIiHxq9lxD77m9y9yDUq33jJ2zL2A==
X-Received: by 2002:a5d:6a42:0:b0:33b:2b45:9618 with SMTP id t2-20020a5d6a42000000b0033b2b459618mr2107676wrw.58.1708044638150;
        Thu, 15 Feb 2024 16:50:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708044638; cv=none;
        d=google.com; s=arc-20160816;
        b=yx2QQXpi3VZzDpCbOwEGfuPTCbodolTzein21Ih/eQtTDJ/d9jmhUCBkS94k2yVPTk
         BknzoniylYNK9a0Xq2e/qrOW1Gx3dzipDWpNuI251Cn4hrC0tHLWl+ieHwaRcHvGk4ID
         0VwBWggma5IoEJsWFDIpz/rR3B1CwhajEWI7jQPQXxFyTITONjgeuC4FuySh53bXDj+g
         BxWDVXbJ3/TptLLvBr8+jaNjojiQcp6RK2IyE4SVRhaS6PTkg6/Oj1PbRhZBvBv1rRe6
         h85tuS6GiNavEQWbUc7+xvZ747lzyr8siCLxJ6SWmJsVCScDlDKkB+IeWoYIuuU+SV1S
         QY7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=mLCxs+brit7Xt9ohcQIkEDEwu4CGUrETZSQhOqg+Gh4=;
        fh=OiwBIvYIPHGDMdlNleqgT10F8L7VFJzUbQ6V59nSWw8=;
        b=gzdDEdTboR7iTi3svroYg+xHJNhQVgE/Zvm8ZEv4dgOi2HcxxBjoOvdsvhr4z4K74k
         5rZ10Uwk5xfMx6Q7HUbDl3eB4/2F0XYaziLxfMvmikyeH/0czWx0ylHrbQ1uRTZ4WNvZ
         mGtoAiAwTiwl4JpN8RyCXX3i+2MNzm0YfKDTkv8FmbhwRxjI/BPNv610ptjaGaRBRDd8
         7EvW96QOJiKfVx9yXqodgEvZGB/L1Qq5I77BNgkkn1+EIgWMIENJj8vHcY9BaLb2kQbM
         NUYB/h/RN68XTnR2irYak79dtomJKLBBIh5C2nt1bBHAT2DzbE/5Q51xbx7OQAdR8zys
         nGpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VQv3k7CK;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta1.migadu.com (out-171.mta1.migadu.com. [95.215.58.171])
        by gmr-mx.google.com with ESMTPS id j25-20020a05600c1c1900b004120a09f45esi18498wms.1.2024.02.15.16.50.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 16:50:38 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.171 as permitted sender) client-ip=95.215.58.171;
Date: Thu, 15 Feb 2024 19:50:24 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, 
	Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, david@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <a3ha7fchkeugpthmatm5lw7chg6zxkapyimn3qio3pkoipg4tc@3j6xfdfoustw>
References: <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
 <jpmlfejxcmxa7vpsuyuzykahr6kz5vjb44ecrzfylw7z4un3g7@ia3judu4xkfp>
 <20240215192141.03421b85@gandalf.local.home>
 <uhagqnpumyyqsnf4qj3fxm62i6la47yknuj4ngp6vfi7hqcwsy@lm46eypwe2lp>
 <20240215193915.2d457718@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240215193915.2d457718@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VQv3k7CK;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.171 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Feb 15, 2024 at 07:39:15PM -0500, Steven Rostedt wrote:
> On Thu, 15 Feb 2024 19:32:38 -0500
> Kent Overstreet <kent.overstreet@linux.dev> wrote:
> 
> > > But where are the benchmarks that are not micro-benchmarks. How much
> > > overhead does this cause to those? Is it in the noise, or is it noticeable?  
> > 
> > Microbenchmarks are how we magnify the effect of a change like this to
> > the most we'll ever see. Barring cache effects, it'll be in the noise.
> > 
> > Cache effects are a concern here because we're now touching task_struct
> > in the allocation fast path; that is where the
> > "compiled-in-but-turned-off" overhead comes from, because we can't add
> > static keys for that code without doubling the amount of icache
> > footprint, and I don't think that would be a great tradeoff.
> > 
> > So: if your code has fastpath allocations where the hot part of
> > task_struct isn't in cache, then this will be noticeable overhead to
> > you, otherwise it won't be.
> 
> All nice, but where are the benchmarks? This looks like it will have an
> affect on cache and you can talk all you want about how it will not be an
> issue, but without real world benchmarks, it's meaningless. Numbers talk.

Steve, you're being demanding. We provided sufficient benchmarks to show
the overhead is low enough for production, and then I gave you a
detailed breakdown of where our overhead is and where it'll show up. I
think that's reasonable.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a3ha7fchkeugpthmatm5lw7chg6zxkapyimn3qio3pkoipg4tc%403j6xfdfoustw.
