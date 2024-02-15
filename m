Return-Path: <kasan-dev+bncBCS2NBWRUIFBBG6HXKXAMGQEM4REWDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 470038571F1
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:51:56 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-50e91f9d422sf221045e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 15:51:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708041115; cv=pass;
        d=google.com; s=arc-20160816;
        b=j87xH0+UTPwTWLqnfIOCzjbjpADDmpO1OGPUYTRnkdPlNs1YThO+Wc2gtYSOr4jsY8
         PxU9sO+tPP1GFDe3jkJq//IwVRJD5Fh7jOYOFTeNdCf1F4uVb4CBSKyugph09T9P3Pc6
         ixuY1mU9okNU4Db3klCHF43NEVoCadfr+ecLrmC+Y+3DA3hWptwbz4HKQTikGZ5BenXz
         n/Rvyg2sUH40juAMih8Jn74W65E8M9R8cDrcSKN5B7Z2Ztbi60zAKyp6BXVEEaf7KMJ0
         FdtqUqkkLZTkIcAW3GtsKY8ALgeEyfixBzlG5HWv+ETkQ8DOQeCI/T5vZyI4uP1EwtSj
         24Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=iJ9UShHTVsU9y+oq7tW5rkAyOQwOBltwQBZQBVnPJpo=;
        fh=52RhcBo13IFtAz0XFVFvyAxLx4Eg9CtxxNl4ICOf8nU=;
        b=JRMEww2SM333hzo9J8Ls7J8/+Iu1L3UiE8/iUw43mL9N8eJtI+3E7HqGdjQcWhU/l5
         8iwuuH1j2xg8dtD6lHqUxQqFVOt7OZat+GZ6YAQnG+UiIVVEG68tjOl1bDBhOFl8UoCc
         mC2vPM9ZwDO/XtFhH5hNZ+In+Tafw5+Zmxd2oRM5YNxTEVuX8kIs6DRl+rtgKtmPRUhE
         QuAFCmhAoZ/twh9FwBte0xJ9tvTrZoBqGz9MMjODUX/WmzVR4t5KmcfZMqGpNAq/E7kT
         8TmiFEFXdsuCPYZs6GGgHNCtZVLSbbP1zoby3pz11p/5szcw9PtgEsmzlOx0lzwCl64O
         FtOQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AX8VvR4l;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b5 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708041115; x=1708645915; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iJ9UShHTVsU9y+oq7tW5rkAyOQwOBltwQBZQBVnPJpo=;
        b=ZMpXvhiDOv850mU18rVkYcEZIrqpXhP7UzelsjW92eLUCRyR5vaQUZmhzISPrmGdtp
         rAHIbVkTUoeyQltvvYnRRf6yP6CvZ7N4p3umukQm7uYZwxv9EdGUpggLeAmLKsZ+Agi7
         oy2nKDrrzdPkuYkRGChPxuJYtJdGbZrYvbPLE66JxCwk+shGvWIlT/haD8+JywUN4NbM
         HUM0LXnve31vpp6UnCdHv+noTmUrVYQp4RKAY6yh0baC2nwzHBafChk+mfxx0JPy1q5i
         YXsjZFgylT/qz3yVkGu+VIJWwF+Z6kgSU9ueCaWwXxCnwArA8P6w/QTbMUQVyrNI9TXA
         H52A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708041115; x=1708645915;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iJ9UShHTVsU9y+oq7tW5rkAyOQwOBltwQBZQBVnPJpo=;
        b=avNxodbhyWdq9Vi+qp62SFFIcwQJapi4mJl4grYR+HsYbDKCWJ5Ta4AnnNqlA/a8qn
         OUR6cYftyxZdV7ng7qSdP+zm8pqyq3qMN1ryXg7wIHatlz8bwihNoeu+vNJCutwGD9FQ
         tuzl2IiSNsnalRyVTwpD1KEE8nysjZmgH0tufYYA8hn/eKhm3xBgfZ0xocuEas/HAqzT
         eGgN5GRlquhxB8dhYM2WCzKue57r5D3YOZ+dF+huRMqgPwLrsvJcOt7FLj404UN7UYyu
         iAsxNfKVSCw+ARDG5b5B56sq7qq0qA1dWJ6xXl6N04Pz0Oxn/LuTmNM0nASYlm60Wu9T
         x2Mw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXB4kQwPOMgWbUiar5OIy1E5wEXJu4JYZ+Buq7d7QStIfAhdc3SgKye3DpDPo3Iq8iWz/EDcG4QTxnu8iyWbkPw08ElR9+Geg==
X-Gm-Message-State: AOJu0Yz2U+jvEb0t2SpXYGRl62OUFPKAEwmv8d9Jh+gM/rk7z4ArsOCy
	GNCGLOokfbkt7+sM+0vTM6WY9cmtmgA8WSY4ygTXvkaeTtp6ESp/
X-Google-Smtp-Source: AGHT+IHonAfS4yLgG+u7huApB9ik1mtysmkG+vi9l/ELMqWtdFMQNniRSpPM0FhvnjanhU9UDiqaJw==
X-Received: by 2002:a19:ae1a:0:b0:511:62a2:bafe with SMTP id f26-20020a19ae1a000000b0051162a2bafemr2863523lfc.30.1708041115391;
        Thu, 15 Feb 2024 15:51:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b14:b0:511:527e:5f6f with SMTP id
 f20-20020a0565123b1400b00511527e5f6fls122315lfv.2.-pod-prod-04-eu; Thu, 15
 Feb 2024 15:51:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCURoTOzQfGZB53ebc48ayePqiTcqG26RNMQHCy4SddB2SBhtjbJHHRdLE95VmBWg/EN/cvbLSKAwz8g2D6yZ8hMXcGHmYbL4FqY9g==
X-Received: by 2002:a05:651c:606:b0:2d2:6c0:3dcf with SMTP id k6-20020a05651c060600b002d206c03dcfmr2282346lje.19.1708041113288;
        Thu, 15 Feb 2024 15:51:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708041113; cv=none;
        d=google.com; s=arc-20160816;
        b=BXu5mt5korS8C7PG7JfFgJBwb7oc58lKj0BzhJ4s1osY05AtsGxJioPXWvFDl2iEHt
         s9DZApPFu8QFVny40oiF9hvqOFVhu4aGXeEaYwNKPPFRToG7M8WiCB2nt1IbFCGQTkn4
         7EwqIbXcjgIwMaToNptV+348eyirq0u40qP4GjTQ6Ez2pY3VVF0/hHD9sjGKOAqJ/4eW
         HtZn8FeniCv2vQA3rNryXg7ZZRAJ3XJCOsEbwW+77iLywuMn6h3f/v+bCx3ehlGgyiPW
         ZHukzxWRFWlsMg1jykPegs4F6PXZceW+SM2I1yT1XCXkIWBTyqw9CYnTUhpjxviLwkL+
         rokw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=fn06dkJ1+mAaWpggeUdl7NGUJOJXRgTvflxoZrn/p3U=;
        fh=OiwBIvYIPHGDMdlNleqgT10F8L7VFJzUbQ6V59nSWw8=;
        b=OCwpzfDbQh9pIhg6LWE9QPwkrj1hrxVwHBV84h2BfHJIlP7JNVna5tfts0wCHlhxru
         cBL19D1B/CCxtVedGMNsrw4afz2T1tbNrJSXD6VOMeyvr46bRya0F75G9DzS/zhiv0Ff
         /JeQ8SSruTqccIAU1JArTaX1vsskoCxyfZWMsFm8ErWhHU3NuNluZiftw/rUss79NkyZ
         J17dwzG8EmXL+YlmEFGS0gKHGdsKUag7PrygHsNQlHpFMJ/bfU33jTWA9QYxY/JSVHyo
         kY8geu8gHfzYzlEfcP5oledGumaj/n4nbxDgJZ3lsFs79sWSg2ilviLmxFqLLMl6WLlb
         NdWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AX8VvR4l;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b5 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-181.mta1.migadu.com (out-181.mta1.migadu.com. [2001:41d0:203:375::b5])
        by gmr-mx.google.com with ESMTPS id z7-20020a2e8847000000b002d0e0aad823si109733ljj.0.2024.02.15.15.51.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 15:51:53 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b5 as permitted sender) client-ip=2001:41d0:203:375::b5;
Date: Thu, 15 Feb 2024 18:51:41 -0500
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
Message-ID: <jpmlfejxcmxa7vpsuyuzykahr6kz5vjb44ecrzfylw7z4un3g7@ia3judu4xkfp>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240215180742.34470209@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=AX8VvR4l;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::b5 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Feb 15, 2024 at 06:07:42PM -0500, Steven Rostedt wrote:
> On Thu, 15 Feb 2024 15:33:30 -0500
> Kent Overstreet <kent.overstreet@linux.dev> wrote:
> 
> > > Well, I think without __GFP_NOWARN it will cause a warning and thus
> > > recursion into __show_mem(), potentially infinite? Which is of course
> > > trivial to fix, but I'd myself rather sacrifice a bit of memory to get
> > > this potentially very useful output, if I enabled the profiling. The
> > > necessary memory overhead of page_ext and slabobj_ext makes the
> > > printing buffer overhead negligible in comparison?  
> > 
> > __GFP_NOWARN is a good point, we should have that.
> > 
> > But - and correct me if I'm wrong here - doesn't an OOM kick in well
> > before GFP_ATOMIC 4k allocations are failing? I'd expect the system to
> > be well and truly hosed at that point.
> > 
> > If we want this report to be 100% reliable, then yes the preallocated
> > buffer makes sense - but I don't think 100% makes sense here; I think we
> > can accept ~99% and give back that 4k.
> 
> I just compiled v6.8-rc4 vanilla (with a fedora localmodconfig build) and
> saved it off (vmlinux.orig), then I compiled with the following:
> 
> Applied the patches but did not enable anything:	vmlinux.memtag-off
> Enabled MEM_ALLOC_PROFILING:				vmlinux.memtag
> Enabled MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT:		vmlinux.memtag-default-on
> Enabled MEM_ALLOC_PROFILING_DEBUG:			vmlinux.memtag-debug
> 
> And here's what I got:
> 
>    text         data            bss     dec             hex filename
> 29161847        18352730        5619716 53134293        32ac3d5 vmlinux.orig
> 29162286        18382638        5595140 53140064        32ada60 vmlinux.memtag-off		(+5771)
> 29230868        18887662        5275652 53394182        32ebb06 vmlinux.memtag			(+259889)
> 29230746        18887662        5275652 53394060        32eba8c vmlinux.memtag-default-on	(+259767) dropped?
> 29276214        18946374        5177348 53399936        32ed180 vmlinux.memtag-debug		(+265643)
> 
> Just adding the patches increases the size by 5k. But the rest shows an
> increase of 259k, and you are worried about 4k (and possibly less?)???

Most of that is data (505024), not text (68582, or 66k).

The data is mostly the alloc tags themselves (one per allocation
callsite, and you compiled the entire kernel), so that's expected.

Of the text, a lot of that is going to be slowpath stuff - module load
and unload hooks, formatt and printing the output, other assorted bits.

Then there's Allocation and deallocating obj extensions vectors - not
slowpath but not super fast path, not every allocation.

The fastpath instruction count overhead is pretty small
 - actually doing the accounting - the core of slub.c, page_alloc.c,
   percpu.c
 - setting/restoring the alloc tag: this is overhead we add to every
   allocation callsite, so it's the most relevant - but it's just a few
   instructions.

So that's the breakdown. Definitely not zero overhead, but that fixed
memory overhead (and additionally, the percpu counters) is the price we
pay for very low runtime CPU overhead.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/jpmlfejxcmxa7vpsuyuzykahr6kz5vjb44ecrzfylw7z4un3g7%40ia3judu4xkfp.
