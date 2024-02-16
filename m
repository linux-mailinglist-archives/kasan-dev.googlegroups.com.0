Return-Path: <kasan-dev+bncBCS2NBWRUIFBBYHPXKXAMGQEO5EP6AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id F137785734F
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 02:18:24 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-40d62d3ae0csf8127865e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 17:18:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708046304; cv=pass;
        d=google.com; s=arc-20160816;
        b=V+KIg33OVZeEbzDJQXUpJD1ugLxEjizo8+DESqieBwbWFQyzeIRaH6mZbcjJolxo4v
         e8XxYwx6ABRTCCkAGpZzj3wIeCpqkyj1Y9yzO9UmhsNL0dME6aV4YLAbr7WWi7Ozypwh
         Z6xBZvYXOEVN0LFZ34NAYfz2jESpcaylJRTmKfSZUf5oAhWwkSpu4zf1Jc07XVl4TACg
         NnfVnMqjNJttOwKgv5pfOlJpCvHqeCnZtw5rFaQJTadruepihtzYpTIz5S7Z2Llyj1iw
         8nSDKYwA1Vs2DOwZMtYCn+UtKssa60mFgUXTWI0KwO22yPxkhCK7MFZaPew1Y4BCwl0m
         XJBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Nu3yyJv5t/zk9uBBwFUccQsJOqeabf/1PvGGSl3f0d0=;
        fh=BlbxRjoT9zGntszW+aCGYP3xksHhglojaxEOBxypP0A=;
        b=si1h7ywON0rUYpbq6SnsNCu4r97PzkOzOAr4mT2ztinNeM84c5J3EAqb2sqc+tyKWH
         X7UUbsgg+kmgEHNSm3Lh/AFMA/XetN1im+Gjqg5rHFKyNvq2QqC2LIiTEAG4bxDk8gzk
         0XYdhbsgBjOJ6SsGotSIYL69Tt3Rz3PpjoCBKOcFktkf2aiBEl6U1fcaxWhMReOYRk3R
         7xtpdbbH7l7K703W65Ptjqw+/c+vBDk9yQT3crInWrGVlwSDH/AYeOEwFANXc5+jbArb
         YPboq7yTcaV1/ZrZQ9PY/aC9/qnv2zHrkAmigB85yesYN2OCA+wN8Ifup1Y1S/2iR0Dj
         zc4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VvLy9G9e;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708046304; x=1708651104; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Nu3yyJv5t/zk9uBBwFUccQsJOqeabf/1PvGGSl3f0d0=;
        b=TsqwUxghL33zkk7FF4rQBM5qcWUsgCJILp25O1cfoz22rzI26U+F5PA5Gr3IewGkBg
         1N/wixXVu1s5DV/YakfQf1QB7WGizyI6kSu7DCxICCfABl6BreHKTflbLt8VMuBqVAsC
         t25cxXQHX/avQpbpIlVtqgKs5kFVBvH1/oiDcjTQgr8fFYrYOB2w/+apZAdOpd+NpUN/
         8H+JxrU1rGS9jVzGtb12anh8GTcCa9cZLqQ+HWGEh/5K/k6fdwcvwJY9extnLUVeu4me
         Wsyhp7uMyMxDyEhCZ7sEMUbe817hVJmXgjMalaczTfzA3tm4MY3mBvmOzIAkp+PhabjJ
         fH9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708046304; x=1708651104;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Nu3yyJv5t/zk9uBBwFUccQsJOqeabf/1PvGGSl3f0d0=;
        b=o/+e9rSNch1QPAsdvOIFGeJmW3MLmg/mLU+i4P2W437nX/22Dxbz1jqE9/KfjtSijG
         mKTZTnXg+gWCWz4V006ys88dVEJQpichF+gotj6rzq5gZKoMvEiDzYoZnq1s9sVBRDkQ
         KiD8zNVxynpQv7K8+WIeMharVBHlT22HGajjGcD4ftOgZLqol2P853mcr9CXjiKnTG5l
         g7af1VCOwe0aASO9oDSC+rFsS4t52VE3Q+pKd/gINQc2G+yZn0lmnjBy3AW+FP72GYei
         F37Jg0MjCtqhDrmEXfdr8mvtRxG7AadCk7LQBILchZK+e4fXpzdK8dcUXAFl8Do+YydE
         3BrQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1PyReLribx5zBERw+do0M1RG69scW2wL3+VPVCxEAiEDvgQEt3iE+5Lr6Nbed7ANevlUfPXrA38X3PO8DliyWI7DBj2aLyg==
X-Gm-Message-State: AOJu0Yw8yJn99FXC2bUhvZz71i5+rTRS1rN2Ji4/GSdP2k++zyp0lY0V
	WHUK4H3aNFxdTj9GdjJAIMAdVyikIkTWqnPWbso/GoUiLTuNsACu
X-Google-Smtp-Source: AGHT+IFKIvTYk8LLX7WQXdfi3O5S70QpdBAHJnvnkYKQBdo4bDfui/f2TcTLLtcAsQ1PKprcIZzlqQ==
X-Received: by 2002:a05:600c:1d16:b0:40f:fe1a:6baf with SMTP id l22-20020a05600c1d1600b0040ffe1a6bafmr2375385wms.1.1708046304251;
        Thu, 15 Feb 2024 17:18:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58d5:0:b0:33d:1369:6b4e with SMTP id o21-20020a5d58d5000000b0033d13696b4els79142wrf.2.-pod-prod-05-eu;
 Thu, 15 Feb 2024 17:18:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVsDwshc4Q6Xcl4BZ2PYIzdG9e4N0CI5QktuHZDgbh1W3DnInRCXtGbSl4NfAU+xiBlisRG3837uRlkeew0AAwYlChelDxWGWp+KA==
X-Received: by 2002:adf:e851:0:b0:33b:8782:b526 with SMTP id d17-20020adfe851000000b0033b8782b526mr2305267wrn.59.1708046302580;
        Thu, 15 Feb 2024 17:18:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708046302; cv=none;
        d=google.com; s=arc-20160816;
        b=stMcpiXpHTWCdw3nTffyJn3zuYgP21/ZvVKAEkKld3dOA+mm5zT1ZjYj4FK9CabyQr
         e4TJ7Fpnu7LY7MCiOQM1vwUpIye0iGjzV8nLaBG5PKTHAHRNNYyoHQHFPdab6ZCjA56K
         PfKOU/xb9rrxIDG+xvg/CSaY6bThtwRjw/6FUE6ZxlYW3GNST5ShsAa8qyKP3khC+ETq
         RtdEhB7oYdg2qU3ODuBW0KZ1pC5/EORnz+2qKlpWfMs334//YQ1asxJ27if7DyXQyK/o
         Gt/VGEUN19MfeJJARe4K90qG3Ge1cXi/QpMd7hSgYZ/IPYinRUaq0UAgLFuKfKPHnJhK
         Ddkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=bAMs9Q6+KFAg+NYYq7o0yZrwECRUxYPjpxPWeQP60LM=;
        fh=OiwBIvYIPHGDMdlNleqgT10F8L7VFJzUbQ6V59nSWw8=;
        b=UW9dzjf24eop9uS6wUTyYboi8pOa2iy2zKHFjXD42s6kSvU97wpWJc9kJ/Kn+CFc1t
         2uEvXpTlatpHJ7pP5tawvflyvJebjabzPuFodt8Y/FRtos8TUaHmGw1uoNCBJr7bM4CM
         B+mXCwPe1qTjPGBbKjl7Ckj4AhyfJEGyeeomFiVEROjpFRGNakY3bSc6XqTxEFNwHX+n
         CqVLWFRIpwEOH5BC+JXjqXEORnPlnjjLOgjOeUZIlQkEDNgEfaIa+545WeXtAoTcYBqX
         sc8JAvBeYcyZUOadQOqgGfjAerdzLi5q0ZekHKhh9XWOK20yBrLU7TU6qBoh07EbzMQp
         fLNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VvLy9G9e;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta0.migadu.com (out-171.mta0.migadu.com. [91.218.175.171])
        by gmr-mx.google.com with ESMTPS id q20-20020a056000137400b0033ce5c2f670si24892wrz.4.2024.02.15.17.18.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 17:18:22 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.171 as permitted sender) client-ip=91.218.175.171;
Date: Thu, 15 Feb 2024 20:18:06 -0500
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
Message-ID: <wcvio3ad2yfsmqs3ogfau4uiz5dqc6aw6ttfnvocub7ebb2ziw@streccxstkmf>
References: <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
 <jpmlfejxcmxa7vpsuyuzykahr6kz5vjb44ecrzfylw7z4un3g7@ia3judu4xkfp>
 <20240215192141.03421b85@gandalf.local.home>
 <uhagqnpumyyqsnf4qj3fxm62i6la47yknuj4ngp6vfi7hqcwsy@lm46eypwe2lp>
 <20240215193915.2d457718@gandalf.local.home>
 <a3ha7fchkeugpthmatm5lw7chg6zxkapyimn3qio3pkoipg4tc@3j6xfdfoustw>
 <20240215201239.30ea2ca8@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240215201239.30ea2ca8@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VvLy9G9e;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.171 as
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

On Thu, Feb 15, 2024 at 08:12:39PM -0500, Steven Rostedt wrote:
> On Thu, 15 Feb 2024 19:50:24 -0500
> Kent Overstreet <kent.overstreet@linux.dev> wrote:
> 
> > > All nice, but where are the benchmarks? This looks like it will have an
> > > affect on cache and you can talk all you want about how it will not be an
> > > issue, but without real world benchmarks, it's meaningless. Numbers talk.  
> > 
> > Steve, you're being demanding. We provided sufficient benchmarks to show
> > the overhead is low enough for production, and then I gave you a
> > detailed breakdown of where our overhead is and where it'll show up. I
> > think that's reasonable.
> 
> It's not unreasonable or demanding to ask for benchmarks. You showed only
> micro-benchmarks that do not show how cache misses may affect the system.
> Honestly, it sounds like you did run other benchmarks and didn't like the
> results and are fighting to not have to produce them. Really, how hard is
> it? There's lots of benchmarks you can run, like hackbench, stress-ng,
> dbench. Why is this so difficult for you?

Woah, this is verging into paranoid conspiracy territory.

No, we haven't done other benchmarks, and if we had we'd be sharing
them. And if I had more time to spend on performance of this patchset
that's not where I'd be spending it; the next thing I'd be looking at
would be assembly output of the hooking code and seeing if I could shave
that down.

But I already put a ton of work into shaving cycles on this patchset,
I'm happy with the results, and I have other responsibilities and other
things I need to be working on.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/wcvio3ad2yfsmqs3ogfau4uiz5dqc6aw6ttfnvocub7ebb2ziw%40streccxstkmf.
