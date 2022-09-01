Return-Path: <kasan-dev+bncBAABBPP7YSMAMGQEXJCMQSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 342D25AA3B0
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 01:26:59 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id h6-20020ac24d26000000b0049462d32f45sf91522lfk.4
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 16:26:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662074813; cv=pass;
        d=google.com; s=arc-20160816;
        b=oD4ofKSwAfX8uyIJFLp1T2s9Fgxq0DyP1Hxk7WfbXHzTslXqLhNT98nsXOAK6xQ8Aq
         Hgzz63FA5ztmD8aJMD2F3Q7+JpxHB4IJns1OL7f7+UuQh7cR0FQu6sz8JOU1sxsFGKrs
         KGTaXIJItv3J+BDA9ZHeOGRx+1K66qUPFR+2j05T9cXjusshvY00sS4ub7r2zeiN1Ott
         B6sQuXqkor5ndklLrt473XEWq/SnmIdcxaxO3ZOkWjBokAJSCNKbVX3A00Vt4AILA8Hh
         8WZZjFsG18E62ZvwrkWXVOyXNDgHVmtbNGdPL0DDNZnx7MIXizpiSxXwgNgH6w7YrDuM
         aHzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QzzF7TcVWHH2qnoyDaXyWVruw+AOJz5IkgX4t/zSRcc=;
        b=bZ4nTBBNPtS9d88/x4KEIV/xynhlPwn6RU0RPGm39RBPp+tgVDw/HrDVvArtJQfB3G
         NXf0oYpJlz4LQszIvfIIE7bCpYBhlOFXBTo6VMERYv7Ehk+errHcZSJEd2ij5lz4t4ST
         DPMEbVswyFKCV0w2nB2bfx+QtaP/ZKbam34NT/PWRdu4qnCExBuefCeBuOw6icNxA0lp
         r4BZCXER1FW4l02cXshpP9qRZBBT7Pg9tRXCXJZ0J3i43v2+LE9zmBqKoPL/65D/STyS
         9wTX8mmJN8rU8lHaoBiwIIzo4rw7z7ojd0y0+xm112cvwNbMo9HlI5n24wKsIJw5lxOR
         aZTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=J6csj5dy;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=QzzF7TcVWHH2qnoyDaXyWVruw+AOJz5IkgX4t/zSRcc=;
        b=azfxB90Ts59hlYYY+QdN5otbOcrlVIT4nbxuPaAvgpaBAZVdGWP2VQb8ZSB2KmMjtd
         opa7BfgAq8rHHzkti5FJ+q0Tqp/LfNnjlm0LhrFGIirggbwRfnvVKg7RIvooHkLnLIcQ
         AZ3nl1/q8PGuuLw/E/x5FC6e0CrjN2szFn+QDqcTEybCzTKsjU+a8RexseOL515WfDKt
         Ygg2OhojOcqcUaTdAUJ0REscUOH3u/8EmDDttj/eVQW3LyiyZiv3ddzucyVNsZDaSFKX
         katvFmyubNEGMOGVI02OuiiwXc/yFACmELkbM+/HDaRVQorYHchC50N5eDjcKrR2SKz3
         LCAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=QzzF7TcVWHH2qnoyDaXyWVruw+AOJz5IkgX4t/zSRcc=;
        b=jIqyfgAVbZ+HjiHoRu0LcnnPiXUkroshVORMaRCA8OpDyfneTZB/GpiT/+oPiXJ7dl
         X0ew4/qf0Wf9YShkEZuZqaXqIcxraI/W+BBMAATpyvm2XWUUHVSa9yz2ZTDOPHql0doY
         9BkUpuFqi0EsVV/k5xr8tAe5iUdG0hk+FdplsouzdpM3cO4BVocHmDQhPCu5aPYjGxGM
         2+mGbr6A/Tjtx4rgUg8iUoLPhDvMIcx1SziS5IrSFUKEk3TMPyrVSB0/pqEC8lwIjmTs
         5eCDnpLv1GGUBLeqX1SpvHK8c6kdS75ggP8fdiHQGYyp9efVHhGxpIMJtRPsDLNBNAY6
         Yu6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2gwpat/6/9DeyT0dvlXgN5/anD3j/6rf/8ceQGvbzQyBQBVrt6
	19hw1R9zSl3B0IIPQU31vPI=
X-Google-Smtp-Source: AA6agR75gjbGWJDZ/WNL8/fJWjcCP3uKHfYsCgJ1tuI2jkiKa2Xx00GzdJNeRhyL4+XLVAiaAuf7bA==
X-Received: by 2002:a2e:92cf:0:b0:25d:d87b:1af6 with SMTP id k15-20020a2e92cf000000b0025dd87b1af6mr10420405ljh.474.1662074813511;
        Thu, 01 Sep 2022 16:26:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:880c:0:b0:25e:7450:b825 with SMTP id x12-20020a2e880c000000b0025e7450b825ls554379ljh.5.-pod-prod-gmail;
 Thu, 01 Sep 2022 16:26:52 -0700 (PDT)
X-Received: by 2002:a05:651c:1196:b0:268:cd9e:7bbc with SMTP id w22-20020a05651c119600b00268cd9e7bbcmr1068316ljo.271.1662074812611;
        Thu, 01 Sep 2022 16:26:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662074812; cv=none;
        d=google.com; s=arc-20160816;
        b=TckM7bzSIWYnFBOMKlEKRJuzXxXf1G8YisLqsoi9russIs71Cn+CZoMMrn6zB9GmvE
         aOPmx4Ir3dz5r6f8o1e0nT5fyThHMYxMxtj0vTUbEnbId+1TKXPdd5dyMf7nb/7JuW7m
         rs5fQr01/5pNnOgS2rndwDl2Ll0TovIKJO04Yeid+FwVfLDyoZw3o84UeTJ1fzvKpUoC
         hw6Fya7rJOHmgsG059Q8vtuG5hegxx17WFzUN9U+Sm3Kj+YPE8gNwfTZa2UFlfoIVLI1
         ckrIc6X1Io/D2PEzMX2dwKZf8DNPVPA968HRzAnJrtAS8F+XMvj6BvOQ/D4Wt062uAdv
         9+WQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=ziQwyv6CBY5n7ARW4qu86GPnvQN6geI/tFyfrLXQmYY=;
        b=VF6wEdzlY7oQAQjfFkwSZqDCsAVHrAWjUb4WFDbJPLO9Vqv/BPiIU79tLBXYd8Kcz9
         ZW7BrkNuSKvSP2IaRgk3RIW+Kr70JRFYS3prfTTWtk/3bLDJ9LIP2Zf8J/VjTCGWZDHg
         gpwMnxdHP8D7+SRw6IEuivCjNLXVKN43mnoAzgNWk1CwBfDHhVBT4xjGD9b9k8f2lF6h
         WYvBOi06Uqpq3I2NeG6O9Fj5T5RgZv/TbTF2guHSb7VslmQK4ymdumWSWPTfNQk+ZRNk
         yyQZGYzgcwPIbtZS+lnxWMGz+L28yA6S4ErI6GIzI57aQ9lzw1rnw4YJ6z6O3GkEmBH6
         +lag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=J6csj5dy;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id s3-20020a056512202300b0049469c093b9si15469lfs.5.2022.09.01.16.26.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 16:26:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
Date: Thu, 1 Sep 2022 19:26:45 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Joe Perches <joe@perches.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
	changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 28/30] Improved symbolic error names
Message-ID: <20220901232645.4dogffr26oisd7p5@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-29-surenb@google.com>
 <c3a6e2d86724efd3ac4b94ca1975e23ddb26cc6f.camel@perches.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c3a6e2d86724efd3ac4b94ca1975e23ddb26cc6f.camel@perches.com>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=J6csj5dy;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as
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

On Thu, Sep 01, 2022 at 04:19:35PM -0700, Joe Perches wrote:
> On Tue, 2022-08-30 at 14:49 -0700, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> > 
> > This patch adds per-error-site error codes, with error strings that
> > include their file and line number.
> > 
> > To use, change code that returns an error, e.g.
> >     return -ENOMEM;
> > to
> >     return -ERR(ENOMEM);
> > 
> > Then, errname() will return a string that includes the file and line
> > number of the ERR() call, for example
> >     printk("Got error %s!\n", errname(err));
> > will result in
> >     Got error ENOMEM at foo.c:1234
> 
> Why? Something wrong with just using %pe ?
> 
> 	printk("Got error %pe at %s:%d!\n", ERR_PTR(err), __FILE__, __LINE__);
> 
> Likely __FILE__ and __LINE__ aren't particularly useful.

That doesn't do what this patchset does. If it only did that, it wouldn't make
much sense, would it? :)

With this patchset,
     printk("Got error %pe!\n", ptr);

prints out a file and line number, but it's _not_ the file/line number of the
printk statement - it's the file/line number where the error originated!

:)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901232645.4dogffr26oisd7p5%40moria.home.lan.
