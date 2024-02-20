Return-Path: <kasan-dev+bncBCS2NBWRUIFBBB562OXAMGQED4ATB4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C907E85C25E
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 18:19:04 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-4121c06be80sf30233605e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 09:19:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708449544; cv=pass;
        d=google.com; s=arc-20160816;
        b=WuA6j8CfKkgvxNl8CnS/Y5tHUK3HdcWKoXy2RVkBk8qjBOrFFgi1MXl2OGa5LyvL8A
         nzfsRA9/vEPcD1j/cnt2JW+Kdy30kW26zCzZhYH/Wh2SrzuaQhrzTNOpUoAMV0kYSz8C
         3y3a5kMHUiw4dSRCTcB0He5iiY0NGoXbXNeO9Z/amea7C3MahbdrS2ixHHHH18VELr84
         S71qNrYOrptwFpxd9Anc9dWWlUtbjzhox/BADTICxU4gbMJOTtzjj/tYybFC20050/oN
         2OLyJ/8kift7hjkjRuxsAFwvaSUP2SP0sbj2OfxRaZEMUIvVorEQimcmZ56rQ1bRopbU
         784Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=DAXBGkvJH1vTLBk641DmJPYAyC/8MUkUxSW02UPNF8g=;
        fh=1gARf+2VpSuAitFdQiVcnJeOP/I2LhzptNUV4s+iEBc=;
        b=ZTdx+4NjvvxPSIvhrXRsefttJp2qkfM+HlpboSXTrHvrZ1GGdA9+z1hYWALfjjHKnh
         3t7/SzVz9rJrdrFOhxGbWzrqu5Ub61njCinzSyZL7V/NKGYE5tdiT+7BxP1UAwzrTf2M
         nXyTZJzd6sfkgf+5qFL+9nVfxLa4HJRTZNVY1GVFRvBRdc3YT1jf/m+6QewWilOwKPWm
         iilDtRcca52wpWwANJs7IzyZ9kAO76kuyakNid1jY60SuSIjq9sVtiobsbBcwQbN2MaV
         B2atmoelGHSjBKZ5IlhMd+xW5lmwhh20wgYOqoQqM0hA460UWnHOh7ijITNj1PXFgOVK
         IjNw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZylNuoqF;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b7 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708449544; x=1709054344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DAXBGkvJH1vTLBk641DmJPYAyC/8MUkUxSW02UPNF8g=;
        b=EOv9E/KdrPXNKT8tbhbOH4Kd0ZfzPBHn6IYnRpucKEO5TCvTZqtxgSc+TNe02d3KBf
         hYNvEzA45MqDla5XgqT7QWpHXH5PLd8i/g522yJpjoaLTecR6XsKn47aF2puoZY8PV9f
         kgcJbqI4ZDhW1LVVkG4NDhy+lHkZr8lbB3ZEKi2tC0MaaC4Pf0QAvOL2cd+aVLe4KUm5
         lF6IGG9wFcVyp9V3xxuvdScLdofygC/LODqexX/TOscvP43NrfD1fiQt2RJeRRoktvK8
         p/AJZeowFtISjUzmQSRrv56MmesXwV6N2R5iJShhm3At8LDVch8e6gmVbX0k25pfrP+k
         wMgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708449544; x=1709054344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DAXBGkvJH1vTLBk641DmJPYAyC/8MUkUxSW02UPNF8g=;
        b=oyhrb4jzpWh6xcoisMH06tYXKegWWRRwOj7He7Ym1/B9WpFnXugD1+J8ioZhTc29Zz
         XcMc2qHHTJvyzYC8/NMJrj1PYDppIV36t2rcLe5jnSFyg5mw7l7y5wigMsh7H8SktcfP
         00+a7qpNXzzsEepTzfHD1xWoLLTpMRR51gVq6sjZECHByA3ijsH1XwWiU9xZyp63W/1z
         hXNHmQ3sFJm0SMy8YacFeTdnVe8pj2zZeUPW0TVKEYXyxUoPdctQO9y7HLp70LeF9l28
         Ba32oCxg9noe+DoE0Pg3VVK7JmbX34EH9LRr5S/YardLrvJS6m9GJk1eC1n6FIFX/pP5
         6mCA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXAN/iS9wvUKsUWj3yBD4FFuhbDymfAnUPyCdXP6F3mf9m0V666s2r8a/pLmmEr+ahnDxO0I1SsW5Sk46I3sSIM37x4Iv9hBg==
X-Gm-Message-State: AOJu0YzGZPlT1g04y6z3GqAYadAzjy9KMva3ETs2OAcYjpWDo06scJ+a
	Ga5o6cYdjA72ExJAUuUtcUwJCPl2n9tJTi63N+ypd7BVe1Yiar8P
X-Google-Smtp-Source: AGHT+IF9IU61OgD/SzRevAGxDbiuDR8zniukMSy+JsQwbEG2PJeFL3oeMJRtp8zMTJSmnC1qtBpNEA==
X-Received: by 2002:a05:600c:4683:b0:40f:e3e0:181c with SMTP id p3-20020a05600c468300b0040fe3e0181cmr11197321wmo.17.1708449543922;
        Tue, 20 Feb 2024 09:19:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e11:b0:412:6e4f:afad with SMTP id
 ay17-20020a05600c1e1100b004126e4fafadls453772wmb.0.-pod-prod-08-eu; Tue, 20
 Feb 2024 09:19:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVDZqDtG5mqolJDuNhOkUJTw8dB8tcXCsXc6O0XtAhREP0FaWKemXXYChiJqkWEu92BpOmC0niN8ldcHAABaJ90wXMXOxtD9GigQg==
X-Received: by 2002:a05:600c:3b19:b0:412:704b:5faa with SMTP id m25-20020a05600c3b1900b00412704b5faamr1381500wms.31.1708449542315;
        Tue, 20 Feb 2024 09:19:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708449542; cv=none;
        d=google.com; s=arc-20160816;
        b=UWwkE6XdQQp+YEy8VkB767ipIeTJgGMG7vYaQwwdlgJ/kPzX+ABhsT7d8JM6nUNOgN
         l1JdHxviFmpzctKnUq847Q4aWkJkT0VKQ8OXsBQljwrcIREk5uNOgpgU2q2ddn3pZ2sE
         xCUHkX2CJVkSgr2xHYE14y6bF4B2GhmKjcfneXwLyXfPUUVWtr8udCaTZKb6zT7yWtI8
         ALSAMbrmkAMGqur81tX8iuL0D9nHo0xG6TD6nPAw53a1614q/HfZrEaMRi+SHtEre2xC
         VW7iS30e4KHjMZNdDKpBT5/8C0cQ6atgzsft7F2SpuSNOUOuj0IvX2fymJ9wfRpBiuyb
         fjFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=TFBMvCwRxxn7Ubei4id/yHwyn/BDb0WjYtVEnoOd25s=;
        fh=cdnrFe24HzwWdEILUfE8iAnKpZWbuzZYUVYziuBEAhI=;
        b=hn0JOn39xfL0zCRjEi/IinCcfoRigoaEcq8BiFqgLUCavIFkXuoMPOkRSgCA/sLt8D
         OzAB63x5cRA5ec2gBaITDrmRXT1CVaTzd0eylOnLEVgqLRYUTzkz2mBsQyxtXf5Cun//
         8OcUwLCkfWkrVVh1jHzdxhFvGOjDf4Xq3CW1Vq+W1u2O3af7N+9dpHkBSUF1HALMKcML
         Y1FzWe4A75tvbei/b/4/SEiksqPpdginu9yOugCKkegIuiz6UcABh5qsKet2sTzx7T5I
         392GmToA2lk3HEdiG62ndMtl2rURzFA8Jf6V7gJCHnNV0H2vDtnMqdRn3mASxzAqyEni
         4DLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZylNuoqF;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b7 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-183.mta0.migadu.com (out-183.mta0.migadu.com. [2001:41d0:1004:224b::b7])
        by gmr-mx.google.com with ESMTPS id p4-20020a05600c1d8400b00411e6461fa7si7260wms.1.2024.02.20.09.19.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 09:19:02 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b7 as permitted sender) client-ip=2001:41d0:1004:224b::b7;
Date: Tue, 20 Feb 2024 12:18:49 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Suren Baghdasaryan <surenb@google.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org, 
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
Message-ID: <qnpkravlw4d5zic4djpku6ffghargekkohsolrnus3bvwipa7g@lfbucg3r4zbz>
References: <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
 <20240215181648.67170ed5@gandalf.local.home>
 <20240215182729.659f3f1c@gandalf.local.home>
 <mi5zw42r6c2yfg7fr2pfhfff6hudwizybwydosmdiwsml7vqna@a5iu6ksb2ltk>
 <CAJuCfpEARb8t8pc8WVZYB=yPk6G_kYGmJTMOdgiMHaYYKW3fUA@mail.gmail.com>
 <ZdTSAWwNng9rmKtg@tiehlicka>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZdTSAWwNng9rmKtg@tiehlicka>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZylNuoqF;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::b7 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Tue, Feb 20, 2024 at 05:23:29PM +0100, Michal Hocko wrote:
> On Mon 19-02-24 09:17:36, Suren Baghdasaryan wrote:
> [...]
> > For now I think with Vlastimil's __GFP_NOWARN suggestion the code
> > becomes safe and the only risk is to lose this report. If we get cases
> > with reports missing this data, we can easily change to reserved
> > memory.
> 
> This is not just about missing part of the oom report. This is annoying
> but not earth shattering. Eating into very small reserves (that might be
> the only usable memory while the system is struggling in OOM situation)
> could cause functional problems that would be non trivial to test for.
> All that for debugging purposes is just lame. If you want to reuse the code
> for a different purpose then abstract it and allocate the buffer when you
> can afford that and use preallocated on when in OOM situation.
> 
> We have always went extra mile to avoid potentially disruptive
> operations from the oom handling code and I do not see any good reason
> to diverge from that principle.

Michal, I gave you the logic between dedicated reserves and system
reserves. Please stop repeating these vague what-ifs.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/qnpkravlw4d5zic4djpku6ffghargekkohsolrnus3bvwipa7g%40lfbucg3r4zbz.
