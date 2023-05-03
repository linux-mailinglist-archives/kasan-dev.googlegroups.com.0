Return-Path: <kasan-dev+bncBCS2NBWRUIFBBTULZKRAMGQE3ZOZ6JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D37E6F5BAC
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 18:03:27 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-3f19517536esf18470245e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 09:03:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683129807; cv=pass;
        d=google.com; s=arc-20160816;
        b=CguXXFiNfFhrEGRvRaqE4Rsl+Xt7s4qeghursNTxy2H7PwRyk69fQs/pcy3lR3iT/U
         fWuKBR3tKDw/Q9o53L///H3lZcfjmQYS6zGEYcbrTqjHiOsuZB0mn27xrihjKCTUsfyX
         xPiZNvZIOvCCneF05ivTyVtKkG0flHNHg+jjrwoddzYJViJ5OzoGk5W3ZhF0YADdIVrv
         GAOLnTU8LPs8WqRqoL/oVW9RUlJNkVyKr/CUnLAIXCjUChu1yScTqa8YkGHX9NAKNpnT
         4oQ3drqnqyn+0nsXv8BmCby78EPKr4H6yos2ziDEKhBxvLygLUYclH+zCT2CogdB4Wws
         SW5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tvF9mQAKvzeH+2jOn7abVjdemdqiwlFImtfMOEcuS5Q=;
        b=gFAHqFCyEmbIHR7kf+T9SG02aYup4THW7tfaWVVjaoecNX39Qn7aGkVUTIQnikbt9S
         HtaCXI+kS2IJskusnMHFve6DHvexT2IkYagHZLU71xbi59aMrJvxDKdLLlJ3NY1Fle1y
         Z5Iy73/TgMSAeOsstVrKEQJozb/Exks22QlrbYJx3iQPW3fcAyrYekfkhrncEPYFAwu0
         70rzeIf4RCMgeolAz02d0yCta7aBWJ8N0eyBlcvihNGx7WuDd3KApaWsz7big/EXRz2Q
         TDgPKw0jmkgJz1W1NlRta0zkfc13VtMITH17Ad85cmFXZ8NtF59DE9d8e/E6rfIrWkSA
         FiuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FpGctQbM;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::a as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683129807; x=1685721807;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tvF9mQAKvzeH+2jOn7abVjdemdqiwlFImtfMOEcuS5Q=;
        b=cr4Nlh0L01xru/VFicaaG5a/kez/vYDWDONvuzp/juBuAdKkdtSU52TndbwD3vDl3a
         jVjCtXD51rAt3f0Z9lC+KWyawCmSEMVS40kHI8oi8Fza6mjo45x49DAexYVahdGGQreY
         1EFNGOCjyj7Vu7La5v3cUL+jnrnVUatlN7tOg7yyNElO8P2gip9kQ5q/wd6zq1PEMuMU
         Zj0OPQdQkocwnaCw0OwweO5pggII5ggSOzJ2wmu9QsX2fcYo5tByB+4x438PDEA0W8u5
         OTWAVvgnfttcncJJbRwQE0h4hxbZYdvfhQGICR2IOnKZ0GK76T/Nbx94A7Aaq8Qfy+MC
         LJMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683129807; x=1685721807;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tvF9mQAKvzeH+2jOn7abVjdemdqiwlFImtfMOEcuS5Q=;
        b=C9vDWmnaoVjuBXgMv2doJL+/P75HoDdGDLDXMEkka4sf3XZKFEUsD2CM9iNIC3hGIu
         pOXGKSo/Enuq2yoWKsCbZSFfeNQOiztMTjLkr0HugEiqHnU2SJ3SBBahqvxn0LleFgWJ
         YNzN62rhu8AbNpKpmW0twF8VlvjnJxT0mwdpBMODFeHFQNQSKtSCgJc1lTCRU+Lgqmy6
         eAUuDMPQmVaFhsuU8Y/+IyFcHJbG6n0Knk00iAP+qPRlzNIDN65L98XX8AUhM+SYamEh
         JR7FrGf9I8PEg6hSi3E+drLrvQufSgowZ8n/ds76KWMYyO90BLDDNBvaUZDkhRIwoYfk
         fB9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyZDNe2M3P6OE8JZCUY/cpIv86jAt1m1YaJQoxsSYQ0m2sbAAdd
	Kv3+MuyX94uRoyHT6vPqJYhS7A==
X-Google-Smtp-Source: ACHHUZ7nvm+Uejn5DFc8Axg6cui+brpyM+gv3bNpb7CIH856TlrJoeAnPka1qsVSx5urh03pR5lWUg==
X-Received: by 2002:a1c:7905:0:b0:3f1:6830:9f1e with SMTP id l5-20020a1c7905000000b003f168309f1emr3736785wme.2.1683129806856;
        Wed, 03 May 2023 09:03:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5a18:0:b0:306:35d:2f11 with SMTP id bq24-20020a5d5a18000000b00306035d2f11ls520720wrb.2.-pod-prod-gmail;
 Wed, 03 May 2023 09:03:23 -0700 (PDT)
X-Received: by 2002:adf:e7ca:0:b0:2cd:bc79:5444 with SMTP id e10-20020adfe7ca000000b002cdbc795444mr500157wrn.2.1683129803741;
        Wed, 03 May 2023 09:03:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683129803; cv=none;
        d=google.com; s=arc-20160816;
        b=CyWqkIjuwpooKKhi1KW/zdJTYkBHQkKNen2nSBKJO70DH8qEz3zUYIBK2O68ZGE6oC
         UNLwpIW0ntUr5wa6jucVWpqmawsPnYingHIz/DTkjw9APAL6fgxCBWcH9QMFOIjGTTh5
         5h+81BjKELlmCmks/x3PiM8/bK2+DDVro/m7v7V4U88A4kZTDtH2lL1DWEWyKqP9lsTT
         30xqWPGBuRvb+UJjuBsQz5DnHMHiwN7T08Mc+5/iFoC+rzDo8pzqKrdqxuWwyUkCY5vs
         8Y9nOJPboVL4VXn1uMf4q+thnOj6L7+M0dTi74hXweCtBubwyxKGJqhwwhGrk5m+FPoB
         BrWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=MZ0TWwv0Mpu9IjWcxRCWjJEEQ++kpZPmKK/VcTJkl7k=;
        b=krDUjcYUETAe7I8BTJQdwrC4G2JZ8xrd089TwSCFn8PpqvbGpJ2zhQUk8dFfwr0BZS
         UrJRQOwDDGURhIwOu1Nuaou1bpe28TdsFpTHxvNM6lkHYx6lDJeDHdHoppQJgBTJf+p/
         lDxWTbAZPb0sJ804PWcIhFSXTbMTEcSWgZSA0nrfvAFzkecAMy7DiYvWXxT/hV77thiW
         2ynNASK3ssvMF8iJ2XswyoxbrmvF/ADBaJXz+82ZJZGmhqycINeA3sKn+WHp2GaVIYoA
         6WDW0rSH4rJxUdGVkFRzHAukswUkDVbyRUfl5Z/132TSiMm+3IvYUaYBvE5JIuFHwFje
         6sIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FpGctQbM;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::a as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-10.mta0.migadu.com (out-10.mta0.migadu.com. [2001:41d0:1004:224b::a])
        by gmr-mx.google.com with ESMTPS id b7-20020a05600003c700b003062fa1b7a0si478841wrg.2.2023.05.03.09.03.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 09:03:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::a as permitted sender) client-ip=2001:41d0:1004:224b::a;
Date: Wed, 3 May 2023 12:03:11 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Lorenzo Stoakes <lstoakes@gmail.com>
Cc: James Bottomley <James.Bottomley@hansenpartnership.com>,
	Petr =?utf-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>,
	Michal Hocko <mhocko@suse.com>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFKFv6F3pRtnAWSS@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <20230503115051.30b8a97f@meshulam.tesarici.cz>
 <ZFIv+30UH7+ySCZr@moria.home.lan>
 <25a1ea786712df5111d7d1db42490624ac63651e.camel@HansenPartnership.com>
 <ZFJ9hlQ3ZIU1XYCY@moria.home.lan>
 <f57b77b0-74da-41a3-a3bc-969ded4e0410@lucifer.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f57b77b0-74da-41a3-a3bc-969ded4e0410@lucifer.local>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=FpGctQbM;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::a as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, May 03, 2023 at 04:37:36PM +0100, Lorenzo Stoakes wrote:
> As an outside observer, I can assure you that absolutely came across as a
> personal attack, and the precise kind that puts people off from
> contributing. I should know as a hobbyist contributor myself.
> 
> > If I was mistaken I do apologize, but lately I've run across quite a lot
> > of people offering review feedback to patches I post that turn out to
> > have 0 or 10 patches in the kernel, and - to be blunt - a pattern of
> > offering feedback in strong language with a presumption of experience
> > that takes a lot to respond to adequately on a technical basis.
> >
> 
> I, who may very well not merit being considered a contributor of
> significant merit in your view, have had such 'drive-by' commentary on some
> of my patches by precisely this type of person, and at no time felt the
> need to question whether they were a true Scotsman or not. It's simply not
> productive.
> 
> > I don't think a suggestion to spend a bit more time reading code instead
> > of speculating is out of order! We could all, put more effort into how
> > we offer review feedback.
> 
> It's the means by which you say it that counts for everything. If you feel
> the technical comments might not be merited on a deeper level, perhaps ask
> a broader question, or even don't respond at all? There are other means
> available.
> 
> It's remarkable the impact comments like the one you made can have on
> contributors, certainly those of us who are not maintainers and are
> naturally plagued with imposter syndrome, so I would ask you on a human
> level to try to be a little more considerate.
> 
> By all means address technical issues as robustly as you feel appropriate,
> that is after all the purpose of code review, but just take a step back and
> perhaps find the 'cuddlier' side of yourself when not addressing technical
> things :)

Thanks for your reply, it's level headed and appreciated.

But I personally value directness, and I see quite a few people in this
thread going all out on the tone policing - but look, without the
directness the confusion (that Petr is not actually a new contributor)
never would've been cleared up.

Food for thought, perhaps?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFKFv6F3pRtnAWSS%40moria.home.lan.
