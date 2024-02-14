Return-Path: <kasan-dev+bncBCS2NBWRUIFBBHWPWOXAMGQETQEGACI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 07702854DE5
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 17:17:36 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2d0fba43533sf29036161fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 08:17:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707927455; cv=pass;
        d=google.com; s=arc-20160816;
        b=AQTOLj/oWVm+xdEkFC23qhX3xhYfQAjDcuIJ/f1wWA6IcDCEjAL1dw9Ls92MfIre11
         y2EH1In0qmGlf8vHDmvB325MuwBG6whwV323e7iUA2JplQACg/Ui747kXXzgNBx4vtPs
         nvEbOG+/2DbqPwk/GAQ5SJCeccg/l4+6d3gsS2/0Qol6mC/n5Yvx7wj0SFmW/yO3aN19
         c0ZVwM6k4wXXUCXGkP6suoazfi9dO40CfZKO4/M2vrwuk13hYc9tiWUSB4ZdyCkkswW1
         8wbGbsFrz+d07PJaq8QYNtlBTZQOKBj5qWxJGrewiELBmjQ9NUZB8dbHPXkEsOf+qg+p
         lpRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LT7n6Su2J4tXEJeC0MYskC6QumQzAc6oy4l0AJobZC8=;
        fh=FVDMrtRThCO3tTjTus8+WffWC6QiDpvG6uyoUZ9DBWo=;
        b=jWfHULLSlw9rYqJ9oKgdR9ILBawMd8+2Dzbpy2nle/I3T0uHjl7R3ulgNk5rCmroYH
         k0xe0cjBpvdIoQjRgMFoFpKKFLFybZMyDd1JOqTqCE8QEeq9d0WL5SFl9/4jKvrm5Rnw
         CiPV6LhyHBRmaHwWmF7KSuFgifjJxooL2ycq4HwHxeOeb71XfYlz/jbhkVeC7zzoB4aT
         EUNtiR2c7U4OoeWFOXScMbF0gh8BVVM3a7kQi4oA611Lp/EqpC5fUU3loduY/17Wt9T5
         8aTT+2hN29nUMNRU5ZW9wM5kyAD9xby7M/e1YOMOBGvO5nvwoyTepLGqEQuG56pC0/s8
         M8xg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=If7KvAk3;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707927455; x=1708532255; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LT7n6Su2J4tXEJeC0MYskC6QumQzAc6oy4l0AJobZC8=;
        b=eizJkkWsx1q72CIv2e3QCeD/A6opxKSn5c0gAtuAi+majT91/y+a+fadLQtd30qdEC
         PGBdiQYU9+qdM2VZUXjfbb3pvZXvAlBt5KiE1yRjtdOecLNb4xT/fzy5ceB5IlRCMWue
         lMr2+6JKiq/DGxM4aJHL+3LdoGokJQho3DNiusUzWCpOYfufjHtg+FgBw+sGiIKx/hRI
         nOOVJcjLKeeJF8w6Wl3JxruOqDS2lkcYtT6yrZYpHPzYqszxCdxOaCHbieuNDAmkU7jD
         MWyIyO5u0xox6lBFO/VN6lj70JHMbLNRlc/kOohhlWp9tuRuo5oxXFN+T+7jqFW2JLrO
         UPPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707927455; x=1708532255;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LT7n6Su2J4tXEJeC0MYskC6QumQzAc6oy4l0AJobZC8=;
        b=EvBhAaSqoylYeZK9wrbb81jiy9Hd+1gJaecXc6Wjzhtayhb+Ca+8di34XJmJ6Lm+kz
         4vCiSRbUfXzX+KslDrC9iOMxUVm7iUg3s62IgjCOe31syuD+IhKy9bZ2mdXWNDdMCUIA
         YAghT+pR+eLsUdpxqiWw3coWaqsY3s0pYH7JWLm+bk0pRkgTKfQFn/McZZ2KexjElT9g
         Rm+pVY+Dcww0K1W67Lq9/0BO2O0RUZRZ0WjtcYmgaay8pfh8LQmn1V//4jXABOG6OXuo
         iXkB7TPUrx48PxMPrmsxBJnC1kl4w4y5WEcxyIenXaqLafPonYux3DDJcaN8+1pTzCpi
         n+BQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXaVSrQ/Uirml9Rcp7QFaXSJMI44haqV5p9KiaJ1LspseuEs8j06gY7JfchqnUoWmLq4ebTfyyH+3oE6uOpOmL3nZFZKp3flw==
X-Gm-Message-State: AOJu0YzBozCN3T5Aqu2RFUn4AEm2LQLDgB1AtUzLwv9lsQQkmuDtsTxD
	5XPPi/ATniN5RAl+y67mLPCXE7W99j4qczUQWKneZVsPZKTKRUoD
X-Google-Smtp-Source: AGHT+IGf0m4feLPRR8VKaS5kL0XP1ynK0RNf+BVlqTiOUaV9DhzUWJWkoR/IhM+fvysW88wo7aCzOg==
X-Received: by 2002:a05:651c:483:b0:2d0:9b1c:649e with SMTP id s3-20020a05651c048300b002d09b1c649emr1991620ljc.31.1707927454681;
        Wed, 14 Feb 2024 08:17:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a36a:0:b0:2d0:f4c4:d338 with SMTP id i10-20020a2ea36a000000b002d0f4c4d338ls87860ljn.0.-pod-prod-05-eu;
 Wed, 14 Feb 2024 08:17:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVJnrJy1/xRM9VDrvrhrcFaEMyQS24Fyy0yooMKmG1b6b6CDpL0+KrYyLPEb8R35Msjek+LC8/H1VFB3jWpPm1H3oC+JWw8uVb+Sw==
X-Received: by 2002:ac2:4c04:0:b0:511:54e8:b82e with SMTP id t4-20020ac24c04000000b0051154e8b82emr2149749lfq.47.1707927452516;
        Wed, 14 Feb 2024 08:17:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707927452; cv=none;
        d=google.com; s=arc-20160816;
        b=E4/qKIqgbFfnzhTtja2ZoMyk2clTIesze6qRAujdZAQtfLZflbQ+SmzqTds7GgRDs7
         6LT6HF6jn4EhnqwhouppStSYIMPSwnoW+N4JQU5l2ifDHTkeuMut3hCsx7DBNHby6RzR
         QmgWhvj9b0G0gniY9DY+jqn633ZPujg7fpiqm7gvIXp+8qxbjOczYG1HRMXj8ITRVAdn
         GDr63aF7QPQVGGWMD+35EYucOzSW2to9hNnUqOzOt8PYM1JtlvdmgsnBU+Lgp61F4/fI
         1uYeRO0/ykt4ZEJkSJT/HzL/RD6Wwm3XvFiLIXtGjJ4sbMx6wHI1XZI+PEEPek+jNMce
         +zlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=WvW8w5yUCB+T24tws0BE+nRUAXqLznpxXzLB9RssHjE=;
        fh=wAsTL9w0XaUit6NRRb4HmLY9pTJrKvLzBWdzWgdnSjw=;
        b=Rr39aBsv1oGDXoyLHptEic08afMqQYm1kNbi/b5A8OkvY4nTg1FXH3rr2gqkMMcKNF
         ITPzfjh4Q3E/CJsWrmoLXgIgkwx22+2lBKNT3eIcPkjvws7vATw4jEHqZz73u6d6KmEm
         7n0CsABSwGjUQwCR89KpVk5cbly35qYbaK20+3owrwJz0fzMNxQKSxD3Npd16bIR4iVP
         jl9AhYL4V1g4aTokFU3O/QGcedPIYfEsvQHj6pvNX0u6gcF3xZx7zXKnDTlO5stxCiq/
         W1dgLxMsrW4iVBCddv/1ABBhivd7ZBjICPd0bxYS3A7OctTJb0+PEmpqZMo+ceCJLP+4
         vMKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=If7KvAk3;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCWAUTtioAlCWjt3ZM6de5DZqlqoPuxeiSPtmswxm7obe5TAbGXtk86V87bPeY+EiRB8eAdpnEJfbFbv0SBpuOhS5TeesfO/0TijGA==
Received: from out-185.mta1.migadu.com (out-185.mta1.migadu.com. [2001:41d0:203:375::b9])
        by gmr-mx.google.com with ESMTPS id dw18-20020a0565122c9200b00511ac70130csi40635lfb.2.2024.02.14.08.17.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 08:17:32 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b9 as permitted sender) client-ip=2001:41d0:203:375::b9;
Date: Wed, 14 Feb 2024 11:17:20 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Johannes Weiner <hannes@cmpxchg.org>, 
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, vbabka@suse.cz, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, 
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <udgv2gndh4leah734rfp7ydfy5dv65kbqutse6siaewizoooyw@pdd3tcji5yld>
References: <20240212213922.783301-1-surenb@google.com>
 <20240214062020.GA989328@cmpxchg.org>
 <ZczSSZOWMlqfvDg8@tiehlicka>
 <ifz44lao4dbvvpzt7zha3ho7xnddcdxgp4fkeacqleu5lo43bn@f3dbrmcuticz>
 <ZczkFH1dxUmx6TM3@tiehlicka>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZczkFH1dxUmx6TM3@tiehlicka>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=If7KvAk3;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::b9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, Feb 14, 2024 at 05:02:28PM +0100, Michal Hocko wrote:
> On Wed 14-02-24 10:01:14, Kent Overstreet wrote:
> > On Wed, Feb 14, 2024 at 03:46:33PM +0100, Michal Hocko wrote:
> > > On Wed 14-02-24 01:20:20, Johannes Weiner wrote:
> > > [...]
> > > > I agree we should discuss how the annotations are implemented on a
> > > > technical basis, but my take is that we need something like this.
> > > 
> > > I do not think there is any disagreement on usefulness of a better
> > > memory allocation tracking. At least for me the primary problem is the
> > > implementation. At LFSMM last year we have heard that existing tracing
> > > infrastructure hasn't really been explored much. Cover letter doesn't
> > > really talk much about those alternatives so it is really hard to
> > > evaluate whether the proposed solution is indeed our best way to
> > > approach this.
> > 
> > Michal, we covered this before.
> 
> It is a good practice to summarize previous discussions in the cover
> letter. Especially when there are different approaches discussed over a
> longer time period or when the topic is controversial.
> 
> I do not see anything like that here. Neither for the existing tracing
> infrastructure, page owner nor performance concerns discussed before
> etc. Look, I do not want to nit pick or insist on formalisms but having
> those data points layed out would make any further discussion much more
> smooth.

You don't want to nitpick???

Look, you've been consistently sidestepping the technical discussion; it
seems all you want to talk about is process or "your nack".

If we're going to have a technical discussion, it's incumbent upon all
of us to /keep the focus on the technical/; that is everyone's
responsibility.

I'm not going to write a 20 page cover letter and recap every dead end
that was proposed. That would be a lot of useless crap for eveyone to
wade through. I'm going to summarize the important stuff, and keep the
focus on what we're doing and documenting it. If you want to take part
in a discussion, it's your responsibility to be reading with
comprehension and finding useful things to say.

You gotta stop with this this derailing garbage.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/udgv2gndh4leah734rfp7ydfy5dv65kbqutse6siaewizoooyw%40pdd3tcji5yld.
