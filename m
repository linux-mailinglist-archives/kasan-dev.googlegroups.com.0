Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7FSXG4QMGQEVZFHURQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D8DAD9C24EA
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2024 19:33:33 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5eb7db06bf5sf1916333eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2024 10:33:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731090812; cv=pass;
        d=google.com; s=arc-20240605;
        b=J4J4za49CcrNTQgVZVw/+rRUvFaOQ5EEq1a3mAydQdyPsBFIPln7VsqjSUn+7/8Mg3
         olkCVh46HTZzn3ERwSFeO1ldXQ1ZCHVXFRyIkmrVv6cZ4UEjkX2onB1rKbQcWEyEE0eM
         Ice6AdBi0mfKQFX2irc/EGlMypjlM8doyJzavIFhwRqwYd8XH1Ao/TwUteRpu3YAtheF
         deviRdzpgQ3gtR9dnxbBtklRoSIUp/G0tQFE3Eu0fxdKt7N/5lzPMMf1p2R6ROIi4pKC
         uYzN055ZPL6Yubr/OscV5vfLYaI1JQV9LS929Rd5FyZTttff3Asxvsq8+R0Ma9mn09Tk
         h4MQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=yajHFMtha8BZv6YoXe+t2rt8ERaxMuEBwL44ltRz3PE=;
        fh=KAhwhRUwa2n+eiuDyNxz2W9WpJkf3XvDJSiQiUZIE+g=;
        b=GWQEXf8+YKfEL/HwaSXz0IY+ANdPTTKwScMxzmHSH4zfWCcBqbe/DTXy+NHsOEbDfT
         wb/z1nj5bYj96LnC+7pKAcz6mJwVh/b9eMqThHlLcRDpwxj4mffTGsla1bcCMR3yMeqj
         lxd9tV+CVZSG6qDkghC9WU63wOgBKqo4wYxT4K3xustjhkgGccyJ2toa4cO54UDgSaCU
         kjpQs/SS3ver43xL73XNvkWL88W+xy7O1VDazy2tbi1KdCNDLOhZ3WHBYsSxf9WNQics
         WU5yX6WMgiLumBNKBRJ4u3BB1Ad7BUDckR5GgINg4PnWoJYV0LK5hgUH6Cknv9xaI4Fh
         IirQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MVJPPh5j;
       spf=pass (google.com: domain of srs0=eyrl=sd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=eyrL=SD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731090812; x=1731695612; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yajHFMtha8BZv6YoXe+t2rt8ERaxMuEBwL44ltRz3PE=;
        b=XQ6RC8mjcFm8XsydPz/N+EcCTEIGUdygIewa2UMYgCRNx3pV428IiGZErbUdLaeewj
         AaXCUySOReSalTmkcXQzJ7s2yyPX4lgFaMbhlgpzfl4DU1eOhwWOw3sKDYaID4fenY6G
         xxy7HinAd+/Zda7HyPhJ+wwyi8O+8sZq9myZltmnuiY23kJW5B6exqeon6TARNjFF3Mq
         ERcNi88hcIJTeTBCCoywrxssQwpdHOm0EeXJqCwG1MuBivgqf57Xss3MAMQN9kM84vOu
         4YEwWbhc2LUxR+moswQCGN4WpZ/+cjG+w5ptZw4QKuGMtBapiK86LuJjTtTcU2+xoNm5
         nD4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731090812; x=1731695612;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yajHFMtha8BZv6YoXe+t2rt8ERaxMuEBwL44ltRz3PE=;
        b=VhW0ZwQfStLYtNJ4/XK7HyvQXfDf8rCiLwzuAPSVyp2YTFSgQ+imQAolrFQb2ESQra
         4vwbClQ+6YJpSjjlCk1Bk/CjozNKwjMMv9NyS142cvadIfpjskK+jQrdyS/UWDeZB7Qz
         Ws0yNChf2n3Q+HZis1G+cqRbucZ9UQz1kHoQfnZByF9YgXwlyboolmDda++bwV6eGO56
         hZNy0NIg+3jeRx/5rTmTmqR03/zbbH86liMjnQ6W+ZFXvM9HJvUr2cfjQDH15OtQ/Kjz
         KPYTH1gySq2ncYjo7pwrNjbit6d4jLUZhr1uR3XXypL+HeXG2A5DXfggCCPMnuX3P/4n
         3krQ==
X-Forwarded-Encrypted: i=2; AJvYcCURWApVaY200nbACtYHySDGhocKcTTB7cpPcgGXqaZ+zm9RYwBUaVoPeIyvotx/Loi+w0PFNg==@lfdr.de
X-Gm-Message-State: AOJu0YyfWSIc0GcepblUBWzGMlExusi4Tni8lrC44KwvyDng3+//kvzV
	rxpb65I0fx4ETe691schi2e3Z264Yq/wxJ2lKUXQYCuMt4xor9KP
X-Google-Smtp-Source: AGHT+IH1h2VPA0g27w/74BHBZyVJuoEjESQ2Yu7A+ZKikHElYT6jpBZUvFR3tmc6Eazs55FtCUPjgQ==
X-Received: by 2002:a05:6820:1a0e:b0:5eb:b292:bb85 with SMTP id 006d021491bc7-5ee57c5c576mr3731772eaf.6.1731090812492;
        Fri, 08 Nov 2024 10:33:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:4c03:b0:5eb:5d64:a13a with SMTP id
 006d021491bc7-5ee45c37039ls2177070eaf.1.-pod-prod-08-us; Fri, 08 Nov 2024
 10:33:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWsOUAlzTVFY3C3Amao0bQ9xluSbARACK7mmJEJEl1k8cD+/p2ptqmFzFyE4h1XtaxzeML8DCG8wFk=@googlegroups.com
X-Received: by 2002:a05:6830:3914:b0:718:c0d:6c02 with SMTP id 46e09a7af769-71a1c1cf9d1mr5535435a34.2.1731090811441;
        Fri, 08 Nov 2024 10:33:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731090811; cv=none;
        d=google.com; s=arc-20240605;
        b=ATNb5rkTZVjv6PezVtXt5pq+qTSLXQ46EebQN+UNcddHMfzA85GKXB7xiFepLa+QTT
         bE9QCLbIJc5Um72X9ev4auI8n9TxvSmCrABX8R87jsrntO1U/6fq8LdDGEl2J6vNrrlv
         uPOGRxviPgq2j4mrpFVwGqNVP6LSGSyos1a9sBs2gtA9mZepc32bh5WJshn39f8WC4ce
         TUeE3/fOtkX15XB+w45AVPkQKU9FHnWZU2vxS1ViUVKCZFGDd5ZwsXnqEkdY2wOXFGLd
         xHaiwiMTZQ/QQH5HEkx2diACJYIpAgU7tDIwomkMIpAvIKkrietJFBgvadlpxyCfP7Kt
         9c5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=lPlUwcdL7Ch242337sgJ/C09io7ClBZTStTAH91hGxU=;
        fh=yIs5K4xDMrEq+My51TTmB1y48I0qd9EjjSdtSz1cYDY=;
        b=HybPzQTJKc9ZK5PtI1BxtysirOcgRGAc6CFUjht83YTzbwG715DkPSpi42Ox8lUU95
         jJVTmfQH0D9kV7uxI7hDgg9Xkof5VehBPkM8+rTCdO0QMyUTpCXIwpxTfnaT3ywziesD
         XKRmVLABaOOzEWvtjH8ec6spEJD/uwpRICxe1dgqkw1Fvavw75/rnsx+Iku6+XbbZvTl
         t6tnopNigbmc7l1FBgd16pRjDhuJ65kGl4OZAWcFeWEKiqA59lBGJpTAfGMRbqFFOQlk
         gRJhktORbfZIjbCoRfcaudEcFvooNN5LbQpn/n53Sd5zIRoe7EYpV78pZ8t50MDtO0LE
         ceEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MVJPPh5j;
       spf=pass (google.com: domain of srs0=eyrl=sd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=eyrL=SD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-71a10697831si230341a34.0.2024.11.08.10.33.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Nov 2024 10:33:31 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=eyrl=sd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 08472A44909;
	Fri,  8 Nov 2024 18:31:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 58A23C4CECD;
	Fri,  8 Nov 2024 18:33:30 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 00191CE09E4; Fri,  8 Nov 2024 10:33:29 -0800 (PST)
Date: Fri, 8 Nov 2024 10:33:29 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org,
	cl@linux.com, iamjoonsoo.kim@lge.com, longman@redhat.com,
	penberg@kernel.org, rientjes@google.com, sfr@canb.auug.org.au
Subject: Re: [PATCH v3 0/4] scftorture: Avoid kfree from IRQ context.
Message-ID: <18b237cf-d510-49bf-b21b-78f9cebd1e3d@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20241108104217.3759904-1-bigeasy@linutronix.de>
 <Zy5OX5Wy0LsFPdjO@Boquns-Mac-mini.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Zy5OX5Wy0LsFPdjO@Boquns-Mac-mini.local>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MVJPPh5j;       spf=pass
 (google.com: domain of srs0=eyrl=sd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=eyrL=SD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Fri, Nov 08, 2024 at 09:46:07AM -0800, Boqun Feng wrote:
> On Fri, Nov 08, 2024 at 11:39:30AM +0100, Sebastian Andrzej Siewior wrote:
> > Hi,
> > 
> > Paul reported kfree from IRQ context in scftorture which is noticed by
> > lockdep since the recent PROVE_RAW_LOCK_NESTING switch.
> > 
> > The last patch in this series adresses the issues, the other things
> > happened on the way.
> > 
> > v2...v3:
> >   - The clean up on module exit must not be done with thread numbers.
> >     Reported by Boqun Feng.
> >   - Move the clean up on module exit prior to torture_cleanup_end().
> >     Reported by Paul.
> > 
> > v1...v2:
> >   - Remove kfree_bulk(). I get more invocations per report without it.
> >   - Pass `cpu' to scf_cleanup_free_list in scftorture_invoker() instead
> >     of scfp->cpu. The latter is the thread number which can be larger
> >     than the number CPUs leading to a crash in such a case. Reported by
> >     Boqun Feng.
> >   - Clean up the per-CPU lists on module exit. Reported by Boqun Feng.
> > 
> > Sebastian
> > 
> 
> For the whole series:
> 
> Reviewed-by: Boqun Feng <boqun.feng@gmail.com>
> Tested-by: Boqun Feng <boqun.feng@gmail.com>

Thank you both!

Sebastian, I am guessing that the Kconfig change exposing the bugs fixed
by your series is headed to mainline for the upcoming merge window?

If so, I should of course push these in as well.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/18b237cf-d510-49bf-b21b-78f9cebd1e3d%40paulmck-laptop.
