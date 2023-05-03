Return-Path: <kasan-dev+bncBCB5ZLWIQIBRBCWVZKRAMGQEW77BCTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F68C6F5E0F
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 20:40:12 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-64378c352b0sf81971b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 11:40:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683139211; cv=pass;
        d=google.com; s=arc-20160816;
        b=T8vUnnJA17KD8tIURHJaEP0ud7NjQdjnny7gerUh5SMsl1IVskyRrZB4EMvOaKtA88
         y1qTN29CNPS8dCe3wAY1i0l2JaVLtHvxnHTQcU02Wf6SeZfXnKPPrwM/qr4utVtC4sOl
         fi2ePnwiopFaym7Lr8AA6UghAl1xstv6vwOzhtcoBnHt0qNhrG7qLO0WDtvEI58gisyq
         +9KRcivHYyR46mHiTiAFGQxS8A1eePs7coNSO5ZPNssZwcTj4kq4lmTlPYZWNr9W05c5
         Je/iTMwKDUIp2h3SgTPQl2z8uEL3/oJ2/a9CeM1m6egZBUKcnbbOpAQ+6nDlYo3bRrVU
         etTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=eJBJ89oK1G8eO8fWF0wTIQjVfsqHAgOfnsnaJOtoVIg=;
        b=0Zg2kjoZOULPoc3CTDB8X2AzUJStmi6CiOyXOZJxI1Cq2VW8yG2b+iccfHJ27Jw1Fq
         UgnYbqPuiTVw+WQahoxcaQCoycdRQm3dYU83Bcb5XgfXy3a2I1q6+QMf4T+ZjvHXVh05
         ij+7o01tYfq7waFqQCT4Yl35nAl+yxCToBvryN0G4mAnbupxDuR1LIqcHNZDv4jZMG3a
         /4TticdHA68LoFkJV+CXJzyc5oUE7YFaggi2TygL/7mLG5Xw85horcrTIXtFUNm0pFdo
         DmoLLhEibXUlortRAh8BcnhQWLFevB7tSgMO/eoEuyjVN9d96KZfVn+kvjXWagfWVXrH
         3YYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=FAsEakod;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683139211; x=1685731211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eJBJ89oK1G8eO8fWF0wTIQjVfsqHAgOfnsnaJOtoVIg=;
        b=OH1MSIJxAzxg3FSD3daZwNBOu+68SY/Mq7ofmpYDQSTQJLD5GZTtQvdEXbI/DPl6Vj
         onVJZyITb11r97RxRZLMFD0+AbMn5XZ3WM7gbU6mgPAATE9hZ4vLPpYH1f/jPlxSII+N
         3OxlWrAyKxcEj+gFzyv0tnoFLnBGff/2+1buuabTRKgfHfFLKgH0o6aVVqECNPdNQWUp
         HYu+cmGbODieHthmP1g1h5XdzMAYb3WEv7JGwAZ/mn4fhW0Oab84DViy/ECtJXHyq+Sr
         6QRN1/0uIOBLLiwCS+PPuhDaJBKfD/1Nv6MtQTURTvO64TiY5b3ORINGIhNkPwkL3jpX
         MHhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683139211; x=1685731211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eJBJ89oK1G8eO8fWF0wTIQjVfsqHAgOfnsnaJOtoVIg=;
        b=ikJFDJQ3uhfp1yAqeD08mBtfHhJvpEgHqaPAFx3jqt/n5fdcm53MY1/KvX5dzoGIG3
         Yvt2MH6wzxD+4usaSq83Rj/w4yrueOoUVKVKMKZNvq2Wv9KXW5Sbuxj1xW5uw5QAY2D/
         OaE9lh3zpWnper2X8lNPfS3mG5G0XuqKQxhOrh/t7iLyqHB5FA/wCgjbyz+OiPaz8Z06
         4WanbtpeVb0R1wD1vfHxVeeW8sciEeTB/L/Z+KSMbyysD1FrJ1tIx0LHSL46OAzMtOii
         TMNwI2zc/t9+riXjATpTIrE+WigZhnOqQRmta9rthPTeJeRG4cUikF+7SxyILG/U9PfV
         4x6w==
X-Gm-Message-State: AC+VfDx6BSokbOYAaBwUQrlTn6dfsPTVF1JTbQyj8+YUu+lpWTJ1plqt
	kmwtarOe79vHR3YajvNxAfw=
X-Google-Smtp-Source: ACHHUZ6uxyWmzXy2jvu7EjMzNFD1oX6yEWpubke7HfRfxja9XuuHDQPxeRPAAoBJ5uLF5VjmeYyFQA==
X-Received: by 2002:a05:6a00:d6a:b0:643:5178:153b with SMTP id n42-20020a056a000d6a00b006435178153bmr492128pfv.3.1683139210992;
        Wed, 03 May 2023 11:40:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2e23:b0:626:9ef:61e9 with SMTP id
 fc35-20020a056a002e2300b0062609ef61e9ls5865247pfb.7.-pod-prod-gmail; Wed, 03
 May 2023 11:40:10 -0700 (PDT)
X-Received: by 2002:a05:6a00:1a42:b0:63f:15cc:9c1c with SMTP id h2-20020a056a001a4200b0063f15cc9c1cmr27131310pfv.34.1683139209975;
        Wed, 03 May 2023 11:40:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683139209; cv=none;
        d=google.com; s=arc-20160816;
        b=ulvxWlZiUkbaCzwlv2Xjekmb+0FN0zfJWA6E1rusU8Oeb0sZTO/hI0hVYpBh4QfCVN
         5z07wzHg5PH92dm0vM0/KcWBVJvrgDBk4lihQGI2NZIgS4mGNtSpVG+BbNef3Zm1Gbiu
         2WcseeFGiiGc+fcBEPD5SH+E/QqDwx2D+S5K7pPrPlrbR5HGQoki+lGnIS+gWp/RfRZU
         /+qx0qKAkyvSqs03/CK1oJW5VYwgjnfsS1O4OtNj8JW5dwsEdDTK7vFMWdxynoXQ+cRi
         gpY1RpZZuIYQFdKSfXrl1z0O25E39+S0ed//nyi4i2QrMzJC3sMjlVIrq+9zEarCH2FV
         nQ3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=sQ2ADeO1XgOmj5DxbzjpzikYpUTn+B695qqaLQsTl4A=;
        b=gxUSsMBR6M9mgukXNgcydnO4R0ofVeCLDLt0rEKlRR2/rFEcR0uik8xAvcRFz+HxKN
         zsXh/lrzgY9pj700LpFHNGdg0jVntPXTAVDxf+kvO4hceHKzPBwrrAsR4DfJV/Sw3FpU
         RTjomgVXYqzBdbUL6UIL0Mzyr+eXqmgp975Ru6jGJ0ilNlVpfWWkwtMr2d+rhfNQ+8t2
         Nv8mdWFk5fdiNtvbFhNgxudAVDMzkOeS68eKya+DED9HFuwZvrFXT7kNfLXHP03QTmo5
         DeJhyLZtfXqszCjcdjfW9Bck70GotoPlaF0bULTouNrJCf2mS4A2SDPXUhN3V+v+yFel
         1IhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=FAsEakod;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id 81-20020a630254000000b0051322a48c32si1956853pgc.1.2023.05.03.11.40.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 11:40:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-52c6f81193cso608917a12.1
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 11:40:09 -0700 (PDT)
X-Received: by 2002:a05:6a20:4286:b0:dd:7661:fb34 with SMTP id o6-20020a056a20428600b000dd7661fb34mr28426673pzj.51.1683139209307;
        Wed, 03 May 2023 11:40:09 -0700 (PDT)
Received: from localhost ([2620:10d:c090:400::5:6454])
        by smtp.gmail.com with ESMTPSA id u22-20020a634556000000b005287b22ea8esm12540790pgk.88.2023.05.03.11.40.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 11:40:08 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 3 May 2023 08:40:07 -1000
From: Tejun Heo <tj@kernel.org>
To: Johannes Weiner <hannes@cmpxchg.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Michal Hocko <mhocko@suse.com>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
	Alexei Starovoitov <ast@kernel.org>,
	Andrii Nakryiko <andrii@kernel.org>
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFKqh5Dh93UULdse@slm.duckdns.org>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
 <20230503180726.GA196054@cmpxchg.org>
 <ZFKlrP7nLn93iIRf@slm.duckdns.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFKlrP7nLn93iIRf@slm.duckdns.org>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=FAsEakod;       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::536 as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, May 03, 2023 at 08:19:24AM -1000, Tejun Heo wrote:
> > Taking a step back though, given the multitude of allocation sites in
> > the kernel, it's a bit odd that the only accounting we do is the tiny
> > fraction of voluntary vmstat/meminfo reporting. We try to cover the
> > biggest consumers with this of course, but it's always going to be
> > incomplete and is maintenance overhead too. There are on average
> > several gigabytes in unknown memory (total - known vmstats) on our
> > machines. It's difficult to detect regressions easily. And it's per
> > definition the unexpected cornercases that are the trickiest to track
> > down. So it might be doable with BPF, but it does feel like the kernel
> > should do a better job of tracking out of the box and without
> > requiring too much plumbing and somewhat fragile kernel allocation API
> > tracking and probing from userspace.
> 
> Yeah, easy / default visibility argument does make sense to me.

So, a bit of addition here. If this is the thrust, the debugfs part seems
rather redundant, right? That's trivially obtainable with tracing / bpf and
in a more flexible and performant manner. Also, are we happy with recording
just single depth for persistent tracking?

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFKqh5Dh93UULdse%40slm.duckdns.org.
