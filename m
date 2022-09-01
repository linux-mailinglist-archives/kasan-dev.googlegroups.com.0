Return-Path: <kasan-dev+bncBAABBB4KYOMAMGQEGR57FQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 025665A9AAF
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 16:43:20 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id s5-20020a2e2c05000000b00268a8808e87sf1348708ljs.8
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 07:43:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662043399; cv=pass;
        d=google.com; s=arc-20160816;
        b=OdkV4ZTM8O41bfOy/jXw1IUbfsISccp6CkuekEmOeVAktNhaNn4+gQBpbXh0SYrkSl
         2uSNt2Y1KNKSKF6jlCBLG88QEWxbjfSBcY2Y65UMqJt6d9jGJAQpS6H88JsIAIjNckUJ
         9/8rbgV44I8wYdZz7ypR3CcV7XX2GB4A7jKHmjxR/zxmPcWDVpmYRSk1I5AyqtaOIyfS
         z49lE/0rPSUUsDlhf95nLCOuya5gI+IBmjJKcqQkwZs0EV47Jx3U1L+lCvrjvo1e1pnn
         b+Ye6b3ZSRqC9R3YMXWN8F98fHGlonKtcf8Xl/4fi3w6adk42whDNWS9KqYc+RJrhTKO
         AqYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=enhObeodgIqf2nZmoeu/TCzgoBWLcVEgK8ezEcu5R78=;
        b=cGYjiohqvIFua4/AqdRbR8JP/R/AaSuaBYRBZcUNXVZ5q5xP1bpKPXCcMbC+RVdZe2
         k2XC19qPFeE7y+lxMM0qIkBwShSNxi1m94ouuXSSazzrVSQKaMHsGG2m6AxEFjJ3/47k
         vl5TwE/5YYrv+jQ2O2o4abG6iloZXL4RbFHJfOgV9J5REZ7dM1v9v+cE6PECFlbTbP0B
         Onx9jR6D0gb9OhH9YCd7Q2ZDZ7qj4j0tzSfDM6kGPTGmYsUvjt72gqhHIAPZwO9HL5kd
         hY+ibYasb/jWTP/G/46ttQHBSjfFT1EUViezANT8zDWTl72X9o1rtMw9WkS5VoxKrCbd
         RoYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DYXiWVC0;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=enhObeodgIqf2nZmoeu/TCzgoBWLcVEgK8ezEcu5R78=;
        b=nZOZ/lsYs2oUaQQQXPinD1ww5uX07pkWNWxCBVKRyZJEpIEjryJTmesJasyl6OTEuc
         poZCS1DGrVaLFdxolTkTkLSLnNJe3fdYJkzdl6TJ6XjDKeBJ7reqTKRPX5SWW+gkxeNO
         7dQ8ptgF8B/OgEup+4zXwecE8DwDoVffRZ1gDAA6XMDnDdNcCkQkJlWtqmb/CdBC81b1
         6SjlboUaKNKHLFesazE2q60fBi7Id3T81VgUKWGyp5O97TMixR7E4F6m3K1ozhiUPHYi
         u1e2RhS+UZQ04f3PQMBG5ouPyGCDpDuhT1ecVHRFCLeRpeHTlYeyi5G+8s5QQl3vl77N
         OMKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=enhObeodgIqf2nZmoeu/TCzgoBWLcVEgK8ezEcu5R78=;
        b=gZlKj2ICWxiWOGwL0pc20JvjiPrCMXGSjqpYA0JmAnCgIx0YQULKWCH70yDoAvsWor
         9JuMuSusWHuuZ+kk5P1t9Co+CH7by9h6UtukSQGCxRZSR2lToV/ZMq3cRw8uyNPr7+eM
         sEr0ttFXp5bPCYWDBfdSMJTS/x49wI0ioVHe4b91rAvmWSlnEtDx/Kde6sqLA1u1/9tZ
         CDx6fWYGX+rlFo4OkLVXK8IYN4vszNO1A08BtXLwM9ehZgICKJYu9E04kx0PqTtWF9ax
         FobYebK5ABIA+HLM2LujrK99PMQukhAkz3zxObicSOxqutMvPIvfm2Jf3xHN4DcxnFtH
         PjCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1eCa8eI4CwfH0QzNYLAgJzSoilQI8wDk54vJg+qnnOmj+MckaE
	hj49kjnB2TGodG3CBoTA/cU=
X-Google-Smtp-Source: AA6agR6QihywBTyyeZOvNgeMCLSywucyql6N+IOwUdzZgOBdFVNUEmFcXD2Pfd6CFz7eDJ1dDvaDFg==
X-Received: by 2002:a2e:99c9:0:b0:265:fd6f:5d7e with SMTP id l9-20020a2e99c9000000b00265fd6f5d7emr5389687ljj.482.1662043399458;
        Thu, 01 Sep 2022 07:43:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:194f:b0:263:7e6f:73e0 with SMTP id
 bs15-20020a05651c194f00b002637e6f73e0ls370302ljb.6.-pod-prod-gmail; Thu, 01
 Sep 2022 07:43:18 -0700 (PDT)
X-Received: by 2002:a05:651c:1114:b0:268:9d4b:c208 with SMTP id e20-20020a05651c111400b002689d4bc208mr2022760ljo.4.1662043398609;
        Thu, 01 Sep 2022 07:43:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662043398; cv=none;
        d=google.com; s=arc-20160816;
        b=EvTSFqBQuhDwGmLWEQrXT08aazq863UZN5VpNhhaqxI4udwTTYY2eQK5oayWC7uDge
         yyvGHE44xMGrK5nL77pb9we79fqpKrlo5OpJ1oF9EiI+gfMgS/UlhRLyIPQO+9550D0p
         eW9yMCCgYBXdTsKg0KlozyVR/wPYatSBAcXGwL6z8/io1znUToYom+TBxF5/mbwTlcu2
         kA1KcsM+yNgDzk1Fgz1BDbx6wiMCZz1Oz8Nd9ZYbKXGUHZzaDvLoocHkQLmFtBCWftlC
         6OFv3SBj5f8G5lvAFTSOFmHJrskqCkd9A7yavod30BdOVuawm7YdkbX3K5ddLMFyRQe8
         oMqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=nOHSW3FDpFxopIM9LbojW3h32sP5UuFpnfFE44cGJM8=;
        b=v2gOduPcfO3WpqE2TIKai+AZY19m8+kHlTgqAxom9g9OP9a+uk53Iw+ffGToiJqsxI
         80Qi8BtciREzKgTsKZz8pq+Hyg5c4l/0PBFoJbc/FLXFf2Ic2QUnpGVTUUReapQ9JOXF
         8zLH5uhPYD5JhjWgybWBF67+OyLUFLRTPCAJgSXR6SGnfEPcE+bPqavLs6p9KSNmNc6Z
         jI4ql1xouKBnDcUVX4H798TAmxp/FUCMxpNy0CLOXaUUobTKco0QGJ6eYVhKQhx8krhe
         FaJPXnDTqMTSKpQpt/t8FIUHEAdllPiRKSVRZHXfHL6PNOQe0kDsdtTm82n3r14CZCTh
         8hnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DYXiWVC0;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id k22-20020a05651c10b600b0025e5351aa9bsi430806ljn.7.2022.09.01.07.43.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 07:43:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
Date: Thu, 1 Sep 2022 10:43:11 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
	juri.lelli@redhat.com, ldufour@linux.ibm.com, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, arnd@arndb.de,
	jbaron@akamai.com, rientjes@google.com, minchan@google.com,
	kaleshsingh@google.com, kernel-team@android.com, linux-mm@kvack.org,
	iommu@lists.linux.dev, kasan-dev@googlegroups.com,
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org,
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org,
	linux-modules@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 27/30] Code tagging based latency tracking
Message-ID: <20220901144311.ywhhdaigweyy7eo6@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-28-surenb@google.com>
 <YxBbFUirdlbXDaZA@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YxBbFUirdlbXDaZA@hirez.programming.kicks-ass.net>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DYXiWVC0;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Thu, Sep 01, 2022 at 09:11:17AM +0200, Peter Zijlstra wrote:
> On Tue, Aug 30, 2022 at 02:49:16PM -0700, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> > 
> > This adds the ability to easily instrument code for measuring latency.
> > To use, add the following to calls to your code, at the start and end of
> > the event you wish to measure:
> > 
> >   code_tag_time_stats_start(start_time);
> >   code_tag_time_stats_finish(start_time);
> > 
> > Stastistics will then show up in debugfs under
> > /sys/kernel/debug/time_stats, listed by file and line number.
> > 
> > Stastics measured include weighted averages of frequency, duration, max
> > duration, as well as quantiles.
> > 
> > This patch also instruments all calls to init_wait and finish_wait,
> > which includes all calls to wait_event. Example debugfs output:
> 
> How can't you do this with a simple eBPF script on top of
> trace_sched_stat_* and friends?

I know about those tracepoints, and I've never found them to be usable. I've
never succesfully used them for debugging latency issues, or known anyone who
has.

And an eBPF script to do everything this does wouldn't be simple at all.
Honesly, the time stats stuff looks _far_ simpler to me than anything involving
tracing - and with tracing you have to correlate the start and end events after
the fact.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901144311.ywhhdaigweyy7eo6%40moria.home.lan.
