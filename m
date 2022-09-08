Return-Path: <kasan-dev+bncBCKMR55PYIGBB35L42MAMGQEPYJ3N2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EE3F5B156A
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Sep 2022 09:12:48 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id q5-20020a2e84c5000000b0025ec9ff93c8sf5271200ljh.15
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Sep 2022 00:12:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662621168; cv=pass;
        d=google.com; s=arc-20160816;
        b=QqJ4208LB1G2Y6bYyLKbDqsnHYaTR2jmvWeRuxx1JCAVsA0AxkyviFqzXri/o/KIud
         VTNwthCpr62dk33S9UNsLSfosEJsrhbmSojQo4j4asOpr2cF+vuU7H3oT4QvM8I69e7F
         VIQwJFvtbVTUsoG0VFu1ObcPFxelnJiXC9Z5c8VMVnw38USS39lIrAAp2ZkyP4C6uiCp
         Nkc3+zD11lYEQjxeKKpClNUkh1k+kgaYab4jloCS6Csf3fN1YA3RL3aAhRTt8THnX4VH
         P5P+SDwFodkCh3uda45RhHX4moS+mKS/3UflkoWeRQwVHfrpVQ64sdomclHiQm6PuyXz
         HGxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=i6vEW9IAXuN3e/Ep/bZWHnNVJQ40xQlPm8lI3jVjJcA=;
        b=rG0pYXVDZuLWushOxPCTt9ktAkCsAiZbBhz3sQWicxdfs/Csw/AYZ6XlmL+DOT5dS0
         Iq+hCAF6QNDbIC8rejBRVspWKaFryMR7Gp2H77uNi7oYZtMhE+jRDV601sBfAMWuK7+l
         HyKD2YdLns+9BDo6HZk9RnnyqwQi4XpfKSqEA20BlfKA9Rk39lMuzUg9FtK7JRCHRghI
         CBAVLAtYmXCeNgq7bW/MuGyyR4/1nWFE/vTql5223k5NN9SgsRU5hEpPTf0zZw2lAFu2
         y9djMUlER3l5wtP1bCpFh/fvaXryQoWVQXKOxwxE/bXYWz/WaQx/xT1bi4ri7EW03lZT
         zHSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=tzO1hqg8;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=i6vEW9IAXuN3e/Ep/bZWHnNVJQ40xQlPm8lI3jVjJcA=;
        b=JH7UaFQpkhUORqEH9uLsNy5G+BkT7C2jMtF8VZk5XwE5MMpGzwiTc9jLKeFs1T1xKc
         d/Z7OXLeP50m5BR/yQqj9eYae8Ad6B/oTsn+nKcJiB16Nf/t3sHhDZWe9cp/z9/S+awq
         mKQpZOGparXyxhHlK3ee/r4nF6R5oeoj/c6Aw/41Q+0NskYQ4mHbtdlYQfctgNHBgFpU
         agUOly/w+nhdIA0Dz2da7rO3QUJH+CFZEmrrfxv3nQCtCk1jQw1hOx17gepH/UwVLZj2
         whxbIQWfdGCYlu3iDFHEKETXc5OVGcZXAUcy4o1sGW6fsf3n3HEFjWpMdk6zq/ne/avq
         uS7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=i6vEW9IAXuN3e/Ep/bZWHnNVJQ40xQlPm8lI3jVjJcA=;
        b=mDFUMsjHyI65coNE3nDlH02tQ44lRNMdPrnXNNFtqDc9KCdOJrm77hiw/76gl4vZel
         rX4AX0D0Io0bVl6ET/4xhG2j1bDsQmyIRjOmGD4LEOWPukcR2W5XmUL79ztqpVk1OkTc
         BLmVUPXGq8IveWHv0/Ig0fo10yieGBs5ICAtQ9TgrjgYBmWbL6hSUw/44Df6XzNMSJPV
         wJp+7rjJW+Zvdo5tX79oOJhlc948I7BiZmT05wXPS3/1Ik815zHq+VUAApLORQl4IoyZ
         mWpg8nryZ3VzHqQ+WTuXyaSTg0fUuXaw8xQdt958gGX8OfiOvWhKDSQ3nhFjSJKio4X9
         DtrA==
X-Gm-Message-State: ACgBeo2cUfqktkK93bIaGJ9EP326Vv7pSfX8iNwFgSsL6Jt7gdO9hxul
	vIAHXXisEpDFsBfVhiRdP/U=
X-Google-Smtp-Source: AA6agR7hN5pz5rSBn+5j75D4p7FACE4EnR+UWAdUUAeEMnm1I632b5O6evnfxKxlFSaIZpsay5mbbA==
X-Received: by 2002:a2e:a5c3:0:b0:261:ac2d:2820 with SMTP id n3-20020a2ea5c3000000b00261ac2d2820mr2149997ljp.243.1662621167932;
        Thu, 08 Sep 2022 00:12:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:210e:b0:48b:2227:7787 with SMTP id
 q14-20020a056512210e00b0048b22277787ls637329lfr.3.-pod-prod-gmail; Thu, 08
 Sep 2022 00:12:46 -0700 (PDT)
X-Received: by 2002:a05:6512:31cb:b0:492:ce5d:af93 with SMTP id j11-20020a05651231cb00b00492ce5daf93mr2066835lfe.101.1662621166447;
        Thu, 08 Sep 2022 00:12:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662621166; cv=none;
        d=google.com; s=arc-20160816;
        b=Vsaygrjr87Fqwp7QAkNNb1v58vUFmfFZK8Sgmsi67YPjB3KUOg/qe+adIpoSNXngm/
         x8IRJEl2F2yNgZzgsWsQwxzM8zLoKYdszW952GaQieddqnJmxlcAmNUGU+R4cilBeibs
         HJmWhhyvVcoCdzsuAfipFIXVJlx6R4//pWGW/tdUqry8SEXop/t9J9XK8fAzG5m8LSyC
         cfbAlYSAxKa4exlS2yBGm75z4O8NyBhKk14QLlO/zJskrn4wN8OvNGn5e1jr2n0bHCAR
         NROBvhsF+vyyZdZ3ErC5Ls7J0LvgRI0VXOHNrnCxhj1Us7JU+JcrGmebutCRjjG0ZF0l
         RkHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=wQxYLHyDLglTrc96Dwo9w9RPNpsCq3XWN1HyAjbRYNs=;
        b=1JvKthLMiVkYuzQTUK0RTWfGoC2Vao9iftR4hrck6q0lr+4Eb73np2nv+Mv104Eonc
         nu7llyimFhLkDTLBtjSSVpIvUwp6IcMX9uW2ALES9z6yF/aBMEPkxgcTo5KgonucJHJQ
         wj7B+4ewAtns2UqXz79r29/88B6Rj9quPKw6br/sZvFfhjTVAcsWWZIA3cCOVtbbMVDI
         4uvmbi64mtaMyTFduW7RisW28IePr9HyN9rx/eVCfxOyqphz7p5rVscBj6t6AzNZxIL5
         ghqbp4KsRshz0KABvSfZTdOCHhvTaGRuAIn5qV7DQrAxnxofFbu/XWli7oXiM3ZwjGJZ
         Mzaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=tzO1hqg8;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id u20-20020a05651c131400b00261e5b01fe0si880001lja.6.2022.09.08.00.12.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Sep 2022 00:12:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id A735433D05;
	Thu,  8 Sep 2022 07:12:45 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 7F64713A6D;
	Thu,  8 Sep 2022 07:12:45 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id Rg4TH+2VGWOnDAAAMHmgww
	(envelope-from <mhocko@suse.com>); Thu, 08 Sep 2022 07:12:45 +0000
Date: Thu, 8 Sep 2022 09:12:45 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Davidlohr Bueso <dave@stgolabs.net>,
	Matthew Wilcox <willy@infradead.org>,
	"Liam R. Howlett" <liam.howlett@oracle.com>,
	David Vernet <void@manifault.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Benjamin Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Christopher Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de,
	jbaron@akamai.com, David Rientjes <rientjes@google.com>,
	Minchan Kim <minchan@google.com>,
	Kalesh Singh <kaleshsingh@google.com>,
	kernel-team <kernel-team@android.com>,
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <YxmV7a2pnj1Kldzi@dhcp22.suse.cz>
References: <CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
 <20220901201502.sn6223bayzwferxv@moria.home.lan>
 <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
 <20220905234649.525vorzx27ybypsn@kmo-framework>
 <Yxb1cxDSyte1Ut/F@dhcp22.suse.cz>
 <20220906182058.iijmpzu4rtxowy37@kmo-framework>
 <Yxh5ueDTAOcwEmCQ@dhcp22.suse.cz>
 <20220907130323.rwycrntnckc6h43n@kmo-framework>
 <20220907094306.3383dac2@gandalf.local.home>
 <20220908063548.u4lqkhquuvkwzvda@kmo-framework>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220908063548.u4lqkhquuvkwzvda@kmo-framework>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=tzO1hqg8;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted
 sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Thu 08-09-22 02:35:48, Kent Overstreet wrote:
> On Wed, Sep 07, 2022 at 09:45:18AM -0400, Steven Rostedt wrote:
> > On Wed, 7 Sep 2022 09:04:28 -0400
> > Kent Overstreet <kent.overstreet@linux.dev> wrote:
> > 
> > > On Wed, Sep 07, 2022 at 01:00:09PM +0200, Michal Hocko wrote:
> > > > Hmm, it seems that further discussion doesn't really make much sense
> > > > here. I know how to use my time better.  
> > > 
> > > Just a thought, but I generally find it more productive to propose ideas than to
> > > just be disparaging.
> > > 
> > 
> > But it's not Michal's job to do so. He's just telling you that the given
> > feature is not worth the burden. He's telling you the issues that he has
> > with the patch set. It's the submitter's job to address those concerns and
> > not the maintainer's to tell you how to make it better.
> > 
> > When Linus tells us that a submission is crap, we don't ask him how to make
> > it less crap, we listen to why he called it crap, and then rewrite to be
> > not so crappy. If we cannot figure it out, it doesn't get in.
> 
> When Linus tells someone a submission is crap, he _always_ has a sound, and
> _specific_ technical justification for doing so.
> 
> "This code is going to be a considerable maintenance burden" is vapid, and lazy.
> It's the kind of feedback made by someone who has looked at the number of lines
> of code a patch touches and not much more.

Then you have probably missed a huge part of my emails. Please
re-read. If those arguments are not clear, feel free to ask for
clarification. Reducing the whole my reasoning and objections to the
sentence above and calling that vapid and lazy is not only unfair but
also disrespectful.

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxmV7a2pnj1Kldzi%40dhcp22.suse.cz.
