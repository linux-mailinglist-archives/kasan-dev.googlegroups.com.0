Return-Path: <kasan-dev+bncBAABBTM242MAMGQEHUN4EEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B8745B14B1
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Sep 2022 08:35:58 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id f18-20020a05600c4e9200b003a5f81299casf8063134wmq.7
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 23:35:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662618958; cv=pass;
        d=google.com; s=arc-20160816;
        b=BP+kyh2GyunQsNlQKP2X1v6CZmUfK7+vNWqdhnmCY4RqeRkVVcWKqDgD+v2t3ktJ+k
         OYGq2Kl4fQuWzYn5bN61DrAkaNsgXtGPsvag9mPqXPDqyq0dC4PtBY1cDHZs4kKslHoq
         AZNoduKpW+a2YZbKJBCvErfdKn9i5FVOQYQ/76oNgKKGsMed16JtRQPNDXaMycds2Klk
         rXvI206A0mMSy0gbFKXDN4vK1WBT6qmp9S9Xy1FR/B8ijqhrmyUd5YvVLUtdeY15uIXM
         F2A3FhO5Vyn+0WrmrSYDvxNQzDIbOrEA0/OT7CibkSPzMLsOotZPtrJd7ETwLuUhG0K8
         JXaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FZnqorwZknyuRlcJGqJxfp9mIs8gPdE1BgcJGG8wM9o=;
        b=yxfJa5aXofoMDxSzxRYogtJCOFjFpMsiPkM3zj88JCZjbTwJ+ZJp2UX7osq8FYQfYW
         fTwPO85fzr1SA8SOiWRUNBC3tnRGzlAq+X5n9/T+mByrudn6Tn1RvxTeeS3Ysr6OHbMl
         akVGpRTGwVJ5LDwF2h3qusZMTzHEAA101OgswA49AlnuYRZBobxNMeW4VowkMMJ7RoZX
         p1IPVc7bH4RcN3o8zBx6ZfuME+lqFtjEkUu9EWaQ2L0oNjXh3eXqFnbM+f2T7UyR/27k
         ktpqFlZf9Iv09gskzHY0bCVRDXevNCttdvCDQJCFXqDFfnLNjqa9yY7GVrIIVfS30AbQ
         41Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MwAw2Fh8;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=FZnqorwZknyuRlcJGqJxfp9mIs8gPdE1BgcJGG8wM9o=;
        b=giIlwTAGgzm8DY5Gu4zikDUeqyObypO2ItzadhVNCzogYVWRliMvVCJ/zGVWfciEyV
         RHXfV6gyXNqp2KuPHpREis+UzNm6SGZn6oPCMotE1CoI5dhrAEpfXjfHfnTLiFXEp0in
         OfjZdIJVMFgiyo5xbgtAXGg99rYOBR5ORvWvsHmCBlaN6UsW9+pnlmWIxpSp0ppJS956
         m5T6Fi+2JAM8MqeQQkLGU7Xq82Dbuqd1O6w8+/+XGLpvBuFyXu0lHK+YJGK8zmbgldO4
         23099m02DCd6zTfqkPnRRjNmXAot2WMhqks/IXA1WMC9LqOnJF3cAWOkxXiKclgJ7Tfo
         bDjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=FZnqorwZknyuRlcJGqJxfp9mIs8gPdE1BgcJGG8wM9o=;
        b=AHD23fWuzVkjlEVUo46Sj2Ir57+o3xmEXIVDcRBF2ma86ESNU4uzMkZP6ceyV/dFkH
         B/WleS+oQ9crb2PjKeeWZkc1vhWyiLsZMj8Gl1DaL8jHSfIbJ62DsnwrC5keL8gwDfdK
         mjYTyeYoo0szxL8+mBGjWznnNOMsYBaVQFb4ZvsAsUdYHxf1fgqg/9xG/Bcifk3uLujR
         V9tihxEUGxNc+syotldKqFNodKifoKD9jrP10NoyV51P6UJ7ocmMzcAtJ9T7Pgke/PDj
         pwTj27Xl5nBO7GQcZn0SD+USk3jbEJAVJME8iwTBpduOtwgpHohVU595E6fRUrxp3KFn
         IPkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3McRkOGEV9tATrueeCq+ZcIX4dDf2vJ+6rFYHl9/HajQwVlG5n
	eJ/Uxu6G77beqqKPiU98wu8=
X-Google-Smtp-Source: AA6agR7qH3scxPWwZViMtpBf0KBLcalRL79hUww1BUlmQRZ3ofCnU1fM7efAvoelTeeleIOzrwUgTw==
X-Received: by 2002:a5d:6d03:0:b0:226:ea3d:eb35 with SMTP id e3-20020a5d6d03000000b00226ea3deb35mr4063131wrq.476.1662618958153;
        Wed, 07 Sep 2022 23:35:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c97:b0:3a5:a469:ba0a with SMTP id
 bg23-20020a05600c3c9700b003a5a469ba0als1162302wmb.2.-pod-canary-gmail; Wed,
 07 Sep 2022 23:35:57 -0700 (PDT)
X-Received: by 2002:a1c:ed17:0:b0:3a6:3e9:5239 with SMTP id l23-20020a1ced17000000b003a603e95239mr1116100wmh.9.1662618957358;
        Wed, 07 Sep 2022 23:35:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662618957; cv=none;
        d=google.com; s=arc-20160816;
        b=rrO0WrWwm1XwC4yyOH3xKWXQv+RIKLjkp2CEBjs2iaHxNTP3GTrrGeP1CkdK4d5W3/
         XgUlGIbTy8/N7J+Gnkfyni5bmcUS9jSPy0ssoDrF8R1Z8dGurUn9+55wY64FJfKzENsq
         b2VRjcmIXE5kFnZSFTwUPXwHl9leUOGgPnkJ0fI/d5GOEXWyDIF6uxE4oOCOffvfkC7V
         48HdJoCUCHz+fFhIebl35Z4qeQMHBupXf38vLXvu08QD+zoXB2aOWwh5JMcax0b0XtcA
         q9IkSW//kLZxwk+kUMb6VuFJyV/ch/RDGZyMVL4lunKw0ZtUMCMVvcZbNMas7Ufnb46t
         Zb0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=jE7lXd8zCts/b8YEvdDXlJ5bev/XqPVvJNSIvscjpW4=;
        b=yG3T/JJhxWKVWykHznSnzKtjn/UX1Rw92kpG40jcOaiEUZAxRuKwgcEs6iOP0infhF
         5Ji6V5xFfX2aqOQVEnuwRd+BeUXNqZgX5iSTJVSxADwRwWx8ykRU7HsPYbO4CwN7LihC
         V2nlw1Omi+dinUU3DF1NJCNx3PMvhTTXYrjiciaKEbDkSfnSSgOsdIn5OtkOgIa33EhD
         6jzOoELUAlTxoOpR8mKh5gO+6nRgau7mpfAGQzo2Y8QDu+nUrP4Bbgm0peCRC+c34OfF
         llNe+B/dFmE1Z707hKHCKCXLQ6LvEV9yQMT4tKRfiVN+LazbxT5I0G23CDm43tQEw8qh
         4Zuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MwAw2Fh8;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id ba29-20020a0560001c1d00b0022707c1dfc8si1033423wrb.6.2022.09.07.23.35.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Sep 2022 23:35:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
Date: Thu, 8 Sep 2022 02:35:48 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
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
Message-ID: <20220908063548.u4lqkhquuvkwzvda@kmo-framework>
References: <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
 <CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
 <20220901201502.sn6223bayzwferxv@moria.home.lan>
 <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
 <20220905234649.525vorzx27ybypsn@kmo-framework>
 <Yxb1cxDSyte1Ut/F@dhcp22.suse.cz>
 <20220906182058.iijmpzu4rtxowy37@kmo-framework>
 <Yxh5ueDTAOcwEmCQ@dhcp22.suse.cz>
 <20220907130323.rwycrntnckc6h43n@kmo-framework>
 <20220907094306.3383dac2@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220907094306.3383dac2@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=MwAw2Fh8;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as
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

On Wed, Sep 07, 2022 at 09:45:18AM -0400, Steven Rostedt wrote:
> On Wed, 7 Sep 2022 09:04:28 -0400
> Kent Overstreet <kent.overstreet@linux.dev> wrote:
> 
> > On Wed, Sep 07, 2022 at 01:00:09PM +0200, Michal Hocko wrote:
> > > Hmm, it seems that further discussion doesn't really make much sense
> > > here. I know how to use my time better.  
> > 
> > Just a thought, but I generally find it more productive to propose ideas than to
> > just be disparaging.
> > 
> 
> But it's not Michal's job to do so. He's just telling you that the given
> feature is not worth the burden. He's telling you the issues that he has
> with the patch set. It's the submitter's job to address those concerns and
> not the maintainer's to tell you how to make it better.
> 
> When Linus tells us that a submission is crap, we don't ask him how to make
> it less crap, we listen to why he called it crap, and then rewrite to be
> not so crappy. If we cannot figure it out, it doesn't get in.

When Linus tells someone a submission is crap, he _always_ has a sound, and
_specific_ technical justification for doing so.

"This code is going to be a considerable maintenance burden" is vapid, and lazy.
It's the kind of feedback made by someone who has looked at the number of lines
of code a patch touches and not much more.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220908063548.u4lqkhquuvkwzvda%40kmo-framework.
