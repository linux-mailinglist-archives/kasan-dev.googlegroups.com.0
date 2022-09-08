Return-Path: <kasan-dev+bncBAABBHVU42MAMGQEQN343CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id E12395B15A8
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Sep 2022 09:30:38 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id bp7-20020a056512158700b00492d0a98377sf4151639lfb.15
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Sep 2022 00:30:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662622238; cv=pass;
        d=google.com; s=arc-20160816;
        b=oHZd8xWEzZWZeXsvPuFKNKdW0sEEpUSLYQYEpznFPPfwlAKu/Mz2qfTo3Dsia679Pu
         iFgiK8YPBEtZ1OCS/LRbYmFh/91q6Ld0SLNA3nFN0aKuzX1XunOOJRCx3SfCKAqxVaPp
         SZqHtO+Ea0Y/mhdzqgKztUzbVuEPHuYRFLtSo+MJlG16s819wwtXv6sKXXTLZpJ9TifR
         kM8NyQCRqyP6sANnG7Z9DPjzyuDvoaljxVTMAToPRWXrLUexEmnlKikZmWPeoQJ1VWu9
         7lECLwerongtu9SvAgstJRcN52X9kC1rfin7QFTR/suvNimrMMK2aA1R0/RmuAm2Rmcn
         aI/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FB5RfG0wA6bLmJEBpjTDM7kjwyRDnbWoK4DhEFKk94Q=;
        b=lL/acIv/xX/vANUxIFk41TFVTdaVvM0HoGoMNZR2em9R1GsLY1YtsUMFnPjd+LItR6
         XHQwFAd7xdpOGyuinfstVTInh5y0P11RI/qXDLoH5kx774MmJMUpKHBIM2xWZ27t9BXd
         KKVG16wcjUMoDIHR32oNE2kwJ15n+EPhfPwD+P+skFr0al9LSjcwJOfCg4yS50G/It4C
         6Z0NRsT+Z7xyx9IF96nlvlSW2RVeCMbDwi7SVjCG/l7fg7X/WlzGcBp7axS7Bt+pkjOj
         cWHUkIGLFC8npZl3NUFKKHbZIQbdBRVyyhKQAJu5MoIrQ0kRkdY93Ak+p0lCCjWNyqFU
         F+HA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Fw8tAVGZ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=FB5RfG0wA6bLmJEBpjTDM7kjwyRDnbWoK4DhEFKk94Q=;
        b=lc7n9OPdBdXgRlgTIQxlmNEDavkcMDe/3WhsR113lmdCAzl+GYGNg1+XpWlhyny2kc
         1/wiGA4VlPyfFckqeC1w1PWCK3yiutvGhLj0vbTMMOpnNADKLcSom10npxmV+riatoEk
         5w+eoFLTwHuSLKm6UYWgDRf+YE8zNRdDHb9TyMcQ4ppGxOvUSv0cCwlZV4HWeY2rS8K6
         s5nML8gufqpNHr7K876MLVJ50fVYLVZkhJxz0eEz+2Suawu2cNihOpGXAWQDAgzovk4o
         HX4pgRS3R58d1y8zDsLxbDVEzMpAzL4kGnnCA3ZyI6K4/P6Bnx+MeJHp1NAK/FCSig4Y
         GpBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=FB5RfG0wA6bLmJEBpjTDM7kjwyRDnbWoK4DhEFKk94Q=;
        b=OSC3W13mLgZu+9Cj/Tg8PvweYwuV/wmLKxIXmKeYzHloHONuIzRIEWJOqznRvkXrHB
         suwX4OhAreSyzSTRClRS8iZ/tLpTfShWwQLT/k0cBA5jiDbZ9nIaloVQAHOjbpY5rSHd
         GMO5ivDOncSDdw0FyEKBZVRFgUOWzyornfVcR1MS2gyLfYqSfKRvE1/IAfl7akPcBeEF
         7axVprPlou4ZKZ3znIxrQ7zdL1pTHGCXcNrb4qT0p3OASdsVfwcv/W7B1GJHRKgZhcGy
         D/IOViJvGNM8MMvwRqU4m0OVI2ytJxWq9yMAgnC58Lfmbmm0Pd3B4CcoVcv6kS+75a/u
         l2EQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3QCw/b2hkXJy4LXVPK7C84EDK5sNxfe57iutVoqaIOBu+VLXv3
	Lcnwk95CV5CnNNb1Zb3V7TQ=
X-Google-Smtp-Source: AA6agR6/ZciDJwvimLuWv+WomKsQlZaNR1iqqR0514Vkx1GqEZ7HIt7Bz++Ybnxw0qB8IOLaA+MT6A==
X-Received: by 2002:a05:651c:1033:b0:26a:aa02:b0fa with SMTP id w19-20020a05651c103300b0026aaa02b0famr2253222ljm.82.1662622238222;
        Thu, 08 Sep 2022 00:30:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls671297lfo.1.-pod-prod-gmail;
 Thu, 08 Sep 2022 00:30:37 -0700 (PDT)
X-Received: by 2002:a05:6512:1395:b0:48d:81c:5159 with SMTP id p21-20020a056512139500b0048d081c5159mr2579554lfa.375.1662622237401;
        Thu, 08 Sep 2022 00:30:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662622237; cv=none;
        d=google.com; s=arc-20160816;
        b=XvUWaowzOTNwoYo7HTqQ49nUedbhZb/kQ95xjWFmwxFRB4e+w/uOpnTOkLshyEsf8E
         HBtZQ5wQd1x2k4CiQRD02qeR1Lw8QyQzhlUZkXJ+Vu3xgJLsYkODNjVReNUtezYAtA9D
         2Mg12PRvZ8HeSQO2yBmkA6ZirxS4GTvorCCqZFIQe1D2lFngjDk3AUCirxjpNQttiFKo
         SDg8oK6ijiRKHFmBsSuARI5/rJtzPegTEL3z7+v1PmPnW2/udSzBmrm2k1QLpqwZenyZ
         9hS3zmQZgwpXCkKvAiKWyoyrBQijaV+J4uquxO6g9aQ/NKQDnHf9z+RlMtBUlzL1VDDz
         QZew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=DqfWXb2eEuuOxMq6abU6PffruFzdNn4Aud1F5cFJAhI=;
        b=Ss7Y9m0B/h4gafgpSLRgOL1Ny4Dq+anVtlNiih07cdBdkXQ31TcuTT2shKrOd9Dk7q
         lcveoNlFTl0bnB+c7/T96p8gRRzr7d3AbXCj+JTpTaGAbmABqxkgT4rMMtok9zny7PGg
         BBGaOA5yTqhYL7IhFQX/NAozCpWt/foDnTgY5yKdB9sQRJe1WRZGJeVHpTRyXBHTwjbV
         Zz3HFx5IxUEAEkaX/r3nNsvVC/QtFxp6Oxek+1KLZhdYtgBjtemoZiDIQNUoz5wKk3UG
         WCjPa9O7FV1259LymJyhGzn7rA/vdJLOL4jnwIXhlNA6qXezsF0AiY1uy4RJC1Fw0BLx
         Levw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Fw8tAVGZ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id u9-20020a05651220c900b0048b224551b6si882556lfr.12.2022.09.08.00.30.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Sep 2022 00:30:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
Date: Thu, 8 Sep 2022 03:29:50 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
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
Message-ID: <20220908072950.yapakb5scocxezhy@kmo-framework>
References: <20220901201502.sn6223bayzwferxv@moria.home.lan>
 <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
 <20220905234649.525vorzx27ybypsn@kmo-framework>
 <Yxb1cxDSyte1Ut/F@dhcp22.suse.cz>
 <20220906182058.iijmpzu4rtxowy37@kmo-framework>
 <Yxh5ueDTAOcwEmCQ@dhcp22.suse.cz>
 <20220907130323.rwycrntnckc6h43n@kmo-framework>
 <20220907094306.3383dac2@gandalf.local.home>
 <20220908063548.u4lqkhquuvkwzvda@kmo-framework>
 <YxmV7a2pnj1Kldzi@dhcp22.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YxmV7a2pnj1Kldzi@dhcp22.suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Fw8tAVGZ;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:267::
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

On Thu, Sep 08, 2022 at 09:12:45AM +0200, Michal Hocko wrote:
> Then you have probably missed a huge part of my emails. Please
> re-read. If those arguments are not clear, feel free to ask for
> clarification. Reducing the whole my reasoning and objections to the
> sentence above and calling that vapid and lazy is not only unfair but
> also disrespectful.

What, where you complained about slab's page allocations showing up in the
profile instead of slab, and I pointed out to you that actually each and every
slab call is instrumented, and you're just seeing some double counting (that we
will no doubt fix?)

Or when you complained about allocation sites where it should actually be the
caller that should be instrumented, and I pointed out that it'd be quite easy to
simply change that code to use _kmalloc() and slab_tag_add() directly, if it
becomes an issue.

Of course, if we got that far, we'd have this code to thank for telling us where
to look!

Did I miss anything?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220908072950.yapakb5scocxezhy%40kmo-framework.
