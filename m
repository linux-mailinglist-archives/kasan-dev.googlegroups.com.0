Return-Path: <kasan-dev+bncBAABB34W3KMAMGQE3CDSJSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 31CDF5ADBFB
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Sep 2022 01:51:12 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id r23-20020adfb1d7000000b002286358a916sf793045wra.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 16:51:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662421872; cv=pass;
        d=google.com; s=arc-20160816;
        b=R+FjtFV7h7ag6s/bFnnm4qdfsLAQajyMstezqcwubYw5sQFpSSpPLz6vkZ/eBb1Q2W
         Vn/RldWNgqW4v8pccCNlSr0FxyI67BIxKr9gcO5ew52CwcAoCUSbeFcx+01gp/ns1JvR
         xpb3gaTlLLhAqkBtuOjMFdTw1MUDiURp9yQjbbXB8ZtIQhXBU966r4Qo2FcHtjY3xmYh
         PjOIUc2x0ZPzdxhfTaWyazeZLf6QvIQclNfpmapDDTSyqSC4ndauOw9JSARNIhihOcyP
         yIcXx5FOZ23enmJ+uX+0Y5MAYv6Vqog2ZxfVR/uwhMh/MYJe2t8h5DRZlL/vJJyfOOsj
         qNzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=g5KMDuhyj3+ZAsA0v2gueCaMsRyKiCFigzIQ8hvZdJ8=;
        b=ckG9J3PY/vDfv0uoKMkRXWMIankOZnoL0x/F0NLSY5DNtFXMq23GTUP+uNC+kKJck5
         IMWL/V3sstTJIdKQ0odxx5md+0zaX1AejsF6b9JpHur9dKUXTDrfTQzR/BAAFMtZg11x
         a3yXTzgx8AEvsz/8RNGCmTZcqLMSVdAjOTQX3xwcHi37QHF7s2L2JzX25nHvOdaECSzb
         YC1Ng1Dg1+l6T2DjRyBIWO5h6lZMOQ4SnfW/z/Tlab6SFOyBpPntx/LnwPInL9DELO7K
         ph3459XYEUlUN2CeqpzxzTU84fRFwkj33H0EwM6Gs2khlUan0Z1Tx63OOIjj3XKOualj
         drhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=K0AUlJQw;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=g5KMDuhyj3+ZAsA0v2gueCaMsRyKiCFigzIQ8hvZdJ8=;
        b=Kccr3FpA1UklEypCNtKXgIGg9N9ENnv+HVAKxChgV+AaKYEKqVj2e4scuj/1FkNNfd
         MHWmuA7FpQbRJf+oLDy9n7FIW6AjdiQ+786q2p/BCuMI1wp22QdohSlLpqs1ETcbF7yq
         deWUotCTK/KuBCmluzlbTGSwS/uZdRzwGsUw7lrL0dbUqkvx3A4ng9Bq1ZWYl8o/fwkt
         2E5Pga3l2lXHFk3iL6n4FULQcfi4ArKPLIQuaWc55aarc4hlVP0kv9oDJY4qo2K1LR2V
         8798rgpo6+Ae1Oea1JEsEHyHjHyukA8Eoh/ZOu0aN0itrWM0Hd5APjOkSy2HfnA8wJR7
         xeJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=g5KMDuhyj3+ZAsA0v2gueCaMsRyKiCFigzIQ8hvZdJ8=;
        b=zL5suo7CH5EOyHLapHhnKTii7g49pMI9esDtXgTbv6KQ6wAmQX+R6SnJtoV1dpBUAM
         Xwg7dI0CvJz5DbxG57mbeK7nDnVcb/uFj6++jxxTfZivTkSJoROvqG/xYpaeWcl0JwiU
         X3FwCWBA1OzaRXuy1hHD/IXWSrBUsbt5y0e87Falf5+fYnBz47PNLoULV4SyKSAYP3fh
         bRPYAoMPK4plCnIepT5hIdK2jtPxs2ix1h/LqwT26zu0mNYj29jS6E/mBwVWp5CF+8IA
         nTpYNbr8OJCgdHJBmlWRh3VidcHt04IJnvIeNoekFPkHzETPymhg/jZ3A6gdyLI6HmT6
         7zkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0/L2QWLzCrFgvUT2XB1A8hEzwra+3XZlyFFd+tVngHtF8JR6u9
	dFILxAr/3nkY04KustTIams=
X-Google-Smtp-Source: AA6agR4LC5aA/FB7lJheT+uj8ivCIhzVkX0ib2C90SpQXW30wJswES0eDijy0EoEChgaq7PTO+7blQ==
X-Received: by 2002:a7b:ca42:0:b0:3a6:9d:a444 with SMTP id m2-20020a7bca42000000b003a6009da444mr12291026wml.51.1662421871837;
        Mon, 05 Sep 2022 16:51:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5b08:0:b0:225:6559:3374 with SMTP id bx8-20020a5d5b08000000b0022565593374ls551559wrb.2.-pod-prod-gmail;
 Mon, 05 Sep 2022 16:51:11 -0700 (PDT)
X-Received: by 2002:a05:6000:1448:b0:228:4813:a511 with SMTP id v8-20020a056000144800b002284813a511mr9021331wrx.715.1662421871092;
        Mon, 05 Sep 2022 16:51:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662421871; cv=none;
        d=google.com; s=arc-20160816;
        b=ahSM0+G3bmG6riK2J2mV5zmD5jd6PfRKDWx6o0aAoW5LKVuUSMoAjA+VOVJWcRMudl
         CWchx3zzrx7gXAXEcz9n3ChjUnqFxqaTG05c22TczRwIlmtYuVJiiffbl6yY3K678xIB
         IJ9SwjoO+p6yGEZNicrMODp0aeUHDe0+9rghKDYyzzILeKHVifiaRCwZqkYDNX9mpnME
         PYS2pkUwqtsH4jRTucw/c3BoTWOpeQjtTkeEInwgG5sWxTdnu4CX5ADmuIx86JeRyyTQ
         ZUsmXTi0DDoofuO7TciapWZ9L/SUggU4YE9z8TFBrjEyU1/5EKOahe3sLemcP0E4ABl7
         FBRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=L/QtR7clKwa18sm3kCbVwFkkFjR319r9zDLdSKgBl/k=;
        b=aLzP/lo70M2ptdDM7rVK+p6yC0UbFHX3RKptwSwg29aRdQ+YfxyhX0soH0aSULp9yo
         TSFstXcYtYE5pCLnA6E6XIKo/fo4wwMmGLM/yyUzbXzKwfFfAmI1UnDRJZg8oDxVrfaT
         +1iabR3s9+HrOO7s+mXkinawga6MXn+tNAnrBjLALRtN4kThkU2XAc108i0mQ/8EY7OR
         T0p0hvce1UYB1g8lCVyD5wNM57xAosE2IjwcGpfBBvLeXaSMb6dDaf2s+w2A44j5bCMn
         CjRg/hu+dq/BKKCScC2ecGvc8x8RhVu6V5CwdV8vKd/jII0viUHXVl4XbQqeDBltI7NW
         VqDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=K0AUlJQw;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id bi19-20020a05600c3d9300b003a6787eaf57si1331625wmb.2.2022.09.05.16.51.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 16:51:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
Date: Mon, 5 Sep 2022 19:50:07 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
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
Message-ID: <20220905235007.sc4uk6illlog62fl@kmo-framework>
References: <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
 <CAJuCfpFrRwXXQ=wAvZ-oUNKXUJ=uUA=fiDrkhRu5VGXcM+=cuA@mail.gmail.com>
 <20220905110713.27304149@gandalf.local.home>
 <CAJuCfpF-O6Gz2o7YqCgFHV+KEFuzC-PTUoBHj25DNRkkSmhbUg@mail.gmail.com>
 <20220905204229.xqrqxmaax37n3ody@moria.home.lan>
 <20220905181650.71e9d02c@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220905181650.71e9d02c@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=K0AUlJQw;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Mon, Sep 05, 2022 at 06:16:50PM -0400, Steven Rostedt wrote:
> On Mon, 5 Sep 2022 16:42:29 -0400
> Kent Overstreet <kent.overstreet@linux.dev> wrote:
> 
> > > Haven't tried that yet but will do. Thanks for the reference code!  
> > 
> > Is it really worth the effort of benchmarking tracing API overhead here?
> > 
> > The main cost of a tracing based approach is going to to be the data structure
> > for remembering outstanding allocations so that free events can be matched to
> > the appropriate callsite. Regardless of whether it's done with BFP or by
> > attaching to the tracepoints directly, that's going to be the main overhead.
> 
> The point I was making here is that you do not need your own hooking
> mechanism. You can get the information directly by attaching to the
> tracepoint.
> 
> > > static void my_callback(void *data, unsigned long call_site,
> > >                         const void *ptr, struct kmem_cache *s,
> > >                         size_t bytes_req, size_t bytes_alloc,
> > >                         gfp_t gfp_flags)
> > > {
> > >         struct my_data_struct *my_data = data;
> > >
> > >         { do whatever }
> > > }
> 
> The "do whatever" is anything you want to do.
> 
> Or is the data structure you create with this approach going to be too much
> overhead? How hard is it for a hash or binary search lookup?

If you don't think it's hard, go ahead and show us.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905235007.sc4uk6illlog62fl%40kmo-framework.
