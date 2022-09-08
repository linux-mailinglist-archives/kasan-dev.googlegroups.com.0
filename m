Return-Path: <kasan-dev+bncBAABBNFJ42MAMGQEBAO2VTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 85CDD5B155A
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Sep 2022 09:07:33 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id h129-20020a1c2187000000b003b3263d477esf104774wmh.8
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Sep 2022 00:07:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662620853; cv=pass;
        d=google.com; s=arc-20160816;
        b=ylEbz1c8rKAn9k2GdLAuPuyKtxs8CMJs6FXLgK70XRuk4RXxfDmn7mRUxaVdCAs/L2
         2VSIEdbLU1YR4GIVBZ08R1Ijlhkm0rh5rXtmvw1/oVM7kxHQ61NONqrSbk2zEXqWK3Sy
         jPpx+0hZ5PV7jQZoepZhF62qvszDL/D1+bJj9Ff0Msj2btBezCe0KVV8UlvydIXAeRut
         brjyXbJ4s5pt0CDgnp/d4anXGQuQsU9lTP+q/KV13Uvd5SfH01egs4rljpiG5ODBJpOZ
         2bmKq2Yuxt+CmixGW1s0SSCMAEJh8pqtKNVL1gFe4tWk9hN4/ql36Zesbk9WqeE6yp0j
         E1cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ijJYqwPOa4bMyPKmrZUfbeKE/OUXLvydAXXOc+sUZMo=;
        b=nAdOXvzxdj5hAnkIE9gAmdwFmE8jcYtjq9wFteiG3TVJxv9cAQTtWhY4D68vfwNEY4
         yi5vbt1A3haPpSLPTYKJegJ0H/JM1j0lv7bdbGs6ILbFN7mZGLJGdhOvYI9GAzoaGEZJ
         FarLIWUfj7klFoIQW0hBB7S9uZHir0y9qZa2WlE0hMTPMIm7JasGW2ze28OviUUaEOgh
         6FWPaQFIBE9D/utmiBSRL8dBCZcTd2BA5Bz1CIjTQQ6h/aR4nIqQiq2JTEJO85cykSmf
         dJAA9J/uGizpJ0KDHebMZYi73ApJUGPqtr6v9BDd0zKCRGz831/+aPpZqrNGBlc6lZlV
         OBJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iJA14xap;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=ijJYqwPOa4bMyPKmrZUfbeKE/OUXLvydAXXOc+sUZMo=;
        b=Htp09v9rw5p+UWuhY7zuW+ETT9bUW+RJH8ovqqESS6fJ0B2t3MJbPCCl8Adx6fSwy2
         Y202XlLoYEYjqYcxQqFIwl58O6bZHCgSv+nLaDSGi1VOvFXZXF1DKxhXYD3NYL4r3XRJ
         ob+/8uH+qO7KpIpF5iC681Dt+tZ1o+QPQV0kEOiJLttgXxjqorxZFpJzgb2AW7JNinuv
         CLItrggfLjSxosIzHWMqIpd7sTpkpqi7mzsy1hUMCKePbXhushxGhySFa6t7TBmv+Umq
         HQTEEDRdXlVOKqYVk3DbqCZAH9D1d4/bwLSYA1M1sit8ISqhfVKNIlhbm//vfa0v5o/s
         uD5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=ijJYqwPOa4bMyPKmrZUfbeKE/OUXLvydAXXOc+sUZMo=;
        b=OTi18qXPyF3zUAxq0Cgn83e37fJffdRBZv24ZB4uqUMqJQ6is8jHNgnV645+VZ1wMz
         IsJSGSI7xFAfY7iWrqfOz97JedEpb6wBroZaq8eQMcYrQcL5yCwUFo1i7qwiEIINc4X0
         ftwhGfFNBq8PCCA3eycFEKbEao51ONNIvpXkQt5cJ36yanjp7MhxcuVz58ZnMG0XxEV5
         WNHCXQuMY3vae5uUM5HNLgF5ikj97MEBhz37dbmTJAAcBdD7D/RP+gPYhpxPxX9thTWY
         jjX9QXjTQs04H+9xchlK2EUY8ubdkV1lBqDY8gQ2c/55i2aWHVpBlZVik1L5YCzfSt+u
         WbWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3dia4ChOGaepfGbHLCX6hxXCYYsk8f0J1M2foFK0UBMtunNKOW
	s/5htpJ2QKCT4hhJeTOKZ3U=
X-Google-Smtp-Source: AA6agR5IP/1NYsNFNrxy0/bdBeC9WI5y5uuMVl9imBkriNZm0CFLcA8twbqzY4ZAXFP+9F1IT1dmMA==
X-Received: by 2002:a1c:ed0b:0:b0:3a6:30c:12f with SMTP id l11-20020a1ced0b000000b003a6030c012fmr1155654wmh.133.1662620853016;
        Thu, 08 Sep 2022 00:07:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7510:0:b0:3a6:6268:8eae with SMTP id o16-20020a1c7510000000b003a662688eaels309088wmc.0.-pod-prod-gmail;
 Thu, 08 Sep 2022 00:07:32 -0700 (PDT)
X-Received: by 2002:a05:600c:3b10:b0:3a5:3357:ecf4 with SMTP id m16-20020a05600c3b1000b003a53357ecf4mr1161631wms.193.1662620852253;
        Thu, 08 Sep 2022 00:07:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662620852; cv=none;
        d=google.com; s=arc-20160816;
        b=rYsJCjJZy7kBjOWx0AwRjH9QyVpUOV3s6BblTHV0+k0/3jSfRGfDCu57P/5o+Geh90
         0bl42GLNJmt14587jLtdxCBYNwob9tmjdat8gluYyGzK/UHT5gYbQUS4RQIgyZos1Ss1
         qTVzU4hjWYhRItAhk5flxmtAzV0umyShiFon4q3GOTd8vaWQtQjkQZ9omiumpaedRmWo
         626HdNEnKgu3N1Z5gaOzEpJc+MnUizCQj2N+dTazlnsslkFTcoT9x/vH8wZCyGTynA7W
         R6etc9PElofmAEca6sDOMqer828ihr6j03rXskT8n7i9QGFK/zuJVzCXCllw1moElI0p
         vo/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=wTEYgGZ5tSon77wS7vl2ROsEnkkCO0gsMgQptW+CPqI=;
        b=BB/i+S0P7UhjIlfe5pPFVs2n/BBKOo/gy16/3n+RwNSpJMIF7OlGX/yh7faNPqppgF
         9epn0AhwH9YrTvgo77jK9DssPq8frvt92h4Ckf/XAF5pV8jWBV4bTtV2p2VLQrFF7onw
         ctXBf8YqjskYAA/BcKEUwMG3EBRXVpNu/VMopy7rS3X3uimUTTK+jb+SvYIJtwuxTRe+
         hz8PChSEzdPQt55uf6Z8cH/AId8FaiJcBKz4XAwB+BRGmGmRT/wBpCskkOETnHk+Uirx
         5KMW1v0ipKTQ0/Rah/2EDYdbvZrY8+IqLusr0osRnUH2rbGF8IZBR4iSbq1S4Y9jE5m9
         xUnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iJA14xap;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id n64-20020a1c2743000000b003b211d11291si202140wmn.1.2022.09.08.00.07.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Sep 2022 00:07:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
Date: Thu, 8 Sep 2022 03:07:19 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Michal Hocko <mhocko@suse.com>,
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
Message-ID: <20220908070719.ootyzzbd47dd5rkv@kmo-framework>
References: <20220901201502.sn6223bayzwferxv@moria.home.lan>
 <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
 <20220905234649.525vorzx27ybypsn@kmo-framework>
 <Yxb1cxDSyte1Ut/F@dhcp22.suse.cz>
 <20220906182058.iijmpzu4rtxowy37@kmo-framework>
 <Yxh5ueDTAOcwEmCQ@dhcp22.suse.cz>
 <20220907130323.rwycrntnckc6h43n@kmo-framework>
 <20220907094306.3383dac2@gandalf.local.home>
 <20220908063548.u4lqkhquuvkwzvda@kmo-framework>
 <CAJuCfpEQG3+d-45PXhS=pD6ktrmqNQQnpf_-3+c2CG7rzuz+2g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpEQG3+d-45PXhS=pD6ktrmqNQQnpf_-3+c2CG7rzuz+2g@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iJA14xap;       spf=pass
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

On Wed, Sep 07, 2022 at 11:49:37PM -0700, Suren Baghdasaryan wrote:
> I would really appreciate if everyone could please stick to the
> technical side of the conversation. That way we can get some
> constructive feedback. Everything else is not helpful and at best is a
> distraction.
> Maintenance burden is a price we pay and I think it's the prerogative
> of the maintainers to take that into account. Our job is to prove that
> the price is worth paying.

Well said.

I'd also like to add - slab.h does look pretty overgrown and messy. We've grown
a _lot_ of special purpose memory allocation interfaces, and I think it probably
is time to try and wrangle that back.

The API complexity isn't just an issue for this patch - it's an issue for
anything that has to wrap and plumb through memory allocation interfaces. It's a
pain point for the Rust people, and also comes in e.g. the mempool API.

I think we should keep going with the memalloc_no*_save()/restore() approach,
and extend it to other things:

 - memalloc_nowait_save()
 - memalloc_highpri_save()

(these two get you GFP_ATOMIC).

Also, I don't think these all need to be separate functions, we could have

memalloc_gfp_apply()
memalloc_gfp_restore()

which simply takes a gfp flags argument and applies it to the current
PF_MEMALLOC flags.

We've had long standing bugs where vmalloc() can't correctly take gfp flags
because some of the allocations it does for page tables don't have it correctly
plumbed through; switching to the memalloc_*_(save|restore) is something people
have been wanting in order to fix this - for years. Actually following through
and completing this would let us kill the gfp flags arguments to our various
memory allocators entirely.

I think we can do the same thing with the numa node parameter - kill
kmalloc_node() et. all, move it to task_struct with a set of save/restore
functions.

There's probably other things we can do to simplify slab.h if we look more. I've
been hoping to start pushing patches for some of this stuff - it's going to be
some time before I can get to it though, can only handle so many projects in
flight at a time :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220908070719.ootyzzbd47dd5rkv%40kmo-framework.
