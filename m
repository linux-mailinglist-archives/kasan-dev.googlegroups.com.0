Return-Path: <kasan-dev+bncBCX55RF23MIRBKMDYCRAMGQEWRUS73I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id D24496F35B4
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 20:15:05 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-509e422cfb3sf3342259a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 11:15:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682964905; cv=pass;
        d=google.com; s=arc-20160816;
        b=I9442yWzIxGsqd7SsW0a4xYos9zjXDmK7ijhrNe9CUMuxwHSQWmoyhNXT8g9mTbadr
         CJzdG/0G355YUW8laVR+Fn0ogtp3/4OBnXBiKAX5zW009qHDfZG2g/xkzOHXJ7fwSTp2
         ce6WX4zTUXne5oX2w1Y7t3qA/k8QOc4XFO9Is1YEa6MZ3WzZ0a65J0NQ3SB4SIaGY1vz
         Wf47Ajbko/+EtW+ogW8OXZRQDm8+0HPhCJOKpYM6RhgYyQBTJoiTEu838hGk2WaDyy8f
         7CLCBz8Zq8rD3ai+AROqj+9ZJ9ESzvlKK6YjYBhKdOh2q/++vRjCXK/L5Iu+AkiGwVLi
         TqtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=FF/4JYQ4qukKy5W3L8AVaqFMihs5iBbDwHSLQj36OGw=;
        b=oUvnZ4kjV89xhrAjZp5Qvk4ptV85PW8TOdIlP434+jjrtCfHlM70OOyghGrwD1I4vI
         yW5rvvQ63pRIS7bRJQCXkBlBu6f8cW2+4va0tMPLyfPPMN02wWaRJzTsPwUTgdCK1SvS
         5WHSMyz6ht04gi+JZeU+cqxFr1VekVrQONzchLCrBUNzrzakZxqmzGMdSZuSNJ1OMK/c
         xTcw8B6PkhXk32gy4alZTKmZCQt9ClUKtiMsiwJF7jFHkGnSthDYPEd47pSLwoO92vEK
         rjmW+dOMbL7n7mq4l1il/wx/IgCluiJQ0IFawfIGisJYFCLBmd3Gcjr8sJ+Y1uMXck6u
         bhJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mSi6IKlT;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 95.215.58.50 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682964905; x=1685556905;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FF/4JYQ4qukKy5W3L8AVaqFMihs5iBbDwHSLQj36OGw=;
        b=XoUnIHICRJXJuMhZqYHgkUlaws62YwqjTgA3z9lqyZlr4e+yeKdU+WAhHG9o4jjCC9
         olOEVsLpXx+LYZM7IbWMCW0YtjkvM76D02Tb4wYBPxWrVBY907jRpb712/PFXMahcVxs
         /XVpB5jZes/BSN7cTRWFYN6HIjaFfxcEjuUc7U9lZWCC/PxQOJ7esjh+C6sXcAXXILVJ
         OSijAa+FRXQXvp3/Un0fD+xCeEQIq3KpA2ft3K6QSDIyt2zZI5idYk+M19Vy5P/ZhAfT
         jowUZSxhrk+h3vc3puHs+/TepU8OWPTElTu7vY2Jkbz+crsRjPL6dfh3WJEeh/CjQicq
         i7VQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682964905; x=1685556905;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FF/4JYQ4qukKy5W3L8AVaqFMihs5iBbDwHSLQj36OGw=;
        b=CNeNZXh5HXBsIrclbTSBxND7rj/VSCV5nqyRImab+cvYoTqxfGTcWeLfxd+oy9ljfH
         6nFxDnQ0FoWrhz7UCXjpVHiCqjdGYXuEkJqOcv/sBZp/JUl3BDuKvAOE6Q+4YFfjPjcU
         w4v4zoDHnoQxEf+Utb4jYmjbffFrMj40IlW4mx1Hk+zskdbI4udtKrXLyXiq0/fMfZmZ
         5EbPPao1H2UbvhkzjlsHMRpZrI31D2c560Y2pp9sPP13/CC+H3Dw06fxudodjtOv2bLE
         SCsJTeSBzTXiAUgzNxGDbFcpvP52DQhuAzX5jPPiudm0iQKu8WxC6/1RhC/UOGau1o79
         hQiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxqsmTWiFTbOx5hY7N+krBBVfCWp5Q0OgUI2urc65Bklg3DU5uD
	N5/v99o+g8iMrgYzE5t+JVI=
X-Google-Smtp-Source: ACHHUZ5kjnahMIHM1nxgvoQunj0O8vo+rm13m4TWAT4HqAnO93UdA483EGO6h3jPZOz+8NIqw8uyHw==
X-Received: by 2002:a50:9fad:0:b0:50b:c82e:270c with SMTP id c42-20020a509fad000000b0050bc82e270cmr1095356edf.6.1682964905330;
        Mon, 01 May 2023 11:15:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:190e:b0:50b:cc92:508c with SMTP id
 e14-20020a056402190e00b0050bcc92508cls719678edz.3.-pod-prod-gmail; Mon, 01
 May 2023 11:15:03 -0700 (PDT)
X-Received: by 2002:a05:6402:345b:b0:50b:c5dc:28d8 with SMTP id l27-20020a056402345b00b0050bc5dc28d8mr2893041edc.16.1682964903904;
        Mon, 01 May 2023 11:15:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682964903; cv=none;
        d=google.com; s=arc-20160816;
        b=JYkhRAPCmc1vPNG/lAst2p9a0+J70qHPeOIqByfk28CGxlDFaX6PTpKJUXEi1/MiJ3
         mw4Ro2Y+AIAQYo548/sI7nbKH8KEkNuHJevuijbKCj9MOuIzsHfGPWUV5I763jo7Ihv3
         f/ltFQx5Q9+NNpGaRUusU7xibptQNV+0Ff49UeWN9cu4QZshPvjoIJPJh2WUADkI224T
         7T4RjRS3qPPYmS67EWIqKmvncnmsTGg8hGLciyie9vWjMk0vA2r+xageUkNTIash8wQy
         seOArsnhyMO0q9Q4/EpOsttc2xFzeQRJnV5RwLGCftex1EhKSS1QvGsaTpyC6RxevUPZ
         gGpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=b6T2XIeT8518y54zvjorB3kR8+9w+3ujz9aAR//CBsM=;
        b=TQcjgt32rM0TV8ytYtp4FJ+x/m2DsgimRn7G2Y2SQ3Up3wkACGEKkZiMSBQM4nDmTN
         SoR0+btoWy31KrWRfDdAxZtrdenpffE4PKkrwgIPQuAJaDwOEXKgWzymHE7cR8yfQrLO
         vC3/PwsK/z8lmR0Du0cYKe5b5p74xsSiYpQ1vx2hEk9P29dp7KFgf6zCA01bfqWR2HLT
         dQH54zcUKjP8mtDDHhPB7o0abf3UVtvDxcS2AYsgQOQ+Tm2OtlM45UY6CupUdw/Kg9g5
         hVQYJDP3aAe3DeB5wO8dTPXwFBFfVVWvUuQ69KfyEPvtyJq5beLOntGhmhMLIGBfCscV
         xceQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mSi6IKlT;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 95.215.58.50 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-50.mta1.migadu.com (out-50.mta1.migadu.com. [95.215.58.50])
        by gmr-mx.google.com with ESMTPS id fi27-20020a056402551b00b0050b87b70258si265426edb.0.2023.05.01.11.15.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 May 2023 11:15:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 95.215.58.50 as permitted sender) client-ip=95.215.58.50;
Date: Mon, 1 May 2023 11:14:45 -0700
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Roman Gushchin <roman.gushchin@linux.dev>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
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
Message-ID: <ZFABlUB/RZM6lUyl@P9FQF9L96D>
References: <20230501165450.15352-1-surenb@google.com>
 <ZE/7FZbd31qIzrOc@P9FQF9L96D>
 <CAJuCfpHU3ZMsNuqi1gSxzAWKr2D3VkiaTY0BEUQgM-QHNxRtSg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpHU3ZMsNuqi1gSxzAWKr2D3VkiaTY0BEUQgM-QHNxRtSg@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mSi6IKlT;       spf=pass
 (google.com: domain of roman.gushchin@linux.dev designates 95.215.58.50 as
 permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;       dmarc=pass
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

On Mon, May 01, 2023 at 11:08:05AM -0700, Suren Baghdasaryan wrote:
> On Mon, May 1, 2023 at 10:47=E2=80=AFAM Roman Gushchin <roman.gushchin@li=
nux.dev> wrote:
> >
> > On Mon, May 01, 2023 at 09:54:10AM -0700, Suren Baghdasaryan wrote:
> > > Performance overhead:
> > > To evaluate performance we implemented an in-kernel test executing
> > > multiple get_free_page/free_page and kmalloc/kfree calls with allocat=
ion
> > > sizes growing from 8 to 240 bytes with CPU frequency set to max and C=
PU
> > > affinity set to a specific CPU to minimize the noise. Below is perfor=
mance
> > > comparison between the baseline kernel, profiling when enabled, profi=
ling
> > > when disabled (nomem_profiling=3Dy) and (for comparison purposes) bas=
eline
> > > with CONFIG_MEMCG_KMEM enabled and allocations using __GFP_ACCOUNT:
> > >
> > >                       kmalloc                 pgalloc
> > > Baseline (6.3-rc7)    9.200s                  31.050s
> > > profiling disabled    9.800 (+6.52%)          32.600 (+4.99%)
> > > profiling enabled     12.500 (+35.87%)        39.010 (+25.60%)
> > > memcg_kmem enabled    41.400 (+350.00%)       70.600 (+127.38%)
> >
> > Hm, this makes me think we have a regression with memcg_kmem in one of
> > the recent releases. When I measured it a couple of years ago, the over=
head
> > was definitely within 100%.
> >
> > Do you understand what makes the your profiling drastically faster than=
 kmem?
>=20
> I haven't profiled or looked into kmem overhead closely but I can do
> that. I just wanted to see how the overhead compares with the existing
> accounting mechanisms.

It's a good idea and I generally think that +25-35% for kmalloc/pgalloc
should be ok for the production use, which is great!
In the reality, most workloads are not that sensitive to the speed of
memory allocation.

>=20
> For kmalloc, the overhead is low because after we create the vector of
> slab_ext objects (which is the same as what memcg_kmem does), memory
> profiling just increments a lazy counter (which in many cases would be
> a per-cpu counter).

So does kmem (this is why I'm somewhat surprised by the difference).

> memcg_kmem operates on cgroup hierarchy with
> additional overhead associated with that. I'm guessing that's the
> reason for the big difference between these mechanisms but, I didn't
> look into the details to understand memcg_kmem performance.

I suspect recent rt-related changes and also the wide usage of
rcu primitives in the kmem code. I'll try to look closer as well.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFABlUB/RZM6lUyl%40P9FQF9L96D.
