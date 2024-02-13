Return-Path: <kasan-dev+bncBCS2NBWRUIFBBIPUV6XAMGQEWBHS7RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FC2B854002
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 00:24:19 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-5118b336cd7sf15276e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 15:24:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707866658; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ojq+ZAKldhZ8ralAhXdeo9MXubsspmD44LnFv4RhtaOX3/CpDxjmnepUW+G7k1D7Rm
         iKmfLDrrtAP4zuKYlnVT4YEX8OwpBETvULNk3LKRQnoGrk2oT8eY/QppcdMGJF2N0mdr
         tFLuvTtbIYSxnCQvjpJdEhZrVWCHWosTXKkWSjFQZarex2qBcUxgWi2kxybuOMhoxhom
         JbQ005hS4AsZV/hghK1q8pZ45QU6YrMbN1Fk0pznaD8ENU2WPyrppZF4gzI2IJatkys+
         lrCprOY6J0PsWDH5aXeyHABvFD+LDej5wD0+ofCOuWH7lJsZHR+vAWviu14mtr+KGFjz
         YI5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=VSBhBsOozU1fo0l0xhOGyIEBO3JZU9ysxdsf5hDKwk0=;
        fh=V2uFrgqwmIZRyn2j6IbrY3rMYuq1CxsujVRRWYkruXo=;
        b=gP8r44okvonl4kRhxtgO7i79JZdFV9NmtUxZIIu3BVEMGCb/QTWWg7x1qvsChBciLd
         zF7K5cTYG28WNMXIoV+nIELS2VoACvxrS9/ydKRqfvjWnExQSCe17hoWcXfYKOIPndVj
         lE9KwSgdn1oAOF+sxV/lBKoJod9XN7wyTdDcv+TYgyNxSC7jenfOqAVewHxLsP+mQEXc
         bKH9O+iFGQL6xJ94JbvlqLbeUYsU/u9tsdvtSOJYzaEzYqTMiy37xOHR3+V3EFhCpRYf
         GTIPTcKuZolcygdAXXSvGpEtLCchSKdEi5ws4GbL4PymWBk2ykLRkX9UqifGH0okTTje
         oJXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=c32gpRAo;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ae as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707866658; x=1708471458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VSBhBsOozU1fo0l0xhOGyIEBO3JZU9ysxdsf5hDKwk0=;
        b=E1Ndd4Cr3sH504sFh2dd0ZguJG+Z9L4MQ6UCe8C1amGj+EsakSsJpmkby/exTJXw2T
         K7e2Y7qVdTxHlTzkaFUkmyZyatzZeSpgmsB4hCY6dIOqzluGTymv4bXNic8Si1tmMGgy
         H/JF59yWY7sgzG8Qe5PUa1X9ulfZSowpspcE0goDYAN83rT+3NBiIElhuk2787oc+gtD
         2DOEzeX1pPkg5IME4Wun0lksgNjQJvi4C3/uI5Rxfnbv0iOQSLOKzsKQ5efRXMkHjfAq
         TAXl/4ZNJ6NB08R5ynar5MQfYFzkE6KPtK/flQfKYiz/+ac55okuHDraitjh9ocv/yTD
         XgYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707866658; x=1708471458;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VSBhBsOozU1fo0l0xhOGyIEBO3JZU9ysxdsf5hDKwk0=;
        b=q/80ZXfY65s7tGLXLrPoxhhUM+zGq4gEI/R6hvfDCjVJfIFMe3ADZb1Jmu+E2vBbWJ
         UoAAnwniYmL7Qa5j0cOijiLXZqQ3W8DyrwnqJYiQD4euNOqZRHiin8FX1EbeO9jK/xZb
         HZdQNKm70wRUFv6NG8SmHZ9KzDqNARM9YWdSzaSm0L1OXsdGHlSKElw1CSCVeAlUBR/q
         Eyu1XgX6lTkhBd3K7bdQAU08YekAV1eoLbBBdbPvJ7wQnSR9YnYDxn1cuAt6YYhO+vu7
         wEbrzfXD2E29DrzKOiudRnMJQgUe9ICDV0wqgi+GVgOihkpoS291vdVzs5WMfw+eU3JQ
         2ZMg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3qdRu/pGT2rAtykZTZUZI/MabfLfCeheZf+paKVQHwSeDwrCKaYhRUpbVhFFCsZqY9pG9RBkMKhITFO5y8u/B4ocTdKjpZw==
X-Gm-Message-State: AOJu0YzH+9MzFP4TkhEe7gJK+8jNnjIeCPO0R5bSyJDoEXeM6EPYuu9y
	p5R6q7x7sd0CwoCbQ3VkRLtGQc1VYePY4ffEBG1bf1gAOOAuuE/S
X-Google-Smtp-Source: AGHT+IGEUfQeSxyNxU15uxAuMIR/xO2kv9p0chK3ZZeNMHKeTkO7zHoPWGT0aR6o50Z7rM/CgSwFZA==
X-Received: by 2002:ac2:4c87:0:b0:511:8ae8:e26c with SMTP id d7-20020ac24c87000000b005118ae8e26cmr65824lfl.4.1707866658067;
        Tue, 13 Feb 2024 15:24:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:168f:b0:2d0:f938:5b4c with SMTP id
 bd15-20020a05651c168f00b002d0f9385b4cls280061ljb.2.-pod-prod-05-eu; Tue, 13
 Feb 2024 15:24:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVokNJlEOI4w49mcF997zv0wcZnXTfS/sMObzfyUpCnGuZbYDId3I35zX0wje3NVzjpl1nhHKPabxF91I/8BP1levka80O9N4aD2Q==
X-Received: by 2002:a05:6512:39c9:b0:511:4683:d537 with SMTP id k9-20020a05651239c900b005114683d537mr704423lfu.55.1707866656110;
        Tue, 13 Feb 2024 15:24:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707866656; cv=none;
        d=google.com; s=arc-20160816;
        b=A0gbD0BQHF74Ekp6SeSvz6tzT94rObjfVcIUI7XjiYRtoCEML9QMkxfx8Sv24f5C6h
         JVnNBd6pkWJXouDs8WEW/k0c0ZokhqW3yuKQsR01oKChUHVeFiFnK9yt0J2UQ5XE5xoj
         OHCszNJq1JW3h0NsG/Y2DmvdoF18xLyBRLKjuEUvNmA4cMoVDcGKgzznK8sJYTIMJp99
         T+vpZ/PIUvHH7iAEjpAVIRqnnTmXo1lYQ7a8lzOvQJL+uSYCZqWJe6nSrs/EWbMOML1u
         NNichYZzal/k3rikAPCwpKYOWN+71P/MK6qcskI0i7GxRwmvyY/K+pv5/FAegoM6mgQK
         ihKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=IQNc5sF3dDkI4DLDAhoYo17ANIh5r48U4JW8o4GQNhc=;
        fh=yTvqvNGQHIhcY6pIhfY5RCKk6qANOy5VBBbNdxPcsbg=;
        b=oHrydj5o9MOwB4SPb83HrIYMN19s9ZQgvKyJLXOLMa7v2HrGpuuNHHkRxKICzk76x0
         kMZs03YZ1ktZSE7jmYFKBnMAW18YtF53Mkn/zQzs9X/PI3QLoGFZd5U1MHzHpLxM2Qoj
         Cq0YgpDcW87smMVTxQa2tDdKIgtezwR3sar5bF7YPGOdfsDUqTtMqxdeI1uDSAqp7CiU
         U8VxlOg9y4aFfsC2dnOxPeXfiUtK44ja7PA0PNl6dnEeQyO0dRGmqrJvX6+6a7BTcUDe
         TU9oPr17dcrEZIWVq4EWAAZyx6tiyIPr/bYPm0msi4NiR/TFPU2IT0ilElyCD6KYMxAi
         WPeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=c32gpRAo;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ae as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCWiglpTnaYwl3ri08R3s//nyNdkuDICoJmWFnOdCCqsdAoV3mhP9X/Yj3j1eiklobBwycSa18tcwnOuPK5m+STCdmlYsGDZqxfvig==
Received: from out-174.mta1.migadu.com (out-174.mta1.migadu.com. [2001:41d0:203:375::ae])
        by gmr-mx.google.com with ESMTPS id f21-20020a05651232d500b0051165efb143si689008lfg.9.2024.02.13.15.24.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 15:24:15 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ae as permitted sender) client-ip=2001:41d0:203:375::ae;
Date: Tue, 13 Feb 2024 18:24:03 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: "Darrick J. Wong" <djwong@kernel.org>
Cc: David Hildenbrand <david@redhat.com>, 
	Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <vxsk7w7z57rgwqgreeq2j4xq5klxeorfhjfysu3re3i6bomh5z@36p2iqhzxjfd>
References: <20240212213922.783301-1-surenb@google.com>
 <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <huysjw5jiyd7m7ouf6g5n2yptg7slxk3am457x2x4ecz277k4o@gjfy2lu7ntos>
 <20240213231115.GF6184@frogsfrogsfrogs>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20240213231115.GF6184@frogsfrogsfrogs>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=c32gpRAo;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::ae as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Tue, Feb 13, 2024 at 03:11:15PM -0800, Darrick J. Wong wrote:
> On Tue, Feb 13, 2024 at 05:29:03PM -0500, Kent Overstreet wrote:
> > On Tue, Feb 13, 2024 at 11:17:32PM +0100, David Hildenbrand wrote:
> > > On 13.02.24 23:09, Kent Overstreet wrote:
> > > > On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrote:
> > > > > On 13.02.24 22:58, Suren Baghdasaryan wrote:
> > > > > > On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@su=
se.com> wrote:
> > > > > > >=20
> > > > > > > On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
> > > > > > > [...]
> > > > > > > > We're aiming to get this in the next merge window, for 6.9.=
 The feedback
> > > > > > > > we've gotten has been that even out of tree this patchset h=
as already
> > > > > > > > been useful, and there's a significant amount of other work=
 gated on the
> > > > > > > > code tagging functionality included in this patchset [2].
> > > > > > >=20
> > > > > > > I suspect it will not come as a surprise that I really dislik=
e the
> > > > > > > implementation proposed here. I will not repeat my arguments,=
 I have
> > > > > > > done so on several occasions already.
> > > > > > >=20
> > > > > > > Anyway, I didn't go as far as to nak it even though I _strong=
ly_ believe
> > > > > > > this debugging feature will add a maintenance overhead for a =
very long
> > > > > > > time. I can live with all the downsides of the proposed imple=
mentation
> > > > > > > _as long as_ there is a wider agreement from the MM community=
 as this is
> > > > > > > where the maintenance cost will be payed. So far I have not s=
een (m)any
> > > > > > > acks by MM developers so aiming into the next merge window is=
 more than
> > > > > > > little rushed.
> > > > > >
> > > > > > We tried other previously proposed approaches and all have thei=
r
> > > > > > downsides without making maintenance much easier. Your position=
 is
> > > > > > understandable and I think it's fair. Let's see if others see m=
ore
> > > > > > benefit than cost here.
> > > > >=20
> > > > > Would it make sense to discuss that at LSF/MM once again, especia=
lly
> > > > > covering why proposed alternatives did not work out? LSF/MM is no=
t "too far"
> > > > > away (May).
>=20
> You want to stall this effort for *three months* to schedule a meeting?
>=20
> I would love to have better profiling of memory allocations inside XFS
> so that we can answer questions like "What's going on with these
> allocation stalls?" or "What memory is getting used, and where?" more
> quickly than we can now.
>=20
> Right now I get to stare at tracepoints and printk crap until my eyes
> bleed, and maybe dchinner comes to my rescue and figures out what's
> going on sooner than I do.  More often we just never figure it out
> because only the customer can reproduce the problem, the reams of data
> produced by ftrace is unmanageable, and BPF isn't always available.
>=20
> I'm not thrilled by the large increase in macro crap in the allocation
> paths, but I don't know of a better way to instrument things.  Our
> attempts to use _RET_IP in XFS to instrument its code paths have never
> worked quite right w.r.t. inlined functions and whatnot.
>=20
> > > > > I recall that the last LSF/MM session on this topic was a bit unf=
ortunate
> > > > > (IMHO not as productive as it could have been). Maybe we can fina=
lly reach a
> > > > > consensus on this.
>=20
> From my outsider's perspective, nine months have gone by since the last
> LSF.  Who has come up with a cleaner/better/faster way to do what Suren
> and Kent have done?  Were those code changes integrated into this
> patchset?  Or why not?
>=20
> Most of what I saw in 2023 involved compiler changes (great; now I have
> to wait until RHEL 11/Debian 14 to use it) and/or still utilize fugly
> macros.
>=20
> Recalling all the way back to suggestions made in 2022, who wrote the
> prototype for doing this via ftrace?  Or BPF?  How well did that go for
> counting allocation events and the like?  I saw Tejun saying something
> about how they use BPF aggressively inside Meta, but that was about it.
>=20
> Were any of those solutions significantly better than what's in front of
> us here?
>=20
> I get it, a giant patch forcing everyone to know the difference between
> alloc_foo and alloc_foo_noperf offends my (yours?) stylistic
> sensibilities.  On the other side, making analysis easier during
> customer escalations means we kernel people get data, answers, and
> solutions sooner instead of watching all our time get eaten up on L4
> support and backporting hell.
>=20
> > > > I'd rather not delay for more bikeshedding. Before agreeing to LSF =
I'd
> > > > need to see a serious proposl - what we had at the last LSF was peo=
ple
> > > > jumping in with half baked alternative proposals that very much had=
n't
> > > > been thought through, and I see no need to repeat that.
> > > >=20
> > > > Like I mentioned, there's other work gated on this patchset; if peo=
ple
> > > > want to hold this up for more discussion they better be putting for=
th
> > > > something to discuss.
> > >=20
> > > I'm thinking of ways on how to achieve Michal's request: "as long as =
there
> > > is a wider agreement from the MM community". If we can achieve that w=
ithout
> > > LSF, great! (a bi-weekly MM meeting might also be an option)
> >=20
> > A meeting wouldn't be out of the question, _if_ there is an agenda, but=
:
> >=20
> > What's that coffeee mug say? I just survived another meeting that
> > could've been an email?
>=20
> I congratulate you on your memory of my kitchen mug.  Yes, that's what
> it says.
>=20
> > What exactly is the outcome we're looking for?
> >=20
> > Is there info that people are looking for? I think we summed things up
> > pretty well in the cover letter; if there are specifics that people
> > want to discuss, that's why we emailed the series out.
> >=20
> > There's people in this thread who've used this patchset in production
> > and diagnosed real issues (gigabytes of memory gone missing, I heard th=
e
> > other day); I'm personally looking for them to chime in on this thread
> > (Johannes, Pasha).
> >=20
> > If it's just grumbling about "maintenance overhead" we need to get past
> > - well, people are going to have to accept that we can't deliver
> > features without writing code, and I'm confident that the hooking in
> > particular is about as clean as it's going to get, _regardless_ of
> > toolchain support; and moreover it addresses what's been historically a
> > pretty gaping hole in our ability to profile and understand the code we
> > write.
>=20
> Are you and Suren willing to pay whatever maintenance overhead there is?

I'm still wondering what this supposed "maintenance overhead" is going
to be...

As I use this patch series I occasionally notice places where a bunch of
memory is being accounted to one line of code, and it would better be
accounted to a caller - but then it's just a couple lines of code to fix
that. You switch that callsite to the _noprof() version of whatever
allocation it's doing, then add an alloc_hooks() wrapper at the place
you do want it accounted.

That doesn't really feel like overhead to me, just the normal tweaking
your tools to get the most out of them.

I will continue to do that for the code I'm looking at, yes.

If other people are doing that too, it'll be because they're also using
memory allocation profiling and finding it valuable.

I did notice earlier that we're still lacking documentation in the
Documentation/ directory; the workflow for "how you shift accounting to
the right spot" is something that should go in there.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/vxsk7w7z57rgwqgreeq2j4xq5klxeorfhjfysu3re3i6bomh5z%4036p2iqhzxjfd=
.
