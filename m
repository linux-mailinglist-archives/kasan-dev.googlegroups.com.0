Return-Path: <kasan-dev+bncBCS2NBWRUIFBBLP4ZGRAMGQEOAO5UDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id DE12C6F5B26
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 17:30:54 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-3f3157128b4sf19032655e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 08:30:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683127854; cv=pass;
        d=google.com; s=arc-20160816;
        b=ufw55CN/faMnB1OrqEaZufCq6we7EijbRYfHH97UQlyPT0Uq1c5B6CxVFSp1N1+TYH
         xJZu3OKXhl7rd74NBe9p0JymuoWrkj/N9jOSwIVfvt3xR/ae3sBzrOz494q3/BEb12+k
         LBKrigHsz6aQ4UTLpbDxcZp0dApg60uk9MhiacwUUElN3oORb49w/ufsRx3jLCjMIusf
         EWNaIfaQKlZt6Aqnh3ljm4OCZ0np6MsVVWR2FbTT/6LgJFVFF4/HQ46iDMN6RntQOZo3
         uqlE2s4r3XmpwQsStJV2MTlhpYmI9UqnVv6Q0ZDLV/ScLMN38bLW+w++jGQyI38wtGOa
         PT4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=LPGWjUotxZeuY145kA9dXr9McC7u4HWA2gQmeOSsiEM=;
        b=DUrHvv3LZIFHMV1g9UJBt+YlsFGlo3zaviXwjU1nQS4NapKQRl/lPqClpjkljyZIWS
         gFF2mrzEq5ke1AqnsZ17dr9aYsWxbXyXDEbktGWhl/Eb0PLUieRVSqesyxFbr/CtgrSn
         chrPD6GgF85gIuuzcLkjb4o9fNja7blLUYeHvX32JHnssuuKQsktqed9z463av60YK5p
         QT0SijN7AFrKKM9Wv+/jHHcI+qC5LFP31i7RpMit5Nd8WJpLT/+gXA1kLZz/KVsZfT3W
         spMa6g5gDVPwNGwm5qoX00lWZNULD8S023dP7N2oBTuD2nU/Qpv/sKHvOY25G2J0AQNA
         1fgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Es8fVBNg;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::3c as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683127854; x=1685719854;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LPGWjUotxZeuY145kA9dXr9McC7u4HWA2gQmeOSsiEM=;
        b=SyF5V2C3/vUDM4XvHAyhdTUBn/3b3Smgix25/w+UQph08DMyvwtALwY2m6QGUiGQ4c
         Fo15SIZAjTRULmUOjI0gpVZ2tPkHbdWymgcYi6t0o1uTCOHkGEsz4agXLN/ZdkR/Kngq
         i/nLn1p6lzHcwaKjQszGHYf+O7MmN72QOeyacg1YOgQOCkwZowdIIZpUpQ3tNcUpTdWr
         U7BoerK5QqY8wffE8Vi43kMdJXXfBzFU1eN0I8+t/SaKJZ2PhdSMuFhU/AjOCGlnqDr6
         7x0WKyze1OAH8qFGMsArCmXhQZbANw5LyAturvilmiQeAIyNzwVKLj1QSLV4yr3fudE/
         8rQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683127854; x=1685719854;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LPGWjUotxZeuY145kA9dXr9McC7u4HWA2gQmeOSsiEM=;
        b=SiVNsLFj1e+V1joWax5Aufh/NN9JpsI9buXDtAOFiGNm8n4KtzZNe235v9fmvLjP5F
         fEHeYNNWBmgLgejpYK4r81+b/Curn41fkbx9fiZ8lH7BA/6Bx8rG0BoIoZYfR5XvQMw5
         x1yD/QfsBWFMn9u/CgHju88bArxKXYVP6dLruROwZCjSY6BnpDz8p3uwqkgG+aB/yfs0
         mAgkYTsAqlSpPAiF9UNwJu4evuYysCrgvf1dd43LqOD53Ta04q89vb3o6LipC7LPxPK5
         wjBX1Go/oY9ORP79eOyoyplKIFzSqRNhvk3azrQUhAbsNDi/PIOD0xUUX6uh+LC9HuPQ
         OgtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxnoPTEj1eRpCPS828QrfIg2pQLyAg30LHG5XHIvYG5zIBwl7qn
	irumKRlqiaO8UiT0S+Fm7cA=
X-Google-Smtp-Source: ACHHUZ7J7wrMLLn2KYvg/Oco0rsUNqloKJWMfEclzIFrnjqFRPEWVe9vR2ogbXj08QNhll8vhqKGgQ==
X-Received: by 2002:adf:f611:0:b0:2fb:9e73:d5d6 with SMTP id t17-20020adff611000000b002fb9e73d5d6mr68928wrp.6.1683127854082;
        Wed, 03 May 2023 08:30:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5c0c:0:b0:2f4:1b04:ed8f with SMTP id cc12-20020a5d5c0c000000b002f41b04ed8fls361110wrb.1.-pod-prod-gmail;
 Wed, 03 May 2023 08:30:52 -0700 (PDT)
X-Received: by 2002:adf:f346:0:b0:304:79c1:725d with SMTP id e6-20020adff346000000b0030479c1725dmr257197wrp.45.1683127852843;
        Wed, 03 May 2023 08:30:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683127852; cv=none;
        d=google.com; s=arc-20160816;
        b=T9vG5JcRDgP6iNk0Q2nWq97oZADe/N1zuJyHe9/SUr7OMAygSWZyFwmZlhbbV8CCTJ
         /rNc8ajoV0SqofMUP3cgdnW++VF7lTxeiJm6kt/IS7tMZsCBhrJxtpbvQWhYu8nYCx8+
         H8BS3KPCf8cNeKVxkjfrY7xCeogIKDDBCKk3/h+O16ItOwCKTTmJ2s+oOmyW6j5SOEAw
         y5m0IRgbBZKjpx7OYkEGyeNSt/VrZiNBTLL46dljVU0MrVKXeQh2/L4CJmTKnpMKMr3e
         yL4E70K6wJKzIFgxvbjdQwGKDBJaRy3zPyDVq+7jRlpfzNCfkuITtgG6OaBAm+jtctua
         OxzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=MnOvQ3HLpCXeXA7UeX7M5XmW5B1KmwVPXucVRQ7GRgo=;
        b=dtvNlq29wzcdIc67MqqE+1EjIJ5lf4xobELdwfX1Yjl0+pYG5pw3St0jWXA4gzMVEH
         OZngjkqzc1tcLk0Oc/cBHPFLFd8enWnGzebvJMaIsmi4q3VRO6KHxb7im124E34v8iC+
         Nk9+B/8EvSPApjrqTd27L3RHC7tAV951JrC4TP48+WOFbnz8Qj+qyvOJfjHb7VJAjJm0
         6h9tNjuJ4WA3ij3nszjEdlj0KzdyxzkrwuaqBQszzPQgAfgxU8cr1S0sP9s4lt2y0xWz
         QAJWvFL6QCt9toW10ZvC7nqeohBb/wrEn7WzqnwLqDN/4yPww+KnESzepIVChqycfJyu
         MvdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Es8fVBNg;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::3c as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-60.mta0.migadu.com (out-60.mta0.migadu.com. [2001:41d0:1004:224b::3c])
        by gmr-mx.google.com with ESMTPS id h5-20020adf9cc5000000b002f41048491csi1857746wre.7.2023.05.03.08.30.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 08:30:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::3c as permitted sender) client-ip=2001:41d0:1004:224b::3c;
Date: Wed, 3 May 2023 11:30:40 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Petr =?utf-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
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
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFJ+IIugLhEtMXXW@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <20230503115051.30b8a97f@meshulam.tesarici.cz>
 <ZFIv+30UH7+ySCZr@moria.home.lan>
 <20230503122627.594ac4d9@meshulam.tesarici.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20230503122627.594ac4d9@meshulam.tesarici.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Es8fVBNg;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::3c as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, May 03, 2023 at 12:26:27PM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> On Wed, 3 May 2023 05:57:15 -0400
> Kent Overstreet <kent.overstreet@linux.dev> wrote:
>=20
> > On Wed, May 03, 2023 at 11:50:51AM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> > > If anyone ever wants to use this code tagging framework for something
> > > else, they will also have to convert relevant functions to macros,
> > > slowly changing the kernel to a minefield where local identifiers,
> > > struct, union and enum tags, field names and labels must avoid name
> > > conflict with a tagged function. For now, I have to remember that
> > > alloc_pages is forbidden, but the list may grow. =20
> >=20
> > Also, since you're not actually a kernel contributor yet...
>=20
> I see, I've been around only since 2007...
>=20
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit=
/?id=3D2a97468024fb5b6eccee2a67a7796485c829343a

My sincere apologies :) I'd searched for your name and email and found
nothing, whoops.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFJ%2BIIugLhEtMXXW%40moria.home.lan.
