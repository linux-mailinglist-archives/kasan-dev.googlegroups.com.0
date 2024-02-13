Return-Path: <kasan-dev+bncBCS2NBWRUIFBBEWRV6XAMGQEP5754OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id ADB22853E29
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:09:23 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-33ce3425ec9sf188276f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:09:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707862163; cv=pass;
        d=google.com; s=arc-20160816;
        b=0b7aNzjgmriIySo/1qnRuAjwQ6751oMCWO0flcIQQ7qLVt70ajULn+bzhmNZ60IDR2
         1cD2CgowNwj3Qzqsl1Y95TRjG1+2GXuzuhgFp3JVqQ+ppjNeaagjM8zQr/l8oqbFWFWt
         m256njO+y4GJsnNwptrGAgommq9i1u6qBVtiMqa4J61FuIX85w19/aJZubtRwaWxS4LQ
         +fGSsYjIaUIzkSMM4yCsTArhWMyoIrHDJWmuO/gLTNiQ2WNTXjhTU21wFh8pMWaLAbzy
         Y88I3Htl+WffqwlnpnHaM4mVxTj6Z3z5aSHxAi0XAMnSr1BqcLsCi5PqoGNhi/RSVVAP
         P3RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=JPyBoUAvJWH8HCP6gffUexphR92mMAahZl7pmC0xrOI=;
        fh=1/4C1Ng44IqGt2MUJ2wP28r0GLfX/K/p7t+fT+h3Kis=;
        b=v6Jo5/XuLx5LrhdpnXqJwvgKvVVKdqcOkyMvjt+asJqA/W5lgij2eZu2E7mELwUsWs
         3mgMbot+EKRqHI5T/RyfVd/COET8WA5dC3qekJPdv9bXgx+0Be8am/rIM99SKathl7Xn
         7etwo8q8Z1XVtcN1vcm2rbTxKlSbM4O9cqA0QXvLJ7IJ/YJ0s1KwwFmgLmoa5Qv+ooA3
         2f3DnOgWSYg3mHUb8T6prGDX/QDDnDa78e9tMc7/JpY7tVKwd9ZK9E5MS1NZISpyqscu
         3ljvVPdy8i2EsCyjFM3PYR9xc9XHPXCTM0uNXTEx4/pinGz/yKz9AHTzFwi3leJWtKkM
         vQHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wiJHD1ro;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707862163; x=1708466963; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JPyBoUAvJWH8HCP6gffUexphR92mMAahZl7pmC0xrOI=;
        b=uaqdox2ZsNOo3dZwhIrQSPOVw1Cv/IzsCMRrYxjUrGl0dJ7eBTND7HrUqoF1QZbFi7
         8/QB92YZ4vdwX3JMV3syAN3h/V4OGnA6rQvfj5aLvDoxhj35lbLwfRoUb85FmujsUOz4
         mBMJAXYs0hg3p5qSCF04mwewMrGxfRFBiU35oSW2VOtY7HqBMAczFUMQoa4e025ZW84O
         6c3k7Z+EPHa5lBBSdpQyFa8t90QSjUr7vPr3/7B24O5aXhJg5sAP/c8IJK9DUzDRH1ha
         FQeqNj8yWwpN67Ls8clx0uflOUQLh9TaxMfXfhcGvfaf2Km36YZtshjroo/DKtVU+Yl+
         uFFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707862163; x=1708466963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JPyBoUAvJWH8HCP6gffUexphR92mMAahZl7pmC0xrOI=;
        b=VD64Mwj3X1e/Iropf8mFlAk7e81vosnLGw92199EoVpEkisNf+bgz6i5/R4d/U2you
         AjCZx0CRHZmfsxpo6nMcnBndehra+oxL3igag2FUbPvpUDWgdOslAXR0KWbwvqSl1CVF
         Ji2F//i7GawZNbLezZli8RFj9dd8vJaEiPJ02m1m7/FMVhyZi5slP7WOfMAL4Y8IPOk/
         x9GtfQxdeYrjRXCiYB50cAd294H1ZfPHSPJLGSz+DpDmqIXP8jVPmi+jtj97Lk7Lso0o
         OWc5N0kLEh2x0ebplpYMU1hgeVuFd+NnMyr8+vU3TfgnwIo1kgY92+yoT2x5AtFY9UyX
         jOmg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVCe4v/zWKxs2Ar+QjfByLd5Tuq2XZMiKlMd74fsI8oc+XQ+oMKjS7QmJxI16nNSMUfh285O1t8ui571m+7fyRae43jWp9j2Q==
X-Gm-Message-State: AOJu0Ywkz2YC5VgK3l9qYEb3E9qjB70OUkngrUdZH7SX6NzA+1bqsKB+
	OelGBCcxiDaI08EZtJbY3ZRQD9RwAobvjKes5KiIcehKxiOaQr4V
X-Google-Smtp-Source: AGHT+IFKcBXmUpduW5q0pRiq3/KSQ8z8Uw2UMPOjZx6whf9/zDuU4M5wc3EUBWlAyzzf6tOlEIVuxQ==
X-Received: by 2002:a5d:6a8f:0:b0:337:bb0f:3702 with SMTP id s15-20020a5d6a8f000000b00337bb0f3702mr483537wru.35.1707862162806;
        Tue, 13 Feb 2024 14:09:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:a1c:b0:33c:e0a8:bf2d with SMTP id
 co28-20020a0560000a1c00b0033ce0a8bf2dls284113wrb.2.-pod-prod-05-eu; Tue, 13
 Feb 2024 14:09:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUFvBtmmK2fusJkPNUzsvrcgM8XXkAQ4e+/fovf9E2d/B0Hq7BXMv8mgtI9XEhCJPt6Qaz222TE/etTEStFog3mSzt8RLxI5RCCqA==
X-Received: by 2002:a5d:6145:0:b0:33b:47f9:d95 with SMTP id y5-20020a5d6145000000b0033b47f90d95mr424268wrt.24.1707862161000;
        Tue, 13 Feb 2024 14:09:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707862160; cv=none;
        d=google.com; s=arc-20160816;
        b=nNOQItxyN4R7aP06htmcGPVA0gqfI7uY49RFQJt/15YCMkXEhlljmM78qDmfXHvpIw
         Ieo/lt9vr3H0DTKJ8iLaPbruazP7ArCI3sTBZ7xd2UsUszLQ9Ia4x/oRm56H8hHs2jkV
         x82PvWVwJmEWqRy9fUgipFjK145zZJYfCjNNDAQIJ/U+2t+LUqMqgVGRreeRVkT4tn1U
         JWkwtKJgzNEW7hutKrrWOiWTq77FThjKX0oAuSBUWnAsHh/jYzbunX/bNZyyTW96LRl8
         maJAEK0n6gVt5G5vo0TAzsf2GaNG9SbxJ3EMoiF7Dyee3e6TazeyAEPrly9qBA6dFZcp
         2LIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=K19bAPZc3Kc3I3XpLB02dh4st8ojApfa6FF0rrEkdlU=;
        fh=QFlkgyyCQ5O38p+6S08QpUFaz8RHvuQLIIepbLH8S+4=;
        b=E0TetclABY5/eyoRJSnIFCETwpzTR3YxEltl8Q2394y0hgb20/sPr0I49IR/TIZIAV
         ZWgwoGwbUv40giqM0z348uIgryTbKZXbCQwFZ89BXMmW+ZlkS376Yw0VeR0CF1Ah+JLs
         st5789f5Adk/YU42+f7iTn+S/acV3J7KKR5O8IHsJTBwUlFdsiIoFhDMI9yqSVYk1o3+
         X8EmRANFrQfCaJVb/DfntwXi83TbvhxZyRJ6MAlTNsMyFbicFBu1zVJyVcMLENKPqKdv
         d0nAOzi9AuECx4CoCAyPhzIsFfnwI7gsPohnmx1r3utZ+Tj/hFF1RmzfF9cSZ5H7KFT1
         bZww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wiJHD1ro;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta0.migadu.com (out-171.mta0.migadu.com. [2001:41d0:1004:224b::ab])
        by gmr-mx.google.com with ESMTPS id fl18-20020a05600c0b9200b00410c1ebf375si1005wmb.1.2024.02.13.14.09.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 14:09:20 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) client-ip=2001:41d0:1004:224b::ab;
Date: Tue, 13 Feb 2024 17:09:11 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: David Hildenbrand <david@redhat.com>
Cc: Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, 
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
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
Message-ID: <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
References: <20240212213922.783301-1-surenb@google.com>
 <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=wiJHD1ro;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrote:
> On 13.02.24 22:58, Suren Baghdasaryan wrote:
> > On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@suse.com> =
wrote:
> > >=20
> > > On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
> > > [...]
> > > > We're aiming to get this in the next merge window, for 6.9. The fee=
dback
> > > > we've gotten has been that even out of tree this patchset has alrea=
dy
> > > > been useful, and there's a significant amount of other work gated o=
n the
> > > > code tagging functionality included in this patchset [2].
> > >=20
> > > I suspect it will not come as a surprise that I really dislike the
> > > implementation proposed here. I will not repeat my arguments, I have
> > > done so on several occasions already.
> > >=20
> > > Anyway, I didn't go as far as to nak it even though I _strongly_ beli=
eve
> > > this debugging feature will add a maintenance overhead for a very lon=
g
> > > time. I can live with all the downsides of the proposed implementatio=
n
> > > _as long as_ there is a wider agreement from the MM community as this=
 is
> > > where the maintenance cost will be payed. So far I have not seen (m)a=
ny
> > > acks by MM developers so aiming into the next merge window is more th=
an
> > > little rushed.
> >=20
> > We tried other previously proposed approaches and all have their
> > downsides without making maintenance much easier. Your position is
> > understandable and I think it's fair. Let's see if others see more
> > benefit than cost here.
>=20
> Would it make sense to discuss that at LSF/MM once again, especially
> covering why proposed alternatives did not work out? LSF/MM is not "too f=
ar"
> away (May).
>=20
> I recall that the last LSF/MM session on this topic was a bit unfortunate
> (IMHO not as productive as it could have been). Maybe we can finally reac=
h a
> consensus on this.

I'd rather not delay for more bikeshedding. Before agreeing to LSF I'd
need to see a serious proposl - what we had at the last LSF was people
jumping in with half baked alternative proposals that very much hadn't
been thought through, and I see no need to repeat that.

Like I mentioned, there's other work gated on this patchset; if people
want to hold this up for more discussion they better be putting forth
something to discuss.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27%404a5dixtcuxyi=
.
