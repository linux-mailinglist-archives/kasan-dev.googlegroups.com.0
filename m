Return-Path: <kasan-dev+bncBCQMPJFM7ALRBQ77ZGRAMGQEYXDSBII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C30466F5B51
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 17:37:40 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-4eff7227f49sf3284102e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 08:37:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683128260; cv=pass;
        d=google.com; s=arc-20160816;
        b=cNXADLahm+KVDLo3wa+XwBLrVf4QVBbDBuz7fVJondaJhdO5W+wT1Nw+Eamofsm6wc
         CUX2XXtfUjkbGndt1FLsP6aU3JL3cg4zB8uZbnjQPvqiZvwjakiyLFakXlV9G9bXXT3z
         TfijJhRaxw5D0ZZZbbO1J9x/skmCZlB4gPtykkRrbPwCK+lcuAgNFSothi+DK2Iy3JA3
         uaQUtvjQ0GTzB1TlxSNCRtnV8ZUEEJhrMIt4rx4JNr1flcfrCxCXWt6Hf98fYmHBDeSi
         7RhyBPTGh9hbdmBaMuuAomIQsDzVOD5tremuQVKcMJAuNyseWCk+llDP9zy13opVbVKx
         ZPQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=w9LJNUjGR21gucRFZGVcqOGS4tO96dvmg0CFDWSrkbw=;
        b=cypu7AbooUdsgCPRtZAvSgysBB2/HEVJEzJCXzNwJDDPzgV4laFS95y7xVmSmOlInC
         iCLmcOCAU9dwdSSdJ1EDv7H1BAoEzwXtWtV/5sYOgRAR9tkqPhFYPCSLvXEvlmG+WsEq
         gO3Hfwojhzdg3rtjVC4m388lRNI4+yVwDEh/9JE+89Lz6f3go31yN2nCGVHZNc8Tgeu5
         +F4NWkqvzjzuBA266S78S5t6FEbvzt9caGHviIM6CGs9tTLqqSOxPsAIoxKkc/4sw9OX
         XK6wSjZrOfm8fwEKkJpqbT3/gVKE5UKnpNLnor/UiOq1IkItsEpicEL0HZoIHuQn36f+
         s+RA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=f1ldkmb3;
       spf=pass (google.com: domain of lstoakes@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=lstoakes@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683128260; x=1685720260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=w9LJNUjGR21gucRFZGVcqOGS4tO96dvmg0CFDWSrkbw=;
        b=hoW6BK9f4+Ck/PZc20bYBRJ5iqPBR56u1/gmIqoLqrw7tkgObwazzvFK+5Zw+xYndr
         PFEP0OeOP7iRrfKdpt24grs+ppy2Tn4t1aR6x717KbGMM8fdi4+URlDq/QEiuY1dDn86
         SOYddsaa25MiB2mss6rLEuPxMCA99T78DuE2o0bMPE+Coi4CbFCyT9Vt+jrEwMXN/miD
         S85hx7JtZAPl9y+7JGYo9BBcAA42GDEzaQnbRgkJTTK3DAvT38vIHYDFSpKwFL+1dmjw
         ziX2RI2pYZ2v5vec8CHEGI3qlEnbN3itLdv7Cay8+n02RPW4fdDMrKAejd9jWSfzZQ6F
         45kA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683128260; x=1685720260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=w9LJNUjGR21gucRFZGVcqOGS4tO96dvmg0CFDWSrkbw=;
        b=S21jRW9sqAiDxRsxT1qJsZ0MxS6baD7mzbY2Ns7F1GemPVqakVry/bwMTx+ezkKNIN
         O8fx1RDAY5NAdApGJ0y0C61gfMy9G7IwVXPdCJhEltWeXbr/cXbIWJN1BgBlsJznoHN4
         WlcoM7HE+z6RN+8hJxfYjIIqTow9W3VqSIjdy7Ju6o6yG5yPzg7+bnvuxw25EkFSCdRD
         NNgQY5R36yLLXdhN7fg21/kTYP4PcWsFilmXDrO/jyFdRXQ4jX9ZLLuOj9lO6B2HRyis
         qvXQIAgYzXXg9Mm67c11N4ivdjiak9Qny7OAPFFhJ6dMRnBg650BHFsIEeZHNmMEn2ap
         D4Mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683128260; x=1685720260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w9LJNUjGR21gucRFZGVcqOGS4tO96dvmg0CFDWSrkbw=;
        b=aEzE1vuanqHMwp4moPuq33zglaha82qhyNAy+v2/+fMXG7AYTUyjV0dY9aSlcY2M44
         TDs4CCyBoZQVkkjU+LIp/2CgB50lmnNN7wa/hcgXgPvUx024vtvoGCQAhjFKp68TtzZh
         tz84bP4mvaFN/ZgSkh5aBV/GJZ0M+mKkgDHCDka4hL0PilSwENU/hywafep761ao+q5q
         EDF9lksxGC8moXVMQ29QUF8Y9hsX3dJu7eHDxDs6w/g7voeY8KVXb56Kbf3m5d0DdZCL
         jZ5wL4/edI0sSG6fICHSa50/xRdPGOOMs19bhaIrPDm0vWmsY59MNFFP1siavpHP7BJM
         fWEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwcOYWSsIF0zub3waeTjrsBM0wWqrIHI8vTC0dq6pwsaG2+LZVa
	j6EyeXG7LEQ+em0KGzfyfUk=
X-Google-Smtp-Source: ACHHUZ4QjNtC+BJFGrDJrGBsYIcRYPAn/2jWnVk3bG+HxMFCwvQcV0YEuXyRmt3q09bIjFVi0hQoYQ==
X-Received: by 2002:a19:ac42:0:b0:4f0:1a45:2b14 with SMTP id r2-20020a19ac42000000b004f01a452b14mr916296lfc.10.1683128260070;
        Wed, 03 May 2023 08:37:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4017:b0:4ed:bafc:b947 with SMTP id
 br23-20020a056512401700b004edbafcb947ls1005610lfb.2.-pod-prod-gmail; Wed, 03
 May 2023 08:37:38 -0700 (PDT)
X-Received: by 2002:ac2:599c:0:b0:4ef:f630:5c1e with SMTP id w28-20020ac2599c000000b004eff6305c1emr933446lfn.51.1683128258689;
        Wed, 03 May 2023 08:37:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683128258; cv=none;
        d=google.com; s=arc-20160816;
        b=N3A9PcTUR1PW2sLqpXLH8nx8xQXGjBvjGfUnFQHNF45w5jWzB/hsh1tqutPxqwaWQI
         UpLNTKJ30V/pI64NKDiDZW1u40FAS5JyUK9iSGOax9Zobm5N9q74yYP3wpSP/2+vQ5D9
         8KO4122Ljyfn7w2HzmnWKDK+DiTIZPIvFCoqU3T1oo9Hfmk/HlCajzeIhdui6EoSYKR9
         l9CqAyCndf3tl1i6dVdUxNe64r2zpncu/GlCjnlCzjmlh3odzhMOyqCPmkXz3ws/jHax
         vpmva2jSQg8HIDeJ9qkYzwDavYRkZbig3/DCsDHvvfnW1NyKFEq6bQtH9I+APoohZzZY
         D6xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=5JJFuEPTE4BVU5/m4SDNq/0rwYCFngwHyNb8+sMGpbk=;
        b=Vwff0K57q/17WzAKye3io+p3ck3yPhLWlMO2xtQqgnUNnyS4S4tChF7CW1xT/bZyNS
         xZt4gB2qO75AE7vDCmfs00DEKB9wxc46W2UTGrZvF+ZmWqEYBy7prQP7Er6nWx1bs67D
         g+4FMg4dHKSJyVRMafgC+l2ldgXucIAPw+zngXdGcaegCvE8ytmO/aPwyE2PopiS+uqt
         1qvqL9C6rVSg1rNMOz1agjfEgLhKFJuiKCqIDKJWipwhCHS3PCMotJ2qq29dna932cbg
         BGUSCBHBPOz0HJYZd3ymEhu3VahVYHarIhb/aBm3uZEjCoTs4z1db3ZaDvBUumvJB9hU
         4PrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=f1ldkmb3;
       spf=pass (google.com: domain of lstoakes@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=lstoakes@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id i16-20020a056512341000b004f1371664bfsi170999lfr.8.2023.05.03.08.37.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 08:37:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of lstoakes@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-3f1728c2a57so53757565e9.0
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 08:37:38 -0700 (PDT)
X-Received: by 2002:a1c:7710:0:b0:3f3:2b37:dd34 with SMTP id t16-20020a1c7710000000b003f32b37dd34mr11146391wmi.9.1683128257631;
        Wed, 03 May 2023 08:37:37 -0700 (PDT)
Received: from localhost (host86-156-84-164.range86-156.btcentralplus.com. [86.156.84.164])
        by smtp.gmail.com with ESMTPSA id l2-20020a1ced02000000b003f19b3d89e9sm2234347wmh.33.2023.05.03.08.37.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 08:37:36 -0700 (PDT)
Date: Wed, 3 May 2023 16:37:36 +0100
From: Lorenzo Stoakes <lstoakes@gmail.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: James Bottomley <James.Bottomley@hansenpartnership.com>,
	Petr =?utf-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>,
	Michal Hocko <mhocko@suse.com>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
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
Message-ID: <f57b77b0-74da-41a3-a3bc-969ded4e0410@lucifer.local>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <20230503115051.30b8a97f@meshulam.tesarici.cz>
 <ZFIv+30UH7+ySCZr@moria.home.lan>
 <25a1ea786712df5111d7d1db42490624ac63651e.camel@HansenPartnership.com>
 <ZFJ9hlQ3ZIU1XYCY@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <ZFJ9hlQ3ZIU1XYCY@moria.home.lan>
X-Original-Sender: lstoakes@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=f1ldkmb3;       spf=pass
 (google.com: domain of lstoakes@gmail.com designates 2a00:1450:4864:20::32c
 as permitted sender) smtp.mailfrom=lstoakes@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, May 03, 2023 at 11:28:06AM -0400, Kent Overstreet wrote:
> On Wed, May 03, 2023 at 08:33:48AM -0400, James Bottomley wrote:
> > On Wed, 2023-05-03 at 05:57 -0400, Kent Overstreet wrote:
> > > On Wed, May 03, 2023 at 11:50:51AM +0200, Petr Tesa=C5=99=C3=ADk wrot=
e:
> > > > If anyone ever wants to use this code tagging framework for
> > > > something
> > > > else, they will also have to convert relevant functions to macros,
> > > > slowly changing the kernel to a minefield where local identifiers,
> > > > struct, union and enum tags, field names and labels must avoid name
> > > > conflict with a tagged function. For now, I have to remember that
> > > > alloc_pages is forbidden, but the list may grow.
> > >
> > > Also, since you're not actually a kernel contributor yet...
> >
> > You have an amazing talent for being wrong.  But even if you were
> > actually right about this, it would be an ad hominem personal attack on
> > a new contributor which crosses the line into unacceptable behaviour on
> > the list and runs counter to our code of conduct.
>
> ...Err, what? That was intended _in no way_ as a personal attack.
>

As an outside observer, I can assure you that absolutely came across as a
personal attack, and the precise kind that puts people off from
contributing. I should know as a hobbyist contributor myself.

> If I was mistaken I do apologize, but lately I've run across quite a lot
> of people offering review feedback to patches I post that turn out to
> have 0 or 10 patches in the kernel, and - to be blunt - a pattern of
> offering feedback in strong language with a presumption of experience
> that takes a lot to respond to adequately on a technical basis.
>

I, who may very well not merit being considered a contributor of
significant merit in your view, have had such 'drive-by' commentary on some
of my patches by precisely this type of person, and at no time felt the
need to question whether they were a true Scotsman or not. It's simply not
productive.

> I don't think a suggestion to spend a bit more time reading code instead
> of speculating is out of order! We could all, put more effort into how
> we offer review feedback.

It's the means by which you say it that counts for everything. If you feel
the technical comments might not be merited on a deeper level, perhaps ask
a broader question, or even don't respond at all? There are other means
available.

It's remarkable the impact comments like the one you made can have on
contributors, certainly those of us who are not maintainers and are
naturally plagued with imposter syndrome, so I would ask you on a human
level to try to be a little more considerate.

By all means address technical issues as robustly as you feel appropriate,
that is after all the purpose of code review, but just take a step back and
perhaps find the 'cuddlier' side of yourself when not addressing technical
things :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f57b77b0-74da-41a3-a3bc-969ded4e0410%40lucifer.local.
