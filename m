Return-Path: <kasan-dev+bncBCS2NBWRUIFBBFFT36RAMGQEDAS5GHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 293E36F9A5D
	for <lists+kasan-dev@lfdr.de>; Sun,  7 May 2023 19:02:14 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-4ef455ba989sf1945481e87.0
        for <lists+kasan-dev@lfdr.de>; Sun, 07 May 2023 10:02:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683478933; cv=pass;
        d=google.com; s=arc-20160816;
        b=F7THlxiLqgpQUnUsmFFG+Jfgd9GmmjPdUmcoAnL2Y5PnYRYM0vg+qSr+EMe/RF9rfP
         g+UhjIzJhX3M2Eac1nbhi7O53Li4KQh+fKsHYXMjnl4h3ABq7ltcdSfVFul3MFUhMXv3
         pcvN/5IvvHxOigGFdN7qbbjQqHuh/oqZOrf+c/aQ7s/5eLsOaJ0zFi6poWs0DNk54ktU
         zTn/FJPkhcpmUli8yTpGfMK8qz++c77IwmQabX2qPNMQQW80hPJpQp/sZ9PqAMGGbdn7
         Xiv+382cpg6TeRN6L9olPTb9dsFWpRTw6jbu0ceXPUt74cdkplk72fEitIbUEUKZwssE
         ZEeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=1GChjAPrBLwpdAhWTJbRQhn/jdgdlbaPHloqhufdJZo=;
        b=vUqbqQJS7fn0eslhgxpFl8fNnZVhEo6E0AsGY0B5aXERwoNppejgswy+x9VCodAva1
         Hmbs8yOOg9rofbkgA7nbLK2CU4/OqQ2sh61zhjMTbOoT7xqdYCQ+ffMLcg4dwfLHWOn1
         YwFKSOclJNnZsPjbb9CPdL2ymFpeM4mOgh2CiQ6h6EQ7QAQxEZQDghVVyToLXPR1jkqG
         TL1b1Rq/VtEYUnFZnaobeWQbwkeq3GAsGiEaDmIrVV6G1eCFduQBHDD0RLlaYYVJFE0V
         K12nlCm0v6ZK+ZYtib1gMSN377ZqbWESmJ2FQsoIbUJGGGMjYjITsDWvVhsMQw5Ves1/
         BCXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RBllo5SE;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.10 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683478933; x=1686070933;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1GChjAPrBLwpdAhWTJbRQhn/jdgdlbaPHloqhufdJZo=;
        b=DXxIr1a0UUEMv4ww5okXPOPqYY83EJzgnW/+z5dtRBc3rl9LndPi9METmARxe/KQny
         fu3A3mK3p/wtPoqvGcZkNYjF7qFS2TFk5lRjglO9t7JFqwmoiadaIwNQZ3gaXZ7Csfor
         j9kQCMWNDuXPUe3iWyZFcUDsmQo2dJNIi3uPkz9bV/EHiFBttv5vMtpLRl1Eu+dt/XMc
         6S6+CQKzAUwhFKmUY+0lQLP9/MbrseBlWSC3l/fG1ELSCpIGBFOyI9xYJrnuNMi9mYvm
         TE+9lCB427kqxLQPzae/3211FIIr8qeVGebPQgjkQ0iyC5qBvZaiLuTYJ0OMoY6xE2xb
         SDIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683478933; x=1686070933;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1GChjAPrBLwpdAhWTJbRQhn/jdgdlbaPHloqhufdJZo=;
        b=NIuzyXzHjWA0xItNQG/Da6nfWSE9qfI8FyJKBAw2K4iCIvt3Fb9y+K278UJeRikkWA
         w6QVWpFwRDIBHlFRvEkr6hgK55uap2MlHX+iVeripVZq/CQQIbMy7zvroC5F/ZNAvtXP
         J2ZmUPuCHRuOquDPpPkhQpl1O+KLjq2964cJ8o/O5LOJYjkCtKmoW/xqT0MEwnUMl3x+
         9x3Wlv9jOwuLzbYLRPjn0CH/R0r9NxiZtJ2gJ17WY0iVA85KxQvdyyJNEqqA4w4dNj/8
         dUEIvvr19zQ7EXi84lNJOuQHbWq5MeJRtLsPInVXN/VvgCcE4W/a0JwDuBjUp5jS2u6d
         Horw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwdyl4K2sdAq9MU8Rnn8aprO/CfPGRqVFhdUTymi66m0/nyP2CF
	vUuRgMF3FYA4DuHcCF3mdGs=
X-Google-Smtp-Source: ACHHUZ4x8xdCfb5hDtx0djBxTiUwN+mdJnKLdhZVfjaYZCYIIQKfDaSRNkH1HOWWMPZqeVotyOSp+A==
X-Received: by 2002:a19:5202:0:b0:4f1:458f:1302 with SMTP id m2-20020a195202000000b004f1458f1302mr1741733lfb.1.1683478933131;
        Sun, 07 May 2023 10:02:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:212a:b0:2a7:99a2:42c2 with SMTP id
 a42-20020a05651c212a00b002a799a242c2ls1008774ljq.1.-pod-prod-gmail; Sun, 07
 May 2023 10:02:11 -0700 (PDT)
X-Received: by 2002:a05:651c:483:b0:2a8:e46b:9410 with SMTP id s3-20020a05651c048300b002a8e46b9410mr2063216ljc.15.1683478931716;
        Sun, 07 May 2023 10:02:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683478931; cv=none;
        d=google.com; s=arc-20160816;
        b=NlFPHiAjTpPQZGT70v9R/pTGiUuqyc2uLqw40J/ffOEQP1jzFzkaZP/ZHQ5LBxB1/+
         yDpxECqGFK1mFx/HCVPGLmr1kb66E3lm3ru7eeHUD2kAOB0IORwLuqRz1eFZ6q5VYzV7
         +Nzu6eUIBy5DiFi4FQPUQ/dBhhmG260W22uzIgEfhsZbmGybZ1UyMXK0j59+Mwrev2m+
         vfyuTpfWI+oh5RNxhH4itoEk1xYvQuKC6Lc8W2m6LhTAIvwR++AQI/+IUsl/7ag0XnB1
         OrbU+CPIZ/80S7w/WtVBHHJC0Zcj/z6PGZJeIq/DJvL3Pk7AjJkR6xSq+1pGnZV5H/j6
         eKJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=K2IKs9gP6n8AwGF/yIy3vUTevnAld9lGncsxDoAPz7I=;
        b=0HwEnrH7LHCj3JCFEUyxU7BMF7X6M5uAO9uCkD3ccqav/sMYn0GAOL1dNSkNTeq3JD
         gDAD9LFvslV3znPvxzeI8c512ArpalLdZpqR5CHoIjaQQHvsMR5IzNxIPGKwRZsT0250
         wxPmipKJEIWd1PIBHRD/Cd/lIB+1rdgxXq9zWDgis72m2aA9hQPgG/7roVsnjBncNPKb
         /URa9RmRyitoS6hHy224n5n5ecgyOp+TcHghouRcg0KNiaYAr0U30bBFWZAOzQq9K3lz
         TAhn5jdIopJ1NaNKXjyUgv+I9+Xn2luliTX89fQBIrs2zztxjJPw7j4jQio0taicIdIC
         PxVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RBllo5SE;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.10 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-10.mta1.migadu.com (out-10.mta1.migadu.com. [95.215.58.10])
        by gmr-mx.google.com with ESMTPS id u15-20020a05651c130f00b002a8ba7c9a04si311372lja.7.2023.05.07.10.02.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 07 May 2023 10:02:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.10 as permitted sender) client-ip=95.215.58.10;
Date: Sun, 7 May 2023 13:01:57 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
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
Message-ID: <ZFfZhTiXqeV1enD4@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
 <ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
 <CAJuCfpEkV_+pAjxyEpMqY+x7buZhSpj5qDF6KubsS=ObrQKUZg@mail.gmail.com>
 <ZFd9BiSorMldWiff@dhcp22.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <ZFd9BiSorMldWiff@dhcp22.suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=RBllo5SE;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.10 as
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

On Sun, May 07, 2023 at 12:27:18PM +0200, Michal Hocko wrote:
> On Thu 04-05-23 08:08:13, Suren Baghdasaryan wrote:
> > On Thu, May 4, 2023 at 2:07=E2=80=AFAM Michal Hocko <mhocko@suse.com> w=
rote:
> [...]
> > > e.g. is it really interesting to know that there is a likely memory
> > > leak in seq_file proper doing and allocation? No as it is the specifi=
c
> > > implementation using seq_file that is leaking most likely. There are
> > > other examples like that See?
> >=20
> > Yes, I see that. One level tracking does not provide all the
> > information needed to track such issues. Something more informative
> > would cost more. That's why our proposal is to have a light-weight
> > mechanism to get a high level picture and then be able to zoom into a
> > specific area using context capture. If you have ideas to improve
> > this, I'm open to suggestions.
>=20
> Well, I think that a more scalable approach would be to not track in
> callers but in the allocator itself. The full stack trace might not be
> all that important or interesting and maybe even increase the overall
> overhead but a partial one with a configurable depth would sound more
> interesting to me. A per cache hastable indexed by stack trace reference
> and extending slab metadata to store the reference for kfree path won't
> be free but the overhead might be just acceptable.

How would you propose to annotate what call chains need what depth of
stack trace recorded?

How would you propose to make this performant?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFfZhTiXqeV1enD4%40moria.home.lan.
