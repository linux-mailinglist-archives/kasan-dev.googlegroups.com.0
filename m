Return-Path: <kasan-dev+bncBCS2NBWRUIFBB4W6ZCRAMGQEU77DO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 488F26F5565
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 11:54:59 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-4edd54a0eaesf3058218e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 02:54:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683107698; cv=pass;
        d=google.com; s=arc-20160816;
        b=LJq1iPYZIw83OejBJNpsXX21SIfhB/p0iMOVnGwisHhQQMBv3TTyHr8PNnMp5Gif/R
         EUJLmAKfJvFAhDr2+kR5d3YjOxLSdXIlOIGGc+8ElyaaTXcX+IOFWc//m3vKQFKIFoRS
         1ae6kLeVOYHweqW4q19GWQpahyU3fEVNoxYEe6AsOkqGWA8nYX2Y2QQsaH5wI5m0QQec
         Z9+r6h2N5ZL1wWqI71sGkdbBwmxWnD8EcfXK0hAclhFAV66SxIzeAWReOvg+f/gkqE9K
         nIACHPBl8GhCH0959Yni3B9tL5t/6VI/8HYZKWeT+4DiO1gxsMthvmLsSRMpQUzRcmmh
         uVCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=afrYdMnUhxBSILcQDUgUACbzH4BYMJ2Ii6wXSMfLpbw=;
        b=VMkNv3moWEYvdkAbMfQu9U42aX7JpBrfyfexKZbqITAiLOszPuErpgObBePm7jaAjH
         FzKkTkTa7J8njWsdjVT6oaS6aHrLiQSkVjqBVFGRVyPPRiE1HxOsFS304ivTMmWLbi1p
         dswRVWqcBKdMLBEeocQP01v8j9s88/EEcR+5qcZxEniD67MtvIBM17q52AL6pmOz2S1F
         Kpxn97U2cyrRKFnIu8bc5+PoTb/gMMll+E89ZLbzpztPqh2esdlLAbfCuUYSFmlPmpSO
         w/kIhwLlqiWNvmb/P0qBwl82GJtd5JmprDdE/0Avsd51p708djHIza3dJ0xxs4DuWaUS
         0gFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lCllcENi;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::8 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683107698; x=1685699698;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=afrYdMnUhxBSILcQDUgUACbzH4BYMJ2Ii6wXSMfLpbw=;
        b=Wr58mOmPHir/QQu9Oyz4an7o/0tYwnU+lYDAab7QN9u7pZyuST1AsRRJUSxGmWBYuv
         lnmcEpSuQrB/OPfEUw/QhmBDlkl/istcjFMuF4ygiFwtAof0tc1wxq2WPSEx64GIhfI9
         PikGb8jsqrMBsLZ5hGt3Z+IizDBBdr8Pa79aqJmjaGnbpYs5Wuf3Br+J9z/ES9dAZo0H
         7Mwtl3cQxUpgAbt8DmUR9zsXjGjwuJiaXsMTwFiuEA4+bGqcoUfTEn4NZ9ILbO2+E5qE
         QYCPBNEIxGwpgP/MYTf8qFrDjH+t36gHEh6isWmigimg0nN25c1LBhm/v1x0lEohpoeO
         x8Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683107698; x=1685699698;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=afrYdMnUhxBSILcQDUgUACbzH4BYMJ2Ii6wXSMfLpbw=;
        b=H63yfoDQWVSGoDU6sZzwARGQP8zFtCPwsDNZm85zi4X46pnlF7onBO+Lz/I+jvnZaW
         LLl2ZWTqdvg3Ei0A2r9UoRyPteQF8YrK9bQFESvPNhwVqmyS4cfzoPEQ2C8MN678C4uR
         27f5se880ulpObnSWM04Kph2fU60Wcm89knOTiFzzXBVdHC4xX1YXorNFe3vVK2IA/tu
         jY7xpPE4C9EdG9ciWZlcAA1jIiBAoV9D9LEPph2iYV4XEl0xIYCbJIe5JFjbroQKfr4C
         Xo2lYp/o4ublehx+NWp3qoSqI3fXLA2OfOhj0glfFBfyTuccqgOXbt9EAra8swwYrMaQ
         1Vfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzo2k458Ny+/TFtKfrgQlmVHZ3+cNTSF7ljOx3q3m5DNQbLC64q
	QSwHFcglk8sj+ILA+n877bk=
X-Google-Smtp-Source: ACHHUZ70u2XKZ3u5vnu7KvzNEY06b7eAPx1vD494TUMaHE3/qUacgGjB8fawj9elNA/fjpMQhY3KsQ==
X-Received: by 2002:ac2:5236:0:b0:4ef:f6f4:7727 with SMTP id i22-20020ac25236000000b004eff6f47727mr678114lfl.3.1683107698375;
        Wed, 03 May 2023 02:54:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4017:b0:4ed:bafc:b947 with SMTP id
 br23-20020a056512401700b004edbafcb947ls245373lfb.2.-pod-prod-gmail; Wed, 03
 May 2023 02:54:57 -0700 (PDT)
X-Received: by 2002:ac2:5394:0:b0:4ef:f6c9:b977 with SMTP id g20-20020ac25394000000b004eff6c9b977mr608665lfh.49.1683107697004;
        Wed, 03 May 2023 02:54:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683107696; cv=none;
        d=google.com; s=arc-20160816;
        b=VB1nJ/hfNe5poNTX8ARuK6k+rMM1JqXTF9gQXnrr37ZRCImAPEXPqKf4k8hpiuwA0E
         binGqHj3lEna+oIl4oroglJ6dhKNAvRfegJ0ip0PwNtfH0ugcod5dqLOFtWhs0LXo1Up
         RuryJqhK/UZrbPM6Wac3scnZkx/6XNzKTLyjiG22cYSqF4d90+YI89ZpXwWUyXztK+eZ
         RLG56vD/rRFzmdTq4wqC2I950cFt19uzEXy5d2FGkBi2uTDZT32VeystDGgR94T9FmN5
         zXEK4UOvP7pzY4fIYV6BZi+FVGKfMDt01qATUSDTf83v3GunIV6KfQsKWpcI/CNXEHaR
         Bdow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=Jg445jwECvvRmiCScPtVAaWcZXXyMj8rYmSMQmAKTHE=;
        b=PbhuJrrNuzrs+1WjvuxjnTQSea1KAV9Z2CjnrBQlQ60oWcgnH97llFQ3z2eu7+ohFa
         l12WOkDppXDM4lnhIxKMwk9shiVsM8OgQEL1MgMlAyYfY8ojTIJ/JjWZbff620RUyWGK
         8pmQj7OmfZh06oTYRh0WpnxTU5RS4+aAGBwjdnEXAKbtp6fkJWUTWbvuDHYjd4iqaTdR
         z0bChPk7cYlhTvIf6zklTQSc6cg5bc78iUp+eKEoWkKCauiYaKmc989V3yKEoOf/DhFw
         CTAqVVffbTf4bMy/RGPC3JvRBiR2TzVnITFJ6U7BXcnKqTowTfjJegblbAy5jvnG6L8c
         73Dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lCllcENi;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::8 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-8.mta1.migadu.com (out-8.mta1.migadu.com. [2001:41d0:203:375::8])
        by gmr-mx.google.com with ESMTPS id i16-20020a056512341000b004f1371664bfsi93060lfr.8.2023.05.03.02.54.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 02:54:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::8 as permitted sender) client-ip=2001:41d0:203:375::8;
Date: Wed, 3 May 2023 05:54:43 -0400
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
Message-ID: <ZFIvY5p1UAXxHw9s@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <20230503115051.30b8a97f@meshulam.tesarici.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20230503115051.30b8a97f@meshulam.tesarici.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=lCllcENi;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::8 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, May 03, 2023 at 11:50:51AM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> On Wed, 3 May 2023 09:51:49 +0200
> Michal Hocko <mhocko@suse.com> wrote:
>=20
> > On Wed 03-05-23 03:34:21, Kent Overstreet wrote:
> >[...]
> > > We've made this as clean and simple as posssible: a single new macro
> > > invocation per allocation function, no calling convention changes (th=
at
> > > would indeed have been a lot of churn!) =20
> >=20
> > That doesn't really make the concern any less relevant. I believe you
> > and Suren have made a great effort to reduce the churn as much as
> > possible but looking at the diffstat the code changes are clearly there
> > and you have to convince the rest of the community that this maintenanc=
e
> > overhead is really worth it.
>=20
> I believe this is the crucial point.
>=20
> I have my own concerns about the use of preprocessor macros, which goes
> against the basic idea of a code tagging framework (patch 13/40).
> AFAICS the CODE_TAG_INIT macro must be expanded on the same source code
> line as the tagged code, which makes it hard to use without further
> macros (unless you want to make the source code unreadable beyond
> imagination). That's why all allocation functions must be converted to
> macros.
>=20
> If anyone ever wants to use this code tagging framework for something
> else, they will also have to convert relevant functions to macros,
> slowly changing the kernel to a minefield where local identifiers,
> struct, union and enum tags, field names and labels must avoid name
> conflict with a tagged function. For now, I have to remember that
> alloc_pages is forbidden, but the list may grow.

No, we've got other code tagging applications (that have already been
posted!) and they don't "convert functions to macros" in the way this
patchset does - they do introduce new macros, but as new identifiers,
which we do all the time.

This was simply the least churny way to hook memory allocations.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFIvY5p1UAXxHw9s%40moria.home.lan.
