Return-Path: <kasan-dev+bncBCS2NBWRUIFBBZVX4SRAMGQEWEEC7WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 222BA6FB47C
	for <lists+kasan-dev@lfdr.de>; Mon,  8 May 2023 17:57:27 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-4f14f266ac3sf4939175e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 May 2023 08:57:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683561446; cv=pass;
        d=google.com; s=arc-20160816;
        b=FZUCsO9OmqJUxlzRCfQIbi9He9NGKANhGWtPC8MSVSWL3+zmK8vcWDx9yCBEEMlIlY
         bc/jmDTh4WIL2L4HnkEwnZiUbl+3Tiq6XdOvpmNCQqkZIOHIxPOMVr1QUeE6R/VcYKFD
         mZMHIEGaHvYtvBiaZ6hLNo49V5+O/rvLRAsFDIgnXmwdvwOtqgOJAep+ZxCvNE+D1yug
         6ZGv7coz1SM0PhpqTXIa2Fjxj395Xyrpnl3zFy1t3fQnhhRgXzzhgvM9YqcXPuK747ac
         C76CzxQ25vsQqxQb9ZamU+VrxIIg5sVqxjNPGu56IWVGnTRpTK/TsuXcJ72ugnsFqAQN
         6Sxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=f5/smnQ2EYXRXJOc+6oRLDT4vscK8XtLBN4huPMO9qA=;
        b=p0qufILq0yHoS3L2br4SbKMHJnEbApeD4tOV/6oU9RsllBqjuC+/ytU6IrRDf6QzE3
         s8ZWB+lhXPqrAuEl2obH1wGWQ8c3D7cIPzs+c/u113xFXfg9POWM50j1/AKur32VppcK
         uwq0d7XXbE27ls/Na6SxSQu6SM8IYOIlY/ZcmQLRzw/6FLag/GRDFD+Wa5T6GT2Vokdr
         78W91NqdoBwrGBw2siKQMbKGZIfGQ6Ve8Dhr5TSfIkxY1L+LlvurwsBbJ5jEcKQ43pPV
         uCHX4QYfOt5R3qk1fgVN0pr/W+4G8p5cfZE7PLq/YA/c4ebvJrUGxIXKtqdoR5hbSveW
         b75g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pAEukJar;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.59 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683561446; x=1686153446;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=f5/smnQ2EYXRXJOc+6oRLDT4vscK8XtLBN4huPMO9qA=;
        b=DTHhYWZS3F+qWYoiKI7l0NFz36Lu9vWmKBRDu3JQiD5SPR+/tvuLT/9uTIZMLDoCiT
         +YfpkQQuGzq+CfVZL4yo4g9Fl8Y86/8My8yh+vOXbrgVlUhEdXm+uyByMmYbNBjNeTYr
         EIddswegCaJBiB2nARVNStF2uGyDeZwcGx9EDphr5hj7RV+fSmHDhomwHrGyPccvTtcM
         WKbVVC8D3dm5GvUFU6Rw0yy1lLyUcRnF0qUcPy9YkdXNlLCDvKK38yp9dauvqu5qk87y
         QAQiSH/N5LNHW7FIfvV5Yp4+dxDRrPLZerMK+J2xuelke97U5LeDTVuTzknL5l9Bx3ir
         iB5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683561446; x=1686153446;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f5/smnQ2EYXRXJOc+6oRLDT4vscK8XtLBN4huPMO9qA=;
        b=O9zCtXA5xKeQ7FP6ouu0J6whz5sWd81TFC5X6AHKRAuyarhs2f1VyVrNwUdfTqvf9O
         wTwlCrMI2Me9dWR5b/hf25XOgEU4zUZqxqjUrlQxwSHNtWy6na5mxdvEDUjQ9flZj5xq
         2vftYl7R/bVUHOzs26oSS/YSK2tdgo9XsXghqsCkagDHUl3JzGBNO0h+6QM0dORim7ig
         3r5tdpFy/S4RS+288+3SwhNsrklZ3XiGrjw1tkItWkDN9Kk8J6oBjPnTKyuIoOmstJYx
         Y0ASD30qXwiLtVC1Tpc/c8TIJwRvpoHSCaNkRx8pP/yyUFTEXvgaUSjCYyETIEVm7h9C
         BdDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwe+0NhDLro6lomUvE/pHAZ97QJ1edN/QFIADlt6jXucZlssZDw
	X0rhjxDBf1OtyXusMA3zq1A=
X-Google-Smtp-Source: ACHHUZ5f9tmDH6PLKavFrPiWlk2WsEepr0GHM9KV+ZE5gn2RyynvuDliICTyP+0F0454ExtZEdoTGw==
X-Received: by 2002:ac2:52ba:0:b0:4db:b4:c8d7 with SMTP id r26-20020ac252ba000000b004db00b4c8d7mr2638955lfm.2.1683561446290;
        Mon, 08 May 2023 08:57:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c4:0:b0:2ac:7fef:f49f with SMTP id x4-20020a2ea7c4000000b002ac7feff49fls2012605ljp.3.-pod-prod-gmail;
 Mon, 08 May 2023 08:57:24 -0700 (PDT)
X-Received: by 2002:a2e:950b:0:b0:2a9:fa39:236c with SMTP id f11-20020a2e950b000000b002a9fa39236cmr3184295ljh.9.1683561444882;
        Mon, 08 May 2023 08:57:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683561444; cv=none;
        d=google.com; s=arc-20160816;
        b=mNtMFmUJu0JKl7UYyvY7EarXeCaE2wGw1srrMK8pCCbMJ0UnD27Ob58fHxRkxXxjOt
         8nK2cILDW0loctygVzsNraoulGX+4kYx/9wDdYffse5P9zr0DJ89yeGhwYpk7fESqCLp
         QxpRORpmoC+85Bl/e5aeWVLVlK8ZBxiCu5aInrHkMD+c+8u+KvBnmixE5awCa2ngp51c
         pV7UuVZ3XxvDW0L9oQ3YVAxdlIhZGtDuqEVMBNN32FfoHdL0C9WGep2PHDrT92uW6tF6
         zXSgIUiEII4mC4bHTtQIQ1NUeNiikVyrRvtYCoN+m4EUZf/kok1jMGBnIUs53MSAY76v
         rvFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=647sHPv4B7hFuK57ZzB2dzj7RoLmpQ+nMy5wXGAldL0=;
        b=irHm2RCwvDZ6g0O3Tj6hZ7i5G798o3VE44HzcsRFeoDz1SHqLmmDP01yU6KrqC4HrY
         LCZN2g9iIv70KTP0zWjFDjkWKog/zc6BK5kw06LrdGl7a8obSpfexXMLyVTKkCBke2y4
         0UfjQgmXt4+6IlOeKlfcUEEuRRY0GtT8wCa9QkFB11rjPY6QnPVMlGun32ALttaC2lvM
         33QxFlLNeb02CZbZ+YlTKa+Udm6DU4BiFNsTcshbNizspAk7E+w8wMIjIoo41WO9koNM
         l9bjADCOk5vjeT//WY5dB3ojbDNrI7FaU1ebwz6JT/61SmAUHv7LxPyeFPq2LDtsEzmT
         KRAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pAEukJar;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.59 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-59.mta1.migadu.com (out-59.mta1.migadu.com. [95.215.58.59])
        by gmr-mx.google.com with ESMTPS id bz16-20020a05651c0c9000b002a8b2891ba7si459775ljb.1.2023.05.08.08.57.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 May 2023 08:57:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.59 as permitted sender) client-ip=95.215.58.59;
Date: Mon, 8 May 2023 11:57:10 -0400
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
Message-ID: <ZFkb1p80vq19rieI@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
 <ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
 <ZFfd99w9vFTftB8D@moria.home.lan>
 <20230508175206.7dc3f87c@meshulam.tesarici.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20230508175206.7dc3f87c@meshulam.tesarici.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pAEukJar;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.59 as
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

On Mon, May 08, 2023 at 05:52:06PM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> On Sun, 7 May 2023 13:20:55 -0400
> Kent Overstreet <kent.overstreet@linux.dev> wrote:
>=20
> > On Thu, May 04, 2023 at 11:07:22AM +0200, Michal Hocko wrote:
> > > No. I am mostly concerned about the _maintenance_ overhead. For the
> > > bare tracking (without profiling and thus stack traces) only those
> > > allocations that are directly inlined into the consumer are really
> > > of any use. That increases the code impact of the tracing because any
> > > relevant allocation location has to go through the micro surgery.=20
> > >=20
> > > e.g. is it really interesting to know that there is a likely memory
> > > leak in seq_file proper doing and allocation? No as it is the specifi=
c
> > > implementation using seq_file that is leaking most likely. There are
> > > other examples like that See? =20
> >=20
> > So this is a rather strange usage of "maintenance overhead" :)
> >=20
> > But it's something we thought of. If we had to plumb around a _RET_IP_
> > parameter, or a codetag pointer, it would be a hassle annotating the
> > correct callsite.
> >=20
> > Instead, alloc_hooks() wraps a memory allocation function and stashes a
> > pointer to a codetag in task_struct for use by the core slub/buddy
> > allocator code.
> >=20
> > That means that in your example, to move tracking to a given seq_file
> > function, we just:
> >  - hook the seq_file function with alloc_hooks
>=20
> Thank you. That's exactly what I was trying to point out. So you hook
> seq_buf_alloc(), just to find out it's called from traverse(), which
> is not very helpful either. So, you hook traverse(), which sounds quite
> generic. Yes, you're lucky, because it is a static function, and the
> identifier is not actually used anywhere else (right now), but each
> time you want to hook something, you must make sure it does not
> conflict with any other identifier in the kernel...

Cscope makes quick and easy work of this kind of stuff.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFkb1p80vq19rieI%40moria.home.lan.
