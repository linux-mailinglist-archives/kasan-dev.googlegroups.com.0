Return-Path: <kasan-dev+bncBCS2NBWRUIFBBAGH4CRAMGQETITNPRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id B440A6F9C6D
	for <lists+kasan-dev@lfdr.de>; Mon,  8 May 2023 00:17:37 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2ac82617bc9sf16733761fa.0
        for <lists+kasan-dev@lfdr.de>; Sun, 07 May 2023 15:17:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683497857; cv=pass;
        d=google.com; s=arc-20160816;
        b=yzrGZj7Dru+Hnai0Kwznz3PRZGgAyEbQqyeAVAKXhk3RNML3O4M2/NkVTGx75aHLSg
         GhpX0Z0vfMKgHNhlbgB+mJqVQsAV4nK/0vR2KTgQ70LZzWaoysSV+95tT7gmDAh53CVd
         RmpsqTWS3ndYqjW+x8oQpW8j8Nx4+zbV9Y5HBtGwbmmTmE8obP7flboh/ILJ3rLFIPZn
         nqF5JShOk7QLcilRknZGyDtTwp7Os3gYmYapANHN0d0Vh1S5CX5DMYhyMXi/0b0TR6pH
         OsxmvKBq/UVY8nfHKssnDZUSyNxwrfYvN6/8raWDmUhqcWTzpO3InXaG3BSdf30srppF
         RGJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PCCBRH6yd515nRpTeDR2wonXbUlhXdCdCxNfHbGAlfM=;
        b=hjMCOKXXLpO1zZs99WYvYCvkQMd1cBIx6bXd8XfrqWDNZ9RdzQ6L3IHmAIoL2fjnO4
         Ux+VV/cS1e2MC+Lp2IaFpJrNfxsXerfD5prxX8r934lkxP5ygdWdRHsDY8xyfYBPUItO
         AlK8TX2PFA3ze9INpU7yVrbG1U7+DExvjVyTzAMW6pF17I/CfcgAGmr52QM5mTuhuflI
         3nT47G2BYzYQQW1s3PNSsQakvW/Xbz5Y2Gxv7TbN77q34JI30VLlKQto9rRF4D3vMBuI
         TfwOK2oRV3OWOfr2CN3FcgBqX+uR8nAYM64v5JZrN3Bk37mpBPcu6uu64pDddxNvxOcX
         r3gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ea2OCk8F;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::17 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683497857; x=1686089857;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PCCBRH6yd515nRpTeDR2wonXbUlhXdCdCxNfHbGAlfM=;
        b=EgIg5C3VG9iTdxPrALnIpzOLvsSvTgXJoF6M4goJZTR/Cn3sTpQb1iN7YAZQ7TQize
         lVeLBstBKpYXT2WKIF4PvhuA3P2weZUdqsQw9ZvgqtRddtD+6F9a0qc1Zqy4XzwHBrgv
         3ZjVfgFe4iCriyjCDPnrLd1xmQqHXW8ho9VyRLHJRPslGt/fNUyTAJBIYp5mI/5p/3JZ
         8O46aPALxwte6Fm8WMrswZFKWHJa9hjtMiHlaNm36fKfPa1zbewY3p9bqwnM1Uy/nMuy
         8GPIUXfP65857VSRczW37U2OTxoEmHhZaLJDqPvJkgCHRpjF9ZTL7QowlXDHfnfSh030
         s1BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683497857; x=1686089857;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PCCBRH6yd515nRpTeDR2wonXbUlhXdCdCxNfHbGAlfM=;
        b=b6W/r5TwQMDrhV3ofnj2yplfj3uYv48PJ4O4qk7YGEPgbmLAn/ILabyDjHv/LbbxzI
         cOzk6eVHaH9qBGpAEkiw2FX+eI2n046gbH5WtbjOgOLU9s/KsNG8vecxcnt6L1E2mF/J
         4pX/LeIE9nxi7m0YEBFZ6b9t8E+9nmKSQyHqexxlUjCsN1LiRkVDM9IrVdOQpb3G423M
         5bErILI4Ty2wVf3QTs/vviiEeRSrTipV97hsOR/YrZOQ9sUj5jB4nXq+xlRm5j9HVDb/
         Cc0d3EJ8kHZue+/qjTAXWyxW/lUwlVIh7oeWiH5DbFZO10Qe2cFeFfiu322XTcrGkrov
         CUuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxSgGm1PwlSpj3gaQeCjx8Nzpe58tCtay6NS13UQFZ2NGphl5ZT
	L4PEYA/Y8ie3V1ATpqkLpb4=
X-Google-Smtp-Source: ACHHUZ6Ezq2+tlR9UvorehPoLyhs842dxzWIFY9qGdOV3Hf/VLsKMLkdCopUCOnChNC6PobGDDGVYQ==
X-Received: by 2002:a2e:8783:0:b0:2ac:8cfc:97a1 with SMTP id n3-20020a2e8783000000b002ac8cfc97a1mr1783367lji.7.1683497856815;
        Sun, 07 May 2023 15:17:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8913:0:b0:2ac:6805:ece7 with SMTP id d19-20020a2e8913000000b002ac6805ece7ls2778421lji.6.-pod-prod-gmail;
 Sun, 07 May 2023 15:17:35 -0700 (PDT)
X-Received: by 2002:a2e:3305:0:b0:29b:d2f1:de9b with SMTP id d5-20020a2e3305000000b0029bd2f1de9bmr2222935ljc.47.1683497855398;
        Sun, 07 May 2023 15:17:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683497855; cv=none;
        d=google.com; s=arc-20160816;
        b=fwykeg3Ex5ThG11TW/BEWCOCrldNJ/xwn/fLgNwIpohc4cKaFv/od2tUL+rZi9wo6o
         +zbHyxJYoAFtqgpr2sh9TNcGoEDQ0ikU1DJWl8n+dt6TRrVo4iCLDM/z67tCiTx101fc
         iMx2fng+kgS971ryRexzBYnSh6aD/Ge4+cSn88vY/PmRkuk7jhXqWOUpFzY5CXnV5rvb
         AXirD/eP7wKEuc7fiBcczM8QQ1zZ60ZzPwtgENdpS5dbm6zBZSwBkBq2GooQbX6DgjxA
         7yYloLrpL8+bfNVeDb/OlmOMUbpyfdvfgkXqRvoUtRO2IZSjf0OV/Wlqs+BdaZ1juMRD
         Ecaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=d+lJOOnfhP+AzQ3DkEk85/ecgDN1f+ChvYq0lSwsbl8=;
        b=wnr/nauBdZZ5BeGN3GpjkmuXPcol7rSlsMEMzqPg1AC49IqjoalWFWHt2uy92exKdo
         x9ahDWNpmylBGpFd1cGMowCjRTqPmgWLOco0sO65Z+4EtD728EaYVDAAr4oQ4DnWdbjM
         7m5nayJNUIUfNRhZwCK48RP3t+h8Am62roK6e26tWtHWfCWJWUUTDH5G4Sq0EuT8b+kC
         ZXu/uL0qxsmUosa8E5vaLs5iKIXK99bkYEipu60JjtDxE+YTdVTyQO0jfnV2BVRoHDZK
         eClsIyjoXAKf39b5DxL8Rc7ZKhVdbcrSnfq+jKhuUTANeZF7sOaWq0gKhl0YV8+V+Ca6
         ZyZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ea2OCk8F;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::17 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-23.mta1.migadu.com (out-23.mta1.migadu.com. [2001:41d0:203:375::17])
        by gmr-mx.google.com with ESMTPS id i22-20020a0565123e1600b004f145ea0d5csi488776lfv.11.2023.05.07.15.17.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 07 May 2023 15:17:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::17 as permitted sender) client-ip=2001:41d0:203:375::17;
Date: Sun, 7 May 2023 18:17:23 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Steven Rostedt <rostedt@goodmis.org>
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
	dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com,
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
Message-ID: <ZFgjc3rGbqGNONnS@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
 <ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
 <ZFfd99w9vFTftB8D@moria.home.lan>
 <20230507165538.3c8331be@rorschach.local.home>
 <ZFgdxR9PlUJYegDp@moria.home.lan>
 <20230507180911.09d328c8@rorschach.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230507180911.09d328c8@rorschach.local.home>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Ea2OCk8F;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::17 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Sun, May 07, 2023 at 06:09:11PM -0400, Steven Rostedt wrote:
> On Sun, 7 May 2023 17:53:09 -0400
> Kent Overstreet <kent.overstreet@linux.dev> wrote:
> 
> > The underscore is a legitimate complaint - I brought this up in
> > development, not sure why it got lost. We'll do something better with a
> > consistent suffix, perhaps kmem_cache_alloc_noacct().
> 
> Would "_noprofile()" be a better name. I'm not sure what "acct" means.

account - but _noprofile() is probably better. Didn't suggest it at
first because of an association in my head with CPU profiling, but
considering we already renamed the feature to memory allocation
profiling... :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFgjc3rGbqGNONnS%40moria.home.lan.
