Return-Path: <kasan-dev+bncBCS2NBWRUIFBBAWPZSRAMGQENI5PZ4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 621D76F635B
	for <lists+kasan-dev@lfdr.de>; Thu,  4 May 2023 05:33:23 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-2f479aeddc4sf3716874f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 20:33:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683171203; cv=pass;
        d=google.com; s=arc-20160816;
        b=jPW/YdqYBNP7a402gbriJaOEgAi7g+LSIZtLLjDdmNrYthmfRumEqDYdkNc6+L8V58
         RjZbJ650qLOe/V9atTMznyRfIKTM8h7i2j+FLafxCJUUYPLaH3tPuO2zo6zTTpZyLokr
         Wpyb7uqs1qV6vtURVpjj86uou1x+xoP/wWKokW49z+uTAQ5hxHuxQLx1Dh5wlNnEwXrx
         D8V/S4bZunTCwp6v2N0O/Hr02BtBG9PaTxYUACBbR8NSV46pS1Nq6HzmuV8M4q4kjwQs
         qpapnkjIjVBDudXn2lRCz9CfyyhJTAsYdCCVs+9UWgigt0qp6weCmjtdQLPg+nOXMZ3v
         Dc7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QUNmsFSadHy65PIJDsVEcVDoCg71hiGBeDK+kl2HHW8=;
        b=zkbGGCDDMAESTXArvCVgnXjtQT7eGG3sn9z7gx3fOkTxqon5sOfPWNM51Amhzrz4jE
         aBYiDeb2CPtRTdjP9PhIMNnEVTaZPp02komOdPor14hniANtC5dCVjNABTrYbXpzNXYd
         DEiT20aT8+4CRe8zCcQKDw/62aAifjTxWxzZsE8E4Gwt72EhlPxDu5173BrdXtOF/3Y7
         7vy++qIq5e0udIJKtFt7LJiQXJji2HMlRGTLQv5d9Oz5i6/WLjnbuftvFZD8NdN5RJk+
         tcZ1svZ5K+cecdRCSSGJXHYl6+TDQGYVmdSr1k8JYQcqygW/VV3yz6R6xzuvbJAU2mLg
         //bA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=l06qAFau;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.12 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683171203; x=1685763203;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QUNmsFSadHy65PIJDsVEcVDoCg71hiGBeDK+kl2HHW8=;
        b=kz2Xu8VS3HgwCZyBFw1Vy/XbFyntGQqcObIAPkIZ4PiGfSiOnk0dqNihCRARWiu/+i
         7rJedrNHrWkK5z0P3Fz3NnWjOxtr/MV0Pf+l4W2JWRRklWaWjuLvfSZygrWuBSZoeWON
         PVSR3xb0NPh4D1Clto2LSaF3WLSEUrKAOmbVi58OP3VtTOuNcPMN4c1isnPEL7pt2Bsy
         pyir/C5Uh9P8gTS95yDfEOYiuOVwelrdbzZuxwwebCMyKxReqAQebjzulcKYJ9CMpMl0
         atlT09XJDFGuCNSuiikqWgU2sp/DZShIeD5CNnh07A0VpiAvpspzWLqu8Zz7JYVQjm8G
         cfxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683171203; x=1685763203;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QUNmsFSadHy65PIJDsVEcVDoCg71hiGBeDK+kl2HHW8=;
        b=Nq6Fd1NwhLr4E2XLG5zFvq+WonAYr5hzIUTqdd+8BIqrc+8JDOxyGPfWv9JDiRjg4L
         RNg0ufSJY4aUVjSRFuO0sJFyKKidiQfAM2svjeRuqSv7JU+c65X3iC3HyZDr5VMtUM0y
         0lic/3oYADi/qFWX/dFCalsbQS6l3RpaW0G8IkWD7zz7gIJT1Xa25vchPWAlAiYwMJdW
         kDFMfBSppCdvOc5IDyk3OrVRQq9Ma8bMEqBIqzzPVTCXQNGN8+8hFxnJcXUT9KCPRa8e
         sxi+YaNKTFvthf02mtMRMGbEM3ywZFfsoNj1En6ZH+9CFCDd9XRFvR0CLNFT5HdPkPo5
         x60Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyyAozSmRMgCIoo014e3bcDLfHMvUiEwFfHvavVpOTUiqG5Dt+j
	Hrcstb3MfPjBCf/cQWT8o2I=
X-Google-Smtp-Source: ACHHUZ7m9px0+SjKyBqEswLPSSSrDwDZbF5var9XySJterdDAD9j6OqGv5fjJoypVdL3+rxcEpzbQw==
X-Received: by 2002:adf:e7ca:0:b0:306:3355:a19 with SMTP id e10-20020adfe7ca000000b0030633550a19mr352799wrn.2.1683171202742;
        Wed, 03 May 2023 20:33:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1787:b0:2f8:4432:9c7e with SMTP id
 e7-20020a056000178700b002f844329c7els2479951wrg.3.-pod-prod-gmail; Wed, 03
 May 2023 20:33:21 -0700 (PDT)
X-Received: by 2002:a5d:6050:0:b0:2f4:e96e:3c86 with SMTP id j16-20020a5d6050000000b002f4e96e3c86mr1360370wrt.14.1683171201492;
        Wed, 03 May 2023 20:33:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683171201; cv=none;
        d=google.com; s=arc-20160816;
        b=WpzIneY0k2LtKhw4QxMDuAUssSPpxb0THzQHl7n8VHmon88yjKYDIVriu7BuYRAXm+
         KWQIPhDyc+nSxFdvKqkPP8KeYcXvH5VkHcmjoJ9EPDmvPncjxRE3xOWu1G1Ys00ZUBcM
         YZI6uSqZjGKnx3GLAocuCHK03DJDRfke2jQUnbYfIp4OQdd/ajl3gVYZi+72IEoacKHT
         RnRXjYcm7yjVCwRQIjLEWKNjVreDtjSOfkdIE/9tamTMRaIDGxoC3Fj5JgFgXKJBVBEW
         +Al9UGWLlyospWef0fonvR6sykVayxCYhyKwQt77/OCDQp9WWm+ztmOjqf4a1OX429f/
         UnrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=LHQ0tWOiBXePRONe9lmx+CgLFkYWwKAc8GKV4/q6DkU=;
        b=KLp5HLTjU/xXMjf7JYjEsGRT2p0XUSyZzyFd88WGN2f1SvZ/75RoP43S6Hl24E98QA
         NTQ3Hg4LwJg9j9wvo2vKWL5iUwp70waY8wBzGpLNVig//xOTMTV4gV6MD2QORYzH2Bv/
         w9deCFhnFnZ4Jkv1RbC7kWNZgNUUX/7hi6q/qQgpUztGapvmev9RhXuM7on8dMZwxzc8
         ZkYVWyuxzWM41caBhn1A98dC9nc2hw7Z3T9k6wqeyYLdQUO+2ANTfxQuS6gbj0ESbmxM
         McBnWkg2cHDBj1uI3nHoT/wtwPN+lMsS3TLckCiLnKQD4R5EUOLfIsbvweJaM3uF6beh
         O/UQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=l06qAFau;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.12 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-12.mta0.migadu.com (out-12.mta0.migadu.com. [91.218.175.12])
        by gmr-mx.google.com with ESMTPS id b7-20020a05600003c700b003062fa1b7a0si554849wrg.2.2023.05.03.20.33.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 20:33:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.12 as permitted sender) client-ip=91.218.175.12;
Date: Wed, 3 May 2023 23:33:08 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Tejun Heo <tj@kernel.org>
Cc: Suren Baghdasaryan <surenb@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
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
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
	Alexei Starovoitov <ast@kernel.org>,
	Andrii Nakryiko <andrii@kernel.org>
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFMndF/nnJyYSMuc@moria.home.lan>
References: <ZFKlrP7nLn93iIRf@slm.duckdns.org>
 <ZFKqh5Dh93UULdse@slm.duckdns.org>
 <ZFKubD/lq7oB4svV@moria.home.lan>
 <ZFKu6zWA00AzArMF@slm.duckdns.org>
 <ZFKxcfqkUQ60zBB_@slm.duckdns.org>
 <CAJuCfpEPkCJZO2svT-GfmpJ+V-jSLyFDKM_atnqPVRBKtzgtnQ@mail.gmail.com>
 <ZFK6pwOelIlhV8Bm@slm.duckdns.org>
 <ZFK9XMSzOBxIFOHm@slm.duckdns.org>
 <CAJuCfpE4YD_BumqFf2-NC8KS9D+kq0s_o4gRyWAH-WK4SgqUbA@mail.gmail.com>
 <ZFMXmj9ZhSe5wyaS@slm.duckdns.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFMXmj9ZhSe5wyaS@slm.duckdns.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=l06qAFau;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.12 as
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

On Wed, May 03, 2023 at 04:25:30PM -1000, Tejun Heo wrote:
> I see. I'm a bit skeptical about the performance angle given that the hot
> path can be probably made really cheap even with lookups. In most cases,
> it's just gonna be an extra pointer deref and a few more arithmetics. That
> can show up in microbenchmarks but it's not gonna be much. The benefit of
> going that route would be the tracking thing being mostly self contained.

The only way to do it with a single additional pointer deref would be
with a completely statically sized hash table without chaining - it'd
have to be open addressing.

More realistically you're looking at ~3 dependent loads.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFMndF/nnJyYSMuc%40moria.home.lan.
