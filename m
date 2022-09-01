Return-Path: <kasan-dev+bncBCX55RF23MIRBDUGYWMAMGQEKJZC5AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 808A75AA3D3
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 01:41:03 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id g19-20020a056512119300b00492d83ae1d5sf114941lfr.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 16:41:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662075663; cv=pass;
        d=google.com; s=arc-20160816;
        b=RM5WU2T9sdCYnahyed5fiKYghXOCh7v1uPtCMh1w4LZVoAtz/aS72Ue9ozsjxgvwjU
         Ot5pKnlFXKn5mJADLEcbz6AdCkS/9oZs/Z8fOT6yYuJ0l08qR69sztXBgo0Oa6URiy2O
         xoP9ygxDTvL90OOLUuKrDMgfEVl3Z0UUvGQe1Bw50ctvwYhly+b9RbmYsxrnvoY5p0wX
         dPDj9z6+3vG6JLf8Muh+pw7wLcVo1wp140uCjf85XXxBgUhE/jgcJH41kL8l+nibdbfj
         mO5kpI/fPVonJYUiVdfUuy91tehPkvWNvblNoPmLDHmvuUkCdgfXrUpU9HQIycpWnQvS
         xKlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GGD7paI4gi8cv9PTC5CgWwgBUVo8DMyheIcHrsMZ4h0=;
        b=H+1qL4R/uqYt+9uagEzPR2IgKI8fFfrcAnKwMCt4YoBVvYu/vkLbw+76o245dBm56C
         za28DWd3+hMOqmDmEvOFKTWpn3sAQCf9LobCVpb9xKD9Jl3Ryb1FWYMBU0pEFfi6SQ0E
         CM3SfxcTePk/wAg7rIif4ijHsblFgZHPMtAE+KowESIMSRuCf1uHMVg3aiAzmCxsX5OO
         q2G1nljKf0ue6+sZOndoN0anyDyHXOpPacFdxmUWC9rnJpVMn6kkJ6cNqNWN9pL8czMi
         Fx3SIQVNSq+qu248A5UwgZeENUvQMcIeqO+w2170GXUrqWK4Q59gwz6tIYFAKAEGP3wi
         bSQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=B9gaPrqo;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=GGD7paI4gi8cv9PTC5CgWwgBUVo8DMyheIcHrsMZ4h0=;
        b=CGAgY2Oww5hdg6T9/vKna/qSfMGqiTe4kQcuSy/+ddEVNA9MqwCrXhYtiachhOgwhl
         Nk1fzCbfw4v1Xbs5TKp7MKSPFcY9Rh+stIcNab5EsrExVqJWCftf6Skk7Cpr/YzTqji7
         eTBb2JwzFvVVWBjCnzj8m2pRnxTzj8Ivjt5O7b0NceTOlA/4Y8DaNVjm0137Nwix0Xln
         yuQ2zgVdkZIZ7P3ExwMJ7e75v/8epMwUiOmV+ReUuNF+zdPv1Z5NXF3/67Ow4+Shi5o1
         mUYTWvx7tMA7qH9T1zl7AXDrNnvc18NzG8sFi7A7JaXauu64tldG0mrU+AwKj4jArcce
         Jn9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=GGD7paI4gi8cv9PTC5CgWwgBUVo8DMyheIcHrsMZ4h0=;
        b=5grAjDVCscVPFcQ15xEqYspzCqpkyd/aeuvfMM2DAlin0hrGueYCVEpDCVs+ADMzb8
         aqKvk6RYYRbzLV4Rh7mTh/TM/BpGKumyAI1+XO5v5HDO5JaPom5WchgkHBjrVERAjZvZ
         r0DgoDfEG4xVvsmWFwCUPdbDpNhIvAH68lz4xcazF6a1UqdojUfbgEbt0a2lmF/POn4p
         T+L5SM0Fu3UyufELa89YPCMKy1gsAVNA9eALufAHV/UXA0eoeVFWeCb6Lou30qHpPxDG
         KU83JVbS/68EURJPteVyZu1sd60Av2RFGRUxomtGdfibTKDoLSa6NOt+qk6ZAEZ/xhIf
         ZU/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2lzzjJDznezrobYh3q1ntYP7qT7AI7FGpKC64tnKncTYWkpWkk
	QTfqxrJhuXsZl2ZjeICvOYU=
X-Google-Smtp-Source: AA6agR4z3VXbU8Dfe/l08tl5BwyrO34BlrSzVdO8dcGlYm1UxR+y7ywTxmpUCDC0dUoTpBb5AS+6Sw==
X-Received: by 2002:a05:6512:398e:b0:494:a211:db80 with SMTP id j14-20020a056512398e00b00494a211db80mr915493lfu.402.1662075662827;
        Thu, 01 Sep 2022 16:41:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3fa:b0:494:799f:170 with SMTP id
 n26-20020a05651203fa00b00494799f0170ls287740lfq.0.-pod-prod-gmail; Thu, 01
 Sep 2022 16:41:01 -0700 (PDT)
X-Received: by 2002:a19:ad47:0:b0:494:846e:bf0a with SMTP id s7-20020a19ad47000000b00494846ebf0amr3704983lfd.576.1662075661838;
        Thu, 01 Sep 2022 16:41:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662075661; cv=none;
        d=google.com; s=arc-20160816;
        b=uuZ+7NzWAbjCxKPxWzN66wN3OGaQcSct0ZslekXLodfVq2Fu3rqSY7tPpYhOwk7f03
         2TqBiPth1ZzgEWfdVsxhTphMxQfBzw3hBklpMlTgTBJLajyxnr6ul1N/9bqvi5ry1h9n
         Zc1zeaDogo6o0z9fKlTmfTX9/zGkj2NLjkckzOwgCwLWlRTWNf39Ji4E+46C3RfddmW0
         TXhpdZsV6/RgH/3C/uiYofSmLyV7dl/sNOCf6XR89lMg6IapfTuO68zs/fjW4sF36dbr
         t6E5WD494AvMNyLX80stfSPsThyLbeEWNlQYGGPBdK/jGNlXq/zlVzBzJ8/odo9OpVFm
         SDug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=VCjuzNKAQwi4WscZTTheCwWMDo51dWnYKGYDxlIvOxM=;
        b=qYc6mRVlPZ6CslsRazw5BDMlZ2s0Y6aIrhW8Y7IYp9PPexxWNJtxCN05frbkv/tPSI
         m5v6MeZSIMhH3xKwNQ8p7AUcex8ObGPghisBhmRPtmxup8042uh2pMKnU9NB4cgBW/1C
         ZwNZNSLRX1Z36bICc9XZA96bsyB+PuPpEFPi9HB+/g118vOxfpvZon7wdvzVnn54j0Mb
         yfiPlgeGjGVDYrQk2d/t7YxeGUD7yIzEVLktpE1LWvQhiZKrmJmzhgOngZvSqW0sPACO
         1cDJu2Dsc377lE1lS4PB+SdiUJ3GcFIzbGjNs+XKLszuq51e7roqPHGsDk/jarEI0Fgb
         pYcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=B9gaPrqo;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id k9-20020ac257c9000000b00492ce810d43si16493lfo.10.2022.09.01.16.41.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 16:41:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
Date: Thu, 1 Sep 2022 16:40:36 -0700
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Roman Gushchin <roman.gushchin@linux.dev>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 14/30] mm: prevent slabobj_ext allocations for
 slabobj_ext and kmem_cache objects
Message-ID: <YxFC9NSQ7OADTEwp@P9FQF9L96D.corp.robot.car>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-15-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220830214919.53220-15-surenb@google.com>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=B9gaPrqo;       spf=pass
 (google.com: domain of roman.gushchin@linux.dev designates 188.165.223.204 as
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

On Tue, Aug 30, 2022 at 02:49:03PM -0700, Suren Baghdasaryan wrote:
> Use __GFP_NO_OBJ_EXT to prevent recursions when allocating slabobj_ext
> objects. Also prevent slabobj_ext allocations for kmem_cache objects.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Patches 12-14 look good to me.
It's probably to early to ack anything, but otherwise I'd ack them.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxFC9NSQ7OADTEwp%40P9FQF9L96D.corp.robot.car.
