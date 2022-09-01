Return-Path: <kasan-dev+bncBAABBP5IYOMAMGQEKZP4BXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id E39505A9C14
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 17:48:15 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id s5-20020a2e2c05000000b00268a8808e87sf1410577ljs.8
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 08:48:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662047295; cv=pass;
        d=google.com; s=arc-20160816;
        b=UU5fO5sQWJGCaLpD9YwcvcXQtXtzazKDlLlhV7nkcXloOki29HXsRKfsQnJWzzlV0b
         BHrk4sUC7U6Q2Id9J59zZNDutSmHc37CkYICyJRZp17x/5eFQ4F+5K+upv30Hu73jsft
         wU5BsjjFeNHjq7dQu6GHNvqrr9zFa8pU6xNbFytaXATk3VxJcEpv2zJjrCyYEb1iYwXp
         Y2sc4BhzaHapzw/udnU0zQW4NIUeWmXcvwzdy3PUsrmd2OVsHTLTKFLMpXoTr2WBfMxf
         KxtmkiuxAgiMBYTWDx+o/iyJwd0s0jDXGH+5L1nKl5siv9x28ve8cVgX4Y4hfdkAe1rO
         TYbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=pK4cgDQCMPCsa3EbA5N5SitMg4WKMWQuLlQ7Nc6/PL4=;
        b=Jher267M6W9PqrZ0ySiNLVZ10rYO1wV+tbFD6eBNxpa4gtJopoovyL2b/9qSL/65cR
         sRHbc9zbXVbRUgULO2DID17lJ5qj2AH+VmnIhUzH4XqU70j9ZrHBtcPAD1qwBRa7xoUe
         kPJwxKFozR+HDUsR+etZUR9/HV75XsD9BAbULUuxKgf3dDZDaoI5h+lJVgQihiGpHKjQ
         GzBewhHeS/9xxDZ/qu2X1Nzh1QFIsCY0SXJ31+r2Am0RndY2XhjZu7FIFjIZIx53FzA9
         aJ7FESdd9ruAq0uHro9Vxl/gcRD+G5d1480Vond4twlBAgsrlIRMPtGV2yp3fA+odgVx
         e9UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Q1w1fehR;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=pK4cgDQCMPCsa3EbA5N5SitMg4WKMWQuLlQ7Nc6/PL4=;
        b=rxKHlVNNN2X5/j6SU/Qmd6JcDzTrzbASVyrnkWD3lZk5Kv7YPwN9lXSCuhEG6/o9Ng
         Z8eBxfu69hCd95mtT+blV8UavSdOv35M0YeLdsakJ1nf7YMFAV6uFve6+jhpcnyrag6q
         Hx69rtGGU0NHauWPiIFcXUu1HB9rqTWzl0L9M8WjFf83PLui13Lfs8fBgWvu3mlxtJvU
         /dlUWtKMTx/l5Gll7CuU3dBQEt7fnrR2MjKBOZIGmFr9wBQKZhOXrFTIT5HtVZ2kS/a3
         nzA53oMdskeJ6kABUtlw2H6mb+B/xXHBDY48DMGcCD5zWfAo4oUaXO3xMG7xT5SR7zMl
         aZzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=pK4cgDQCMPCsa3EbA5N5SitMg4WKMWQuLlQ7Nc6/PL4=;
        b=ggBau40KpLTIIS8l9LHJO9s0hbR0QXMOK9eDCa9yFbpn9qNxATKUm2k9bAGpkLwiuH
         mtdlR6RtVnHCslsmmZkyVKVLiSUwQOObbVxTThd3kVtw6wcQKwvb/oVOEkWdgp8K+iRl
         vl4xW+QfrgM8NciAPAgbaDf90JMnp5W/zVF1P/5eYgRuhdNAwlak7f89FdSOxG1R6MST
         XEXpQk7v2nF70kGMLPI+xy0zl72K8T+w2ilcbjMzOKbepGClSw4j4ONcS3DztPVa3k/2
         cvoUUb5VQ6mpzRwkjNNXh7jkXjEpYodn5NENZKfklt4WZo8o56IwQcpxMacE/f+qYIrp
         Grjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0SK1VUVxxP8/UkxjuXxx+ABi7qgV5ImAn+91vyE+alTJhL/HXr
	GcWh1UAamjGtaEmawBOsvxY=
X-Google-Smtp-Source: AA6agR59NHuLmg21IfXIlC1U45InTFYYdjQQ1s2tQ710SOif6bdg4FwfzOoZXTF1jFNCmxAzZJCVpw==
X-Received: by 2002:a05:6512:3049:b0:494:72f0:d647 with SMTP id b9-20020a056512304900b0049472f0d647mr5741839lfb.513.1662047295441;
        Thu, 01 Sep 2022 08:48:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:106:b0:261:d944:1ee6 with SMTP id
 a6-20020a05651c010600b00261d9441ee6ls410814ljb.0.-pod-prod-gmail; Thu, 01 Sep
 2022 08:48:14 -0700 (PDT)
X-Received: by 2002:a2e:be28:0:b0:25f:d901:16ef with SMTP id z40-20020a2ebe28000000b0025fd90116efmr10391220ljq.126.1662047294574;
        Thu, 01 Sep 2022 08:48:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662047294; cv=none;
        d=google.com; s=arc-20160816;
        b=RWCJC903gPXwJStC/vaN+jnZ2sJ9QjpEfA9s+vwI795UwBulCMdSwhmfBq4Tec3ttx
         YaTGGZMgKL2PDqZXpei8AZ9Uw3NYy7lJlD4Icx83VGAOGq+kFW7htTiascR2Uc6P4mPP
         77lNMgl4XBPCRjyVr0SxNj4+IVaLx4eGG5/U8hBaugGuzJ5ojWbAKMSMerNGI9nIWCjP
         CKo8PdgmuNpabI9Ppf5AEyaL8vQMzRuDMpuVBdZEcGSx327W4WL4OlTVrGp6LS6P/DpK
         UvWa09UKkIAOC9dITA72ePM1CJHrVl1vq464Jhgy0S2HrWbHF7Hskh2/wxrgwccFOAAc
         NtcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=3q2ab5lCOZK9vdiUhbwubrfwUeXCUS3nuV3JJ1P3MrM=;
        b=kavKukcnlKZKMJdsYP1dEqxtaN3bIE8H2mvoygAWQ97WUXx/744Y73A/J40Enl0bkA
         0w2m203nvpti322NR52j/445Cn+wBeyZrNao2ZcmFzjJ7VBZPhZj1/zalnn418hxkMn+
         lCbE9G4eZIPRJcLaNaGxs/Sab1GR6Wn7ek5vYU1sKINUyCpV3k3TmpMXeiKf9e6xv4gp
         M1vC22G0hTBLAB6BcXIYHmwJC1XDKEVYRyq0SUVb1VGoa1xDhUy6XDB1Z16UG/qeH+J/
         Vg91z0L0ixMUVfETZWq99fuYywSs1L5upwSfW6rKb5HlVeaceETFdmG6trc288M+KybV
         LmNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Q1w1fehR;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id k22-20020a05651c10b600b0025e5351aa9bsi438885ljn.7.2022.09.01.08.48.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 08:48:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
Date: Thu, 1 Sep 2022 11:48:06 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: David Hildenbrand <david@redhat.com>
Cc: Michal Hocko <mhocko@suse.com>, Mel Gorman <mgorman@suse.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	void@manifault.com, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	peterx@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, arnd@arndb.de,
	jbaron@akamai.com, rientjes@google.com, minchan@google.com,
	kaleshsingh@google.com, kernel-team@android.com, linux-mm@kvack.org,
	iommu@lists.linux.dev, kasan-dev@googlegroups.com,
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org,
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org,
	linux-modules@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220901154806.q4eegemrho6hgidu@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <404e947a-e1b2-0fae-8b4f-6f2e3ba6328d@redhat.com>
 <20220901142345.agkfp2d5lijdp6pt@moria.home.lan>
 <78e55029-0eaf-b4b3-7e86-1086b97c60c6@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <78e55029-0eaf-b4b3-7e86-1086b97c60c6@redhat.com>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Q1w1fehR;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as
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

On Thu, Sep 01, 2022 at 05:07:06PM +0200, David Hildenbrand wrote:
> Skimming over the patches (that I was CCed on) and skimming over the
> cover letter, I got the impression that everything after patch 7 is
> introducing something new instead of refactoring something out.

You skimmed over the dynamic debug patch then...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901154806.q4eegemrho6hgidu%40moria.home.lan.
