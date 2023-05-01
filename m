Return-Path: <kasan-dev+bncBC7OD3FKWUERBFUAYCRAMGQEBC4V4KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BC156F35A4
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 20:08:23 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-2f625d521absf1634932f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 11:08:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682964503; cv=pass;
        d=google.com; s=arc-20160816;
        b=P/H5SarGSXfR6WdsVT9Bl0U7n8qf6j1GsB5tNWbgKDLQD6xmcVjQrd1qN2xBRXAIbT
         OgiXghFg1TyUCrqYiAAjcT8z5MQh/AeTjgPNmAPwV8oNrn/q8CnXDUpzECPVbmr4WM9w
         SeQw7kc/tQE52iT4nu8bZyipflgLJnYYEiP6WlT4irws/5dKyyT2ZFSS77VHSxq5MpPR
         AingOyF7puWOJDyQTRXVnQ4RbsCUtV3uAVWFcZAzF66tXM3IHgIuYI8mDP/q04z3BUXd
         ZFPcoElJg4A4xON/IVMW7cQLJJDfFJM3iUkCyoufnPXLRTZiQxL+w6H9mvVBluMcG53Z
         +RCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=N1WKeA6b4oDamc5DGzSZpgCstJfmC5tpC7i9XojusQU=;
        b=rhrEplMEqx4l46bP1TgpdJ/4FemiL78dDdaw6xVwfO+ZfSq2OUrS4tEKuVDRsMbR5N
         XKCvoyZWwvB8cgo0BuJw8qi1MY9mFzZkLknA9dW8BeRXfGPFWuvv4BuRNWmfIatfxj4U
         7IXeZDnNaWsUoI5AA7U+EIKGRQGCERpOcW1fGB2hVTQucuBp0/ZK41wzhPpef7tuVlic
         W27Jy5hvluq2/cmRVWZprQz3eaxKGgRHDrxLzGMxQTFp3+Cmb2jxiSzr+TYu+pnaZ8fY
         xxb7sBKBJh/5JloIQrwCR9c6IhATPSEGcVSaZMbd1/ujpnSyhQNNOSg2j4qocRP4bgsf
         XPzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=InnNvCby;
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682964503; x=1685556503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N1WKeA6b4oDamc5DGzSZpgCstJfmC5tpC7i9XojusQU=;
        b=qWoEopAiy27npmv2hAy2u2qG+HAqpQvpv1cYfj4ubEuCKFGfZQuAag9qt49teNKIC9
         biVyZkjPEK/sQc0iGDIb8A+wwJnF3kgtmTbXe0Nm++xKYc7535aa2zeMnxTWLKZ0FLt8
         IN9mKnBUrAVVHtTMCYvcnr9dWBiX/pVuLhOlvj0gRQkzAamKWbkEpfYoGBX2ZJb9gizA
         r6o3f9H8UdeAun1z328gtJrEu10jSae719FnTskLr8+o+WY5CiSASwfWOwv6D9jgQj1m
         0tG2YXQpRq30BkX28JTg8gEbhHBHPDvk3o12/bLzt5GX/GYS8bPltmHGvv9q8FuSIaOY
         7B2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682964503; x=1685556503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=N1WKeA6b4oDamc5DGzSZpgCstJfmC5tpC7i9XojusQU=;
        b=fYlQtfxp2ycmAwE+ykW5ctA4rJLO/DG12OIqFVKkLCYe4mjt/cDmYUmLmfVDBcMoEh
         3qa2Ve5WeYrEoYTc+g8DEynXjtbeuV9I4gs5TfOt8zK0NfQC4a8uxX4l3T+kIFHI76OP
         k4WY4e9CF6wOli6kJGwMxd5ayOK07bwBVGQiLumUYw3x6bPlbZ+NuJg/F2Q+YY2Uy9qH
         hqTsI7r2PW1g7N8s+oR3XVDMjxODk4W5j7C/3GLo2TKPKEzwT/we0qFz7nWF3w0zalDc
         79N8AbxhPKZGooiiVbeoZRRTp6fqeo9/hSR42FVZbv4WAByCLt3vGi/N3YYwmEQvJQ7o
         TpUw==
X-Gm-Message-State: AC+VfDwTJ2ui781+0CQMWuo1BM36xEO4EyQzZ/SYNLiQOq8gYVuOdQ3k
	9+MOTMjLnMYfwkm+tEIIW/w=
X-Google-Smtp-Source: ACHHUZ6gQ5Dh85CR1MQ4V+g4nQbmPNkrVBA5KE6mfLtdgD7InT5oVLYMHpHCrDTe3VouPcGBUuLtTA==
X-Received: by 2002:adf:ee05:0:b0:2fa:d7ac:6462 with SMTP id y5-20020adfee05000000b002fad7ac6462mr2354832wrn.11.1682964502595;
        Mon, 01 May 2023 11:08:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:45c4:b0:3f0:b128:14c0 with SMTP id
 s4-20020a05600c45c400b003f0b12814c0ls5632540wmo.2.-pod-control-gmail; Mon, 01
 May 2023 11:08:21 -0700 (PDT)
X-Received: by 2002:a7b:cc1a:0:b0:3ed:33a1:ba8e with SMTP id f26-20020a7bcc1a000000b003ed33a1ba8emr10245021wmh.1.1682964501393;
        Mon, 01 May 2023 11:08:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682964501; cv=none;
        d=google.com; s=arc-20160816;
        b=vTLqT1+uA19PGsKFpBx/zoh9hXc6y2xS7FSNPJ/ssLDOcJx5Dd+RDY0N2ul2x5qzV0
         2ZJEtXSqh7Dokrm+ABA6DiWOc9A11LPa5hi53sRzvGhGHZIbqw3veM8UPfJ6U9sUx1VV
         clvbNOZ+kCGHkP1JbwyLnYd54PQQ1hFSCNooyPnDdnWGcRT5gDQ70OoIO4Z0wSumWNtt
         OHG31Oc6VlJVL2xLMPilh+i5RHvmunGnyM2CT6SLEMppFc52SIOqHfln0eOuPS7+ZIxC
         YIbfk/wuEZtohumqgwheta8talANNfxABa1McNTI6yfRnU0a6gaAKRaxdCwa1V+sHcTU
         yz5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+2lYHhqlJD16G2HYpsFMb3ZFL7Kq76WjunB2OGwz3cs=;
        b=c/ODpsfUqfkt6TEqZ9GoSO4xHBYnBYDr2qm374oEqrNcNe486vj+6W5O5MHvLsSuj6
         vemsoEfos9mksot9PlYyBURBy+UCy6yfhl2r2P7uGQv2y4Bept8MI/AJyMJhB1u/AlBu
         00EYVk9ojAHtLcCSgcmuDt52mC3F1kTjcb7SAkAQhWV8V/StlxvdftLswVnDYkZPx8/O
         O87pU8YDHEvXbu2qIot72NMC184BxSzg8CTSTLprz8CFTHF5exa6hxmVjJk12AjVUnmf
         WQilJu1d+qZ6gET6IDLvUBvXmyLuK7s96waVArdM46wnCtIJlPeBGNko0nGr/qo83MjL
         4ioA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=InnNvCby;
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id n37-20020a05600c502500b003f189de7e3fsi1652020wmr.0.2023.05.01.11.08.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 11:08:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id ffacd0b85a97d-2f833bda191so1584300f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 11:08:21 -0700 (PDT)
X-Received: by 2002:a5d:6351:0:b0:306:2b9e:2a8c with SMTP id
 b17-20020a5d6351000000b003062b9e2a8cmr3336094wrw.11.1682964500617; Mon, 01
 May 2023 11:08:20 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <ZE/7FZbd31qIzrOc@P9FQF9L96D>
In-Reply-To: <ZE/7FZbd31qIzrOc@P9FQF9L96D>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 May 2023 11:08:05 -0700
Message-ID: <CAJuCfpHU3ZMsNuqi1gSxzAWKr2D3VkiaTY0BEUQgM-QHNxRtSg@mail.gmail.com>
Subject: Re: [PATCH 00/40] Memory allocation profiling
To: Roman Gushchin <roman.gushchin@linux.dev>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=InnNvCby;       spf=pass
 (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::434 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Mon, May 1, 2023 at 10:47=E2=80=AFAM Roman Gushchin <roman.gushchin@linu=
x.dev> wrote:
>
> On Mon, May 01, 2023 at 09:54:10AM -0700, Suren Baghdasaryan wrote:
> > Performance overhead:
> > To evaluate performance we implemented an in-kernel test executing
> > multiple get_free_page/free_page and kmalloc/kfree calls with allocatio=
n
> > sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
> > affinity set to a specific CPU to minimize the noise. Below is performa=
nce
> > comparison between the baseline kernel, profiling when enabled, profili=
ng
> > when disabled (nomem_profiling=3Dy) and (for comparison purposes) basel=
ine
> > with CONFIG_MEMCG_KMEM enabled and allocations using __GFP_ACCOUNT:
> >
> >                       kmalloc                 pgalloc
> > Baseline (6.3-rc7)    9.200s                  31.050s
> > profiling disabled    9.800 (+6.52%)          32.600 (+4.99%)
> > profiling enabled     12.500 (+35.87%)        39.010 (+25.60%)
> > memcg_kmem enabled    41.400 (+350.00%)       70.600 (+127.38%)
>
> Hm, this makes me think we have a regression with memcg_kmem in one of
> the recent releases. When I measured it a couple of years ago, the overhe=
ad
> was definitely within 100%.
>
> Do you understand what makes the your profiling drastically faster than k=
mem?

I haven't profiled or looked into kmem overhead closely but I can do
that. I just wanted to see how the overhead compares with the existing
accounting mechanisms.

For kmalloc, the overhead is low because after we create the vector of
slab_ext objects (which is the same as what memcg_kmem does), memory
profiling just increments a lazy counter (which in many cases would be
a per-cpu counter). memcg_kmem operates on cgroup hierarchy with
additional overhead associated with that. I'm guessing that's the
reason for the big difference between these mechanisms but, I didn't
look into the details to understand memcg_kmem performance.

>
> Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHU3ZMsNuqi1gSxzAWKr2D3VkiaTY0BEUQgM-QHNxRtSg%40mail.gmail.=
com.
