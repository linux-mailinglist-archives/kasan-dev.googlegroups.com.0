Return-Path: <kasan-dev+bncBC7OD3FKWUERBYOD6KXQMGQEVLTBH4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E20B886244
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 22:08:51 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-29df180bedcsf1047155a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 14:08:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711055330; cv=pass;
        d=google.com; s=arc-20160816;
        b=V2MmOLL7U1ZsLHdLyUWZINtql43x12ErLXt+HKutL0kvNiAlTgS8B0AYZ8X6KIEQsn
         iqtTlzJdUmgbbUaaTVUIgKTq/5yy2D9Dwj2ZcEIk0alqoc2IndtE3BV0UJaqTB2Gjy57
         4tJHPMkegtByVmhMMYz/IPwHWCyWsa6Z215ASkqAjDWqbJVQGtgPvkA1FEi0yZXtxu/r
         P9APb3kOS1r0IKCsxPId0Fw+ep0KIOX8VJNV/uqsasm9Vuyb0o5ee2wr9zBZ4j69jnKG
         OSF1H9SL4DPicvZyuDa1Y5IAo7IR84GpNjs4AwWXKF77zDpMc8wyq4TvV3l03bDxILqM
         Q4gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9bRpumrwYEzFx4iyhjFNb6QKNBl4Y++LadmgPAu5Q48=;
        fh=ioXUWqQWusAJE9nReGudszlXLwS3FVEgCOu0iRz7mKc=;
        b=kyKClD6d81aqRZchKIAdrn3MV10OwOSOdXUEug159pqswryn7lCb1iPOLtmZ/zKgQk
         qKq/tbJENs/R4lRq0uVvNnbb1c3j7o6FXRL9tOZVHuZdd+GUTvGHGwUKiV9eexHwlZWu
         Wr9lWwZpZQlpJhJsyaOXh7sCCnmLAOhvaDw2kmB6UFdRe75TQf+oI1rX8KcL2I3xq5oB
         nPhWWYQKetmMT5TEleJDW301JfdLaiEybubDBLILBXYmeXc/FA1xeZMHOCUBBjimwQ0Y
         krB98n+vMQoIOK063SC+WkgJmz6C8BikMyO3FVv4l4OyXyFdvfys+aa4esE4kOJg7JQ9
         dc4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2dwCX5Or;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711055330; x=1711660130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9bRpumrwYEzFx4iyhjFNb6QKNBl4Y++LadmgPAu5Q48=;
        b=RCv6C20a0iqjmFfjQ7a+WGJhF/KkRfe2Nua53+dOC90FB2Vh/iKsym2dTQA8er9cAU
         i7nr5QRRtCB3KVFxhN6BoZ3K6rMmjmEuIC7T4NGfWxqdr9FUFnf5DxiRFa4Dlv/vU5iJ
         5fZsgeewGMvHP5N6/AhGLSi8de/aSlgW17SkwfzTpY3TpOH1DE/JRgab5Q0bG4DrHrb1
         cVh6xSP35GcAY53Ale5vryG9ZtRoLvMTBqYE3qHCr1b50eLn5HRLY3Pqx5lEZSKBxjQ5
         cyjmSy0NlHOOKZyr7kmBrCf23tbcWacHU2jnvsTALY19cnKXpL7x+RvzI/QGAJ1BTyqC
         6uPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711055330; x=1711660130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9bRpumrwYEzFx4iyhjFNb6QKNBl4Y++LadmgPAu5Q48=;
        b=ew2UGqmeG11u8/FlHBIkrT1uJl9H5UGz0Erqn24Ctt4cj8eCnh2b6ss8DNAJC8Erzt
         1rquyxWDH9OduK+cTWSzq6lACxNJypt5kHr+ckFih0yp2CJq/0RhgUxhyo5FdOZ7np+s
         /wCce5u9zz5EQbmAce8sM5klsPjRarjeNAJ4H+DYc8UjFHWyoUIAYzJfRCOIyFr65pei
         LBz4qz3xWgocA+nNeEZSuH+7hBXiPcV82Wcm6xclXYGxjSSCfRl3YW4QHYEPJ6DjQ2nO
         vyANldpGncPBZ/Jy1kxBGX1yR6XCwM2dQ3mAPnXKY8kS/4Sy8bb4+oh1UzcPcNwlk1Ux
         6+xg==
X-Forwarded-Encrypted: i=2; AJvYcCXACQIxNvVGsL2Kb+fxzBdayCIYSwg3KyOTJjlxDvdQ7sSxxIJGVH7Tez1gBl8j6Oc2WC8Mh7WNEnC1uJEY+FQ0TUDKzt7aLg==
X-Gm-Message-State: AOJu0YzvvMgNE8IqztdCJJyE7xd4XCBT7KUZF9BF40k+TL/hAoJWVMLo
	Q+QqnTwIw52/X4dkSh43gegGW6PgnQfFX5ffxQMNmg7MZWLGza/EjlA=
X-Google-Smtp-Source: AGHT+IFDGNkGasaG59zm9jK2JLzKd4zcF+VHKn99AWPtO2XVRdkLdEGK+EBrDDicijlNt7nTU0BqEw==
X-Received: by 2002:a17:90b:8d4:b0:29c:45f1:8984 with SMTP id ds20-20020a17090b08d400b0029c45f18984mr604437pjb.18.1711055329970;
        Thu, 21 Mar 2024 14:08:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c45:b0:29f:f632:f466 with SMTP id
 np5-20020a17090b4c4500b0029ff632f466ls933640pjb.0.-pod-prod-06-us; Thu, 21
 Mar 2024 14:08:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW3lvor3CXExPG7fVEeyOgoTy2rCiG73gN4yT3x4kyGi1ITl0+tEJUgcZIk0BqhjKnd5I9aX9kF7lFDTF6uLbNr9LCUFaXWIjUulg==
X-Received: by 2002:a17:90b:30d1:b0:2a0:390e:f032 with SMTP id hi17-20020a17090b30d100b002a0390ef032mr107603pjb.32.1711055328810;
        Thu, 21 Mar 2024 14:08:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711055328; cv=none;
        d=google.com; s=arc-20160816;
        b=D39jdB39nkWblOk9OvBjP+ckcn6wvdamHoQzWpb5H4ISLdTrBwF2hazVx3T36sCGYc
         ZtbgvPtdjCUl5znqGy7/3sALGf6yQQpCGF2PXAWyTw7n3/NFKC+NSkiu/99SUL2jhC4/
         1eTU1i1hI1aOIKU5hkQF2bfNWpZFPRgR7iq6tYQnzI1UFUz1WJz/hb9M449pxnYec3pn
         +P6HY0wjszURrDFlBo7xsmZXmGJvNnvbOuux0Y3G1PqiEqt6C7XklwlcA/YVhkBoJRk0
         hI4m6AesdFfZrTpopNm2qF58j3DlVyDk3wQ0jmLOzHdVSUp/OOTOyYnLBL3e0piP8Mar
         RvGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NRNPrWHMxiQDcKwm3DA9WZxrfwYc+pk9Whir/OXbLVs=;
        fh=q5iGdB4cFfJ194I3jnut6tFuM4FyeIg9F75Yhx/1gHI=;
        b=GGvtgFWg05PcqGm1cVY9NZ1J7rFiGDdBJnvwddCmAHsf1TOuJ8NlTNkLJn5I1lV/uD
         OY2RZ81dwTtMxp8+9aFs0Z/KhwOV90P7O5PVwwBtImrobAC8QPva3sjpXZQapn8/KXVh
         4wJ/y1xR9pL4HpjVAU3H779gPLK1Xy+MJRs34Bm5ajoRZSop/sXNZqlcDXmQTCoy28uX
         2eJlA5YjuI2DjIi7pi9egQtgkFTZnUKb2yeYEYOy9RudDghYFZwa5Zv6vSwN8MJ3PdJs
         s1YJWwLuqKvyP8qGYEJZyVXnB3BwgQWjl0EG/8gZQwRT8MD9nuWA/A8FcKxHRJ9OZAwD
         8PDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2dwCX5Or;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id pw6-20020a17090b278600b002a0293f7703si93228pjb.0.2024.03.21.14.08.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 14:08:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 3f1490d57ef6-dc6d8bd612dso1362974276.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 14:08:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXuDUBVITD4ImYFGV+k5XuZW2FkOEuAGoZuIVsD6q1xyMYhkq5MgNJ3nsmYt4s7AR1ofwGRB5spDJN3HZoM5cY7XAW4of8YC28B5g==
X-Received: by 2002:a25:6903:0:b0:dcf:f78f:a570 with SMTP id
 e3-20020a256903000000b00dcff78fa570mr390215ybc.7.1711055327530; Thu, 21 Mar
 2024 14:08:47 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <20240321134157.212f0fbe1c03479c01e8a69e@linux-foundation.org>
In-Reply-To: <20240321134157.212f0fbe1c03479c01e8a69e@linux-foundation.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Mar 2024 14:08:34 -0700
Message-ID: <CAJuCfpG-KiE-MyOR0ZCghOswDMKS-9SmBh_UEdzSf4GHTB1wBg@mail.gmail.com>
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
To: Andrew Morton <akpm@linux-foundation.org>
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=2dwCX5Or;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as
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

On Thu, Mar 21, 2024 at 1:42=E2=80=AFPM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Thu, 21 Mar 2024 09:36:22 -0700 Suren Baghdasaryan <surenb@google.com>=
 wrote:
>
> > Low overhead [1] per-callsite memory allocation profiling. Not just for
> > debug kernels, overhead low enough to be deployed in production.
> >
> > Example output:
> >   root@moria-kvm:~# sort -rn /proc/allocinfo
> >    127664128    31168 mm/page_ext.c:270 func:alloc_page_ext
> >     56373248     4737 mm/slub.c:2259 func:alloc_slab_page
> >     14880768     3633 mm/readahead.c:247 func:page_cache_ra_unbounded
> >     14417920     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
> >     13377536      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
> >     11718656     2861 mm/filemap.c:1919 func:__filemap_get_folio
> >      9192960     2800 kernel/fork.c:307 func:alloc_thread_stack_node
> >      4206592        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_ct=
_alloc_hashtable
> >      4136960     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] fu=
nc:ctagmod_start
> >      3940352      962 mm/memory.c:4214 func:alloc_anon_folio
> >      2894464    22613 fs/kernfs/dir.c:615 func:__kernfs_new_node
>
> Did you consider adding a knob to permit all the data to be wiped out?
> So people can zap everything, run the chosen workload then go see what
> happened?
>
> Of course, this can be done in userspace by taking a snapshot before
> and after, then crunching on the two....

Yeah, that's exactly what I was envisioning. Don't think we need to
complicate more by adding a reset functionality unless there are other
reasons for it. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpG-KiE-MyOR0ZCghOswDMKS-9SmBh_UEdzSf4GHTB1wBg%40mail.gmail.=
com.
