Return-Path: <kasan-dev+bncBCU73AEHRQBBBQGUXKXAMGQEEIKVHKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DD6F857263
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 01:20:17 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6800e52d47asf53857456d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 16:20:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708042816; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qz5+jgxZ4G0Bwo0C4S5IddIh1DAgBATcsp9dLBtVgOOsSbzMzOKIrKSXhrhfLID3KI
         Ju8ivYLHa8T0tl7TFumbbKea9g579Fve4eUC6Zn4X+WqVFJE861dYSXwUPN50KU5FJsD
         Y8Y6cKLpz1oK3LctFDpWCirjJV1ccotZzA2r3W6rxGshPjpF6f/rkacH15ZN2kBVO65R
         51EXOQafu/230gsJ4V+qN7AbQCYjE0+dl7VfzSVUD5rwSTd1iQUuXllCEuCyKwEQ2zMB
         Iv5528L0IYci9Wyv3J/g6wHKTHvn+gOd+Y7i2LFmq1DCFLysLKcYCDQQYgzcjNiKQUoA
         +q3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=jB+6LxD6KkZlLCyDlF6L0+ReKE+sktigy+Jw7FP9FW4=;
        fh=hIDOGvDxX/yeYI7ScdUcZVq9O6ieOwNt5J7Fl3gu52I=;
        b=qPNWTDpb+c6K9L7ZPMdBGPGH6ZOT+QG9pMi9AyFFK+C5N4qok4JG8qWHqOY3OA+7FU
         TeKGdvEOW+8xqxkzIv0tkKMMRaRwZ7ghqf/UtgJCYucX2W+0yG6LOwwdYE+tgYWNK5vS
         pW8xNk9l36Ay59ukXp+Q4ocWYdpJJtA2rSOIKT3Ae2mpujaNapMV7/oZPjhIqU1QPl/Y
         Oh6dsl6WFA2fuY5lxEEEH7rrGq/UaHicTX1f0R9CZ/x7Kz+Fn2bOBIv18ZKKR+YBXY0q
         7uvE8oSxxXhIEsUr/6cj84g5mzfvJKYc6FDeWL15M7iHSD3pC6AiseXmgwNsXjsf+2Gh
         Vrqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=rkxr=jz=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=RKXr=JZ=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708042816; x=1708647616; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jB+6LxD6KkZlLCyDlF6L0+ReKE+sktigy+Jw7FP9FW4=;
        b=ueaHNK489Za0icd0zbSmnt7QGi/CxsxmRACw3p0apprrulg39cy660eB/67aiKD6Kr
         EeaHdEw2Xxsj6wjdOFhWKK3OOouWqVjP6+orqAYEz73U/1Oolzfb7ixW01f4dLydP9XX
         ku8JYcLCeUBQ5SVtmtPR8ZOe2E7WoMiap650CjDd3OJF0YrNqC4sNtgA1TvYdB4euj5/
         NnV9d82Uzu9tCEWcrv8FMJUX3khc7KfcSGvWJ3yexrGWjRxrpj47EHR+aKPhAIgY6k6N
         MnobKr5tF4HpWSjKjG9xJwz49zHC5S3BGnchtr2qnkKQrbGNfGQVQpvJ1PfQlFkNP5tD
         uwNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708042816; x=1708647616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jB+6LxD6KkZlLCyDlF6L0+ReKE+sktigy+Jw7FP9FW4=;
        b=i8slmR5sbMWt0vpRgi9VtR3AmRoROdaOUgEYr1UUyr7CSfykhWOB+n6MZbR547Bov1
         se4IkC4EFhN7dFUBBUJ1HrbWTb4zPJWaMUxW0DbP2rFZSBHAktrckMSqGyCyfO+JQghC
         jspb/tMyXH/YmnAOt5Uyu8EoWt7G3P/KQ4VS5vqNqyOpekI4fkhyyUrvrH4VGZRWaRoV
         WaHAuYu4kpPIPC67mq7foXgy6y8euKtwfEEwFajuOmyeVhAACjGLiB9AxuxaE5jpGC3G
         FE3P1j7ahcc0RLui7Ydk5ydvlPKsXSjZ8YU/uUNtrgb5owO828acaIJ4vUHgtRP13f3L
         cbMQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUb9SlWthIG5DfisJvgnnbPpT/HQSVlYj9RuigLwFG4n7aeW5YU761RydNNS/mgHOwrhhHtoxTszbnBz4GZP1NRiRcurhrUcA==
X-Gm-Message-State: AOJu0YxU1S+ZiJrPbKiOI3HEWJ4ZMirbLUXZlxhscne1Pa2YfLqFRdpl
	MXXNa69uB77dickgYiy3K97bj0dNSHIjWP16TYBDDuoJSpbKaJUS
X-Google-Smtp-Source: AGHT+IHyskkx5Tudp93Ykt3XXbd0st4wf4oozR0hniCU7aZIOYkNLr/2WaHudZOtzTeeT+pzoH1e4A==
X-Received: by 2002:a0c:de0b:0:b0:68c:ae6d:2abb with SMTP id t11-20020a0cde0b000000b0068cae6d2abbmr5219025qvk.15.1708042816310;
        Thu, 15 Feb 2024 16:20:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:519e:b0:68c:3fc2:b931 with SMTP id
 kl30-20020a056214519e00b0068c3fc2b931ls552394qvb.0.-pod-prod-00-us; Thu, 15
 Feb 2024 16:20:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWWDcOhtyyp20c1UFolw/otXsZtYdCvh6dnOp+h3l7y8nXYxgDbwf6RmlvzD8blGIGoiKeAnjtUY4BTSKA/OlCGV3/L42n4DbtXLg==
X-Received: by 2002:a05:620a:909:b0:785:c16e:181c with SMTP id v9-20020a05620a090900b00785c16e181cmr5160018qkv.10.1708042815340;
        Thu, 15 Feb 2024 16:20:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708042815; cv=none;
        d=google.com; s=arc-20160816;
        b=ocAnqup4SGCSU07aLoDDHFZnGADSeSKKjR+RYAkkkJRUZZn+xH3wh4/gfmQvGvBiUh
         liUAPiB53Q3Zd8HaKWfV/znBfClIHDuYcV0F142UcY2p2VCwi13r+ly0sgHtrw9KKkcv
         6JjqyVjxw3NelC0mtMQtB7Nz8POzcXP8lZvQkYSsOo64XFTx0MAxdimdNLS5nTiWlXtP
         Hwf7cVbZzUkX72+OIsgUJsfxOMJ7yaW0g5Unl1qDJE8vRN+7woR/jEM721mVSkvEVXfb
         xWknDAPDVHq/oaqoXyH+twHJe/ZCX+bExi5egsmJoLroacE0cU3Hep1GbAxQo/Aov65a
         VE7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=DL8SVS/pGFfqx8KyoD0I3M9q9Kd9vzdnyK00eWaNogA=;
        fh=yAsR8mz6OHt7FqUIcMxTq2xSLRkYQrfOXi2SdkYqlko=;
        b=qcivh0L+D9/vgtqpHKQ3Mjca+Nph/5IK6YOrBV2LaIQHPbhrE9OSJLHUa0EwZLG7Mz
         cwpqOO59KNajaKx82Oi/P2aVWXKlVo2ASgUM+MeNjQtUnkT6p9YiRdZWCPpKtUadmM09
         ss6aH8B7bc8PHjuXdX3Imt0bu+SRit+KbaQmJVY0VXhRtkliDicD4qcfz+8P4WFyTDQy
         JwonrYvZ3WxwHdVafIQkuxsBRfxA8dVc6ZBSFWM9FDNaP96ZrcFLqnm68NjMk1QmVtxk
         ZlCljsS60uk+yGGJ+6nVxAcwfyHkSqItE04b9aAjoYRAEHowGz7YWsSIAETxIQNujKZq
         +5Dw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=rkxr=jz=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=RKXr=JZ=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id u28-20020a05620a085c00b0078735b2ce54si139359qku.1.2024.02.15.16.20.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 16:20:15 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=rkxr=jz=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B2E91614FA;
	Fri, 16 Feb 2024 00:20:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3D7BAC433C7;
	Fri, 16 Feb 2024 00:20:07 +0000 (UTC)
Date: Thu, 15 Feb 2024 19:21:41 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan
 <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 akpm@linux-foundation.org, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
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
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in
 show_mem()
Message-ID: <20240215192141.03421b85@gandalf.local.home>
In-Reply-To: <jpmlfejxcmxa7vpsuyuzykahr6kz5vjb44ecrzfylw7z4un3g7@ia3judu4xkfp>
References: <20240212213922.783301-1-surenb@google.com>
	<20240212213922.783301-32-surenb@google.com>
	<Zc3X8XlnrZmh2mgN@tiehlicka>
	<CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
	<Zc4_i_ED6qjGDmhR@tiehlicka>
	<CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
	<ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
	<320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
	<efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
	<20240215180742.34470209@gandalf.local.home>
	<jpmlfejxcmxa7vpsuyuzykahr6kz5vjb44ecrzfylw7z4un3g7@ia3judu4xkfp>
X-Mailer: Claws Mail 3.19.1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=rkxr=jz=goodmis.org=rostedt@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=RKXr=JZ=goodmis.org=rostedt@kernel.org"
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

On Thu, 15 Feb 2024 18:51:41 -0500
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> Most of that is data (505024), not text (68582, or 66k).
> 

And the 4K extra would have been data too.

> The data is mostly the alloc tags themselves (one per allocation
> callsite, and you compiled the entire kernel), so that's expected.
> 
> Of the text, a lot of that is going to be slowpath stuff - module load
> and unload hooks, formatt and printing the output, other assorted bits.
> 
> Then there's Allocation and deallocating obj extensions vectors - not
> slowpath but not super fast path, not every allocation.
> 
> The fastpath instruction count overhead is pretty small
>  - actually doing the accounting - the core of slub.c, page_alloc.c,
>    percpu.c
>  - setting/restoring the alloc tag: this is overhead we add to every
>    allocation callsite, so it's the most relevant - but it's just a few
>    instructions.
> 
> So that's the breakdown. Definitely not zero overhead, but that fixed
> memory overhead (and additionally, the percpu counters) is the price we
> pay for very low runtime CPU overhead.

But where are the benchmarks that are not micro-benchmarks. How much
overhead does this cause to those? Is it in the noise, or is it noticeable?

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240215192141.03421b85%40gandalf.local.home.
