Return-Path: <kasan-dev+bncBCKMR55PYIGBB3EYZCRAMGQEPK43ZYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id BDEE96F5148
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 09:25:33 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4f12f45d113sf657411e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 00:25:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683098733; cv=pass;
        d=google.com; s=arc-20160816;
        b=MoDqjONZu3zFNaKDLkNub4DfT3NSGU3oQzqRu2+4FBUCEHLfUyaQRzKSx10bSZaWPI
         ahTC1D+OVpcGW8UWT6TYe/D5oiuRJ5QckV/hPnJy8q8NcNOMBy9NTuuYEpn7auVBX6fL
         /P4DJRXoLhucbnFjmxBfxdYfUUqfG0ILqZ57yv+L3zY5UUC4mZ4Ls+vZsZ+gCleeKxTT
         VSMq+M4AENyn1TTLCpjiUKmKSnANgknaC2JwVbwcLNa1KBK+IyaiHMLdMRUYceYi6I0s
         cvZkOjexqWXOPzA5CWR4o+b70xmG9LdH8ZyZQ0sWpxCAgd1OriRSLIpV4dNzh3lGXeB4
         a7Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8hGSSJlM52O4PTTN+tH/sjNKsPOWbLEVcoIwtP+Nb4Q=;
        b=Zld8axARAyAxjOPnnQCcvwzYNA9mJvxJrBUNpEwVut+8kdNB9eGWAY7TzamneB6zJC
         f/8wsXvGnp/Kwbk/CgYzkz3YYut0wtbyRB/Rhem8K/iE96zAvB+CmBhvOfwz4ZQwGZki
         7Re115r1ueP/toykPSAJayGbnQ110Y9bOxKtIGXCpgszAYPYbU+/9k+6XHnUmtkXRANz
         A5LlFLM0u84RpyvMRI8OhDf7PiNN/8tjhZyLolbgzTDTBHY2JWWceUmB7CQGxcVtLFsP
         UgI9e6vKMFLB5c1o2DZbLt+9VRKpDqiC85q79MB5e2xOczPB/7P4/9yiVa5XQ1YGBIU1
         RmtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=u+3Vi8PD;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683098733; x=1685690733;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8hGSSJlM52O4PTTN+tH/sjNKsPOWbLEVcoIwtP+Nb4Q=;
        b=bUXSTeYxphmsNZHmJfabD8Qwtl96RSpp+xAKFfXfLvMGtZC3Pm7bX2cjbVAnQ0Uvst
         DVY6lwLfxGOAJDE3dy+wAx4FKqmOm/xqCnc+PoIamj3CJHgY2SZ5ZAqMl+BLsZw6qFPI
         SimdtO0I6y3ZUyFrDRg/kOrVF3Rz4u43vREpr9ymgWj/G7/3MmdsQmmio4oG8c4xRyuq
         z9pBjE63AxRYKIMTrINvC73vnHyA1cAfOvewNgvZgofvOOMfl3fxVLMU1y5khUQFyoqg
         KMNcilg3WDTGaBHsdRW8wYRV9jXJ9ah5LapK6vZqVVSUH6T8M+Oxx7KUj0QElDvCJks5
         koCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683098733; x=1685690733;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8hGSSJlM52O4PTTN+tH/sjNKsPOWbLEVcoIwtP+Nb4Q=;
        b=OUrMXavvb5uAYox8K0iHvZbVrZUN22rA/DGEJJdimLdEKAWzVsMjH1qbcxdPOUkXFL
         q/iYA25AAtyySfntCo+bwDH0PGWTPaEnZ38NfQ6gcLdJZAJM1bOay9sj9TPAHuuBGxLg
         2dIS0Qhhhc5Jj4/XUNRV3TTnavOvR3ViVMqFAwotKYCyr4M2LSm/nyvywILoMglp4q3w
         qD17C2A+lDM4Q2h32cmfnyW+AsfOFzzUIltY/a0dy/OlZHQs1SgBJWTj9Q2MCtGl2TAU
         8QfNJvXqfJKkYpCvjwWT+FHlmp7rbrkeHYpLm/DpYJy9rJszJ7MCXLjHkaNiXZgj+zJe
         WoAQ==
X-Gm-Message-State: AC+VfDykS7sFyEW+uxUaB7qVVCIOd8zsasREN8e0wys0Vv+FRov+/8Q5
	sWrs2iPLMsL3JQJ3l0YKRiw=
X-Google-Smtp-Source: ACHHUZ4X7TTZcJsbWQTqX8DYtDahaW8ygk9lrSwVEQPjrTki2J5Q0ojZ97uQPVpcOiBmgNdLmeljNw==
X-Received: by 2002:ac2:52a9:0:b0:4d5:ca32:9bd6 with SMTP id r9-20020ac252a9000000b004d5ca329bd6mr617376lfm.2.1683098732799;
        Wed, 03 May 2023 00:25:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a5c3:0:b0:2a7:b0f2:717a with SMTP id n3-20020a2ea5c3000000b002a7b0f2717als3243628ljp.5.-pod-prod-gmail;
 Wed, 03 May 2023 00:25:31 -0700 (PDT)
X-Received: by 2002:a2e:808a:0:b0:2a8:adbb:908a with SMTP id i10-20020a2e808a000000b002a8adbb908amr5153791ljg.13.1683098731051;
        Wed, 03 May 2023 00:25:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683098731; cv=none;
        d=google.com; s=arc-20160816;
        b=ACz59QoQm/PJrfQGMHUcK85qyN1Z+3X3bS9pQiOXahYimWW9S59tYb0rqKqLRmsO4v
         /x1McpItML6cywlk/NoqsFftyzb12Dg6Gt4ga7y/eosB2JbkO1l9cxB8N6Ka1P5JpW9b
         qSAvoHKrFVcLJQBTnOTYNM/qWmZGwmBrYNks71jzynnMOTXEJ6z+lIUPFnpHLOsQPLXh
         fdE43M5Itb8dHP2WccCvxfdQIXtZP9vL7WF3HWWvFO/Da3laHO5B8JWNfCCBipgX81MD
         rTZOVUPpOVGefJaeL+e14SZDZeDQvbunRbJmz1eAUrJXkcErcsgE63UF79kB9EYTdKEO
         +9JQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JWB7/k68Y9sA1GCsD2EpPdE47UaCuB2lkBwAJ+0gleQ=;
        b=lkJ0HBeAj2BEiNnxD/vQvnP6uyGLZ5LtPSUdlIfrhp7X5BMTwKxIjoWEaOaOgE0ADD
         Pk08opyZ+kS4i55KRI423ycNgI8BrhzbhFcmz1ftsLyoPNwNcEfvWafAK+GuguaWe94U
         1ka3ocaC/h4DsyRY4AL5se/g4gQrNG4Tel5PL7PkZ+LUDCXEyI55+ykMiEPegQuVsVWu
         Q1+bHyjFCoJn9ZUtQdOEn5KaRHe/cVt/z5eKjgnm1IVT2QvUp0S1ixKWybM5wKhZGtrQ
         u91FFoYtogzf4cF1mctYFVgKVBTo602KSFivoXPeWwPi6IJ9BxganByllIv1uRqLqvnp
         T22A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=u+3Vi8PD;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id b29-20020a2ebc1d000000b002a8ba7c9a04si1769344ljf.7.2023.05.03.00.25.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 00:25:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 4146120060;
	Wed,  3 May 2023 07:25:30 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 1A7741331F;
	Wed,  3 May 2023 07:25:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id Rjr6BWoMUmQBTQAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 03 May 2023 07:25:30 +0000
Date: Wed, 3 May 2023 09:25:29 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
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
Message-ID: <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
References: <20230501165450.15352-1-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=u+3Vi8PD;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Mon 01-05-23 09:54:10, Suren Baghdasaryan wrote:
> Memory allocation profiling infrastructure provides a low overhead
> mechanism to make all kernel allocations in the system visible. It can be
> used to monitor memory usage, track memory hotspots, detect memory leaks,
> identify memory regressions.
> 
> To keep the overhead to the minimum, we record only allocation sizes for
> every allocation in the codebase. With that information, if users are
> interested in more detailed context for a specific allocation, they can
> enable in-depth context tracking, which includes capturing the pid, tgid,
> task name, allocation size, timestamp and call stack for every allocation
> at the specified code location.
[...]
> Implementation utilizes a more generic concept of code tagging, introduced
> as part of this patchset. Code tag is a structure identifying a specific
> location in the source code which is generated at compile time and can be
> embedded in an application-specific structure. A number of applications
> for code tagging have been presented in the original RFC [1].
> Code tagging uses the old trick of "define a special elf section for
> objects of a given type so that we can iterate over them at runtime" and
> creates a proper library for it. 
> 
> To profile memory allocations, we instrument page, slab and percpu
> allocators to record total memory allocated in the associated code tag at
> every allocation in the codebase. Every time an allocation is performed by
> an instrumented allocator, the code tag at that location increments its
> counter by allocation size. Every time the memory is freed the counter is
> decremented. To decrement the counter upon freeing, allocated object needs
> a reference to its code tag. Page allocators use page_ext to record this
> reference while slab allocators use memcg_data (renamed into more generic
> slabobj_ext) of the slab page.
[...]
> [1] https://lore.kernel.org/all/20220830214919.53220-1-surenb@google.com/
[...]
>  70 files changed, 2765 insertions(+), 554 deletions(-)

Sorry for cutting the cover considerably but I believe I have quoted the
most important/interesting parts here. The approach is not fundamentally
different from the previous version [1] and there was a significant
discussion around this approach. The cover letter doesn't summarize nor
deal with concerns expressed previous AFAICS. So let me bring those up
back. At least those I find the most important:
- This is a big change and it adds a significant maintenance burden
  because each allocation entry point needs to be handled specifically.
  The cost will grow with the intended coverage especially there when
  allocation is hidden in a library code.
- It has been brought up that this is duplicating functionality already
  available via existing tracing infrastructure. You should make it very
  clear why that is not suitable for the job
- We already have page_owner infrastructure that provides allocation
  tracking data. Why it cannot be used/extended?

Thanks!
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFIMaflxeHS3uR/A%40dhcp22.suse.cz.
