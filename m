Return-Path: <kasan-dev+bncBDV2D5O34IDRBDNBYCRAMGQEPFEATOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8621E6F3697
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 21:18:38 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-76978e7cd59sf71097039f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 12:18:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682968717; cv=pass;
        d=google.com; s=arc-20160816;
        b=W0AlKGP71zwrLdFqe85nuxZW+f9SkX1B/E98xV0W5gc6P98qPcTMKUe6YL4JVQxgch
         6XtSQYxAEH+9ifLruw0IssPzf2q0Vrksm8OGmkZQ9lC5nSy0184m/KfYsu//S44jtTqa
         Sh7czs2eyMny0UD64BjYrtCZTyTHxDA0x8w4A2uoHCAu//cX7e7RbYiiZf+66aNUBTUg
         +V7UAX47q5iukaJs0u7KQm36gNHsoz6nggWbSzQcHHO6ydb5fvl0Q2tyWR0YaiJuXe3G
         qo7Ndr2HagOqgw599iCHIZwflBgNQufc8aLBCAue4x8aUdG+xPUOH8c+QyTuBXKiHGwJ
         yskg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=scRYYocCdY0C8TNza91Z48eRJuP2S/9j7V2IKvsO4Yo=;
        b=GHRLYPQuzrBJlC+1MuRDM/AqeX914dNA5dRN1O7qKiwx9KNTe4nftTNSgb6W9UjfUC
         ZIMNpo3xiH9SF9FKWJ6OX0A/leAoxMEJy3FRwdvzx9oWPTfAo4Kxr8Y1JBqzfuX6icI6
         F9cKJ5DdWm8+i2mQogcBcd3Bn6rSMsAcqffPIA/cSpxaDntsfbv7ivT0dpvtmxquTxF1
         sN2bfjGhr8DGUoK88N/ZKXxUUmEgMi3YjSOjj3KYv62Y8enV62Du4fbWQgSLAIizwXBk
         ZsDYX5TAgJtIE7M0lhsj0UtbqUTnC5UrK7Q8TO3z33sWPDB28u/YGIt+GoLmbJ6rXRdD
         /4gA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=m24iecrt;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682968717; x=1685560717;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=scRYYocCdY0C8TNza91Z48eRJuP2S/9j7V2IKvsO4Yo=;
        b=D/ab6eV+J0Z6e5fba/uU2t6F6LiY5QBPnXb+Y4ppmaFOw6S//HOzpunhcnFW69AU8p
         lyx1GSYY2JLX192Mtpk6pKMwhCyMzXL/wUR/A1ri0jPaQva/bccKhaV2Uj3R9KeC4jLr
         ALh3ywli4afJWjyXwyAHBzkbnf3kuKk3WvvrLoEDHizg2r/vHyGcr/WPStwNw0A/QsUC
         UI7WG+DN6J8JVdc1++jJFuJELyaWjqAzBLiwgm2QMTi4YLPXZcXdXmS9k9gCnWNEQPvp
         mG7iKXdGFlte91xIQfZa121Y/rSeL0xHs8HludgOnNv4DacDB24/c6PE5kQe7SOAryob
         VLkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682968717; x=1685560717;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=scRYYocCdY0C8TNza91Z48eRJuP2S/9j7V2IKvsO4Yo=;
        b=GBDFFJLQF38sT7KjL86X162uH01unEwYb0R3JGJoPoIHRgDcUoA9KqdGMMkwp/P6xS
         S8f97twyljBBlkgniVCI6UKYiA5zZIcO9x3qN4E2J/tFE5wYbBIRSgkOMeKbTuyQvAIb
         VltC1VAZot5igGOiHjWUTgtb+xJWw+IGrGXHdyRS/Jz5pPWhO7/OSIbHB/E5HWydswNl
         YBecC8oqm0ZEMQN+uFBgNDUIBHFMcsfIw69A+0Zd9BLGMizjkanaspZH6QBJYiy/Gorj
         1vyUgxDc/LR3tvaTsRbzyZXJQvy6xiW5Gmw4nkq9dnEPm/gPajoUVGzRyX5ovsbUpPFJ
         7T/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzTXLC7P9Nrz1kakn1qd8LCEntQttmSUBpSzj4VSWndEOTsfXcp
	Ll5eITm/3/JZBkbYUuwuYOw=
X-Google-Smtp-Source: ACHHUZ45WrheWmq5YoX4vomcrNj8m+P4B9FXeEKPNCmJ42eckaErXa9+S3TmaytSuMeDVTauQBxDng==
X-Received: by 2002:a6b:ed18:0:b0:766:506d:d73a with SMTP id n24-20020a6bed18000000b00766506dd73amr6224130iog.1.1682968717328;
        Mon, 01 May 2023 12:18:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:3818:b0:745:5be5:240d with SMTP id
 bb24-20020a056602381800b007455be5240dls2218885iob.2.-pod-prod-gmail; Mon, 01
 May 2023 12:18:36 -0700 (PDT)
X-Received: by 2002:a05:6602:184d:b0:746:1b8:8687 with SMTP id d13-20020a056602184d00b0074601b88687mr10354325ioi.14.1682968716650;
        Mon, 01 May 2023 12:18:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682968716; cv=none;
        d=google.com; s=arc-20160816;
        b=Sv6Hmw62JLRKls1SDyipwrq2hvr/iaiMEQR7Hi8xOYeH7D5ZRccmh0mrKfdMZl5L3v
         hEBG/hRag3zCw2LczdyMP5UTsYMvNxsZKC17FZsG0cdif4oHBVIlUpbZXuJXPOO7Ki/M
         XagHHEcx7j7uorDVFjXuGxzOIpNTXkVQIIa5SFU8vgy7rgcrWRx18DWGlKxSJvXfWvsu
         N7CA0KUcJJUMs0pjjeOKwToxazKk53B1vctwzP7MimcSHg114ilhzYXH3WBzo6YVyh1q
         8DrQwrieOhStbvU41oVN3zxExB2uXtlb3B2Ga21kQnCa+KVaGtyePmyvLBdCYoQIwf9l
         C8sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=5UxSQNJpFaq+7dWUx985o9MhLzvQlphTHJz1Ql9KvxU=;
        b=Y/O2J0QDDAcWtN6AIZYYOyA8h/aY0LklHcsjrHel64LXBBec7ggvYuDuzDpugV9VFf
         2GJo94EpfQhv31qrKhlfmsXnN5EKEJjErhF/uQeKzorSUyr0MuIFB4Vamef8P4rI8AR3
         X258dDbBmO5VPr14Dpn2NTDCXzzqyOBP5wUtO10k7GBgXx4tb3OomjBGJx1xUyuVDpNQ
         EKvblcFVmFZ0ZwcyyiEnOIHdnOl9R+JGhv/2QmmrzKkD+rPz+5vBCEdMLBZxT5NAyg9q
         7hoB6aKy2A6EAdNHYcRbYQxO4jjsNHmfUv9qjCaBKQqLovJ41tcYVrYt+LHebSoUsZuT
         mvKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=m24iecrt;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id bf11-20020a056602368b00b007624b031dc8si1786846iob.0.2023.05.01.12.18.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 May 2023 12:18:36 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2601:1c2:980:9ec0::2764]
	by bombadil.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1ptZ1u-00GeuY-36;
	Mon, 01 May 2023 19:17:47 +0000
Message-ID: <91a360d3-c876-0a57-5cb1-e3a5f419080d@infradead.org>
Date: Mon, 1 May 2023 12:17:42 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH 07/40] Lazy percpu counters
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
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
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-8-surenb@google.com>
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <20230501165450.15352-8-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=m24iecrt;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=rdunlap@infradead.org
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

Hi--

On 5/1/23 09:54, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> This patch adds lib/lazy-percpu-counter.c, which implements counters
> that start out as atomics, but lazily switch to percpu mode if the
> update rate crosses some threshold (arbitrarily set at 256 per second).
> 

from submitting-patches.rst:

Describe your changes in imperative mood, e.g. "make xyzzy do frotz"
instead of "[This patch] makes xyzzy do frotz" or "[I] changed xyzzy
to do frotz", as if you are giving orders to the codebase to change
its behaviour.

> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  include/linux/lazy-percpu-counter.h | 102 ++++++++++++++++++++++
>  lib/Kconfig                         |   3 +
>  lib/Makefile                        |   2 +
>  lib/lazy-percpu-counter.c           | 127 ++++++++++++++++++++++++++++
>  4 files changed, 234 insertions(+)
>  create mode 100644 include/linux/lazy-percpu-counter.h
>  create mode 100644 lib/lazy-percpu-counter.c
> 
> diff --git a/include/linux/lazy-percpu-counter.h b/include/linux/lazy-percpu-counter.h
> new file mode 100644
> index 000000000000..45ca9e2ce58b
> --- /dev/null
> +++ b/include/linux/lazy-percpu-counter.h
> @@ -0,0 +1,102 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * Lazy percpu counters:
> + * (C) 2022 Kent Overstreet
> + *
> + * Lazy percpu counters start out in atomic mode, then switch to percpu mode if
> + * the update rate crosses some threshold.
> + *
> + * This means we don't have to decide between low memory overhead atomic
> + * counters and higher performance percpu counters - we can have our cake and
> + * eat it, too!
> + *
> + * Internally we use an atomic64_t, where the low bit indicates whether we're in
> + * percpu mode, and the high 8 bits are a secondary counter that's incremented
> + * when the counter is modified - meaning 55 bits of precision are available for
> + * the counter itself.
> + */
> +
> +#ifndef _LINUX_LAZY_PERCPU_COUNTER_H
> +#define _LINUX_LAZY_PERCPU_COUNTER_H
> +
> +#include <linux/atomic.h>
> +#include <asm/percpu.h>
> +
> +struct lazy_percpu_counter {
> +	atomic64_t			v;
> +	unsigned long			last_wrap;
> +};
> +
> +void lazy_percpu_counter_exit(struct lazy_percpu_counter *c);
> +void lazy_percpu_counter_add_slowpath(struct lazy_percpu_counter *c, s64 i);
> +void lazy_percpu_counter_add_slowpath_noupgrade(struct lazy_percpu_counter *c, s64 i);
> +s64 lazy_percpu_counter_read(struct lazy_percpu_counter *c);
> +
> +/*
> + * We use the high bits of the atomic counter for a secondary counter, which is
> + * incremented every time the counter is touched. When the secondary counter
> + * wraps, we check the time the counter last wrapped, and if it was recent
> + * enough that means the update frequency has crossed our threshold and we
> + * switch to percpu mode:
> + */
> +#define COUNTER_MOD_BITS		8
> +#define COUNTER_MOD_MASK		~(~0ULL >> COUNTER_MOD_BITS)
> +#define COUNTER_MOD_BITS_START		(64 - COUNTER_MOD_BITS)
> +
> +/*
> + * We use the low bit of the counter to indicate whether we're in atomic mode
> + * (low bit clear), or percpu mode (low bit set, counter is a pointer to actual
> + * percpu counters:
> + */
> +#define COUNTER_IS_PCPU_BIT		1
> +
> +static inline u64 __percpu *lazy_percpu_counter_is_pcpu(u64 v)
> +{
> +	if (!(v & COUNTER_IS_PCPU_BIT))
> +		return NULL;
> +
> +	v ^= COUNTER_IS_PCPU_BIT;
> +	return (u64 __percpu *)(unsigned long)v;
> +}
> +
> +/**
> + * lazy_percpu_counter_add: Add a value to a lazy_percpu_counter

For kernel-doc, the function name should be followed by '-', not ':'.
(many places)

> + *
> + * @c: counter to modify
> + * @i: value to add
> + */
> +static inline void lazy_percpu_counter_add(struct lazy_percpu_counter *c, s64 i)
> +{
> +	u64 v = atomic64_read(&c->v);
> +	u64 __percpu *pcpu_v = lazy_percpu_counter_is_pcpu(v);
> +
> +	if (likely(pcpu_v))
> +		this_cpu_add(*pcpu_v, i);
> +	else
> +		lazy_percpu_counter_add_slowpath(c, i);
> +}
> +
> +/**
> + * lazy_percpu_counter_add_noupgrade: Add a value to a lazy_percpu_counter,
> + * without upgrading to percpu mode
> + *
> + * @c: counter to modify
> + * @i: value to add
> + */
> +static inline void lazy_percpu_counter_add_noupgrade(struct lazy_percpu_counter *c, s64 i)
> +{
> +	u64 v = atomic64_read(&c->v);
> +	u64 __percpu *pcpu_v = lazy_percpu_counter_is_pcpu(v);
> +
> +	if (likely(pcpu_v))
> +		this_cpu_add(*pcpu_v, i);
> +	else
> +		lazy_percpu_counter_add_slowpath_noupgrade(c, i);
> +}
> +
> +static inline void lazy_percpu_counter_sub(struct lazy_percpu_counter *c, s64 i)
> +{
> +	lazy_percpu_counter_add(c, -i);
> +}
> +
> +#endif /* _LINUX_LAZY_PERCPU_COUNTER_H */

> diff --git a/lib/lazy-percpu-counter.c b/lib/lazy-percpu-counter.c
> new file mode 100644
> index 000000000000..4f4e32c2dc09
> --- /dev/null
> +++ b/lib/lazy-percpu-counter.c
> @@ -0,0 +1,127 @@
> +// SPDX-License-Identifier: GPL-2.0-only
> +
> +#include <linux/atomic.h>
> +#include <linux/gfp.h>
> +#include <linux/jiffies.h>
> +#include <linux/lazy-percpu-counter.h>
> +#include <linux/percpu.h>
> +
> +static inline s64 lazy_percpu_counter_atomic_val(s64 v)
> +{
> +	/* Ensure output is sign extended properly: */
> +	return (v << COUNTER_MOD_BITS) >>
> +		(COUNTER_MOD_BITS + COUNTER_IS_PCPU_BIT);
> +}
> +
...
> +
> +/**
> + * lazy_percpu_counter_exit: Free resources associated with a
> + * lazy_percpu_counter

Same kernel-doc comment.

> + *
> + * @c: counter to exit
> + */
> +void lazy_percpu_counter_exit(struct lazy_percpu_counter *c)
> +{
> +	free_percpu(lazy_percpu_counter_is_pcpu(atomic64_read(&c->v)));
> +}
> +EXPORT_SYMBOL_GPL(lazy_percpu_counter_exit);
> +
> +/**
> + * lazy_percpu_counter_read: Read current value of a lazy_percpu_counter
> + *
> + * @c: counter to read
> + */
> +s64 lazy_percpu_counter_read(struct lazy_percpu_counter *c)
> +{
> +	s64 v = atomic64_read(&c->v);
> +	u64 __percpu *pcpu_v = lazy_percpu_counter_is_pcpu(v);
> +
> +	if (pcpu_v) {
> +		int cpu;
> +
> +		v = 0;
> +		for_each_possible_cpu(cpu)
> +			v += *per_cpu_ptr(pcpu_v, cpu);
> +	} else {
> +		v = lazy_percpu_counter_atomic_val(v);
> +	}
> +
> +	return v;
> +}
> +EXPORT_SYMBOL_GPL(lazy_percpu_counter_read);
> +
> +void lazy_percpu_counter_add_slowpath(struct lazy_percpu_counter *c, s64 i)
> +{
> +	u64 atomic_i;
> +	u64 old, v = atomic64_read(&c->v);
> +	u64 __percpu *pcpu_v;
> +
> +	atomic_i  = i << COUNTER_IS_PCPU_BIT;
> +	atomic_i &= ~COUNTER_MOD_MASK;
> +	atomic_i |= 1ULL << COUNTER_MOD_BITS_START;
> +
> +	do {
> +		pcpu_v = lazy_percpu_counter_is_pcpu(v);
> +		if (pcpu_v) {
> +			this_cpu_add(*pcpu_v, i);
> +			return;
> +		}
> +
> +		old = v;
> +	} while ((v = atomic64_cmpxchg(&c->v, old, old + atomic_i)) != old);
> +
> +	if (unlikely(!(v & COUNTER_MOD_MASK))) {
> +		unsigned long now = jiffies;
> +
> +		if (c->last_wrap &&
> +		    unlikely(time_after(c->last_wrap + HZ, now)))
> +			lazy_percpu_counter_switch_to_pcpu(c);
> +		else
> +			c->last_wrap = now;
> +	}
> +}
> +EXPORT_SYMBOL(lazy_percpu_counter_add_slowpath);
> +
> +void lazy_percpu_counter_add_slowpath_noupgrade(struct lazy_percpu_counter *c, s64 i)
> +{
> +	u64 atomic_i;
> +	u64 old, v = atomic64_read(&c->v);
> +	u64 __percpu *pcpu_v;
> +
> +	atomic_i  = i << COUNTER_IS_PCPU_BIT;
> +	atomic_i &= ~COUNTER_MOD_MASK;
> +
> +	do {
> +		pcpu_v = lazy_percpu_counter_is_pcpu(v);
> +		if (pcpu_v) {
> +			this_cpu_add(*pcpu_v, i);
> +			return;
> +		}
> +
> +		old = v;
> +	} while ((v = atomic64_cmpxchg(&c->v, old, old + atomic_i)) != old);
> +}
> +EXPORT_SYMBOL(lazy_percpu_counter_add_slowpath_noupgrade);

These last 2 exported functions could use some comments, preferably in
kernel-doc format.

Thanks.
-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/91a360d3-c876-0a57-5cb1-e3a5f419080d%40infradead.org.
