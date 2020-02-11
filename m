Return-Path: <kasan-dev+bncBCZLJOMFV4FRB7F6RTZAKGQEOAFTMGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id BAC53159B4E
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 22:41:17 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id p15sf3045251uao.9
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 13:41:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581457276; cv=pass;
        d=google.com; s=arc-20160816;
        b=LE1WniofvWFm1Rd3jCFKrNjAOli3xVC41f1Xtdq2pLYNpzEQqK6Ze+HBJsvmtefaY7
         fb2QcjEWewAGhFft/uZ968hI726EDdVmCe6e8isSxXlPU8kU/tEZcconYSbKByssbAb1
         MavesTerO+sYQ98G+CZrbxLfLLeQl+qnLOH8qxCiVm3bpuUxwI34WAO1LqLr89vv9+Mx
         /DuN9VlX9BZ3hMR6EjhAJcxNY/HJ+kg2RzO7vtL8vgBfL6MQY0PSWEG+ik3ZM+QYs4T9
         oLEyGZU2Ze8dKDQYFx8q6WUv1CmrM1qqcJjbvfkyd7KAhggnhpj547PsOnSC+cLKWYZn
         flpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=X4+of/eeWzh3mOAnenR/Ge0WDFdPMByuAQmCTMIfOu0=;
        b=rZuEAgBzv61CwriUV2BotF5B9FkecjDXBwipCI8tcEoIWDNSDR1Bsm0i3kNBxtEnJa
         Q3Leozay+OSNk99z9z1yqXPY8NmP57x56pT6Za1sHpTOrhdauBnPsJmb8xux4mXaciAA
         xGa0sp9NgkdYltQjN+LcasSkoG9wbl5VV4QSDrFGUnxAY9aoBo0d+YCFcYkR4l/9urTA
         K9T0akLbchXRD9hkG9hUZH/sDgCTNMf3jrmhh5PQpCzKw8/myxliTIVbHRtFyvDPIG14
         NSnOnC+PzQ38L7Ai30BYNW7KB/Cv3ozu/MmAL4eogQIMzmD0GYqyqtAe4S9JTfCG4fwk
         ui7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nvidia.com header.s=n1 header.b=bUEGGRRP;
       spf=pass (google.com: domain of jhubbard@nvidia.com designates 216.228.121.143 as permitted sender) smtp.mailfrom=jhubbard@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=X4+of/eeWzh3mOAnenR/Ge0WDFdPMByuAQmCTMIfOu0=;
        b=dlYbuAekvm59/gIJ68xIIoReL1A6vU6roqHt+scWMWZURDuqBqeMAcEsyAAujGhsOy
         nP7arn6wmFEg2uxdeq96m4hVgLIVCKXf/WwfUufi5PMGLgpVdWAACMPj/wAl+wb3qIiu
         pGIZHd2pHSzOH8U/KZrMZ1v14fX2NosEnwf+CiwxvVxlER9K30rE6wXdVZDj63KaVFqK
         +uE7h1fSZKoYU0fMf5QgVoBMTRLTWW4Dp6ks6Ru7KygjZZMCTM/8pA0kt1SFiy074nVU
         dmVRqpixrQRRQW+7eX+6vK7a1uMLzyW6RINYEYBUGQIvx3z2GFsq3xnXsu8xeYN+Im+k
         G8IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=X4+of/eeWzh3mOAnenR/Ge0WDFdPMByuAQmCTMIfOu0=;
        b=Hz0j7n0FLsr8d8SqRBm53tFHfw695vzBVuckemMWftnjlQwawmrUBPmh9EB2LQJkmS
         tugTdDD4rP8yRi+vQzj8VbCtuTzOY6sFWhma6SKYaXt1RjLUiwN78JdvvkH6K5a/fhFZ
         EXtjheEdrBWAbNUHD9GWnhn5s2k5NirlhvDSTkpLntgnEOHHxWBBpN/UCzQ+6ofvp/4P
         WMyOZ55ekjtkd7bQ54qJnPjfYtpa8u3AotZd+RAVKPALbMCHNQAGFVaAc9mTeODp9xW1
         TDDgc/eRzs9GGXKlpWHuhBJIWIWsIWKLWKf6if5DZTqdOnwiUGUBWbt5PXuN7l1kWJXP
         qaZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVZzg4KpJ83AqQVc1sCIe/KrRL2kp+CUKaKP5X9KlMNVmp005vf
	Q8HhhWWI9HnGMbzc8d3ODjY=
X-Google-Smtp-Source: APXvYqwCtBM1AROC9eylTmb9elT97mU2BTlgl3ESR3V6GP7fldd3C6gye3Xf5fNLaRIn1FL/rMycxA==
X-Received: by 2002:a05:6102:3c2:: with SMTP id n2mr10016388vsq.172.1581457276709;
        Tue, 11 Feb 2020 13:41:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d38b:: with SMTP id b11ls1389181vsj.9.gmail; Tue, 11 Feb
 2020 13:41:16 -0800 (PST)
X-Received: by 2002:a67:b607:: with SMTP id d7mr10272451vsm.234.1581457276233;
        Tue, 11 Feb 2020 13:41:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581457276; cv=none;
        d=google.com; s=arc-20160816;
        b=nGQmRKs2DVfKnAaK2wIaahcIUUhV7cTIg9qs8HCM4cWAkIfKccZNU2QhLjai8SUmDl
         PZAXZ8a2j15BoMg0Zn+JiK8fHMIF4cnKHX+LLSdCt0m21N6kX1oTXmapofZO6pvTHeBX
         kdiXf/UKIWROKn1bqxrWwfgpl2n48R8KGO+zD9GbNL6biXfwVJclicSgaMKwdjfaXux6
         EetrXwhBGvQW0+6e9mlkOQhcbCNpWxBUddC4qxwnHC3kRuM8fG4Tau+18Bvhk1xGaP1Z
         8lwP3LhRf/nbtWO/XicaE3194HBhkM67fnrbVHvl5vUfAcwBWaFrivOHOu3+TemCmpUE
         EgpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=dkim-signature:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject;
        bh=NSJKRR7Tf70zmrBVjiqXiHe+qUGFkKDLPc36fwOB/eM=;
        b=wi5GadgJa0IsWk+Wfq4PtI/5NOvnbMbLLrqnr6nCcSWyySuqSkQ0LoP42q2OEofouo
         64tx+uZ5icEH9gDe6kc3gb51/f46JiPvjujEElBAoeeLHxRxKr7KCaybsxTQwvJXfcQ7
         TR30vOkEfxLYFZWwbvvRexx281pqin6wPwxg6bikcc2h1GTKvCw70ENvAeHWHK4q2RRE
         LQ3PwTGJ3nNfi0sE2XFOrEUOUA+zp3ybGWCI8XgTCSN6P6EYHghiOyl/LLxaqd9csFlZ
         rxlkg4rsu4p2DWWf4bSOlrrtEoqdbsdNu2KZEJrzK6i6irgxjhvqmMMppQvJQoO6Oee+
         Wdgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@nvidia.com header.s=n1 header.b=bUEGGRRP;
       spf=pass (google.com: domain of jhubbard@nvidia.com designates 216.228.121.143 as permitted sender) smtp.mailfrom=jhubbard@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
Received: from hqnvemgate24.nvidia.com (hqnvemgate24.nvidia.com. [216.228.121.143])
        by gmr-mx.google.com with ESMTPS id o19si246942vka.4.2020.02.11.13.41.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Feb 2020 13:41:16 -0800 (PST)
Received-SPF: pass (google.com: domain of jhubbard@nvidia.com designates 216.228.121.143 as permitted sender) client-ip=216.228.121.143;
Received: from hqpgpgate101.nvidia.com (Not Verified[216.228.121.13]) by hqnvemgate24.nvidia.com (using TLS: TLSv1.2, DES-CBC3-SHA)
	id <B5e431f3b0000>; Tue, 11 Feb 2020 13:40:11 -0800
Received: from hqmail.nvidia.com ([172.20.161.6])
  by hqpgpgate101.nvidia.com (PGP Universal service);
  Tue, 11 Feb 2020 13:41:15 -0800
X-PGP-Universal: processed;
	by hqpgpgate101.nvidia.com on Tue, 11 Feb 2020 13:41:15 -0800
Received: from [10.110.48.28] (10.124.1.5) by HQMAIL107.nvidia.com
 (172.20.187.13) with Microsoft SMTP Server (TLS) id 15.0.1473.3; Tue, 11 Feb
 2020 21:41:14 +0000
Subject: Re: [PATCH v2 5/5] kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
To: Marco Elver <elver@google.com>
CC: <paulmck@kernel.org>, <andreyknvl@google.com>, <glider@google.com>,
	<dvyukov@google.com>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>, Jan Kara <jack@suse.cz>, Qian Cai
	<cai@lca.pw>
References: <20200211160423.138870-1-elver@google.com>
 <20200211160423.138870-5-elver@google.com>
From: John Hubbard <jhubbard@nvidia.com>
X-Nvconfidentiality: public
Message-ID: <29718fab-0da5-e734-796c-339144ac5080@nvidia.com>
Date: Tue, 11 Feb 2020 13:41:14 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.2
MIME-Version: 1.0
In-Reply-To: <20200211160423.138870-5-elver@google.com>
X-Originating-IP: [10.124.1.5]
X-ClientProxiedBy: HQMAIL105.nvidia.com (172.20.187.12) To
 HQMAIL107.nvidia.com (172.20.187.13)
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: jhubbard@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nvidia.com header.s=n1 header.b=bUEGGRRP;       spf=pass
 (google.com: domain of jhubbard@nvidia.com designates 216.228.121.143 as
 permitted sender) smtp.mailfrom=jhubbard@nvidia.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=nvidia.com
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

On 2/11/20 8:04 AM, Marco Elver wrote:
> This introduces ASSERT_EXCLUSIVE_BITS(var, mask).
> ASSERT_EXCLUSIVE_BITS(var, mask) will cause KCSAN to assume that the
> following access is safe w.r.t. data races (however, please see the
> docbook comment for disclaimer here).
> 
> For more context on why this was considered necessary, please see:
>   http://lkml.kernel.org/r/1580995070-25139-1-git-send-email-cai@lca.pw
> 
> In particular, before this patch, data races between reads (that use
> @mask bits of an access that should not be modified concurrently) and
> writes (that change ~@mask bits not used by the readers) would have been
> annotated with "data_race()" (or "READ_ONCE()"). However, doing so would
> then hide real problems: we would no longer be able to detect harmful
> races between reads to @mask bits and writes to @mask bits.
> 
> Therefore, by using ASSERT_EXCLUSIVE_BITS(var, mask), we accomplish:
> 
>   1. Avoid proliferation of specific macros at the call sites: by
>      including a single mask in the argument list, we can use the same
>      macro in a wide variety of call sites, regardless of how and which
>      bits in a field each call site actually accesses.
> 
>   2. The existing code does not need to be modified (although READ_ONCE()
>      may still be advisable if we cannot prove that the data race is
>      always safe).
> 
>   3. We catch bugs where the exclusive bits are modified concurrently.
> 
>   4. We document properties of the current code.


API looks good to me. (I'm not yet familiar enough with KCSAN to provide
any useful review of about the various kcsan*() calls that implement the 
new macro.)

btw, it might be helpful for newcomers if you mentioned which tree this
is based on. I poked around briefly and failed several times to find one. :)

You can add:

Acked-by: John Hubbard <jhubbard@nvidia.com>


thanks,
-- 
John Hubbard
NVIDIA
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: David Hildenbrand <david@redhat.com>
> Cc: Jan Kara <jack@suse.cz>
> Cc: John Hubbard <jhubbard@nvidia.com>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Qian Cai <cai@lca.pw>
> ---
> v2:
> * Update API documentation to be clearer about how this compares to the
>   existing assertions, and update use-cases. [Based on suggestions from
>   John Hubbard]
> * Update commit message. [Suggestions from John Hubbard]
> ---
>  include/linux/kcsan-checks.h | 69 ++++++++++++++++++++++++++++++++----
>  kernel/kcsan/debugfs.c       | 15 +++++++-
>  2 files changed, 77 insertions(+), 7 deletions(-)
> 
> diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> index 4ef5233ff3f04..1b8aac5d6a0b5 100644
> --- a/include/linux/kcsan-checks.h
> +++ b/include/linux/kcsan-checks.h
> @@ -152,9 +152,9 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
>  #endif
>  
>  /**
> - * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
> + * ASSERT_EXCLUSIVE_WRITER - assert no concurrent writes to @var
>   *
> - * Assert that there are no other threads writing @var; other readers are
> + * Assert that there are no concurrent writes to @var; other readers are
>   * allowed. This assertion can be used to specify properties of concurrent code,
>   * where violation cannot be detected as a normal data race.
>   *
> @@ -171,11 +171,11 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
>  	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
>  
>  /**
> - * ASSERT_EXCLUSIVE_ACCESS - assert no other threads are accessing @var
> + * ASSERT_EXCLUSIVE_ACCESS - assert no concurrent accesses to @var
>   *
> - * Assert that no other thread is accessing @var (no readers nor writers). This
> - * assertion can be used to specify properties of concurrent code, where
> - * violation cannot be detected as a normal data race.
> + * Assert that there are no concurrent accesses to @var (no readers nor
> + * writers). This assertion can be used to specify properties of concurrent
> + * code, where violation cannot be detected as a normal data race.
>   *
>   * For example, in a reference-counting algorithm where exclusive access is
>   * expected after the refcount reaches 0. We can check that this property
> @@ -191,4 +191,61 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
>  #define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
>  	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
>  
> +/**
> + * ASSERT_EXCLUSIVE_BITS - assert no concurrent writes to subset of bits in @var
> + *
> + * Bit-granular variant of ASSERT_EXCLUSIVE_WRITER(var).
> + *
> + * Assert that there are no concurrent writes to a subset of bits in @var;
> + * concurrent readers are permitted. This assertion captures more detailed
> + * bit-level properties, compared to the other (word granularity) assertions.
> + * Only the bits set in @mask are checked for concurrent modifications, while
> + * ignoring the remaining bits, i.e. concurrent writes (or reads) to ~@mask bits
> + * are ignored.
> + *
> + * Use this for variables, where some bits must not be modified concurrently,
> + * yet other bits are expected to be modified concurrently.
> + *
> + * For example, variables where, after initialization, some bits are read-only,
> + * but other bits may still be modified concurrently. A reader may wish to
> + * assert that this is true as follows:
> + *
> + *	ASSERT_EXCLUSIVE_BITS(flags, READ_ONLY_MASK);
> + *	foo = (READ_ONCE(flags) & READ_ONLY_MASK) >> READ_ONLY_SHIFT;
> + *
> + *   Note: The access that immediately follows ASSERT_EXCLUSIVE_BITS() is
> + *   assumed to access the masked bits only, and KCSAN optimistically assumes it
> + *   is therefore safe, even in the presence of data races, and marking it with
> + *   READ_ONCE() is optional from KCSAN's point-of-view. We caution, however,
> + *   that it may still be advisable to do so, since we cannot reason about all
> + *   compiler optimizations when it comes to bit manipulations (on the reader
> + *   and writer side). If you are sure nothing can go wrong, we can write the
> + *   above simply as:
> + *
> + * 	ASSERT_EXCLUSIVE_BITS(flags, READ_ONLY_MASK);
> + *	foo = (flags & READ_ONLY_MASK) >> READ_ONLY_SHIFT;
> + *
> + * Another example, where this may be used, is when certain bits of @var may
> + * only be modified when holding the appropriate lock, but other bits may still
> + * be modified concurrently. Writers, where other bits may change concurrently,
> + * could use the assertion as follows:
> + *
> + *	spin_lock(&foo_lock);
> + *	ASSERT_EXCLUSIVE_BITS(flags, FOO_MASK);
> + *	old_flags = READ_ONCE(flags);
> + *	new_flags = (old_flags & ~FOO_MASK) | (new_foo << FOO_SHIFT);
> + *	if (cmpxchg(&flags, old_flags, new_flags) != old_flags) { ... }
> + *	spin_unlock(&foo_lock);
> + *
> + * @var variable to assert on
> + * @mask only check for modifications to bits set in @mask
> + */
> +#define ASSERT_EXCLUSIVE_BITS(var, mask)                                       \
> +	do {                                                                   \
> +		kcsan_set_access_mask(mask);                                   \
> +		__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT);\
> +		kcsan_set_access_mask(0);                                      \
> +		kcsan_atomic_next(1);                                          \
> +	} while (0)
> +
>  #endif /* _LINUX_KCSAN_CHECKS_H */
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> index 9bbba0e57c9b3..2ff1961239778 100644
> --- a/kernel/kcsan/debugfs.c
> +++ b/kernel/kcsan/debugfs.c
> @@ -100,8 +100,10 @@ static noinline void microbenchmark(unsigned long iters)
>   * debugfs file from multiple tasks to generate real conflicts and show reports.
>   */
>  static long test_dummy;
> +static long test_flags;
>  static noinline void test_thread(unsigned long iters)
>  {
> +	const long CHANGE_BITS = 0xff00ff00ff00ff00L;
>  	const struct kcsan_ctx ctx_save = current->kcsan_ctx;
>  	cycles_t cycles;
>  
> @@ -109,16 +111,27 @@ static noinline void test_thread(unsigned long iters)
>  	memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
>  
>  	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
> +	pr_info("test_dummy@%px, test_flags@%px\n", &test_dummy, &test_flags);
>  
>  	cycles = get_cycles();
>  	while (iters--) {
> +		/* These all should generate reports. */
>  		__kcsan_check_read(&test_dummy, sizeof(test_dummy));
> -		__kcsan_check_write(&test_dummy, sizeof(test_dummy));
>  		ASSERT_EXCLUSIVE_WRITER(test_dummy);
>  		ASSERT_EXCLUSIVE_ACCESS(test_dummy);
>  
> +		ASSERT_EXCLUSIVE_BITS(test_flags, ~CHANGE_BITS); /* no report */
> +		__kcsan_check_read(&test_flags, sizeof(test_flags)); /* no report */
> +
> +		ASSERT_EXCLUSIVE_BITS(test_flags, CHANGE_BITS); /* report */
> +		__kcsan_check_read(&test_flags, sizeof(test_flags)); /* no report */
> +
>  		/* not actually instrumented */
>  		WRITE_ONCE(test_dummy, iters);  /* to observe value-change */
> +		__kcsan_check_write(&test_dummy, sizeof(test_dummy));
> +
> +		test_flags ^= CHANGE_BITS; /* generate value-change */
> +		__kcsan_check_write(&test_flags, sizeof(test_flags));
>  	}
>  	cycles = get_cycles() - cycles;
>  
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/29718fab-0da5-e734-796c-339144ac5080%40nvidia.com.
