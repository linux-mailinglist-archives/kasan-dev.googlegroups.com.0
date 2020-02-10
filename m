Return-Path: <kasan-dev+bncBCZLJOMFV4FRB6ULQ7ZAKGQEVYFCJXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 2778315848E
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 22:07:08 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id a31sf394972pje.4
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 13:07:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581368826; cv=pass;
        d=google.com; s=arc-20160816;
        b=O3kqMTQREc3T2SfuK20+TfPwo6nPv/He7ZwkApq2RKT+4WgB2VhwMnWPC8gwhbWgkt
         8Q736uks/RoRZMqkLlVV8XW77xjVc0io07T/cGtpJu8vfHoWiqZiCvBftFoTQDLCL5Wr
         3S2a6hNRqdadHaFh/ZSr8TSoziayZVJJYo09lDjdY1PKhj6O4y7DfS1nllOYDj0WNa7k
         FLapVrPK0UKVW4WC98nw/x6IJ8d06xPBMC64N+OuJ1Wlri/QK5QJ+DcWPbHAGmkahfq8
         W3llt2YAMUNzvVdvD8YVE/zzVEeeUe2IwVZyXrLzjTwc8crRM7dVYWFTCXyc0x44uuc+
         jpog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=VS11O5stwguM1bVJ1vc70oAEASvNphrCL1rck3mj8dE=;
        b=tIA9vCBKLDe+jYeuyEiKYKlK9vnBDJ7KsqQ1fHmQJWRcLNHwqbJ5LukKBS0TiCPjb+
         bZDYnTycp1KCDd1l7uawIWRlh/csigVhFhVvDYuIpJF859WaO/yQBRfjW8VthVUsChP9
         qjHXayXMXD8oZduFq/8xqe3bSX2cTxV2Kvwc4WO3BOmGUaJmKVMZFVlYfgDRD+9U533f
         SgFslHqgownXeOLbHahxk9tHxLyWyvci7tVC5yvQbxHJwsuNxnSse7NyLjvQ1MWXnhud
         hLLJwS+12kmR70qTAwg0Z/hnlKVTDV/mjwaNnurh1phihPv2PT5t7ZNjsSWbiC/ztsCr
         800g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nvidia.com header.s=n1 header.b=BR9X6s3L;
       spf=pass (google.com: domain of jhubbard@nvidia.com designates 216.228.121.65 as permitted sender) smtp.mailfrom=jhubbard@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VS11O5stwguM1bVJ1vc70oAEASvNphrCL1rck3mj8dE=;
        b=TjxLgEsia28XvgQ05oYcEhZ5unGAc9rb2WKLDANQE0bDjL4FA2TxGSIKFz1knkAylC
         YRLbI31zFYZ/FDbrrZvLhHuceWpX2+hr3Dm7SuQpMxuzrWSOkJzeIc47UzlYE2sHazQ+
         9h1y5RjePUiaj9nEXI4Up/Ci06PgSFCicyVrMxFdEqOXDhuLZ4WQTgJl9jV1f8VB2sdd
         bkq49+Hfcu1TGvuN2xCveuzftkjToTqLm4is4SoCZk2Ezk22z+pS2EMly6qI5O9Joyao
         G5o2TKdVp/OiFBIoPfR+HRGblRZUamkJMWxCuWfi27UFQyk+eQRPNqIZ7rJZfVpzifSk
         iHfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VS11O5stwguM1bVJ1vc70oAEASvNphrCL1rck3mj8dE=;
        b=BdqybPvcK/gX4GVB4+m6WYbnP/6Ns4X28v+Qn2N6ESJ2M1V+xYx80geE8VrnZy9bgh
         DaZNbWu9fyf5b/QeRzE98u4MOx7Wh4wXsWOmCYuMnywj+E5Kbtw9UzM5NTRIkF/d86UP
         CG6bsZtLcs1/ypuKh3Es7Oa5G0E+ApRHRchXiS8V+ZiBQM3jMCKqP296tzuE7NfyH1RG
         Cpo3ezfexXUmPAZZUAeoYO/wYZTkzpFJPXZc1Ou4KzKUQpgI92JEPO5zFmc3H1B/85E1
         mvr8eQf4xHU8Gw8J4cnOvj6sUtZWK0ga+Sfn0HgvIeqDEjDn3XuSmLNg3LqAINKWI01v
         7b1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVZI+1Duj2CLpsFqK0d1ZDwVTVadx8lZNVqC1BzAeozWVYqiwnm
	ImW3SYLEU8TbD+B5+DnYv0w=
X-Google-Smtp-Source: APXvYqz6CXdsNrg7mmid+ffln7BhHPwfduWnzn7/sxHcVb0jBYBk2UcejimSa6Ed40Ei2KC+pW9DHg==
X-Received: by 2002:aa7:8695:: with SMTP id d21mr2937670pfo.199.1581368826604;
        Mon, 10 Feb 2020 13:07:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b26:: with SMTP id 35ls237779pjq.1.gmail; Mon, 10
 Feb 2020 13:07:06 -0800 (PST)
X-Received: by 2002:a17:902:be04:: with SMTP id r4mr14501749pls.315.1581368826169;
        Mon, 10 Feb 2020 13:07:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581368826; cv=none;
        d=google.com; s=arc-20160816;
        b=WieVjQgzCMS7i8HQjMb4uqbZ/2ghsrKAHgjwAkd91TeIoylM6buuJeaQ9fwOF1dAvw
         m5Huf7+JoHoG2pLBCFyJLzvDH+mmaVquuROwVKJDfQ8UE8ccE7LSfjoPMwbZDCVmC2Js
         OCr0UuPmjbj2vN8XPqCTojPrptaqkB/n1+rCfTHuDD9QfiR4gw5dqaa0OYZPs6zbwQdU
         68Cc4I05yusYP89fZ2VbUyWJktGJ4a5qZJDY8W5Th1ftO470xwEAoulO2sHwIcILR/Mc
         qKqLyvWDL/U3M3B0CYVXwjmdxwrLgNpABKoo4TCd3dd+qtMRGEf0gDXqBl5OmPMtTF8E
         Nnrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=dkim-signature:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject;
        bh=x5jlNDmZWfgsReEBA1RyRhnoPE9uvIpHWxzFCAc54tQ=;
        b=H38C3efSuIKTooLukoGSSvYsfG79Jru0PLqmaDEayTgbvBMJdfGcFw4D3sxwasT6dl
         VkQYSAofRq2bPVp3hyEhjzTAyneh3S0Inbr08qFvKGPiuezIHd9jaVKapNeYvICYd+Qq
         Q+cfidYMWO2JJx+l+M+Aqw7/YtBm8lFAkK9xwvNiWdSzi7g/ta+kw9ADv1jJ4kckiDlZ
         pQwnmd6I+9oJwF24cAQdZf9H141DnCM1vv5RG9CYPT6RIQC8Ge8HVmBqgvwjkV1xIubG
         uCL2ncF/8++yNSqIFOPQB6WkjpX++Skj6KLeOZ6UCITO5g7YaMfp9JhpXsbPTk4fIzXZ
         2e6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@nvidia.com header.s=n1 header.b=BR9X6s3L;
       spf=pass (google.com: domain of jhubbard@nvidia.com designates 216.228.121.65 as permitted sender) smtp.mailfrom=jhubbard@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
Received: from hqnvemgate26.nvidia.com (hqnvemgate26.nvidia.com. [216.228.121.65])
        by gmr-mx.google.com with ESMTPS id y13si90115plp.0.2020.02.10.13.07.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Feb 2020 13:07:06 -0800 (PST)
Received-SPF: pass (google.com: domain of jhubbard@nvidia.com designates 216.228.121.65 as permitted sender) client-ip=216.228.121.65;
Received: from hqpgpgate101.nvidia.com (Not Verified[216.228.121.13]) by hqnvemgate26.nvidia.com (using TLS: TLSv1.2, DES-CBC3-SHA)
	id <B5e41c5e70000>; Mon, 10 Feb 2020 13:06:47 -0800
Received: from hqmail.nvidia.com ([172.20.161.6])
  by hqpgpgate101.nvidia.com (PGP Universal service);
  Mon, 10 Feb 2020 13:07:01 -0800
X-PGP-Universal: processed;
	by hqpgpgate101.nvidia.com on Mon, 10 Feb 2020 13:07:01 -0800
Received: from [10.110.48.28] (10.124.1.5) by HQMAIL107.nvidia.com
 (172.20.187.13) with Microsoft SMTP Server (TLS) id 15.0.1473.3; Mon, 10 Feb
 2020 21:07:01 +0000
Subject: Re: [PATCH 5/5] kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
To: Marco Elver <elver@google.com>
CC: <paulmck@kernel.org>, <andreyknvl@google.com>, <glider@google.com>,
	<dvyukov@google.com>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>, Jan Kara <jack@suse.cz>, Qian Cai
	<cai@lca.pw>
References: <20200210184317.233039-1-elver@google.com>
 <20200210184317.233039-5-elver@google.com>
From: John Hubbard <jhubbard@nvidia.com>
X-Nvconfidentiality: public
Message-ID: <3963b39c-bdc9-d188-a086-f5ea443477d1@nvidia.com>
Date: Mon, 10 Feb 2020 13:07:00 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.2
MIME-Version: 1.0
In-Reply-To: <20200210184317.233039-5-elver@google.com>
X-Originating-IP: [10.124.1.5]
X-ClientProxiedBy: HQMAIL111.nvidia.com (172.20.187.18) To
 HQMAIL107.nvidia.com (172.20.187.13)
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: jhubbard@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nvidia.com header.s=n1 header.b=BR9X6s3L;       spf=pass
 (google.com: domain of jhubbard@nvidia.com designates 216.228.121.65 as
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

On 2/10/20 10:43 AM, Marco Elver wrote:
> This introduces ASSERT_EXCLUSIVE_BITS(var, mask).
> ASSERT_EXCLUSIVE_BITS(var, mask) will cause KCSAN to assume that the
> following access is safe w.r.t. data races (however, please see the
> docbook comment for disclaimer here).
> 
> For more context on why this was considered necessary, please see:
>   http://lkml.kernel.org/r/1580995070-25139-1-git-send-email-cai@lca.pw
> 
> In particular, data races between reads (that use @mask bits of an
> access that should not be modified concurrently) and writes (that change
> ~@mask bits not used by the read) should ordinarily be marked. After
> marking these, we would no longer be able to detect harmful races
> between reads to @mask bits and writes to @mask bits.

I know this is "just" the commit log, but as long as I'm reviewing the
whole thing...to make the above a little clearer, see if you like this 
revised wording:

In particular, before this patch, data races between reads (that use
@mask bits of an access that should not be modified concurrently) and
writes (that change ~@mask bits not used by the readers) would have
been annotated with "data_race()". However, doing so would then hide
real problems: we would no longer be able to detect harmful races
between reads to @mask bits and writes to @mask bits.


> 
> Therefore, by using ASSERT_EXCLUSIVE_BITS(var, mask), we accomplish:
> 
>   1. No new macros introduced elsewhere; since there are numerous ways in
>      which we can extract the same bits, a one-size-fits-all macro is
>      less preferred.

This somehow confuses me a lot. Maybe say it like this:

1. Avoid a proliferation of specific macros at the call sites: by including a
   mask in the argument list, we can use the same macro in a wide variety of 
   call sites, regardless of which bits in a field each call site uses.

?

> 
>   2. The existing code does not need to be modified (although READ_ONCE()
>      may still be advisable if we cannot prove that the data race is
>      always safe).
> 
>   3. We catch bugs where the exclusive bits are modified concurrently.
> 
>   4. We document properties of the current code.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: David Hildenbrand <david@redhat.com>
> Cc: Jan Kara <jack@suse.cz>
> Cc: John Hubbard <jhubbard@nvidia.com>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Qian Cai <cai@lca.pw>
> ---
>  include/linux/kcsan-checks.h | 57 ++++++++++++++++++++++++++++++++----
>  kernel/kcsan/debugfs.c       | 15 +++++++++-
>  2 files changed, 65 insertions(+), 7 deletions(-)
> 
> diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> index 4ef5233ff3f04..eae6030cd4348 100644
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
> @@ -191,4 +191,49 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
>  #define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
>  	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
>  
> +/**
> + * ASSERT_EXCLUSIVE_BITS - assert no concurrent writes to subset of bits in @var
> + *
> + * [Bit-granular variant of ASSERT_EXCLUSIVE_WRITER(var)]


No need for the square brackets, unless that's some emerging convention in the
documentation world. 


> + *
> + * Assert that there are no concurrent writes to a subset of bits in @var;
> + * concurrent readers are permitted. Concurrent writes (or reads) to ~@mask bits
> + * are ignored. This assertion can be used to specify properties of concurrent
> + * code, where marked accesses imply violations cannot be detected as a normal
> + * data race.


How about this wording:

/*
 * Assert that there are no concurrent writes to a subset of bits in @var;
 * concurrent readers are permitted. Concurrent writes (or reads) to ~@mask bits
 * are ignored. This assertion provides more detailed, bit-level information to
 * the KCSAN system than most of the other (word granularity) annotations. As
 * such, it allows KCSAN to safely overlook some bits while still continuing to
 * check the remaining bits for unsafe access patterns.
 *
 * Use this if you have some bits that are read-only, and other bits that are
 * not, within a variable.
 */

?


> + *
> + * For example, this may be used when certain bits of @var may only be modified
> + * when holding the appropriate lock, but other bits may still be modified
> + * concurrently. Writers, where other bits may change concurrently, could use
> + * the assertion as follows:
> + *
> + *	spin_lock(&foo_lock);
> + *	ASSERT_EXCLUSIVE_BITS(flags, FOO_MASK);
> + *	old_flags = READ_ONCE(flags);
> + *	new_flags = (old_flags & ~FOO_MASK) | (new_foo << FOO_SHIFT);
> + *	if (cmpxchg(&flags, old_flags, new_flags) != old_flags) { ... }
> + *	spin_unlock(&foo_lock);
> + *
> + * Readers, could use it as follows:
> + *
> + *	ASSERT_EXCLUSIVE_BITS(flags, FOO_MASK);
> + *	foo = (READ_ONCE(flags) & FOO_MASK) >> FOO_SHIFT;


In the general case (which is what this documentation covers), the
READ_ONCE() is not required. So this should either leave it out, or
explain that it's not necessarily required.


> + *
> + * NOTE: The access that immediately follows is assumed to access the masked
> + * bits only, and safe w.r.t. data races. While marking this access is optional
> + * from KCSAN's point-of-view, it may still be advisable to do so, since we
> + * cannot reason about all possible compiler optimizations when it comes to bit
> + * manipulations (on the reader and writer side).
> + *
> + * @var variable to assert on
> + * @mask only check for modifications to bits set in @mask
> + */
> +#define ASSERT_EXCLUSIVE_BITS(var, mask)                                       \


This API looks good to me.


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



thanks,
-- 
John Hubbard
NVIDIA

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3963b39c-bdc9-d188-a086-f5ea443477d1%40nvidia.com.
