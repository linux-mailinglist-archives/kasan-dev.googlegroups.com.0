Return-Path: <kasan-dev+bncBDV37XP3XYDRBWVRY3WQKGQEMJ7HO4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 93DE8E3253
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2019 14:28:10 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id w24sf8261091edx.16
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2019 05:28:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571920090; cv=pass;
        d=google.com; s=arc-20160816;
        b=nuPuAzeBzFJThBm8OaXgmScCfGDh/Zbr4e+tLHXVXRWLlC2/Az132NENi11dtwTogG
         BUOablvqzpIzQ/P5Qqs6jpSMx2PDxhssq3kukk3TJ8m5BQYO/2GKJuEUGUi0Y3iFwtT2
         hCSgffxACpZxHCu7D4+Hdlav9Q0Q0R4ASQZtCfrp7seSIJFwS843WcGWie3s0YzJpdWZ
         s+nwHKdKl9d59DdggnU/719W5zLSa1Dso1lIm2lUnanW73L2+q55lDCi6MW+D8yw+q62
         2x/8Hf+wyIfFcxWwQshlzSqmiA3O4McEC4wyknkn50x3sk72tfFx6WhxlKERFDlsoSzC
         KgnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=djnDMOAth6z8gF41csHDdo6PznT+3a67Avw/LaSRbYQ=;
        b=HBaj92t630O5jticenbLCJVrOYe1LL1Gly+YWlwrfy9uSfUihi3OZmR05zVzotd9Rw
         crH5CeJHkAo20O6WeFTe/UoOp/eyJMAF0YCBq7lPX00bT/bUoUqi3j3BojdOnXiSFsXn
         NvxOSCoIMTsjZQvdEHtbxxrsQ2Pd2kD/hUtNMrAXw3oefeCKj9MFNDkb0mrSadzhieiZ
         5i2+n98CrIAbKDClFoQevs29pjUn8i2R+H6xyKk3C8LLF1r15Mn3lMyUzpQMoJsoZc3U
         zr8orZzg4pLzZGakE7Kx6eGpDgFKn85gIR20XqOPGNoO57KVQ0hIUnZtrKZ43GTTTG27
         CMSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=djnDMOAth6z8gF41csHDdo6PznT+3a67Avw/LaSRbYQ=;
        b=pLMplmnZpwyxT6TH4NTsoJc8JQRQ1Im5jMflzCH4sukiI3qJmLo9wwG54iYR4ROf/P
         ErVv91JeOnQJxLXXlCW0HxTbEYZfxm+fEFtXD/VC8grKWEQLIA6K5u2e8jVPVzCuzg/z
         dLZMIcMgehK9cfnE1NxCWRffqfWxShuOz+FfwvCaD8lhVX+ZQDcO1BCIYC8Zczx0KtHZ
         4BDW+fQIoU71WIpIDv6q/KpKuBPtRxs40LZo7hpeugpUlQohEXHvQhQu84wij7/232VJ
         mcYE6Rq8hxl6FNdN3eEGBSfqNVrmQePSSq2uTSbpH3h+jvjQpnBa6IG1zXuS3e8/n7A9
         cjlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=djnDMOAth6z8gF41csHDdo6PznT+3a67Avw/LaSRbYQ=;
        b=cXqwlvhNFnnZHvG3C7LeSBBRPv19qJsHE/GYUZ0V6P2gwKUR22F+WPkN0YB1Ioh/nN
         jCAQoz1a7KSQkE1mFZ+zoP1YvP33ZSUZwgwdfAI2MFW8SWgX4E7OtaO5xzyhCaEjDeNl
         fuG0UbtNOqilOdwmXfMvxaI0qWiXYy+icb8q9vsiGomV43UpPbA1mWiEe9mK78ZbAHEV
         Y/q0tUAJPeZmIyU2MFVEAvOzfUzFgpGv/j3srMpwmXWIFR2ejaxq/ro0kac2D0uXAv76
         QFGl+1RHSRk1KMtO9OaoQny15rzQDPlonFA0t4LRKoCaCQqg/9ZZVYlDaA17lxkERX/V
         JNTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUj3YNMfhrcSizpdBvHPCaRjJk9i/Ek6EIewyAE1D4WILSWK4cP
	W5X+e70bXbhJq6TFqvkRbh8=
X-Google-Smtp-Source: APXvYqyFiu3f3UOzso8PWkFUu7MFkdY9iL4zWMM6MQJQPDJmbnCuASceo/lC2F/h8YlyabK3S08Urg==
X-Received: by 2002:aa7:c257:: with SMTP id y23mr43038844edo.39.1571920090308;
        Thu, 24 Oct 2019 05:28:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:b54b:: with SMTP id z11ls1350936edd.6.gmail; Thu, 24 Oct
 2019 05:28:09 -0700 (PDT)
X-Received: by 2002:aa7:dd88:: with SMTP id g8mr14922371edv.247.1571920089754;
        Thu, 24 Oct 2019 05:28:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571920089; cv=none;
        d=google.com; s=arc-20160816;
        b=qkidREIZBWTnFT2d/tBAOB+VoqWIC+dSYVUMWJVnB9I8aC6SkyXKfUaDN7ICSHLG63
         uUiOHs7A1xumhiuZoduLAuZsJlCXVoSq/HOR2tORZ9GADXVnh/29FSUtET16LQ1AKteV
         R0oa2nLNsTsXiD/u+djx5gYdn/OSQ4PD+dBN8ApN8j65sPuoc0i55Gvir64STm+6b4AW
         rILpq1onJjTH0lpfCnuezJcTRSSv0YqKp1U+E2TV11yZIP+HXp0dLovIbCtl7Z1QTtjk
         oa7N/0bv28U/w1MaO30C9E/iadOKvgY1V+m0j99bpmdr0ajE//8dLZlLmAI9UZtMXcUM
         vo0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=hbpJlasMClQmY5YU/yCDc6YRqQI+bH/wBMDpkyzESIg=;
        b=ygS6VhvWjue7lquyvLyC6xIbF7tthQ1xN8R6ca2XwnsmUpgxfuecgcvd3xTaaiHiee
         7mv985PuAXqWqFy3bM/ugiZTtm6GgLRsRhH15+VZqy2OatLjUPcNPkKbuNvYCMU0mCMZ
         pJifNS5w1Ii+IxN2k/Yg31+bvAujTzihgxM5rdynBaOAf/0uZG51CBGX54GeZEIoRkHh
         ynVRQgjF8fdWvJ83cwa8c4P4ZCj1dkgjRQEfeVc8J+DUxyifTCJ9WRXuqAMa37EJzrZV
         iULxkKvuAkqarix+QuzZXrM9LpDJUoU3hYj+Vqciuj94EskTbAUQMYDf4RDUmAIkzZA9
         62wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id q17si748944edi.1.2019.10.24.05.28.09
        for <kasan-dev@googlegroups.com>;
        Thu, 24 Oct 2019 05:28:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E39F1B57;
	Thu, 24 Oct 2019 05:28:08 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A58543F71A;
	Thu, 24 Oct 2019 05:28:04 -0700 (PDT)
Date: Thu, 24 Oct 2019 13:28:02 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com,
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
	bp@alien8.de, dja@axtens.net, dlustig@nvidia.com,
	dave.hansen@linux.intel.com, dhowells@redhat.com,
	dvyukov@google.com, hpa@zytor.com, mingo@redhat.com,
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net,
	jpoimboe@redhat.com, luc.maranget@inria.fr, npiggin@gmail.com,
	paulmck@linux.ibm.com, peterz@infradead.org, tglx@linutronix.de,
	will@kernel.org, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v2 4/8] seqlock, kcsan: Add annotations for KCSAN
Message-ID: <20191024122801.GD4300@lakrids.cambridge.arm.com>
References: <20191017141305.146193-1-elver@google.com>
 <20191017141305.146193-5-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191017141305.146193-5-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Thu, Oct 17, 2019 at 04:13:01PM +0200, Marco Elver wrote:
> Since seqlocks in the Linux kernel do not require the use of marked
> atomic accesses in critical sections, we teach KCSAN to assume such
> accesses are atomic. KCSAN currently also pretends that writes to
> `sequence` are atomic, although currently plain writes are used (their
> corresponding reads are READ_ONCE).
> 
> Further, to avoid false positives in the absence of clear ending of a
> seqlock reader critical section (only when using the raw interface),
> KCSAN assumes a fixed number of accesses after start of a seqlock
> critical section are atomic.

Do we have many examples where there's not a clear end to a seqlock
sequence? Or are there just a handful?

If there aren't that many, I wonder if we can make it mandatory to have
an explicit end, or to add some helper for those patterns so that we can
reliably hook them.

Thanks,
Mark.

> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/seqlock.h | 44 +++++++++++++++++++++++++++++++++++++----
>  1 file changed, 40 insertions(+), 4 deletions(-)
> 
> diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
> index bcf4cf26b8c8..1e425831a7ed 100644
> --- a/include/linux/seqlock.h
> +++ b/include/linux/seqlock.h
> @@ -37,8 +37,24 @@
>  #include <linux/preempt.h>
>  #include <linux/lockdep.h>
>  #include <linux/compiler.h>
> +#include <linux/kcsan.h>
>  #include <asm/processor.h>
>  
> +/*
> + * The seqlock interface does not prescribe a precise sequence of read
> + * begin/retry/end. For readers, typically there is a call to
> + * read_seqcount_begin() and read_seqcount_retry(), however, there are more
> + * esoteric cases which do not follow this pattern.
> + *
> + * As a consequence, we take the following best-effort approach for *raw* usage
> + * of seqlocks under KCSAN: upon beginning a seq-reader critical section,
> + * pessimistically mark then next KCSAN_SEQLOCK_REGION_MAX memory accesses as
> + * atomics; if there is a matching read_seqcount_retry() call, no following
> + * memory operations are considered atomic. Non-raw usage of seqlocks is not
> + * affected.
> + */
> +#define KCSAN_SEQLOCK_REGION_MAX 1000
> +
>  /*
>   * Version using sequence counter only.
>   * This can be used when code has its own mutex protecting the
> @@ -115,6 +131,7 @@ static inline unsigned __read_seqcount_begin(const seqcount_t *s)
>  		cpu_relax();
>  		goto repeat;
>  	}
> +	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
>  	return ret;
>  }
>  
> @@ -131,6 +148,7 @@ static inline unsigned raw_read_seqcount(const seqcount_t *s)
>  {
>  	unsigned ret = READ_ONCE(s->sequence);
>  	smp_rmb();
> +	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
>  	return ret;
>  }
>  
> @@ -183,6 +201,7 @@ static inline unsigned raw_seqcount_begin(const seqcount_t *s)
>  {
>  	unsigned ret = READ_ONCE(s->sequence);
>  	smp_rmb();
> +	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
>  	return ret & ~1;
>  }
>  
> @@ -202,7 +221,8 @@ static inline unsigned raw_seqcount_begin(const seqcount_t *s)
>   */
>  static inline int __read_seqcount_retry(const seqcount_t *s, unsigned start)
>  {
> -	return unlikely(s->sequence != start);
> +	kcsan_atomic_next(0);
> +	return unlikely(READ_ONCE(s->sequence) != start);
>  }
>  
>  /**
> @@ -225,6 +245,7 @@ static inline int read_seqcount_retry(const seqcount_t *s, unsigned start)
>  
>  static inline void raw_write_seqcount_begin(seqcount_t *s)
>  {
> +	kcsan_begin_atomic(true);
>  	s->sequence++;
>  	smp_wmb();
>  }
> @@ -233,6 +254,7 @@ static inline void raw_write_seqcount_end(seqcount_t *s)
>  {
>  	smp_wmb();
>  	s->sequence++;
> +	kcsan_end_atomic(true);
>  }
>  
>  /**
> @@ -262,18 +284,20 @@ static inline void raw_write_seqcount_end(seqcount_t *s)
>   *
>   *      void write(void)
>   *      {
> - *              Y = true;
> + *              WRITE_ONCE(Y, true);
>   *
>   *              raw_write_seqcount_barrier(seq);
>   *
> - *              X = false;
> + *              WRITE_ONCE(X, false);
>   *      }
>   */
>  static inline void raw_write_seqcount_barrier(seqcount_t *s)
>  {
> +	kcsan_begin_atomic(true);
>  	s->sequence++;
>  	smp_wmb();
>  	s->sequence++;
> +	kcsan_end_atomic(true);
>  }
>  
>  static inline int raw_read_seqcount_latch(seqcount_t *s)
> @@ -398,7 +422,9 @@ static inline void write_seqcount_end(seqcount_t *s)
>  static inline void write_seqcount_invalidate(seqcount_t *s)
>  {
>  	smp_wmb();
> +	kcsan_begin_atomic(true);
>  	s->sequence+=2;
> +	kcsan_end_atomic(true);
>  }
>  
>  typedef struct {
> @@ -430,11 +456,21 @@ typedef struct {
>   */
>  static inline unsigned read_seqbegin(const seqlock_t *sl)
>  {
> -	return read_seqcount_begin(&sl->seqcount);
> +	unsigned ret = read_seqcount_begin(&sl->seqcount);
> +
> +	kcsan_atomic_next(0);  /* non-raw usage, assume closing read_seqretry */
> +	kcsan_begin_atomic(false);
> +	return ret;
>  }
>  
>  static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
>  {
> +	/*
> +	 * Assume not nested: read_seqretry may be called multiple times when
> +	 * completing read critical section.
> +	 */
> +	kcsan_end_atomic(false);
> +
>  	return read_seqcount_retry(&sl->seqcount, start);
>  }
>  
> -- 
> 2.23.0.866.gb869b98d4c-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191024122801.GD4300%40lakrids.cambridge.arm.com.
