Return-Path: <kasan-dev+bncBDBK55H2UQKRBWEXQO4QMGQEDZ5FMYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id CADAC9B489D
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 12:49:46 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-539e75025f9sf3123086e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 04:49:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730202586; cv=pass;
        d=google.com; s=arc-20240605;
        b=BozkXA6iT+7T+vCvqkvWLHNBXSPH/N9fJmcQtQ9/vf+FXhG2kLoLxg9pZ/mVXziQHq
         ickEvPf7PBX6MYg9zJMVQ9m1GK18TB1P4QVwyke7KNvYtXTaUII26hlT/u+R2wu2y5Yp
         jevby7UhY1aop2FqKauuly4CdE1rtbQcFTRY0IK1Uf67Y6aoEXPCizpZAGPbPeiN1n1y
         HtDrUnngR+UY1t7zqpqIGgpBX47abgtevsN8VH3qMc0lYkuNKiHGNiJpoqsKEmUWElaD
         TnYny/XQxOb7DqD5JVhDq1ZFHzKz1mDG6EEprwosFLT7CI4lGeQz+haiFYRG6jm1jkl/
         dNKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gybQKPDNWsgZd1PEZ1ZWMA4xSKoF2pMLmzENT8cxixU=;
        fh=NDdA++6rjKhS/6Gtn8xsDRD1tftJx5cL4840MRMHSYE=;
        b=dFhtgXyiS+8l8+IL9atIcztAUpf3a7W0t+pz0oGpA4InBZubxdRuc3TjcqDKQbR1yG
         jgEQjZlETGj2DV+Kf6khgxo1i4MwH0/qDzHveaeYgtPESR/q3ideyOGaLjcFNzxVQWh+
         s20TLSTXT6A2tP96UgwKNk5OzmYuzahvmMIKqRlQyvl+qOz32QmdXgR0OjgEORUYDn0N
         1DIYpVmxqCIgnaSYuGTqaVnT9EVR9LcQ104He3POHD3yOR/abhxLanZv6i+BCD2TdKqe
         uEa5f0W56zmiVdVBmX0GgHT2r7ml9AylcLnBy6zIQwdBP+NsjpLRXHHIl3lpmyUS83Ez
         Vt3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=HpLCuFOC;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730202586; x=1730807386; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gybQKPDNWsgZd1PEZ1ZWMA4xSKoF2pMLmzENT8cxixU=;
        b=GcElghv5qJRa+CiLS2oRcuRYxCiDk1UnlS11o4byZCxl1KOszvlWnrwD31iI+VBYQY
         kbeP12vi224zFznJOYdxYwOrZ/AwTMh/xwcki0i31qyBAF7sromAZXHaa1fwuNQOBHT1
         M4n0QL8U9Aquc+U46pbgDhyHOdbcI+AFA4XE56uYYp8JRclXKGmbVpGutPtS40QVFl7/
         5pSXa0w1S5cU682ycoUXSfEyPRnb4V6kKIBvG2tpYqsiy8FLR2YWEhk4vPMOjdcJ0WbK
         Jn0Aie/BJUVgdcOmkshphalDo4rLVO+JWj+XLBiab8Xh3Qu0b9rIjjDrbonnF8t5qv/S
         FURA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730202586; x=1730807386;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gybQKPDNWsgZd1PEZ1ZWMA4xSKoF2pMLmzENT8cxixU=;
        b=gp3LDJW9s8kY8WndxLHEVYegiXxZt9NkjhnbuKpQsozzf4mhlBSuUyn+aTMw3Oap8Z
         arEu9+zt/r0sY9Iv+ehh+WvFbf8XEGSGBxehflnHbe9VcVskntiaI8kJE6zCsMO22uGB
         /o2KxmVCp2Dn29lTrzqTzAM9SmZYAWjVJNJGRp6OhPobWMJOso5Uso3OEV2WlhKuZfzP
         +M3sfFXabbA45cXyWZ18ZFnIp77COhP2AvhFSzxLo53yG9KtbrwbaCVkF5vHMnuuEh9L
         HTcznXkqSh6FwXfgxOoysDLdS/sAv1W1DxF6UfRa1oF9BuvvlJT3FrmJ9bSMFbfZn4hy
         s2sw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVv6RYtFF4rPcu6JHx3snCKvdticMkBS31ghTWvgvsHptkhfGWgxVSFOURjc4ChTH3YvSJj3w==@lfdr.de
X-Gm-Message-State: AOJu0YwPESwvt1CE+P10vI3FgFLDh3U9OgRhCs1ct3XNrWAlGZqgFL4V
	bDsjn4+6BGfhD811hMDqUnNUf0NdzjYl6RF672yci8DCPgOEtSsn
X-Google-Smtp-Source: AGHT+IEpUEayGaGY3wOrfXxmqDFUxAElMOpLzxEqGQkP3TA6y1Al1LO9GoT5+FnFyV0eZDFvoIUojg==
X-Received: by 2002:a05:6512:1105:b0:539:e776:71f2 with SMTP id 2adb3069b0e04-53b34a33f15mr5268576e87.52.1730202585020;
        Tue, 29 Oct 2024 04:49:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1111:b0:539:ee1b:fdb5 with SMTP id
 2adb3069b0e04-53b213a5f60ls183818e87.0.-pod-prod-07-eu; Tue, 29 Oct 2024
 04:49:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIW5FQFS6SBk1pDnDd9FynAq4LDf5qK3vlyDF7+P+fXJ6mS4ITXAogWcvCvw616/isKX3lruhM8mU=@googlegroups.com
X-Received: by 2002:a05:6512:15a9:b0:539:ecef:376d with SMTP id 2adb3069b0e04-53b34a33d05mr5453850e87.54.1730202582083;
        Tue, 29 Oct 2024 04:49:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730202582; cv=none;
        d=google.com; s=arc-20240605;
        b=h98oAHWsO1YeLEJPL7dczDHrMfpqPBQdRLB3ku/Gy/FKAYbxeKkrxnFzb3avd6Yrzc
         SwVI6ce8+YRz2tIGqd5Zib2jlaenVeCenRlyTJUr2J4ZgkV8aFYOSIIFLDgwO/f5FTZn
         u4EUUCxsT0AWyJUq71zbUiCC3VtIcqVleN06pkYuzeEa5fDPzlnZJczF06oKKNEkIigj
         0tAASrj+wgqQJAKHvdhaMUknkvI6KbMmkMXUOMDRaPQyOJCYQL6TN21xcaUZnIVPk3Lm
         PqLfHw2fucRxR18mt8XLVoDuPkqUoh+k1MHMf69q4nc81jRiOpzWzpg2FqzYwBCUnJUp
         tCbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=cAU3cKOmIcgayaZwMEuWmWzKdhGtdQEk6QwyUpbPf3w=;
        fh=rsYLeNn3EhqnY/ERv90DXt1NYQkHGuhFKomDG1eXtr4=;
        b=k3kt7DGFfNv56eFlgVSBPiqlhE+YmxqOtIdNaq4sAaemqRaqfmT08gUTvKgifUnG3o
         D6sOQeAU2jv2jQCoqbrhQj8lPCtuizGN7bJ2keQgw2mXJNVVFKOxgRycDwP9XdBwQEK+
         yW6TSDm8hfOWnR5F2yHQsDlidfS4ZHrN8kN9dQJuCwLxHRjLU3yXTap5YW1mKeyypjx+
         0MTsZc2fwpw4CW7W8qDhvO06qm6M+Y1RcP9SKf6Yb8edWYJF+Mi8nMeFeq30wM6uZqcl
         hwrZVeF7s+JOoD/czsa2ZHEvacGjF/XSYDI8rIcV2jB00g7NlSdlfLy2yWIVbFYEu7W6
         xprw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=HpLCuFOC;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53b2e10a00dsi176297e87.2.2024.10.29.04.49.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Oct 2024 04:49:41 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1t5kjB-00000009eiw-0XRn;
	Tue, 29 Oct 2024 11:49:37 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 478AF30073F; Tue, 29 Oct 2024 12:49:37 +0100 (CET)
Date: Tue, 29 Oct 2024 12:49:37 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Alexander Potapenko <glider@google.com>
Subject: Re: [PATCH] kcsan, seqlock: Support seqcount_latch_t
Message-ID: <20241029114937.GT14555@noisy.programming.kicks-ass.net>
References: <20241029083658.1096492-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241029083658.1096492-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=HpLCuFOC;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Oct 29, 2024 at 09:36:29AM +0100, Marco Elver wrote:
> Reviewing current raw_write_seqcount_latch() callers, the most common
> patterns involve only few memory accesses, either a single plain C
> assignment, or memcpy;

Then I assume you've encountered latch_tree_{insert,erase}() in your
travels, right?

Also, I note that update_clock_read_data() seems to do things
'backwards' and will completely elide your proposed annotation.

> therefore, the value of 8 memory accesses after
> raw_write_seqcount_latch() is chosen to (a) avoid most false positives,
> and (b) avoid excessive number of false negatives (due to inadvertently
> declaring most accesses in the proximity of update_fast_timekeeper() as
> "atomic").

The above latch'ed RB-trees can certainly exceed this magical number 8.

> Reported-by: Alexander Potapenko <glider@google.com>
> Tested-by: Alexander Potapenko <glider@google.com>
> Fixes: 88ecd153be95 ("seqlock, kcsan: Add annotations for KCSAN")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/seqlock.h | 9 +++++++++
>  1 file changed, 9 insertions(+)
> 
> diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
> index fffeb754880f..e24cf144276e 100644
> --- a/include/linux/seqlock.h
> +++ b/include/linux/seqlock.h
> @@ -614,6 +614,7 @@ typedef struct {
>   */
>  static __always_inline unsigned raw_read_seqcount_latch(const seqcount_latch_t *s)
>  {
> +	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
>  	/*
>  	 * Pairs with the first smp_wmb() in raw_write_seqcount_latch().
>  	 * Due to the dependent load, a full smp_rmb() is not needed.
> @@ -631,6 +632,7 @@ static __always_inline unsigned raw_read_seqcount_latch(const seqcount_latch_t *
>  static __always_inline int
>  raw_read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
>  {
> +	kcsan_atomic_next(0);
>  	smp_rmb();
>  	return unlikely(READ_ONCE(s->seqcount.sequence) != start);
>  }
> @@ -721,6 +723,13 @@ static inline void raw_write_seqcount_latch(seqcount_latch_t *s)
>  	smp_wmb();	/* prior stores before incrementing "sequence" */
>  	s->seqcount.sequence++;
>  	smp_wmb();      /* increment "sequence" before following stores */
> +
> +	/*
> +	 * Latch writers do not have a well-defined critical section, but to
> +	 * avoid most false positives, at the cost of false negatives, assume
> +	 * the next few memory accesses belong to the latch writer.
> +	 */
> +	kcsan_atomic_next(8);
>  }

Given there are so very few latch users, would it make sense to
introduce a raw_write_seqcount_latch_end() callback that does
kcsan_atomic_next(0) ? -- or something along those lines? Then you won't
have to assume such a small number.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241029114937.GT14555%40noisy.programming.kicks-ass.net.
