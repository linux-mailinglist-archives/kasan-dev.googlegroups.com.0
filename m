Return-Path: <kasan-dev+bncBD3JNNMDTMEBBGECVG6QMGQEG7UV2NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E5C89A2F67A
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2025 19:10:33 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2b845a01e68sf1014309fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2025 10:10:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739211032; cv=pass;
        d=google.com; s=arc-20240605;
        b=O5+l2kkv4nL37DWNLfkfZ6HGQ7+2PAVm+aF4LXjEkm9BFmyby3jiPpvjzMLURiFgZP
         3TuWeYK1bP4NxF676Wbwf1o1qrz5EtxonRSrJQLUmXVc4+OiH9ee9DTSqDGLEjY7V3jg
         EzFyuSvpHyzuEdQsqqmgSXtjkNTIxndDdPOqPckhVFN6TqSwx+DvUedRXSZtfxM15qQk
         k4jHmlAIvmKotUdTx8Z3o4OGqhBl///BzZXVJqoq9pdVwzNryOD8kdYSh8WGIwcbDJ47
         k17ZvkzYRqEULi2jfYbWI7WwhQLOmkzfK24s8YvumSLV0xIGTlKM3nlpjRKpqR6yLPyK
         Q7Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=a7x3BoPD3JD8Zv7vP1rvhrRYUWOZo8kSd9Zjh3HX5Mw=;
        fh=EeXUOHR8cfgiFff4GggVFvSIH/Ln7SHI0C9rZy3xvgw=;
        b=XJ/tk4dywBMjAdnlNwR4kl5EHfpPVfXw60Per6ybQIu5p6pkCkmCRlxwkc48JxNkYg
         qRFYpD3AKbFE0CouBW6x8Wz0r02ka4Ex8UfURFNxyDhWvq3wW3TD0Jax8HB9umIF0qug
         bP0hVCvZbfrLlzY4IviVmxxZD3zbD3P8d/wQtbrXfBksMwWrdk+8jVtFx0LPrCz5wIPn
         qK9LnVt6Kzukj/fWnd1kFpgBa8UoxOYxCV+lRYCbjzSscGG8wVYClnaWPIOT6HgQzXkw
         J1y0V6086v4pCatMBV+uqGDx8Hae7hwB1CoQnOhlo9w4vYtg0LQzqLDSix29fqR6uh+E
         nQ0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=qzADi6ZF;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.11 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739211032; x=1739815832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=a7x3BoPD3JD8Zv7vP1rvhrRYUWOZo8kSd9Zjh3HX5Mw=;
        b=SXe3GEUXuBrr2IeuGsqiuZJvlz7LkdyENAsRmVyTiT860SgeMzg2d0SvuYjGEkC+0b
         +oe0KJXMAzHRvTG8+6G3NNS4vFOoisBhyRn7LQFf7q+/2o7y75tSgdBjcECtUzIsdMya
         sStTpZ/cqrwovs0j25MrHeq4rYBn21xZL3qefWIM6XNQoCd4OcFDh9AUkIKzZiD5/VUY
         s7ptm3zVi9i0R+4Jg7vmnbqpnGAoCbudFt38QMUJBpP6EhIVBdlPi8Y2/SnHM5f/w+h8
         1erXt2aS24BFc1RxP9NpSbq06Tb0xdQNwQY3SFAvI97xwOWihOx34A6ZkbJrmYkyMzsv
         zYGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739211032; x=1739815832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=a7x3BoPD3JD8Zv7vP1rvhrRYUWOZo8kSd9Zjh3HX5Mw=;
        b=VmjzOxzhFAK0VbAWAulc+tEGrny/NzqePk6LSl1IyH0T167qGEn7waqbdsIExLFg36
         I2rpG4dV562PzFQCY0Y2k4tDog0/IyW/SnXquoNs+P0b4PC+yg+psjs1pvGYzaApybYG
         EYgU+gzn87JXoc0uth9Crqm7WmldKi/fNxpjTCLWLm0Aec5yDaQzo9r8Tky1DZr5JwTW
         vz2NsMbW8o23yfYOPYOaH82k6pk9eNKiVM4hMpbnoGFRSIph/cuLmVX1unLGsXL75jTo
         cvgqAHfDEE9yTRtcTLJ5ImTS62h/I1fpmZuk3df06cIhm3Qq93nkIV4XfWKEmmWIBhD1
         RTnw==
X-Forwarded-Encrypted: i=2; AJvYcCUhaJmJ0jGxc2JjnFkRewSOl5SYfC1VOgBoNquTZg5DM1Y5jbgBlp1aghzxGQABiBb2DCMkJg==@lfdr.de
X-Gm-Message-State: AOJu0YwF73S/S+ubSLGDQpDsxALMs81E7kD0ehc59YUzZ+Sgr6y2OEce
	cfDTvayHs0gMfSVcchRSDOfLU2UCNVH7X9m0xk27KgAQTx32keJi
X-Google-Smtp-Source: AGHT+IH4vWTepBESTh/T8fxgQUMlewn50QuHmY5JVr3MAzTh00NWFIF423mIKk1DypPW07EsaY8cOA==
X-Received: by 2002:a05:6870:f114:b0:29e:3531:29da with SMTP id 586e51a60fabf-2b83ebd338fmr9784751fac.9.1739211032282;
        Mon, 10 Feb 2025 10:10:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGUS8FxSvcgdqW0rFWGUUv17FTqPoxodMjzs2efGmuagw==
Received: by 2002:a05:6871:279e:b0:29f:c765:d0ec with SMTP id
 586e51a60fabf-2b8b69e34abls33210fac.0.-pod-prod-06-us; Mon, 10 Feb 2025
 10:10:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUeHvQcF0OFltgGH8nYy7SJAOEqhRRDY5+jRX87xqq5vmA6nxQXjRircT1QFKsdU/7e/HlVqQtTqpE=@googlegroups.com
X-Received: by 2002:a05:6808:908:b0:3f3:b0ae:7978 with SMTP id 5614622812f47-3f3b0ae7af2mr3433716b6e.12.1739211030778;
        Mon, 10 Feb 2025 10:10:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739211030; cv=none;
        d=google.com; s=arc-20240605;
        b=QLEHjs8BN+u8UjqD+1TdQ/bIF50plovo3+xnxq7qxjjYsKQLUs3d8LwzzAWZeuBMHy
         NwsIQk91tReJkJ94C2blf52dg1N8Kfc91uvGvXsKFj4GIo1j7oivsRYGzAzfZwSgBdHH
         ww3uk1KrpRKYNfoPOZFMPlovB2qfwoIbnwoQ010J2O5swIwAaJW+bo89JztSqXSmXu+Y
         dFKkq/AaSnWRxKcMzaLckC2UdVSSeEzJF+Hbzx8bKgZh2AO5ep6ywyI3TYIUaTK1WcMs
         5R5uz5kfpISDzXGYbWXN2vuz8FUovkqCMt9BuaUvxXeuO8im7wyMleFAyjlcMm5uZyTU
         C52g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=5d4NYfy5d24mQ4QZnrsHA0r6Om6Ygst0euippVvDqVE=;
        fh=0Ovo09T/l7iyAM2CZR26Zg4xB/uj/2vRoIXmdAf37Lk=;
        b=ekjo7tVogKD/oBh/INmpfrOMR+GRWsRk08acvFWKMYMoZ5uGXO91FTKiCMjVZGw05Y
         /pWu+bQTMpF0JD3wg3Of1cWNBjzOwQieVmK68HeEbmuAbI0W7UL5EXrZZZo82aIHPbLb
         yo7irwS10PqgYL1EH48Xwf/XzQl3la+BuKTfRqC+Gfmn8TxI6qvrZlBOGXfJQEI5OYS8
         n0LmG+Otw2+ox1wEF+AP4MKPAHFAlF/gQYYj9EDQx2Un3H97/pj+k2K60drHQOJu2oDE
         +DAuvi5tyaBKjXIM5SinsKTWcc7gLZEzewtZgtw2/c4jgaZK5JCVnBEpXz4EDZOuDYqR
         y0rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=qzADi6ZF;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.11 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acm.org
Received: from 008.lax.mailroute.net (008.lax.mailroute.net. [199.89.1.11])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3f389f91ad4si471271b6e.4.2025.02.10.10.10.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Feb 2025 10:10:30 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.11 as permitted sender) client-ip=199.89.1.11;
Received: from localhost (localhost [127.0.0.1])
	by 008.lax.mailroute.net (Postfix) with ESMTP id 4YsCKy1Kt8z6ClRNh;
	Mon, 10 Feb 2025 18:10:30 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 008.lax.mailroute.net ([127.0.0.1])
 by localhost (008.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id vKI5VGS4czNT; Mon, 10 Feb 2025 18:10:13 +0000 (UTC)
Received: from [100.66.154.22] (unknown [104.135.204.82])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 008.lax.mailroute.net (Postfix) with ESMTPSA id 4YsCKK2JxDz6ClY9g;
	Mon, 10 Feb 2025 18:09:56 +0000 (UTC)
Message-ID: <e276263f-2bc5-450e-9a35-e805ad8f277b@acm.org>
Date: Mon, 10 Feb 2025 10:09:55 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 08/24] lockdep: Annotate lockdep assertions for
 capability analysis
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Bill Wendling <morbo@google.com>,
 Boqun Feng <boqun.feng@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Frederic Weisbecker <frederic@kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
 Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <ndesaulniers@google.com>,
 Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>,
 Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>,
 Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-9-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250206181711.1902989-9-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=qzADi6ZF;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.11 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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

On 2/6/25 10:10 AM, Marco Elver wrote:
> diff --git a/include/linux/lockdep.h b/include/linux/lockdep.h
> index 67964dc4db95..5cea929b2219 100644
> --- a/include/linux/lockdep.h
> +++ b/include/linux/lockdep.h
> @@ -282,16 +282,16 @@ extern void lock_unpin_lock(struct lockdep_map *lock, struct pin_cookie);
>   	do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)
>   
>   #define lockdep_assert_held(l)		\
> -	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
> +	do { lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD); __assert_cap(l); } while (0)
>   
>   #define lockdep_assert_not_held(l)	\
>   	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_HELD)
>   
>   #define lockdep_assert_held_write(l)	\
> -	lockdep_assert(lockdep_is_held_type(l, 0))
> +	do { lockdep_assert(lockdep_is_held_type(l, 0)); __assert_cap(l); } while (0)
>   
>   #define lockdep_assert_held_read(l)	\
> -	lockdep_assert(lockdep_is_held_type(l, 1))
> +	do { lockdep_assert(lockdep_is_held_type(l, 1)); __assert_shared_cap(l); } while (0)

These changes look wrong to me. The current behavior of
lockdep_assert_held(lock) is that it issues a kernel warning at
runtime if `lock` is not held when a lockdep_assert_held()
statement is executed. __assert_cap(lock) tells the compiler to
*ignore* the absence of __must_hold(lock). I think this is wrong.
The compiler should complain if a __must_hold(lock) annotation is
missing. While sparse does not support interprocedural analysis for
lock contexts, the Clang thread-safety checker supports this. If
function declarations are annotated with __must_hold(lock), Clang will
complain if the caller does not hold `lock`.

In other words, the above changes disable a useful compile-time check.
I think that useful compile-time checks should not be disabled.

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e276263f-2bc5-450e-9a35-e805ad8f277b%40acm.org.
