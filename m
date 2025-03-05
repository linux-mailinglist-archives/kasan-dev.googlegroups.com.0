Return-Path: <kasan-dev+bncBC65ZG75XIPRBAE2UC7AMGQEC5GBOXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D6F62A4F8E8
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Mar 2025 09:36:18 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-43bc97e6360sf11200925e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Mar 2025 00:36:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741163778; cv=pass;
        d=google.com; s=arc-20240605;
        b=Boh76vSVNYMPJarAaGauGTrW69t7M3EvjN24yzzp2rOQb/i7y7YuPHlOhxSsjJJIyw
         zkEB0fzdHnAgdC0RnYeVfgB5bbY1uDnzH37o/MbHsgFlTc4R5QBKZ/WktiUs6Vz6ynKQ
         c3bDtLZqNmT9lDjnBw4mVHEaBTo00ESUTOuI1USrlAWsiSrELDjWcIoTjc4w+A6r7NpY
         EMhk3ElEB37BlOSUNsv2rPnAT5UGQgVaVjRdhemI/3hFHZO+LLSt9jqwaqJhHeV7BODc
         ToOgb3hIvRmaD1XBOR37vHSfe2mQ4mpXQYZJF8EEl5zP8IBDmiNChL4qp5/GY0bTY6fw
         BE1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=N+PRLRDdDwVdXNceoM3zQRfP9NjDTPUUKyYy5EToFgY=;
        fh=+OJq3Hf/OCAncUkDEIMeH4FGuAMWhsBUj0cDSdUOmoc=;
        b=gchVN+3FwpnVTqvOMKQp84XgMOTKsZHu65FI0mnDwFmpUY7IKFwygdVIf1SU3ySGPV
         TItFV2L08VnLlFPXtKGk/jdcD853uHym/nmCkwwtgSqA9EzA1KdxdaTmw5urocvVkEAe
         YwabKaMkRVZm36aOk03qhGyYq492biNxDBWEKO8sIiLze3KD0pCqLd2Q/B3Yptdzobp3
         vWxfJb/eYxQ7LYeszn+Fjv/whhKqFKC6vnPiIZgV0yFZk/6OqRIWCkVXpByNAo6/27+A
         +5GnzTlMUm/XH5eRFug6Dtc9degNkH0qPfFyBU8kIUUFVFPbXhKGXOZ12bKtxTFqpzm0
         v7RQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=fxSuU3Jy;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741163778; x=1741768578; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=N+PRLRDdDwVdXNceoM3zQRfP9NjDTPUUKyYy5EToFgY=;
        b=BFQ2MyU9f3vrth5dN5aaM2MQF0FNtwEZ5xLnIgA4QhvjO2bptVznmFm971dFU7sEIJ
         LAMVh05xMKhSKQ19C2zfEmFs2Iz9bHBsf/kzwxtJjcuK0UXQ3SlEj7DWT9gwVmgwKQMp
         0QyN4vK7pvq4RBDxa9hFo7MEW2chX7uVyMTx+YH4Jv1HrRwPngXqT56wCpk8rYne7h6N
         W+kjFOHUZ/b0nv4poOYK5vgUqOx9saW1Al4gtNvAhMBrTBzpxTOXxLXpy5NP2ffgz9rg
         bMJ6zhKJSTzCag/oqCF/PKtBw+1C/CjCHm51t5X4OVUZC+uBDFLFmxQhr656EVssJSpm
         /+Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741163778; x=1741768578;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=N+PRLRDdDwVdXNceoM3zQRfP9NjDTPUUKyYy5EToFgY=;
        b=T5H5ir5umvL6Y7dQs2X6r2pj1wqaZFP9Q7xtYUdaWttBFwOkxT7nEohmKuJhfw+skZ
         6F+6DVzrNtJoy4ejBe84BqzPfv0Ib6MLtm6Yic8aZ/wjPan0ZirxD8t2h4OixvkBsFdd
         c++lQD/O/DIqZhGsDHwQMuz1KknuExnLCtuwpIymFeE/9scLVqgj2n0G0rrDY51LekzG
         IPR1rEalQgAoMaYS/EkuLrJIsqwz3lsFuYKc1gaz/NiAyU/zwdGsavfx62fRfrNkoSGP
         tTkiEqUDg0UmVrttYYdyAydrs+qzii2JUVaIZHtfZOGFpm+sSq5N21ySiZNulZFfZ4jX
         0I4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6agBNQpqzeP8YHoixcT1LtnDyTIog7M0NCC3vJXgQYXYnLf9hztk/HP9ZUQbUOrwDedxffQ==@lfdr.de
X-Gm-Message-State: AOJu0YwsDaNdYZWy51l16I/J6dQOmY9eNr52UCcGAmTsRpACBfGNz89c
	UMhvPCtrafv4DVDaFh+hW7WjdOYpWq2kqIsPAO2n1Ewyp2XsKmkc
X-Google-Smtp-Source: AGHT+IHC1ze38j0Bs5aZZqPPcOeV5cDLdI4xAcbDc8gDbGqnuWIKH9AxiEiSeUULga4k987ZC/FHHw==
X-Received: by 2002:a05:600c:45c6:b0:439:98ef:5d6 with SMTP id 5b1f17b1804b1-43bd2aed717mr11048955e9.22.1741163776790;
        Wed, 05 Mar 2025 00:36:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHtIv/UbgEbgEw2Qj0cxM8N1tqODLrRgXUubNeIb5InPg==
Received: by 2002:a05:600c:6dcc:b0:43b:cf96:122c with SMTP id
 5b1f17b1804b1-43bcf961380ls3937045e9.1.-pod-prod-06-eu; Wed, 05 Mar 2025
 00:36:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVenC0ibmQkp9i8un6r/lsL5ca3M+4BikUzjhUPuabtlFrhnvwkRJGOgaxxFQNivZsl/6e9q5+e+Uc=@googlegroups.com
X-Received: by 2002:a05:6000:156d:b0:391:10c5:d1a9 with SMTP id ffacd0b85a97d-3911f76e3a4mr1779475f8f.31.1741163774633;
        Wed, 05 Mar 2025 00:36:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741163774; cv=none;
        d=google.com; s=arc-20240605;
        b=TT9vj/gRC9cYA2cViwtikUzIjw26JjdOBtH0QBV7rtIstfSJWas5rBQUd0Ip4xLbS6
         aScU94FuuoE+8JyhyLusUR/R2CfGLLFOgz7SL0xJoixCi4nTa6ZT39cV/jXZws5X2yD7
         RtqIQKyBQ1jzDqMYYChbwVZd+V3VrNGhGxtcJjWY60ChPei/tYlRXw4KLwYGb50xH42Y
         d/wwvD/93ZMJbr6rpF8Vz6N3IcfDe3k46IeUjaZ3oiFOCmCLp7xZOYQcJcSDWpUbagpL
         gUivRdAYzNY/YiRsL7vma7IkgPTpeOqBTl05mrKkPcfaFlrXCjv1OPDQuZT39eGj1yVY
         sz0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZfQXwUL3Ydz7mR+cjRUeO/xqWRGS7uJqxxJMkaNfgT0=;
        fh=9YTsZXK20ADq/ax32AnC72srY9NImZZEfFOURKE19Mg=;
        b=kLswxA9HFxgPrX9nIJ/8XSxFXfSh+ASJ6udNhkAxCC++ET4UA0lcb4V0dBkxlAlLEa
         kPOtv7okFEsgtw2CRxgVdmjX9xUg2sm9PqyEeodEsvIVWJf221is20nJGzogTSTVeWBt
         ChFMA52UNNs6ff/bmJeg9uPypKdlKB1mB05TVdvR4Ly+Wb3xVwlFD3ZSQT6N1jlfBLPf
         rtkRv6vqBodhRFOfy+1O7jnLUQrAa6QSUJAlKRaB58OolN2DmgNGVqpnGb+nclksPQgi
         EWxGOP/+tgu3VLuz74PDFua1LVF25DbKqDM6b0jRWDmQ/xiyn60Pu9a6r3rtKOtcrkLC
         SfkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=fxSuU3Jy;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bd42e34b2si159445e9.2.2025.03.05.00.36.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Mar 2025 00:36:14 -0800 (PST)
Received-SPF: pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-38f403edb4eso3897167f8f.3
        for <kasan-dev@googlegroups.com>; Wed, 05 Mar 2025 00:36:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX01/6ARnhuqJfFmpA6BbMPwjYDYLrWR8u9IilLd9aqXimLajGjdN7UQhCo7reEzCNdsT8j7+vwvBQ=@googlegroups.com
X-Gm-Gg: ASbGncuTwxnBUueDMFxE2ToGeoPdsVZvl/XEJbyDZ1yVv2rn7yT2punqF/CLHEPWp0I
	9qVpYb6Z7SYgVhSW5r1OvGdizX0bYZrfgdEJwqqlhhcPO6zcCcHAbtWEvyE0hxFw25rI8rlVvul
	65FvL58zT3TNBMgicf5o7Zkr/6PNIgsAE1ciCBS7odncHkBHx3CSHEAXOIa7duweqnFAChd6FMW
	dZ4wb5I9maqg2PJEEkWdAj5QnskagV3TjSVEASRCtp/715LAyNE9l37Izj4PhhzHqZqQAmsWU0X
	YTaPQwp7Aey/azpAGDFTNzdYDAhdMkpgJrCwbvTutc16G2bPjg==
X-Received: by 2002:a05:6000:184c:b0:391:23de:b1b4 with SMTP id ffacd0b85a97d-39123deb51dmr497486f8f.45.1741163774150;
        Wed, 05 Mar 2025 00:36:14 -0800 (PST)
Received: from localhost ([196.207.164.177])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-390e479608fsm20564933f8f.14.2025.03.05.00.36.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Mar 2025 00:36:13 -0800 (PST)
Date: Wed, 5 Mar 2025 11:36:10 +0300
From: Dan Carpenter <dan.carpenter@linaro.org>
To: Marco Elver <elver@google.com>
Cc: "David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Jiri Slaby <jirislaby@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-serial@vger.kernel.org
Subject: Re: [PATCH v2 01/34] compiler_types: Move lock checking attributes
 to compiler-capability-analysis.h
Message-ID: <f76a48fe-09da-41e0-be2e-e7f1b939b7e3@stanley.mountain>
References: <20250304092417.2873893-1-elver@google.com>
 <20250304092417.2873893-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250304092417.2873893-2-elver@google.com>
X-Original-Sender: dan.carpenter@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=fxSuU3Jy;       spf=pass
 (google.com: domain of dan.carpenter@linaro.org designates
 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
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

On Tue, Mar 04, 2025 at 10:21:00AM +0100, Marco Elver wrote:
> +#ifndef _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
> +#define _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
> +
> +#ifdef __CHECKER__
> +
> +/* Sparse context/lock checking support. */
> +# define __must_hold(x)		__attribute__((context(x,1,1)))
> +# define __acquires(x)		__attribute__((context(x,0,1)))
> +# define __cond_acquires(x)	__attribute__((context(x,0,-1)))
> +# define __releases(x)		__attribute__((context(x,1,0)))
> +# define __acquire(x)		__context__(x,1)
> +# define __release(x)		__context__(x,-1)
> +# define __cond_lock(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
> +

The other thing you might want to annotate is ww_mutex_destroy().

I'm happy about the new __guarded_by annotation.

regards,
dan carpenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f76a48fe-09da-41e0-be2e-e7f1b939b7e3%40stanley.mountain.
