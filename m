Return-Path: <kasan-dev+bncBDBK55H2UQKRBSWDU64QMGQEMASJETI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 240019BC8CE
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 10:13:48 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4316e2dde9esf44165685e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 01:13:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730798027; cv=pass;
        d=google.com; s=arc-20240605;
        b=PVC47OuyHcTeiEOFWgP1Z6i1+Iwea9EQ6uqzqvV1Eidk9b7H5Jhhx28XNTUFZOm6eY
         JeRwy7Q246qXH3Sn+s9qBmAouGeKvR9bPdt23jcrIXHoeP+/J2qgK3JFvTX4qJ6r34ZU
         UyYj2c+FiBhmiKPrZmzIpuzv6JSj2QrWoXbgtTAkeJhd9zjyAH4yR4NVaSESO2z+W8mt
         i+GiJib7/gxDJpXY4KVyQexbM4fUtKgGebQrUwA2Rez4UvOElaHLDd6iffkC4YGRZ4VD
         6YZJE6THyhvZJJWFaVOXqAUSingKzwsOhk6T113aDr+OqmJ3L7vPz0xE2uxPUFZwPKnB
         k7HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4O0YL3PFt+rs5sxrIFrdSE4aEuVgRz/dq25IxMXaYO0=;
        fh=RwgaLuAP8RICHVpG3AurcKaHZcJwm/pitJ4+ksXn2Ns=;
        b=ksI77PphuCFZnAM/V5P7qrjoosmJIvf78j1tiibupAtbmWC0lvuFFMMK6ByI8Xy4BY
         fzXHpSjhHU9TwRFMxYAi/BdfFUO9TmMAbXtnDBCxtLHifBMUuq2gyHf0W9eosociObdn
         Onz6Br2tlFBKRPxUT8F78hPrS+FDO+iLDfwaK2K5U4Sa6049ZcFAUydw5novaUuA46B2
         ZPn3CNuuZEZBkfztpfHfpWkdFmPVLqjO5qbZW5diwm2lOPvluJYTIPEikYjgJNKzYhus
         pgJDu6pY9r88zRrkmwYp9WqoJff6RYG02GYMn8j+EVlzFRivXP/SEEB9r5nrD90MXuwR
         iwSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=j6wavOpN;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730798027; x=1731402827; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4O0YL3PFt+rs5sxrIFrdSE4aEuVgRz/dq25IxMXaYO0=;
        b=aikWjAG6qMeO35bxIgoWPjWFOscMX8Vyv9yV1ZdrOUclN1D4XjqyFO7mpQniE8GBAF
         s6GwhlwqWaOasD/akQXOzsGq/Mx8ySzSrV+y6PYgH9p1tyF890LNNxihYeW7lrypnQ2T
         SeLPPGP2Q0JQWgGsmXlZidGth6clcDRNWoqdN4Xkx8R+ldncihrm2M0AoyHBaSSDtsL4
         Dg/+8Z1sk3Dpf0GvQmF9q5VaqrVtVnh5WHhZVWAa2HFHQJ4AFztVn+9NGIZZR3YFkNbm
         PFnyA5ppHFrAq5B9/hIT7tBOH9vVQSfXYVUMFTrracYdnJUzAl6jT9jEgqyrdKorzm9Q
         KpQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730798027; x=1731402827;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4O0YL3PFt+rs5sxrIFrdSE4aEuVgRz/dq25IxMXaYO0=;
        b=dr9Dy1DSabq2T2fR1s5ZQL08/vpefQ2kyo2wwA3SXjYVRORmiIxJHlHDYasyaxd6HY
         4DrT0dXiGrp7eDgGpaexYDI3UeL18oUVlhBIoCco/RH+kL/WBp/CNH2V89Wg2ihe2yRd
         t1/pfa73qelfjtbx1XFLDXQS8VIWB8XHiDrkE3c59FuuKDJa1xQ0WrM4NNcWtKzP2YIj
         znvAv9h1QfJBxjPprIdrewxMMTBPuRqygwUCNiXsttJpeJL/U39RpLhMB5AAsNWmDyVd
         QBgn7xT0eYorjh8KSZZOcxlBS11msfL0iePYZSafCl+sqhL/NbDVUa/hS67vvkT2Ceek
         yv3w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCULvtKei5DWKIsYip5YxjgiZ3oIoUzpKBm/K6AtNfhXTSVdd6WLA/YmxSXkXOogBxaMTF/X9A==@lfdr.de
X-Gm-Message-State: AOJu0YzvqjAdQx7gyxCycXQ4divc/GRfHbPMutJB0Py8obJH3JBk4gtH
	PKH1PVMBxbHvbPNr8pepPKGySPgNcYXF8taXy39ww6hFbQYDMMzE
X-Google-Smtp-Source: AGHT+IG+ip/zQDRL0QYxrc7ltlwsAdLWs11GyIOUwS+W2e/lOixYuMwY64663ZLjViyYL8Lk9X1++A==
X-Received: by 2002:a05:600c:a07:b0:431:4b88:d407 with SMTP id 5b1f17b1804b1-432868a5b83mr145637455e9.5.1730798027157;
        Tue, 05 Nov 2024 01:13:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4fc3:b0:42c:af5b:fac1 with SMTP id
 5b1f17b1804b1-4327b808c5bls13998935e9.1.-pod-prod-05-eu; Tue, 05 Nov 2024
 01:13:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXz+7KICRBARJJ72E/QbSDErZtQk2S6GHgwAx8CMHWsWyD6b28L05mYvH3B2VdXVcu9i8sHveOnqJE=@googlegroups.com
X-Received: by 2002:a05:600c:3b22:b0:42c:a387:6a6f with SMTP id 5b1f17b1804b1-4328325638emr152957575e9.20.1730798024658;
        Tue, 05 Nov 2024 01:13:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730798024; cv=none;
        d=google.com; s=arc-20240605;
        b=EiDUKU63/sT6IkhEqNXLAYnVzrw4fnuPusXIuqkTLcE9RffiGpxkr1WY2gpT6zp1e+
         lnXkP+G1YqiOvjcHgsJwlHk+xH+37ieHaJ0kjt9kxQ5zuSx28Fw7iDpOPMBCSnvV85uy
         7BNaB6eKaOdd5guTXPbH+GAcOTRKkPG6EKZpB28JtQsR2WbpAeazobLMNsSx9Gj9CBRg
         7TXQt5+qvq2kRXwJXLzbK59wCnrwQRgE25tOlYhMtt/4bmLlCQ7XReiqibFP5VUC1B/R
         JfuRtJq4AKR5LVRUGNuK6n8htaasm9y4E6CCteamx8wBxY9fqvYtEXy9Mfifu/kjlPOY
         /pBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=VM47Ewpc3p9HPFEpEOl521sbhCukpieT/LlFQiMY2IU=;
        fh=q22nnqEYxLaZ5p13IaefHl8mMeMIQGs3udPudinbBQ4=;
        b=M2idZ0zMsw9eE5h27rm+GhyXHKuCAF3peJw9LTvrazqM96yC4XUiy8ZULuQCwUHMA0
         Rb0+lgse2f9U32L79V9iGf9tQAyiWEnn72W7GFW5k/Ro0rHCp/iZvN2SbjFfjhLXtWGk
         DZTnfuDXS73HCQf311GNDW9H1AlW8Zip4XS3wae5PYPW9AE6LfHfCjR7CefXNu7IFePU
         AXZ8e/n2GdM2gk4DGf6LZ5oUwCDoygvowPfosZTRAiKFARBZ9qM2YZaD6+25GujonfLr
         sHAMZrUJnCfbTXzY3ZznWzXFmkhJW2SEhVpmSsQHFd96we6q7AQxGX2C0ZlI+We2tpVk
         IX6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=j6wavOpN;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432a368745esi440485e9.1.2024.11.05.01.13.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Nov 2024 01:13:44 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1t8Fd9-00000002L2H-09J7;
	Tue, 05 Nov 2024 09:13:43 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id D3FF930083E; Tue,  5 Nov 2024 10:13:42 +0100 (CET)
Date: Tue, 5 Nov 2024 10:13:42 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 5/5] kcsan, seqlock: Fix incorrect assumption in
 read_seqbegin()
Message-ID: <20241105091342.GA9767@noisy.programming.kicks-ass.net>
References: <20241104161910.780003-1-elver@google.com>
 <20241104161910.780003-6-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241104161910.780003-6-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=j6wavOpN;
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

On Mon, Nov 04, 2024 at 04:43:09PM +0100, Marco Elver wrote:
> During testing of the preceding changes, I noticed that in some cases,
> current->kcsan_ctx.in_flat_atomic remained true until task exit. This is
> obviously wrong, because _all_ accesses for the given task will be
> treated as atomic, resulting in false negatives i.e. missed data races.
> 
> Debugging led to fs/dcache.c, where we can see this usage of seqlock:
> 
> 	struct dentry *d_lookup(const struct dentry *parent, const struct qstr *name)
> 	{
> 		struct dentry *dentry;
> 		unsigned seq;
> 
> 		do {
> 			seq = read_seqbegin(&rename_lock);
> 			dentry = __d_lookup(parent, name);
> 			if (dentry)
> 				break;
> 		} while (read_seqretry(&rename_lock, seq));
> 	[...]
> 
> As can be seen, read_seqretry() is never called if dentry != NULL;
> consequently, current->kcsan_ctx.in_flat_atomic will never be reset to
> false by read_seqretry().
> 
> Give up on the wrong assumption of "assume closing read_seqretry()", and
> rely on the already-present annotations in read_seqcount_begin/retry().
> 
> Fixes: 88ecd153be95 ("seqlock, kcsan: Add annotations for KCSAN")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * New patch.
> ---
>  include/linux/seqlock.h | 12 +-----------
>  1 file changed, 1 insertion(+), 11 deletions(-)
> 
> diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
> index 45eee0e5dca0..5298765d6ca4 100644
> --- a/include/linux/seqlock.h
> +++ b/include/linux/seqlock.h
> @@ -810,11 +810,7 @@ static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
>   */
>  static inline unsigned read_seqbegin(const seqlock_t *sl)
>  {
> -	unsigned ret = read_seqcount_begin(&sl->seqcount);
> -
> -	kcsan_atomic_next(0);  /* non-raw usage, assume closing read_seqretry() */
> -	kcsan_flat_atomic_begin();
> -	return ret;
> +	return read_seqcount_begin(&sl->seqcount);
>  }
>  
>  /**
> @@ -830,12 +826,6 @@ static inline unsigned read_seqbegin(const seqlock_t *sl)
>   */
>  static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
>  {
> -	/*
> -	 * Assume not nested: read_seqretry() may be called multiple times when
> -	 * completing read critical section.
> -	 */
> -	kcsan_flat_atomic_end();
> -
>  	return read_seqcount_retry(&sl->seqcount, start);
>  }

OK, so this takes us back to kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX)
and kcsan_atomic_next(0).

Which I suppose is safe, except it doesn't nest properly.

Anyway, these all look really nice, let me go queue them up.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241105091342.GA9767%40noisy.programming.kicks-ass.net.
