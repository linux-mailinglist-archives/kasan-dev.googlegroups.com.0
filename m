Return-Path: <kasan-dev+bncBDBK55H2UQKRBMFZ7DFAMGQEOO7BJGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id E9A0CCFCA78
	for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 09:43:29 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-477563e531csf11450005e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 00:43:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767775409; cv=pass;
        d=google.com; s=arc-20240605;
        b=cvo7AqJyKuaA0nfpSHd5dGFEWmOXuMeIXNrRI7tLwgsxkAZX6gwzyvKRkne9psdXp2
         EMMwYC8t0yhZKgeyVJbZwdSd5TzAv9FapDZU8SpR++PoV1I6O/cbF3AsKQRPxE3IyvyF
         V/mTkA8VR79hIRLA4Iy/G5Q6rFYwCB7Fm3CMA0HxubGCj2loa5xXTz53Vboi790qtCJY
         fPHpkY2P4MDZpzdFD5A1Yk2ykjqqhGUeohUJRRHqArFr8Dbv7dOFoVaypZCFk7jClI/y
         AC1fJjjOH732tAIxQ4zUua8lzGeCUoJw2vuAGnFwuj6Ofn0IpGZNn9l/Y2Owp1zdJRHd
         Tctg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5+p3KyYH9ejbgg80FKcCgIVxHlosXFqlsvJoenzPluo=;
        fh=mouWyuSJTYxVmyR1RaE4lBxIztOnHc2iVCdAABxQLuE=;
        b=M61PpfAVspZDiHZyQ7jq6QLjDpR2PtNJVgH13cJ1945MnIlGXsNgBCo1lPnTpDJLor
         pKcbzjDBZhGQN8zlxBiQpWIUOTg/rzorNIfSYg1tkHNkqZGBsdafX7nf41xkNi70kJ3U
         NjgQ0D6X7P3UqPbc58FXsuTYtRvPDA12PILHs37xAcTwwu3jNf8EeZHMMVEJDdMJgDBj
         H2C86MYmVq6XkZarz0tPIkWLysNPCw8VEApL2gyMuOk4cXpjtkvUXwdwGfYe0dWtcmeb
         YByfmx3FEvcGXc3uAI7OrLBzBAYTooQFuVeg52WB1+KKll99PpetN3zcDFGdMFpc4sEw
         /iQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=fTZpoVpt;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767775409; x=1768380209; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5+p3KyYH9ejbgg80FKcCgIVxHlosXFqlsvJoenzPluo=;
        b=EDKA1gETr3flOgCpxKU5DTyK0zkIiAoxxiVUgGocUMABmnXO25Ihh+Uk1GbVqB1TQG
         J1uZ0gPHsJzoxTznh8LXrvpBfw8J+1Tq/b5XYYmLbel7OUgZFnwF8/AuOBAyfIbMnjKK
         DgRUuoL4K21CRTaNP6g2Z6prXciYnzzk1vEBgVqDpiZqyj+ZwnVCJd4ohhYI1Z13dySV
         1GBY2+h1Tbf0khXkASlxtxwZgWYqFSIhl4WiliEDHls26noFxvaFJO096lqVvisy7oqr
         wbFf9hIY8K4AHp0BBxQN/91J8mPLLJg/NUVYzDTapzclEhblqoWGJTCBWbos7V9mtdWq
         1EHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767775409; x=1768380209;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5+p3KyYH9ejbgg80FKcCgIVxHlosXFqlsvJoenzPluo=;
        b=ZJCI3MUTov4NQNS1oUcEkSej1JOc2vgcPXw2R/0xjhKNKMU4SrF4UXrbEyZ/RBrAup
         2siiJ7geUcPFInu0yx8oZu6MD1U7dkjh4/QBMo/9jz9besmRZeCleceQih/pl3cJ63oB
         vJkzIcnpH7/ETPNNhPP7emaoXX1dgdvYQM4vbEHpUt9c7NhRJj5oNJfIV2HK+Sm4LhG1
         o7ytxsgNm36zQawCyLhWGsthkIsGgnWwl+MBZvdGl716BeUufiORV3xYB0EDFGMDYjWp
         ouu4yCr2S6UB8xk5Crs+7pgsIc+4C9RJWI8AvqeklYHxlt5y8Voh1BM2na8V6wN0Lbfc
         JMcA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXix1mohcDJJIGsg8lx5b+w/Rw1dIxoSoUYKilk4y1bkLQB/ZD1x4ZWlKitSYc6qfmDU0f3cA==@lfdr.de
X-Gm-Message-State: AOJu0YxPmw31LBQpANXTv5TAnCX0Sg4B8EfhH0Qa3Ce1rTPUWJ4l0HxV
	TClXhu/f/D1NCrdBrwELM0HhkZ28wolO/FbGc8aBgxyeZKvV5We6Lk84
X-Google-Smtp-Source: AGHT+IFxsmaVQVqaFD137U/3lvNOK/Pgu4WDb3+DXx2ZV6cEl8VHVsw/+nacNuToJNrgr3O/GwkzcA==
X-Received: by 2002:a05:600c:6287:b0:475:dcbb:7903 with SMTP id 5b1f17b1804b1-47d84b17b7cmr16189065e9.9.1767775409161;
        Wed, 07 Jan 2026 00:43:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb3Slepisa1JiRhWE/tXUCdI7PWjdyO56R2CaSpEDbY2A=="
Received: by 2002:a05:6000:2c0b:b0:432:84f4:e9e3 with SMTP id
 ffacd0b85a97d-432bc91e6c2ls1033396f8f.1.-pod-prod-06-eu; Wed, 07 Jan 2026
 00:43:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV0/RP36zZb1AqgGm3p4Pj1nHQLYeDKimi1YiRM8jbsOZY40X5tncFwI2BPQX3SxYlR0mtym1gKw1I=@googlegroups.com
X-Received: by 2002:a05:6000:1843:b0:432:851d:23e2 with SMTP id ffacd0b85a97d-432c37616b7mr2033396f8f.49.1767775406559;
        Wed, 07 Jan 2026 00:43:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767775406; cv=none;
        d=google.com; s=arc-20240605;
        b=QGSyfouYz2E8aGhjMgkqIUaDCRzVKwxtQLlx81yCxhzu3TvvgEZ5F70HXyEzu7Jmor
         fy59tZGeokUfzhLJVUUVJJ4KEGNhrCbSLzbPEc0HtmFuKsivmYWOf6wesaRHvStXRoc6
         sPsDlhNiK+ObxxrBotUajkANKX9LbBPFboOnVuCM5Nc9VoVnSgUM93SBhe1olMm+iXgd
         Ibqr0MH5uyQPt+EnNXGnSEuxuUyCZ6qc+FQ3nWCkr2HQPybrQUpCjCIyWcM63R0aK2Ki
         PNuyzCxLnF3wUSCZmQzpai4FMHWr6KGza0AXy9eMmfDA2Gy9KYB7D6VeU2ujBHzGwlrl
         YKng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UybR8h6LJ7X/dgWxJlHGwPKuKCGXzpl1N/omiIktehk=;
        fh=yQB06ROPERhWb6RtNBkuAGhmdbpRSTcAyXmein7pyjs=;
        b=FSNb3IQe1qEctD1euVyKnBkoFR0bpTaBevxzN4vg5wiRgiugtN4spwyDBw9i+Q9SdQ
         9fkWTHzAWk+3mB19pj0LfKNQYhcLRP5FJCRlMv6vXye3vSU6hQ8AaZuFxDjUzA/v7wH5
         0g1LYyvVUxU8K4Dxd7E5sSJZE/r3tFCCiUOMfopRSRLWUJ6QjzsBriYKBWdgT2Wo7Bph
         8inYnJsgs1Mdh/0smagLKKxp9RlGTL+FLtEhFaXCnBWAWFBDMs4arUs6yzGXQZJQetlk
         vXIkJPtwL2bidFJWlrAwY8F0ihgSRP2Doxc3mYgpIyn/YQjWpn8CJXcXpQQeh551CwWI
         ze+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=fTZpoVpt;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432be35a16csi46901f8f.3.2026.01.07.00.43.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Jan 2026 00:43:26 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vdP8V-0000000B0RI-14Mc;
	Wed, 07 Jan 2026 08:43:23 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 29E43300329; Wed, 07 Jan 2026 09:43:22 +0100 (CET)
Date: Wed, 7 Jan 2026 09:43:22 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Boqun Feng <boqun.feng@gmail.com>,
	Andreas Hindborg <a.hindborg@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>, Gary Guo <gary@garyguo.net>,
	Will Deacon <will@kernel.org>,
	Richard Henderson <richard.henderson@linaro.org>,
	Matt Turner <mattst88@gmail.com>,
	Magnus Lindholm <linmag7@gmail.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	=?iso-8859-1?Q?Bj=F6rn?= Roy Baron <bjorn3_gh@protonmail.com>,
	Benno Lossin <lossin@kernel.org>, Trevor Gross <tmgross@umich.edu>,
	Danilo Krummrich <dakr@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	FUJITA Tomonori <fujita.tomonori@gmail.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Lyude Paul <lyude@redhat.com>, Thomas Gleixner <tglx@linutronix.de>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>,
	John Stultz <jstultz@google.com>, Stephen Boyd <sboyd@kernel.org>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	linux-kernel@vger.kernel.org, linux-alpha@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	rust-for-linux@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 0/5] Add READ_ONCE and WRITE_ONCE to Rust
Message-ID: <20260107084322.GC272712@noisy.programming.kicks-ass.net>
References: <20251231-rwonce-v1-0-702a10b85278@google.com>
 <20251231151216.23446b64.gary@garyguo.net>
 <aVXFk0L-FegoVJpC@google.com>
 <OFUIwAYmy6idQxDq-A3A_s2zDlhfKE9JmkSgcK40K8okU1OE_noL1rN6nUZD03AX6ixo4Xgfhi5C4XLl5RJlfA==@protonmail.internalid>
 <aVXKP8vQ6uAxtazT@tardis-2.local>
 <87fr8ij4le.fsf@t14s.mail-host-address-is-not-set>
 <aV0JkZdrZn97-d7d@tardis-2.local>
 <20260106145622.GB3707837@noisy.programming.kicks-ass.net>
 <7fa2c07e-acf9-4f9a-b056-4d4254ea61e5@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7fa2c07e-acf9-4f9a-b056-4d4254ea61e5@paulmck-laptop>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=fTZpoVpt;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Tue, Jan 06, 2026 at 10:18:35AM -0800, Paul E. McKenney wrote:
> On Tue, Jan 06, 2026 at 03:56:22PM +0100, Peter Zijlstra wrote:
> > On Tue, Jan 06, 2026 at 09:09:37PM +0800, Boqun Feng wrote:
> > 
> > > Some C code believes a plain write to a properly aligned location is
> > > atomic (see KCSAN_ASSUME_PLAIN_WRITES_ATOMIC, and no, this doesn't mean
> > > it's recommended to assume such), and I guess that's the case for
> > > hrtimer, if it's not much a trouble you can replace the plain write with
> > > WRITE_ONCE() on C side ;-)
> > 
> > GCC used to provide this guarantee, some of the older code was written
> > on that. GCC no longer provides that guarantee (there are known cases
> > where it breaks and all that) and newer code should not rely on this.
> > 
> > All such places *SHOULD* be updated to use READ_ONCE/WRITE_ONCE.
> 
> Agreed!
> 
> In that vein, any objections to the patch shown below?

Not really; although it would of course be nice if that were accompanied
with a pile of cleanup patches taking out the worst offenders or
somesuch ;-)

> ------------------------------------------------------------------------
> 
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 4ce4b0c0109cb..e827e24ab5d42 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -199,7 +199,7 @@ config KCSAN_WEAK_MEMORY
>  
>  config KCSAN_REPORT_VALUE_CHANGE_ONLY
>  	bool "Only report races where watcher observed a data value change"
> -	default y
> +	default n
>  	depends on !KCSAN_STRICT
>  	help
>  	  If enabled and a conflicting write is observed via a watchpoint, but
> @@ -208,7 +208,7 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
>  
>  config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
>  	bool "Assume that plain aligned writes up to word size are atomic"
> -	default y
> +	default n
>  	depends on !KCSAN_STRICT
>  	help
>  	  Assume that plain aligned writes up to word size are atomic by

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260107084322.GC272712%40noisy.programming.kicks-ass.net.
