Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VD6XFAMGQEY5MP6OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B40CCFA0CC
	for <lists+kasan-dev@lfdr.de>; Tue, 06 Jan 2026 19:18:40 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-3e82af7316bsf2191881fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Jan 2026 10:18:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767723519; cv=pass;
        d=google.com; s=arc-20240605;
        b=da5GcALDNQucc8uTbk617gkUzJYRpiU8SyjfwIEfdfn+z+XKWJLefTpqu72iTxrVW2
         J4wBBcxE2AwPSJlt7DyxQ8PRN8910bWAYLq8FqUnmx9GZSSJ19rpy4DdbYvsQFhVi5ks
         rujutbRh+C+Jck30bFOBnf/WEx9bmfeLG4th+M879rPjXPXwMQIS0dHPVa2SKvVq3ate
         EMQaAoQqsyvgyK3M3ZcUY4s9VTvBIFQckxh7yj1pRMv/HTkMYHhc0Z0kRJte2OZnGqnt
         FdOwoeDVG6HeqlQkHE3C2CgiqVmriAJtml8b+h89U5teSHcXlnnLIll1nCB+vwahu1CS
         QMmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=NfwF5nBDxYcpL1LeC9SsiaJHawQ5x31vHKar7W7KfzE=;
        fh=M0RNbxo0j3hDBBBtrjwLDn6T2m9eFDwhBzgt5aqrlbI=;
        b=ciQEJ7xewHoOCSWhnoHEoq0vMCPnVjzn6synkBuCVwuiplHCiOlA1+DcqIGCT3lm5I
         wXzdCaMTDrS6+AVy9ZnBL4vbs103V3Wy7YHK5bWsP7dkowj24+FX3IwHQ+bLcM3na4dv
         OHmL40odATF07KhbqV0jINtoGqt3Pn9BMGXUJ6TQnjNGjqZun69jfKyZGIzKEIZaPmUO
         mCyg8xEWaflVYoJYv1PxDB0RlxLM4+gmWcHENZDVuo3RpSxTMWGkEWrY/d8TueHjtzDJ
         UjoJ1DOi5zZqarCwwaYLs7L8Z0AOATdS2Au+jHyb9k9eKoyQt1bQ2+8eU5wN9tIhnOEi
         b6ZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tzz8m5do;
       spf=pass (google.com: domain of srs0=tqzs=7l=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=tQzs=7L=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767723519; x=1768328319; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NfwF5nBDxYcpL1LeC9SsiaJHawQ5x31vHKar7W7KfzE=;
        b=DjeRtqQubfPnpR7HGguHCH3jQhLxHHvRO3z4uV3nYQ1YXWdPdZp3WLphcN5XZhB7XC
         jBcO05AJ6HGEdjNad2UXikwQ4AVhVzSmVQ4CWJL6SiDca8DAMhpwBBQ4xfzW00ks0LF9
         fiiiRDKrY6j+FfW+j4bPbY7Q3yvxxK5w0/3YhPpOsxyn2YmZ9sk/VEuqwWljHBn4chP8
         cXyZGgTo1vq2gwmzLGZxCtw7XM7Wt2P8QLTk2T7eihe+h7sz7NbpgVO3A6P1+PcAXv+b
         +ADOEsobVEpgK9Wf/5thQtDwHLUde7uNtgVOS+wd5v9U3YztNEj6kCPw2IeSFXib1oX4
         Voow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767723519; x=1768328319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NfwF5nBDxYcpL1LeC9SsiaJHawQ5x31vHKar7W7KfzE=;
        b=Kr665PXUmf5mORI0URcKLLnmzgmoxW6DZ96u9MaN9RFgIYaivYF4iKhgTU3Yd3uMZ8
         FOBHNFbgNBI/SLsGINmaQQRNmG6hXEkbolcflellU0AHCjpzqY8ltr5cvW6qv1c1jy+i
         kZ40CRxLf2Ckhd/vHid8jUTYpOeBrj0gYTmm07UAd2n+l6SblXGpxgR4mpQHQtgWp0gk
         iq/NP8aAGJ7SjWcoz0YfsRZHHHkYeI1Y5EqUceOoPNF3GAKZspaMKOVuIHejoAEEbYHZ
         dQGwDkyvQ/EUxhBLL2CRXviWY8GABTDNLIObEphc6teLG/+cJpaTHR+xtuaSjxJb48QN
         YW8w==
X-Forwarded-Encrypted: i=2; AJvYcCVYEyFhLemciM1eBobvCnzggCdclLEzx01FMSrD0LiTf+EAvJBH9OJfQIvmwEm8/RCVKZkpQw==@lfdr.de
X-Gm-Message-State: AOJu0YxYZsPL6hpRgvNexpbwnysYlwzYVZSHQOXsTYMiS2INj+qVk62G
	SDYjQxUS5j5JImk682BMZn4vMCf9iVGlDJVad1sswGwPC5rV7WA/mBcc
X-Google-Smtp-Source: AGHT+IFciaHuTgGEwpEiEvnLOC0b25anc7A+pqRB+lhfZsBaEMB6Wva+SLCGKaRqM1uajvr6BgY/Fw==
X-Received: by 2002:a05:6820:807:b0:659:9a49:8f13 with SMTP id 006d021491bc7-65f47a14e2emr2029588eaf.36.1767723518736;
        Tue, 06 Jan 2026 10:18:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYzKtJ2AIwY4U3twBgrsi/C8aEFJUB5SWBYmk9ApHiUag=="
Received: by 2002:a4a:d113:0:b0:656:d601:dbcd with SMTP id 006d021491bc7-65f47308d21ls538785eaf.0.-pod-prod-07-us;
 Tue, 06 Jan 2026 10:18:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV+8ROwDSODIhSngKDfO6+GH7z8m/gGdkZooNtZ9wXdqz2jL3obSkmMAFqmMgqbRWV9onkqs2/6CeQ=@googlegroups.com
X-Received: by 2002:a05:6830:4109:b0:7ca:c897:fc5c with SMTP id 46e09a7af769-7ce50a29fd5mr40500a34.20.1767723517621;
        Tue, 06 Jan 2026 10:18:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767723517; cv=none;
        d=google.com; s=arc-20240605;
        b=aY808gFH6WBBuwFacXPzXs8HYTtnfGkyEQnwYEXLGnlTkseubtAOoZ609ycECg2WtX
         kL4cHQJp6zMASVOURA8ha4EB2BTbEoyam9k8cdRkbWfMlr42WDWJ/mS/BMhHkQhZTTGq
         zg/enAnH1DMqOZnNyOdQTLgcK7hYJ61Z1TFhrZjtm2UynVsBfDYbGXxPZvx0/MhyZygn
         lR7RyBYUCUOj+/sqWRxmtlmX6r/OOfXOYO2QngQSqj9w6xFD9S+z3XWM9EC3tWxbU3c5
         lbQZt+CBoWmoohsgKdzuZwLbGURApvUBgmyZsXuyV4NNdr4XN00uokXCwchXH8ONlbf6
         LlQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=W7MtjLRkxuXa/oxgkoHv/9IRUda5kTR8D5KCIwmfrHA=;
        fh=M91/4o6ZDmglamdio9PadT+TMBvC/sSSP6UJGcNQcHI=;
        b=K558dJFJXw0wmj2sZu8Z1O3s5xPZvaJ6ZALIGKdUA6v+5he4U9k1nUhmjLhii6+gI6
         NrkCc0R8qrHaqJqBvUwj/Jxcl4yM7iz7H/tX21Ji201NaCppLR3Qm/s53mXkIat1yzMo
         w9vkKPOHrLsQTET7c07qNdse/R31xShQ/ehMXPJ9ZuSn8j4DqnqBsx8YWq3B/a8AY+sx
         jWOWbF2xZgvFXU2lz6PGZSskvk2+PUo8g46sBWiCRpN+11fNcD2CnzTPnDiDAit3CTCu
         bqzIByMVstRJliae8ryptL9G0S0yjSaNhdfevUtybqkyRVeHgM0CJNCmT3muSlKWKcS0
         PrtA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tzz8m5do;
       spf=pass (google.com: domain of srs0=tqzs=7l=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=tQzs=7L=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7ce481d629esi203506a34.3.2026.01.06.10.18.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Jan 2026 10:18:37 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=tqzs=7l=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id C7D3F60007;
	Tue,  6 Jan 2026 18:18:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 74CC6C116C6;
	Tue,  6 Jan 2026 18:18:36 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id D8D24CE0F95; Tue,  6 Jan 2026 10:18:35 -0800 (PST)
Date: Tue, 6 Jan 2026 10:18:35 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <7fa2c07e-acf9-4f9a-b056-4d4254ea61e5@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20251231-rwonce-v1-0-702a10b85278@google.com>
 <20251231151216.23446b64.gary@garyguo.net>
 <aVXFk0L-FegoVJpC@google.com>
 <OFUIwAYmy6idQxDq-A3A_s2zDlhfKE9JmkSgcK40K8okU1OE_noL1rN6nUZD03AX6ixo4Xgfhi5C4XLl5RJlfA==@protonmail.internalid>
 <aVXKP8vQ6uAxtazT@tardis-2.local>
 <87fr8ij4le.fsf@t14s.mail-host-address-is-not-set>
 <aV0JkZdrZn97-d7d@tardis-2.local>
 <20260106145622.GB3707837@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260106145622.GB3707837@noisy.programming.kicks-ass.net>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tzz8m5do;       spf=pass
 (google.com: domain of srs0=tqzs=7l=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender)
 smtp.mailfrom="SRS0=tQzs=7L=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Tue, Jan 06, 2026 at 03:56:22PM +0100, Peter Zijlstra wrote:
> On Tue, Jan 06, 2026 at 09:09:37PM +0800, Boqun Feng wrote:
> 
> > Some C code believes a plain write to a properly aligned location is
> > atomic (see KCSAN_ASSUME_PLAIN_WRITES_ATOMIC, and no, this doesn't mean
> > it's recommended to assume such), and I guess that's the case for
> > hrtimer, if it's not much a trouble you can replace the plain write with
> > WRITE_ONCE() on C side ;-)
> 
> GCC used to provide this guarantee, some of the older code was written
> on that. GCC no longer provides that guarantee (there are known cases
> where it breaks and all that) and newer code should not rely on this.
> 
> All such places *SHOULD* be updated to use READ_ONCE/WRITE_ONCE.

Agreed!

In that vein, any objections to the patch shown below?

							Thanx, Paul

------------------------------------------------------------------------

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 4ce4b0c0109cb..e827e24ab5d42 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -199,7 +199,7 @@ config KCSAN_WEAK_MEMORY
 
 config KCSAN_REPORT_VALUE_CHANGE_ONLY
 	bool "Only report races where watcher observed a data value change"
-	default y
+	default n
 	depends on !KCSAN_STRICT
 	help
 	  If enabled and a conflicting write is observed via a watchpoint, but
@@ -208,7 +208,7 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
 
 config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
 	bool "Assume that plain aligned writes up to word size are atomic"
-	default y
+	default n
 	depends on !KCSAN_STRICT
 	help
 	  Assume that plain aligned writes up to word size are atomic by

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7fa2c07e-acf9-4f9a-b056-4d4254ea61e5%40paulmck-laptop.
