Return-Path: <kasan-dev+bncBDBK55H2UQKRB7UJS66QMGQEDRQOSVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id F3F05A2BDF0
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2025 09:32:38 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-307df2167d9sf7010581fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2025 00:32:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738917120; cv=pass;
        d=google.com; s=arc-20240605;
        b=HPBsvr/eawBAxSp4IFkImolgCrxjny9x+wp1pIu55sn69G3yi6qZHn1JPSjIxX18l1
         /tk05fUBcNbFuhr1hrQ95GwV5apqbmsG2cT9uQs4xyVP/D/4AqCUMf0m/Y6M/R91/yTg
         2XsDf9Bwu51uH7nFo+7ST2lXrMM/0di7ZhCzcfx+MlN9JfSCMlp9HpbZ1M49QbsKmTFf
         9A04zEQO/ZNnGYCv7c9OjDypVe6k3TNETp/7Ip77MWAyfdqSRf6uErR5b6g6hb8xxjah
         jjLla/RvBVmQYQvngWnyzo6NNUAQnF+rpZwCutArrXWuDWHvKwZeV5iwMd7U03bSBhsu
         QYaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=z0xA3FywJ+PCouH3Ml6++bTLjyAoQkKslr/VVCE4s+o=;
        fh=dMfuBGRF3hyiV5iR2Ibkv1g75VTKuk/e0k8dqVBAkGI=;
        b=JJJW7oi0um1VRgswNi+4lMGl+JFncPIkx5vqY6uSk5C2SSnBd40mkMVObSvjRM3pZI
         Dw4Rvvyw5UTl1n4Bi6UpC2e99YQmr1Ge1mmBwHDgfxtWRmLR+TB46bT0huz3Z/bfKJhT
         /AlQkWSwKqXxdTuDtqZORlK+9cWEcCw7pZwZoM4k0xaSVlv1oivvZF6FohxcEmCAZivn
         kwIcoC5EuqhKhAvVJ/bCRBzi4kdbvD1SLOo3lu7Jvzwe93sBhLkXspRbMO4UODyIYnRI
         jwOSMPbGAJtO/dGk4Mubxa5Bh/yKfhx7LEwhrZcfWTzJOBNwQ+x7xDN/KwifiHHihHxx
         iQzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="n1aF/WV1";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738917120; x=1739521920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z0xA3FywJ+PCouH3Ml6++bTLjyAoQkKslr/VVCE4s+o=;
        b=peKQVCp1xa7I5bSLuueR7n8eUYgmpWhvQiI3Pmv9jthQGT1/rZhYVl2VYuohvEwsJZ
         AFFYfdkgwqTmjrcQ0x2iQ3RZs638wyvRI28k736YF05D/b2xpfEGZvdqcIkkVjNc9aZN
         jYzgBDOIaJ/r8eqthDXAN48SmcAGA7oSbg35lrdwnT1qf17j3zB/lkD4HCTbeJbse2hR
         XsZW1pTO9PY8NkqeFVjl45X4w0tEJhrlcOKEiEvc63gnkZLLp6CvftrHZnJDimMmJowl
         YiJeGW/2a6MS4CzbVUWV2ZMrDBuMBAWcQ0jee5f/u9xa58FKEDz1zOj9c1MAYK1IL3e1
         lAsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738917120; x=1739521920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z0xA3FywJ+PCouH3Ml6++bTLjyAoQkKslr/VVCE4s+o=;
        b=GbBFF8pykvWIWswwNsU7IKx0CddrCJJWr0vkjEN7mYJrKrXRzfDhzmAbW+R7XOgHam
         tkJP2JxlWmDuotnhV86fjxDTn7ATm9XC3dzg4gnkPFcgAbcY/uhYWeGL3IUUECjvA9nj
         mUHo5ivYDXFy+hfa1ishQKTuGMLY1iPIXRzE7sMXUqmy4TheZyRyjrzvj7QDYlySS5+o
         FkNzx4hYKR9LIv9ASiSOHpt/laou1zmfrqXS2r+I8cceHQuqiZfd1hH+ulGnlCyiRVGg
         GBUyiq5WULO8EqWaEL3AJu2AnKeDz+IlWUD7qUbq7ojWtZUbbi/iQjoMfuxqZHmtHYXl
         sn/w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXPfBzM5xD3JdG4HBvXp89fqdnBaobB/feRL+eR7eu8lpVCQGuP6G+Erry5dQxrgCIMo7djOA==@lfdr.de
X-Gm-Message-State: AOJu0YxkS1/mw22U7dyeQAcxofq92RkhMy1PSB1FXSlfLnmnU9xFW5OF
	ObdBA6ArRyZvicz7e96WC0CDRh7KXyejXNrI3VA2CyA3hv+ZWEEz
X-Google-Smtp-Source: AGHT+IHWmrXuzBc4NSmJdpPSJNGH/q5VFkbi4q4Njk/KKYSO2RdlPDKQRsSCRh4Z4hLwR97uRooFvw==
X-Received: by 2002:a05:6512:b1d:b0:542:9a42:797f with SMTP id 2adb3069b0e04-54414a96232mr501519e87.1.1738917118778;
        Fri, 07 Feb 2025 00:31:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:2d57:0:b0:543:9af0:d22f with SMTP id 2adb3069b0e04-54413c7cf97ls127889e87.2.-pod-prod-08-eu;
 Fri, 07 Feb 2025 00:31:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVr0t5b7PFpOFRurPwZzh8uyRMVZrrcXHuhqnrqKFh3fPtro51z1EVLeqPlD4IQydmsNNRXw0Q0Pyc=@googlegroups.com
X-Received: by 2002:a05:6512:1195:b0:542:6d01:f55c with SMTP id 2adb3069b0e04-54414a962c4mr776225e87.3.1738917115886;
        Fri, 07 Feb 2025 00:31:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738917115; cv=none;
        d=google.com; s=arc-20240605;
        b=YqysLVKWmnOraJ9ELM2+D1/n4ipMIF0Ad5BdgGkdhXQAdb/QU+iNuhJsRk/CKid2XK
         JskfbVx5Vnp7xy18MTOFm+4kmAsvjwfKjGWHoKXdQnAOwwaG7scDJRqeI1r2SlTVBScQ
         bZpXS9S0uT4c/J6A3WcSIuDfXF6B22PMpyIhMAzsmdQkemWqcLpqJT9pCCBhXlp/sRaa
         gZ3+Intgx4ioa+PSc9LUnMl2zzBr8LSQf5xWOreSpFYXRGiD4WM2ODScl3fsRTPar/1u
         cSRYEa5U2UazHoE165+q6/ITUuPXgOvXaslmaI66Y00H/OTl6W5ZVPkSBJpUIkPNg84F
         6SRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=MToFBoTN88Sw05TH5ZS066HLD3eJYQXco+AkkB2Qigk=;
        fh=p9qVCSW3g/knQl1jy4WovKLdPkqy2lNlDCIoDQ06JPc=;
        b=FZXOsbTl2B5PXB5VeAK4ux6+S3muNrxIVsQU6Fw2h68FvJ9kAV8c9U/vMCvFmD1/Lh
         Ll8wytzGyQPrIAOce9JjBrh2QCbA+MIGzrhzPgBgq7We7pY3C0/0I2fOr+sMiI85PjK5
         9fzMyUYkg3Jq+R6K+NUT1KHtLL8wp6/DaTWANJfflGhng84wOg9rO8G7jCOsK5pZnNHt
         Y96wwCa7UPWcX4rnJH7Alk8QTtqiYFspuo3X/ZWeqCrlW3+BRdKjl12b0aXrtR9Lu2Uh
         MIvVNBFYnBFpXlb26fsfzOOu1yHTY3Y8Mp6g7KQOkqYQOL0HYsZLrl+xq08pm+ReLKNI
         QYHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="n1aF/WV1";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5441053eae5si44458e87.1.2025.02.07.00.31.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Feb 2025 00:31:55 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1tgJlg-0000000H8yt-07vH;
	Fri, 07 Feb 2025 08:31:45 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 7B47E300310; Fri,  7 Feb 2025 09:31:19 +0100 (CET)
Date: Fri, 7 Feb 2025 09:31:19 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org
Subject: Re: [PATCH RFC 11/24] locking/mutex: Support Clang's capability
 analysis
Message-ID: <20250207083119.GV7145@noisy.programming.kicks-ass.net>
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-12-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250206181711.1902989-12-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="n1aF/WV1";
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

On Thu, Feb 06, 2025 at 07:10:05PM +0100, Marco Elver wrote:

>  extern int __must_check mutex_lock_interruptible_nested(struct mutex *lock,
> +					unsigned int subclass) __cond_acquires(0, lock);
>  extern int __must_check mutex_lock_killable_nested(struct mutex *lock,
> +					unsigned int subclass) __cond_acquires(0, lock);

> +extern int __must_check mutex_lock_interruptible(struct mutex *lock) __cond_acquires(0, lock);
> +extern int __must_check mutex_lock_killable(struct mutex *lock) __cond_acquires(0, lock);

> +extern int mutex_trylock(struct mutex *lock) __cond_acquires(1, lock);

> +extern int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock) __cond_acquires(1, lock);

So this form is *MUCH* saner than what we currently have.

Can we please fix up all the existing __cond_lock() code too?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250207083119.GV7145%40noisy.programming.kicks-ass.net.
