Return-Path: <kasan-dev+bncBC6LHPWNU4DBBVFD5SZQMGQEAJWSNCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C09CE917096
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 20:52:05 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3d22af89310sf9007249b6e.3
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 11:52:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719341524; cv=pass;
        d=google.com; s=arc-20160816;
        b=NsHTZQCmAR7Z4K7VQnXRtvwLYNiQ76i7nSMwNq8VX4wUKjN2ggmZdcSgeWT9URzNSq
         NQr9739v4CZ9EoHXyC7XNow0lI2dIXZisOnCiTqYF5+9VgEpSO8exre5nl6tPQPVFT7I
         xLefi4nPy7mnXgZbRPQpRukCxJ9/hvP66PYof/oddLSCJjAUJtowG7VOktp6+yPRLx8U
         O26edsNfxIbiCGWP7mvG9OgkoyG+Le5HFAc8WjIQI+2BvLZLCoseFHDkPfadgA2f+ixE
         Q+fCwd829XWFdxgwEeVOWyx3++HRW2EiGHE8KTU83Yc9wS1ttxRs3j9ut56lSqmwfL7d
         VqVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=j50aQNZTpuOV6Ojj8fIVaTU7smLV9NuG/n0oQpLH14k=;
        fh=7QnqgYKJt/0PwAacrG14l6uu3bWYdqjWrSph7DlLVC4=;
        b=dahxHcqNHBppfv82x6lzZHP74+9O76MsAjBjqb3udisd3lHZfz/sw/I8Nt92juuAGq
         vT9Tv1lAWWLsNwTQjiTfcE99EWWvZiLa69ms44Sv2Kd2LGWWjDMbmw3AD8vt1GcuSm6Y
         818d+p/EPFaiKT1HP45axqRlBoh1zvNdArurR63Xrm+4VmvWcGwvN4cT6UcbKHzk4peX
         f53CFhC8W8BnSpklFr8sjRQjwQyG4Ln5PD/4wUhHtzN3foNmwX2/8w6Ru52OkOHP4Ghq
         uYdYnYejzac0cGaG8s+wWrXFyTohyW2S+nwOhfv+yTh69KGHcGtpGTAHaUbIhLqQ3rza
         HXUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DE9cclJl;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719341524; x=1719946324; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=j50aQNZTpuOV6Ojj8fIVaTU7smLV9NuG/n0oQpLH14k=;
        b=EmG7VKJmIYWH0u1Fg+Tb2JRFk7B/nmLkVMlffC+vyH1KJUgwDxUXGLEUawPkPfGOWQ
         J13eYS1ierVuK8qwit7VYdE7zwR3rw4kIMtTmBS+2iXtBgBhvdnCHDMbtzhAvZWJ6F3k
         NF8MVRt05+z8B9Z6sSEGE6twNVT0MC6CT1kOPTtBaNkZYKAXfeh5aGHYR23FOF3DwHjF
         0Wl5fvsNGWm0b42Uyf1UMewQGRg02QTqD0mI2XchSmOg5/NKSR8g5InioosN7ooXrh78
         D6xTZVxnoAMcPyCSdnBg+B5Wwaoofj093qhHEsM/+/SJH2X29kBMiX16DEKQHg2+HIi9
         +/Xg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1719341524; x=1719946324; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=j50aQNZTpuOV6Ojj8fIVaTU7smLV9NuG/n0oQpLH14k=;
        b=jti29vEfR0PsHzwazJg7J/D/Ba1heDGUKpvytxyUwX1PBvZb0eZDOb6TYyC+sAZkgv
         dFZp/0s5hBtMuDH9HpSl2XFa+yPhDV4VHvcUv7dCG+mIwQ2Bi6nsNqJGEdeJ3H0Pw1Xj
         dRdCHwSjGqfHDXDyHXffdS76AAcOzhf+OXPz8GX8ebomA9TLdbbCUj40+dRe7+2hkw+k
         uIE1uU82T/rLF9KKFwx+UmQdz/SoxuC35pBYOKOGEOmzczj52OiBtwQak+oI4dhbufsi
         gnyCNnugKLBg1sn4Y4ExOG8fhx21ciMseajV7IcR43Ew/VF4vtrcKR/xHYNKp2YlNJPJ
         Wdwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719341524; x=1719946324;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=j50aQNZTpuOV6Ojj8fIVaTU7smLV9NuG/n0oQpLH14k=;
        b=viCx4KEcfBA8HbIYFnbIVNZ9ZcyOxMAn8ICd6tDY3YQJw47ib3zfg/GSdNxZU27j/4
         9GvvFQ8v3U/posAPCZyBow+KyLRjgMhpul0fc762x1vTNLiifQhhQbLASHawHlX3MLiY
         WHVM1A8eFFeTrbEZl68beq6xYORcagcSRKI0qzuu7fzW3sNFqFL8XWCuQRZBT2kEBU75
         lkxfs7FPuQPYpu+ZqxGFoXyHvGl6BXQjjLPRRFiO0jzALlYPoFl+rxnl3l8XZdUGwTcW
         4ysH89Bmzuwikt+oiz61t9/AeuEph+It3OVHIvXylucg9b5gyyiK/iKXVykcw/I1vLjK
         X4MA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUJjn4NJHe/hMFngkZSF2cSg92qpUtEYAnflP4fH+ZNTkY3/x2Hj2k94/DgF1rYqqpkb2Mt90g1A+837xwN8s7uYilVyUtfwA==
X-Gm-Message-State: AOJu0Yzdlg/jAmAH0YtOPZB8BmRRR/0nVRoQzqVSl6k5TaROm5ehrDi4
	NaRtNgJC4IiJQeFSoVcrE8ycyCB/fWYTUvWmaqBso01H+IcDxRDo
X-Google-Smtp-Source: AGHT+IE5FnKYTpPhb6fZ/bEi6QWtpPXOiqBGH8UvZtlu4JRF9z225OE95BRoXTVBv0hLTOyi1CEDCQ==
X-Received: by 2002:a05:6808:2203:b0:3d5:1f50:186a with SMTP id 5614622812f47-3d545a52d3dmr10035258b6e.39.1719341524323;
        Tue, 25 Jun 2024 11:52:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:520b:0:b0:444:f8aa:d081 with SMTP id d75a77b69052e-444f8aad188ls12244261cf.0.-pod-prod-08-us;
 Tue, 25 Jun 2024 11:52:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWGC0cSzk5GKLh3hoiGse1EhoKcpBB0qrcxdxIqtm9UZIRLz99mmgNsHHw96EgckmBP4lmMIC/vxtVRmporZMeKfoIE/PIvKsrVtA==
X-Received: by 2002:a05:6102:361:b0:48f:508b:d3ec with SMTP id ada2fe7eead31-48f52946e34mr6275460137.4.1719341523510;
        Tue, 25 Jun 2024 11:52:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719341523; cv=none;
        d=google.com; s=arc-20160816;
        b=PqR4wJvkdesWxQLCan2RtL4Z3F/daIirX9fj2hu+Mv6Xc8hfHSsWHdZ03LJOoKalGI
         kYumk5T0kPACtfKzk1+pB2PE7eFjJLRXw35VJFBNXnkCpC4jEaCHSsTHcsvE4/zwgCdt
         VGelIMvn9Bg3m9K19rpyEawBNk7q7NjMQ9XnkRyanRK5ySovr1QVOPQs8ynLEBItccJb
         Q0XJomkTbuzonbEG5Im8w2zU1q2dPSaYeOvWfRronW+RMynPOnkalvFeaYSUfGkGyGA/
         F25Jn50QyQ2ji+YEk25XqTCnHKjwByGK3Q5lzfcwRZ+JeYWk8uFv+FqpKGRGwR3WoPQb
         UvTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=LMdSyT3TskY0tTwnKiqqMsQwUOsNCEG9Wo5ZTR+RF68=;
        fh=YSiFsv1UtoUUlUWay6jA6Jh6WuMlOtTMD/HTDKwraU8=;
        b=peX8If4zGIuOLnzdTX9ef0GLthzgq/4RhqKGz/TUdkw2/+h8kcAWAxrzi36eGOy/R6
         imSNvuBVNZKBctgKWMTdpXkLoVqQLMO++t1Tf+FH5++gkuEDJpfZHcZsT27btUchb+oE
         unz6Yn0KVChv/ncRLrjuyFjDYk1lu4f8OFG+d8XZ9Y1eSExdANW8H8do73rjyFpue4wA
         J1ORLS4kUt0NPOmuwLwxF6sox//wiEY+QjzgqGJPkJdIEkN2/6P2So9pW4+/JjfUwZqX
         5vq8TppaybgBrXWTtOj/HLQzdqBs/KcPyrvlSjTuUugAxlDpak6L/nKAddPHFULnaYCS
         yxQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DE9cclJl;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-48f499dd0fesi297784137.1.2024.06.25.11.52.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 11:52:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id af79cd13be357-79c0c19ff02so63246985a.1
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 11:52:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXsUk4RVMNVp+pZ+3ZwySQCIi2eszUM8PyoMRFgn1zJDDjgcXWM0WmOIX5QNW+bi2W/uv2QDbQRcPcvBFEQz1RX8GLSYl//52ZE7g==
X-Received: by 2002:a05:620a:240a:b0:79b:efe1:1221 with SMTP id af79cd13be357-79befe112f7mr863743985a.48.1719341523018;
        Tue, 25 Jun 2024 11:52:03 -0700 (PDT)
Received: from fauth2-smtp.messagingengine.com (fauth2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-79bce933e28sm430784785a.120.2024.06.25.11.52.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 11:52:01 -0700 (PDT)
Received: from compute4.internal (compute4.nyi.internal [10.202.2.44])
	by mailfauth.nyi.internal (Postfix) with ESMTP id 2D06D120006B;
	Tue, 25 Jun 2024 14:52:01 -0400 (EDT)
Received: from mailfrontend1 ([10.202.2.162])
  by compute4.internal (MEProxy); Tue, 25 Jun 2024 14:52:01 -0400
X-ME-Sender: <xms:0RF7Zi4cCwR_2FODPaE_7FeHVem8MDWqwS4NTWWmVxWyBvw1QAVWAA>
    <xme:0RF7Zr5vato65g-qckf9tV0sTMuzk97uUQ61jKPH1liKzEIHrtahAYFkY8tvCn5CI
    mQI2H7yHO-VkQBs1Q>
X-ME-Received: <xmr:0RF7ZhegPl7nkM2qRWPjNQoDHlGfw1gBwBU8WlbnEQ48Rp6uHs-QFzpbtg8HYw>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeftddrtddtgdelkecutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpeffhffvvefukfhfgggtuggjsehttdertddttddvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuggftrfgrth
    htvghrnhephedugfduffffteeutddvheeuveelvdfhleelieevtdeguefhgeeuveeiudff
    iedvnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomhepsg
    hoqhhunhdomhgvshhmthhprghuthhhphgvrhhsohhnrghlihhthidqieelvdeghedtieeg
    qddujeejkeehheehvddqsghoqhhunhdrfhgvnhhgpeepghhmrghilhdrtghomhesfhhigi
    hmvgdrnhgrmhgv
X-ME-Proxy: <xmx:0RF7ZvI_ljCVI6m0sZT4hN8n0VmMOvU2Q_ix2HcmJkITQN5YisVFrw>
    <xmx:0RF7ZmJqyLhitldL8C2O3d2yp5fmTEqQLPO9Io6X6Zc2e3Ih3YhAZg>
    <xmx:0RF7Zgz0J0wvDHQqeZ1547t6VZvKf1jD-Dm_g7zjufymrDnvZq5Rgg>
    <xmx:0RF7ZqJC8ydfOY3LVrFGwtlZfl-V6weIVhH_SS-H5eAT8OhxPwGUbQ>
    <xmx:0RF7Zta3eYLagYLdZx9_jAjELamV3pyR5pvr2KwBtCCCBB6LVDMvumxl>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Tue,
 25 Jun 2024 14:52:00 -0400 (EDT)
Date: Tue, 25 Jun 2024 11:51:23 -0700
From: Boqun Feng <boqun.feng@gmail.com>
To: Dave Hansen <dave.hansen@intel.com>
Cc: Alexander Potapenko <glider@google.com>, elver@google.com,
	dvyukov@google.com, dave.hansen@linux.intel.com,
	peterz@infradead.org, akpm@linux-foundation.org, x86@kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>,
	"Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH 2/3] lib/Kconfig.debug: disable LOCK_DEBUGGING_SUPPORT
 under KMSAN
Message-ID: <ZnsRq7RNLMnZsr6S@boqun-archlinux>
References: <20240621094901.1360454-1-glider@google.com>
 <20240621094901.1360454-2-glider@google.com>
 <5a38bded-9723-4811-83b5-14e2312ee75d@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5a38bded-9723-4811-83b5-14e2312ee75d@intel.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DE9cclJl;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72e
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Jun 21, 2024 at 09:23:25AM -0700, Dave Hansen wrote:
> On 6/21/24 02:49, Alexander Potapenko wrote:
> >  config LOCK_DEBUGGING_SUPPORT
> >  	bool
> > -	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT
> > +	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT && !KMSAN
> >  	default y
> 
> This kinda stinks.  Practically, it'll mean that anyone turning on KMSAN
> will accidentally turn off lockdep.  That's really nasty, especially for
> folks who are turning on debug options left and right to track down
> nasty bugs.
> 
> I'd *MUCH* rather hide KMSAN:
> 
> config KMSAN
>         bool "KMSAN: detector of uninitialized values use"
>         depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
>         depends on DEBUG_KERNEL && !KASAN && !KCSAN
>         depends on !PREEMPT_RT
> +	depends on !LOCKDEP
> 
> Because, frankly, lockdep is way more important than KMSAN.
> 
> But ideally, we'd allow them to coexist somehow.  Have we even discussed
> the problem with the lockdep folks?  For instance, I'd much rather have
> a relaxed lockdep with no checking in pfn_valid() than no lockdep at all.

The only locks used in pfn_valid() are rcu_read_lock_sched(), right? If
so, could you try (don't tell Paul ;-)) replace rcu_read_lock_sched()
with preempt_disable() and rcu_read_unlock_sched() with
preempt_enable()? That would avoid calling into lockdep. If that works
for KMSAN, we can either have a special rcu_read_lock_sched() or call
lockdep_recursion_inc() in instrumented pfn_valid() to disable lockdep
temporarily.

[Cc Paul]

Regards,
Boqun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZnsRq7RNLMnZsr6S%40boqun-archlinux.
