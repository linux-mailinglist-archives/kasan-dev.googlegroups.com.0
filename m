Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ6X6GFAMGQEXPJ2OKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C6CD0422C12
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 17:13:43 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id n3-20020a7bcbc3000000b0030b68c4de38sf1169111wmi.8
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 08:13:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633446823; cv=pass;
        d=google.com; s=arc-20160816;
        b=EXdHsDXB4EgAOnOZDuSFrpTJgy/6jyRvrRSdqyIMk7sPkbm+iMYSYAenyyExY1z9O4
         p9pnpq5ak3EZPDx4qjfF7dDAfQ1xU3In2TL3aF+ehUCUtX8c1ZjWu1Eopq6rR5u9qdt6
         cmekcOCP35zTOmiwiA3/xBP0Hbp6GrpDMWX21/o6ROtP/NVGzOLTSRGvpiifa6y8T4VP
         WY2e21aY3v/VVaGM0SkHLVpunMCu22rvDZcOVCkoZXxSCQSqvwc57NtpAVCxseBcV6cw
         Y0CfX58pPRJuRHKFqUxrmu+V1RgnBhMcGe0oAH9eeRsyeX+QhgaByqkLGqDl9BuYj055
         3gGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=CUrlVmg1Qw+nBZwCLA4nE0PEcHDnvPD/pDj7a5dU7fM=;
        b=do1w0i6J9zVIesi1JXfNB3U7Plhxc+XTKUCEbzySWTuK+5/BhAkANRZjpUBRZyOuYi
         pNrzBr+B2+ZvJdnfTLuC+Rf+yOL/J4nhKQoAcKyvV2o/b5gHj6W08N+95jROSWdl5QFb
         nglqlHq0A7rurT1gImWscncPTwnBjGGL2YUlJZFREFvMc+qcRlhxoYGpGHWwOBKLbU5h
         G5ISV0MlwJOE/37ifH2/20Nr5HLQOFytrDWzzAPH3n2GBghhg2Vcu1yi9GLlgphZte3E
         D5wEyeTZBk/JHc4WiUXU5uA3mz1nTXxRayM2OMcqh31IwseC2MjGPD+P4OYAfrEgJKL2
         DEHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C1yvQF0y;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=CUrlVmg1Qw+nBZwCLA4nE0PEcHDnvPD/pDj7a5dU7fM=;
        b=K5KOXaz1j6bLCHNVgIshNLmvdR/C/49DB1B8cVu5OlPmrGbVuUSzWcUzt5LJT0oJkB
         1KyHu65l6N8IIMZBbguYDSZYPds2AoZL6Hs4q/DghPiV3Fu1tJ0axmNVd75Ztqp5kZ7x
         fn2aIET2hNZuklTizC6UJmU7mgyisQAYmzQqsLqN1EwER04mfC29mmw1FxkbDzy5rxTQ
         OyZxsscsaDoDQ1eyS+quPDMyrnPMkbMbdK3BiOzLAaLMODXoXeRcozJTDxMLK+xsz5Y5
         OsAAVDm/sk2aYI9LZs56Sar+nKtqoVOBk88gGdie5IUx2HoONGvcs/u0fUwPo+MRXRdD
         2vaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CUrlVmg1Qw+nBZwCLA4nE0PEcHDnvPD/pDj7a5dU7fM=;
        b=3vgJoxVgGA1oFvCcYViEK2S08GMSmpLhaXp8c8/BQmtI5u+tgyFSKsfGrQeVufLzcz
         U1MJ/CPJkjCllkyL4zAReZ+MN8Rhj8uevKo9wqAsNVnpWVk1y+Fs2aQHsFQMIc0zXknz
         VLUneSGBT+fMUbCDHeVmk7c/dohrTo9WGuVd3QfzqCU3EMd/HLJpUmq4BrTSjjIKmSST
         3nqHMXfCzHfCsqlWiL0GL+jgIuFujXUhUtfi6g8ghEiP18iJ/Wi8DcdgD052wsnnExLU
         twnx0YMZzpI2v6bYb5rVEFjo92QRBu1SZT/bUXk1bF8Gs0RNsITT0kBBgdJ57PX6RsM/
         O2YQ==
X-Gm-Message-State: AOAM530mAsLM0eD4fZrzkW1NPlAQeufEIMe63uJCXtjm5lDH/j/aGyfn
	pCSdEh+mSqKe0wTO14ePNDI=
X-Google-Smtp-Source: ABdhPJw8UxQD2DYkKDZbX/6ql/BPaZJUf/Z17LrEkak3WM4Cn10evtmhqVwFURT5V/0K3Kf4wpPsZA==
X-Received: by 2002:a5d:55c3:: with SMTP id i3mr22539395wrw.87.1633446823586;
        Tue, 05 Oct 2021 08:13:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a285:: with SMTP id s5ls3068526wra.1.gmail; Tue, 05 Oct
 2021 08:13:42 -0700 (PDT)
X-Received: by 2002:adf:ae1a:: with SMTP id x26mr10667867wrc.30.1633446822644;
        Tue, 05 Oct 2021 08:13:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633446822; cv=none;
        d=google.com; s=arc-20160816;
        b=Qbp2EaLSYi+qWkZDqAasnfnWaclBPWZ3MDOWbCtIPN4XCJmbgV1831U0AdwUQH9bT7
         0oXDj8vgXIGQzmHffcLUsuCjwsIMpRVhRrkkXLvkTjmtRkBZ5Cnv7R1vGWvNOJn26CFX
         SMVdbLLy+UW0OdwV5Rwk1l+ainq6OY/mCJqQcegHHXJyA450+xKFKwRMo5oKJii0/cFc
         E6plud3MT542D6CZD3iZ8mn6jexY0FpD7An5hN3LzncIbzdpxeJSJYBjjFTnqWLiozoQ
         iIcycbsz60g8h1hnuoXOv41F0HCNOwPP+qbnEwOJPUdO3QNsNXt8Y2qX8TYt2njDxP3A
         9OrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=PWCYDGGbLpSMPRQR7ZAmGiH0fGx9oqlU5WKkX0Mb0qU=;
        b=k2t6DkIIzlJ9Bl4FLeccLf6c0uWqqcLzhDY8rMznm9mnBMQvSWLAGqw0uqIlNT+2GH
         iN4MBW3osNHmhyGEDImeSJxNdJVWYpA+/PWMHA7mcnkXsBIdAf3v6oI5bm8OojVrNN99
         0BblEdR7Mt2E5tJQKmN5G06aiz3yHqPRZq+b2wKli6dwPhA/W9DxRXgRU+639CjtK+7S
         OcfjSTH3D+6UP50rMn3kGw4yVmxtl5tXckWG7HOElVSvJo1cO5N1a0Xha1UdHZ3qnKgI
         g5yF3vMFXF4/7o5a/yXhEM+CKmP6NdhozK10kx7ju8Di8gc/mEPCwYn0/MUNYSXybqvU
         AYrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C1yvQF0y;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id e2si1048092wrj.4.2021.10.05.08.13.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 08:13:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id v17so37957604wrv.9
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 08:13:42 -0700 (PDT)
X-Received: by 2002:adf:e6d0:: with SMTP id y16mr22269412wrm.181.1633446822192;
        Tue, 05 Oct 2021 08:13:42 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
        by smtp.gmail.com with ESMTPSA id a2sm4377335wru.82.2021.10.05.08.13.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Oct 2021 08:13:41 -0700 (PDT)
Date: Tue, 5 Oct 2021 17:13:35 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E . McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH -rcu/kcsan 23/23] objtool, kcsan: Remove memory barrier
 instrumentation from noinstr
Message-ID: <YVxrn2658Xdf0Asf@elver.google.com>
References: <20211005105905.1994700-1-elver@google.com>
 <20211005105905.1994700-24-elver@google.com>
 <YVxjH2AtjvB8BDMD@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YVxjH2AtjvB8BDMD@hirez.programming.kicks-ass.net>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=C1yvQF0y;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Oct 05, 2021 at 04:37PM +0200, Peter Zijlstra wrote:
> On Tue, Oct 05, 2021 at 12:59:05PM +0200, Marco Elver wrote:
> > Teach objtool to turn instrumentation required for memory barrier
> > modeling into nops in noinstr text.
> > 
> > The __tsan_func_entry/exit calls are still emitted by compilers even
> > with the __no_sanitize_thread attribute. The memory barrier
> > instrumentation will be inserted explicitly (without compiler help), and
> > thus needs to also explicitly be removed.
> 
> How is arm64 and others using kernel/entry + noinstr going to fix this?
> 
> ISTR they fully rely on the compilers not emitting instrumentation,
> since they don't have objtool to fix up stray issues like this.

So this is where I'd like to hear if the approach of:

 | #if !defined(CONFIG_ARCH_WANTS_NO_INSTR) || defined(CONFIG_STACK_VALIDATION)
 | ...
 | #else
 | #define kcsan_noinstr noinstr
 | static __always_inline bool within_noinstr(unsigned long ip)
 | {
 | 	return (unsigned long)__noinstr_text_start <= ip &&
 | 	       ip < (unsigned long)__noinstr_text_end;
 | }
 | #endif

and then (using the !STACK_VALIDATION definitions)

 | kcsan_noinstr void instrumentation_may_appear_in_noinstr(void)
 | {
 | 	if (within_noinstr(_RET_IP_))
 | 		return;

works for the non-x86 arches that select ARCH_WANTS_NO_INSTR.

If it doesn't I can easily just remove kcsan_noinstr/within_noinstr, and
add a "depends on !ARCH_WANTS_NO_INSTR || STACK_VALIDATION" to the
KCSAN_WEAK_MEMORY option.

Looking at a previous discussion [1], however, I was under the
impression that this would work.

[1] https://lkml.kernel.org/r/CANpmjNMAZiW-Er=2QDgGP+_3hg1LOvPYcbfGSPMv=aR6MVTB-g@mail.gmail.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YVxrn2658Xdf0Asf%40elver.google.com.
