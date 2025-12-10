Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO6W47EQMGQEJ7MX3TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id CBC24CB4186
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 22:50:53 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-3438744f11bsf581998a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 13:50:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765403452; cv=pass;
        d=google.com; s=arc-20240605;
        b=AYhyzrII5nLzIl2HsjsxjaWJImQaUC8sDa2Yw3MD9OCn89sG9Iyu4D49DtphzOplJH
         isGSb/l1ftkXH3DWtkIsU+6Nm7GN1wqOd99A+KUyb7OmnmF8WkmI7xDKDQDUUdx4+pdM
         z4aLAgW03Jdh1e0A69oCpIdBfW2Yfql1F5tENuGzVpUvMtK77OTyxJnRVbPF0oH2u60Q
         exvVqUSlgLPI4YILSfA4XMJ8hWZObY55aTQaKM3/VXlEC1ZDEh7xZRUSZ/dca6HnYAb/
         MU8eZ2cZ0tCE6TvFs1PfvSqURtRgsfo+VnD5BeMDChwVjRCNJzLk64I3qMh4nVGQGups
         w+aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=W8enhXsucuPUMPajdV2c3HXkoN3Fdt+gJPb53fF2YG8=;
        fh=DJ1BWz1ShvexfB8zObkPYn5UNInUF5QrE+VlIU1rvCs=;
        b=Du+i85c2WqtoB0fdhzyloD2xiDjh4Z+wKtqmbw4f2pHMrwFn6OuICofRCLlXeHXL1S
         eKL5mDMQkYBA5Lc5lmiaFmq0bsa/kiydlhzhh98kOIqdYyxBdV0D/tJYI0ZeKJPZ4Cdn
         trxoKXivAXAH2rh0B69MfJ166UlHtBkjns/0cY8WrZnCtd1EMm/1YRbtjCHI9rzgSyQ+
         BBRpl8HzudbaTZTIhZVkuGO2ZXWNxSxVsYfEhfT85OLDADCx3pgqiKpMi13IYdo5+u16
         tyKuNN2pGTzLWEVrrMj42rOWiTqvBmT8gxaiNlw40hbx4t1uTv1aBgl4hG7C1iB6JGBO
         vngA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jS6JDFzC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765403452; x=1766008252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=W8enhXsucuPUMPajdV2c3HXkoN3Fdt+gJPb53fF2YG8=;
        b=GMtiQeuOId5uwDlXXQ/7ex04cDzkt9Ds2OTrVkhOOFs3Hm5WxxKCmtZP5puVESOj0z
         cBRgSfF9pFwhkg6dNAFic1Py+Ddrl0scG2/OPee4/WriZc+9D6E59Z1DkzmB8PdL41Du
         0vuH6Sn4aCpcF8ycOLbNh2a31jBpVoDSvbyhyzYShFbV8061FE/7QHlyR6WzNtTERkTb
         a1G3EMsUYJ6qqFzya5U5jvjMJIrWGrG0hhC6igykq24D+hi42dGJgwxCkNwe5CKdSYRs
         cQwU5+6FYl9mYxNJcJW3QRxb0MlVGvtPlfL7grzPEWLQfFPODgxOqWlNyWHcO0f62ScW
         FZZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765403452; x=1766008252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=W8enhXsucuPUMPajdV2c3HXkoN3Fdt+gJPb53fF2YG8=;
        b=JqTbmie+pFxQV2WYQPpFJ8O1aWyUbarw/bMARJRHakpF4EwUJ59EQ+jWT+Em/6yyAx
         e37l3ZLQi4vgYwQB2r3LQyRqI5IJbDCtYFiqMnVV6fwlxtMrnK9LD9SgZCJJqCi47EiD
         DqkrVTZgiB1qLW+ODVrpJ3WV4fSb0E90uTVrPfFOrd4vjUISkDp5I9QZY6Zh/nOsdE1S
         yN00wKUmGPc0ggv6SMBIPalwff9FzMtibm0IR/MpKMwtuDpoDZgxMjGLKDhCtvslbd5d
         /rOlzkl5rrT7M8eIMMagpzpFMAfXdPfqXxQ06VYMDBw49U1wiQBWmAjVbvzGhF4dmj8k
         iDIg==
X-Forwarded-Encrypted: i=2; AJvYcCXKnLvFTsMhnqNr5MVZrQuEo7YyO4rQSXhtTSDqS3nOhiwh2d202WeUxuYGkdpEIJMqvwMcGg==@lfdr.de
X-Gm-Message-State: AOJu0YyNkaRp3DJPnl2BuzNbdZcjg2GymRtOaGZU0uqmilT3A5vB0D5j
	UeY23a1flOvg0xK9Z7RQ5/ZxCjbR5guktZsx58zshUBEZrI+ph8hqcYE
X-Google-Smtp-Source: AGHT+IEZjYS/+uIGgb2+VxI9vuU3MoWTbLpiHbUmeT9Z+1YRiVtk2Bj8WAkB8sdfObGy2hFRbP4czg==
X-Received: by 2002:a17:90b:2e10:b0:349:3fe8:e7de with SMTP id 98e67ed59e1d1-34a728d5ff7mr2908943a91.28.1765403451583;
        Wed, 10 Dec 2025 13:50:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbaetBaOZXnDjqnsbZIKt/uq1TqSr7FPRbKBhmobua97g=="
Received: by 2002:a17:90a:a694:b0:341:1a01:6228 with SMTP id
 98e67ed59e1d1-34a8fefdfd1ls90041a91.1.-pod-prod-05-us; Wed, 10 Dec 2025
 13:50:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVz+bfLR88+KTCucITHKE8h3KbSeDw1hssx4wb7BN1/knuQunWfPra9Rg/mCmL312ohRcgdUlwasmQ=@googlegroups.com
X-Received: by 2002:a17:90b:2647:b0:32e:5d87:8abc with SMTP id 98e67ed59e1d1-34a728ed974mr3374266a91.36.1765403449934;
        Wed, 10 Dec 2025 13:50:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765403449; cv=none;
        d=google.com; s=arc-20240605;
        b=a9GHT2LWpkIVQ+rxkRVy8M15UTbFt5by0neiqjbtiinir3IwQ0HByzFJi1W8dKj3Ps
         14YWterClIZZAsDb6yD++102pDza6XfDOyQ1nGtojnHq0aHG4XR4tamgxuDOOeyFSSEl
         sQ+0ejuoqFdtlS+JnaKVn+V7Q1OQbGvrmTAv+zkLRG+BD8yyVG/fFAfndJNx3gYsylj1
         f4yNfg1FFbIybe0M1L1Wo4Hnz+OtTr06A7Ik66OqBprZmX1Gjfa6T7hX7+4LMPjByfIf
         RJp5xiNp9IyDN3sYUwECLx2OAigFKLjhcmPSOk4BYPz1fv0CVtOChmKl8wABe5mke2kM
         EGJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KCsZw6r2H+GxT2oqUVKFZFncfDO2e0BQEMkV3Qsj/LU=;
        fh=kb3BaF9wOYCuPopxQBWs4egr9gq5RVadLsy+4knnibc=;
        b=MKYgabFU84xCS3OhlBqxYfiIkB4Lo4hLbXO/UK5DtkEqCUFyasNgeSZw2HB0tOKG+h
         1qPP8W5/YpMpIH5HWfWFFqLjqVffU5oQxi0S38LP32gTlbHVW0WWQ5K05p0ZtfzPNUfy
         l9f90UFb/K3PyXCQOEwBvq1DTsExOpGJ6is79n2xd1MALyRSXOIQlz6Sa38FDaifpoXr
         LpHsEd07HB1EsNrQjKURZDIws1NliggHa40MO766GP19wL332+Bv53YqGhfsLP3BEYSz
         vc9gRheMw8+vGlWSCEH/fqLKUsxBWOr55eoDTY5Cc4CkL8VDPnJsvdGMbwRhsHodqD2+
         mJew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jS6JDFzC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34a4a8429dasi65323a91.3.2025.12.10.13.50.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Dec 2025 13:50:49 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-29ba9249e9dso4524055ad.3
        for <kasan-dev@googlegroups.com>; Wed, 10 Dec 2025 13:50:49 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUadfKTSfNDR0zcafrd1WdREr6HrdLlFY6e4bDPMM0A3O0RbNV0PJs/plm/N1MofCC7KvavSn/Q48U=@googlegroups.com
X-Gm-Gg: ASbGnctnZHbKMKCk73oK1EwzFAOQfp6cpKZlE7w1nDgGbXrJjFQac8IfvBqAYx2RYWJ
	xenKXDmBwci4ymrrTJLeMmR58hVYSazZYchdrZJUxVdbxuSWTpIoS7FD9MwErhZ9NdQ62VNNVB/
	SScaZlXMrvYmJmnc9q34RRFdqb2q40dDTatB8tAhGcR1LhSWD2X6KbXMmCGIE4GqPC23LbiEMcB
	D9TiGm++91NNpiubF16tqIykeMTC/5jE0uXRZOY055JO/FghYxLeRVvCZhG+mqAzJwe8GDauUeZ
	Fw1vBtuvEWmKm9vCLlPUZPzcCPg=
X-Received: by 2002:a05:7022:b9c:b0:11e:1bc:bd9c with SMTP id
 a92af1059eb24-11f296cbd83mr2505193c88.28.1765403448696; Wed, 10 Dec 2025
 13:50:48 -0800 (PST)
MIME-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
 <20251120151033.3840508-15-elver@google.com> <98453e19-7df2-43cb-8f05-87632f360028@paulmck-laptop>
In-Reply-To: <98453e19-7df2-43cb-8f05-87632f360028@paulmck-laptop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 10 Dec 2025 22:50:11 +0100
X-Gm-Features: AQt7F2rgWALnmd_GDAhG6zPIDGFcnPDoNGOr0zzF94TJ0iWpe4L1lGnI4olCNso
Message-ID: <CANpmjNNsR_+Mx=H6+4zxJHwpRuM7vKUakS8X+edBD521=w4y_g@mail.gmail.com>
Subject: Re: [PATCH v4 14/35] rcu: Support Clang's context analysis
To: paulmck@kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>, 
	Joel Fernandes <joelagnelf@nvidia.com>, Johannes Berg <johannes.berg@intel.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jS6JDFzC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::629 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 10 Dec 2025 at 20:30, Paul E. McKenney <paulmck@kernel.org> wrote:
> On Thu, Nov 20, 2025 at 04:09:39PM +0100, Marco Elver wrote:
> > Improve the existing annotations to properly support Clang's context
> > analysis.
> >
> > The old annotations distinguished between RCU, RCU_BH, and RCU_SCHED;
> > however, to more easily be able to express that "hold the RCU read lock"
> > without caring if the normal, _bh(), or _sched() variant was used we'd
> > have to remove the distinction of the latter variants: change the _bh()
> > and _sched() variants to also acquire "RCU".
> >
> > When (and if) we introduce context guards to denote more generally that
> > "IRQ", "BH", "PREEMPT" contexts are disabled, it would make sense to
> > acquire these instead of RCU_BH and RCU_SCHED respectively.

 ^

> > The above change also simplified introducing __guarded_by support, where
> > only the "RCU" context guard needs to be held: introduce __rcu_guarded,
> > where Clang's context analysis warns if a pointer is dereferenced
> > without any of the RCU locks held, or updated without the appropriate
> > helpers.
> >
> > The primitives rcu_assign_pointer() and friends are wrapped with
> > context_unsafe(), which enforces using them to update RCU-protected
> > pointers marked with __rcu_guarded.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Good reminder!  I had lost track of this series.
>
> My big questions here are:
>
> o       What about RCU readers using (say) preempt_disable() instead
>         of rcu_read_lock_sched()?

The infrastructure that is being built up in this series will be able
to support this, it's "just" a matter of enhancing our various
interfaces/macros to use the right annotations, and working out which
kinds of contexts we want to support. There are the obvious
candidates, which this series is being applied to, as a starting
point, but longer-term there are other kinds of context rules that can
be checked with this context analysis. However, I think we have to
start somewhere.

> o       What about RCU readers using local_bh_disable() instead of
>         rcu_read_lock_sched()?

Same as above; this requires adding the necessary annotations to the
BH-disabling/enabling primitives.

> And keeping in mind that such readers might start in assembly language.

We can handle this by annotating the C functions invoked from assembly
with attributes like  __must_hold_shared(RCU) or
__releases_shared(RCU) (if the callee is expected to release the RCU
read lock / re-enable preemption / etc.) or similar.

> One reasonable approach is to require such readers to use something like
> rcu_dereference_all() or rcu_dereference_all_check(), which could then
> have special dispensation to instead rely on run-time checks.

Agree. The current infrastructure encourages run-time checks where the
static analysis cannot be helped sufficiently otherwise (see patch:
"lockdep: Annotate lockdep assertions for context analysis").

> Another more powerful approach would be to make this facility also
> track preemption, interrupt, NMI, and BH contexts.
>
> Either way could be a significant improvement over what we have now.
>
> Thoughts?

The current infrastructure is powerful enough to allow for tracking
more contexts, such as interrupt, NMI, and BH contexts, and as I
hinted above, would be nice to eventually get to!  But I think this is
also a question of how much do we want to front-load for this to be
useful, and what should incrementally be enhanced while the baseline
infrastructure is already available.

I think the current series is the baseline required support to be
useful to a large fraction of "normal" code in the kernel.

On a whole, my strategy was to get to a point where maintainers and
developers can start using context analysis where appropriate, but at
the same time build up and incrementally add more supported contexts
in parallel. There's also a good chance that, once baseline support
lands, more interested parties contribute and things progress faster
(or so I'd hope :-)).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNsR_%2BMx%3DH6%2B4zxJHwpRuM7vKUakS8X%2BedBD521%3Dw4y_g%40mail.gmail.com.
