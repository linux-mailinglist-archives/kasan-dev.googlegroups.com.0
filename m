Return-Path: <kasan-dev+bncBCR5PSMFZYORB6O6XTXQKGQEQKLYCWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A3F8117FD8
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 06:39:07 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id d14sf13508658ild.22
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 21:39:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575956346; cv=pass;
        d=google.com; s=arc-20160816;
        b=Of+1hYfa5P7Ktf5jYBQAF8xED3JgEQSQyAL0wLp2qD/RtRPL+wkk86FWiuZuagFiL9
         rcWZJz5Yv1Jw4L6RAWfeHRuEA2UbSiAemBRS8hLh1JGXsSSIChmp3QB8aKbzr3KiGiXd
         SJhMmbaR3BQqfa8duT+SsmBzFoyaAG0pB06ATqkxP8d8BAJmQV+qUp4OOLZqsEe+GudT
         2+OiO7XpUaB4Sac3ZfRz0edsPXMNJTTFR62jMFA5QJ5OG8jF1guNRFP1UHlU/57LAQ0R
         X4tcEt6N8OFYbqPXiZeljc6ZGadQswWnXbHQ+/+bhJds/8mf/wG0XayjU6R6XhDFcluG
         kJrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=zvRhtiKaCOJVnzfiIst9TbngnYAFIpYqeL/ZsEeQG38=;
        b=bvL/4Ode+LWVeGTZ2+EB/jKWBl9gxeOALBwhQbt3h2Be9T4RHd2tRjCB7vOdPz8WOU
         Ksh5ejr2L9bnI4jVNyjab71F8F2Li+P0LYsYx3OdN5TKixr1j4ytjttWqFUDG4Z86Jl4
         vErONMg4ogycnzSL044Yz6oCpRm2W7C3rjglQegafjhJTZlOXwq3RFVGPvPbre4TEgNg
         r7GLyJv3ZgcTDljbmdhg/Yg8uf15YV25miJa0PPt40dO5ax6iYRHdN1M26NDpmWd0EPt
         uXm6M6GuBkXAcpG4Fh9cyPZAoD3tghgORPaEB0pRWoosj7PxP0YO2SSA5QVyjRfrz1CG
         Bdvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=oh0C7uIz;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zvRhtiKaCOJVnzfiIst9TbngnYAFIpYqeL/ZsEeQG38=;
        b=WcvhLi/7+08mVPbNz63NBkkqg3XpVomTltyVY2SbsO/BpMXB+yonYbOMWkipaTNn2v
         cLcD49GK4MdVOGOWpdqTppO53x1CDOQgS985gs+0kPF52uapwdEIT8xkvjJtqafdFOGa
         qclEJAddcmpCAEddQWNJA4OajbX76P5C+usm9X+HsxyyPjFdqWzcPjk3+TLZ7p4lembV
         NM9zo8EJzPnSTNEIz1bc2v5p4V7ui5D0gLPvnC7VJZdxhzdicY9V0VCSXRZ73J/SAzlT
         3BOPpGvPMVb5l/qFTkWRhmM+XlhCkHM1U2T0yAZJeE6LrSOiExtKUsfiN9z0J3TOlNH/
         sOrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zvRhtiKaCOJVnzfiIst9TbngnYAFIpYqeL/ZsEeQG38=;
        b=Aou9n4iTHwNr3KHeXN3YKsju6l+LZKRg9mxwlqI57w7P8c5fD4yysK7Lw/2rgABKcO
         vVfk6QgSRC4c55HZLdzsYtlbBxGUgwNwVVSDQKocbCoXBySN0ebL+Tn3aq5ERmxUZKzs
         ACmSyHMPIhTdf2QLJsJOXdSM0tnJnwjUI3xyxB0LRIlwMEMrguD6lLXIAkw+yOPd6Rwb
         Rtg698uJsWFPytCbbsYob4sTO4Yc85NjTn2SudZj7FJQpp3pwBZMsKBnIywrsQs7ngXt
         mDypolLIpJd6umIrdAf4WHcKhWv/lLevfPcxOqJ828IBbLcOe4jS00DOT4vjkBgiG/fT
         zZNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUDwjjCAGgZCAsC/wSjgxx+GoqOlDGBu3kzWx0/0AEx3LfmxI78
	h2IUp7is2hQRCTkIRtNcJYU=
X-Google-Smtp-Source: APXvYqzScabRhVF5mv6TN6qvKMT6hdohG7Ro1/M+K9cwCj25y6mok/AHsz+mhH8Lh9AZaH/bv3UorA==
X-Received: by 2002:a5d:83d9:: with SMTP id u25mr19730984ior.234.1575956346045;
        Mon, 09 Dec 2019 21:39:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c6b2:: with SMTP id o18ls35396jan.6.gmail; Mon, 09 Dec
 2019 21:39:05 -0800 (PST)
X-Received: by 2002:a02:238b:: with SMTP id u133mr991583jau.69.1575956345391;
        Mon, 09 Dec 2019 21:39:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575956345; cv=none;
        d=google.com; s=arc-20160816;
        b=PUJR7jr1mmhtjZLXYQZoCjpCQks1+N7HJQ+AuGxlYL+sdAlg/vrgB0oPhbmOMSz6am
         /WU4idpob3RYcN/S83xsw9JP15TqaqwTVmLhBVaPUF0/4awWHDZPBpaL4iYQuN1znCac
         1d15VTKAZDF4GmjuXbHSftvIjRG4WrfBiWo/8+WD9kKzsalpdAVL2bS+YKdqnB3Hpi6i
         V6R24hCCUdnw4JVEbWhG+GBO8PgQxmWRmcBHHkGfhoOgm3yG9uuNw4nNuHm1BLY3WW6V
         JxNYvRTSdeAtXbwJb9/nUPiRedizuOFazYxgMT5IqL521GUfsRgV3Mki3TohfOVjy1aO
         /1dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=0SL2lbRz60hy6/f9ji5LVe+jsZjOuGOowPR37+h93Tg=;
        b=ArkvxYeRWOD6cIv2fbR85ZtK4K0q3SP3CAltmkXGWOeWk1repNwRgCvbUJ1zE94zgf
         7YJkcni1OKTZ53kR6+yVaqJ5uZhS/acf1jZ72DtWgRv1xMC7APFdystAXTL9CCdcfo/T
         L+yyX/nfV5TBr4f58v8Nw9KTkqKrlp0Qk+4JMKEAp/DXpJdUh7SWAtWtIOg7i6p2Uyoy
         yMInx+zYxMJjMzv10W+jo1/YWFOB3SQrxr01sR3GOL7sminG7F3LC366lKA4hENhE7i/
         JD1yR7vRDf+ma0e5IvfM6EcWxVTYt3b5+eS8Scr9QHxdBdj2pJp3VpDmeHh6mAE2UcC6
         9qFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=oh0C7uIz;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from ozlabs.org (ozlabs.org. [203.11.71.1])
        by gmr-mx.google.com with ESMTPS id z20si138470ill.5.2019.12.09.21.39.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Dec 2019 21:39:04 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) client-ip=203.11.71.1;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 47X84f2hMWz9sPh;
	Tue, 10 Dec 2019 16:38:58 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, dja@axtens.net, elver@google.com, linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, christophe.leroy@c-s.fr, linux-s390@vger.kernel.org, linux-arch@vger.kernel.org, x86@kernel.org, kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>
Subject: Re: [GIT PULL] Please pull powerpc/linux.git powerpc-5.5-2 tag (topic/kasan-bitops)
In-Reply-To: <20191206131650.GM2827@hirez.programming.kicks-ass.net>
References: <87blslei5o.fsf@mpe.ellerman.id.au> <20191206131650.GM2827@hirez.programming.kicks-ass.net>
Date: Tue, 10 Dec 2019 16:38:54 +1100
Message-ID: <87wob4pwnl.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=oh0C7uIz;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted
 sender) smtp.mailfrom=mpe@ellerman.id.au
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

Peter Zijlstra <peterz@infradead.org> writes:
> On Fri, Dec 06, 2019 at 11:46:11PM +1100, Michael Ellerman wrote:
>> -----BEGIN PGP SIGNED MESSAGE-----
>> Hash: SHA256
>> 
>> Hi Linus,
>> 
>> Please pull another powerpc update for 5.5.
>> 
>> As you'll see from the diffstat this is mostly not powerpc code. In order to do
>> KASAN instrumentation of bitops we needed to juggle some of the generic bitops
>> headers.
>> 
>> Because those changes potentially affect several architectures I wasn't
>> confident putting them directly into my tree, so I've had them sitting in a
>> topic branch. That branch (topic/kasan-bitops) has been in linux-next for a
>> month, and I've not had any feedback that it's caused any problems.
>> 
>> So I think this is good to merge, but it's a standalone pull so if anyone does
>> object it's not a problem.
>
> No objections, but here:
>
>   https://git.kernel.org/pub/scm/linux/kernel/git/powerpc/linux.git/commit/?h=topic/kasan-bitops&id=81d2c6f81996e01fbcd2b5aeefbb519e21c806e9
>
> you write:
>
>   "Currently bitops-instrumented.h assumes that the architecture provides
> atomic, non-atomic and locking bitops (e.g. both set_bit and __set_bit).
> This is true on x86 and s390, but is not always true: there is a
> generic bitops/non-atomic.h header that provides generic non-atomic
> operations, and also a generic bitops/lock.h for locking operations."
>
> Is there any actual benefit for PPC to using their own atomic bitops
> over bitops/lock.h ? I'm thinking that the generic code is fairly
> optimal for most LL/SC architectures.

Good question, I'll have a look.

There seems to be confusion about what the type of the bit number is,
which is leading to sign extension in some cases and not others.

eg, comparing the generic clear_bit_unlock() vs ours:

 1 c000000000031890 <generic_clear_bit_unlock>:             1 c0000000000319a0 <ppc_clear_bit_unlock>:
                                                            2         extsw   r3,r3
                                                            3         li      r10,1
                                                            4         srawi   r9,r3,6
                                                            5         addze   r9,r9
                                                            6         rlwinm  r8,r9,6,0,25
                                                            7         extsw   r9,r9
                                                            8         subf    r3,r8,r3
 2         rlwinm  r9,r3,29,3,28                            9         rldicr  r9,r9,3,60
                                                           10         sld     r3,r10,r3
 3         add     r4,r4,r9                                11         add     r4,r4,r9
 4         lwsync                                          12         lwsync
 5         li      r9,-2
 6         clrlwi  r3,r3,26
 7         rotld   r3,r9,r3
 8         ldarx   r9,0,r4                                 13         ldarx   r9,0,r4
 9         and     r10,r3,r9                               14         andc    r9,r9,r3
10         stdcx.  r10,0,r4                                15         stdcx.  r9,0,r4
11         bne-    <generic_clear_bit_unlock+0x18>         16         bne-    <ppc_clear_bit_unlock+0x2c>
12         blr                                             17         blr

It looks like in actual usage it often doesn't matter, ie. when we pass
a constant bit number it all gets inlined and the compiler works it out.

It looks like the type should be unsigned long?

  Documentation/core-api/atomic_ops.rst:  void __clear_bit_unlock(unsigned long nr, unsigned long *addr);
  arch/mips/include/asm/bitops.h:static inline void __clear_bit_unlock(unsigned long nr, volatile unsigned long *addr)
  arch/powerpc/include/asm/bitops.h:static inline void arch___clear_bit_unlock(int nr, volatile unsigned long *addr)
  arch/riscv/include/asm/bitops.h:static inline void __clear_bit_unlock(unsigned long nr, volatile unsigned long *addr)
  arch/s390/include/asm/bitops.h:static inline void arch___clear_bit_unlock(unsigned long nr,
  include/asm-generic/bitops/instrumented-lock.h:static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
  include/asm-generic/bitops/lock.h:static inline void __clear_bit_unlock(unsigned int nr,

So I guess step one is to convert our versions to use unsigned long, so
we're at least not tripping over that difference when comparing the
assembly.

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87wob4pwnl.fsf%40mpe.ellerman.id.au.
