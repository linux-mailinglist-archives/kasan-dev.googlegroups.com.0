Return-Path: <kasan-dev+bncBCV5TUXXRUIBB2HAXXXQKGQEIJLMIYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C27C1184A9
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 11:16:09 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id s25sf11134626pfd.9
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 02:16:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575972968; cv=pass;
        d=google.com; s=arc-20160816;
        b=A5+/xYgZWKrv3QsRlYzwpDAtcHVaTw5dTTiMztMIxl0zuqqIU1Tsampc0YplOg/5zK
         ifaUy7eMcACjNhlIJ+o6u41YIsif7ZbuiTO0V4lJkZg+76ruPqozLUu1XU8QNmM7y8Bd
         MrfkTF2KdAkU6CC9MeqqieQwvaw++e0iqc+HB+P5EvwKolkszEuP3dgTMNifpLckMr/V
         x9V+Hp/k8bPZ6luFJ+o2HhPVvAgJ6Cb+RHF1Tb3bDTYOaa3FhAqyAF8c7h/5vna65osV
         MznvW5qlCMzE9jj3n7un4bGWQ/QGND5eByzWNBa+bGZ4NiZi5s6Y5MqfYvY8utN8nOdF
         BsLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=79Q/2XQCHlmepUGBlv7/jKWrE0E90Kdf52FdoZSCdGc=;
        b=bMJoLNbYoFzUOgQ3hBC7zWek7WJGFntsowFPiVtc86K0Q/rUI1QQ2PmQpXo0AJ/Uu1
         /DiorPn+Zmc4vG08zx/bmgKL7pYXVSzKCWz6S9U8zfjp7vrlA693NMcZ+wIMYNmUbWzP
         rxZx3HwwbDfMRURp7P0iitL55PmTZcRwrzK6OQzldC1xDpfoxMj0vT9jItQOqresVkmX
         NehOEBI8Opgixuxi1C+4tlDsmmNbO1KyuCrNpf2DFcZbjavSOiFmtLwqpelR50Ji4yOx
         g3udATYV0mN0pyy+EKsY01QUYCHdRNe67m0Wi4UZyQOqCFmH+sQ/QvUm6lGYLH89HM3a
         dCaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=XjKOtmLC;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=79Q/2XQCHlmepUGBlv7/jKWrE0E90Kdf52FdoZSCdGc=;
        b=GalYmLrmCyIfJBuDrdmL2wAzjNCMFyMY7lBDWjk4vZOpfb/Ibgiy6d1ZZcXgTr8tbK
         cTGshrb1gweNKg2/lW5+pN6q+MatcM2BLvj0+G7l3UpBXj/SsINFcy7mmRAHmnFZEk+Q
         sfD8ye5noweGAYuO3ykZpzaKKBbz2y+86hKDu4jUpFD7olkzTJtVsaQGH5471LrC5zhi
         hWM0a0BuVIDJaOApTDVXNWXk+dBhX3XrH4mxeZJAcyifxyLZIbGT+ICSshfj0Un9Vw3J
         FbQdGGXeSIGrHCETIbCRWUjkw6/T622XSIdN+akpR3vZML3xDNCdz4FCO4Qqi9+0SFYZ
         fFng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=79Q/2XQCHlmepUGBlv7/jKWrE0E90Kdf52FdoZSCdGc=;
        b=jyqMluwgIR3BhW3yjZhj9eqoRafKtp8lKHJ2UzxGawsI+iGzLgZLbRbxvzAl/O31MI
         XKJxFJFXMohe+vGajpUw4BkjTURD2nD/1AOGuBQQSKo/YzT87dUcTkhmWNSoKH7RVZZV
         qyJ54tao9YNkKBIh/1531CsbEq1jEsTBf2PkQE6+HgskVgRDF0byxCiy2jLaQ9A5tmS2
         NXqyo46Pwe43Rm07gJewsTmeUxnP6f7wTC2vpA0g7wBUcqI0rFQlz5Fx/yUOch2zix3J
         +vs/AbaXvDky13P0vFrAVRObikFSO4JvbIIjWPsm5bn9cGsEKxjjGKSF4QNQrkXsa/jb
         /MOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUFIhN3uzTcyw11TBd0AyS7k4/dWw3EhgJb8r6rsMLSr/5ydkPH
	vNZxDxDJagzdq5JhRQd1NaU=
X-Google-Smtp-Source: APXvYqz0PMkP6HIrfkCVNqABSmxJSbGGGNblWAQoiEDd9Dkv5nVIIPsk0neNqjOvni0S0QFcyRjirQ==
X-Received: by 2002:a63:360a:: with SMTP id d10mr2490551pga.366.1575972968071;
        Tue, 10 Dec 2019 02:16:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ab83:: with SMTP id f3ls1588963plr.10.gmail; Tue, 10
 Dec 2019 02:16:07 -0800 (PST)
X-Received: by 2002:a17:90a:d344:: with SMTP id i4mr4643029pjx.42.1575972967717;
        Tue, 10 Dec 2019 02:16:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575972967; cv=none;
        d=google.com; s=arc-20160816;
        b=LtxRnyO5ZsuKG3O9eOe1XSKS/CDiW6FEPgIdOBhF9Cm2YbsKWblc464pjQCw0OUtUr
         AFSaP7EqBHEybfLBVXfAIB2fkDWspKShW3z7E2NIysxgViS8bBWahN/PWSlM+uQLAXMX
         aWL5MA8+8n1V4FmGg/PX2jJatrdyBb0iZ5vGHtyxBY3BHwXJSZIb4yM6A58di3RIJbhI
         4ddd1h1lmsVDcdEjemOK1j9kAkD//WhBsMkLcMVAXGMmxaTrwTktQKR178nl0mQQijEx
         QwHLpsukujgBowY3mrTQvj8yZb4kz8GB31A1usdQcAVT5ZDcw4aGa1bVQ5XF7qpTahSU
         /RvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=e5Wq1cFS0C0HbXjy/2CErHJ0P8SNw5EcJk6ucsk+DLA=;
        b=CMH9ysDCj+SocZjlH4PQR650/NR9WhOmpNWEUJRQXW80ccAyN7FTdD/78hdaSqtGpB
         +2+3Y0Iw2zrHWR1G2grBl8mTjCs+fT3o9eGgGvOEO/QUaK7X8UoDFSvBQtlog5CaMHBp
         uv8HKZoV8MSiP3SMKQcqMUjcNY0XpauWkrQpfZd3prrAk88CnLv2V37iFUhpIk8GReVw
         rGDxb1Lc3tQvdsuKupUYadE3ToTVmSyfSF79RUHARPcq/64wBQr/dxrEcgSaD2qWB/j7
         j2EV4x3ANe5p1pAz2xd1HOXjHQQCveY7IG/MBO+fyNEaFwUOr8NTHxRTvZjSMgAuNLuC
         Cl5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=XjKOtmLC;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id i131si98019pfe.3.2019.12.10.02.16.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Dec 2019 02:16:07 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1iecYX-0002cL-52; Tue, 10 Dec 2019 10:15:49 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C2373305FD1;
	Tue, 10 Dec 2019 11:14:25 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 342092010F142; Tue, 10 Dec 2019 11:15:45 +0100 (CET)
Date: Tue, 10 Dec 2019 11:15:45 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Michael Ellerman <mpe@ellerman.id.au>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, dja@axtens.net,
	elver@google.com, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, christophe.leroy@c-s.fr,
	linux-s390@vger.kernel.org, linux-arch@vger.kernel.org,
	x86@kernel.org, kasan-dev@googlegroups.com,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>
Subject: Re: [GIT PULL] Please pull powerpc/linux.git powerpc-5.5-2 tag
 (topic/kasan-bitops)
Message-ID: <20191210101545.GL2844@hirez.programming.kicks-ass.net>
References: <87blslei5o.fsf@mpe.ellerman.id.au>
 <20191206131650.GM2827@hirez.programming.kicks-ass.net>
 <87wob4pwnl.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87wob4pwnl.fsf@mpe.ellerman.id.au>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=XjKOtmLC;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Dec 10, 2019 at 04:38:54PM +1100, Michael Ellerman wrote:

> Good question, I'll have a look.
> 
> There seems to be confusion about what the type of the bit number is,
> which is leading to sign extension in some cases and not others.

Shiny.

> It looks like the type should be unsigned long?

I'm thinking unsigned makes most sense, I mean, negative bit offsets
should 'work' but that's almost always guaranteed to be an out-of-bound
operation.

As to 'long' vs 'int', I'm not sure, 4G bits is a long bitmap. But I
suppose since the bitmap itself is 'unsigned long', we might as well use
'unsigned long' for the bitnr too.

>   Documentation/core-api/atomic_ops.rst:  void __clear_bit_unlock(unsigned long nr, unsigned long *addr);
>   arch/mips/include/asm/bitops.h:static inline void __clear_bit_unlock(unsigned long nr, volatile unsigned long *addr)
>   arch/powerpc/include/asm/bitops.h:static inline void arch___clear_bit_unlock(int nr, volatile unsigned long *addr)
>   arch/riscv/include/asm/bitops.h:static inline void __clear_bit_unlock(unsigned long nr, volatile unsigned long *addr)
>   arch/s390/include/asm/bitops.h:static inline void arch___clear_bit_unlock(unsigned long nr,
>   include/asm-generic/bitops/instrumented-lock.h:static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
>   include/asm-generic/bitops/lock.h:static inline void __clear_bit_unlock(unsigned int nr,
> 
> So I guess step one is to convert our versions to use unsigned long, so
> we're at least not tripping over that difference when comparing the
> assembly.

Yeah, I'll look at fixing the generic code, bitops/atomic.h and
bitops/non-atomic.h don't even agree on the type of bitnr.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191210101545.GL2844%40hirez.programming.kicks-ass.net.
