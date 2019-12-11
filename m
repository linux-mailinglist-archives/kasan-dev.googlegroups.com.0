Return-Path: <kasan-dev+bncBCR5PSMFZYORBZXQYDXQKGQEYR2UTHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc38.google.com (mail-yw1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1136311A001
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 01:29:28 +0100 (CET)
Received: by mail-yw1-xc38.google.com with SMTP id o200sf449743ywd.22
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 16:29:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576024167; cv=pass;
        d=google.com; s=arc-20160816;
        b=HaeaAmJilou+OV+s3QP9JCuamGLVj4Yt/hkSI+JZSdy6FrRNONVC9C8uy16SrXtf/q
         OUZIFU61hxxQPZpqhTRT7DNDqYpWhf9W43VtuTAiBMAxxDojbN6xn8xF07hgsNuBFkxk
         aymMezE4dUWVNMCsH9RpK/AO4ieMMmcyJhgNPJATD+EEPxPcSgW+DJ6suYD3dP18BqrA
         +33Ha1kVOIJ5QtpA/shYsRcy9L1VVl4VmaBVcdqoNXDDHaf7vNRTFq+kLvukJdT438GN
         IakfH/4gfTglV1tPD4WBhecBbrcsFurPwM/tsGjljUkHVI6uzf4HU3mTvas3SvYti7Ps
         yYow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=DvqEh3AEJchTfPzn2k6EgfcYtnKvGO5m47eoXnYewJo=;
        b=V6ulyyDVqj/HhGaCKbf8bqGvBmKjQvvGdI4LN/Cy98DNxYiskimlWTNGJwaIiXly3/
         QsJGT/ZVcHSMW1c+zUhViNSipEsbRoCzmX3YOT0C3f0je4gOC/BIolJSjXzGkN2fBPx3
         xVmu+U31b3pp4tNOlhKow7WKQROmOYL4zJiRdb/4OFLPI7s0v/tFtB8k0Rk6qn+hIDqo
         OJYmPjVJNi/nn0Xq8YSQQ0R5gvi42GM/4ubYtZvP3fsE5i9FrV3s2dpaJHat6ZmvwrXc
         tHn8hQcaYVqo7NKCP7ibLu1qDcJrMQCihIxLN7gnWlJIzT27Rtu9Vj09qrVV3ghnVbjk
         M/2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=Jn2SQvPi;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DvqEh3AEJchTfPzn2k6EgfcYtnKvGO5m47eoXnYewJo=;
        b=iHgrTUEkOp9HcVVRsxSQ1uftXDKHWpYGdjSlaFJ2CILLC7RPYMPXu8UWC5qnDnHa3q
         Vk6EuzXfQ4F99e/mayi4otcKUeA4UE64Bk7sG8lm0C+7n77MN2SaPwgOJ4OH8wR+pBqD
         VdI+bT4Q0LM4X6JQIfgowIofpYjfCbAFEs/+/CSxoxGmYOTnOpnajvHHVE8Mv+Cdos4Q
         tWySdtN5Nv8x8n/XOiC0TgEGtcWLKELY4r37DoQ96WN1VNQIHigx6ixcSteTsVxrOAvn
         MbcuNvlQHiPSyS4fdvhitMDERwXtr2Ngxii/E7YwG6WaT2nwekRiS9sKU82+uJoS2EoD
         /PqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DvqEh3AEJchTfPzn2k6EgfcYtnKvGO5m47eoXnYewJo=;
        b=PF0+rl0F2pqWhz93k5a7jtUz7uec9gb8JZk/p2ioEfOo57UwcmPIXdFcIx/C/u7zMn
         0v8sj3Q8rrWB+EABxZOG8nxvT1eVeoxZ8wzIWzzxi9W/14iNcu5bSavH7gDMb6V8ZUa1
         s/BNV0qLphAmewZ7UK4PUgv3k4z/+yeg9gLb428hpQSbK/Z3iTmO2RWa849KRBO70fOl
         EmwwqKFmuiQ79f5mbt+jb6LZCHz/wiKW35H3uyTuO/XRH/azm9rh6xAsuu3FzASrslZo
         rIRuPXjwIHWKLmQ0CPck/m9GAhvAVzxFxjfP2S26dx75v7Ghxe0znd4LrFWSu1Lkjx/U
         8onw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXWLABfx7zqqP0bvLy3gcutt+Z76B0fbJz9XJgDxNiOixe79UPK
	9j/VKoE1yDoN077k+PF/UnQ=
X-Google-Smtp-Source: APXvYqwjNQawQHi7z6MxVE/O8TujnHFswYphikQfp8m80FBJmAzaTFxZ2pkMjRgKxEtAOsZZ43HCpw==
X-Received: by 2002:a81:130d:: with SMTP id 13mr271296ywt.168.1576024166992;
        Tue, 10 Dec 2019 16:29:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:fc85:: with SMTP id m127ls32571ywf.8.gmail; Tue, 10 Dec
 2019 16:29:26 -0800 (PST)
X-Received: by 2002:a81:4755:: with SMTP id u82mr292848ywa.94.1576024166249;
        Tue, 10 Dec 2019 16:29:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576024166; cv=none;
        d=google.com; s=arc-20160816;
        b=uvBAPl+29v2iZim8CVi2KXnVt5je/EUjqvPj+qoUe8+2wu3vxIXkTJIHHWUZh6IRZn
         DlOd923e+g5aITUoUAltDw8Ka49Gn0liA8BcHLQD9voZnUb3QD49CUxAtQBTyxM3ECjP
         qpOaTMGFh4TBSotaMHLGDpI9gmtWKPAmAvYOOpqRMRTPzM8Ws0DNrifsLl/NCPbZHwJC
         QpGYsHBuffyH5Qi35vROeGiXNm75n+YjAC8Dj5+CMPtDtuiyKb/90melAsj2Sv/oNBtx
         AI/iAQ3fuTSsfKCbZ5sU1g3ITpHK7fOcqdgkC+sj/Pw+mnFV69TF6NpLwfcI8cHaZjyB
         4gAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=Ng/0ezKD0TtIAYgW99PT/vYxFMIODr0QEpq5l6nJDic=;
        b=mv47xrwe2N8WT9b69YcwY3JbHYlMciKQM4z1ZlxmElfIT5ZP8jMPPEhLBMgR8N2Jp3
         PXaLT26Y0xQRC0kumUMxkmrfwu2ed7ZgOuyfGb5zzJxUI4lIx/bozfVbGTKHbpNdq7p/
         KNBRCxieqZdsDcPjLsex3fQgUy2P7Vze5+JZDMm75QQ8MYJ5+V5FbRuCz/Ro7mBwL3Ic
         prudhMCL9hGe8Q/GPTmLPqfPK72L9UR4+UkYiYuV+YbONhzj+m7tQb7ZsRflh91EBEDa
         fAC2arou79eJmfvr00uoo15t1dnAAfD+0QerA/dSZ+J7mmyzBOd6ua0MT853x145R+V0
         WQZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=Jn2SQvPi;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from ozlabs.org (ozlabs.org. [2401:3900:2:1::2])
        by gmr-mx.google.com with ESMTPS id m125si20834ybm.1.2019.12.10.16.29.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Dec 2019 16:29:26 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) client-ip=2401:3900:2:1::2;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 47Xd8v5C5Hz9sP3;
	Wed, 11 Dec 2019 11:29:19 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, dja@axtens.net, elver@google.com, linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, christophe.leroy@c-s.fr, linux-s390@vger.kernel.org, linux-arch@vger.kernel.org, x86@kernel.org, kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>
Subject: Re: [GIT PULL] Please pull powerpc/linux.git powerpc-5.5-2 tag (topic/kasan-bitops)
In-Reply-To: <20191210101545.GL2844@hirez.programming.kicks-ass.net>
References: <87blslei5o.fsf@mpe.ellerman.id.au> <20191206131650.GM2827@hirez.programming.kicks-ass.net> <87wob4pwnl.fsf@mpe.ellerman.id.au> <20191210101545.GL2844@hirez.programming.kicks-ass.net>
Date: Wed, 11 Dec 2019 11:29:16 +1100
Message-ID: <87lfrjpuw3.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=Jn2SQvPi;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as
 permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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
> On Tue, Dec 10, 2019 at 04:38:54PM +1100, Michael Ellerman wrote:
>
>> Good question, I'll have a look.
>> 
>> There seems to be confusion about what the type of the bit number is,
>> which is leading to sign extension in some cases and not others.
>
> Shiny.
>
>> It looks like the type should be unsigned long?
>
> I'm thinking unsigned makes most sense, I mean, negative bit offsets
> should 'work' but that's almost always guaranteed to be an out-of-bound
> operation.

Yeah I agree.

> As to 'long' vs 'int', I'm not sure, 4G bits is a long bitmap. But I
> suppose since the bitmap itself is 'unsigned long', we might as well use
> 'unsigned long' for the bitnr too.

4G is a lot of bits, but it's not *that* many.

eg. If we had a bit per 4K page on a 32T machine that would be 8G bits.

So unsigned long seems best.

>>   Documentation/core-api/atomic_ops.rst:  void __clear_bit_unlock(unsigned long nr, unsigned long *addr);
>>   arch/mips/include/asm/bitops.h:static inline void __clear_bit_unlock(unsigned long nr, volatile unsigned long *addr)
>>   arch/powerpc/include/asm/bitops.h:static inline void arch___clear_bit_unlock(int nr, volatile unsigned long *addr)
>>   arch/riscv/include/asm/bitops.h:static inline void __clear_bit_unlock(unsigned long nr, volatile unsigned long *addr)
>>   arch/s390/include/asm/bitops.h:static inline void arch___clear_bit_unlock(unsigned long nr,
>>   include/asm-generic/bitops/instrumented-lock.h:static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
>>   include/asm-generic/bitops/lock.h:static inline void __clear_bit_unlock(unsigned int nr,
>> 
>> So I guess step one is to convert our versions to use unsigned long, so
>> we're at least not tripping over that difference when comparing the
>> assembly.
>
> Yeah, I'll look at fixing the generic code, bitops/atomic.h and
> bitops/non-atomic.h don't even agree on the type of bitnr.

Thanks.

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87lfrjpuw3.fsf%40mpe.ellerman.id.au.
