Return-Path: <kasan-dev+bncBDQ27FVWWUFRBJGA5XVAKGQE57ZPBYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id AFD23954A0
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2019 04:51:17 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id w12sf1486641vsl.17
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 19:51:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566269476; cv=pass;
        d=google.com; s=arc-20160816;
        b=ipJVaz6SjiXTrqSjkK/96B4c37OUAg2otrdMgtmRRm+83FmE24Ly9qeDqGEONsEjqg
         VsIUlWgbzIdEE2NoGpQXag3W1IXZPqgD6kf6Hr0cstcCMHa03dTXu6GURams2AWVf/q2
         ItolRQ5nrZZ4UR2LfdsUrmKNnofXvpRtjdslomEr8sLmuf5B3ZQhysvPGTmATLL/2s+j
         Mo6/aLMHbUXxurO+ytPbWlFdesDVZ+J6iuyU7UzGBN11FoXVWBz3By4PCIBtrB3xOC5q
         NvC/bkXg3kN8PEc6G1yrRRHlR9c214+luF/d/lDJHQGKZAAowo8IBs/RyfnWTKcm9pVU
         Pqdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=RihB3Z7ohgDkpO1TYRhAw4vZs3Qn4cjLIJ1eLn+1FKk=;
        b=ebkjsyHdYm807TQuz+vyFEsEASGE24NvRgsk17QU4FQh5mOmRMcWSMhWvvtFYIg6Qi
         iYUZg+BnDtuL5NmwwpaGSNLbqj5Z+gTzkb71TKr0LQjY0K2EfQGiftYzMW81eud1oPCv
         u9zT8oZrWrhcK678HbcFXlooY7PXjsB6XKiDTT60iYh8lUnJV7/mX4zmF5F4KEvYiUAp
         qz2MMoVOKy/bWe9vKkVQrl8TJT0kZ7YiFvQgaHWO3EtlNRWJsIRRv/6TjGT1DoSl2ueh
         FOE38xwfRUsStxztgMbzhTLLPplpvrAXOzr1INBk3gQvqoEkJXqr2MMLv/bx3+60Zz9Y
         tfJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fgruBeYm;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RihB3Z7ohgDkpO1TYRhAw4vZs3Qn4cjLIJ1eLn+1FKk=;
        b=NpfdwrjEb7pqwKk9Kxi1FoKCDTb3TSeqDkyv4LdopSe5jpRk2KDnecNIN1xuKcW1h5
         oOyq5RxrgVpW1rO1CGs2mbUf8lxRi/RiIgRVYD6Q91BUcboRYAmfwoiHQcd2O3A5PsPi
         +vEs+TPXi2Z/FnyVR1qqervQVYbO9P6bA/hWX3av8fEzboAVkBSYt8GCYsXxYA9q0/X9
         dLkT5zxsP4PWCqmd+lHyp/TPH73xXoXyRjBWx6889e0bQVdXSzx+07fFCZZPEmGl9P7C
         kZ4Kw1S90/P4Eype21YBnairTNzTU3aBO2WTIcfBjwaltAzhggTXVsJx4daAMCEIBs3+
         QIlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RihB3Z7ohgDkpO1TYRhAw4vZs3Qn4cjLIJ1eLn+1FKk=;
        b=XTQ5s7S+aFO++W+ce3h6+nx3UKTKYkB9KihpWidolvAMj7vsFYp4RK8Jk3FAUH6Cv3
         j09GtHd28PbhPUPg59G1cSgfu9tbtDwCeSBj+RS3yE4Sb+TEK85eEp/ZRzVzJP39omSh
         ZGAJHics2ikDmLChnriIHRjBGmttUy2PNPKIX5beWFnR+NOn2aMQDoggbSYex+f+TcYB
         jMhgP1aVrZNkXZUIUwcbI4BQmpWTvNWEgh+du2m0vr4loz1Jb4EgF7n4OglqPTNoHIg3
         jNJvwv5+hejb4e++gFUrXG6IFm2RYON+yWVaXyapY831ITt1cT/ty0q0lPPp62THAsd4
         RRqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU/JX9D5mSQh6qcKsR3GS9x1zp5bG1kLI4OAy6LDfr5ta+8jfE3
	1RgxEkB88x+nxmf2m53v+gM=
X-Google-Smtp-Source: APXvYqznyDDXOe0K/VTAewh4PmNucvtBQRUs0VXCqD3DVridVuAkvo5AbUFfUMArzs08NLTpPZMsNg==
X-Received: by 2002:ab0:2685:: with SMTP id t5mr2319298uao.48.1566269476523;
        Mon, 19 Aug 2019 19:51:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:be0b:: with SMTP id x11ls1990089vsq.7.gmail; Mon, 19 Aug
 2019 19:51:16 -0700 (PDT)
X-Received: by 2002:a67:fe54:: with SMTP id m20mr777824vsr.10.1566269476256;
        Mon, 19 Aug 2019 19:51:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566269476; cv=none;
        d=google.com; s=arc-20160816;
        b=HkjAkYPqWDcPFNC6R33lvR6QFBPPnJXqzeVVlzsvtgVGicwVLGLJLebFMR/pwl+RIL
         XlNhvrdxllP6E2X8hqoln9TfqkGjeA+Vd2+HN8UMugVi8zVBYKco3UD4r0CoZTM/Er53
         naSaSJOSFjI4gYrBsaylV8ndqi88h3OKyKOsKNZae9cpPj59fNR0xorL8/0iAwhFQQc5
         MIjpUog51/MjdlMJPfj7Hk8wDzTvc863dq7kIfvjZd1+X+OwaC1YIwy0PIqmLOBbgTdE
         tvbH/I9zr91Jfb2/oO6tauKWkzHL5lWdz0S1APHwl0H80s2Nap7sfxZjHh1Gciq1uBJM
         fmdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=4MweJtv161U2CMaz91jtsrp2c+G77sFGRYDZ+W7nfdg=;
        b=kekaxjzvR3XumfLcqDlfcCCX0bcRGrgjOS/BbkhuacbUBZzqKEBPtJMrA4VVRhVf1F
         vu59ZQ9eZeSaydD/et7GBkDxu6/H7MHyhje7P8DlrXhminJ87j/MaUlUYEQXb7GoywfA
         ykHZQLAYw0yMNZV22T6oxyM72Z44iuDS8kK6mnqHNS5idZf3/oNtWvxkX0GgccUF8O5O
         AAe6DTx+2A0HhyV6UNAMtoQPxBQoBQgNLpmV7kwjN9aiYjsVZsn0DwY55/2IeOvP3ulj
         yYc5z46+oKfrLd29nJ2SNMuNdigUpqVjllslAeGzC9g7n/BMOwd7z0s5bneGVlJ2S9xq
         oEOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fgruBeYm;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id z67si1002805vsb.1.2019.08.19.19.51.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Aug 2019 19:51:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id f17so2397783pfn.6
        for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2019 19:51:16 -0700 (PDT)
X-Received: by 2002:a63:f342:: with SMTP id t2mr21527124pgj.2.1566269475088;
        Mon, 19 Aug 2019 19:51:15 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id 203sm23555877pfz.107.2019.08.19.19.51.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Aug 2019 19:51:14 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, linux-s390@vger.kernel.org, linux-arch@vger.kernel.org, x86@kernel.org, linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com, Nicholas Piggin <npiggin@gmail.com>
Subject: Re: [PATCH 2/2] powerpc: support KASAN instrumentation of bitops
In-Reply-To: <a1932e9e-3697-b8a0-c936-098b390b817f@c-s.fr>
References: <20190819062814.5315-1-dja@axtens.net> <20190819062814.5315-2-dja@axtens.net> <a1932e9e-3697-b8a0-c936-098b390b817f@c-s.fr>
Date: Tue, 20 Aug 2019 12:51:10 +1000
Message-ID: <87d0h0tuqp.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=fgruBeYm;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Christophe Leroy <christophe.leroy@c-s.fr> writes:

> Le 19/08/2019 =C3=A0 08:28, Daniel Axtens a =C3=A9crit=C2=A0:
>> In KASAN development I noticed that the powerpc-specific bitops
>> were not being picked up by the KASAN test suite.
>
> I'm not sure anybody cares about who noticed the problem. This sentence=
=20
> could be rephrased as:
>
> The powerpc-specific bitops are not being picked up by the KASAN test sui=
te.
>
>>=20
>> Instrumentation is done via the bitops/instrumented-{atomic,lock}.h
>> headers. They require that arch-specific versions of bitop functions
>> are renamed to arch_*. Do this renaming.
>>=20
>> For clear_bit_unlock_is_negative_byte, the current implementation
>> uses the PG_waiters constant. This works because it's a preprocessor
>> macro - so it's only actually evaluated in contexts where PG_waiters
>> is defined. With instrumentation however, it becomes a static inline
>> function, and all of a sudden we need the actual value of PG_waiters.
>> Because of the order of header includes, it's not available and we
>> fail to compile. Instead, manually specify that we care about bit 7.
>> This is still correct: bit 7 is the bit that would mark a negative
>> byte.
>>=20
>> Cc: Nicholas Piggin <npiggin@gmail.com> # clear_bit_unlock_negative_byte
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>
> Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
>
> Note that this patch might be an opportunity to replace all the=20
> '__inline__' by the standard 'inline' keyword.

New patches sent with these things fixed, thanks.=20
>
> Some () alignment to be fixes as well, see checkpatch warnings/checks at=
=20
> https://openpower.xyz/job/snowpatch/job/snowpatch-linux-checkpatch/8601//=
artifact/linux/checkpatch.log
>
>> ---
>>   arch/powerpc/include/asm/bitops.h | 31 +++++++++++++++++++------------
>>   1 file changed, 19 insertions(+), 12 deletions(-)
>>=20
>> diff --git a/arch/powerpc/include/asm/bitops.h b/arch/powerpc/include/as=
m/bitops.h
>> index 603aed229af7..8615b2bc35fe 100644
>> --- a/arch/powerpc/include/asm/bitops.h
>> +++ b/arch/powerpc/include/asm/bitops.h
>> @@ -86,22 +86,22 @@ DEFINE_BITOP(clear_bits, andc, "")
>>   DEFINE_BITOP(clear_bits_unlock, andc, PPC_RELEASE_BARRIER)
>>   DEFINE_BITOP(change_bits, xor, "")
>>  =20
>> -static __inline__ void set_bit(int nr, volatile unsigned long *addr)
>> +static __inline__ void arch_set_bit(int nr, volatile unsigned long *add=
r)
>>   {
>>   	set_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
>>   }
>>  =20
>> -static __inline__ void clear_bit(int nr, volatile unsigned long *addr)
>> +static __inline__ void arch_clear_bit(int nr, volatile unsigned long *a=
ddr)
>>   {
>>   	clear_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
>>   }
>>  =20
>> -static __inline__ void clear_bit_unlock(int nr, volatile unsigned long =
*addr)
>> +static __inline__ void arch_clear_bit_unlock(int nr, volatile unsigned =
long *addr)
>>   {
>>   	clear_bits_unlock(BIT_MASK(nr), addr + BIT_WORD(nr));
>>   }
>>  =20
>> -static __inline__ void change_bit(int nr, volatile unsigned long *addr)
>> +static __inline__ void arch_change_bit(int nr, volatile unsigned long *=
addr)
>>   {
>>   	change_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
>>   }
>> @@ -138,26 +138,26 @@ DEFINE_TESTOP(test_and_clear_bits, andc, PPC_ATOMI=
C_ENTRY_BARRIER,
>>   DEFINE_TESTOP(test_and_change_bits, xor, PPC_ATOMIC_ENTRY_BARRIER,
>>   	      PPC_ATOMIC_EXIT_BARRIER, 0)
>>  =20
>> -static __inline__ int test_and_set_bit(unsigned long nr,
>> +static __inline__ int arch_test_and_set_bit(unsigned long nr,
>>   				       volatile unsigned long *addr)
>>   {
>>   	return test_and_set_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) !=3D 0;
>>   }
>>  =20
>> -static __inline__ int test_and_set_bit_lock(unsigned long nr,
>> +static __inline__ int arch_test_and_set_bit_lock(unsigned long nr,
>>   				       volatile unsigned long *addr)
>>   {
>>   	return test_and_set_bits_lock(BIT_MASK(nr),
>>   				addr + BIT_WORD(nr)) !=3D 0;
>>   }
>>  =20
>> -static __inline__ int test_and_clear_bit(unsigned long nr,
>> +static __inline__ int arch_test_and_clear_bit(unsigned long nr,
>>   					 volatile unsigned long *addr)
>>   {
>>   	return test_and_clear_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) !=3D 0;
>>   }
>>  =20
>> -static __inline__ int test_and_change_bit(unsigned long nr,
>> +static __inline__ int arch_test_and_change_bit(unsigned long nr,
>>   					  volatile unsigned long *addr)
>>   {
>>   	return test_and_change_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) !=3D 0=
;
>> @@ -185,15 +185,18 @@ static __inline__ unsigned long clear_bit_unlock_r=
eturn_word(int nr,
>>   	return old;
>>   }
>>  =20
>> -/* This is a special function for mm/filemap.c */
>> -#define clear_bit_unlock_is_negative_byte(nr, addr)			\
>> -	(clear_bit_unlock_return_word(nr, addr) & BIT_MASK(PG_waiters))
>> +/*
>> + * This is a special function for mm/filemap.c
>> + * Bit 7 corresponds to PG_waiters.
>> + */
>> +#define arch_clear_bit_unlock_is_negative_byte(nr, addr)		\
>> +	(clear_bit_unlock_return_word(nr, addr) & BIT_MASK(7))
>>  =20
>>   #endif /* CONFIG_PPC64 */
>>  =20
>>   #include <asm-generic/bitops/non-atomic.h>
>>  =20
>> -static __inline__ void __clear_bit_unlock(int nr, volatile unsigned lon=
g *addr)
>> +static __inline__ void arch___clear_bit_unlock(int nr, volatile unsigne=
d long *addr)
>>   {
>>   	__asm__ __volatile__(PPC_RELEASE_BARRIER "" ::: "memory");
>>   	__clear_bit(nr, addr);
>> @@ -239,6 +242,10 @@ unsigned long __arch_hweight64(__u64 w);
>>  =20
>>   #include <asm-generic/bitops/find.h>
>>  =20
>> +/* wrappers that deal with KASAN instrumentation */
>> +#include <asm-generic/bitops/instrumented-atomic.h>
>> +#include <asm-generic/bitops/instrumented-lock.h>
>> +
>>   /* Little-endian versions */
>>   #include <asm-generic/bitops/le.h>
>>  =20
>>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87d0h0tuqp.fsf%40dja-thinkpad.axtens.net.
