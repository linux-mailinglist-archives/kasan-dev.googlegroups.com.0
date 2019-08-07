Return-Path: <kasan-dev+bncBCXLBLOA7IGBB76NVPVAKGQETRAVSFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id A1B6384F4A
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2019 16:58:07 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id s18sf2218689wrt.21
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2019 07:58:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565189887; cv=pass;
        d=google.com; s=arc-20160816;
        b=pvmhyxiMJt32eAxxMr80q8sMi/ir8CTytCxeGWsC5ocQVkO4esVeaSwSAxRjh4DzWL
         JLyzl1CKMEqU3ncwQ+UquV02v66aMr1Sb8GGMchIO9iVozzILGB7/GLPaSoHErKksy9Y
         dHti/SLDM1V8kLk4A6V7kw6v6wPrnHEVXNxlvQE4dmxZrquER5NPEFY5JRmyKzcJ4BdI
         UuiE/bxQHa9ATgP9QRRTG9alrlugxYAUto3N1PfKurvpkDrjEh3MdaM0yyDM7aY+xTYR
         z5gbO27ky6D20Mqvm/7MVxZjjE/LlJXd5+rh591s9vaXUwpNpVySftgPPoVWuuWUUonr
         auJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=rGBqrfoje+hoxlqbUqHG0BgeCAPvxrHQnRsyPN6U2ro=;
        b=epsHRdU4AkwBe7h+0HSp/HWIUH1Uvk5B/3pxTmdopqBi1WBMwFJPZb0q5ZmrW5jGS2
         0EmX1PMviOOF6h+i4RdYwgNPogMk/KmQ6N7DTb8TZ0DKDfjNzDrxuu0FzWxlgfA8aLHB
         Dy5T3tNvBYFMbDpsjlDSesBJEGa027/jZjsghgCcAQ0Ghfdtd3VUSsmDtxpD1SRorfAe
         5IpsrMdqBt1ucfoLdEYrC0zHz8CXREHy++Q4nX/MlW75LM+WaEiQ0TjmMIgEMWXIzPWa
         QWPyJurZFn/6yLhNp96iGeHzpZLqLj6H4JZvs9da1c+j5BPpnk1HkwLAJlZ8MdDTRv18
         1CyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=OnboGd7K;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rGBqrfoje+hoxlqbUqHG0BgeCAPvxrHQnRsyPN6U2ro=;
        b=GAq9SjBUi9By8aGxvwRZIO4pZEt4Mk3tXOGaS0Ge0QqswRf6MpOSdSYlMKRqHyvQT/
         G9LI5FWSewjVwbk8mWJnXSodSmsz4goHCNCvA8ZFMZvLn9liM+rbiXCrTzi/26haahsQ
         fSsxbIwViz+peoiJoPRXZfteVTSOoQAeczjRpBeTUxEDb3R9lbI5l0fZCA3jl0wlqZwi
         HteFAUUi0/zDdOEzEiM7RjqqoiJypXI5TyK+hLzeyfVIb4SMSjjZ5uh8gwdRBOkJw53v
         DuU7IXDraywk4M7JwRRpVg8I9urODMwwi/L8tAcOu1dpUAJYsSc35+Iuu7/NqKzZ8vXs
         /EQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rGBqrfoje+hoxlqbUqHG0BgeCAPvxrHQnRsyPN6U2ro=;
        b=PhHRMfNZGfFq4h7GUuJMDd8edHYMkNxIPcp3FsNbObR32+bha9Tupf5r/TnA4TYdWN
         jHhg574c5iHGTES8qQwlNdTqcX65z25LH+uBQgCehjdIZw+ztzAVk7nebopk8NQQfP5S
         ItdZUiHDP7F3wedONdK9PUUT7wkZl8i/ZQTyzD/Ux1ZYTDVSKqz6oUCxdlj72xdOrxQv
         5emspZEUWQOUmqGPC2AqRKCDAaz0xIrEwD8CxD+YHZtZVvHCUqNQ5wVkNLfZWbKln+UU
         c2eWgXc0xx4jbDahpGKR6KBBpKRXaxHBL665PUJHw0PGbAHA3IQbmu2HnM75Q7j/9LvD
         wRdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUvDRSWLzxQpCCS+DgIKGqKE4ni92UvdRkTD8QdvNmpsxJrUIxe
	vMNrsoxzAvs+xXDILfVO/Ps=
X-Google-Smtp-Source: APXvYqxA+xZl1JrpI0k+p+fd1x2q/70+Ce9kBz6Fh7081gUdKnFMGKueNsgBjJH8QU+Z6OtckP5AlQ==
X-Received: by 2002:a7b:c0d0:: with SMTP id s16mr348641wmh.141.1565189887402;
        Wed, 07 Aug 2019 07:58:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:448b:: with SMTP id j11ls26638524wrq.3.gmail; Wed, 07
 Aug 2019 07:58:06 -0700 (PDT)
X-Received: by 2002:a5d:4602:: with SMTP id t2mr11460891wrq.340.1565189886968;
        Wed, 07 Aug 2019 07:58:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565189886; cv=none;
        d=google.com; s=arc-20160816;
        b=yGWWg3TBq+ClUVhPBOs7oxb0Uiii6fhUNfx4L/m4UANjLM9lb+AezakmvP2b57Ga6/
         q6/VvgB+K447VFcEbFMZhxQJOwPYIfdL50gN2DmuEJj6qGSUaaBNsi1pQUW05goH36CX
         QHoqEy1i6nhzg2mgpSGlW7ZsjF+V71q8+Uub4mcxLr346nZbVDSuN4i9qnqIEdYTtO7b
         aEkVYkBzjfUc+cq4/+ZV8P0sIF/1nHI5nSvVr2VYb7UJY3Y7DQM6q9p5layrhZAmHOBT
         ImLILnfKUrHQLqasHHsJc3N330kwcHdYiJGLpZFLP9Lv/8F515aWCoHTmttzOYQbhMcQ
         qfDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=ZXMwBhMnE2fxHI+Z/uLlnfh3kEwMCmIcy0QbJ9cqoeM=;
        b=jNgim5Uh6LC/2e0szEkbY3jEGt35ab5vRHwFOeZwpWT3HKMBFV5OvvlpcmD2iUfPDZ
         OnaxmWKAzGN/ixaubUikvnFvBzP0HocFnvnlGwPcxK/rxG0vQSY0fCtXnCqNAW3u23ag
         THxCHJ57V/9k9P2OGT8NC+T5g4mAbYIPh+6eIkur3URLbcgCnzMDKlOTpivZkRfjL4Iu
         KHYfJjdyG/57z6zowRWPy8JR0hKs0VyzfpuV6k9syZTeyECZx1umqnLQVwGDmeGSidEl
         eXky7EPT21Cam59rirZqBsE1bcnYeyW2CJFQHmzgqM+Vg5++raB1sq9oYo3r+tninhMq
         A62w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=OnboGd7K;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id j18si11896wmk.0.2019.08.07.07.58.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Aug 2019 07:58:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 463ZPS6L3Xz9vBmt;
	Wed,  7 Aug 2019 16:58:04 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id KfhgThT8rrv3; Wed,  7 Aug 2019 16:58:04 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 463ZPS56BXz9vBmK;
	Wed,  7 Aug 2019 16:58:04 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 625DD8B832;
	Wed,  7 Aug 2019 16:58:06 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 89Fy8lsRt1wx; Wed,  7 Aug 2019 16:58:06 +0200 (CEST)
Received: from [172.25.230.101] (po15451.idsi0.si.c-s.fr [172.25.230.101])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 374988B81F;
	Wed,  7 Aug 2019 16:58:06 +0200 (CEST)
Subject: Re: [PATCH 2/4] kasan: support instrumented bitops with generic
 non-atomic bitops
To: Daniel Axtens <dja@axtens.net>, aneesh.kumar@linux.ibm.com,
 bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
References: <20190806233827.16454-1-dja@axtens.net>
 <20190806233827.16454-3-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <107dda59-45ce-98f4-4959-187f35514728@c-s.fr>
Date: Wed, 7 Aug 2019 16:58:06 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190806233827.16454-3-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=OnboGd7K;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 07/08/2019 =C3=A0 01:38, Daniel Axtens a =C3=A9crit=C2=A0:
> Currently bitops-instrumented.h assumes that the architecture provides
> both the atomic and non-atomic versions of the bitops (e.g. both
> set_bit and __set_bit). This is true on x86, but is not always true:
> there is a generic bitops/non-atomic.h header that provides generic
> non-atomic versions. powerpc uses this generic version, so it does
> not have it's own e.g. __set_bit that could be renamed arch___set_bit.
>=20
> Rearrange bitops-instrumented.h. As operations in bitops/non-atomic.h
> will already be instrumented (they use regular memory accesses), put
> the instrumenting wrappers for them behind an ifdef. Only include
> these instrumentation wrappers if non-atomic.h has not been included.

What about moving and splitting bitops-instrumented.h into:
bitops/atomic-instrumented.h
bitops/non-atomic-instrumented.h
bitops/lock-instrumented.h

I think that would be cleaner than hacking the file with the _GUARDS_ of=20
another header file (is that method used anywhere else in header files ?)

Christophe

>=20
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>   include/asm-generic/bitops-instrumented.h | 144 ++++++++++++----------
>   1 file changed, 76 insertions(+), 68 deletions(-)
>=20
> diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-gene=
ric/bitops-instrumented.h
> index ddd1c6d9d8db..2fe8f7e12a11 100644
> --- a/include/asm-generic/bitops-instrumented.h
> +++ b/include/asm-generic/bitops-instrumented.h
> @@ -29,21 +29,6 @@ static inline void set_bit(long nr, volatile unsigned =
long *addr)
>   	arch_set_bit(nr, addr);
>   }
>  =20
> -/**
> - * __set_bit - Set a bit in memory
> - * @nr: the bit to set
> - * @addr: the address to start counting from
> - *
> - * Unlike set_bit(), this function is non-atomic. If it is called on the=
 same
> - * region of memory concurrently, the effect may be that only one operat=
ion
> - * succeeds.
> - */
> -static inline void __set_bit(long nr, volatile unsigned long *addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	arch___set_bit(nr, addr);
> -}
> -
>   /**
>    * clear_bit - Clears a bit in memory
>    * @nr: Bit to clear
> @@ -57,21 +42,6 @@ static inline void clear_bit(long nr, volatile unsigne=
d long *addr)
>   	arch_clear_bit(nr, addr);
>   }
>  =20
> -/**
> - * __clear_bit - Clears a bit in memory
> - * @nr: the bit to clear
> - * @addr: the address to start counting from
> - *
> - * Unlike clear_bit(), this function is non-atomic. If it is called on t=
he same
> - * region of memory concurrently, the effect may be that only one operat=
ion
> - * succeeds.
> - */
> -static inline void __clear_bit(long nr, volatile unsigned long *addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	arch___clear_bit(nr, addr);
> -}
> -
>   /**
>    * clear_bit_unlock - Clear a bit in memory, for unlock
>    * @nr: the bit to set
> @@ -116,21 +86,6 @@ static inline void change_bit(long nr, volatile unsig=
ned long *addr)
>   	arch_change_bit(nr, addr);
>   }
>  =20
> -/**
> - * __change_bit - Toggle a bit in memory
> - * @nr: the bit to change
> - * @addr: the address to start counting from
> - *
> - * Unlike change_bit(), this function is non-atomic. If it is called on =
the same
> - * region of memory concurrently, the effect may be that only one operat=
ion
> - * succeeds.
> - */
> -static inline void __change_bit(long nr, volatile unsigned long *addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	arch___change_bit(nr, addr);
> -}
> -
>   /**
>    * test_and_set_bit - Set a bit and return its old value
>    * @nr: Bit to set
> @@ -144,20 +99,6 @@ static inline bool test_and_set_bit(long nr, volatile=
 unsigned long *addr)
>   	return arch_test_and_set_bit(nr, addr);
>   }
>  =20
> -/**
> - * __test_and_set_bit - Set a bit and return its old value
> - * @nr: Bit to set
> - * @addr: Address to count from
> - *
> - * This operation is non-atomic. If two instances of this operation race=
, one
> - * can appear to succeed but actually fail.
> - */
> -static inline bool __test_and_set_bit(long nr, volatile unsigned long *a=
ddr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	return arch___test_and_set_bit(nr, addr);
> -}
> -
>   /**
>    * test_and_set_bit_lock - Set a bit and return its old value, for lock
>    * @nr: Bit to set
> @@ -187,30 +128,96 @@ static inline bool test_and_clear_bit(long nr, vola=
tile unsigned long *addr)
>   }
>  =20
>   /**
> - * __test_and_clear_bit - Clear a bit and return its old value
> - * @nr: Bit to clear
> + * test_and_change_bit - Change a bit and return its old value
> + * @nr: Bit to change
> + * @addr: Address to count from
> + *
> + * This is an atomic fully-ordered operation (implied full memory barrie=
r).
> + */
> +static inline bool test_and_change_bit(long nr, volatile unsigned long *=
addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	return arch_test_and_change_bit(nr, addr);
> +}
> +
> +/*
> + * If the arch is using the generic non-atomic bit ops, they are already
> + * instrumented, and we don't need to create wrappers. Only wrap if we
> + * haven't included that header.
> + */
> +#ifndef _ASM_GENERIC_BITOPS_NON_ATOMIC_H_
> +
> +/**
> + * __set_bit - Set a bit in memory
> + * @nr: the bit to set
> + * @addr: the address to start counting from
> + *
> + * Unlike set_bit(), this function is non-atomic. If it is called on the=
 same
> + * region of memory concurrently, the effect may be that only one operat=
ion
> + * succeeds.
> + */
> +static inline void __set_bit(long nr, volatile unsigned long *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	arch___set_bit(nr, addr);
> +}
> +
> +/**
> + * __clear_bit - Clears a bit in memory
> + * @nr: the bit to clear
> + * @addr: the address to start counting from
> + *
> + * Unlike clear_bit(), this function is non-atomic. If it is called on t=
he same
> + * region of memory concurrently, the effect may be that only one operat=
ion
> + * succeeds.
> + */
> +static inline void __clear_bit(long nr, volatile unsigned long *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	arch___clear_bit(nr, addr);
> +}
> +
> +/**
> + * __change_bit - Toggle a bit in memory
> + * @nr: the bit to change
> + * @addr: the address to start counting from
> + *
> + * Unlike change_bit(), this function is non-atomic. If it is called on =
the same
> + * region of memory concurrently, the effect may be that only one operat=
ion
> + * succeeds.
> + */
> +static inline void __change_bit(long nr, volatile unsigned long *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	arch___change_bit(nr, addr);
> +}
> +
> +/**
> + * __test_and_set_bit - Set a bit and return its old value
> + * @nr: Bit to set
>    * @addr: Address to count from
>    *
>    * This operation is non-atomic. If two instances of this operation rac=
e, one
>    * can appear to succeed but actually fail.
>    */
> -static inline bool __test_and_clear_bit(long nr, volatile unsigned long =
*addr)
> +static inline bool __test_and_set_bit(long nr, volatile unsigned long *a=
ddr)
>   {
>   	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	return arch___test_and_clear_bit(nr, addr);
> +	return arch___test_and_set_bit(nr, addr);
>   }
>  =20
>   /**
> - * test_and_change_bit - Change a bit and return its old value
> - * @nr: Bit to change
> + * __test_and_clear_bit - Clear a bit and return its old value
> + * @nr: Bit to clear
>    * @addr: Address to count from
>    *
> - * This is an atomic fully-ordered operation (implied full memory barrie=
r).
> + * This operation is non-atomic. If two instances of this operation race=
, one
> + * can appear to succeed but actually fail.
>    */
> -static inline bool test_and_change_bit(long nr, volatile unsigned long *=
addr)
> +static inline bool __test_and_clear_bit(long nr, volatile unsigned long =
*addr)
>   {
>   	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	return arch_test_and_change_bit(nr, addr);
> +	return arch___test_and_clear_bit(nr, addr);
>   }
>  =20
>   /**
> @@ -237,6 +244,7 @@ static inline bool test_bit(long nr, const volatile u=
nsigned long *addr)
>   	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
>   	return arch_test_bit(nr, addr);
>   }
> +#endif /* _ASM_GENERIC_BITOPS_NON_ATOMIC_H_ */
>  =20
>   #if defined(arch_clear_bit_unlock_is_negative_byte)
>   /**
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/107dda59-45ce-98f4-4959-187f35514728%40c-s.fr.
