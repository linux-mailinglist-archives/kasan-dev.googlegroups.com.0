Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4WJ7GRAMGQEKSHBTJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 731BB700CA0
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 18:10:28 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1ab0f01ce43sf96919955ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 09:10:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683907826; cv=pass;
        d=google.com; s=arc-20160816;
        b=M+qr1QR9VgWtV9rgG6SGiqSYwzbBxlABtchppCOo1xdNZZGrS6qFe6Qddqy6HZV1+e
         IA/TAXwMd01JWo9W2XmHGQP97Dm6BvVsW65rQhkowWagZVKcjUYxVvQEUbl6XHOSbQym
         +lFZU2R7uT4SmcpRjve+qDRwpf4cW2C6gDsrpvtp6pvZCjrf2zPJcKVv1KogCCP6J9sI
         Y+Cle5CQuDwEkAS/epz52c4jciva+ysBdzPoM8ojiSTzIBXJa4gQ+6HPQUJ1Y4AWu+Qh
         qkO2xP3rTlAZ7gRhblQcaPMtc1JvACA+Y92ECCW+Mssia/DjOlg/L/fHMYtb9trYzMMC
         cfpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bwHM7wJZyUYIINKUTAPr5/3c9eIIk8zk+bnhjKMldlM=;
        b=z6NuExbWgvwJHsknJgTFbrjuKbtUJQF4MOewJVcS3mi6V84ZmRckoMKyh5lEAVVo84
         LFoOQ49qnj1Cy4szRVQLP6oPE27QE/e7ad9XE2fjTG30u2XpqVNkhiiu/vZYdu0B+uA9
         M8fsrzIA3QByQCeYjzN0MXzur7kOhH1pgGH6gEXa36CruQqZBS3pj4mhoa/l1XsMz21x
         5xgGTFsKTzsqDOiG3QH0zjjtNo4HVLpQ11oBBsHFaPOrJ25kaytI5UQ2CtjqBSPGOmyK
         2gCAu//U5dLY+PGSXd5WCrX9Pg6fj8WqHhwVNO/rOGjMJNf4+MSNicSJfzOlHGPOGcHO
         nT8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="vHsBiI9/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683907826; x=1686499826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bwHM7wJZyUYIINKUTAPr5/3c9eIIk8zk+bnhjKMldlM=;
        b=LCSv62QYu8pdkDPjTRnUsxsTuK+/1m2l4kBTiaVDJic5voyzgflZvu04YR0ewVxzRX
         Zci7j75ZpUPLapeiXQXkQhSW0EXuuFnPlp32x/Djf9e0UQI+1BOSufcohi7FFpComKvW
         htHOAQT5zDdkMPbH1D+pDJTM1t0srC/IIg5mwiFNBQJlBU5Ohl3zEj8490jUXwmhGBu8
         TzMRioX3hVjuOxSo+y2HZyYaNrbLjZGD1GIRjXpUVYxX18NrOV/DxBb/OCSPcwWi4jg/
         FdTAWXouaOVZwzj3AhFU3vizAmF4MFeVcfeQDbmf/sGvK3YLC2MRza7Li9r/oe3ZCNy9
         43PA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683907826; x=1686499826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bwHM7wJZyUYIINKUTAPr5/3c9eIIk8zk+bnhjKMldlM=;
        b=jaxsuQSpTlquPKdr42PrM4TUxSxy5PY0IdJ7zhPgHjGtXR6DNyOChlUos4qJhNINkq
         z+WqF9lSxU1ej7ab7z6Br9YTU+TCpioG6+S23y63GvCaFIqO6rxvf9ftoex4LApIY/fN
         sA/pmmXGgmZtlVS2UA1TIjX/JwGGrGXAGf/p9voJyfesXcbzgQbJczUJGDtr21BdyUGh
         MIjYWagEHtE30OLcsAgeCcTU6gCegtGVvGghTyYdE6UuuESOeM4KqIFQX4RZf8IPLwki
         88xg8zLgnhqeDBdeRn4Tvc+Ac4l9TB+AVe8qxEkbzwYGVOP2UYohPOoU4bZ5XXZ9Rawa
         IMtg==
X-Gm-Message-State: AC+VfDwgQDz8lBsqTBmoKc+qmppXeJc98SzLz3EuFZ2/xDLFqpy36RTK
	oZ9BXa6lgJH2W1ykYXMaPBg=
X-Google-Smtp-Source: ACHHUZ5v/HipmyFkH2ruy1O7PASGgZEvdBfdQk7V9RBxSEhUCJoDmvepDtJRvPVV7bqFsRCbjd2o1g==
X-Received: by 2002:a17:903:32c4:b0:1ad:c749:9c9f with SMTP id i4-20020a17090332c400b001adc7499c9fmr2147781plr.9.1683907826455;
        Fri, 12 May 2023 09:10:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e1d1:b0:1ac:aba5:788d with SMTP id
 t17-20020a170902e1d100b001acaba5788dls1649956pla.1.-pod-prod-06-us; Fri, 12
 May 2023 09:10:25 -0700 (PDT)
X-Received: by 2002:a17:902:d304:b0:1a9:21bc:65f8 with SMTP id b4-20020a170902d30400b001a921bc65f8mr26415568plc.11.1683907825279;
        Fri, 12 May 2023 09:10:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683907825; cv=none;
        d=google.com; s=arc-20160816;
        b=Bb0cVi4ovnsBumyfnCo2B68q2euFahcw49KLuFB/Hk2iI6rL5s6pVWgbq5UjgFO58y
         dOOlq+Dr1uvvGMzN8KAL0SBbj00y2X0/1RHud2M60DNX3sxdt8s43pQoV/Xf+Zlc226H
         TSyNzxw5RSPjWnogGS9kvHcnZqe9iMRdntCmaT2qXKx6O054/mpWkZWJjGGICGlOQ2UU
         lpfa5doYiKo9er8LgcpJaOZdj2dmNEyedHxH6TUevjzPoqhn7qTbhNC7dwYjC02yT626
         ZXClM95DCV+uYjj/up2aUSje8cfML1s9jUYYT3apDHC34Yi9zeSXX8XCbyMSEhm65YNm
         f46w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M0UJ2m9D/uUbhV+yi63iViM82oPaAy45wfjsXlqa/O0=;
        b=tzo6xvqMVbTjyi6+ETIU08FxBYdcqfMe53zrQqqFY43+Sn+Y7yu6g/0xiGdEL3NzW9
         iEAf8uSfvLN4E+Wn6dlMxx0LJYCgjB+3/F4XyGDwAkqGfQPXXvnUDngC3M5VJ3OF9BPw
         /NTTnuQa11+1R0piRV4+C9FW3hJdKFi2kTYD6YosHhvEmBUKzFpnAhcJxWvakSRR0Dx+
         lBs3/6n4n765V2Zq5ZYMw+gvi+rxN4mSw9VAwIhUlqUD/ABShPNWDXSxH5BXZKu72HYT
         orrKpU5xLI7Nq+AAo18tZhzQZRxiLNjaq46Tzvi0ugCDyFzP+71FXBh906uF8ogYMvu/
         dK/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="vHsBiI9/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id p11-20020a170902c70b00b001a4fe95baf3si523733plp.3.2023.05.12.09.10.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 May 2023 09:10:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::136 as permitted sender) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id e9e14a558f8ab-3360a95c0a1so4733105ab.0
        for <kasan-dev@googlegroups.com>; Fri, 12 May 2023 09:10:25 -0700 (PDT)
X-Received: by 2002:a92:3210:0:b0:32b:2884:667d with SMTP id
 z16-20020a923210000000b0032b2884667dmr19850155ile.7.1683907824530; Fri, 12
 May 2023 09:10:24 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1683892665.git.christophe.leroy@csgroup.eu> <d9c6afc28d0855240171a4e0ad9ffcdb9d07fceb.1683892665.git.christophe.leroy@csgroup.eu>
In-Reply-To: <d9c6afc28d0855240171a4e0ad9ffcdb9d07fceb.1683892665.git.christophe.leroy@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 May 2023 18:09:46 +0200
Message-ID: <CANpmjNMm-2Tdhp6rDzA7CYvotmmGmLUnZnA_35yLUvxHB=7s0g@mail.gmail.com>
Subject: Re: [PATCH 1/3] kcsan: Don't expect 64 bits atomic builtins from 32
 bits architectures
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Dmitry Vyukov <dvyukov@google.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Chris Zankel <chris@zankel.net>, 
	Max Filippov <jcmvbkbc@gmail.com>, linux-kernel@vger.kernel.org, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, 
	Rohan McLure <rmclure@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="vHsBiI9/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::136 as
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

On Fri, 12 May 2023 at 17:31, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
> Activating KCSAN on a 32 bits architecture leads to the following
> link-time failure:
>
>     LD      .tmp_vmlinux.kallsyms1
>   powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_load':
>   kernel/kcsan/core.c:1273: undefined reference to `__atomic_load_8'
>   powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_store':
>   kernel/kcsan/core.c:1273: undefined reference to `__atomic_store_8'
>   powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_exchange':
>   kernel/kcsan/core.c:1273: undefined reference to `__atomic_exchange_8'
>   powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_fetch_add':
>   kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_add_8'
>   powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_fetch_sub':
>   kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_sub_8'
>   powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_fetch_and':
>   kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_and_8'
>   powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_fetch_or':
>   kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_or_8'
>   powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_fetch_xor':
>   kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_xor_8'
>   powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_fetch_nand':
>   kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_nand_8'
>   powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_compare_exchange_strong':
>   kernel/kcsan/core.c:1273: undefined reference to `__atomic_compare_exchange_8'
>   powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_compare_exchange_weak':
>   kernel/kcsan/core.c:1273: undefined reference to `__atomic_compare_exchange_8'
>   powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_compare_exchange_val':
>   kernel/kcsan/core.c:1273: undefined reference to `__atomic_compare_exchange_8'
>
> 32 bits architectures don't have 64 bits atomic builtins. Only
> include DEFINE_TSAN_ATOMIC_OPS(64) on 64 bits architectures.
>
> Fixes: 0f8ad5f2e934 ("kcsan: Add support for atomic builtins")
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>

Reviewed-by: Marco Elver <elver@google.com>

Do you have your own tree to take this through with the other patches?

> ---
>  kernel/kcsan/core.c | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 5a60cc52adc0..8a7baf4e332e 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -1270,7 +1270,9 @@ static __always_inline void kcsan_atomic_builtin_memorder(int memorder)
>  DEFINE_TSAN_ATOMIC_OPS(8);
>  DEFINE_TSAN_ATOMIC_OPS(16);
>  DEFINE_TSAN_ATOMIC_OPS(32);
> +#ifdef CONFIG_64BIT
>  DEFINE_TSAN_ATOMIC_OPS(64);
> +#endif
>
>  void __tsan_atomic_thread_fence(int memorder);
>  void __tsan_atomic_thread_fence(int memorder)
> --
> 2.40.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMm-2Tdhp6rDzA7CYvotmmGmLUnZnA_35yLUvxHB%3D7s0g%40mail.gmail.com.
