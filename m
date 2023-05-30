Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFOR22RQMGQENHUNMRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E36C71573B
	for <lists+kasan-dev@lfdr.de>; Tue, 30 May 2023 09:41:12 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-517c06c1a1bsf2256131a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 May 2023 00:41:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685432470; cv=pass;
        d=google.com; s=arc-20160816;
        b=W5Gxt+IiqZnXiT9sRe5yVPqMrbl30sc09JzraEpjpOUur/in4F5IocmMvcUmD6OG6U
         MwRxYStHLqVVFeNki6E9+TYEhLR5mUr9IxkjampWhCERHzMjZItPMdhBRCYIPQSh8NOi
         3zOCfea8FloLHMEhcU/CueJCx25CG9Dd2Heh418YZQHwhNdKpnQrGrTBNsxFcgvqTSDk
         IRwygty4XGGmk+s4rSNhZhTkuGT74+aN1J5jCxX8KEGB7Nix1yZlgiCRgC2QlsNBKpAt
         jfBpIIGGX5guMYmfhKKO7Ix0D9TxmQF6PEk8s3fV/y7dc64pkTP6kOcFAynMAFuI8qll
         v8fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jnhCBhKcrqdNfH7rjS/OU1Z1Ey63ad5kQ2IQlRAk2Do=;
        b=pVwmW1vSFLWscVqMS+VkzJ4vTVrwTNjZYmJ1pmD5cg9ub+pL+j420u+COjYRuVmK5i
         R4cn4qcxdpo0sk7pWhc/sbwtlHn4Sh2+U42+4BIV22NU32QUCnSYizROPaWoz1HOMk1Q
         ljoX95G10XForkVYAlH6JAs6/4OCsBecHlOj4W8N7Q51b/eujuKwVcOP6ycRInADcSP8
         nFj1ubhe+N+KY3E40kdCQt9UrotDf2Z+6xopx0fR6UtfURSwB+yHEcLq6hUabnAPoSSg
         rp/HIFB42IzMzeWkxtSXfDT4vWCYjqOUbdQYtaWU6IuxitLkZPI9y+v4XmMForJ7GEnE
         BI7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=cWfjTtF3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685432470; x=1688024470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jnhCBhKcrqdNfH7rjS/OU1Z1Ey63ad5kQ2IQlRAk2Do=;
        b=DtrdxQbPwXJMiHFX5ygtEmjmEMlGjbq/E8ETBZ4undxb9uC9K8Cl+wQ7FftqbdK+IP
         XDKAxBbEN/qx4GJAPHYVDZrQNNDUYDAzxeY1RK1WaWZhK0U33rRVMgGociEE7ZGriKtM
         YMjg6MolRiFirBFpyP3KNksKmd2vWb0WfoDjbEeqCuzeZOUzzSHZ59ctCPoRo9A7NN2O
         YBBO1C4v8ZBI96idW8Fu65DEnr2qwdUUg40DdpXw1v6JC9IjWKnjTsGnH5aSE83nGa9V
         Q3fOvmIwinFzojR7lPZuyGU6oVYl1UT8FYJ81Xxer8NAmoy0u2uVlSr4qFOUdZKpvHUk
         TkRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685432470; x=1688024470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jnhCBhKcrqdNfH7rjS/OU1Z1Ey63ad5kQ2IQlRAk2Do=;
        b=YTkKjR9TWwQzlxhbclhRhm3EhQNTU3vXf3/qVtZDIfP4rh76Y60sjbKZIThbaAowY8
         beP9rx8YfzHUfBGWM4LuqFXBhRfUHKFbBvc6CC7t8MCD+YFI2FETf5w276tOhTlNpRiW
         yJN0t18TuhnpJISk2u3lrAfdbAJeCBnHzQR5QlZGoy6XWUSZ94yRaRfWpTqB7f7mWSBr
         oCGZEJNT41yyi54embQxErKcgvqQqzj3Cvot7W9DraX+AWoerq4uf4bWJWCIyojlsxxk
         LHcQ9xFzkVEWPP4HygQlYoeFoHF+CFYAezsW5RF4ImFq1DIqBcneDMWPRCN27XAH7Ipn
         2XCQ==
X-Gm-Message-State: AC+VfDxNt2XuaUplBe/KDKnAz1mY7dg7B9iYbnTpFei7AzsrPPNURark
	TmtYyhoQl6w4SyHYivbIfOU=
X-Google-Smtp-Source: ACHHUZ6gqteBeC4D6vYTda1ajnULY2qGA0i3YZxiR804ja35vtfC5Sr4YhIGgrWlUtSELf/S0HQKYQ==
X-Received: by 2002:a05:6a00:883:b0:64d:2f36:8f31 with SMTP id q3-20020a056a00088300b0064d2f368f31mr473853pfj.0.1685432469867;
        Tue, 30 May 2023 00:41:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:828b:0:b0:64d:430d:f271 with SMTP id w133-20020a62828b000000b0064d430df271ls3142316pfd.0.-pod-prod-09-us;
 Tue, 30 May 2023 00:41:09 -0700 (PDT)
X-Received: by 2002:a05:6a00:16c3:b0:643:59ed:5dc9 with SMTP id l3-20020a056a0016c300b0064359ed5dc9mr1280687pfc.12.1685432468889;
        Tue, 30 May 2023 00:41:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685432468; cv=none;
        d=google.com; s=arc-20160816;
        b=jiukv1Ywic/qwrATWl5wMrjOflZskpTcm6ZyYSHk7KoMqLdyOKoysRKr/tFZI3mUMj
         VjehCgoE+0Kg0Rkx8sHRBDdxIuhCntSKZtB7iN+zl6oaGxTtzqcFq5NCF3wkJqcPViDK
         N5i3mjwESMRo8wM5a0aKOsEns9qIWvHDiPhoQW1Gi8pFyyQv8BHfAqefXtEKPE5hhzuR
         g+kYx/5raEqVR8DzLK+DtEQUecYAj4+lNBSwcArdwZNo9TdRMs8NP2slPRWZ7Px3yyel
         zO5zxaWuo94u3yiedS7zX52vAj99k3YlUghNkttzgAtVRT8u0+jmCUqQXNjuABbCZ91E
         qYqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q1cf9BwhoNeWlUyQ+nRhOtzcn4y84LDXQwm01y+BcxQ=;
        b=a/mP1D+imSZdiOo39NEdsRPG+KJ9RHbSndm4FMtl+AHewgVV+zfiRzVhknyT3j8hr+
         ThPE1JCvy/oKmO/NEZHgjlzjgKHm0T/1Bm0Z4YnBwJIpuXJh/f6ZPm4G1xnGbVg9q4uB
         KdP6ha4cjY7BiX22uyIOzwGZnVSvDqSpMWfyeGnZm9wYRoFdUdZddv9HShqKWHZ15MlW
         fVjmLsQxhp0m7nwbBBbXDlTL8SPKm6wPyp9sW5hucAB7FXqIVRP2SqxMHeq9tsiu0O10
         iRhQLZhGx2HktI5aBBGwUscIfSfdoI2IIfrdasF3VDoeE3v5NLqOABAskpveisKdoIBH
         NoCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=cWfjTtF3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id c19-20020a056a000ad300b006438069d21bsi192943pfl.1.2023.05.30.00.41.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 May 2023 00:41:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-565e8d575cbso19876247b3.3
        for <kasan-dev@googlegroups.com>; Tue, 30 May 2023 00:41:08 -0700 (PDT)
X-Received: by 2002:a25:b290:0:b0:ba8:2889:3b8a with SMTP id
 k16-20020a25b290000000b00ba828893b8amr1752504ybj.30.1685432468007; Tue, 30
 May 2023 00:41:08 -0700 (PDT)
MIME-Version: 1.0
References: <57834a703dfa5d6c27c9de0a01329059636e5ab7.1685080579.git.christophe.leroy@csgroup.eu>
In-Reply-To: <57834a703dfa5d6c27c9de0a01329059636e5ab7.1685080579.git.christophe.leroy@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 30 May 2023 09:40:31 +0200
Message-ID: <CANpmjNN1VWdwEVouVfPHZqYYszPNo=TbmXt6na9q+DuOkXY3xA@mail.gmail.com>
Subject: Re: [PATCH] powerpc/kcsan: Properly instrument arch_spin_unlock()
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, linux-kernel@vger.kernel.org, 
	linuxppc-dev@lists.ozlabs.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=cWfjTtF3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as
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

On Mon, 29 May 2023 at 17:50, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
> The following boottime error is encountered with SMP kernel:
>
>   kcsan: improperly instrumented type=(0): arch_spin_unlock(&arch_spinlock)
>   kcsan: improperly instrumented type=(0): spin_unlock(&test_spinlock)
>   kcsan: improperly instrumented type=(KCSAN_ACCESS_WRITE): arch_spin_unlock(&arch_spinlock)
>   kcsan: improperly instrumented type=(KCSAN_ACCESS_WRITE): spin_unlock(&test_spinlock)
>   kcsan: improperly instrumented type=(KCSAN_ACCESS_WRITE | KCSAN_ACCESS_COMPOUND): arch_spin_unlock(&arch_spinlock)
>   kcsan: improperly instrumented type=(KCSAN_ACCESS_WRITE | KCSAN_ACCESS_COMPOUND): spin_unlock(&test_spinlock)
>   kcsan: selftest: test_barrier failed
>   kcsan: selftest: 2/3 tests passed
>   Kernel panic - not syncing: selftests failed
>
> Properly instrument arch_spin_unlock() with kcsan_mb().
>
> Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>

Acked-by: Marco Elver <elver@google.com>

> ---
>  arch/powerpc/include/asm/simple_spinlock.h | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/arch/powerpc/include/asm/simple_spinlock.h b/arch/powerpc/include/asm/simple_spinlock.h
> index 9dcc7e9993b9..4dd12dcb9ef8 100644
> --- a/arch/powerpc/include/asm/simple_spinlock.h
> +++ b/arch/powerpc/include/asm/simple_spinlock.h
> @@ -15,6 +15,7 @@
>   * (the type definitions are in asm/simple_spinlock_types.h)
>   */
>  #include <linux/irqflags.h>
> +#include <linux/kcsan-checks.h>
>  #include <asm/paravirt.h>
>  #include <asm/paca.h>
>  #include <asm/synch.h>
> @@ -126,6 +127,7 @@ static inline void arch_spin_lock(arch_spinlock_t *lock)
>
>  static inline void arch_spin_unlock(arch_spinlock_t *lock)
>  {
> +       kcsan_mb();
>         __asm__ __volatile__("# arch_spin_unlock\n\t"
>                                 PPC_RELEASE_BARRIER: : :"memory");
>         lock->slock = 0;
> --
> 2.40.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN1VWdwEVouVfPHZqYYszPNo%3DTbmXt6na9q%2BDuOkXY3xA%40mail.gmail.com.
