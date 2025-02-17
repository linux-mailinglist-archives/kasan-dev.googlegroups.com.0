Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC55ZO6QMGQEICO5MWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E165A37BB7
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 08:00:29 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6e64dac8126sf61494406d6.3
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Feb 2025 23:00:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739775628; cv=pass;
        d=google.com; s=arc-20240605;
        b=TUsOBMvy6p2Xo0xyCsDnAS2rRf9gHLkHExcWKWH+oQUAsfKgrkxcwoH3cP+9n0/Q2g
         E72CkdBxLkIWj7lZcrW8XQh/B2ntqZg+TPsb6y16/mccqJgXVWQ5VHnzGjicrPhfzSNk
         p0llhBugt4Ko0DuCiDj27Wa1pl+9tgs4AsM9RUhkWFKbevsNxqFJ2O20kywDyUKr3UVK
         r2DawJe7bS/EHaed0F5R19JbVMUaYcKSnmmjYrhFHEF4LZfb1b015o3OC58HPC8AQ+Ik
         QwQWv7Foi5G7iZJO0fYvQOx9EeMD3CuMatzsrvU+hqwdK68nMX1Km2kOjFPuKlhur1C0
         zFZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5wvzgVmsBn8vDh6681PAZJm0pHvA6iFSQayuNtikHVw=;
        fh=yHN0mzJGqju92H1LZSa30/en22IRgB89Nwq+F9bj/u4=;
        b=ZamC0iBKtslfbGEcczsUtcz/0DY7nUaVBS8JYa0/W7XOBNUo9/iEVgM2+nr1WgqBFp
         zm/NYzoKaM6+zRX1f8U2IsBe/TOikxEzTmibJVshdY3ca8hZT0X2nrCxLIVotrk9jPIg
         3KHSh0bY+GN3EM0Smz1xqC4wPBNYx9hth22mpTnGxep2Zi4uVlyE32/vVTNtLL6XiaQ0
         rDswPB2Rwkfnv+56cYJTX6klgxfWP2bGQiGXE6lG1hECuSBRVr9MDcwwATf36jlAkp+2
         To3kTHcG7va9HSK/1z8vgBmlo7bPrV1hI2Iq6TFtdOLUtYaBI8tksI2em/m10OTYpo0j
         AXyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=T7bEGE55;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739775628; x=1740380428; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5wvzgVmsBn8vDh6681PAZJm0pHvA6iFSQayuNtikHVw=;
        b=JVHh07j8Zf6ovi3uY7HC2PU9eJquZ70Jqnx1vgFuPv14F50Jkzk2zWbzgat04iU9sn
         BTSA/KgHaTgLC/ghrHSbFZtZultlFgDhMfoSsJa66OCsv2/mcDN/7+NJIBmql0OcFeNe
         F7Yppzi1fcVTV4dRFkE1zgM1k0lkSe3t/eWXhCn0d2t3RNjK7nJ7dhW7cwKt+Fap1O06
         c2wPQBjGj82Psqca/r7K0tplHQGAlaFIe+E0zxTNJkZR1sVfgR5sCK7eL3hu76hLjJtF
         t/mOsIhElAbXLEQcGPpzjNzoMRc7Ao8n6o8d+U3MSkkqLwKNHSxLiMeOcA/QAlg1rzlV
         A9aA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739775628; x=1740380428;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5wvzgVmsBn8vDh6681PAZJm0pHvA6iFSQayuNtikHVw=;
        b=LTDUlY7u19Yo3e/NnCRppiZPRSmU5A3G5XuD62okq7+P6Tv0VlQkwxT5TG8SwMoknh
         LqzAt+0eVrejWjaUMohql2I8gA4QlOhnqKqKOn68zF3GbXvfWRN2T/TcKOH0lXR7avN5
         dCk+hFVJuAKbRhI2jdiJQHeeIPmrM2niLqjSc5bD02dPQESxTspMQ/Pph0xEbpffJNUr
         946onWBdJWUnhunhB/P1kmtQbzumHW/TU2F4SfpFrM7fQn9ULwsxyr4vCao5NLmYBtGj
         AdEhgtpZhKaxHMTtzmXD7K1cDbuG6W5z7Uin8PS9OGZfASPej4bfC/yiy7qxrB5TDDte
         iDyw==
X-Forwarded-Encrypted: i=2; AJvYcCUnUIIN912/X6DEO6TQNfynk1hwu7jpkG7CeF7J5wHwA5IzJ9P90LafrwoHOlUOSiR1jClQTw==@lfdr.de
X-Gm-Message-State: AOJu0YwFfGfMdVlDy6IeTZwRu6PirWX2nqkytOYHpmAGiottrEx8olzE
	rgKcpoPruJJvp3HgJKZxo3VcTFouJPM2HKqew79I232Y2NIYhXVp
X-Google-Smtp-Source: AGHT+IHU1lddpCGTGQJzQR8mBigey/kAo4aEsHYghc5luTSMvctPm1WOWPe+7CwhFswWUxD4G/BdWA==
X-Received: by 2002:a05:6214:c4b:b0:6d8:8256:41d4 with SMTP id 6a1803df08f44-6e66ccc47a6mr133232766d6.19.1739775627812;
        Sun, 16 Feb 2025 23:00:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEFII2nTyiB95gmbBOlSc5VjZ6wGWK+k3C5bGPExRdxCQ==
Received: by 2002:ad4:5e8b:0:b0:6e4:8bc3:c15d with SMTP id 6a1803df08f44-6e65c281cf7ls12240906d6.1.-pod-prod-01-us;
 Sun, 16 Feb 2025 23:00:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWlGpvuWTCvUIt7SfSRHrNDmEjNJzZmKGa8kbsSOQrrQn4FsHYI6ZL5Uhg65wbOkCvgouivbPzzb48=@googlegroups.com
X-Received: by 2002:a05:6122:2881:b0:520:535e:89f2 with SMTP id 71dfb90a1353d-5209da97468mr3253861e0c.3.1739775626700;
        Sun, 16 Feb 2025 23:00:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739775626; cv=none;
        d=google.com; s=arc-20240605;
        b=RcyzUbLVF0QvnvKw4SEHu7C8ajUX2YqQcc8Ugtosp9B1VRgHLFuOp9x02Nbpjo1lFJ
         7JlPFeh31xSAXzSMg8xglgfOzJ95W48Sy5tAciyEso3ayjKQn2a7+SYbr6B1OHVXN0YK
         pPJTuAPCwrKdfHbPTchHf+k0b/bn1zkoZL6QXVW6uVnuv4KNwUipc1tdfl3ReO6oJkhP
         yxz2oMLt+tA9Fh6CUZZ+IV51IHOZJN2gPRFnrOHgLW0+wzkOMcc1RefNb5ejCaa6QEPS
         ttns4k+6ylvorRS2Jb3gp0QP1nkq0nfQid1EkAq8STTh3c3C1UOEf5ff6L+GYEUbsaSj
         4Q+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S/kidt/+m/QUXKGxp/hFK00u7EvOABsDl7T7sblEpXY=;
        fh=jHKSYZBBF7FAERz9Zn2z02Sk79+D4D9EBpaAXGSHrBE=;
        b=Q85YZ4/NN876cpUdH4iWvfYlEa2GO0SV5ahC+SY40E/t5IKWrTuUcVLdF6N4XxR2+1
         1WspkYKN4lZpfBbex8+I9c0BHExJx+hIqG2BNfvY1Bbjt/f0BEerXoGXTA2EjPMdGOco
         lmw03AWgHiuCbmzIwNvve0G9z9FzDcv9jLDbTmMqHMuJ+M8aGVV/MDkGiBiZKV4w9+4v
         6+ndVI25TO/TikJepih4l45L6G5cIdHxdqGO8ZinOuM2yQUiwZBAp5y5iLm4m5hRMeat
         ZlqaPNgNgXBeyc7HXv70zXvzNO/aux+fyXHncQLeKFHDT5aC5OaMIGAvrV6gpfLlZHJg
         Cz4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=T7bEGE55;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5209d09e834si217054e0c.1.2025.02.16.23.00.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 16 Feb 2025 23:00:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id 98e67ed59e1d1-2fc1843495eso5011586a91.1
        for <kasan-dev@googlegroups.com>; Sun, 16 Feb 2025 23:00:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUCFm/TXaePLRaUwnLNBPRNrVbAZ73oGwUiPg6mC80AUslZS45IFkF89A7SvQQWdXtI7CX0A8ffaPw=@googlegroups.com
X-Gm-Gg: ASbGncu0pciD8XXDZItf41ytkVBzuUS5hfltzAjGxIaSkvwdgYJDhDCsSiflFbbPv53
	maCqNKPPHAXlf9Lbk0uNC/0b3m8Abmrz7mR1ErWwsK3gdOYcnBxGrcqvkdueYjkK0U+E5ajb3H8
	WhgCkxP/TezKDDEYCpOOfP8p5lA0Do
X-Received: by 2002:a17:90a:ec8d:b0:2fc:3264:3666 with SMTP id
 98e67ed59e1d1-2fc41153decmr12093928a91.30.1739775625488; Sun, 16 Feb 2025
 23:00:25 -0800 (PST)
MIME-Version: 1.0
References: <20250213200228.1993588-1-longman@redhat.com> <20250214195242.2480920-1-longman@redhat.com>
In-Reply-To: <20250214195242.2480920-1-longman@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Feb 2025 08:00:00 +0100
X-Gm-Features: AWEUYZkyCYAFeX-s3finstA3GzhMKKZ63CjP0dxLIlHJtFCqcCRgDj5s5rXnCbc
Message-ID: <CANpmjNOMnSXGBUWyycUziKcxcN=Vb5_qvyrrATHZoKgVacpAgQ@mail.gmail.com>
Subject: Re: [PATCH v4.1 4/4] locking/lockdep: Add kasan_check_byte() check in lock_acquire()
To: Waiman Long <longman@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will.deacon@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=T7bEGE55;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102a as
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

On Fri, 14 Feb 2025 at 20:53, Waiman Long <longman@redhat.com> wrote:
>
> KASAN instrumentation of lockdep has been disabled as we don't need
> KASAN to check the validity of lockdep internal data structures and
> incur unnecessary performance overhead. However, the lockdep_map pointer
> passed in externally may not be valid (e.g. use-after-free) and we run
> the risk of using garbage data resulting in false lockdep reports.
>
> Add kasan_check_byte() call in lock_acquire() for non kernel core data
> object to catch invalid lockdep_map and print out a KASAN report before
> any lockdep splat, if any.
>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Waiman Long <longman@redhat.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  kernel/locking/lockdep.c | 9 +++++++++
>  1 file changed, 9 insertions(+)
>
> diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
> index 8436f017c74d..b15757e63626 100644
> --- a/kernel/locking/lockdep.c
> +++ b/kernel/locking/lockdep.c
> @@ -57,6 +57,7 @@
>  #include <linux/lockdep.h>
>  #include <linux/context_tracking.h>
>  #include <linux/console.h>
> +#include <linux/kasan.h>
>
>  #include <asm/sections.h>
>
> @@ -5830,6 +5831,14 @@ void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
>         if (!debug_locks)
>                 return;
>
> +       /*
> +        * As KASAN instrumentation is disabled and lock_acquire() is usually
> +        * the first lockdep call when a task tries to acquire a lock, add
> +        * kasan_check_byte() here to check for use-after-free and other
> +        * memory errors.
> +        */
> +       kasan_check_byte(lock);
> +
>         if (unlikely(!lockdep_enabled())) {
>                 /* XXX allow trylock from NMI ?!? */
>                 if (lockdep_nmi() && !trylock) {
> --
> 2.48.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250214195242.2480920-1-longman%40redhat.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOMnSXGBUWyycUziKcxcN%3DVb5_qvyrrATHZoKgVacpAgQ%40mail.gmail.com.
