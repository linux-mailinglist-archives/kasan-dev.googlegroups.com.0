Return-Path: <kasan-dev+bncBDBK55H2UQKRBYEXRW4QMGQE4FINTHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 75FBF9B774E
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 10:20:33 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-539f067414fsf396827e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 02:20:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730366433; cv=pass;
        d=google.com; s=arc-20240605;
        b=bpnxYrfRLl/9EnxkpRSf6sEZFmcM1TJXQTVuFAdzi8gpaCYK3/Fdt4QMSwTfqWIy6a
         QaQ6KgyiZiVaA2atllRixNsVbxCyjIXP51/pXTjTrinpoWeoSGJqhKOAXy4WfYflS+lG
         fgO53Auoefj/YN9AXRToalj9iLAUQxlQwBOwou8iwOQew6N6Yy+EpjFAkkK96Iz2lGdQ
         Jl0E93KPX7CBxNoxix3RsXAeFGrCCO40PG7KQ3LFxfI18U6zWtQ2CE6CpfAEaD0of9kV
         ew52kRmlo/M1h/1Lziuf78ZVHkXhLRpn9v4NYwu4RZi/MsZ8dAfdx0gfIAz8IDDBJSL5
         /Eqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tvZmyTBegN9wwGvVuVcxU0LhPUjX4yErmLqlDD2zvdo=;
        fh=gYQD6EUbugnUP4XhTmq95P6CB7sG17Eot+NW1WELv3Q=;
        b=XQNl40kjvzaNsctL4aluGOt9pzfYJIhIkBMjImgZqnDbWW/0IzFJtIqs9jqw1wekip
         AwDx5HPBkFdtwoeeCXD9uwpTY5J1K7bhgaYMnkdSOq1U6wg85jyjhovCxfmrcIahcDhL
         JajxDZ91J8q81TF3DchUvqTmCau+93gjd01D507exd9CsCF5gfvjoJkanEs2ygd2VYqb
         nEtCpbL+mv5XMpgzSXsuef3IxX5nwZ1Ekx+OWDMy2r+Yjdj2QRUKe1GIv8ySaXG+T/bh
         Uv6BS0E23zicH2xotd7S9UeHtx9VL9jB9zVaE/jsf9CNvIzzCfDMB+FFp2ZYrvM1e9vF
         KynQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="E1w/a6LW";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730366433; x=1730971233; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tvZmyTBegN9wwGvVuVcxU0LhPUjX4yErmLqlDD2zvdo=;
        b=e2t9bJjG2u5xmxxk8vP2b0s6wlm3PJwSZXBkDOx6IRj1vNzd49tRyJtFhU2ciPiH5Y
         Bf8nuUZ1r02ytPg1ZPta8+eDEjyRgAOEOA+NldiTIKZMpeqKEWsEEzM+B1Jl3Zk336aX
         hU1gk3xdFhf8/Me3rCrJr2PflupEGfU0qe4JGyJxCAbV7vtR0rmRsy0u+ibFqKD82rJd
         N0ZKP6fvGkE9F1YQ0C+KKKNtt7615cVaLg8LsYWtNiznVBdRRwKL22+F9eNyAqjDI0fk
         tdMvuSbTWx0+7KA4KmqNMMznDzK/MB9URnSzVsb0L+klKEpixVbAX1cuDrz3TXS1iftF
         chCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730366433; x=1730971233;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tvZmyTBegN9wwGvVuVcxU0LhPUjX4yErmLqlDD2zvdo=;
        b=fIhXAae6+C7zZOLpB+vIzVlWdIwUIZzyzoyDLZqJq5Ja9rAj4K8WUI7Cx8qwtUKe/b
         /bBaSEWRGAI9OeRDDTQTrqATlrYPcjVrz/ogNBQ9AXP7fq59H71HQh6yBJnlTyeCmeTB
         C3D6ErXwhznpqyRImdr3E/vpfIxrYWa/PSYD8b5lCgGkKXgUO6whLV6fj0LBsG+pYl5P
         URvY9zxL6/pOKk7Yz/KKS/LfnXuYXI9Bfr/whS5nRXFTMWfkYR0dHr1E2YDPlQ332nJX
         lBWnFAepnjrIGd82G7eOA7iHSViyWuSoJILa48dokfiBoATPJRWKGZQfW5P1FHhwzyCk
         v5WQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrCOu6vRUBJ8RqXFuCIUqZzYgkS2G9Hi1hheVvEL0tGXnF8mAjUuqA8zDG0K0IhbZKHclmrw==@lfdr.de
X-Gm-Message-State: AOJu0YxNB8+MuDjUXmkWf+Adb2QumM2MrvXpWugysEmGmAi9M1QGS/1y
	IuG6MxGx3Rk/mTWTO6SlzzSYqHh6kW1By5sn7xutVqLmi1ZsE1im
X-Google-Smtp-Source: AGHT+IFv2F05KpEY153RLzL96uN03kxqdbCs62JAojXjfG6uYa1f/WcMEMtRbfYsnArEF4/2dAndZQ==
X-Received: by 2002:ac2:4e06:0:b0:52c:fd46:bf07 with SMTP id 2adb3069b0e04-53b34a2e4d0mr7870634e87.49.1730366432409;
        Thu, 31 Oct 2024 02:20:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2803:b0:53c:75d1:4f0e with SMTP id
 2adb3069b0e04-53c79502c1dls207162e87.1.-pod-prod-07-eu; Thu, 31 Oct 2024
 02:20:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAsrW5+muPuHCDq5ksdc1A4dr9RjrCngXlszvrUADbTNRs9/4t/vefZ/Nf6vgBgpQz4ZWEKyrvxCM=@googlegroups.com
X-Received: by 2002:a05:6512:ba2:b0:539:968a:9196 with SMTP id 2adb3069b0e04-53b34a2d6e3mr8649611e87.48.1730366429837;
        Thu, 31 Oct 2024 02:20:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730366429; cv=none;
        d=google.com; s=arc-20240605;
        b=BF1cDMwmaNaW+fdzaKBwf+x4NAPb+Cume2BmA316aO+TuQKrG9cQjKbH8qedYwECJq
         +LF6LmbrSsYgYm9b/566QjkP9eFu1AFqW2Vc/zQzAZAZ3JRvV2B5w/7KpqBNTLQ3X9KY
         SSkyoujav3LApD/mFZ+RgdJ7tz+h0wb/mRSMvEbf1ANigXdz3OrQ+BAEWI6P0mKymMSy
         ay6FqslLf6RedD8547G7mnjn78O7+Z0Yk0nThuIp2VEj8AyLmWmyXrYD4X1wI1uk8asJ
         zZ09eT0fFyVagPWX+wPxIsohMlrQiwHW+/ltVU/xaYXuBjY5HxP2Ie9BSVhe9P6aYQtD
         D0/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1q52zKliJkMThvPumU3SPfBPY2krJYFtdl0Hl6uLP8c=;
        fh=rsYLeNn3EhqnY/ERv90DXt1NYQkHGuhFKomDG1eXtr4=;
        b=jkBVHXXWn6zlTozAoAj8urlL7XS9nS+C9LdUaPEeFaH/b3JInd6S4BYxGdwBDaacpL
         SGna6/Aecfo6Rf+6ebz96DFPBevZ8s9/EKdHGSJSnFG9fxEKI79JmOj98N7u0kcdkcur
         kPVV9g+bilYyVxL13jKDMd6GzJChMqxUw01HXFWeJyNkiZJumzanhElScTeVJmRJPrmV
         Biti5xrdVRMxEsCEfSvNe8YMF9yED3MFVvXaWOQRL2ahDMEqijMkqFVffTkvBwILEmXD
         MJGv2XPa6GO+619z0Cfb/IWxwCCadvMDzfoYL7loPLvm/dodNbO0muqukSV9+wV4onx7
         NlHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="E1w/a6LW";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53c7bdcbe5asi21765e87.13.2024.10.31.02.20.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Oct 2024 02:20:29 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1t6RLu-0000000EWbk-2fUW;
	Thu, 31 Oct 2024 09:20:27 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id D573D300599; Thu, 31 Oct 2024 10:20:26 +0100 (CET)
Date: Thu, 31 Oct 2024 10:20:26 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Alexander Potapenko <glider@google.com>
Subject: Re: [PATCH] kcsan, seqlock: Support seqcount_latch_t
Message-ID: <20241031092026.GU33184@noisy.programming.kicks-ass.net>
References: <20241029083658.1096492-1-elver@google.com>
 <20241029114937.GT14555@noisy.programming.kicks-ass.net>
 <CANpmjNPyXGRTWHhycVuEXdDfe7MoN19MeztdQaSOJkzqhCD69Q@mail.gmail.com>
 <20241029134641.GR9767@noisy.programming.kicks-ass.net>
 <ZyFKUU1LpFfLrVXb@elver.google.com>
 <20241030204815.GQ14555@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241030204815.GQ14555@noisy.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="E1w/a6LW";
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Wed, Oct 30, 2024 at 09:48:15PM +0100, Peter Zijlstra wrote:
> diff --git a/kernel/time/sched_clock.c b/kernel/time/sched_clock.c
> index 68d6c1190ac7..4958b40ba6c9 100644
> --- a/kernel/time/sched_clock.c
> +++ b/kernel/time/sched_clock.c
> @@ -102,7 +102,9 @@ unsigned long long notrace sched_clock(void)
>  {
>  	unsigned long long ns;
>  	preempt_disable_notrace();
> +	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
>  	ns = sched_clock_noinstr();
> +	kcsan_atomic_next(0);
>  	preempt_enable_notrace();
>  	return ns;
>  }

You might want to consider also folding something like this in.
That should give this instrumented version instrumentation :-)


diff --git a/kernel/time/sched_clock.c b/kernel/time/sched_clock.c
index 68d6c1190ac7..db26f343233f 100644
--- a/kernel/time/sched_clock.c
+++ b/kernel/time/sched_clock.c
@@ -80,7 +80,7 @@ notrace int sched_clock_read_retry(unsigned int seq)
 	return raw_read_seqcount_latch_retry(&cd.seq, seq);
 }
 
-unsigned long long noinstr sched_clock_noinstr(void)
+static __always_inline unsigned long long __sched_clock(void)
 {
 	struct clock_read_data *rd;
 	unsigned int seq;
@@ -98,11 +98,16 @@ unsigned long long noinstr sched_clock_noinstr(void)
 	return res;
 }
 
+unsigned long long noinstr sched_clock_noinstr(void)
+{
+	return __sched_clock();
+}
+
 unsigned long long notrace sched_clock(void)
 {
 	unsigned long long ns;
 	preempt_disable_notrace();
-	ns = sched_clock_noinstr();
+	ns = __sched_clock();
 	preempt_enable_notrace();
 	return ns;
 }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241031092026.GU33184%40noisy.programming.kicks-ass.net.
