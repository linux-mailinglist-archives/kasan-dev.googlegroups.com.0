Return-Path: <kasan-dev+bncBDX2TFNKQIHBBO7MY2YAMGQEVGT3W6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id B165589ACF0
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Apr 2024 22:53:16 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id a640c23a62f3a-a51cbc4cf1dsf3876366b.2
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Apr 2024 13:53:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712436796; cv=pass;
        d=google.com; s=arc-20160816;
        b=ejq66oObA+iKzfjg6giUALgp+st43YKx76nVm5xcVAg/WayWAWfWvLJDKIbPX3ROYl
         INJ6dOk1qX9PjCHQwPc3nR/AtajJjPERfG8deUOZ7Q5719NucRTAmxSu0QbxqIKSCAZy
         obGE93QAUHj3adEwa7si/3+PbcH0PVeag2K5zFm2r8HJoQjDGcpYZSk7vb7IOxsaZbfI
         2loOx4sPEvmVTWTkCrB3qxsIHhTq1mkHE1zZRRAAZCe8DXtJXytMSwHNeXAEld+FFtv4
         fxwlwfybuNtx+nrbhdi+jNhKawcdhTXSse5K3JXumpx1ySTSJWV7TdM758gCCLa/7aO6
         XO+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:to:subject:cc:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=bTFg64/5CZRofLABWQJwkuFi9wK5BkRTwryPQ0DME6w=;
        fh=SjGyWp9jAzwPUu2Fs9PZLkelES610HfNKxLmemsgYeI=;
        b=tP84toa2p+33E4wWtxfUp1HTdBrdtpMEgrhuNVhs/tSZMkW1BFU396VNRE12SK28XV
         eTeTOJBGURhW6/IXvZ9oCritRQvesyQk2jG26FWE8wCQryD1AUJc5vsu/fzG9ZFJnNSP
         YAHStAaEN0Ekc9ld1BWV/fRVPIc94qZq/Nrd02IMM2hDcbXyxIghx7i5XNp11onaPa2L
         rTKNfImTWmWqvlTZDZAsFlnHZqaJYE25H9/41XJNq7XDGlXQ6ABhAzUMKe0aDP9j3rMu
         HaUkx3Lbcpz0QuIV3yAWJJQKQJZa+rIEwuQXAXQ2Xf6jA+eDF8O87JfMmPhWCD+Nf1f4
         CNBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@collabora.com header.s=mail header.b=rRHpjH2t;
       spf=pass (google.com: domain of usama.anjum@collabora.com designates 2a00:1098:ed:100::25 as permitted sender) smtp.mailfrom=usama.anjum@collabora.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=collabora.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712436796; x=1713041596; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:cc:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bTFg64/5CZRofLABWQJwkuFi9wK5BkRTwryPQ0DME6w=;
        b=JXczUB50bmuuNhQEIncMAfj/UtBdmLia6y8OtK/6r6LeOqzKnCaEVe9DR/YgO1EipX
         ROxkdaBS8XrAr/eZG9mlk5kC3me1+cunca7bvthjzaJA+kDYy6n1+1BDMlrV7F6i24Dz
         G9rwxs6/rh8cdYl+LN/OmPsMat+BN2hMmFDfO7Yny0s02EDnbmark1q2cf10ydiv5yA1
         gK98uOAwFKj1/KrRSdI1YE3mzUQvAMtiRXOcPIwrTQu2ShRC7qrGZE5Ca50hAi2vXFvW
         iNvTGcWhEq2LHNnluq6Tqr8/aa6laKOrAQrmghxNDOgGVOsi8Qke/jzlaurda267X3ls
         IpuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712436796; x=1713041596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:cc:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bTFg64/5CZRofLABWQJwkuFi9wK5BkRTwryPQ0DME6w=;
        b=t8UQfPtSaWBTOP4JoNov3qh3NQR0e4o2syZuojMiAul5HGY0H3jc+feaA7JiLYDuql
         X3coctojJHeqvslMWwTIm16F5HLoO70mE5RSO1BAN4ijAHVhXwLBlvUCpOMPQRMCTvwT
         FidTgk/ywm5utIdmLPmFKNqAW2xLHn3HgpXxqVSdaXUkdRfwPfI5Kc2aFeGafkOSwiRK
         4iaFnutGYIQFJejiZeb5U2lfduCVLpA932SeLBXctAHMFpljxiCElknLqbo7FRr0ambs
         LtH7J3W2iCFCFNTeHDxqLFx0FHwSh5qpbiK8WnC4ZoJGwerGQbzSH3g6usKJ62a1rwxI
         SExA==
X-Forwarded-Encrypted: i=2; AJvYcCU5r7HfMXtSCXEY8PfEG1NHdKk7eHYb9c/Y3yr3YEyLNFMvdlh/Hoyo4E2b8lVFmw8GbG7LZwxiZWRh7k4drewk615EUZDe7Q==
X-Gm-Message-State: AOJu0YzQMWaVHgKx5HgrmDre348Y32APIUmg7fPMxjpzO2kcpH2D+xjm
	AYBSikP5l1QHZtCmEOoDF6ZDMKZZEwc/wdlNIC2JiuKoPZx9SCHX
X-Google-Smtp-Source: AGHT+IEfk4iYVpqcMbBMvK7f1qjX/sQrqnSWwjFnUVMwAp0SaVPLAPUQZL1v1x45LCX38wZ3SUhp8Q==
X-Received: by 2002:a50:9f4b:0:b0:56c:5a72:176a with SMTP id b69-20020a509f4b000000b0056c5a72176amr4068614edf.3.1712436795751;
        Sat, 06 Apr 2024 13:53:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3899:b0:56e:1e81:e8cf with SMTP id
 fd25-20020a056402389900b0056e1e81e8cfls65404edb.2.-pod-prod-07-eu; Sat, 06
 Apr 2024 13:53:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWcnLOhmN19jwwLwQgFPChdhIYCx3OG8V1Qdfq1TY/UE3p/ZPOBFItM3NSZJDr0qAJgdo6cPJcZmneFuuCJ6iLat7xxVCCz2abMrw==
X-Received: by 2002:a50:d5d5:0:b0:56d:c722:93a3 with SMTP id g21-20020a50d5d5000000b0056dc72293a3mr3936501edj.21.1712436793414;
        Sat, 06 Apr 2024 13:53:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712436793; cv=none;
        d=google.com; s=arc-20160816;
        b=hrRA8/3Jj628I8eXnUgIiqPkIzAq93v8Npqybb7Wd+Gj+OPGG3MVj9c9Yf8EsEWNJF
         6QroIUTNnXsc5bhNHxE4SFQYKN0qkjsaZcIl9vIwe5sXoIHMVmsVpk4XFxtUkmMCyFxO
         2aKmGBB82PoVw9kKbbuah3lY+GKaxEmdzpXLdEDRPusQGAjUDMhSHkLEyg6lAlH4oTtC
         Fpf/qlSpXniRfsHTn3/mc4/Wd8rBeN4vAloHEyWVW/svgDaqZQZGSLhUA2iZpkfYAOkO
         TwqaC7m/GK5+iYrPotaBriz2BPdz8TNJgMePFSiRj08ehRfTyfyYzdDsXQeJOZxkeyfq
         zaEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=rzg8JtxyHSzcHkBIGtTmMqVM3MIxkgLWpGzsrxYXkHI=;
        fh=PJ8COFmZmRCQxQGertJpXeF/Quc5YaXD7AnUzE5i0Wg=;
        b=rwxDgMvKXpsExHNME2LUYY22Y02WAKBfKtJRtO014TIQFofdF1Inlp8FCl98PFCIj4
         /am3QUhxB5xZZv4kfY7AqdzAqY6/nnN0FXsrXQSlHEIwwk01Z9DIkXbtCiD0xdLpX3LV
         Atk10qNdYOscemwZJgK06F9g/DxWmbjyjO8tqyrT4Ox2blzcRGHELVnH3YrWwaO5Jxjm
         F5MDzEHietI0ga2zR3C2WlxDQL6kHA/t+1w7LCOC/t8BKQ8mhKhtzZQUx/K1nXvINs2n
         KQKvz1kkeXWR8biiajR4zhvcTMmrNFkvvg0tpkPU7LxM+Ea8SoFhNsBc2hMhz7zqj4hS
         yCZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@collabora.com header.s=mail header.b=rRHpjH2t;
       spf=pass (google.com: domain of usama.anjum@collabora.com designates 2a00:1098:ed:100::25 as permitted sender) smtp.mailfrom=usama.anjum@collabora.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=collabora.com
Received: from madrid.collaboradmins.com (madrid.collaboradmins.com. [2a00:1098:ed:100::25])
        by gmr-mx.google.com with ESMTPS id y14-20020a056402358e00b0056e23a15716si94094edc.2.2024.04.06.13.53.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 06 Apr 2024 13:53:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of usama.anjum@collabora.com designates 2a00:1098:ed:100::25 as permitted sender) client-ip=2a00:1098:ed:100::25;
Received: from [100.113.15.66] (ec2-34-240-57-77.eu-west-1.compute.amazonaws.com [34.240.57.77])
	(using TLSv1.3 with cipher TLS_AES_128_GCM_SHA256 (128/128 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: usama.anjum)
	by madrid.collaboradmins.com (Postfix) with ESMTPSA id 2444037809D1;
	Sat,  6 Apr 2024 20:53:08 +0000 (UTC)
Message-ID: <46ad25c9-f63c-4bb7-9707-4bc8b21ccaca@collabora.com>
Date: Sun, 7 Apr 2024 01:53:40 +0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Cc: Muhammad Usama Anjum <usama.anjum@collabora.com>,
 Oleg Nesterov <oleg@redhat.com>, "Eric W. Biederman"
 <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com
Subject: Re: [PATCH v6 2/2] selftests/timers/posix_timers: Test delivery of
 signals across threads
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>
References: <20230316123028.2890338-1-elver@google.com>
 <20230316123028.2890338-2-elver@google.com>
Content-Language: en-US
From: "'Muhammad Usama Anjum' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20230316123028.2890338-2-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: usama.anjum@collabora.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@collabora.com header.s=mail header.b=rRHpjH2t;       spf=pass
 (google.com: domain of usama.anjum@collabora.com designates
 2a00:1098:ed:100::25 as permitted sender) smtp.mailfrom=usama.anjum@collabora.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=collabora.com
X-Original-From: Muhammad Usama Anjum <usama.anjum@collabora.com>
Reply-To: Muhammad Usama Anjum <usama.anjum@collabora.com>
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

On 3/16/23 5:30 PM, Marco Elver wrote:
> From: Dmitry Vyukov <dvyukov@google.com>
> 
> Test that POSIX timers using CLOCK_PROCESS_CPUTIME_ID eventually deliver
> a signal to all running threads.  This effectively tests that the kernel
> doesn't prefer any one thread (or subset of threads) for signal delivery.
> 
> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v6:
> - Update wording on what the test aims to test.
> - Fix formatting per checkpatch.pl.
> ---
>  tools/testing/selftests/timers/posix_timers.c | 77 +++++++++++++++++++
>  1 file changed, 77 insertions(+)
> 
> diff --git a/tools/testing/selftests/timers/posix_timers.c b/tools/testing/selftests/timers/posix_timers.c
> index 0ba500056e63..8a17c0e8d82b 100644
> --- a/tools/testing/selftests/timers/posix_timers.c
> +++ b/tools/testing/selftests/timers/posix_timers.c
> @@ -188,6 +188,80 @@ static int check_timer_create(int which)
>  	return 0;
>  }
>  
> +int remain;
> +__thread int got_signal;
> +
> +static void *distribution_thread(void *arg)
> +{
> +	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
> +	return NULL;
> +}
> +
> +static void distribution_handler(int nr)
> +{
> +	if (!__atomic_exchange_n(&got_signal, 1, __ATOMIC_RELAXED))
> +		__atomic_fetch_sub(&remain, 1, __ATOMIC_RELAXED);
> +}
> +
> +/*
> + * Test that all running threads _eventually_ receive CLOCK_PROCESS_CPUTIME_ID
> + * timer signals. This primarily tests that the kernel does not favour any one.
> + */
> +static int check_timer_distribution(void)
> +{
> +	int err, i;
> +	timer_t id;
> +	const int nthreads = 10;
> +	pthread_t threads[nthreads];
> +	struct itimerspec val = {
> +		.it_value.tv_sec = 0,
> +		.it_value.tv_nsec = 1000 * 1000,
> +		.it_interval.tv_sec = 0,
> +		.it_interval.tv_nsec = 1000 * 1000,
> +	};
> +
> +	printf("Check timer_create() per process signal distribution... ");
Use APIs from kselftest.h. Use ksft_print_msg() here.

> +	fflush(stdout);
> +
> +	remain = nthreads + 1;  /* worker threads + this thread */
> +	signal(SIGALRM, distribution_handler);
> +	err = timer_create(CLOCK_PROCESS_CPUTIME_ID, NULL, &id);
> +	if (err < 0) {
> +		perror("Can't create timer\n");
ksft_perror() here

> +		return -1;
> +	}
> +	err = timer_settime(id, 0, &val, NULL);
> +	if (err < 0) {
> +		perror("Can't set timer\n");
> +		return -1;
> +	}
> +
> +	for (i = 0; i < nthreads; i++) {
> +		if (pthread_create(&threads[i], NULL, distribution_thread, NULL)) {
> +			perror("Can't create thread\n");
> +			return -1;
> +		}
> +	}
> +
> +	/* Wait for all threads to receive the signal. */
> +	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
> +
> +	for (i = 0; i < nthreads; i++) {
> +		if (pthread_join(threads[i], NULL)) {
> +			perror("Can't join thread\n");
> +			return -1;
> +		}
> +	}
> +
> +	if (timer_delete(id)) {
> +		perror("Can't delete timer\n");
> +		return -1;
> +	}
> +
> +	printf("[OK]\n");
ksft_test_result or _pass variant as needed?

> +	return 0;
> +}
> +
>  int main(int argc, char **argv)
>  {
>  	printf("Testing posix timers. False negative may happen on CPU execution \n");
> @@ -217,5 +291,8 @@ int main(int argc, char **argv)
>  	if (check_timer_create(CLOCK_PROCESS_CPUTIME_ID) < 0)
>  		return ksft_exit_fail();
>  
> +	if (check_timer_distribution() < 0)
> +		return ksft_exit_fail();
> +
>  	return ksft_exit_pass();
>  }

-- 
BR,
Muhammad Usama Anjum

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/46ad25c9-f63c-4bb7-9707-4bc8b21ccaca%40collabora.com.
