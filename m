Return-Path: <kasan-dev+bncBDX2TFNKQIHBBR76Y2YAMGQEI55C4HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D70C89AD10
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Apr 2024 23:31:53 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-344035328d9sf197374f8f.0
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Apr 2024 14:31:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712439112; cv=pass;
        d=google.com; s=arc-20160816;
        b=JbSX8obg/ALUvM3IiJvPAA8GX+8vGCMTIzPdKxMjE0aIlTPlgKsx8yVeDwQ94vPQYJ
         nAMTvkDlT4GqnLGmClzn6x1rxwxgFFEoaj+fxdh9abrzguYO5CLhhirjbSWyw2yFR/+f
         KBIGdJ8aodDYEGb2WnSSX/NgCG8zVox3onAQsW85AKIcAGVoazbdTY8cw8p0Lkn37L45
         bNccuRCKk1WrT5aLHtTE9hYwOlytaYONe+MIxW0UqgQpoKe8f3uNrPG4YObMruJdQQPr
         jam9vaxlRl6QDxG6NDkWji3XSKcS24vyvzYc0oQ0Sh+XmxV5k8+fU3qUtgR7NUr57rrn
         ia7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:to:subject:cc:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=zdIRwHZ7JXofPAlRmtHHbsWEHLFacn/DTnMnSo44K7s=;
        fh=9Ec/7OD7z6ZGDjQrGoO4gxBa6DbkOwFFDczYmuqad+o=;
        b=I3VsmFPmcVQ4lERmrCaNo6N5f3wN4Q6vAA6gfVUfKpKSu8r4+Z/5Pa5WIdn31I8/PR
         AzwkdS+TQjrF0/uDqrDrsb9SX1TVx+0iRg1GzfVVfwVinimJI4XcRl6EHfaQjhVh6t1T
         YfKU+q60NMum8/UzKv+LIKW30MT7y311pyHvnJVzdHLA5c3bxqOufedPwZFGSIoq6P05
         Rs8P7+lW1+yhMXgH/jJeCsaSXEZllZJkGmc9jN8mk4ItwM0ofv8z3P0884pdyWcH5H3R
         P8cZPUHtEGWRcFVGCNzHiCxjZGMVUEUiSd9hHnbBJ+laRqiH1B+WkLfR95aN8+jFRaWn
         iOsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@collabora.com header.s=mail header.b=CUxgIwux;
       spf=pass (google.com: domain of usama.anjum@collabora.com designates 46.235.227.194 as permitted sender) smtp.mailfrom=usama.anjum@collabora.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=collabora.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712439112; x=1713043912; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:cc:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zdIRwHZ7JXofPAlRmtHHbsWEHLFacn/DTnMnSo44K7s=;
        b=vg4O7qToczA+oaA5EuqVTQeB5koWRB+NMvT4PXG9uhfSGtEHcIq4s0OLtGbDAKDcbX
         c1CVjI4cWOSP13gCE+454T8BvppvY0GHTZDnK0KlMEh0q5XxdFg8qwtX8qpbdC9BfR9u
         sItxXTLecrqAi980voHd3BTEiKFjWOKtDwdsrD5G032qQGfI+qKhwTySJc96Ej4miDbz
         N3D9eqCMfMz/722r8gAIjP0gl+yC+RXNs+BT8z8xajVUFnPEAjYnCF/HuATGTYNwIzJi
         +6gf9fDOGUIGdmeAcCplQUGEOKYczJZ+sBjdWS3V6G/hAIC5OiRDFg+zvSGjpfBVzVnw
         y0PA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712439112; x=1713043912;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:cc:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zdIRwHZ7JXofPAlRmtHHbsWEHLFacn/DTnMnSo44K7s=;
        b=a60XWXjn6Ak56YS9Xjte7HElXPbrJ9E/xKqC3nPH9NV0fpWrQVEhv50IPDT0YC33dB
         KlQyrPEmdlXpZCKN9aPzv7GUpSVHyZH6BBb+NRfVdfO/3xcm8G4/dIHqQLWFUDh7noSf
         oWVRIIjh6F090txvW/sjF0oKmtXrLxcNU+IrDt3cgyjcEYX6LvoDC8wK2qUKud/9+4P4
         Efn+g7pxBAoCULaxs/cCb5zYHjUdZcA/w2/ROS/EvnPIzChdRDroA8/4B/EEwb7BGTLg
         cPsB+dtDpaCZgtOqrb8AT21hW3fM4D2qGfFpassVLmJeobhlYHxOh47UFl/NmzgUSOIG
         taEg==
X-Forwarded-Encrypted: i=2; AJvYcCUhGeh5/EHdgqEO3HbyJPNd6mZAAulnrCCuAlXcwBl/hzSQEddzwdGAy3NWSzSTuEY0A1XwvlfPq9P27kYewa03JiY4j2eUlg==
X-Gm-Message-State: AOJu0YzvLctUfIQJNB2HRkaA8xfz73/AAskqDYNCPVFRT3+y550TieTV
	WHrE5iFjArHb7HOxNBc4ipUvU/0Vghjrluhi4rLkKNZc2vaIKqb0
X-Google-Smtp-Source: AGHT+IEGq8Ljk7HvtUTTBUGy+Y4GhlVvSS7RgyYXBmCGwBFnBVBUDHGJOVRV4b5kAmwFoXIiRFFHiA==
X-Received: by 2002:a05:600c:1c89:b0:416:50ad:8d49 with SMTP id k9-20020a05600c1c8900b0041650ad8d49mr406224wms.0.1712439111572;
        Sat, 06 Apr 2024 14:31:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d90:b0:416:37ec:4c25 with SMTP id
 p16-20020a05600c1d9000b0041637ec4c25ls394734wms.2.-pod-prod-02-eu; Sat, 06
 Apr 2024 14:31:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1EShy/Gh3InPugZfImY5vg1AoZQO3N7KWa7reW9HIYGChRE0Q9D2Vxz/10MfSsNr1vjWdIvBez0W3YybK5lF1clvKIACyTJVAzQ==
X-Received: by 2002:a05:600c:6b13:b0:415:4b1a:683b with SMTP id jn19-20020a05600c6b1300b004154b1a683bmr3540664wmb.41.1712439109468;
        Sat, 06 Apr 2024 14:31:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712439109; cv=none;
        d=google.com; s=arc-20160816;
        b=JrCKUN9w8klPCQpjUaVzWheDHkGyhAcRpmmKW91jAeFpJZQD/reRmpNagUdZtc6QQO
         NhEDmZfjnH7Crly0BVNMUPW1Sg2l+XfSG9MXhF1NOaEyFOU+cVFiRdwjxw6ibvah7gcn
         +E0LqNFZhh8Q2D25x5uRDRdbJsMnAkfws0HujYVRdIKBLRdCQ4qrW2FhCx5a/pnvzM46
         bU55KVUdwxjxQfaO9a/6vchcVxni5MTvpHP1ik4h9P4+uNCiqIkcD+X8yYBPEqMas8pi
         eyLjK5MC8GVvKBHsLv57y2EqXSSRpriJZ6nKCB29BMj3CkTM6szCRxJYwwu9rLnBzZbn
         fizg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ieDNL4rhi5NeaLS2VvOID9TjiyxKWitXdBFt1XRLCjo=;
        fh=6FJQgL6VMXhNKEog3men0pYA3qfmW0p+qXMph7dzMWY=;
        b=oi48JYgBBHfTVFSl8Kk6fpsw3lwt9bt8QOwJa3WYhcTTTwwGaK1+qU4OML3sMsh35Q
         TQyTIacrt2mNvv2I4Zf2v0hmM5ril2qYA5YB8vPxnb9KuVEkxl4YodbvHIpkLI6mSH3U
         HhgExqOIsCQikJ8HJayDmktc9SdRHqzhH8fdB4ZfRWUw7/1k89xeOoL8PJMW/N8QWDN/
         QsENd8tUSf1JGp1vqWb3vamtJNvsYz88I27+n9x46fJP2/7tbmYH31YjocPvhmr7AMW/
         kTrwjaoWEEgOnvTzH3FH+/3G2zbM/FYt8McRpMD/xn+JOK4WEXsnB0DMi7OkpS5fugIR
         NkIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@collabora.com header.s=mail header.b=CUxgIwux;
       spf=pass (google.com: domain of usama.anjum@collabora.com designates 46.235.227.194 as permitted sender) smtp.mailfrom=usama.anjum@collabora.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=collabora.com
Received: from madrid.collaboradmins.com (madrid.collaboradmins.com. [46.235.227.194])
        by gmr-mx.google.com with ESMTPS id g38-20020a05600c4ca600b00416414a841asi44158wmp.0.2024.04.06.14.31.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 06 Apr 2024 14:31:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of usama.anjum@collabora.com designates 46.235.227.194 as permitted sender) client-ip=46.235.227.194;
Received: from [100.113.15.66] (ec2-34-240-57-77.eu-west-1.compute.amazonaws.com [34.240.57.77])
	(using TLSv1.3 with cipher TLS_AES_128_GCM_SHA256 (128/128 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: usama.anjum)
	by madrid.collaboradmins.com (Postfix) with ESMTPSA id 89F6037809CE;
	Sat,  6 Apr 2024 21:31:41 +0000 (UTC)
Message-ID: <a282446a-6e37-4be7-bb9c-e268c99656b6@collabora.com>
Date: Sun, 7 Apr 2024 02:32:14 +0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Cc: Muhammad Usama Anjum <usama.anjum@collabora.com>,
 Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>,
 "Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com
Subject: Re: [PATCH v6 2/2] selftests/timers/posix_timers: Test delivery of
 signals across threads
To: Oleg Nesterov <oleg@redhat.com>
References: <20230316123028.2890338-1-elver@google.com>
 <20230316123028.2890338-2-elver@google.com>
 <46ad25c9-f63c-4bb7-9707-4bc8b21ccaca@collabora.com>
 <20240406211312.GD3060@redhat.com>
Content-Language: en-US
From: "'Muhammad Usama Anjum' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20240406211312.GD3060@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: usama.anjum@collabora.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@collabora.com header.s=mail header.b=CUxgIwux;       spf=pass
 (google.com: domain of usama.anjum@collabora.com designates 46.235.227.194 as
 permitted sender) smtp.mailfrom=usama.anjum@collabora.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=collabora.com
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

On 4/7/24 2:13 AM, Oleg Nesterov wrote:
> Muhammad,
> 
> I am sorry, but... are you aware that this patch was applied over a year ago,
> and then this code was updated to use the ksft_API?
Sorry, didn't realized this is already applied. So this patch is already
applied and it has already been made compliant.

Thanks

> 
> Oleg.
> 
> On 04/07, Muhammad Usama Anjum wrote:
>>
>> On 3/16/23 5:30 PM, Marco Elver wrote:
>>> From: Dmitry Vyukov <dvyukov@google.com>
>>>
>>> Test that POSIX timers using CLOCK_PROCESS_CPUTIME_ID eventually deliver
>>> a signal to all running threads.  This effectively tests that the kernel
>>> doesn't prefer any one thread (or subset of threads) for signal delivery.
>>>
>>> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
>>> Signed-off-by: Marco Elver <elver@google.com>
>>> ---
>>> v6:
>>> - Update wording on what the test aims to test.
>>> - Fix formatting per checkpatch.pl.
>>> ---
>>>  tools/testing/selftests/timers/posix_timers.c | 77 +++++++++++++++++++
>>>  1 file changed, 77 insertions(+)
>>>
>>> diff --git a/tools/testing/selftests/timers/posix_timers.c b/tools/testing/selftests/timers/posix_timers.c
>>> index 0ba500056e63..8a17c0e8d82b 100644
>>> --- a/tools/testing/selftests/timers/posix_timers.c
>>> +++ b/tools/testing/selftests/timers/posix_timers.c
>>> @@ -188,6 +188,80 @@ static int check_timer_create(int which)
>>>  	return 0;
>>>  }
>>>  
>>> +int remain;
>>> +__thread int got_signal;
>>> +
>>> +static void *distribution_thread(void *arg)
>>> +{
>>> +	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
>>> +	return NULL;
>>> +}
>>> +
>>> +static void distribution_handler(int nr)
>>> +{
>>> +	if (!__atomic_exchange_n(&got_signal, 1, __ATOMIC_RELAXED))
>>> +		__atomic_fetch_sub(&remain, 1, __ATOMIC_RELAXED);
>>> +}
>>> +
>>> +/*
>>> + * Test that all running threads _eventually_ receive CLOCK_PROCESS_CPUTIME_ID
>>> + * timer signals. This primarily tests that the kernel does not favour any one.
>>> + */
>>> +static int check_timer_distribution(void)
>>> +{
>>> +	int err, i;
>>> +	timer_t id;
>>> +	const int nthreads = 10;
>>> +	pthread_t threads[nthreads];
>>> +	struct itimerspec val = {
>>> +		.it_value.tv_sec = 0,
>>> +		.it_value.tv_nsec = 1000 * 1000,
>>> +		.it_interval.tv_sec = 0,
>>> +		.it_interval.tv_nsec = 1000 * 1000,
>>> +	};
>>> +
>>> +	printf("Check timer_create() per process signal distribution... ");
>> Use APIs from kselftest.h. Use ksft_print_msg() here.
>>
>>> +	fflush(stdout);
>>> +
>>> +	remain = nthreads + 1;  /* worker threads + this thread */
>>> +	signal(SIGALRM, distribution_handler);
>>> +	err = timer_create(CLOCK_PROCESS_CPUTIME_ID, NULL, &id);
>>> +	if (err < 0) {
>>> +		perror("Can't create timer\n");
>> ksft_perror() here
>>
>>> +		return -1;
>>> +	}
>>> +	err = timer_settime(id, 0, &val, NULL);
>>> +	if (err < 0) {
>>> +		perror("Can't set timer\n");
>>> +		return -1;
>>> +	}
>>> +
>>> +	for (i = 0; i < nthreads; i++) {
>>> +		if (pthread_create(&threads[i], NULL, distribution_thread, NULL)) {
>>> +			perror("Can't create thread\n");
>>> +			return -1;
>>> +		}
>>> +	}
>>> +
>>> +	/* Wait for all threads to receive the signal. */
>>> +	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
>>> +
>>> +	for (i = 0; i < nthreads; i++) {
>>> +		if (pthread_join(threads[i], NULL)) {
>>> +			perror("Can't join thread\n");
>>> +			return -1;
>>> +		}
>>> +	}
>>> +
>>> +	if (timer_delete(id)) {
>>> +		perror("Can't delete timer\n");
>>> +		return -1;
>>> +	}
>>> +
>>> +	printf("[OK]\n");
>> ksft_test_result or _pass variant as needed?
>>
>>> +	return 0;
>>> +}
>>> +
>>>  int main(int argc, char **argv)
>>>  {
>>>  	printf("Testing posix timers. False negative may happen on CPU execution \n");
>>> @@ -217,5 +291,8 @@ int main(int argc, char **argv)
>>>  	if (check_timer_create(CLOCK_PROCESS_CPUTIME_ID) < 0)
>>>  		return ksft_exit_fail();
>>>  
>>> +	if (check_timer_distribution() < 0)
>>> +		return ksft_exit_fail();
>>> +
>>>  	return ksft_exit_pass();
>>>  }
>>
>> -- 
>> BR,
>> Muhammad Usama Anjum
>>
> 

-- 
BR,
Muhammad Usama Anjum

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a282446a-6e37-4be7-bb9c-e268c99656b6%40collabora.com.
