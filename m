Return-Path: <kasan-dev+bncBD66N3MZ6ALRBS7WY2YAMGQEASRGK6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 67E2189ACFC
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Apr 2024 23:14:53 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-6ea10b45918sf137548a34.1
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Apr 2024 14:14:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712438092; cv=pass;
        d=google.com; s=arc-20160816;
        b=V3DgwNmhTJbnNqAIU3XxbyH8AIpjkbjV+H1PR6JHcjX3OG7I1PilSSIL4nKaDvSMWw
         hLzP7n1+6w3eBCvc18uPo+XaXN7qEl3wAZPDw/jiEGZZYduweIK+F2vAsO3+g63p3PVe
         roJEaUjM1PZwFy/VaBQTrmuWXqCCve/9Ektf63lgpzuxo2MSQI7cBWHpVQ7V0u9C+W/t
         JKo/P/+Ybl0tPNHoIMNfchW/nCGQ0h7jVFkixuDjvuJ+7Kjxlpw+E7r4CaIsc8JTDszL
         dfEWXoK9XNgAsAGMKzwMS1kq2zjV6F2z6huKsXdkd+e9WsC8HExsxDLGuwOapyZxSTpa
         zqHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=oWiWl+XVa2nU+2yBdWon2kEysab2BZ88ObAzsuEUpWU=;
        fh=FOs2tihxO4dbhPE29CNWeTn+kswP8QZOfLYzAFUvL40=;
        b=wrrTSwr7nDAI8KX7OkknLdiSNrHlCwddmh+5XQs9+XmN93vUQsgh2J8J9fPicbH5aY
         vAjngOWE5TSlGmCG+NrMoh4zam0KC0Z5rlPycazlUeipeF+8nigTLhDAwM0pm0e1VnNN
         QvvX3cyFf6vy3QzX2rZEKMg+KA0O5he0qZ4GLlT7pTaZYOiJ4T5gvQi5cW9l93Jss46/
         EQnSRczgdQGjwj+YkkyRo1WHXPY+ALfS6bmuOHm/NKMYsc4JOGqgwO3Gkj6HGQy/3XEV
         N5M4VZ+w32jygLJrtZdyvc0jiDNU9ixxFcQx2hPl1SRn7u9bOvlCBrOnuxBHdI/mbHCx
         6ypA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DZPRGUz3;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712438092; x=1713042892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oWiWl+XVa2nU+2yBdWon2kEysab2BZ88ObAzsuEUpWU=;
        b=SiLyoIGoHerJdINTnXl+3B4ildhod2WZE13PdwzSKvZniD0sjrJLIkd2vwpRjPmUoq
         PX5CngmvfP53IIhEFYnXLT1XT/FyHaQ9dZyJ0Qm0vcIAuad7kN3Njk1tvZV8G6w9ssSe
         83Oy9XESigvvwQxxukHtbh439DUhtnf2lbCwF1YX6Jan4p90rB4O7GnfPw3pYz2/mffF
         KUl9LSnv0U/utPsbbZJ1dYsPTgpGgvrIL98AY8xIZJ/Rl1EU0Go3S09vqIAmVkCGjtuf
         a++nKhJe3qZCPVDM7XmegnnlK2OXjnyTaNt5v2OlIS8Fn/wOfgMsT9RpQTP4mt5E4Av1
         5tSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712438092; x=1713042892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=oWiWl+XVa2nU+2yBdWon2kEysab2BZ88ObAzsuEUpWU=;
        b=LP3H0Td9oxz+/Q3CyBX0MAZszaa7TQH4GmZrzj5JMyx09xX3oHFdXKFIEeVCWJeaOI
         2aRhvztxkNq4qRatrZuxrjTPTo+QV/YNq0WWFh8nBY/O6rokwBrfeiiaJEfc5cUZbZkP
         bmXqwLfsURf9B8qEFIN/GNbN/CCloK6V8G7m9rRIRQnosm8CUtcKYQBz5mq1KRiaFu1l
         9k253Q2Cg7N+tbo+pCV/7t0HjTfkYIUg5pgeUxR0oBvNtdPh+5ocJFBnE5vtzk/v1xPh
         LrRuR5S7ttmB7+0SLm9jxGiY6w5xbmDNkMyk41CrUNBIIEhKYYCKKVrR38nJqrD29sNp
         mbQw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWGHKzWAFIC9mNq/eC68kKlMuiZYK8hHBv4l+ntBJf9sHGP6M+BjAQIBl0g3l8fHVTtyXCN7+M6Kt1cx+FWdy2vokneiu8YTA==
X-Gm-Message-State: AOJu0YwrC0IEFhCO3WpTMjJK/uGdbR3z1ApwaFZgj/OCHhMowx8WXz9c
	EwqVi1Ro1Ls/p2fzshZtM4NVPBV+T5adCbV3cWtlqOLNsR6sgw+f
X-Google-Smtp-Source: AGHT+IGJzBjA26gJ4CKo7UNf/pnDK/Ps6hIkFdiCUfoYndCMVt88fZBlidl1f+mkulCbRwo2Q+MJ1Q==
X-Received: by 2002:a05:6871:1d1:b0:221:dcec:fb7b with SMTP id q17-20020a05687101d100b00221dcecfb7bmr5255517oad.6.1712438091349;
        Sat, 06 Apr 2024 14:14:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4d07:b0:22f:4b4:f2de with SMTP id
 pn7-20020a0568704d0700b0022f04b4f2dels288321oab.2.-pod-prod-06-us; Sat, 06
 Apr 2024 14:14:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWRcqk8ScaaIGFobl4Ktfa2eb1xavUfPNuNw2PnzkWLeXU9SWmtaTqnDoNQ+m0sczW1GtPSP2cEGXIsIr7uFOmJzGSLeQ7YEXv2Iw==
X-Received: by 2002:a05:6870:3102:b0:22a:afb6:76f7 with SMTP id v2-20020a056870310200b0022aafb676f7mr4754622oaa.1.1712438090392;
        Sat, 06 Apr 2024 14:14:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712438090; cv=none;
        d=google.com; s=arc-20160816;
        b=dAAjnPtZpf8ZzhPqNmtaI68DXjKz3CnWaQ4Mqgyt3qPrxAefDQeabbaScAmgt9In+o
         O2xtDmO6JjwTzjiryWORb8H8pXnqEGVoHPflMmQ2LPZ1AtzrAjXp3StWMybkWmwX9jPy
         hinHHFaWQZ4Fy6Vgnd/0WgSjP0nvd4TRTXNGka89Gi9eQZIwu296kSnSXCSZapJyAfhQ
         yEWF/IYEqYjIS1v+jvnFwmLReKhYeH2QDIa/m70gD6et0oW4BX7ztiED4OX2OK2sJH83
         HWXTG6MZ4hyNwMxcnYkXlXooR0CcUIiJewGrntbQgVY3TZ5CJH0JJUhJoaWhwTsmHLSw
         cY1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=oHlEIGlMy5AeytAApxqnvbACljlKOkZKhDAKTWpoYzU=;
        fh=bGKKw3htlceobEgjBC75QDV5i+zKnR8IWRiRENRx0r0=;
        b=gv4wcrMOfVch0I4fM7yf6oR2rcoEOVqsJ318nAPdtJYhdJ8FPeQPIociW6BhFgMNFV
         kIJ6K44XR5Ahl1nr2kqWcxBH70E4jsqVBznFJ6EqpkCseirnClzn/kMlvkCsDaRQSA9p
         hzjKUP4sk7NdEM3zyFGqaI/lAg80Sfm0bajUg0BmSC5v3/QopgYD/hMOAjq9p8Jey8N2
         UnGSB989H6H7b3xvL4JVfAT/UAR/55WR2oMYGuzlp/Dc+cIMXx2gW3Waus6qgVSPbYqF
         Gg+jvMebOHYzXusmXp5yIDXiyL807ZV9SSa8Q+iVIeHTaTu4hADlmft7f4GGRcBteCaS
         X00w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DZPRGUz3;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id m13-20020a056870a10d00b0022a076681b5si377911oae.5.2024.04.06.14.14.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 06 Apr 2024 14:14:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-156-xrmUZh_FPx27M8azjuNlpg-1; Sat, 06 Apr 2024 17:14:45 -0400
X-MC-Unique: xrmUZh_FPx27M8azjuNlpg-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.rdu2.redhat.com [10.11.54.3])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 0DBCD180A1E7;
	Sat,  6 Apr 2024 21:14:45 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.226.136])
	by smtp.corp.redhat.com (Postfix) with SMTP id A5BB2100077A;
	Sat,  6 Apr 2024 21:14:42 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Sat,  6 Apr 2024 23:13:20 +0200 (CEST)
Date: Sat, 6 Apr 2024 23:13:13 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Muhammad Usama Anjum <usama.anjum@collabora.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v6 2/2] selftests/timers/posix_timers: Test delivery of
 signals across threads
Message-ID: <20240406211312.GD3060@redhat.com>
References: <20230316123028.2890338-1-elver@google.com>
 <20230316123028.2890338-2-elver@google.com>
 <46ad25c9-f63c-4bb7-9707-4bc8b21ccaca@collabora.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <46ad25c9-f63c-4bb7-9707-4bc8b21ccaca@collabora.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.3
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DZPRGUz3;
       spf=pass (google.com: domain of oleg@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

Muhammad,

I am sorry, but... are you aware that this patch was applied over a year ago,
and then this code was updated to use the ksft_API?

Oleg.

On 04/07, Muhammad Usama Anjum wrote:
>
> On 3/16/23 5:30 PM, Marco Elver wrote:
> > From: Dmitry Vyukov <dvyukov@google.com>
> > 
> > Test that POSIX timers using CLOCK_PROCESS_CPUTIME_ID eventually deliver
> > a signal to all running threads.  This effectively tests that the kernel
> > doesn't prefer any one thread (or subset of threads) for signal delivery.
> > 
> > Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v6:
> > - Update wording on what the test aims to test.
> > - Fix formatting per checkpatch.pl.
> > ---
> >  tools/testing/selftests/timers/posix_timers.c | 77 +++++++++++++++++++
> >  1 file changed, 77 insertions(+)
> > 
> > diff --git a/tools/testing/selftests/timers/posix_timers.c b/tools/testing/selftests/timers/posix_timers.c
> > index 0ba500056e63..8a17c0e8d82b 100644
> > --- a/tools/testing/selftests/timers/posix_timers.c
> > +++ b/tools/testing/selftests/timers/posix_timers.c
> > @@ -188,6 +188,80 @@ static int check_timer_create(int which)
> >  	return 0;
> >  }
> >  
> > +int remain;
> > +__thread int got_signal;
> > +
> > +static void *distribution_thread(void *arg)
> > +{
> > +	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
> > +	return NULL;
> > +}
> > +
> > +static void distribution_handler(int nr)
> > +{
> > +	if (!__atomic_exchange_n(&got_signal, 1, __ATOMIC_RELAXED))
> > +		__atomic_fetch_sub(&remain, 1, __ATOMIC_RELAXED);
> > +}
> > +
> > +/*
> > + * Test that all running threads _eventually_ receive CLOCK_PROCESS_CPUTIME_ID
> > + * timer signals. This primarily tests that the kernel does not favour any one.
> > + */
> > +static int check_timer_distribution(void)
> > +{
> > +	int err, i;
> > +	timer_t id;
> > +	const int nthreads = 10;
> > +	pthread_t threads[nthreads];
> > +	struct itimerspec val = {
> > +		.it_value.tv_sec = 0,
> > +		.it_value.tv_nsec = 1000 * 1000,
> > +		.it_interval.tv_sec = 0,
> > +		.it_interval.tv_nsec = 1000 * 1000,
> > +	};
> > +
> > +	printf("Check timer_create() per process signal distribution... ");
> Use APIs from kselftest.h. Use ksft_print_msg() here.
> 
> > +	fflush(stdout);
> > +
> > +	remain = nthreads + 1;  /* worker threads + this thread */
> > +	signal(SIGALRM, distribution_handler);
> > +	err = timer_create(CLOCK_PROCESS_CPUTIME_ID, NULL, &id);
> > +	if (err < 0) {
> > +		perror("Can't create timer\n");
> ksft_perror() here
> 
> > +		return -1;
> > +	}
> > +	err = timer_settime(id, 0, &val, NULL);
> > +	if (err < 0) {
> > +		perror("Can't set timer\n");
> > +		return -1;
> > +	}
> > +
> > +	for (i = 0; i < nthreads; i++) {
> > +		if (pthread_create(&threads[i], NULL, distribution_thread, NULL)) {
> > +			perror("Can't create thread\n");
> > +			return -1;
> > +		}
> > +	}
> > +
> > +	/* Wait for all threads to receive the signal. */
> > +	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
> > +
> > +	for (i = 0; i < nthreads; i++) {
> > +		if (pthread_join(threads[i], NULL)) {
> > +			perror("Can't join thread\n");
> > +			return -1;
> > +		}
> > +	}
> > +
> > +	if (timer_delete(id)) {
> > +		perror("Can't delete timer\n");
> > +		return -1;
> > +	}
> > +
> > +	printf("[OK]\n");
> ksft_test_result or _pass variant as needed?
> 
> > +	return 0;
> > +}
> > +
> >  int main(int argc, char **argv)
> >  {
> >  	printf("Testing posix timers. False negative may happen on CPU execution \n");
> > @@ -217,5 +291,8 @@ int main(int argc, char **argv)
> >  	if (check_timer_create(CLOCK_PROCESS_CPUTIME_ID) < 0)
> >  		return ksft_exit_fail();
> >  
> > +	if (check_timer_distribution() < 0)
> > +		return ksft_exit_fail();
> > +
> >  	return ksft_exit_pass();
> >  }
> 
> -- 
> BR,
> Muhammad Usama Anjum
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240406211312.GD3060%40redhat.com.
