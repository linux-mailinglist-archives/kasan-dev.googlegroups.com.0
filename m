Return-Path: <kasan-dev+bncBD66N3MZ6ALRB6GMYWYAMGQETHW4NTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 40CD189AB8F
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Apr 2024 17:12:58 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-78d346eeb02sf113406085a.1
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Apr 2024 08:12:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712416377; cv=pass;
        d=google.com; s=arc-20160816;
        b=mrStKk660JfXrrh27KRHWq9gC2zBO1Ui4jVFkdo1dg/+YJrdIb+cYTZErOVptu6sKC
         dHe5tjsknGpX8iIluTFzxd2p89d0YwgVgHH0HFJWoEz1tj+od45C73hUK4dB9vo3JbLJ
         xaScYfI+INIYwvvPDbZ2P6kmYMsyPomDNXgS5h0Ve1MMYlPXRRBkoHR9Alg0v8TF7AJj
         zodc2UlDkqSJt3UT9ANFfB8eE9LJRoHPi/2sh5ZXkeFnykVzQhgYl47x0poFD2hPY/SR
         4MV2m+kVfSSOuG22LRqGVfO2T6nwg/gp4EtBUxRhJSNjoOYtozELfgkO0XwTcilfjm57
         bcOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=XDjYPwe3jJOnY3bDz8Z/8aMjLDa+2fqkBy6USzwMnRc=;
        fh=C8Uplsb1WTdZqJXlwmiE8bOAqtu5yWNMCETJU5w92CQ=;
        b=f0GAygcdm22V8WHX3Qj6V5czvesoZftNIaV2qpGKHjXZq/dm6yrf2YKHB3WY75nI7l
         OkZaYeVpLsLmpz1QUkeSy8v5SJhfSsPd9LiH+dihAn+8/v1JNGgeiKVm1orMovRLmdb6
         V6uKgBIYLdsybmOgVdM9Wlyiki/z9PkrCcIV/PFtg060/PTpS2abbvlWPHpDbNamsdIW
         Oib2ii1y7SsVhdpFLjBUl/V/0JaOHBrsOcnGBy4V8OUY2IDj7uwGLzzEXxGVbdwWKM24
         m2bUis1tlROb+x36/eQaJfb8cLPBbQkLMocRNsQCAv2C3j35/QCTIvMc6qYcsj7L/Tx9
         BqdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=N9u4d8jW;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712416377; x=1713021177; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XDjYPwe3jJOnY3bDz8Z/8aMjLDa+2fqkBy6USzwMnRc=;
        b=uBSsdzq4i0WFQUMBgDMnaovP+vom2uNUzlsldnrlD7IaROVUFMOGqZ6jyH0u0321S2
         y5rdhNMFeuFjpq+EMAGSGZLbAx02MAhuJ4Wn6FSfkrHWQBqGAL21RZuIXVjovuppBoa8
         QuopQBLvJ0+p0CRqKdAGG5U/acwtYvxwv9ilSfCsBP8I2EojpWPSG9M5OdQMqmU5ljEX
         xnG6HevN36Op7puqslVxrPADFZcfTQNw8yMYsRpl5ZMIdZzWh3PMVafQPo5/yqyJ5B4a
         K63Pr7DlZU4ZuJpxEnzW6UfcjogkAR9Ao6bmIZAqUaDOOfa1CwtCuq0QUph/NjgexVcD
         HWNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712416377; x=1713021177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=XDjYPwe3jJOnY3bDz8Z/8aMjLDa+2fqkBy6USzwMnRc=;
        b=tlJD85qjVIteto97ubPYcCly3PcbtymArf7KoE7uz5L2rQhaNp1kxG1Df/UUkKEz7Y
         IklWpkUvEmkXG6ASYBuBPhb6vj0vINDR7iWEyxndAzNXBYu3katdxZ/8sfj5Z+66i+30
         Eg+hIIFeTOVhlFixD4Igb+uNcsD60rrb5DoPcxpxt9yrjP/cQ0gm2nS+s6eO0BoWIKve
         2c4rM8ymMAIadMC/qvbkEpDotAA2HXO+hwuMsFivonMeqldt8DvTNFpD1bHS/ZOvunxN
         w+GWtVF5ladwKygnYluEVFeS9Tr65m91VMFkAlRxHK+BeUg58sHwRAKR1adQpTYhS02F
         wfkw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUiNjD1Rp6UTUbaI52GxLIWf2Z6DV9JCpO0ZBVIglD8iPwkyy024RIVQpertvnihl/qfBq5cilezUFzVGP93tZJpKHE4wnyrQ==
X-Gm-Message-State: AOJu0YxmSKeMFMTJzfcwFSZG5Q7c+ZIfr3h70jl0/pyJY7SYJznOijLh
	Pld2OUDdry5nAKJ5QMqMmFdqyatxqK1B1bv72lGmA+sE04RwryVB
X-Google-Smtp-Source: AGHT+IHWe4w8igj/Ev/bdtXmOKufU+2f1qxyXSIpI8k1EnS/GwIxSutvJWGsgFEKnWPQ3m9isT6g/Q==
X-Received: by 2002:ac8:57d5:0:b0:434:797d:b55d with SMTP id w21-20020ac857d5000000b00434797db55dmr1365588qta.2.1712416376780;
        Sat, 06 Apr 2024 08:12:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d91:0:b0:432:c29f:106e with SMTP id c17-20020ac87d91000000b00432c29f106els3924802qtd.1.-pod-prod-05-us;
 Sat, 06 Apr 2024 08:12:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU0aZX+hBItPY2wzGeDUc4SeaITpfCCDaiviS4IL1Xgts/c76/bBXn2iSFCy1wSD7vrEitOhrSylvAU9yzeiOakWQWn3TdO0nisiA==
X-Received: by 2002:a05:622a:1a12:b0:432:b6a1:e52d with SMTP id f18-20020a05622a1a1200b00432b6a1e52dmr5859015qtb.11.1712416373584;
        Sat, 06 Apr 2024 08:12:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712416373; cv=none;
        d=google.com; s=arc-20160816;
        b=fk41gT/48HPlqs2jYqXWZb+KlvoehfMc8GJLEON6FJiluGiLsWs5JG35Vc28DEgFX2
         6aO8cD/SNbNlbYawjwQjuIXL52YN+sq5ib08SC9so3rcto17u2MybRxnbH1oZs35+M0k
         Uy/nXQdtpKenYBKNTOv9Ol2MU695eHJBNsl2Ri+ISBq5n8i+AkJJ8GTyjuufKQneyx8r
         zwLY4K3352dda9axVCjOZqgx0PYTlDNHSWrmUu1V9fNgM5FcaV3LDLtwGam9WvgonS7A
         i3HGVB404QSivzXfIWl1eXEp5BBnvKeDEqD2cNHWJyhA8+AVd0C9chkmvDIUrtJlVyBk
         cO8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=BGna14aQz4iT3c7nYzBJYPjJNR/JUSUa0PJutHav/fU=;
        fh=QM13yX5cyx0gKVLH9qgXc292C0jk7N6nZCeRL8zZxhQ=;
        b=ssRgjDGoSjWzcL6icmm4BkSvtKkVoxXK0KkCSWsmiHQvIjjapmPXpIs3YmMO1EkCXS
         tVkZ35MCRlauDTMl6FQSyWAxtgXFCjSIQSsCKoLeoMHgkdLVLJPznDcW06TDro1bJX4S
         3zyJJnF3vDbvdWd3hPBo2RXxvtXWicqs52TEB/dkdt4RO4rMxn2K8ud4b0TdIPnjn4au
         z1k1ZuY3AAOna7F6oooXcWSlNfoAQ6SI8fR2HOoIMOSDaquep2avWiPmBmOz3xPtSoR9
         FVztQCpNnXKWKfdFZyt8BhxdmpFlYg/FLm3mtBoV0XPSBBR2iox8rBbPK4ijVLiXyp85
         MqwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=N9u4d8jW;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id r3-20020ac84243000000b004347bf979cfsi28001qtm.2.2024.04.06.08.12.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 06 Apr 2024 08:12:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mx-ext.redhat.com [66.187.233.73])
 by relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-130-aioIAyOMMAu4xX5FZxTryw-1; Sat,
 06 Apr 2024 11:12:47 -0400
X-MC-Unique: aioIAyOMMAu4xX5FZxTryw-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.rdu2.redhat.com [10.11.54.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id B957A3806061;
	Sat,  6 Apr 2024 15:12:46 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.226.136])
	by smtp.corp.redhat.com (Postfix) with SMTP id A39DD3C20;
	Sat,  6 Apr 2024 15:12:43 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Sat,  6 Apr 2024 17:11:21 +0200 (CEST)
Date: Sat, 6 Apr 2024 17:10:58 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Edward Liaw <edliaw@google.com>,
	Carlos Llamas <cmllamas@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
Message-ID: <20240406151057.GB3060@redhat.com>
References: <87sf02bgez.ffs@tglx>
 <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx>
 <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240406150950.GA3060@redhat.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.1
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=N9u4d8jW;
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

Dmitry, Thomas,

To simplify the review I've attached the code with this patch applied below.

Yes, this changes the "semantics" of check_timer_distribution(), perhaps it
should be renamed.

But I do not see a better approach, and in fact I think that

	Test that all running threads _eventually_ receive CLOCK_PROCESS_CPUTIME_ID

is the wrong goal.

Do you agree?

Oleg.
-------------------------------------------------------------------------------

static pthread_t ctd_thread;
static volatile int ctd_count, ctd_failed;

static void ctd_sighandler(int sig)
{
	if (pthread_self() != ctd_thread)
		ctd_failed = 1;
	ctd_count--;
}

static void *ctd_thread_func(void *arg)
{
	struct itimerspec val = {
		.it_value.tv_sec = 0,
		.it_value.tv_nsec = 1000 * 1000,
		.it_interval.tv_sec = 0,
		.it_interval.tv_nsec = 1000 * 1000,
	};
	timer_t id;

	/* 1/10 seconds to ensure the leader sleeps */
	usleep(10000);

	ctd_count = 100;
	if (timer_create(CLOCK_PROCESS_CPUTIME_ID, NULL, &id))
		return "Can't create timer";
	if (timer_settime(id, 0, &val, NULL))
		return "Can't set timer";

	while (ctd_count > 0 && !ctd_failed)
		;

	if (timer_delete(id))
		return "Can't delete timer";

	return NULL;
}

/*
 * Test that only the running thread receives the timer signal.
 */
static int check_timer_distribution(void)
{
	const char *errmsg;

	signal(SIGALRM, ctd_sighandler);

	errmsg = "Can't create thread";
	if (pthread_create(&ctd_thread, NULL, ctd_thread_func, NULL))
		goto err;

	errmsg = "Can't join thread";
	if (pthread_join(ctd_thread, (void **)&errmsg) || errmsg)
		goto err;

	if (ctd_failed)
		ksft_test_result_skip("No signal distribution. Assuming old kernel\n");
	else
		ksft_test_result_pass("check signal distribution\n");

	return 0;
err:
	ksft_print_msg(errmsg);
	return -1;
}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240406151057.GB3060%40redhat.com.
