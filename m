Return-Path: <kasan-dev+bncBD66N3MZ6ALRBBH7XKYAMGQEYGSKWUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 81324898A7C
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 16:56:06 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-36660582091sf10915375ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Apr 2024 07:56:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712242565; cv=pass;
        d=google.com; s=arc-20160816;
        b=gbLisVMjyefza3BeMkocYwhaPkDDOs6IAr7A0e5EDcip5867SogOFdMx7kw6I8L7y+
         I+vXFSp27h/d8y54RiKOagd1pD8G/PjRtH5z6BIHtlWOixMnBhql7DD9UVLBHTaCMjHt
         qSI7JHvhrBnABLE1m23QND6OYwHDJsgDbF8HvxhZUuvGO8iLNZIvi5wnEwnjWzvIRW7S
         emWN2U7w7OiqUlXu/8tv46BRUzIw6+ygBq7AiTPTlig/TCiizWODGzMLH63MaTjUQ4TQ
         Ad/GjZcBtJQ1xOAHn2cT4+lPU7qherToXlDqUy2kYYbOrS64FvVNJ2kxShHr44XN+0o0
         KhOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=HKfB2iyw8ORL1FADtwqWyVnJYW2anMmyQ7EqvCNtsGI=;
        fh=BHIDl7gJ81kBLApzbe/aJY+ycqxcSH2PfeXikUm57Ek=;
        b=kKJLsuhNOvd3MOg0iBYC1lm1AmC7yQfbSFC+ZmFCYavyh4A0UoPW5ByfMQeK9Bzk+B
         xFO4T/439fDTjAGH3CRF7hdwfL66HAP/3pubtd8UF469q6zIEcw5Up7eVECHuarV1G/J
         JhaExXJG0JZxtipOYK4p+y5hT8JGF+VWcgOZiQd6ZNY/eY3+t6Z1/+ymUHZ9bW/sOrm3
         dIWTgNxrnpB56k+rXypqqDhgVm9LQbBodgUlBAi3CBmoZGEKN+OM5KReqLjbT0+10DJn
         zQ5Kdwadc30OkCSq/Xo7hA/Kxmk+0lLGJq1d2uhjHp17Nu+qpJcFD10DZVWh6CEwXqGb
         Qz9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TZBp7Eah;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712242565; x=1712847365; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HKfB2iyw8ORL1FADtwqWyVnJYW2anMmyQ7EqvCNtsGI=;
        b=hksIdlLVgBmCappEe/V6je3pbE/+vD9zp8HJHg/YC29pPhfFS3/KZclBaWduWV0b/4
         kHndid61X+/4LIZ/sl3MuJwkUghk1CuwQ7vOsRhDhyLPxBp2uR3nPyJ/0/n4dfPMpPVh
         8QIzmx7o+rNKIAk6IVqn9KmFQy+xzYJJLPwCtGhJG8gLH6zaKPvvdIIxrPbsoHRw95Cl
         a0pxZ8gTqT5M47jP12mumj49VXF+hymSXwwwjciTQNpKWQd6IsEI+q1nlVf92pfTaY7J
         sp7Fcigwbyt+olVjogIJoF/dpIrxYb4RgdjpVB3L6lxh5UdsxE9r0eQkNDo24Y2eqyyd
         XMgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712242565; x=1712847365;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=HKfB2iyw8ORL1FADtwqWyVnJYW2anMmyQ7EqvCNtsGI=;
        b=mR4e9tWsc2f5W3cSWPIdk+V1hWQKRDvKAzI3eqhjgwCNUbFpZ3oGazzWkYuM037BSr
         5HPj4Mx8BhiRPqRr1+C9uOIwKLPJnqRRtfzoZF/yYpImSlIldLRyewhsIU1a5SrADyAr
         6gXwTpNK2DDJjRB2BGpryD/j8RsZklqVIbsdnfFvcq0N1B6sNx2qxM9mFmqOoN+gaQsb
         jqKi4sJ2rAM6i2eqr1//ycFbZx8FCv6XYAr3+Mh07NGgtE4TqUz59GbZgesIgFtMh3c9
         bhrVcUYe2eEi6ybvS5kavkQnmqVzxJv6b43cOm8Pr+Qi8GWV58+8drcZib8GDpvnbEgz
         IhzA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU704YMI7wGNxsA70R/PFBkadOwqMapgoc+DpneOR9TuPfyHVQyTWi/ZruqWk65ps7hz0SsI8u9gcL7O9Qz9ZwniYzX4Zo0/w==
X-Gm-Message-State: AOJu0YyDlU6e6A4NBLFH/JAPsOwQUyMQ9s8sXAITv3u5awSakwBAcaNj
	CYVq8HYpEJvtVSDgGjx0JM+WUPn+4/onxCfING4CzW+MiSt9EqFe
X-Google-Smtp-Source: AGHT+IH6wfMa4vTC0N+BoILFqh4fLfs0QIFj1rahwapTNPMmifFMpOzWmYlkBRCBEA5oePHi/xPyXw==
X-Received: by 2002:a05:6e02:1c4d:b0:369:eece:acb8 with SMTP id d13-20020a056e021c4d00b00369eeceacb8mr3708725ilg.4.1712242565126;
        Thu, 04 Apr 2024 07:56:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3497:b0:366:280a:d8a5 with SMTP id
 bp23-20020a056e02349700b00366280ad8a5ls863061ilb.0.-pod-prod-05-us; Thu, 04
 Apr 2024 07:56:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUbfW5WNAPZ58QTxFHF/iWZ3LH/a0Fpf+/ADUL4bfTUp6HFre1K+Ws3nKHKUKcnHAzTIunYfBL8NGUQodwf1xD5jwU4aX/C088/ZA==
X-Received: by 2002:a05:6e02:3f05:b0:369:f74f:bbe8 with SMTP id dr5-20020a056e023f0500b00369f74fbbe8mr3342355ilb.14.1712242563355;
        Thu, 04 Apr 2024 07:56:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712242563; cv=none;
        d=google.com; s=arc-20160816;
        b=LC/ysBvHlxigGAqTD4V5FcemeOtsQO2Kj1j0VBWHMnscXewM2oXVmaaq5xuKmdsrHx
         Pni7b/iMH0qn418Yu+NG4cTiutwqr1bnxTc9MUFOaoxWIFjz2HLjw6vZNWEJL8nJvQ7i
         IbumDlT8gglkp8SXlvo9veYRW3VNEjNRmY0eFryu8k3EuB2fRu0SUpxqz1+nPA9UGUdD
         8Rbw2SVrdF3JRtNMzUutLmY6dwSZR+S4rKfsdq4KckMcygT9uy/EXuTbybZ4RM/Wh0KO
         Nf7o6L7uVOtcu9NJe2IYPgy3EZkX14Uk2TRjxeYaX5jMkEuzL0kmMBob/WCGSAi2w8qQ
         WZ1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NQJMd58pUdtgy9XOZ35rBzvDWBc5FSPJawvsuooB2RU=;
        fh=QM13yX5cyx0gKVLH9qgXc292C0jk7N6nZCeRL8zZxhQ=;
        b=N3wZq7+rxFbnGi8Ctl/LO331/RkRVu2xKB68SyJaKie2J28aCY5SJXjBlZWAVamMQD
         lcMej94bS40sUkJ4B0QhN97VGJeNDmCkqLYq1I7wbR0k5P0oUiRaCVAPa7iKZETikToP
         W6EKPCiRhLRpgY7XwdGMuN49Ma1NXVkKe8ogeX9DQ2NtnN1nIpxz9zmRMJ09xyVmFYYa
         zluZBRriwe/+zAim8Yl3MLB7o8vlw2GsT3/MZRF+LE7Lrq/3yAcN8f9IIzNVqgWrC7CL
         B4kTddp5wbukzRmrX4v3K4m6dzoJ8Ev8OKzlphWin5rWVIWfKwyn0WO+m9t3tq74Sa/6
         gF3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TZBp7Eah;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id u6-20020a056638134600b0047eeea2465dsi811243jad.5.2024.04.04.07.56.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Apr 2024 07:56:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-246-N99Y3y5yNh-I55Dli-sewA-1; Thu, 04 Apr 2024 10:55:57 -0400
X-MC-Unique: N99Y3y5yNh-I55Dli-sewA-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.rdu2.redhat.com [10.11.54.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 1BBF088FBAB;
	Thu,  4 Apr 2024 14:55:57 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.225.21])
	by smtp.corp.redhat.com (Postfix) with SMTP id 43CDC3C21;
	Thu,  4 Apr 2024 14:55:54 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Thu,  4 Apr 2024 16:54:32 +0200 (CEST)
Date: Thu, 4 Apr 2024 16:54:08 +0200
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
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
Message-ID: <20240404145408.GD7153@redhat.com>
References: <87sf02bgez.ffs@tglx>
 <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87frw2axv0.ffs@tglx>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.1
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=TZBp7Eah;
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

On 04/04, Thomas Gleixner wrote:
>
> IOW, we cannot test this reliably at all with the current approach.

Agreed!

So how about a REALLY SIMPLE test-case below?

Lacks error checking, should be updated to match tools/testing/selftests.

Without commit bcb7ee79029dca assert(sig_cnt > SIG_CNT) fails, the very
1st tick wakes the leader up.

With that commit it doesn't fail.

Oleg.

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>

#define SIG_CNT	100
static volatile int sig_cnt;

static void alarm_func(int sig)
{
	++sig_cnt;
}

static void *thread_func(void *arg)
{
	// one second before the 1st tick to ensure the leader sleeps
	struct itimerspec val = {
		.it_value.tv_sec = 1,
		.it_value.tv_nsec = 0,
		.it_interval.tv_sec = 0,
		.it_interval.tv_nsec = 1000 * 1000,
	};
	timer_t id;

	timer_create(CLOCK_PROCESS_CPUTIME_ID, NULL, &id);
	timer_settime(id, 0, &val, NULL);

	while (sig_cnt < SIG_CNT)
		;

	// wake up the leader
	kill(getpid(), SIGALRM);

	return NULL;
}

int main(void)
{
	pthread_t thread;

	signal(SIGALRM, alarm_func);

	pthread_create(&thread, NULL, thread_func, NULL);

	pause();

	assert(sig_cnt > SIG_CNT); // likely SIG_CNT + 1

	return 0;
}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240404145408.GD7153%40redhat.com.
