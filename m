Return-Path: <kasan-dev+bncBCMIZB7QWENRBNWWZ2YAMGQEWIW6TMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FD0E89BA48
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Apr 2024 10:30:48 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-56e645a8762sf427186a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Apr 2024 01:30:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712565047; cv=pass;
        d=google.com; s=arc-20160816;
        b=cxQodTmIa73nfx747JdMhsF1KHigLAkxNAbOcWRNcu1HZ09gowaeZCggzHMBikDOq2
         N9hlncMuPcwcaeuP13Bu6zLf6B0PNcjumuc9JKrvIjDNwac/eL24tqJWB8E/z5UwP569
         p1gY6KgaUjGJ1rBUP1Xx/I0e/C1OWcha+bKC6j3TNDYVs+ftcQOeC5y0diMR6xejXH9+
         rCa1rdG6IzpI/ISU9Ur0oQ41LvLUSm8MEiOOFywCVGGlZwg+Ua4atIcfWuyjK1/ooO2B
         gaHpVy3JbaHsKywxYsxXCT8E9UOrmyZ9S45J+65RHczMTPomrdFQ0Yxg6p+zCK9qRTaF
         z0pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R8yvctOJ3pRBOiNcyHyzKVs472JUoVHrDTUZOrYfN1M=;
        fh=Ou11e/594pJXYXzZCs2E0mO2Ya1MnDHgNzjju3rG+nI=;
        b=y4TO9XlKHj8mXio3PVGMA+CKMdqTDUAQBe3JKfUdbycy6E0OBuXg9ZDmJZP7pXXEl1
         09Tg64o6GLgV/FZHKrjjKGJcpmFRtheRhx2CGHATvkyILMWIk/b7PNJTqRZCi32AwSt/
         JUwrOdU1aG+JquGc9VnQln4SsfOhCYSw9EO6iBVSr/HvFSd5pKFTH6lmokE4YOmE6FcN
         3BDvJ8rkdctAnReNtBqvWtkTxFk33hWn0Rzqv8JXXXwlRJjr/s40EU4EeX8kmMGZAXU0
         F5tTXKO76+wyUXpKvJNX7YLjlJ4CubOox6PHS90y5guPsvLb928c2hxS3exa2Qr+LsmA
         rXRA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FiI4lveQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712565047; x=1713169847; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=R8yvctOJ3pRBOiNcyHyzKVs472JUoVHrDTUZOrYfN1M=;
        b=vw0f9sVqRLWqJB+a5Cf02BG0THp1tGikFAsiys5cClP/d4fl3Vmjv56iia6eFr6AXA
         zalN2ldow255/eAZXzIFlQDAvUqZFhurHOqy2O6DBDFh/roMrbWp+JM2jAwOL/s3aS5A
         IPtJg9So0I4BoE99ZhSIxG15WZvxVY/x+f9dlr7dACYw4lb65BeKH+tUNRGfJth8PMSv
         bHCzRgGgv1bNMQwpHMtW9YRMMjjg9PsBMrSAGq1oUoJZKtrmz909xRmriajsBRh1EuLc
         c8c1Whc8gZwhkH25o0uEmH94PRXkncpGdwQmrWMQ43mhmVqUHwSvb+fh+5yBXAj53KUU
         okNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712565047; x=1713169847;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R8yvctOJ3pRBOiNcyHyzKVs472JUoVHrDTUZOrYfN1M=;
        b=wg/XvbUJwrZMg9v877cr0gci6zuBPCXXCahzAqEGFPuGUQiU4Q5UNP1A9DuASLHIbq
         dA75QmCQXn8ZD2UxniGKN9SspkC+eEYBprka2hDsq24bvGZIOUYh4f1n08ciJQsaqiLU
         TsSsMDQjtPYR2CdXvFgYoGx3c5OkqaAWlZXLrXJodidTNnbXmy7r3wPTRojkQAMxBLSL
         MtLh8PonE51jVKFGAn3TLyCCzacnU483SKMh+m9MZ0KhT+82fONDVKRsU1kqHsSu74li
         pHSSRykJx8aBZ0g8T7pddaLau+JFhe4ZoueT7NDWLZg5qtCGxvZx46LS+RAYt2XWYQEf
         JrfQ==
X-Forwarded-Encrypted: i=2; AJvYcCVRODJiQvv1X0Bpu27oDPAEyABkSRgFg1NmZPQKpFKK4Nnj6Q1c+W3peo/y0A/edFAngjVyWv2kHcYyOAbPEGWcjSfYMjhurw==
X-Gm-Message-State: AOJu0YzKbb1ZPFbKR85FYDiG9kc2cIbir8kgHguSy6zAiSF0AJpSflCW
	xSy8kIwKihgUleGVMuGa2FTfamG30PlYE+cij8S9BSGzI5HT/MXQ
X-Google-Smtp-Source: AGHT+IEoUrD/LLUBgYHTmjQTHs4FlXXmhTWprJv6OBSAbzM38hGmbTbx4O4yO+P/ZRX+oZUUmPU0fQ==
X-Received: by 2002:a50:d75e:0:b0:56e:3774:749b with SMTP id i30-20020a50d75e000000b0056e3774749bmr4324602edj.42.1712565046902;
        Mon, 08 Apr 2024 01:30:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2487:b0:56e:5a09:9be3 with SMTP id
 q7-20020a056402248700b0056e5a099be3ls9932eda.1.-pod-prod-03-eu; Mon, 08 Apr
 2024 01:30:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlUTYG4sUH5xYzTG8QWCKFWpcOoL728xIn8N+wKbDAMGJdB368lewPIc/DncXyU1FQTmKjr8JtOyuPfacROgyQ0LZ0QNgckOmfJw==
X-Received: by 2002:a50:d6d2:0:b0:56e:2bf4:fe0a with SMTP id l18-20020a50d6d2000000b0056e2bf4fe0amr6280065edj.35.1712565044846;
        Mon, 08 Apr 2024 01:30:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712565044; cv=none;
        d=google.com; s=arc-20160816;
        b=A3jlfSKW6gfNhcjRf5+wj4DJTGn4vWDY0cTWbZ75edTAxnyHL85R7eJ3bmxlXIBDeY
         TOTfEu1HMkgVyQc7imi75c6OPwBk6v9Wn2MNIQo2dzA2GLYMyOSpi4oSeA+FwgSiUgFm
         XN8nVCUCp7uad17G8Lv7LhBCg9B01YSRS84/tMc/zhPsvQTMg6C4tQY2YKaqqU475pPq
         i6fydXT4aEzMraT2gLwrHeWGBCcHmUFHGSBgEH7br7ZY+1BjLDpcotPxFWvZaYj8FdEN
         G5fW4yFjIQIeQrDbIiUDKwgtu0NIa+GBNx6/tDcpW8wqxq5ce3MDrTsccR8q3oRhZQJq
         mx6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=W9xvn/M8xXcsYEzO1oyT+gGu7oWuytzcOqfktvcQPMI=;
        fh=vd0eBorevdiRyzxNR72KbHOUo+stFwlbx72t18/R1yY=;
        b=p++VRqdfCB6zQ0ZrAoi0q2PoFXADGntLuynsYWNPr8nGRHP0KCpGu/bx0ocERcZain
         HwiDBYkWMun0kNoa57GtVbFnne7+4e/w3vanwXZDgzAGPXxPER/dpBADfRN/Jn6hzU3C
         zyNKyY6G0XYb0AG3NsWMX6FBskTpfDLL5MXKBdoJPZBRavC1ejKbFJBsr3wxYwuS4tSX
         MacqgBwefGX7EkI7ElnxfdOP+xgLuIfZd+OhMn24/6sNGZx9hY+J1kfetbqIn/We9KVk
         q+l39AhSeCPkehCFGBXFoLV+g6S+tq1v/qnZ3ifqyODwcZZfeG4HGsTkADy1gNulqXe9
         G/5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FiI4lveQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id y14-20020a056402358e00b0056e23a15716si142017edc.2.2024.04.08.01.30.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Apr 2024 01:30:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id 4fb4d7f45d1cf-56e67402a3fso3231a12.0
        for <kasan-dev@googlegroups.com>; Mon, 08 Apr 2024 01:30:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJhsIa6Cgx3BKf5anjpgc3/SedAop+kFgkW9V4wQXWQu8HfFQjh/Pgrb+SRUDvd/wzilMTHZ5PNhmuKh/CchTQBG2YvFc4mLaDHA==
X-Received: by 2002:a05:6402:542:b0:56e:ac4:e1f3 with SMTP id
 i2-20020a056402054200b0056e0ac4e1f3mr203931edx.7.1712565044222; Mon, 08 Apr
 2024 01:30:44 -0700 (PDT)
MIME-Version: 1.0
References: <87sf02bgez.ffs@tglx> <87r0fmbe65.ffs@tglx> <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx> <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx> <20240404145408.GD7153@redhat.com> <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com> <20240406151057.GB3060@redhat.com>
In-Reply-To: <20240406151057.GB3060@redhat.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Apr 2024 10:30:32 +0200
Message-ID: <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement check_timer_distribution()
To: Oleg Nesterov <oleg@redhat.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, John Stultz <jstultz@google.com>, 
	Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, 
	Edward Liaw <edliaw@google.com>, Carlos Llamas <cmllamas@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FiI4lveQ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52f
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Sat, 6 Apr 2024 at 17:12, Oleg Nesterov <oleg@redhat.com> wrote:
>
> Dmitry, Thomas,
>
> To simplify the review I've attached the code with this patch applied below.
>
> Yes, this changes the "semantics" of check_timer_distribution(), perhaps it
> should be renamed.
>
> But I do not see a better approach, and in fact I think that
>
>         Test that all running threads _eventually_ receive CLOCK_PROCESS_CPUTIME_ID
>
> is the wrong goal.
>
> Do you agree?
>
> Oleg.
> -------------------------------------------------------------------------------
>
> static pthread_t ctd_thread;
> static volatile int ctd_count, ctd_failed;
>
> static void ctd_sighandler(int sig)
> {
>         if (pthread_self() != ctd_thread)
>                 ctd_failed = 1;
>         ctd_count--;
> }
>
> static void *ctd_thread_func(void *arg)
> {
>         struct itimerspec val = {
>                 .it_value.tv_sec = 0,
>                 .it_value.tv_nsec = 1000 * 1000,
>                 .it_interval.tv_sec = 0,
>                 .it_interval.tv_nsec = 1000 * 1000,
>         };
>         timer_t id;
>
>         /* 1/10 seconds to ensure the leader sleeps */
>         usleep(10000);
>
>         ctd_count = 100;
>         if (timer_create(CLOCK_PROCESS_CPUTIME_ID, NULL, &id))
>                 return "Can't create timer";
>         if (timer_settime(id, 0, &val, NULL))
>                 return "Can't set timer";
>
>         while (ctd_count > 0 && !ctd_failed)
>                 ;
>
>         if (timer_delete(id))
>                 return "Can't delete timer";
>
>         return NULL;
> }
>
> /*
>  * Test that only the running thread receives the timer signal.
>  */
> static int check_timer_distribution(void)
> {
>         const char *errmsg;
>
>         signal(SIGALRM, ctd_sighandler);
>
>         errmsg = "Can't create thread";
>         if (pthread_create(&ctd_thread, NULL, ctd_thread_func, NULL))
>                 goto err;
>
>         errmsg = "Can't join thread";
>         if (pthread_join(ctd_thread, (void **)&errmsg) || errmsg)
>                 goto err;
>
>         if (ctd_failed)
>                 ksft_test_result_skip("No signal distribution. Assuming old kernel\n");

Shouldn't the test fail here? The goal of a test is to fail when
things don't work.
I don't see any other ksft_test_result_fail() calls, and it does not
look that the test will hang on incorrect distribution.


>         else
>                 ksft_test_result_pass("check signal distribution\n");
>
>         return 0;
> err:
>         ksft_print_msg(errmsg);
>         return -1;
> }
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYch4%2BpdpcTk%3DyWYUOJcceL5RYoE_B9djX_pwrgOcGmFA%40mail.gmail.com.
