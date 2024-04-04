Return-Path: <kasan-dev+bncBDAMN6NI5EERBKWZXOYAMGQEVIXU2XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 39D79898DBA
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 20:08:44 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-516ae78d9a7sf967002e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Apr 2024 11:08:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712254123; cv=pass;
        d=google.com; s=arc-20160816;
        b=AuS7JOhKxuLy/7V5tDgKrZe9LkUVRuS/64Qq+kWg1RdGmXtZ8wnbxmT7PCjWFp5t+z
         Zl4W7RZEMv1ywRL334h12Zm/Nw0EIs6HndW5BZQ7SLPuWC3jsCC0M4lS/kaI8H5k1tAb
         EJJZkCBXljLLkvu8bKAcw0mSL0xmqbkV8oeZUvgRdgL/xHGyc72HjZ88mJz6FDuOd3mN
         gAF/LxZMVOO3HDQADUzinSlCtNy/Sc/JpzQKi4YnvG6K8IgZ+VXWBf4c07vHrBN16+Fv
         nKHFV1mBExVuWKD7WlHLi2ocWT0sonTYmGEVl5ppcJHSDwqoVrDFw6lqCl5jADDWI+Ah
         +bmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=8BlXbmM09zFvEizeAgF8wSQOPPzz1BAvpkjpuucLO+s=;
        fh=mkjBvS8a8o0iKUQg9DAS+U36Z+FDrXZHVzPF3jeZo9Q=;
        b=n/3zx20T7eMk2QNSzbGCZvd4hQiQTBRy/OLkE/hlyVeKUshA1V5+2T4SLjtp+j+z++
         7pibvBtAQUBgDkqKwISKVVCEONDRw/DAOqdn+MKqbQ4IdYMa0Bgca6eUmRracT0fCqUH
         d4wVTsd5AwUOFGYG1FdBVxuIqEzMwsss3ruQvPmoTZ4g/T2LQxPNHkegBxStTNylfPUH
         vJe6ETNjO7YJgndeUaxA1yvDClQ4Zx+/oLdT4clliSt6x4yK62vicSVW0bSg+a0DOG+x
         tqfvhIT/O2JfMHPygMFb9AN9KbrzmA3ArjegWCtApuqZv3t5inwb83O45aXELa7Pl80d
         09+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=IKN17SMS;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=fxB5JykP;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712254123; x=1712858923; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8BlXbmM09zFvEizeAgF8wSQOPPzz1BAvpkjpuucLO+s=;
        b=pgAZZ8EKjevuCityNvhVYF5T9WK/rNcW1CjhJMWueNdREhLsLdlDgazN3uQi56eGor
         lUQb4o+02tKdj1V2gSvAoPGoazF7wx6xdU9XCvy43NDUjaE5SyoXQJk/EsXZwiXupooA
         X7JGppw3WmkYdJcsP4gwhGX5OCVSmi3fpZNyCCNU6sTxTiRul/gQIzDNZyD7+RyuM1Xd
         rNJdDn9DgUfiw9u8IP7nGEc44MIevXs/lS/vkcQMxrJw+tCSp9BdQFo40XDkNeBa8mjC
         wmC7PQjP7xK3X7duGGYV8roG2sJfRnnmCvCf6C+t5PSka5W/QqzcnEFklgyZCWvMngFI
         c/ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712254123; x=1712858923;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8BlXbmM09zFvEizeAgF8wSQOPPzz1BAvpkjpuucLO+s=;
        b=J5CLUpuMvDQYINLxW6dneCrZb+qRFOgcLCz8R4lCg0jWxcD1Fm3BzQNrJsv3Z8AtsM
         hwDoFQrMNeADA8OZLC89kh+dO/K5NkJZmsvv+lqtkVIU1V/aQ1tcRQHoHTuhmjzhZZZm
         Jp2TqQOUSdZKo2cyS6Adkq7tKUWr11cMVk1PS3Tp4dX3qCuhKOjIqHA8zrj9m/GM2lNa
         koqPmkSxRfK+DrE4g91osrItFJzhXCBuZh5/ZAO1sS4kZjMyCb232fClcoRcaA2HdonK
         fD3zRoLOdD701OlUFHFRryZyZ3NUAebbRGyeXY+gEX9o0jXQKnBtGwjplmTNTUQ67ff1
         9jIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWknZmqtG2wye32Jjpiy1AwhoL073VghVXf8kvlbAMPaAn4czNEWw9a9Sz582wO9LmiUH8msUkH6R7IBMPqqWrwI0h5GupuAA==
X-Gm-Message-State: AOJu0YyCFiocJuW8VaUZ7f5ThRn6PQJIrdzWNHuAUXGwXKqXsJ90WOkg
	rXx2g51xqB0dNe+fn71/fE0mAnRMkXKEubytGBPWn76anAMtnh6w
X-Google-Smtp-Source: AGHT+IG2gIIpKftHkmWF3Twtu/WdxtOEH8/cTuu8/pXghnXOgC7PJwangZAdyAXWbyP5xk3+lbMRWg==
X-Received: by 2002:ac2:5e6d:0:b0:516:c766:5b4f with SMTP id a13-20020ac25e6d000000b00516c7665b4fmr1812777lfr.67.1712254122466;
        Thu, 04 Apr 2024 11:08:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c29:b0:414:8fd0:9be with SMTP id
 j41-20020a05600c1c2900b004148fd009bels676967wms.1.-pod-prod-04-eu; Thu, 04
 Apr 2024 11:08:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLpFI+hi/SieU02lBJG2oQuSnAP1d0mXqWwZxlrxX2ZFyFTTBs05P8Q/xFnfsY0I0yHbysKEPxcUb8TNl1sBMIlNo+y85w+LTQjg==
X-Received: by 2002:a05:600c:5350:b0:415:680c:b3ec with SMTP id hi16-20020a05600c535000b00415680cb3ecmr2245085wmb.40.1712254120514;
        Thu, 04 Apr 2024 11:08:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712254120; cv=none;
        d=google.com; s=arc-20160816;
        b=PLDO1l4TTCj5bGfFNeNlmqzWbpuXDuPuSbZ5E3wTjYy9Fo48Dhks2BOvVWbZOz09mK
         zRmb3uAClMHP+bsO0ktWWFy88tezSAZyiWBmvo926o57yT+DQ7XvDZNfDEm5RlZMADEo
         rA2BP9c8Ryp55yPtIjJ25LYK63ru8S46MNWgrWqhDk/JK6AKpVVn8XE0jrcvTAz0bkq+
         fzzbmtD2e6B4cdTfv2GPk/KOWH2by0hOx4Zd5BB5BIbRWfiUXVV9I2KUeun5EphwP4F3
         ck2iGb+nYlq1PWKlkOGKWK4wX88w9N7yGVHsTZ3D6GliKy50qnf9IQdwIump4L6/d8Mn
         D9LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=tkMiv2B4K7kFjJ2XUNPtFrHanpcstv972bKvZlxjA74=;
        fh=OuAojZ9XtyzR6STIF2qTI9iuNn5xasdqzotJ7hmY3kQ=;
        b=yZPKb7HauIWHMluVsbGU67OnosUnmawg0v9xwwu++5u6pHRfbkBjuQ9A4iNS9D6HMT
         1EMIa4kl4qoTuoYz5Hk0OPYw9eS5Cs+WrRSWo4C4vaR+56TDF/NqJBtVs7Z3ET7gYFmf
         eY7y+lzf+LrRlQp5Ye13fcD0QxWbuL69gJvxgHvbYLQbgv/y3AWydA0P/p7XzIEa2aPi
         KAYrS9Q9q1kSxvxTRanP/m3bZi8kCLqAP9RhxRFQAm4+Iw7E5+Wd6m/AYugMfp8QCTcS
         GPHdvMS6tOpLRNzzmwgjmpnL6PDibRf2aUVXdu+BCNyzHDmo5TAMa4dj8RwakDGJRTFS
         9NAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=IKN17SMS;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=fxB5JykP;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id jp12-20020a05600c558c00b004149266c3fdsi149851wmb.1.2024.04.04.11.08.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Apr 2024 11:08:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Oleg Nesterov <oleg@redhat.com>
Cc: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>, Peter
 Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, "Eric W.
 Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, Carlos Llamas
 <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
In-Reply-To: <20240404145408.GD7153@redhat.com>
References: <87sf02bgez.ffs@tglx> <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx> <20240404145408.GD7153@redhat.com>
Date: Thu, 04 Apr 2024 20:08:39 +0200
Message-ID: <87le5t9f14.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=IKN17SMS;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=fxB5JykP;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Thu, Apr 04 2024 at 16:54, Oleg Nesterov wrote:

> On 04/04, Thomas Gleixner wrote:
>>
>> IOW, we cannot test this reliably at all with the current approach.
>
> Agreed!
>
> So how about a REALLY SIMPLE test-case below?
>
> Lacks error checking, should be updated to match tools/testing/selftests.
>
> Without commit bcb7ee79029dca assert(sig_cnt > SIG_CNT) fails, the very
> 1st tick wakes the leader up.
>
> With that commit it doesn't fail.

Clever!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87le5t9f14.ffs%40tglx.
