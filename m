Return-Path: <kasan-dev+bncBDAMN6NI5EERB2EAZ6YAMGQEQSF6SRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 06BD489BC82
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Apr 2024 12:01:14 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4162501ba28sf21953695e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Apr 2024 03:01:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712570473; cv=pass;
        d=google.com; s=arc-20160816;
        b=o30pYZSvE1qq/j3OqxaReTtX4s7wn0Ima1gLRONe205caOAg6ZzJWgsKty8MGcPZGW
         oqkWvkJOVUqhpa89n2cKQJR4izcSBwShKZbLUjrt7Z2fYBCaYZOoyTXpriHZR2Fu7CM5
         nbh9K2WPXTQ6sNDxk02pWNaquxIeVnujCjmH+5248MJHEgVo9zlDuoqNvSq6wsd9iTmV
         4eS2Tv21AJjgeXHd2aRvdTc9CXrRsJ5gVIAjADhlQtU5I/w7KMH1cGEl/xQDmYEEzgxy
         Qjr7T+XUmDPKHBr4kXsZdwy45OvVICpvTadNszlIuSqqT1qkUwhTRaydvpLAr+WtKg7/
         AMag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=EO7Qlx4bG3vk4pqnsyZwKcm1K0b2ylw4c++A8NsvnpY=;
        fh=jUBUVGLSln0ngdJmDwWd/pSXvxAqVl2fXXlqZ/157C4=;
        b=cHD07qum9K/5qtAbo17ej/CpDv3TojadN4boa+neyPAGx3bl0BssErr7VhUlE6n5bN
         KxqzW347AYKzIFPStrPj38mTHllHmiPwxHHzPjRCE+Czh9M32CPghy5SWHZ7aLHinahA
         Q9+D9gBuVcBhdC1fRD9bH3jlBENLWYjDTu9M98Wk1LuMy2LQezzpLtsDwlLXMVjOO5xu
         F0Y9QWximAcUMQTWFuK9JomN0Fpbfzjp92SEAsgzJeCxNbgfjh60afs7oH1oRM0vfwPK
         T4q1SePZWiQkLrR3ZZmnNk2BLzztQUmnZ6GRia6Qrvsrpmp6xk6a2YP5wWb7zYak2KNF
         CvQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=RwSIqjLx;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=kB1agHNu;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712570473; x=1713175273; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EO7Qlx4bG3vk4pqnsyZwKcm1K0b2ylw4c++A8NsvnpY=;
        b=m94vAYkd6moRxfdpdEfplO53Dv4lM7k0HC4JO4B2J5A5eUwKCBaxFUdDt4CJNV2kEL
         gFcx42HMGBVd5aI/oqk1SmC6sv+ZAKbJzI5zoKUcQQPVUbfcJjfwdxVo9+ntYhY7ey1E
         TKrI9eg5rCBuBfWk+nZUBAy8rDSqMHhENbmx7q2KR3o5znr3Ow8xi8NhApLOPq81H9H5
         tvcP5jTeAOi7fmfP9o2ob55LDVOCWAnhN5gH+vuy7lvFzomkXhytAIrfDqUSIgHxbSe7
         C1MOdeWIilXTuj9vVO/LZAs13PWYmNVr/ebwdJ0j2iD2lOvM6KlSgT4NluTVhQy9lJfJ
         PYuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712570473; x=1713175273;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EO7Qlx4bG3vk4pqnsyZwKcm1K0b2ylw4c++A8NsvnpY=;
        b=Z+7WS9RReGTwEcgQEfunyoATWGLQ/OblblielNDUZYtik0wfYvFOxjfK8OfP1YDs4L
         oL9AA/+Nx8vesXGGSMxU0eBJ00J0+3wSUdpgh0gUQo9gEvlqmrZw444zafrMgpxTn8Kc
         vGHQodnarpk1WWph0wgearBt1rvAUvg1THlKnLcwnQtx6h1BY8jRCnxxBCllkpsGisnI
         dXbBrEEezagq91lX3Xxfb5MmNAbbk1NmoX2NYk9263Nfr6TfPb24erooS85MU77ThTK6
         nLvJll0SzneBOmMF1ffuY0GK8yO80IWWE/485Fgv8hvn3waZJTILMJshLJUGjakmzESX
         PTjw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXollX/rPVzdJe/S9nUriEvj1j4S+EpWKRhBuYdg+cIl8OvOANxP1T+RdqNDaej6jwewTxBazzxdhm474rSY9o5dFiwYrrx7Q==
X-Gm-Message-State: AOJu0YyG4Ej6ry6lJ3vOQiZspa67m+4e+DS9F/J7FixKBCHnRfUbksY5
	2lVZ13sK9cncTJwoJ1sbW7ndQv7/5oFWAOsmieXa267GbZWWEWs3
X-Google-Smtp-Source: AGHT+IEswiI5TqLJZQ9S1ZS2K4eUAfX5+HI3u8g8hcJ35F057Kw3LSidh/48cuk3HSxE1560lGCcPA==
X-Received: by 2002:a05:600c:4f45:b0:416:70a3:8af1 with SMTP id m5-20020a05600c4f4500b0041670a38af1mr1966112wmq.0.1712570472600;
        Mon, 08 Apr 2024 03:01:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f15:b0:416:7060:a7f1 with SMTP id
 l21-20020a05600c4f1500b004167060a7f1ls315562wmq.0.-pod-prod-00-eu; Mon, 08
 Apr 2024 03:01:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVQpVF6TUuPnh198tkzOI4Lb/bbTO9UaOygVXUGaWZylY8ZQMSVzZ78sLzLgeHRLpGOCPLm8arKhfb0+I4b+Hkkut4L5LKQil8mGA==
X-Received: by 2002:a05:600c:4f86:b0:414:8f85:6e50 with SMTP id n6-20020a05600c4f8600b004148f856e50mr6499826wmq.19.1712570470531;
        Mon, 08 Apr 2024 03:01:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712570470; cv=none;
        d=google.com; s=arc-20160816;
        b=zYxmT2Tb1KRCwppEZO+ShN65dyKPBOb7Vum3f92fdscPlUlK+sOn5wRsGfN5M1WfV1
         jQKjlnoB+7jJF0nrfFzL6Czgg2JCDNyMX5NBYzRlh6hB/CZPzYqLsgDDnNMFLlugvGKg
         RI0UV8KQXAbGCZrrGk1kFZPLAzBviXuBPBkZhz5C9xSgajKO/wasLJDiiZ0Z1BX1PGY9
         u7mCaJBPMb9SG00d9UIdQPFMWTGFtUa8tRK6bNNBbwGtgdf2IRTSJE2Jntv5z3ltUCAQ
         Ha85w/sbvBCqhFjTH4nFw4HYvqsRyVbw2plRtxayOm323UBzRYI9Z2TtBojoe/OpPRLs
         Nr/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=tytVrNkppEDDbZ2QmPPIzRlo6qH+BZiddFSHis9hHWU=;
        fh=L5/Ag6zommlmN61H9o2Z8uLOyZ6K2+5E8X61JXkF8qo=;
        b=C7NObCoRpF3v0nARsnctcut8KNkWQoYZrCxFK/Q+DLntJy+6Nl4Vy4/Y8dyx1gocFt
         YSCHb87yXRHC1GkxizINTserngMW3sr/HOUHIxlLbCTZOhgAaHWcT8+GxaZR7fdth+Cc
         jwftfFlnNWBzKruybfVNpr5AOFMWNcjLnQR63upMIhaN1ZeKdZsr7AsP1zKmABZ4KJR+
         Wxzk69Vq9kaJa3J2UVGqgiVHbewMV8ZevSn2o2HHdfrurwmMs5b+oT5L71mpfkNHKtfZ
         WfQfmzZ9g4zLW9k+OQyJScfCeNEzyukyhnZRHuNo/vN0iAt1sEqUxDm5ijilR/qmyeJ0
         r5mA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=RwSIqjLx;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=kB1agHNu;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id m13-20020a7bca4d000000b004166311952fsi138036wml.1.2024.04.08.03.01.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Apr 2024 03:01:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Dmitry Vyukov <dvyukov@google.com>, Oleg Nesterov <oleg@redhat.com>
Cc: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>, Peter
 Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, "Eric W.
 Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, Edward Liaw
 <edliaw@google.com>, Carlos Llamas <cmllamas@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
In-Reply-To: <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
References: <87sf02bgez.ffs@tglx> <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx> <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx> <20240406150950.GA3060@redhat.com>
 <20240406151057.GB3060@redhat.com>
 <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
Date: Mon, 08 Apr 2024 12:01:09 +0200
Message-ID: <87wmp86umy.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=RwSIqjLx;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=kB1agHNu;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
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

On Mon, Apr 08 2024 at 10:30, Dmitry Vyukov wrote:
> On Sat, 6 Apr 2024 at 17:12, Oleg Nesterov <oleg@redhat.com> wrote:
>>         if (ctd_failed)
>>                 ksft_test_result_skip("No signal distribution. Assuming old kernel\n");
>
> Shouldn't the test fail here? The goal of a test is to fail when
> things don't work.
> I don't see any other ksft_test_result_fail() calls, and it does not
> look that the test will hang on incorrect distribution.

I have a fixup for older kernels. I'll get to Olegs patch and the fixup
later today.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87wmp86umy.ffs%40tglx.
