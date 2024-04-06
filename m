Return-Path: <kasan-dev+bncBDAMN6NI5EERBGUMY6YAMGQEZKJPSKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id F013C89AD73
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Apr 2024 00:01:42 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-56e566498a7sf857a12.1
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Apr 2024 15:01:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712440859; cv=pass;
        d=google.com; s=arc-20160816;
        b=l7MH3vsAeUYcEx27ew1BI/GSb/dSQZ3SVWCcE0/Dz6prrDe5rM259326EmewN7DS2c
         F267m6BS72fp5IgHb9Pl9MEG6ahccld0r2/ykHojIklsl8NZzYWCDAGYXCOS1bERrf7F
         PIP/2BPmwBlNpEg/3vipYVvN/GbjT8FjEDOennFf6wgTvw3W0pnGbLAwIPVKBNLm2W2u
         V1rJJsb4hRRefEsZI2ylawgZ4/HDjrPWh9V1HGGqh2XUKDuEOxcQQRt9quTogZTV6zx1
         TTrRM1SuYVLWhHKPecLHK2ogzwHtzM7uYAz6tjdf19oHcfZd38ju4lMC7Jmhl4nxkydd
         zczQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=XaG0fn5xs4FnZYj8bbCJYW6QxXcjlGFW1Aj6rvCFQxM=;
        fh=x1qaGIDL/SVEZkew2YIwE3zLMQbH7XB3Tj4yB0l/Im4=;
        b=qO4vcERvvqODhk/gfX/j1FwypG8imC24U+ZAod8X2Bc2UUzsLNuhuV4RhG/nNkOIoJ
         AwPNaHWoK6itqpzBHRzgqhmJbmwJfvFWw4Wr/+BpcF8n6Mw6LfC+wq0Y0gA/iS8lZUMB
         CPQkDNiOozmFcs0JdO2IUfrzRR19g2v5T1TfMgPUsUrop65ObKMlJvs9yHzPXdA0n1Qq
         c0WTNZHvQPTPaaKoio3U9G2KPuWo4+LgASfEz8OJwYpIuT5D57/DvabzBfrUmDSqE+P4
         AU6Z+eVHjeBaVrpPEHEv51AUh6u5/p5U7vnyfQfKYKlPww/lM3q+2RhTCu+sxBzuwA+F
         2DXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=SaGi5AFV;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712440859; x=1713045659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XaG0fn5xs4FnZYj8bbCJYW6QxXcjlGFW1Aj6rvCFQxM=;
        b=TCzX+0lTJew5r2jetGRhwyCJwAY1nrKbGLwmg/5o9r9F7Uv7KEs54gkPcXSD9Qpz57
         c5Rs9dU/PcjfbB6kaDZwVqFHEmpbCoaY9pr/ubDcpPRIviPuSvw4zVbF04OGVH+HwlLe
         OUTW3i9dGhUGPPPjZKaFm9/vFy1VuE2RxPV+M1e30nhv+NgNCFoIcEvpwwzNvem6zQyz
         aP7EF1Uqf/x+5VBMX02wlnMEyVm9FSajuwFWpiqxVcicusmLtEkZrs4bbUBRmIxBzLA7
         GlWEBgHu5CYCy0XicCzulH+0iyTM7bUPeUkRSxiOwGL/T9CJ0TvpqkEEA74hxC8VSU3q
         wo1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712440859; x=1713045659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XaG0fn5xs4FnZYj8bbCJYW6QxXcjlGFW1Aj6rvCFQxM=;
        b=FTG0BIb196v5SgSidivW1hvYbNlNutq5FSs8kL0mgwKRAfGOGoPuCpizL1Y8GSvvhs
         E8y0Z563Fx9KZqij1QJPBiEfzPZBriKbwMcv1uxozu0bNwfOq44VkwRz3da9oko8yCue
         zOPEs/iT6T0XvxOEkYv7R9jkr/s3XfQgfgeFV5uAsapkJLDUSAWD0C02PmW1y9KxbpwK
         GLrzNvBNvMlQxdCwwWQD5ljJSlZ7Z9sQ0eKcX82lmGYiLKYY1bcxz8IVTtAnCaNJl7uP
         Qkm3QHwfPyY/v/iXL0yhV62hZilebo86nHoA99iktcDgVoqiujY0Hf1/R//bpin3oOjT
         F9xQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUzSrsUwGTycAcjpc9aKd+JsuZFH60U2IKqJsWmFC6U3xjCPoltCSJC1LEYy3An7BxCRZ13s57R4nO0FmAPio2vMz8pNilRjQ==
X-Gm-Message-State: AOJu0YyiAH/HGLlWSQ8NbjWseACNESFiDyFIfBOHom87LMAF6uRYScn5
	JMZed30qHkr3P+K/su/KaHmH+KUvevIlqpOKsj19YPvYb9jX3ZYL
X-Google-Smtp-Source: AGHT+IGHjQvD34V1jFvcwudM/um0Okclv4w4Duf45hvd23VO77DYVyPm0x4wODhZ77IHJN4YybUI/w==
X-Received: by 2002:a05:6402:14c2:b0:56e:2ba2:c32b with SMTP id f2-20020a05640214c200b0056e2ba2c32bmr129775edx.6.1712440859239;
        Sat, 06 Apr 2024 15:00:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5297:b0:56e:50e7:4b39 with SMTP id
 en23-20020a056402529700b0056e50e74b39ls181691edb.2.-pod-prod-03-eu; Sat, 06
 Apr 2024 15:00:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUrRviQUwrFxeWebJH+sZw+6Jx6PZFBqxGQB3ecppnEZVypDg8GuV6elQbbHAI3lC0StoIKnA59oqXSu7tbJ88oxVs8IFnXyh0HjA==
X-Received: by 2002:a50:d5d3:0:b0:56e:34e0:4699 with SMTP id g19-20020a50d5d3000000b0056e34e04699mr3475237edj.30.1712440857141;
        Sat, 06 Apr 2024 15:00:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712440857; cv=none;
        d=google.com; s=arc-20160816;
        b=cecdsX6Wi1/G2Lxtd8cBPfqnGMyrxL+UJ5cWR+7SqhfE0ziC28clUw1MraFc9rG13U
         xUI9EPV2MP3tiu9uYEAkKSAEBm7SC920x97Ttm7tU+u/uxWJXgLp0UqYQjq4cSneDL/j
         LGXbTOX8jW4nyaynWlIVyaIDR8xfSZLFu5Q62uzBIoYhjQ8Hy4It7RNzzPaGF6kuvcFb
         TrztAbnDb87h/48nH/9Lzi41HxXgfo6LJfg2sgk3fRhwAJN3TtJdT8Nz5/9iKuYtDTI/
         UXSZvrzADgevASQi/9rrtaSvb13WQXwjizRfhTaGFY+gl1idKsoOVJGiQABeklO/Tr7Y
         vNbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=WALSA6ekTbORB+oMNmPW1aBENZ+fWec6I1EASj2qsLE=;
        fh=OuAojZ9XtyzR6STIF2qTI9iuNn5xasdqzotJ7hmY3kQ=;
        b=b9MeS162vmYJZCvqN38CoPHf2Oj/huylSLAEYrFnVKCLcU4heaviQHL9SvAlXaXW2v
         nbjHTPpKmrXvZKGkxUio6mJPpoonrpDuv4PmMGlUV3d8NVN/FZgKS6jY2mgc1mM7Jue9
         Z6WueN8RlOQKw/kmfzWGmfJ+Ky/1gQD0s/5ee91phTRRZTgLqGx+V9nouJWatiQKLNtj
         boPGLNj5EafN/i3tCqh7pybZTUZLO/qf3gSCXOeLXdOZhbyiGtKU84yfuivGEwWyUYnO
         /uZ7bgyFEwUuXTW2JnxBTGCHFm/nIZ+HM2W58SUNuUJ5sFjHOzwx5eUf7uNyjYj4A0wm
         gPhg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=SaGi5AFV;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id cq20-20020a056402221400b0056c2ef3a441si109502edb.3.2024.04.06.15.00.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 06 Apr 2024 15:00:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Oleg Nesterov <oleg@redhat.com>
Cc: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>, Peter
 Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, "Eric W.
 Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, Carlos Llamas
 <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
In-Reply-To: <20240406151057.GB3060@redhat.com>
References: <87sf02bgez.ffs@tglx> <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx> <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx> <20240406150950.GA3060@redhat.com>
 <20240406151057.GB3060@redhat.com>
Date: Sun, 07 Apr 2024 00:00:55 +0200
Message-ID: <878r1q882w.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=SaGi5AFV;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Sat, Apr 06 2024 at 17:10, Oleg Nesterov wrote:
> Yes, this changes the "semantics" of check_timer_distribution(), perhaps it
> should be renamed.

Definitely.

> But I do not see a better approach, and in fact I think that
>
> 	Test that all running threads _eventually_ receive CLOCK_PROCESS_CPUTIME_ID
>
> is the wrong goal.
>
> Do you agree?

No argument from my side. All we can test is that the leader is not
woken up.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/878r1q882w.ffs%40tglx.
