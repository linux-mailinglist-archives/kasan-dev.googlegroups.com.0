Return-Path: <kasan-dev+bncBDXZ5J7IUEIBB7HK3DCAMGQEUEUXVOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FE9EB1EDD9
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 19:35:58 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3e40058db50sf21500945ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 10:35:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754674557; cv=pass;
        d=google.com; s=arc-20240605;
        b=QD1Pt+Wz8O1h6WMIiz2JaSq5UDM6pWnA3wX3t+XSm9E6J2Ipd6GtK9MjEo1A2+ryg/
         Ktr1cVLGwse6H2q/5pdPpkq9NTjNa2wYJOg9k2UFZUCGmxlSxuXu5BHFmKmQDxBthePc
         Hmhcjws1hMgidZJx7IN+r54IThW0uUYAfcFo+8DpPomGcwidWx0clI7bzlP8rImFzhy2
         AS/VevKboUhF2WAzi4bV5Kuv6opUn0DcmDsjomwjF8p0Oe6e1hqQV8zR2TSLz32yjau1
         IsNGyVxsX3gv8F3wz8nSIJ5JAkOVCkm8RLCwHfB8ofDm0/IErX2A4YtAQYwI6V8OENHL
         mPCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:organization:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=inQRJjTkLIof80nmmQjYFyYuYb2mvwVgYc0kM+ZAEHY=;
        fh=gjop8Ufd+odC+LaxiZu1Bp04K/LSYFoZ47+2aK0rMUo=;
        b=gqVyooKmfJ3dsKkSO4Vwc+f28ZJ0re4MPgpjcLe4vUpT1dcwUKlkSBDdqcniaW7KlN
         Rz4cv6xSS7c6rGQv7UxECJQID++GyBRJ/GcOgoFVkSIrkHN02YDw9V1IBmh+L1da6SBn
         Ny3Fez/jQs4RfnhpDc5dHcZtyW5N+Uf8nHZ7pNfTs+7zlZ6Anip0CVlJfBKLC7+cU089
         yW32tbv2uysgPBky+k9DQ0YosLAo0aCpidCMS8ngEWmbV/tDXRe40i8eIDtFqwI1ZWPG
         Cwv80BgFKCn8MTZyRT0wFhbS5TjTeI5bvMQo6kxC0kEnJ5TD6GkSQ4Lt2+Y9Vn7bYn+J
         bTiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.210.180 as permitted sender) smtp.mailfrom=yskelg@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754674557; x=1755279357; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to
         :organization:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=inQRJjTkLIof80nmmQjYFyYuYb2mvwVgYc0kM+ZAEHY=;
        b=eu1VD/8OvOO4LGxIumy/9Emp0X/2TFaKtzc2RrwaSmFWNhgwvzDW+7A0NAhCDW8E8S
         ilCkbud2OS/fp4KQwGaliPj7k7nMTC1I87ZBquGdshaZTsk44oM/71ZWcCbg+vnLG2Ei
         bowW78jGSm8spELKMExZjWvQzr0xhcAw58P1lj5t/9Fr3Tu2HZVbFlSqseoQgmLyQq8/
         v/RRtfenngWDEsJz1hctC4W57SXCM6c2ioK5wvKB5Sa7cBVfoZbVdlKp6ymDKTMsHLzq
         dk1eZ5RUEMXKhmkIuudQPoR+PP0xMkRwkiq98xIXHVsTIOWkWEFZSlFsm8Ee9L1r3//s
         vX7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754674557; x=1755279357;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=inQRJjTkLIof80nmmQjYFyYuYb2mvwVgYc0kM+ZAEHY=;
        b=dR4+AbOdzTXlPNnvIIUI3cG6NZFCvTTehJ+zpfHT1p1VMd2FrmQgBlOn9I3MBeqyaQ
         mi52LDiTL4bHOxnAF/cnnUHMfJRC0vsheF+SHMag3QtjWriDf0cjIYPMgaKRIFxnh35t
         2NdvrLGuuEFGQIHhRwkvpvVbNcXFqJcXNgla/p4xUweT8Uw8Vv0pIcMNbaXlSd6HayBx
         DaA29cRSQ9TRNGYmu+2kWYrY1NCd5OKeE+utIkGmjAjskIfPCP7ElwLVFg76mYTyy1K3
         3axeI111uPS4xGlmwdlhGhW4KHNErDiTPjsZtDmjLEBh5eIvB40roK6DCJtBe0TAUseL
         1W6w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU9CIRKI9qUWSnMVKW14eaHaNtoRjNqHW/nc9VZXg88C3zRJiWq3EolTsMqt0C4KmjmtOmYoQ==@lfdr.de
X-Gm-Message-State: AOJu0YzjvbG40O71akl/2QkEews9S8CQgMsj+c3xSouUUjMzk+kZgRuU
	XNECXCm0jhHjEznncI3EuieYJL42rHiemVNGbmMa2CO9muJTLx6tZsME
X-Google-Smtp-Source: AGHT+IGnZsGLGXvQWnsZ1MPK+iJRR0E1uCJlbDwfGn63EZLsU5FAUCZ0GPzOtRWaWmNf18oPSOfo6Q==
X-Received: by 2002:a05:6e02:188f:b0:3e5:2646:df03 with SMTP id e9e14a558f8ab-3e53313e0e6mr72804655ab.12.1754674556665;
        Fri, 08 Aug 2025 10:35:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeKZTlLdFbcenhZEsLsOi+K1gwCI3uJnyKFFqwdmtKu8g==
Received: by 2002:a05:6e02:3802:b0:3e3:e743:1e41 with SMTP id
 e9e14a558f8ab-3e524ae5d28ls19976655ab.1.-pod-prod-04-us; Fri, 08 Aug 2025
 10:35:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZ7m92IyIihqc+EntSr3ode2GuiAidSCzxRqA/B46aJ0qmxoqeJej8ftit9S2KkttadCOwgcAb87k=@googlegroups.com
X-Received: by 2002:a05:6e02:dcc:b0:3e5:3bed:a403 with SMTP id e9e14a558f8ab-3e53beda62bmr7817105ab.9.1754674555773;
        Fri, 08 Aug 2025 10:35:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754674555; cv=none;
        d=google.com; s=arc-20240605;
        b=dzFdjYfoYD/CqFs/ETs/piYYnIP5toIELWMtgdnCJcelVl+bWbcIy4K6op6DpVE/2h
         3fWhu+sITKvE2FP6QXnkkNX3pfpzesfYNBZh4JWPUpAwHBJs3r43KCvU5b5UUjTHQWAF
         +dIhfbBLU2IH1t6U/9G1PvicWL+MexTXb7tzvMacmfSNze+cAZIu+Wr3/brGQYNrwGGB
         jplXwPTrnOGIgJ0qK9xOSPKHLpHx4eNvEIGzTQSbYAlOX6uwLMUzXHVd8TiJmaYjkta4
         2Bj9mZQ1qPueZ47n5ah/lDIXCWpwOS0aRVXxDDdw3I9xfmCHfjAsEOJvQzYxMPgOZn8i
         BcKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id;
        bh=cWQx0Bz2e4dgqP38uiBm8lwh1j15JZqgNFOPKY08noI=;
        fh=9fsGV0WktiBJ/s5+OXOBAsa6fPI7u6EJlqj0Ooheu10=;
        b=J2jQwGXwET1BcfHiw0kBEgbG1E6ncCAr6RtC7OpBEixed7ISRT5Bnydh/ahK1TGD+x
         8soACbob5/7bOCZf+yjuyRw7QExO9NoNhCjEmZQb6rDORwDNNmxaDcpZnbVnkEivbjR1
         /jzG6NwCBlSA/lCo7gYEBh8n3CH1UoRVZxE7EWBGAo4ndlZ9AIC2/88yUajwYzJF/0Fa
         tcuwrl4LrW9/uzUuhCqI18AYSDmkNXRNqplSSnkdt23vJrrk8eLh+tQ+XEjU7Au1b+Ja
         +tzwlqqGPfZCYpzmxAXELbJ4ffRAPk0jUrhIGEIz61tBrZTWbas564FERKMG6nT29eSZ
         UXWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.210.180 as permitted sender) smtp.mailfrom=yskelg@gmail.com
Received: from mail-pf1-f180.google.com (mail-pf1-f180.google.com. [209.85.210.180])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae972f695si101129173.0.2025.08.08.10.35.55
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Aug 2025 10:35:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of yskelg@gmail.com designates 209.85.210.180 as permitted sender) client-ip=209.85.210.180;
Received: by mail-pf1-f180.google.com with SMTP id d2e1a72fcca58-76c0387f1edso275750b3a.3;
        Fri, 08 Aug 2025 10:35:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUYBC2LHJKdlCpN0EAk9ykOa3U4xqVLLYnnkf6XezukCeMhmwjGhNtnF2mtlD6dFp+avfcDFO4lYZp1@googlegroups.com, AJvYcCVuC4H+NyHLKGtnJA0X1arR8EtZakBh0IDGo/VBvjricTc+Idp03M4JaahB9orpvuWLVqmr6cvm8s8=@googlegroups.com
X-Gm-Gg: ASbGncu/k08WS8cDOhuM1rwXBDxF4VCAZbBkcb4ZvJCsg3q8pRJ13IOxDbtMQaymAjT
	ZKs2R1+IPryrq/jKWZh1FdYYx984c2cbE2GIUTqRvPzJVzgHzRQyBfFWMEBAgvsuq22ckZu3J87
	z7sPa48/DOYbdSD/8ltEtdqlkiNcOACvXr8rhZ0H5bpk8d32psKGWfFuipiTYwy5vXU/j0UhuIa
	b88eh5VKm9FTv3ZT4irZ7Zee46pVHA0wYnYFqL1AafYuHbIpD1td5rMkpxickD3bYnT9YLOHB0A
	unkdLenzkmLF1hgT+345+5/HhkDdBTnIMox/EkeioAVtfgTHcAiT0b12OtIRgos69PPFqGAcq/H
	t4zBwzSdZ/YGKaK15InqniyQfd7kWMWrr
X-Received: by 2002:a05:6a00:2d85:b0:755:2c5d:482c with SMTP id d2e1a72fcca58-76c46135279mr2391297b3a.4.1754674554720;
        Fri, 08 Aug 2025 10:35:54 -0700 (PDT)
Received: from [192.168.50.136] ([118.32.98.101])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-76bcce8de34sm20851670b3a.30.2025.08.08.10.35.50
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Aug 2025 10:35:54 -0700 (PDT)
Message-ID: <ee26e7b2-80dd-49b1-bca2-61e460f73c2d@kzalloc.com>
Date: Sat, 9 Aug 2025 02:35:48 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kcov, usb: Fix invalid context sleep in softirq path on
 PREEMPT_RT
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Byungchul Park <byungchul@sk.com>,
 max.byungchul.park@gmail.com, Yeoreum Yun <yeoreum.yun@arm.com>,
 Michelle Jin <shjy180909@gmail.com>, linux-kernel@vger.kernel.org,
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Alan Stern <stern@rowland.harvard.edu>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Thomas Gleixner <tglx@linutronix.de>, stable@vger.kernel.org,
 kasan-dev@googlegroups.com, syzkaller@googlegroups.com,
 linux-usb@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 Austin Kim <austindh.kim@gmail.com>
References: <20250725201400.1078395-2-ysk@kzalloc.com>
 <20250808163345.PPfA_T3F@linutronix.de>
Content-Language: en-US
From: Yunseong Kim <ysk@kzalloc.com>
Organization: kzalloc
In-Reply-To: <20250808163345.PPfA_T3F@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: yskelg@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yskelg@gmail.com designates 209.85.210.180 as
 permitted sender) smtp.mailfrom=yskelg@gmail.com
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

Hi Sebastian,

I was waiting for your review =E2=80=94 thanks!

On 8/9/25 1:33 =EC=98=A4=EC=A0=84, Sebastian Andrzej Siewior wrote:
> On 2025-07-25 20:14:01 [+0000], Yunseong Kim wrote:
>> When fuzzing USB with syzkaller on a PREEMPT_RT enabled kernel, followin=
g
>> bug is triggered in the ksoftirqd context.
>>
> =E2=80=A6
>> This issue was introduced by commit
>> f85d39dd7ed8 ("kcov, usb: disable interrupts in kcov_remote_start_usb_so=
ftirq").
>>
>> However, this creates a conflict on PREEMPT_RT kernels. The local_irq_sa=
ve()
>> call establishes an atomic context where sleeping is forbidden. Inside t=
his
>> context, kcov_remote_start() is called, which on PREEMPT_RT uses sleepin=
g
>> locks (spinlock_t and local_lock_t are mapped to rt_mutex). This results=
 in
>> a sleeping function called from invalid context.
>>
>> On PREEMPT_RT, interrupt handlers are threaded, so the re-entrancy scena=
rio
>> is already safely handled by the existing local_lock_t and the global
>> kcov_remote_lock within kcov_remote_start(). Therefore, the outer
>> local_irq_save() is not necessary.
>>
>> This preserves the intended re-entrancy protection for non-RT kernels wh=
ile
>> resolving the locking violation on PREEMPT_RT kernels.
>>
>> After making this modification and testing it, syzkaller fuzzing the
>> PREEMPT_RT kernel is now running without stopping on latest announced
>> Real-time Linux.
>=20
> This looks oddly familiar because I removed the irq-disable bits while
> adding local-locks.
>=20
> Commit f85d39dd7ed8 looks wrong not that it shouldn't disable
> interrupts. The statement in the added comment
>=20
> | + * 2. Disables interrupts for the duration of the coverage collection =
section.
> | + *    This allows avoiding nested remote coverage collection sections =
in the
> | + *    softirq context (a softirq might occur during the execution of a=
 work in
> | + *    the BH workqueue, which runs with in_serving_softirq() > 0).
>=20
> is wrong. Softirqs are never nesting. While the BH workqueue is
> running another softirq does not occur. The softirq is raised (again)
> and will be handled _after_ BH workqueue is done. So this is already
> serialised.
>=20
> The issue is __usb_hcd_giveback_urb() always invokes
> kcov_remote_start_usb_softirq(). __usb_hcd_giveback_urb() itself is
> invoked from BH context (for the majority of HCDs) and from hardirq
> context for the root-HUB. This gets us to the scenario that that we are
> in the give-back path in softirq context and then invoke the function
> once again in hardirq context.
>=20
> I have no idea how kcov works but reverting the original commit and
> avoiding the false nesting due to hardirq context should do the trick,
> an untested patch follows.
>=20
> This isn't any different than the tasklet handling that was used before
> so I am not sure why it is now a problem.

Thank you for the detailed analysis and the patch. Your explanation about
the real re-entrancy issue being "softirq vs. hardirq" and the faulty
premise in the original commit makes perfect sense.

> Could someone maybe test this?

As you requested, I have tested your patch on my setup.

I can check that your patch resolves the issue. I have been running
the syzkaller for several hours, and the "sleeping function called
from invalid context" bug is no longer triggered.

> --- a/drivers/usb/core/hcd.c
> +++ b/drivers/usb/core/hcd.c
> @@ -1636,7 +1636,6 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
>  	struct usb_hcd *hcd =3D bus_to_hcd(urb->dev->bus);
>  	struct usb_anchor *anchor =3D urb->anchor;
>  	int status =3D urb->unlinked;
> -	unsigned long flags;
> =20
>  	urb->hcpriv =3D NULL;
>  	if (unlikely((urb->transfer_flags & URB_SHORT_NOT_OK) &&
> @@ -1654,14 +1653,13 @@ static void __usb_hcd_giveback_urb(struct urb *ur=
b)
>  	/* pass ownership to the completion handler */
>  	urb->status =3D status;
>  	/*
> -	 * Only collect coverage in the softirq context and disable interrupts
> -	 * to avoid scenarios with nested remote coverage collection sections
> -	 * that KCOV does not support.
> -	 * See the comment next to kcov_remote_start_usb_softirq() for details.
> +	 * This function can be called in task context inside another remote
> +	 * coverage collection section, but kcov doesn't support that kind of
> +	 * recursion yet. Only collect coverage in softirq context for now.
>  	 */
> -	flags =3D kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
> +	kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
>  	urb->complete(urb);
> -	kcov_remote_stop_softirq(flags);
> +	kcov_remote_stop_softirq();
> =20
>  	usb_anchor_resume_wakeups(anchor);
>  	atomic_dec(&urb->use_count);
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index 75a2fb8b16c32..0143358874b07 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -57,47 +57,21 @@ static inline void kcov_remote_start_usb(u64 id)
> =20
>  /*
>   * The softirq flavor of kcov_remote_*() functions is introduced as a te=
mporary
> - * workaround for KCOV's lack of nested remote coverage sections support=
.
> - *
> - * Adding support is tracked in https://bugzilla.kernel.org/show_bug.cgi=
?id=3D210337.
> - *
> - * kcov_remote_start_usb_softirq():
> - *
> - * 1. Only collects coverage when called in the softirq context. This al=
lows
> - *    avoiding nested remote coverage collection sections in the task co=
ntext.
> - *    For example, USB/IP calls usb_hcd_giveback_urb() in the task conte=
xt
> - *    within an existing remote coverage collection section. Thus, KCOV =
should
> - *    not attempt to start collecting coverage within the coverage colle=
ction
> - *    section in __usb_hcd_giveback_urb() in this case.
> - *
> - * 2. Disables interrupts for the duration of the coverage collection se=
ction.
> - *    This allows avoiding nested remote coverage collection sections in=
 the
> - *    softirq context (a softirq might occur during the execution of a w=
ork in
> - *    the BH workqueue, which runs with in_serving_softirq() > 0).
> - *    For example, usb_giveback_urb_bh() runs in the BH workqueue with
> - *    interrupts enabled, so __usb_hcd_giveback_urb() might be interrupt=
ed in
> - *    the middle of its remote coverage collection section, and the inte=
rrupt
> - *    handler might invoke __usb_hcd_giveback_urb() again.
> + * work around for kcov's lack of nested remote coverage sections suppor=
t in
> + * task context. Adding support for nested sections is tracked in:
> + * https://bugzilla.kernel.org/show_bug.cgi?id=3D210337
>   */
> =20
> -static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
> +static inline void kcov_remote_start_usb_softirq(u64 id)
>  {
> -	unsigned long flags =3D 0;
> -
> -	if (in_serving_softirq()) {
> -		local_irq_save(flags);
> +	if (in_serving_softirq() && !in_hardirq())
>  		kcov_remote_start_usb(id);
> -	}
> -
> -	return flags;
>  }
> =20
> -static inline void kcov_remote_stop_softirq(unsigned long flags)
> +static inline void kcov_remote_stop_softirq(void)
>  {
> -	if (in_serving_softirq()) {
> +	if (in_serving_softirq() && !in_hardirq())
>  		kcov_remote_stop();
> -		local_irq_restore(flags);
> -	}
>  }
> =20
>  #ifdef CONFIG_64BIT
> @@ -131,11 +105,8 @@ static inline u64 kcov_common_handle(void)
>  }
>  static inline void kcov_remote_start_common(u64 id) {}
>  static inline void kcov_remote_start_usb(u64 id) {}
> -static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
> -{
> -	return 0;
> -}
> -static inline void kcov_remote_stop_softirq(unsigned long flags) {}
> +static inline void kcov_remote_start_usb_softirq(u64 id) {}
> +static inline void kcov_remote_stop_softirq(void) {}
> =20
>  #endif /* CONFIG_KCOV */
>  #endif /* _LINUX_KCOV_H */


I really impressed your "How to Not Break PREEMPT_RT" talk at LPC 22.


Tested-by: Yunseong Kim <ysk@kzalloc.com>


Thanks,

Yunseong Kim

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e=
e26e7b2-80dd-49b1-bca2-61e460f73c2d%40kzalloc.com.
