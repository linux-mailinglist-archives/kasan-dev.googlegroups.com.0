Return-Path: <kasan-dev+bncBDXZ5J7IUEIBB57UWTCAMGQEVSV3JVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id CEFF9B1891A
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Aug 2025 00:06:48 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3e3fa175c41sf15600635ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Aug 2025 15:06:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754086007; cv=pass;
        d=google.com; s=arc-20240605;
        b=jtiC9hhdX81ar0MjaLpAiJgzyvGKmAfgwukP8xTdYcff8+HyDNHRcMhqQi47rajIAP
         5wnYuT6JEq4mIwNy3K51WRDV7EqH8K/SD+YCa9mcFKglgkiTGmWDtjIhmrDciEriNd8a
         0mSmIXoGm13Wx+OG/98jAUE1/sK8zq03mXWBJ2ss5kUX9029eV0rORMHsb/YaUPFFSDT
         w8K6XDi0VBdOPLE6YQovJK1I3CcrLjD128zRhW0Z8ucgGzu1OfHRQKYX0/In84PgKnQ6
         n/WjwmdenU0pgbPtYH1Wmx9cNPVC4xjQ65AkO1pa+VCqquOxOXCITmKbcvRQcjSwqcEC
         xqdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:organization:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=LGV3V6G6TtauSUFutSeMkIZwKZfUvGh2CDR4STgWUWE=;
        fh=egg7yEOKYP4sUTtbA1CN3PrmKBSNM24xJ3FVlHpdVHM=;
        b=SLdRKOsUUySQwyV19Ts13WTC5AWhKrhwVLYXzdNq8aujf6FNXtRVoHaN7nf97CEgUP
         GjnqisZiFRCKMXuqAR7S10hrFDhwyWOc+OniNnHZiVdAq5oIftu2A200obt2bOZ9Eplz
         7AxeaRTAyxrcx3cfTXjOqDsb7zZKTYF3jMOfbV0wzgvi9IvngKd4BoF0eYMFgOCS2Qhp
         tKbqENbfs2gmMhA5KZiopwG37SAOcHa+rf5/UBbOK1PXOHiOQNbSKJZ4AFdY3LM3Rzna
         6z6JnuTnDoSPXo0oKIaxpIsK0bFTxK/P5W89G2Ol+qEoenE0zcsd12BcfNKVqGbob7tA
         QvNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.216.49 as permitted sender) smtp.mailfrom=yskelg@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754086007; x=1754690807; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to
         :organization:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=LGV3V6G6TtauSUFutSeMkIZwKZfUvGh2CDR4STgWUWE=;
        b=RErDTI7yYAId6JbknHP0oEL37eEGdcmTqshVJmWj7XkWe1l18wAo2kEUlprkNOgelp
         IcbEohtDJiWJsFpVBYcgpCWjdf5vRH2w8t10bHTvrYPm6jMAzc+n6gjOcGJPavb8hCj2
         sUc2y++UmeZSt5MPfxz9Pm0Aq9AQ3+XECGCJeTqvDadAUgw35PQapYhKVQiP4XfLk7nq
         xb07cDchjzIDznE9e94ltWxw6bUcIONiwXqviNxFczGIZyqmSEzH0yhFSpMs8sV8J5fS
         8cWNhSZdhFAuE6JtfDeO7ZTKglihRq8tDtiH+W6PjMiH+FiiUys0qMcTHcH7O1pdiWz1
         ohHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754086007; x=1754690807;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LGV3V6G6TtauSUFutSeMkIZwKZfUvGh2CDR4STgWUWE=;
        b=cSYieDciV9l1Mxq2+QwMbmmrdiOB/gG9QPSg50SO18qUkP6qdxoP8Wft3vGDtqpkeP
         VZ1nUkkyCxgmaqSKaWPQEQOTbvoFs9tKFWGXqqVVsq4QRwS6Bodrb2usREnO8Iq+bibV
         OA6c2AX4TDkpTl2AMeDEhkc3qovIszyYXZP4kmASVOVKjf24J2yrRQU3kBKvzR4R+KRf
         xUHs3NRz2K7D8nLXhJEWQTDIfCRkXeCrgf6W2VxDsbTRBOcexlFa4l598n1G/O42Hgn3
         M+pJmyWEVyifBwlXZNm+D+EnGcmqnu95RGTqGcMD+5zppZkoeBRlTq8Q6mFNfb7/0Uve
         P88Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUDcohPqENTeOyjxSzP5Evhlis2mhwlzddBiuCr409HfFKd64UVEe8B4+2bswcQErDMNnCEYA==@lfdr.de
X-Gm-Message-State: AOJu0YzYl/rXqub22R9XXEQ3t/NJmI5c7vjN7H1tidhmyOmutBiO3Oj6
	mxrn7d92ggbgoYp8DSGAGVzEtidZgYUWlxGRAsxtDpSO+EN7mCtkjgMQ
X-Google-Smtp-Source: AGHT+IFJi10oxkFt0qj5Ioxq2Eg/Gdr7qCC0z9i48vumZ6MyHoZF1Rj3IZ7MNBs59PBoNi23MTN3UA==
X-Received: by 2002:a05:6e02:4517:20b0:3e4:17e3:212d with SMTP id e9e14a558f8ab-3e417e321ffmr831385ab.16.1754086007306;
        Fri, 01 Aug 2025 15:06:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdghtyqdDBu1tokpMIyNWi3DJe42Jl4/h2FxLb+2tEpTA==
Received: by 2002:a05:6e02:214f:b0:3e3:a316:8533 with SMTP id
 e9e14a558f8ab-3e401bf7525ls19583695ab.2.-pod-prod-07-us; Fri, 01 Aug 2025
 15:06:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXBWaEbZbx4DEMefjXlg4zotbZyhBC1fYPZyQXg/f32ntrNc19fTVyvIDsNyMcv+aBQuPrCl42x394=@googlegroups.com
X-Received: by 2002:a05:6e02:b4d:b0:3e3:be0e:375a with SMTP id e9e14a558f8ab-3e41610bc76mr21616605ab.2.1754086006411;
        Fri, 01 Aug 2025 15:06:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754086006; cv=none;
        d=google.com; s=arc-20240605;
        b=cKepL8dLjqF5G6nOgknqzYGNzH0/hiNh/ZElnYRDjz2ZEyouCDvQc0IeQA9DokOeJA
         pe3i2fcqpiGOCVThUsG/x56wJrir5pqn0Sy4DBBEnuq3U/T0QOM7Ed0fB6zzbGot20hv
         lNXJfX6X+1ZHY8OH4xBr20FkPcaf4pAVX6XVSeDZZmgNPzcScBiDucR0df/7x7moGT4o
         +6Ri5+eygSjDAqH4vU3MEIA/ceRHHNd+A9LLizmvveK0jXdQtqF/jrwEWpl4knGV3v+S
         LwmlVsSpKR/AGUnDZ+kAqBo/lMA6bLOACpA1np5gYsdezPJ680kW8uKxyUZXuSd/Ab1E
         f47w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id;
        bh=eGMI5UFLAL8h+XrJLA1qy7vAWgjKkChdeP7O9TQ3ZSg=;
        fh=1dUlDUIrz0Tlt/tMW7m7wzmquakWzPzRH/LdPFCkC9o=;
        b=gmmeu2/4V6SKqzVP5f83ehHZeKugP5FzSG4leMxw1+IvcdNMq8f2HHooiDXBjzlS4W
         VQxKJVOq5pCAXkQh56Hh0tyYtPnoezimc2ZYpihXsjtWPX6F2dNZwJzmz6Y1ff3cNY1c
         Ha13tTBfsfLnDoYmPx/XipIJ7ZZTkivdeCIlAKmx/Pp+jLMcmXha/nXiYdap0sCrgFxe
         lUFQAnJl975rH3+4k2P2HMBRhgSBItzLswti1/FPNgfD2026A8VMAR/sXsQDBT4nGNp5
         fuRRMsyrV6o8Nj8d9mOAnd7jRqM1dNL/e4fj8eL9Jbv9WUHtOlpCyj70/fIoeIbJOJzF
         LC5w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.216.49 as permitted sender) smtp.mailfrom=yskelg@gmail.com
Received: from mail-pj1-f49.google.com (mail-pj1-f49.google.com. [209.85.216.49])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50a55f3ae47si249315173.7.2025.08.01.15.06.46
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Aug 2025 15:06:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of yskelg@gmail.com designates 209.85.216.49 as permitted sender) client-ip=209.85.216.49;
Received: by mail-pj1-f49.google.com with SMTP id 98e67ed59e1d1-31ef3e9f0adso188890a91.1;
        Fri, 01 Aug 2025 15:06:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUW1M6o1ADq0Esp0wifdzNhun/HKKeHLdrXxrysyH/nTB5kaI10rxGR09/gIrWrKJF+Pp6lQJkxQFUM@googlegroups.com, AJvYcCXUZqRP+qeX7hYvwEhsHqAOUipxPYbKPsV1VLS8VyvH+i5SDY1u9lBAc6tPRFxc0QZQD2Y+cwuMTCQ=@googlegroups.com
X-Gm-Gg: ASbGncvoyVXZ2PltXs7TktBL4doVfC7PkGoMDzYRJ5j+BztxC6sfVvJw9htkeJl/SUY
	7s3ZH3H0H6QkA70Ibfr8B0/6Fxxy/z9agNaSZK0X4aQCcoJeUwK3MZfFG+4c7AO9rJCdiTrm5m/
	nTOuEptNakinpSiyDwtMuVfYQTeUUbvDLDn8qwGo1QS/+7DVXTZZHGYdKj/qXKztMO049hSSw18
	CJ41iyDhXDJ3fej8eY3795C2O4HM+qZRThCicnX8RtjL9wm9znOc8EZgtXdLmLYu96CjyMjgxD+
	+qSNaHJaV1FTNA8EoUVoGlFNcqJ2v8EJGNgLOgUb1E5BYaL5kUp+mKQrG3OyNcbnc9MXqHt590x
	PV/EFMDOSOFiaPNTlM/xfRmvnDYC5AR53
X-Received: by 2002:a17:90b:38cf:b0:31f:23f0:2df8 with SMTP id 98e67ed59e1d1-321162c7222mr590990a91.6.1754086005463;
        Fri, 01 Aug 2025 15:06:45 -0700 (PDT)
Received: from [192.168.50.136] ([118.32.98.101])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-32115948a74sm827193a91.4.2025.08.01.15.06.41
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Aug 2025 15:06:45 -0700 (PDT)
Message-ID: <4834c0cf-b0e8-49c8-a13b-27c80921a03d@kzalloc.com>
Date: Sat, 2 Aug 2025 07:06:39 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kcov, usb: Fix invalid context sleep in softirq path on
 PREEMPT_RT
To: Thomas Gleixner <tglx@linutronix.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Byungchul Park <byungchul@sk.com>,
 max.byungchul.park@gmail.com, Yeoreum Yun <yeoreum.yun@arm.com>,
 Michelle Jin <shjy180909@gmail.com>, linux-kernel@vger.kernel.org,
 Alan Stern <stern@rowland.harvard.edu>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, stable@vger.kernel.org,
 kasan-dev@googlegroups.com, syzkaller@googlegroups.com,
 linux-usb@vger.kernel.org, linux-rt-devel@lists.linux.dev
References: <20250725201400.1078395-2-ysk@kzalloc.com>
 <2025072615-espresso-grandson-d510@gregkh>
 <77c582ad-471e-49b1-98f8-0addf2ca2bbb@I-love.SAKURA.ne.jp>
 <2025072614-molehill-sequel-3aff@gregkh> <87ldobp3gu.ffs@tglx>
Content-Language: en-US
From: Yunseong Kim <ysk@kzalloc.com>
Organization: kzalloc
In-Reply-To: <87ldobp3gu.ffs@tglx>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: yskelg@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yskelg@gmail.com designates 209.85.216.49 as permitted
 sender) smtp.mailfrom=yskelg@gmail.com
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

Huge thanks to everyone for the feedback!

While working on earlier patches, running syzkaller on PREEMPT_RT uncovered
numerous sleep-in-atomic-context bugs and other synchronization issues uniq=
ue to
that environment. This highlighted the need to address these problems.

On 7/26/25 8:59 =EC=98=A4=ED=9B=84, Thomas Gleixner wrote:
> On Sat, Jul 26 2025 at 09:59, Greg Kroah-Hartman wrote:
>> On Sat, Jul 26, 2025 at 04:44:42PM +0900, Tetsuo Handa wrote:
>>> static void __usb_hcd_giveback_urb(struct urb *urb)
>>> {
>>>   (...snipped...)
>>>   kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum) {
>>>     if (in_serving_softirq()) {
>>>       local_irq_save(flags); // calling local_irq_save() is wrong if CO=
NFIG_PREEMPT_RT=3Dy
>>>       kcov_remote_start_usb(id) {
>>>         kcov_remote_start(id) {
>>>           kcov_remote_start(kcov_remote_handle(KCOV_SUBSYSTEM_USB, id))=
 {
>>>             (...snipped...)
>>>             local_lock_irqsave(&kcov_percpu_data.lock, flags) {
>>>               __local_lock_irqsave(lock, flags) {
>>>                 #ifndef CONFIG_PREEMPT_RT
>>>                   https://elixir.bootlin.com/linux/v6.16-rc7/source/inc=
lude/linux/local_lock_internal.h#L125
>>>                 #else
>>>                   https://elixir.bootlin.com/linux/v6.16-rc7/source/inc=
lude/linux/local_lock_internal.h#L235 // not calling local_irq_save(flags)
>>>                 #endif
>=20
> Right, it does not invoke local_irq_save(flags), but it takes the
> underlying lock, which means it prevents reentrance.
>=20
>> Ok, but then how does the big comment section for
>> kcov_remote_start_usb_softirq() work, where it explicitly states:
>>
>>  * 2. Disables interrupts for the duration of the coverage collection se=
ction.
>>  *    This allows avoiding nested remote coverage collection sections in=
 the
>>  *    softirq context (a softirq might occur during the execution of a w=
ork in
>>  *    the BH workqueue, which runs with in_serving_softirq() > 0).
>>  *    For example, usb_giveback_urb_bh() runs in the BH workqueue with
>>  *    interrupts enabled, so __usb_hcd_giveback_urb() might be interrupt=
ed in
>>  *    the middle of its remote coverage collection section, and the inte=
rrupt
>>  *    handler might invoke __usb_hcd_giveback_urb() again.
>>
>>
>> You are removing half of this function entirely, which feels very wrong
>> to me as any sort of solution, as you have just said that all of that
>> documentation entry is now not needed.
>=20
> I'm not so sure because kcov_percpu_data.lock is only held within
> kcov_remote_start() and kcov_remote_stop(), but the above comment
> suggests that the whole section needs to be serialized.
>=20
> Though I'm not a KCOV wizard and might be completely wrong here.
>=20
> If the whole section is required to be serialized, then this need
> another local lock in kcov_percpu_data to work correctly on RT.
>=20
> Thanks,
>=20
>         tglx

After receiving comments from maintainers, I realized that my initial patch=
 set
wasn't heading in the right direction.


It seems that the following two patches conflict on PREEMPT_RT kernels:

1. kcov: replace local_irq_save() with a local_lock_t
   Link: https://github.com/torvalds/linux/commit/d5d2c51f1e5f
2. kcov, usb: disable interrupts in kcov_remote_start_usb_softirq
   Link: https://github.com/torvalds/linux/commit/f85d39dd7ed8


My current approach involves:

* Removing the existing 'kcov_percpu_data.lock'
* Converting 'kcov->lock' and 'kcov_remote_lock' to raw spinlocks
* Relocating the kmalloc call for kcov_remote_add() outside kcov_ioctl_lock=
ed(),
  as GFP_ATOMIC allocations can potentially sleep under PREEMPT_RT.
  : As expected from further testing, keeping the GFP_ATOMIC allocation ins=
ide
  kcov_remote_add() still leads to sleep in atomic context.

This approach allows us to keep Andrey=E2=80=99s patch d5d2c51f1e5f while m=
aking
modifications as Sebastian suggested in his commit f85d39dd7ed8 message,
which I found particularly insightful and full of helpful hints.

The work I'm doing on PATCH v2 involves a number of changes, and I would tr=
uly
appreciate any critical feedback. I'm always happy to hear insights!


Best regards,
Yunseong Kim

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
834c0cf-b0e8-49c8-a13b-27c80921a03d%40kzalloc.com.
