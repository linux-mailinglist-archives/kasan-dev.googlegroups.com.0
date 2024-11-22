Return-Path: <kasan-dev+bncBCPILY4NUAFBBPUPQO5AMGQENPMJNDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EC629D63B1
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 19:04:48 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5eb61b55b47sf1863468eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 10:04:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732298686; cv=pass;
        d=google.com; s=arc-20240605;
        b=OHp2Dx+ymsmby4lzrES6ohlAWz+ln6qauDLn4fbwEu+HrtQ5UNS5xca+ogvFTeJR4q
         0w3DEHalG3OGCYWb4SJsrg/ubb0DGxBKWb7fc6pnx5Mu3zD0tveIs5Xik2M45MlxcYjt
         TilFtSA81kBNjXFupkVaA5174G/4QKaegb8u0a7gsyLYugOGZcurkYquoK2J9bEx/qhy
         SUFPFSVXfMf1Jvpah0mTHh14xGLrsZwQLnK+Yht1T29yFRIxaD0kOKlCKcJkmW9Di+Xs
         jSLZOPMB5duMIZPfdHH1expp15IGHTJUJwfiwruCgh2J/fDNdgulNW3z3pDoUY87VW1Z
         uPqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:sender:dkim-signature;
        bh=aPm/SS0igCi79yGHnKg4khItJGMXytpB8+yzorvgE9w=;
        fh=CTIOGYdf8Fab/VGMKSjDDwUJAfPnqBQza7CHg6quTa4=;
        b=JR5jcv23yi3AmgPcnXON+q0hZ8XmgNFed4nl5vBLtR37UK1mgAnJ7vC+lwh7FlzcQR
         qASjqIK5dvISuAbFzrlXwaOmmTO3z0jR2RdZM6jFzIb/KUPvMJKxXLl/I0eXsIZ92SuB
         WYqjOJFnFeov1eFYOCWrgkItxrQNp2+MACpgks629GMiXf43M2XoXuHypPtLZXRzf9g+
         Kkvm9SKmAJcx0JlsRCLY28ogJmuBpbDHWK3G/zaX0mif/RQF0B/+k4Jxl3WNGu78PtYB
         YtKeSllssiqa6Eui/HqjeeoUPvrCeNsr4AY1LPfQy5+8rJk8B17WCoqyRg26/yY5s8/M
         J8qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GqyXe4yZ;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732298686; x=1732903486; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aPm/SS0igCi79yGHnKg4khItJGMXytpB8+yzorvgE9w=;
        b=kO8lwhu32YyjugwovV751R1jGkC7aSvfDnRt4+/xTHb0Mb9uamGBwe7/W1uLIxXpIg
         WRMj3iTPJmwrUtWLuJPaxARQY+YILxjlthtWKWyt4eiK0fDecb/gY1PPShpQLWZ+CCuy
         e65hFv8XAVEG6CHDGhQPiueXJx/YyVt0nbvoP+roeuTkVC/3WLGXVP7R+hDJ0mZl46fE
         /1F0ub7jPIdH3bgtCE/aPZr8LWIC5+yEWQUS4GFv17Ac0yOEwK1iZTtJC7kdCTiB+5N2
         dlI9qi42V6qn6nMiq+NQMh/KaOlj5HwJp8zIhx+05FJhkK37P7dAZqF2HKBpojEkSCJJ
         fIqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732298686; x=1732903486;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aPm/SS0igCi79yGHnKg4khItJGMXytpB8+yzorvgE9w=;
        b=wv4EJep0qpblwNws8QcFos/0U5dMmElV+HhWlrAQFTO5NdgsdVDcOVgWOBEpLzgxid
         bmPnOemtbpO+YvnkJB+iQmYGg1A17IZO12ZikiRpNJ6T4PTv669sbc2sPrr9nQoiWr/b
         +bi3IY99ku8Dr7IicZDmQ5LNRJ5HZurtSpHvBMDGOe7V83Rw/HuJN5aG/KNhAsYb78ob
         RbNQCt/A+VQxk3UKNVjENOgN3ixEOc9hNuBwMpA5a8+fIrHBDaoL0x7PEzuucBPoFDrR
         0a4u8rPRjFuNFqIr43z0VZxqTWfUGIF24RD7vXJkVQxs/iQKdtoCdaVpxdevxBRe2rkb
         ssdQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVtfx5hDRfXp5MW0xoHGrZvYVcR8HXEp8OoFMKAKkRiupe7Jt0fi6fd6j0LIVWpq8EtVyVCpA==@lfdr.de
X-Gm-Message-State: AOJu0YwxuUfOjlMjFsmbX9nrntmv/E3R5MYlJMy7B4qoybz1RsFnW1E7
	dB5CMLwEmgni/TsqZZbcvW3h3p4PL+GjJtA/GekjbUmE1Aw0ospf
X-Google-Smtp-Source: AGHT+IEyg/niCD70vyoPO1wkydUnfm6XafJaHnrqS2ZO/0wuaBY1sV+/HOjoqOhtnxMEWOXylE47qg==
X-Received: by 2002:a05:6820:1806:b0:5ee:56d:69f9 with SMTP id 006d021491bc7-5f06a9f95ecmr3543199eaf.5.1732298686567;
        Fri, 22 Nov 2024 10:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:22a4:b0:5eb:5d64:a13a with SMTP id
 006d021491bc7-5ef3c4c4703ls2071306eaf.1.-pod-prod-08-us; Fri, 22 Nov 2024
 10:04:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUsF7n9Rk9aX0bccWNkCyHKHpIFeQLzh2ncG+FFtgKbM6o5J0bx9ROKQmSjz8EPTzrwX0odhgJppsg=@googlegroups.com
X-Received: by 2002:a05:6358:2190:b0:1c5:e364:d4d1 with SMTP id e5c5f4694b2df-1ca797ce0bbmr291345455d.26.1732298685537;
        Fri, 22 Nov 2024 10:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732298685; cv=none;
        d=google.com; s=arc-20240605;
        b=IDNwuB+/yM/vIVkcFbFg6x0W0qXt6EkwRrz6RT+znqOG6Fjt+2XG7f68OAPJkBWUbc
         WM4Hlwow4bd25VjxjBOan7cO7dHlOK/gLxzHkQMnuDXpc21UcqTOZyKfs6AaqwuqUPEj
         o5ISLfqqLuGBDZEi9NxqPnwxXroBtYV7ZfrUiV+Tqts6QK8YX/gltw3W5Ex4DX2gnHdU
         AZ8jScnTqfdMWLPu8nwEcRvQ411sGTDD+SybF88YO/Oqq4pDpJZEGoYf9bEaC+9duYcC
         nyloy2FKR3KiKgllUuYgr9CAxxuwcDCGfP9jtmSmSmF1A/6rA9T32PUb4X+rVekFDY/6
         QyTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=CgB4Xh16LltpIZ14PxsaottjJCcCZ0sRpmkNwhVZ7wk=;
        fh=tGwDmbOzoD0oFZiSWCLTpIBZXnoehvYlZjKB35dcHCI=;
        b=XVj9rICAWyMUzaYWV5c0MJi2LxD5B46ay8PI4O+eaMgwvcvRNNq6zekop4DnrC92qv
         hi8+NlFeOOdMH/5M7Cs1ZtNrjLXdHWFXMXdgzcGZoHN4cmYZal02458eSXw9OoXvmrPU
         z/eMRkorSFHN+ObBDM/HQojrXUuNawjiH4T73/8JWCFxrNXnGw04oGndM7wCekIm8Yxt
         Xi4t9/r2yXjGL2yhrZXDOmbmFF0SpAeRjPP6aK9ZyBaZtv9YryYQjKuT1oq88HJ+ui8+
         LYoHgQufEbGFMBCYlZoKWxblxqLjQpYgMXSn/0bXMo1VlxZwiaT9010n8DKGJBpnfYF1
         aPLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GqyXe4yZ;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4adda6fd5c4si113492137.2.2024.11.22.10.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Nov 2024 10:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-il1-f200.google.com (mail-il1-f200.google.com
 [209.85.166.200]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-668-Dyw2B9kjPx6J0CnjOUljKw-1; Fri, 22 Nov 2024 13:04:44 -0500
X-MC-Unique: Dyw2B9kjPx6J0CnjOUljKw-1
X-Mimecast-MFC-AGG-ID: Dyw2B9kjPx6J0CnjOUljKw
Received: by mail-il1-f200.google.com with SMTP id e9e14a558f8ab-3a77a808c27so24692455ab.1
        for <kasan-dev@googlegroups.com>; Fri, 22 Nov 2024 10:04:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUiQYhNRKsWFYe0NuDcKZ74zZJuva8pozwt90svtSAAipl2g5Y18AONa39TXG0uWPei4Ui6pqtOeoI=@googlegroups.com
X-Gm-Gg: ASbGncswenedMKpPfKeA4udcp6zk4Ib4ULWoYryNzK74Ghm6bHE2wCyp/JGxSIm4Dt4
	1m6Qx36U1Nl0bmeeryiuGTSDMtQVxuYQ2SLJQvJExjIssesWYLBw5KWH6OCM0voxrH8x7IVQ/Iu
	yqIHNWiWm87CyutamZE80WyoXLQ+FRRZg4+IAkiSjIvDiReo/uJlnPikvrs8Pf08ra4wP5hdH9E
	evbf07nRLI3K4+zLEMyRTI6ANKFirDiVwWc8jtJRA/8evK+0isfE7iTRwPbHR1yzK25uMzN6/VZ
	wNEg/4+5BW9gOFMaKQ==
X-Received: by 2002:a05:6e02:3187:b0:3a7:a553:7dc with SMTP id e9e14a558f8ab-3a7a5530fafmr21839535ab.7.1732298683164;
        Fri, 22 Nov 2024 10:04:43 -0800 (PST)
X-Received: by 2002:a05:6e02:3187:b0:3a7:a553:7dc with SMTP id e9e14a558f8ab-3a7a5530fafmr21838975ab.7.1732298682781;
        Fri, 22 Nov 2024 10:04:42 -0800 (PST)
Received: from ?IPV6:2601:188:ca00:a00:f844:fad5:7984:7bd7? ([2601:188:ca00:a00:f844:fad5:7984:7bd7])
        by smtp.gmail.com with ESMTPSA id e9e14a558f8ab-3a79ac9735csm5893795ab.50.2024.11.22.10.04.36
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Nov 2024 10:04:40 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <514c8a18-0b12-481b-94c2-00cabd5a4a42@redhat.com>
Date: Fri, 22 Nov 2024 13:04:34 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kasan: Make kasan_record_aux_stack_noalloc() the
 default behaviour
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Vlastimil Babka <vbabka@suse.cz>,
 syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>,
 Liam.Howlett@oracle.com, akpm@linux-foundation.org, jannh@google.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 lorenzo.stoakes@oracle.com, syzkaller-bugs@googlegroups.com,
 kasan-dev <kasan-dev@googlegroups.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, dvyukov@google.com,
 vincenzo.frascino@arm.com, paulmck@kernel.org, frederic@kernel.org,
 neeraj.upadhyay@kernel.org, joel@joelfernandes.org, josh@joshtriplett.org,
 boqun.feng@gmail.com, urezki@gmail.com, rostedt@goodmis.org,
 mathieu.desnoyers@efficios.com, jiangshanlai@gmail.com,
 qiang.zhang1211@gmail.com, mingo@redhat.com, juri.lelli@redhat.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com,
 mgorman@suse.de, vschneid@redhat.com, tj@kernel.org, cl@linux.com,
 penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
 Thomas Gleixner <tglx@linutronix.de>, roman.gushchin@linux.dev,
 42.hyeyoo@gmail.com, rcu@vger.kernel.org
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com>
 <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz>
 <20241104114506.GC24862@noisy.programming.kicks-ass.net>
 <CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com>
 <20241119155701.GYennzPF@linutronix.de>
 <CA+fCnZfzJcbEy0Qmn5GPzPUx9diR+3qw+4ukHa2j5xzzQMF8Kw@mail.gmail.com>
 <20241122155451.Mb2pmeyJ@linutronix.de>
In-Reply-To: <20241122155451.Mb2pmeyJ@linutronix.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: JL86u7fvvM5jz35L7ImQjusie4EHWwvDIQS85CvDOTc_1732298683
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=GqyXe4yZ;
       spf=pass (google.com: domain of llong@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
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

On 11/22/24 10:54 AM, Sebastian Andrzej Siewior wrote:
> From: Peter Zijlstra <peterz@infradead.org>
>
> kasan_record_aux_stack_noalloc() was introduced to record a stack trace
> without allocating memory in the process. It has been added to callers
> which were invoked while a raw_spinlock_t was held.
> More and more callers were identified and changed over time. Is it a
> good thing to have this while functions try their best to do a
> locklessly setup? The only downside of having kasan_record_aux_stack()
> not allocate any memory is that we end up without a stacktrace if
> stackdepot runs out of memory and at the same stacktrace was not
> recorded before To quote Marco Elver from
>     https://lore.kernel.org/all/CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd=
4jtbof9nVQ@mail.gmail.com/
>
> | I'd be in favor, it simplifies things. And stack depot should be
> | able to replenish its pool sufficiently in the "non-aux" cases
> | i.e. regular allocations. Worst case we fail to record some
> | aux stacks, but I think that's only really bad if there's a bug
> | around one of these allocations. In general the probabilities
> | of this being a regression are extremely small [...]
>
> Make the kasan_record_aux_stack_noalloc() behaviour default as
> kasan_record_aux_stack().
>
> [bigeasy: Dressed the diff as patch. ]
>
> Reported-by: syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com
> Closes: https://lore.kernel.org/all/67275485.050a0220.3c8d68.0a37.GAE@goo=
gle.com
> Acked-by: Waiman Long <longman@redhat.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Reviewed-by: Marco Elver <elver@google.com>
> Fixes: 7cb3007ce2da2 ("kasan: generic: introduce kasan_record_aux_stack_n=
oalloc()")
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> ---
> v1=E2=80=A6v2:
>    - Renamed the patch as per Marco.
>    - Added comment to kasan_record_aux_stack() as per Andrey.
>    - Added fixes tag since Waiman that it is the only user.
>    - Added Marco's quote from the mail to the commit description.
>
>   include/linux/kasan.h     |  2 --
>   include/linux/task_work.h |  3 ---
>   kernel/irq_work.c         |  2 +-
>   kernel/rcu/tiny.c         |  2 +-
>   kernel/rcu/tree.c         |  4 ++--
>   kernel/sched/core.c       |  2 +-
>   kernel/task_work.c        | 14 +-------------
>   kernel/workqueue.c        |  2 +-
>   mm/kasan/generic.c        | 18 ++++++------------
>   mm/slub.c                 |  2 +-
>   10 files changed, 14 insertions(+), 37 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 00a3bf7c0d8f0..1a623818e8b39 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -488,7 +488,6 @@ void kasan_cache_create(struct kmem_cache *cache, uns=
igned int *size,
>   void kasan_cache_shrink(struct kmem_cache *cache);
>   void kasan_cache_shutdown(struct kmem_cache *cache);
>   void kasan_record_aux_stack(void *ptr);
> -void kasan_record_aux_stack_noalloc(void *ptr);
>  =20
>   #else /* CONFIG_KASAN_GENERIC */
>  =20
> @@ -506,7 +505,6 @@ static inline void kasan_cache_create(struct kmem_cac=
he *cache,
>   static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
>   static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
>   static inline void kasan_record_aux_stack(void *ptr) {}
> -static inline void kasan_record_aux_stack_noalloc(void *ptr) {}
>  =20
>   #endif /* CONFIG_KASAN_GENERIC */
>  =20
> diff --git a/include/linux/task_work.h b/include/linux/task_work.h
> index 2964171856e00..0646804860ff1 100644
> --- a/include/linux/task_work.h
> +++ b/include/linux/task_work.h
> @@ -19,9 +19,6 @@ enum task_work_notify_mode {
>   	TWA_SIGNAL,
>   	TWA_SIGNAL_NO_IPI,
>   	TWA_NMI_CURRENT,
> -
> -	TWA_FLAGS =3D 0xff00,
> -	TWAF_NO_ALLOC =3D 0x0100,
>   };
>  =20
>   static inline bool task_work_pending(struct task_struct *task)
> diff --git a/kernel/irq_work.c b/kernel/irq_work.c
> index 2f4fb336dda17..73f7e1fd4ab4d 100644
> --- a/kernel/irq_work.c
> +++ b/kernel/irq_work.c
> @@ -147,7 +147,7 @@ bool irq_work_queue_on(struct irq_work *work, int cpu=
)
>   	if (!irq_work_claim(work))
>   		return false;
>  =20
> -	kasan_record_aux_stack_noalloc(work);
> +	kasan_record_aux_stack(work);
>  =20
>   	preempt_disable();
>   	if (cpu !=3D smp_processor_id()) {
> diff --git a/kernel/rcu/tiny.c b/kernel/rcu/tiny.c
> index b3b3ce34df631..4b3f319114650 100644
> --- a/kernel/rcu/tiny.c
> +++ b/kernel/rcu/tiny.c
> @@ -250,7 +250,7 @@ EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);
>   void kvfree_call_rcu(struct rcu_head *head, void *ptr)
>   {
>   	if (head)
> -		kasan_record_aux_stack_noalloc(ptr);
> +		kasan_record_aux_stack(ptr);
>  =20
>   	__kvfree_call_rcu(head, ptr);
>   }
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index b1f883fcd9185..7eae9bd818a90 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -3083,7 +3083,7 @@ __call_rcu_common(struct rcu_head *head, rcu_callba=
ck_t func, bool lazy_in)
>   	}
>   	head->func =3D func;
>   	head->next =3D NULL;
> -	kasan_record_aux_stack_noalloc(head);
> +	kasan_record_aux_stack(head);
>   	local_irq_save(flags);
>   	rdp =3D this_cpu_ptr(&rcu_data);
>   	lazy =3D lazy_in && !rcu_async_should_hurry();
> @@ -3807,7 +3807,7 @@ void kvfree_call_rcu(struct rcu_head *head, void *p=
tr)
>   		return;
>   	}
>  =20
> -	kasan_record_aux_stack_noalloc(ptr);
> +	kasan_record_aux_stack(ptr);
>   	success =3D add_ptr_to_bulk_krc_lock(&krcp, &flags, ptr, !head);
>   	if (!success) {
>   		run_page_cache_worker(krcp);
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index a1c353a62c568..3717360a940d2 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -10485,7 +10485,7 @@ void task_tick_mm_cid(struct rq *rq, struct task_=
struct *curr)
>   		return;
>  =20
>   	/* No page allocation under rq lock */
> -	task_work_add(curr, work, TWA_RESUME | TWAF_NO_ALLOC);
> +	task_work_add(curr, work, TWA_RESUME);
>   }
>  =20
>   void sched_mm_cid_exit_signals(struct task_struct *t)
> diff --git a/kernel/task_work.c b/kernel/task_work.c
> index c969f1f26be58..d1efec571a4a4 100644
> --- a/kernel/task_work.c
> +++ b/kernel/task_work.c
> @@ -55,26 +55,14 @@ int task_work_add(struct task_struct *task, struct ca=
llback_head *work,
>   		  enum task_work_notify_mode notify)
>   {
>   	struct callback_head *head;
> -	int flags =3D notify & TWA_FLAGS;
>  =20
> -	notify &=3D ~TWA_FLAGS;
>   	if (notify =3D=3D TWA_NMI_CURRENT) {
>   		if (WARN_ON_ONCE(task !=3D current))
>   			return -EINVAL;
>   		if (!IS_ENABLED(CONFIG_IRQ_WORK))
>   			return -EINVAL;
>   	} else {
> -		/*
> -		 * Record the work call stack in order to print it in KASAN
> -		 * reports.
> -		 *
> -		 * Note that stack allocation can fail if TWAF_NO_ALLOC flag
> -		 * is set and new page is needed to expand the stack buffer.
> -		 */
> -		if (flags & TWAF_NO_ALLOC)
> -			kasan_record_aux_stack_noalloc(work);
> -		else
> -			kasan_record_aux_stack(work);
> +		kasan_record_aux_stack(work);
>   	}
>  =20
>   	head =3D READ_ONCE(task->task_works);
> diff --git a/kernel/workqueue.c b/kernel/workqueue.c
> index 9949ffad8df09..65b8314b2d538 100644
> --- a/kernel/workqueue.c
> +++ b/kernel/workqueue.c
> @@ -2180,7 +2180,7 @@ static void insert_work(struct pool_workqueue *pwq,=
 struct work_struct *work,
>   	debug_work_activate(work);
>  =20
>   	/* record the work call stack in order to print it in KASAN reports */
> -	kasan_record_aux_stack_noalloc(work);
> +	kasan_record_aux_stack(work);
>  =20
>   	/* we own @work, set data and link */
>   	set_work_pwq(work, pwq, extra_flags);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 6310a180278b6..2242249c2d50d 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -521,7 +521,11 @@ size_t kasan_metadata_size(struct kmem_cache *cache,=
 bool in_object)
>   			sizeof(struct kasan_free_meta) : 0);
>   }
>  =20
> -static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_fla=
gs)
> +/*
> + * This function avoids dynamic memory allocations and thus can be calle=
d from
> + * contexts that do not allow allocating memory.
> + */
> +void kasan_record_aux_stack(void *addr)
>   {
>   	struct slab *slab =3D kasan_addr_to_slab(addr);
>   	struct kmem_cache *cache;
> @@ -538,17 +542,7 @@ static void __kasan_record_aux_stack(void *addr, dep=
ot_flags_t depot_flags)
>   		return;
>  =20
>   	alloc_meta->aux_stack[1] =3D alloc_meta->aux_stack[0];
> -	alloc_meta->aux_stack[0] =3D kasan_save_stack(0, depot_flags);
> -}
> -
> -void kasan_record_aux_stack(void *addr)
> -{
> -	return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC);
> -}
> -
> -void kasan_record_aux_stack_noalloc(void *addr)
> -{
> -	return __kasan_record_aux_stack(addr, 0);
> +	alloc_meta->aux_stack[0] =3D kasan_save_stack(0, 0);
>   }
>  =20
>   void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_=
t flags)
> diff --git a/mm/slub.c b/mm/slub.c
> index 5b832512044e3..b8c4bf3fe0d07 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2300,7 +2300,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, =
bool init,
>   			 * We have to do this manually because the rcu_head is
>   			 * not located inside the object.
>   			 */
> -			kasan_record_aux_stack_noalloc(x);
> +			kasan_record_aux_stack(x);
>  =20
>   			delayed_free->object =3D x;
>   			call_rcu(&delayed_free->head, slab_free_after_rcu_debug);

LGTM

Reviewed-by: Waiman Long <longman@redhat.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5=
14c8a18-0b12-481b-94c2-00cabd5a4a42%40redhat.com.
