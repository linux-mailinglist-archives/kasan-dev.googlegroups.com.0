Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVXWUK4QMGQEROMLIYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 082AD9BB477
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 13:17:28 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-460d76f1d7esf86399801cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 04:17:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730722647; cv=pass;
        d=google.com; s=arc-20240605;
        b=FkoxkQcvMdZcGE1r1FKENflYrgrm3IlQdcGgtKk4E544qIDihqfYNosB2c9856hGc+
         TjpBaeDCJq9PhYXBc6nW0CVpaWVraPdYKMu/9YE7L7nsPszTCpMGP709ZEj8wVWw7K5z
         VriWJfCYTBqF5bUkZvxIDWqi9UAqUlervwh4jFFaKAL7LNgEgZdskdPL7PmwkoqFY8BX
         6ChrPj1JmWlkBSX+8kCv37yvlMrkiGN67ddbhTUkW++4BYYPwQRe0Mfv9OMtPI48lBXQ
         1dFcPGfuOgqbrlLnqExOQyr7OlnLNzyfBdYn4d3I7MXCRIXCzVdGVSyFaQ6ieG5lFP8s
         syVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/ej5FjQXiKaGpORomIoBv53QkaVI6bOgpFXCOf2jsVs=;
        fh=41jCWGUHBZYGOCSo975fOiVGoYasxzMWtxuwmXgRxcE=;
        b=UkgBTW3Nq9EEJBz2LTjxfNEiiMp6B3KZJ0NjpbGXVKlRq0fdyW0PlCjAFIuc8gZ3To
         PjZGnjvEHgrTYTWWtkjrZJU+kX6K7gWimVclFJdZqh0XLoUeusoDSss5MkPeMsuKd7sk
         mo38Vw4ZWuBhGHXfys0swX7m+be0B831jn1zbJcOZVXRopVYU4uwrJg9eoo7814kB432
         +P6UDDia4Qz/Xc34OEhjMmWStwEDU9OIPGeXZCxcRZAm/GfMshRhEfEqPVBpY9xlZn9F
         k0tlBq24IV6yiqH/xgVit0BJ63F6upC9keVfkVRhjmnY6SMLQ3j4SlQtbkCVuHVL3UQI
         MDQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AQGEDZbp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730722647; x=1731327447; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/ej5FjQXiKaGpORomIoBv53QkaVI6bOgpFXCOf2jsVs=;
        b=wxsEbxtbpMzfvl1ATYwswYMRkTGVKYbVJbYx6MwGb87LwyzRak43gUvprZsSM+Jz7+
         0YjHCI4TRmspOVeJ96aEYszogxU1CUxeWF87S06Wy5bF9tpPKPZ16Z0Z3xXY1qiZY+Aj
         gWUySxhrGO409A5r0JnyYi0fRC73+x9VFbY9j5T0vkbMZUs76OsBsEiziGExOWI5TDKP
         y8CJliV9sCW2GW7jmNuEspHdZqCjz+g6UTVCri55Wl/GnGVwBPPd3b6JLdo4bLgAqF+A
         akTH68SQCfRp5ZIv7K2pU9Aoap8F4RJF/9waqdbKtB9RoT4DnzN+evKfEe7rMz6Mnveh
         Xw8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730722647; x=1731327447;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/ej5FjQXiKaGpORomIoBv53QkaVI6bOgpFXCOf2jsVs=;
        b=o0i6WbLyUytKDH6kzGjPBgm1e6StRoRpeS+T8rA47m0b0xgSDN2EcNFJfZ7/gFRUJF
         Dh5TZktj5xgXvrIbcSfsEMNg6l2vDbedsRet9jnP3oYuC0YNteejoK+NltgajosBIghi
         BODYInIgg71NhGIJa+EK688ZO9K1dgdN3MIRt6plXHWxzPjAb25LbNjSOJ2rYGN3VDw/
         DG1OeaLOfqWJuptp4dgmj0CbUuRGE/T/xjL9YcS29u4v0kZwfouIHUwXg19FLWhGFYvT
         XtXGtrT9GiBN1PV22iFrPkPcL7RoA/b37NGYredMyf/cUMiQicXuVEzB6grJ+bBDpJGU
         TYEQ==
X-Forwarded-Encrypted: i=2; AJvYcCWskq6Q1YDFOBXYWKpsUc8OZjh+nL0dEzQrHCR7bhaIv3sWNiIulnEj5knEb0/so2Prn/3Itg==@lfdr.de
X-Gm-Message-State: AOJu0YwcWmA5TcDxdFnb2hbpU30ORSIbr8tucBRbRC6oqtxk8RStv7/k
	nceDIYdiVwYn+L14yamzCh5VaUXi8EFWKeT9JbCdyDNEkW6/c2YY
X-Google-Smtp-Source: AGHT+IHlGuJqHTWMFG0sMa6aH87AZ77fRoNFUyZ/3iDkAXAXCL+qyAuj55zVEigb6Y+sp9ZHxn95pQ==
X-Received: by 2002:a05:622a:1b9e:b0:460:8d5c:34bd with SMTP id d75a77b69052e-462b8686c43mr210692241cf.17.1730722646672;
        Mon, 04 Nov 2024 04:17:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:671a:0:b0:462:ac20:a453 with SMTP id d75a77b69052e-462ac20a53fls45164931cf.1.-pod-prod-05-us;
 Mon, 04 Nov 2024 04:17:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVggrb+ijTMLy5f1iroTbFrdncMd5kDpTqdsC4/+r48TATIAYCuDZjkWGcmoKjl8otdfMSeY0VJIdg=@googlegroups.com
X-Received: by 2002:a05:622a:253:b0:458:532c:2059 with SMTP id d75a77b69052e-462b8686c1amr164430141cf.18.1730722645791;
        Mon, 04 Nov 2024 04:17:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730722645; cv=none;
        d=google.com; s=arc-20240605;
        b=OQhPeX+8HY8b3S5uOg8dRPPDTAql6J2IXxKfzZnq7V+l4ENphBY1+GgfEfo6V2Wy1v
         qeDM6biKjy1Gk2XdmeVc8LU7FuHFPVkRKS344V02T2pcjBCqIE773iJ8z3dMOmODfEiT
         ejtku+e4ymQDNMPMIdt+cBWkcP8WZm9kNIGzj80SyYYvyZujSF4DvwxTpQfbtXqtedJR
         fwd7HH3T1DQZMN6lLCT6Cnbw4KvSJJ5Hhij3PVqJdox2bVy+X0n5yOccuiCuZtjaUyDg
         G7RHNP3AhYR+gtmbVW1oS9U4X3fhDPl/MtzQEbL95skxTJ+L6gd7ZA9JS7zKK44c8/RR
         lIZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5kQZWCzIhxI9ZXfcfMMtM58/ZtX8V/ECMx6VB6xWUdw=;
        fh=QA/3hnVwK0bnlVnyzJr3hP4IjZlu1h4mBDZEalQxNEA=;
        b=DetzXF3Wxnz7lgPI2Pssq6Ihy0Fs7EcV6lGEjhq9mqBSr2PQmq9MdYIrrkNeXqY/PX
         idWM6ebJioBLwh6gp311swGHPGVPk8inOF0QGgnWG7j7vQ4/hLcJFwvJIt7cu53WcLwo
         gc0tkkDAhAsHIfBtvN2BPaJiw7fw4vVEPFofpuKk8rd52uILWQMEEOic2xnw6k9Yy6ZF
         UrQGwm1acH95bwDVuA8bLUDFDMaO3/vA9l7FSCgCbtVVELRNbNTLNO0upwqsD/KghBTw
         tbFJN4QbAjm6sUdcZ8o7q1KHiZiYOm34qoddhRG5cGxYuiLiaZFQTsfZtb6HStzl3qpK
         DyrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AQGEDZbp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-462acf84abcsi4361821cf.0.2024.11.04.04.17.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2024 04:17:25 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-21116b187c4so26245025ad.3
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2024 04:17:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUtwoj23UBKwrSqZJxckVXx1d3JYdf+jUbcFKI/AXAgARqTzb4TtRHWIwmCaaTFq5brwuYHXEjWVjw=@googlegroups.com
X-Received: by 2002:a17:902:e884:b0:20b:3f70:2e05 with SMTP id
 d9443c01a7336-2111afd6c99mr175024815ad.41.1730722644347; Mon, 04 Nov 2024
 04:17:24 -0800 (PST)
MIME-Version: 1.0
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com> <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz> <20241104114506.GC24862@noisy.programming.kicks-ass.net>
In-Reply-To: <20241104114506.GC24862@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 4 Nov 2024 13:16:48 +0100
Message-ID: <CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com>
Subject: Re: [syzbot] [mm?] WARNING: locking bug in __rmqueue_pcplist
To: Peter Zijlstra <peterz@infradead.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, 
	syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>, 
	Liam.Howlett@oracle.com, akpm@linux-foundation.org, jannh@google.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lorenzo.stoakes@oracle.com, 
	syzkaller-bugs@googlegroups.com, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Andrey Konovalov <andreyknvl@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Waiman Long <longman@redhat.com>, dvyukov@google.com, 
	vincenzo.frascino@arm.com, paulmck@kernel.org, frederic@kernel.org, 
	neeraj.upadhyay@kernel.org, joel@joelfernandes.org, josh@joshtriplett.org, 
	boqun.feng@gmail.com, urezki@gmail.com, rostedt@goodmis.org, 
	mathieu.desnoyers@efficios.com, jiangshanlai@gmail.com, 
	qiang.zhang1211@gmail.com, mingo@redhat.com, juri.lelli@redhat.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com, 
	mgorman@suse.de, vschneid@redhat.com, tj@kernel.org, cl@linux.com, 
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com, 
	roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=AQGEDZbp;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 4 Nov 2024 at 12:45, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Mon, Nov 04, 2024 at 12:25:03PM +0100, Vlastimil Babka wrote:
> > On 11/4/24 12:11, Vlastimil Babka wrote:
>
> > >>  __alloc_pages_noprof+0x292/0x710 mm/page_alloc.c:4771
> > >>  alloc_pages_mpol_noprof+0x3e8/0x680 mm/mempolicy.c:2265
> > >>  stack_depot_save_flags+0x666/0x830 lib/stackdepot.c:627
> > >>  kasan_save_stack+0x4f/0x60 mm/kasan/common.c:48
> > >>  __kasan_record_aux_stack+0xac/0xc0 mm/kasan/generic.c:544
> > >>  task_work_add+0xd9/0x490 kernel/task_work.c:77
> > >
> > > It seems the decision if stack depot is allowed to allocate here depends on
> > > TWAF_NO_ALLOC added only recently. So does it mean it doesn't work as intended?
> >
> > I guess __run_posix_cpu_timers() needs to pass TWAF_NO_ALLOC too?
>
> Yeah, or we just accept that kasan_record_aux_stack() is a horrible
> thing and shouldn't live in functions that try their bestest to
> locklessly setup async work at all.
>
> That thing has only ever caused trouble :/
>
> Also see 156172a13ff0.
>
> How about we do the below at the very least?

I'd be in favor, it simplifies things. And stack depot should be able
to replenish its pool sufficiently in the "non-aux" cases i.e. regular
allocations.

Worst case we fail to record some aux stacks, but I think that's only
really bad if there's a bug around one of these allocations. In
general the probabilities of this being a regression are extremely
small - same as I argued back in
https://lore.kernel.org/all/20210913112609.2651084-1-elver@google.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ%40mail.gmail.com.
