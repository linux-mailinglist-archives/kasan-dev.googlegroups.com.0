Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU5WWDBQMGQEOKNB2VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 941D9AFBB89
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 21:09:09 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-235e1d66fa6sf29058475ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 12:09:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751915348; cv=pass;
        d=google.com; s=arc-20240605;
        b=E08OVss2cwMIFyhWp368Gc+K1kuMgBNIIpb/Cb+uLUNsAl3Q7fI+DkCrjJJEalJwQ5
         VNMDIG+b0C6Yhw+3QQzGb9AF17si1jEVbhLttbk4y0N1oDna7unmNLJjdrY4VQKtHoq2
         Szh/BwRj2NEZmA1j1Pb0Yi62cY03132+nXTzlP6P6EbVSdlPyuHkauevjUA9tKv+HYnr
         slOEGHeo4pXE7q+0Wgnm+fGZdOhTRUpTm9xJ5AZmkUDF0Su6C0BzvQ63heW8OlUv5O3a
         qUT8SLW0pudvkAlwynvC8eogzWna0kJZcKqzWTXQNm3EZr6jjTrAS+R83pQ/AYVl1gFY
         E3rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BDMzqBjpt9iUWdEWsW0J6c6ntjlq8YsMTuT0E58Nauw=;
        fh=JVxG+z9Bz0p8NbHbQcEvdvaCyCPaRUdVOB2zZ1odbqc=;
        b=K5SEWRWVLKHPJ+LSmgKXuTKDmpVAAfWKbATd2uW9cleOVNj9iKwH9ivOkXG4PxKsVw
         RDxYZWPevNp6dWebewYikW1sKZAUfWGS+rM23SpoX/BkOLJGoCu6vOuiDgk9KpT3qWX0
         J9MigrUwHgF6L2YJj6N5cpem+2Smcy0C/HOR7eHAbU3K/Uwk2OWM7uCvWmT017HUrYPG
         f26zkJkqDgkVe3I/v3+KgELZdptXYB4fPcNPbz3Jm15v75/rnyvWSU2Ya9A4MhCsCfeO
         tJjRZJjy2xiZ0PbsyZqakr51h2MNh+9J14QO/F8r5MpPbkDHec5AC19v8PytEWqydZdk
         uRfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FARnVJHE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751915348; x=1752520148; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BDMzqBjpt9iUWdEWsW0J6c6ntjlq8YsMTuT0E58Nauw=;
        b=TucvoGFtXAbHu2iHWNAGVaKR0Nd2dGten6R6szkAOTN0KlCoyEReu4xMajR/wiO6cb
         sKs6dixaGd5Qcpyhhs/nsu4AAri4ZMFQh3/99bNaof/fsIJg+E/dwq/i9Q5AWGfUeTPL
         jlIXX0JkjMQ4QsfYhUJHqzb42fkdEnsYfF7Sp0u3yYwfIZ8WomIrI5BNomq4FTamU9V9
         uSS1TRmx9f3Xdjh7IPaYmDkhBoMP/hSSo3JL0Jum2lpD8qpDJ6C0OT5QpkE/gSRO7k7B
         pQDPeBeWqN0+dy85opPMx+9eQjRfQYq0iSGUB3EWjI14LQJOMMj/Y6lHp9AVvpgawxTO
         XELQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751915348; x=1752520148;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BDMzqBjpt9iUWdEWsW0J6c6ntjlq8YsMTuT0E58Nauw=;
        b=tnIILxBkt4mMwFg+np91Vuo6GPVDhyNylyLIXiKN+G/M15lG2I24GLrZOPIzuV0gF6
         YSO4aQLwIyvEN2p0u//BVMx+jJECF8fxvj4ZkaUCEM06XU01bs64AFfgszEV3rIPG9tk
         4wxrxXYO56ab9MUlWxpDVCT4yWMZa6mmVQMUBfFZnE2mIaGJiqmhgpvoV7jomYjhAQZV
         Z+xC9eXQkkCSDHPaqaDLtALQknh6IP16a8VkWs27kAa4/phTWN4C6+YijHY16krTzm31
         o6cEvD0LCt5aA8mPrQMgiHAUZz6Dxu3kFeEXupFQzYqT+DRZ/TW4+LKyZxoQwvvBR7TT
         QpNg==
X-Forwarded-Encrypted: i=2; AJvYcCWaWMO7yAcp15fsVwWzNJjrkz7traWTP0gZJfCUHkN1z6P7vwCDEj2UGwASG7HrCw+g+6h+1Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw1Ii9t5tZBF7/6ucXMoOgPcod2A/YaBDbukTrSv5bYPtgEC9Bo
	uEcKtbjI0pRSnJfVw7vS483ac6D0HaZVjLHu43RhQnAHVTLV2lg/RmG4
X-Google-Smtp-Source: AGHT+IGqh+DzEF2VcyXGpv8QQ3i2OL8qEFUz/sQB1s4Krr5cbtvmUg0VHFTCTgUiOiOQNl70eMIZJQ==
X-Received: by 2002:a17:902:f60e:b0:234:cf24:3be8 with SMTP id d9443c01a7336-23dd0d1c13bmr7435175ad.28.1751915347861;
        Mon, 07 Jul 2025 12:09:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfnf3B3z+IpFr5CK5JXWoah4oCWgSMpSyQjQty8FG85sg==
Received: by 2002:a17:902:d486:b0:238:cdf:5037 with SMTP id
 d9443c01a7336-23c89ac5153ls29813515ad.0.-pod-prod-01-us; Mon, 07 Jul 2025
 12:09:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXCllIgxRaTYogAVv/79RThXKO0qnH27cLy4U/syuVHJihKFzVqzTv7au+3/19rh7e5i/CLzqynayE=@googlegroups.com
X-Received: by 2002:a05:6a21:32a8:b0:222:d89:7a6b with SMTP id adf61e73a8af0-22b45044395mr313676637.19.1751915346284;
        Mon, 07 Jul 2025 12:09:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751915346; cv=none;
        d=google.com; s=arc-20240605;
        b=RMwhXC98L325rcZwybO6v1v41dX3TvKea4orZ1tijGsXKQFLVFBUWR75YZO27yc3S6
         ujZK2q6xLVp0dHCs9FYdHrlJmIUgMWaOyA7HKP2FuHruFWoRRik98y30ZuhG7zKnNiQH
         Pta8m7LOXoJVTnjDZuUp5wsv6ANIVh5pMCT92OjhgxE/dnPHf/sr896CqaxIvq8bRTny
         CQ7RWFJZ/2WvMWQQ1IQxOIPQVQQKFS/epKNCwoF7KoqXT2HPj1GKOXrcLv0XnWa56Lco
         s7WtLqdqNDhCzHTJBiRUvJ+URyTuZqcuDDzUFtJcn+lO4L6XFcdc7/Mq+JS5S6erk2G4
         Tp8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SCwp2HDrQpkP/bLom9Qnn8CJJY2djxK53T9Kul+hqH4=;
        fh=7P7R8Q5pTRLCYjhNf5nWmqHTYx0N8tiCQkcAKsD3IcA=;
        b=a2R/LK30enwwSFlTStcKv7LGAilX8eg8YsMnTG6VGOJvgrXCfqSfbGXTxoWARGFQuH
         W9O5v/iR8QggEh/FEn8+ncmcsNpJC1dCJ6Y3EDz5WbLuvGlwCU4vQPoIuYBYqCRO/C1r
         S/Qeo8SscrWL9U5hkBeaH1SdW9SWXiU60RAPRLNruSowrnUgBAJiUxkdxvt5hU/gIziT
         79A5CdIlP1jjYWf08+ZvxrznzVmJ2MqKhh+e2pLesaieNx5IONhuxBOWVzEE3lTtwI/y
         UgXdq/vWWNCPCFeyk1j2uUBMjFw6Rr1QIX1iAycEtC1y4jPxGHJEdRILFn2b1Zxh6zwT
         2nag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FARnVJHE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-74ce39186b0si439986b3a.4.2025.07.07.12.09.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 12:09:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-b271f3ae786so2770224a12.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 12:09:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUlmaH+nmrt1NHBd4OxYHhA1rvKlEBP78pe+4hv1bbSGEzycHvkfit4c3FpD17AjWJ6RfMFrSI160w=@googlegroups.com
X-Gm-Gg: ASbGncvdwg99naZNTujiqqT6BmUTXUn9NWCKEcl4WhEMXS3IbJbo7YaPpKJaBG/Fw2Q
	ZHMeZRn3s0IC72vU901y3s+isBJstIfaoDH90fQvFgbL+h7XqEgRcAwE8U0vJYVnPsAsMBh9QIY
	JLPFruYOGAwkSu06sIWLVUrjwwZYYbzYdc8fDeeiLYzyleZavvsPdiZ6FyCD4Mke1Ecy9Wlrk9p
	w4IrEVpZ+vH
X-Received: by 2002:a17:90a:a409:b0:30a:4874:5397 with SMTP id
 98e67ed59e1d1-31c21cd7f0fmr159082a91.9.1751915345690; Mon, 07 Jul 2025
 12:09:05 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751862634.git.alx@kernel.org> <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CANpmjNMPWWdushTvUqYJzqQJz4SJLgPggH9cs4KPob_9=1T-nw@mail.gmail.com>
 <kicfhrecpahv5kkawnnazsuterxjoqscwf3rb4u6in5gig2bq6@jbt6dwnzs67r>
 <CANpmjNNXyyfmYFPYm2LCF_+vdPtWED3xj5gOJPQazpGhBizk5w@mail.gmail.com> <gvckzzomd7x3cxd7fxb37b6zn4uowjubpyrnvj7ptzz3mr3zq2@xovzgew63mxr>
In-Reply-To: <gvckzzomd7x3cxd7fxb37b6zn4uowjubpyrnvj7ptzz3mr3zq2@xovzgew63mxr>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Jul 2025 21:08:29 +0200
X-Gm-Features: Ac12FXzEXTnw7qQ8nVMOKnW9TwW3dvF1frJO3Pa1PT5XcHth3lVbJtQONABfUf0
Message-ID: <CANpmjNO0_RAMgZJktaempOm-KdY6Q0iJYFz=YEibvBgh7hNPwg@mail.gmail.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Chao Yu <chao.yu@oppo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FARnVJHE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as
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

On Mon, 7 Jul 2025 at 20:51, Alejandro Colomar <alx@kernel.org> wrote:
>
> Hi Marco,
>
> On Mon, Jul 07, 2025 at 04:58:53PM +0200, Marco Elver wrote:
> > Feel free to make it warning-free, I guess that's useful.
>
> Thanks!
>
> > > > Did you run the tests? Do they pass?
> > >
> > > I don't know how to run them.  I've only built the kernel.  If you point
> > > me to instructions on how to run them, I'll do so.  Thanks!
> >
> > Should just be CONFIG_KFENCE_KUNIT_TEST=y -- then boot kernel and
> > check that the test reports "ok".
>
> Hmmm, I can't see the results.  Did I miss anything?
>
>         alx@debian:~$ uname -a
>         Linux debian 6.15.0-seprintf-mm+ #5 SMP PREEMPT_DYNAMIC Mon Jul  7 19:16:40 CEST 2025 x86_64 GNU/Linux
>         alx@debian:~$ cat /boot/config-6.15.0-seprintf-mm+ | grep KFENCE
>         CONFIG_HAVE_ARCH_KFENCE=y
>         CONFIG_KFENCE=y
>         CONFIG_KFENCE_SAMPLE_INTERVAL=0

                     ^^ This means KFENCE is off.

Not sure why it's 0 (distro default config?), but if you switch it to
something like:

  CONFIG_KFENCE_SAMPLE_INTERVAL=10

The test should run. Alternatively set 'kfence.sample_interval=10' as
boot param.

>         CONFIG_KFENCE_NUM_OBJECTS=255
>         # CONFIG_KFENCE_DEFERRABLE is not set
>         # CONFIG_KFENCE_STATIC_KEYS is not set
>         CONFIG_KFENCE_STRESS_TEST_FAULTS=0
>         CONFIG_KFENCE_KUNIT_TEST=y
>         alx@debian:~$ sudo dmesg | grep -i kfence
>         alx@debian:~$
>
> I see a lot of new stuff in dmesg, but nothing with 'kfence' in it.
>
>
> Cheers,
> Alex
>
> --
> <https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO0_RAMgZJktaempOm-KdY6Q0iJYFz%3DYEibvBgh7hNPwg%40mail.gmail.com.
