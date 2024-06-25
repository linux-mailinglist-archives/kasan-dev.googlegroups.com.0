Return-Path: <kasan-dev+bncBC6LHPWNU4DBBK5Z5SZQMGQEK6KCKXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 431CE91712E
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 21:38:21 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6b50430e9c1sf90371326d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 12:38:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719344300; cv=pass;
        d=google.com; s=arc-20160816;
        b=WUaOBkhfQPDMyE8pcqgibyy2RfuR65Mqi8sxpcQXc9MFg9pcB/W29eRxiVZtLZS+FM
         KhyzyHXGgLgamx8I5ICwgfyEaz0ZStnHdzgLfo2m90W7boSEyxTf4aXxQitXPDKA1DNT
         pOy/DXtAQqhpsudlR95Nb3GSG3QnuQVlMxGFc7VPNcEoSlyZC/E7h2TPSMz6MxQ3rECo
         xQSfmVg79fReoFNas1MvUlH6brSPAkmLRa6UmZIj7aKKzgD3fIr4BdtCq9pIiQsgDWPF
         bG0b6cTvmJQna8M942myn2XgYAK92BUCJj9INcnfnCuRMqy0yDubknWQpzl744PnZ5kL
         pPUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=ooplZnyN1mrHYBqaDl0WDe4x50BPSMixNgPuBB5YAdY=;
        fh=oPwvZbC/Zp6wQsamE+R2en/UnsLsgqvTd1rugrQ+v8k=;
        b=AEA5483ghbb1HJ76f6DNBTWeIvh5F67v0q8Rfw59TUR5KJpr9bcEr+KTm0nFSXQ2NG
         6c1rESLe66ZaaELRII6Ah4Zdsp8HQwZsxsKOiKRa7WXkrlCmtEMFPWd05sAEIC/qsKwB
         a/MtZKh6IJum9b2geBTZPUnE8Y5XblDK2yerETdnzDNO/AQi0aSn0LqmsrQ1iNbXgVmY
         q9Niy1wL+RaF26xShdOTr9A3tnEnqrGYLe6nQaV+USAEYNRGfGGODL/19AzSHutAO6a8
         Eqm+0Sf0De9C7fN7gMRYhCWylvQtks45bv68wRy/2QYK7TJ7JyyYrCC4EIJnScpFW5sO
         x7IQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AJ39h90N;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719344300; x=1719949100; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ooplZnyN1mrHYBqaDl0WDe4x50BPSMixNgPuBB5YAdY=;
        b=swhH8Mokqwqdj5x8PZ68OXGJqcqtceSMaHN9GXC7eMxwyNVMzQsHFeXzTbFK2wlT53
         qXxo0tv1+j1nGIGRBgetE4GiH9bxYs97JscFUFidsA2BsYwG3kBgS12WxiIVVJZxPXza
         /P/rIc9UpYslFiAeesCfM0t5vlvxj2KFcI1OqosEY6vowruJd2Fz6KnzAvOMHtSHrhqo
         ni8x7z3db4+K8G8VjsDS46yoUNkotwkabRM2HOeKCjA19p34A0YehaOt4wkQjkIeRcPP
         eaSh/D7zeHDRGGVr4YJ5Y5W45TkX2A+FXGbgsjUbFKGMl0YO/x+gkblKHFaodtucJ3UP
         xGhw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1719344300; x=1719949100; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ooplZnyN1mrHYBqaDl0WDe4x50BPSMixNgPuBB5YAdY=;
        b=B6PyB8LqLcaYYqN05AnIKgH2sd3YUB7M1Uk1LqLlFtztm3aY9e0B2zLF7mOJVgNB69
         szeQ08IApg+I26n6+1WrrwjsgcIzBQM9NALHkyMH2aM6H8JJMm0zkY6yVicwf2RJa5aP
         wPIRwq/nHtsTzlo/NG0pHqwNdrZ27j5YdxRivxzZ+AZGmXmPCxM9pY1J07JzHsnaFyGo
         vN8YplVNcH9ByB9CV1oR73A56Wv3xGxiaDGLhxNu42ZR3+gliWcFBsPRwMwBkbGsEITo
         JnIh01q718jPnkRd6JLz84gPB0SsuwMf7II+PBa9K7ckYKJTMEwH/5KynVeRHtVnjn0T
         cMLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719344300; x=1719949100;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=ooplZnyN1mrHYBqaDl0WDe4x50BPSMixNgPuBB5YAdY=;
        b=CnB8Awx6oXmfXPREziU/hoF/UhumohgbNEwwX8pY/Gyuo/u+0VKbr3jjESamFxtOS1
         Kv6SWGzhOUaZcY3v31PNbNRoN6k5ikUrN8CQn+ctr+UyhZwyz55pS6nXLeYzAAfzRf2L
         CSG8Pre8YU0djAfRY2g2x1my5+ahgkL2CwAgitCdh1nCsI8TGdl4Z36a5WaxQATbOzCL
         cKQ5yKo1FjuAjKi3gCPoxD4M/RymiL4UGHRcSOhWbNQGmstOVgX+2E1NfBw/4DVU1psq
         XACH0ZXBm5VFedbUeudC71wapjI+LnYiy8OaJQiUpF/ROzP7VThDgK/ublIDQO60gkHF
         /skw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXHSgKLSliJnL0n9qq//cjMxDu9d1dX1bMcpQDG7sdocesB1JKj6KFa1OkLgR8MSSGkRIMlU7VGcjnlO+CtD5uS2DwUbyCErA==
X-Gm-Message-State: AOJu0YzT7Vczu93XxDigZFvE8H6qzsAIKRm4CnsZXbU1hc9KrQrZ3mlA
	scGLzEZxVKfgGHQA+i4YVypsjAoCUTSY++Dm3idGl28uX+FCRURD
X-Google-Smtp-Source: AGHT+IGRkK+evUcH6uu2vy/S9JOHzmlf0u19PPaCmgdd56HExTwqRfbBsOYkRhmetieyaHLvEVtnrw==
X-Received: by 2002:a0c:e611:0:b0:6b4:fea8:6bfc with SMTP id 6a1803df08f44-6b53635d67amr95002946d6.10.1719344299830;
        Tue, 25 Jun 2024 12:38:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3113:b0:6ab:8f81:8496 with SMTP id
 6a1803df08f44-6b51032d628ls71226486d6.2.-pod-prod-01-us; Tue, 25 Jun 2024
 12:38:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5NU6x/g5hYJdPBBjs+qLnOc76RXx9oFSuYaLYZD99n1xw9JIgnZbo8L2TIQnVs/ZYs5yOKWl4YUhlGlN9wzWVZ5Y9BmxfAgCcEQ==
X-Received: by 2002:a05:6122:182a:b0:4ec:fddd:a8c3 with SMTP id 71dfb90a1353d-4ef663f9d0amr8282430e0c.12.1719344298344;
        Tue, 25 Jun 2024 12:38:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719344298; cv=none;
        d=google.com; s=arc-20160816;
        b=TsCJgcjZ03gjlc76TbKAITmqjViaCPn3A4blilEJr3gIvID74vIEECHVPq4MiYhaET
         z7XFUnKtvSxAA+B9VwEDKVzduy/mH6O6J9aNEKxZejVslXq9GOnFpszEQuqrREuo9bhb
         NDQkewNsY0Rh9GAvXoydG1BCGm0AcV0FSNS4TtsFg+4XOzR3wq+2zO+Ijvgb43MGYDyG
         w8FVttto74fBWvcEy6NTzdOQ9kpeRFyZRizSXM21RKBtiy0KKPoOQuMdV70gWywZrKCd
         T332zDRQVlZ4Dbk+FMh9aPsCdbM0hHxNGUjNI5SdqtdJzqzT0j64JVqCwOmqZSl/J4Qq
         zwXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=i+5LEc+OBSMgdXBP2ouh0qVEc/wr3Xl6YlFgRK9NbOk=;
        fh=gVnpOdvqqwzVg2aDy6uziQ/Ud3v/75eLMO0J7vMTKWw=;
        b=D7+yXr736kLtzXKRpMLU638riAK907IvZ1xT6nVAuUUy2rdvr5w6jy4LLL+fhlyqiz
         Tpbf7M2xPnMyKdxS+hizFcnd3m7Dp0bhc5IXj0c7P59iRDtV/9dRCr5z2fc/dFOu5ynQ
         aF5l0601GfoYXv1VLx5CkVRdbxsVaCSpjNvhEGgaxhb3OVbOtvb+kcMPVMX7wuTqrh/s
         z64I3WOB3NbYNzP6VXgF16PeqSlaJDyD6WkBJeimLoHZ0voyVvmDrlXuK+oNclOnAVeu
         njZNNC9ay8FbFgAsc7KbOkwyVMQROS41zkOfPWi0tqV49Jwj2C/r7OkdjZg8MGXn9uwn
         nyPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AJ39h90N;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x831.google.com (mail-qt1-x831.google.com. [2607:f8b0:4864:20::831])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4ef735ab2aesi129178e0c.3.2024.06.25.12.38.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 12:38:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::831 as permitted sender) client-ip=2607:f8b0:4864:20::831;
Received: by mail-qt1-x831.google.com with SMTP id d75a77b69052e-444ca0a84c5so25167731cf.1
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 12:38:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW71nj/BJ8IQPn31O73ofil43cnvf+uaWmhK478iQHrmRVnU5w84FSQ01uWzQ1rtl44JKzigWs/XigbPdJ1+ZQ2tzghn2lRhN6zDw==
X-Received: by 2002:ac8:5dd4:0:b0:440:1c16:547f with SMTP id d75a77b69052e-444d3c0aed9mr122255401cf.41.1719344297880;
        Tue, 25 Jun 2024 12:38:17 -0700 (PDT)
Received: from fauth2-smtp.messagingengine.com (fauth2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-444c2c3e5b5sm58778321cf.75.2024.06.25.12.38.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 12:38:17 -0700 (PDT)
Received: from compute2.internal (compute2.nyi.internal [10.202.2.46])
	by mailfauth.nyi.internal (Postfix) with ESMTP id CEAD91200069;
	Tue, 25 Jun 2024 15:38:16 -0400 (EDT)
Received: from mailfrontend1 ([10.202.2.162])
  by compute2.internal (MEProxy); Tue, 25 Jun 2024 15:38:16 -0400
X-ME-Sender: <xms:qBx7ZmyTkk67Ybc-mSynYuPRafaBlYzIiXJxfzwE7nF7PPVCdj_ylg>
    <xme:qBx7ZiTpYfyPcuAFK-R_tMwgZdP2BdaQibXg1Xs_iFr3apdM2RHCtwiWh0P7YrQgM
    lAu4JODeRqLygB0hA>
X-ME-Received: <xmr:qBx7ZoX0tom6ICw_nxCdLafA-mSLBl1GPhuLdxgTGP65nBZlAX4a6WiW-QlDOg>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeftddrtddtgddutdejucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepfffhvfevuffkfhggtggujgesthdtredttddtvdenucfhrhhomhepuehoqhhu
    nhcuhfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrdgtohhmqeenucggtffrrg
    htthgvrhhnpeehudfgudffffetuedtvdehueevledvhfelleeivedtgeeuhfegueeviedu
    ffeivdenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpe
    gsohhquhhnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdei
    gedqudejjeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfih
    igmhgvrdhnrghmvg
X-ME-Proxy: <xmx:qBx7ZsgGFQjaQ_uS7IvnQfBSOMBV1bTbl2UcMlzij-JIDaYF6Wk_hA>
    <xmx:qBx7ZoBXr0HfsyRoPj6ULAHE78TcxIkW3rXl4TyM8oFtDtz3HNwlDA>
    <xmx:qBx7ZtLdK6sK_1NQL89itZCYgN0x5CPLUv7H2Oso_WU2cSUPK7ywoQ>
    <xmx:qBx7ZvCvLVeWtU_Et0OSkqB3S4p-2IWVzblvlYjZc3OAmgtmzyp9uA>
    <xmx:qBx7ZgxWdoTdHTHPNc3qnI-U0B2ElqEa1H16-A1UZoboanNBZlU6KeVj>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Tue,
 25 Jun 2024 15:38:16 -0400 (EDT)
Date: Tue, 25 Jun 2024 12:37:39 -0700
From: Boqun Feng <boqun.feng@gmail.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dave Hansen <dave.hansen@intel.com>,
	Alexander Potapenko <glider@google.com>, elver@google.com,
	dvyukov@google.com, dave.hansen@linux.intel.com,
	peterz@infradead.org, akpm@linux-foundation.org, x86@kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>
Subject: Re: [PATCH 2/3] lib/Kconfig.debug: disable LOCK_DEBUGGING_SUPPORT
 under KMSAN
Message-ID: <Znscgx8ssMlYUF5R@boqun-archlinux>
References: <20240621094901.1360454-1-glider@google.com>
 <20240621094901.1360454-2-glider@google.com>
 <5a38bded-9723-4811-83b5-14e2312ee75d@intel.com>
 <ZnsRq7RNLMnZsr6S@boqun-archlinux>
 <3748b5db-6f92-41f8-a86d-ed0e73221028@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3748b5db-6f92-41f8-a86d-ed0e73221028@paulmck-laptop>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AJ39h90N;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::831
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jun 25, 2024 at 12:06:52PM -0700, Paul E. McKenney wrote:
> On Tue, Jun 25, 2024 at 11:51:23AM -0700, Boqun Feng wrote:
> > On Fri, Jun 21, 2024 at 09:23:25AM -0700, Dave Hansen wrote:
> > > On 6/21/24 02:49, Alexander Potapenko wrote:
> > > >  config LOCK_DEBUGGING_SUPPORT
> > > >  	bool
> > > > -	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT
> > > > +	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT && !KMSAN
> > > >  	default y
> > > 
> > > This kinda stinks.  Practically, it'll mean that anyone turning on KMSAN
> > > will accidentally turn off lockdep.  That's really nasty, especially for
> > > folks who are turning on debug options left and right to track down
> > > nasty bugs.
> > > 
> > > I'd *MUCH* rather hide KMSAN:
> > > 
> > > config KMSAN
> > >         bool "KMSAN: detector of uninitialized values use"
> > >         depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
> > >         depends on DEBUG_KERNEL && !KASAN && !KCSAN
> > >         depends on !PREEMPT_RT
> > > +	depends on !LOCKDEP
> > > 
> > > Because, frankly, lockdep is way more important than KMSAN.
> > > 
> > > But ideally, we'd allow them to coexist somehow.  Have we even discussed
> > > the problem with the lockdep folks?  For instance, I'd much rather have
> > > a relaxed lockdep with no checking in pfn_valid() than no lockdep at all.
> > 
> > The only locks used in pfn_valid() are rcu_read_lock_sched(), right? If
> > so, could you try (don't tell Paul ;-)) replace rcu_read_lock_sched()
> > with preempt_disable() and rcu_read_unlock_sched() with
> > preempt_enable()? That would avoid calling into lockdep. If that works
> > for KMSAN, we can either have a special rcu_read_lock_sched() or call
> > lockdep_recursion_inc() in instrumented pfn_valid() to disable lockdep
> > temporarily.
> > 
> > [Cc Paul]
> 
> Don't tell me what?  ;-)
> 

Turn out that telling you is a good idea ;-)

> An alternative is to use rcu_read_lock_sched_notrace() and
> rcu_read_unlock_sched_notrace().  If you really want to use

Yes, I think this is better than what I proposed.

Regards,
Boqun

> preempt_disable() and preempt_enable() instead, you will likely want
> the _notrace() variants.
> 
> 							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Znscgx8ssMlYUF5R%40boqun-archlinux.
