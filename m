Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH6R326QMGQEIVV7UCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 47D73A3E744
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 23:11:45 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-2aa17a7d70dsf1392361fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 14:11:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740089504; cv=pass;
        d=google.com; s=arc-20240605;
        b=gBeVxS8oJ+KhlVwDTKW09kNf+5vIknRoktHSIC9QuTGNz6xMzE8L86QPNBu+53ZCWJ
         kS0+tcF8SAHfeCq9/cbYbD8VocDK0xjyTLrpFNPVounWhHuxZNjmuUaosEAXdqEyfA9m
         qGZToB/OxvJlB3bz52yV+sygAZKE59jps9OKF7j7a840iTB/rHtmzFcPN4m+5ZuG/T9o
         +ipr1SQ5U3O3iTPWzlnUQXNnNrl6FMuHFQIROL877muZfpqfG0XxPHR2YbLzCYB7Q00J
         69JfeAQSs0PHttG4k3NorTgWnKwCTpg0TAO3VdKrkbwKe9by6oX4GghW+wKwxE6Pmse3
         mGiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=d+rpXCeSR0zqoahPK6HqXncL2hNM4DK+JT4XRIBcv58=;
        fh=ziXFZeQlozAiUFSWFOSWhRYUx41a7WwWpU7MsWIz45Y=;
        b=ZiyM2LuQ8g6Wr0QQmLGSRyDatcKRAQCTGlKPyV0/aoitGXQMqaRIrLlwuGTPamwzjh
         xF6z+jqB4reoWI1MCscbHbKzA10Rp7WzLEnUk6T+Zze8ZtJfHbTU+M2bva1ndeuG2NKi
         kEEA4MJkccMCeiTw87O05mJ1nD9QLNfpOcwxF4uKBvDJ57LWnnhV9l88Uh4ekFOK2W+p
         /fbluUbTq+wfDgnjHDWT5jvcaOd7FWdYrgqAE4RCHwkt2sy304NwZReRC47oKhqaJIc8
         wJMLTdw39me2gS2nmpinOq55tlBFlAo8lb2D9IhxrTNIO5I0bVMQGRcWUywEPwIYlpPi
         VX/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Vpe2ZO6g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740089504; x=1740694304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=d+rpXCeSR0zqoahPK6HqXncL2hNM4DK+JT4XRIBcv58=;
        b=s75JPosZDBi5XNNcRgL2oQCOcvdwzoygGwQorucXeGMamVo2B7BldtG1vEFTZz6da6
         4iHyOlfrxW4BGjTsNkASovcCAcNWj3BtJ8CX2M0FYEUEGYMvlqcRcmoejNq2C/lrCb5R
         Ghx7foHQSJqEyo4owpMB15QknQp0wsEjzL+5GVNe2c7Sh88QzasZUEhKfmQjmaj2oDcS
         9fUDG+Hk6SpryRhdB+aK34cGkJQouPoDc89bOZevrC+YG9ex0Ag6yXFPaYB8D6qc6M+k
         wrCePyY6ot9u0SXsiPGFe9ai7bWXH+mxQubvJ5F6UgdP+vgaURQvtAFUG1FtpNaSYqdc
         weDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740089504; x=1740694304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=d+rpXCeSR0zqoahPK6HqXncL2hNM4DK+JT4XRIBcv58=;
        b=QMPyWCXQUdECuuIXnv0z4tX7n6xwN7mJD2fAX5l3Vc7pgiTYJNkxKBuDDW9UfK+vJz
         BC6iH2M9m5TEneo/F/Db/4WCk1s36MIrhtx6x0NdW8vKvMI1ovjxHQr9y8V0DPb1Pr31
         m8jhbxR2UV4vK2b4KI1lkEw/mV8pLY7qar/SGs0OXilw90hiKmdQTYpkYZ8MGcotlhLE
         M8yFKCIlBE46RelzOBtG4Xby345fmJfLBn7o+Ac9/U3PXuSZE3abYJw8VrLZTlDlkLLu
         ft+IMxdqDFl2uKX1JdxfKGvy5A930VrfI+0jLKH5yqmxUEatDiZAXuit5UqVqRIYyLjn
         eW8A==
X-Forwarded-Encrypted: i=2; AJvYcCW2C5FKZcOpbCBxYZMpVgTvbOL+gzESWkXuXSP5ASyntJIWDOHqDLKh05hEGhHwSvPwqzcBMA==@lfdr.de
X-Gm-Message-State: AOJu0YxKrWujiRp5O5q71ZZ2O2fTOcq47w2Lxlehhm7xUaldxsSkwO1x
	j827yfXrzF49BJmeyK1Xv5I+KiiVZpkYvogk5Aqdap4qWwX9PQcs
X-Google-Smtp-Source: AGHT+IGGiMG687C0hzthzMo9RPJ9cpLvW8kbxQEgE9ccQRU5Me01CNKcCcZOs8KN2tTX8Gh9/Ks73A==
X-Received: by 2002:a05:6871:108:b0:2b8:eb06:57e2 with SMTP id 586e51a60fabf-2bd2faa67a0mr3906971fac.1.1740089503808;
        Thu, 20 Feb 2025 14:11:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFP0qRuzksdDV4aq+8Ug8vt3qDN6I/GnzgLY7ppdOwqTw==
Received: by 2002:a05:6870:4d04:b0:2b8:aad4:83d with SMTP id
 586e51a60fabf-2bd2f39998fls798106fac.0.-pod-prod-00-us; Thu, 20 Feb 2025
 14:11:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVM1fFiEDOhnFk1R/rCiS8BC3Mbrmg9KhjhQazSka1igujmCGmyOWB1CIAUp9rZvX7YL69lOMWfaEk=@googlegroups.com
X-Received: by 2002:a05:6871:4b0f:b0:297:683:8b5b with SMTP id 586e51a60fabf-2bd2fba002fmr4440853fac.10.1740089502919;
        Thu, 20 Feb 2025 14:11:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740089502; cv=none;
        d=google.com; s=arc-20240605;
        b=fLRsItgony/rSHuKQvTBdzg/tOKkFiV4YuyXec3ijboS2OTbnqYbJiae3DyQyk0gk9
         DfZkO+mDrYIYsUAW6pLbauuExflUYdeKNnZbsjn/oQzGNY6TK+k2jYHYe+XHaTN+ANSj
         ga7aIaHWiFhUcB7fXyMQAbz7Qu600iylyXNUWiKUHu9MYyMMBBUb3drU73/TXX3uidBt
         qwSsCZRBe7vlZT/D4vRAIjleIFMAECPjpNtE9ftECZmrJ5Vl/GCzqM1Ine0tTUyMPiYP
         HFrP2LXf8lWap7BX+z0GgN4awEnndJeKTeMyGEo4FyXdYEPzPxNAQb2qaMjCRfEIRAWt
         GJ3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uxsIjlZZ4NvCMtUBbUKBaSillRpgb0iDSMQ6jrfUP4s=;
        fh=Cx1yRSEjzkzXFLeJ5t7I+DkGmSnmOmA9HMHIOY9VW9Y=;
        b=Y7uIUMSAMgzPnDy2GKAUrTlQcpNsqf8NZHxBR9rZqIPk7xRJOqEYsCpO3X3jJUCLAP
         szdY205cnWJWeMVYXUUKx8mQ7n7UoQn6USLgr4M5K8D6xfKn8VUI3VyYpdTw3gTTC+/s
         ybqm0YvF7eZOI1J5NFS8fjwS6I8tcsgFor1IEWQMc5XKPP+hO9ErUoFo41V39lHVZDsr
         a+cbCK/fVBmPlyBc1bvnhxG5uEsnU+NM5qec3ciBjUIRWqgmeloD9SEmztvh4hUVMXV5
         Cc+QSweuzdNNoXFSNGvJYcp3IzTqfUWizrftEB0CZ8ZW5VeWklbSbm0BcKpYbaGdnxYp
         01XA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Vpe2ZO6g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2b954aeb15bsi980803fac.3.2025.02.20.14.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Feb 2025 14:11:42 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-2fc1f410186so4529679a91.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Feb 2025 14:11:42 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXFW+YnLPpbKtGMjJhVX9F9Q2/bgvSb8KuJebvTll2mfs5u6v293HQzJEWQs1RmdPoRXrsyAIxnYmM=@googlegroups.com
X-Gm-Gg: ASbGncvijG62QnheC2BGrJDqGfyIWk4H5pxG3ajHc0uoWVAuSLLVsvxyl6i/MYaWLHB
	T378vKmE2LV4J4R3zetcRZnDnaRTjMeiT7n1luivr6axJVruF+Kb7PTPhdyDBO6s/As3Dkz6KBH
	W+BDCgV953Lug9yXCu6RP2avSoVRCm
X-Received: by 2002:a17:90b:56cd:b0:2fa:22a2:26a3 with SMTP id
 98e67ed59e1d1-2fce7ae91d9mr1293778a91.6.1740089501933; Thu, 20 Feb 2025
 14:11:41 -0800 (PST)
MIME-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com> <20250206181711.1902989-16-elver@google.com>
 <a1483cb1-13a5-4d6e-87b0-fda5f66b0817@paulmck-laptop>
In-Reply-To: <a1483cb1-13a5-4d6e-87b0-fda5f66b0817@paulmck-laptop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Feb 2025 23:11:04 +0100
X-Gm-Features: AWEUYZlmUbD3zD2pKUzd_1_BxaT4jGAHcCF6wIRviSAHlg-jN4GDUIL9VOeu9Kg
Message-ID: <CANpmjNOPiZ=h69V207AfcvWOB=Q+6QWzBKoKk1qTPVdfKsDQDw@mail.gmail.com>
Subject: Re: [PATCH RFC 15/24] rcu: Support Clang's capability analysis
To: paulmck@kernel.org
Cc: Alexander Potapenko <glider@google.com>, Bart Van Assche <bvanassche@acm.org>, 
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Vpe2ZO6g;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as
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

On Thu, 20 Feb 2025 at 23:00, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Thu, Feb 06, 2025 at 07:10:09PM +0100, Marco Elver wrote:
> > Improve the existing annotations to properly support Clang's capability
> > analysis.
> >
> > The old annotations distinguished between RCU, RCU_BH, and RCU_SCHED.
> > However, it does not make sense to acquire rcu_read_lock_bh() after
> > rcu_read_lock() - annotate the _bh() and _sched() variants to also
> > acquire 'RCU', so that Clang (and also Sparse) can warn about it.
>
> You lost me on this one.  What breaks if rcu_read_lock_bh() is invoked
> while rcu_read_lock() is in effect?

I thought something like this does not make sense:

  rcu_read_lock_bh();
  ..
  rcu_read_lock();
  ..
  rcu_read_unlock();
  ..
  rcu_read_unlock_bh();

However, the inverse may well be something we might find somewhere in
the kernel?
Another problem was that if we want to indicate that "RCU" read lock
is held, then we should just be able to write
"__must_hold_shared(RCU)", and it shouldn't matter if rcu_read_lock()
or rcu_read_lock_bh() was used. Previously each of them acquired their
own capability "RCU" and "RCU_BH" respectively. But rather, we're
dealing with one acquiring a superset of the other, and expressing
that is also what I attempted to solve.
Let me rethink this...

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOPiZ%3Dh69V207AfcvWOB%3DQ%2B6QWzBKoKk1qTPVdfKsDQDw%40mail.gmail.com.
