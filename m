Return-Path: <kasan-dev+bncBC6LHPWNU4DBBSUTVXZQKGQEDNJD7WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AE0C1842EE
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Mar 2020 09:52:27 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id a66sf5267242otb.6
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Mar 2020 01:52:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584089546; cv=pass;
        d=google.com; s=arc-20160816;
        b=jI2vsDC/TtpfRNq8/1+UBM3IEvzcXZ/N60O67KigQWHyY/21vVB4nvvvtbM14yGh9k
         Gu6EVP59/2wZG7wzIi9mftgW+vw7ODVbaNVHBeEd4vKz74JNO17eDTGEqDIeafj1gmk8
         6ovkC8gDr/NZ7yYWJ4lb3ot2wyc18i7fw+YAOLpTVz6wJOnMMcPSwSBVCp5hOPOrz9kG
         Jh2UcWk0t6cX8aSBKxiVRbS0Ke3+UsXzAoQv2+Y/qf3yTqUOLrCD+q2RGJVjRF2WoyMU
         Gsv/ImHbFdI/PlYGGcJCO5++IVuBnthHnVyyZv7b7OSiago1DOQ5vtdtVNJiKvtckPAm
         S91w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=x6AsEi+iR3H/bzXK4/07X1+14/ZP9HclOGIDBNDY+AA=;
        b=ne/MISQ3zVgt/txmPOdhOaPHHQyvkTm2T3Jfkr3ywm+hBTftpTCOlqTeGyAznqAzQl
         B6ZOImZLxnZZsA1sFM1fRKre6QXFaPm8HaFNOLoQ2HkwCiroBWgH5JEq3uGDkg9zOYeh
         O5jysqm75IIh46NranAN2mgNlZx4i0edSwKurL5NSVKNmYR2X+SqhN1XO508Wmpe4SO0
         ETxLnrj3cNOKXeh5OzJqCyBR8gr+f94j7VlyJWQdwTbcawGBS5+jknqlVLEnZxwtS4zA
         WyDLbV/5LTC6L4Hack9xR681JTDc/BjXPmvC7hA4/2aEX05ANVn+q5T7UAAPMMYwg6OC
         10MA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=HG2uCC6q;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x6AsEi+iR3H/bzXK4/07X1+14/ZP9HclOGIDBNDY+AA=;
        b=pgH7WruW2qckmhfQl+HNmR7UMrmlRK1+Df3S65VnlN20pI7SQA8wL2VqmsHRQ+8DKn
         d8jAdPItOHrZkKiiIxz6roV1B55m6ImHlYuFMIbmJ4vUFGoJ8XPvgENUmk6Uok9LWyt+
         Nj7bLB6ZptYx7rJY7DnsUGRVR0uSPdEDCufZrZup4g9j/cMsiCEcwpjR6BLB5t/stF9E
         RsBW8Sp1s+jAR+34j1ykdICbkgmOYWYNUUH1wUtUxcqeMIDTNEwqBO9B1P8ZP1IF4Jq4
         6FA0FH7XXAJFDQVK1wps35kk5ugXRu0U5D9gh4hq23H8I9b9MmePsD5J/wjaKUTuXiQG
         9GpA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x6AsEi+iR3H/bzXK4/07X1+14/ZP9HclOGIDBNDY+AA=;
        b=f5qrP0JsOwO9POs4pO2eCyu4y+b/YheMXQTx0O9iCp+sBaVxMzOqCHR48XnmUwDu5b
         nb/eRZu0KOlLSqh3xbZJjiqx9wb6IeotZj4FILAAKNLapX4pY1yYvbf2uQMBRqlr4XZw
         tXTRLQNB+vsIfo/vi6XufRQy9tX2mTW3y/IECmkv55un9qgSQnj/K7CBAGJors8HpbIM
         4ywkC/zE/J8y5zJpgyVJXiDP8pgep+ozzXf+EvXU+6WlxhxU69K3Axy/36JWP2sf56+j
         yokUJVHZ552MLhht6EG+XI7WfWGwTXHpjErKETe8knbRKBSZ++yI4VTRbqqGrOmufgTC
         1r7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=x6AsEi+iR3H/bzXK4/07X1+14/ZP9HclOGIDBNDY+AA=;
        b=fI8t0DJkZh6WnX+yN8Vt3rDQejNsP2GPpu/vgStr6Sc9B93Lbj51kpvey0TLKFXmJB
         J/thP/ICJlS9uNvudO+YDu2MhT6JDqAgWYLjbVJzdxJ7uCl22USXCaJGCwQMKiqgU9ta
         4cNCn4IWZavvVZNZvAbBgpbnbYifJZEOjNmJ7K92ML/w1tM7rhTNM/cnpr1u2vaJX7LG
         k/JUAhbhYisPBmwTom9EHGSESL1oX0chjoAcpJ2nLkbO/IBGHHMqGCIzgM3H/Aj96hKJ
         4New33u9b5AEaxvXzWlEN2XpY4Zl16YuomkyxpZl9Btbc1ECgtUxZIvApmHaLYPE9A2i
         wfVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0XOLKOlZksL2D8v1f2MYhialYlZXbYkSSHvXIkGxxWVaR2lA9o
	pV3UK2tyAATfkFxeyf6JylE=
X-Google-Smtp-Source: ADFU+vvpYGXPmuoz3oNnPkXlfwDDrYSVmrQDe5uND/ntXMBOCdIrqZvWQlDg1v4oElaaTCPSlUDu/A==
X-Received: by 2002:a9d:64ca:: with SMTP id n10mr10092477otl.325.1584089546168;
        Fri, 13 Mar 2020 01:52:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:410e:: with SMTP id l14ls2360103oic.2.gmail; Fri, 13 Mar
 2020 01:52:25 -0700 (PDT)
X-Received: by 2002:a54:4816:: with SMTP id j22mr6175340oij.162.1584089545803;
        Fri, 13 Mar 2020 01:52:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584089545; cv=none;
        d=google.com; s=arc-20160816;
        b=e4ahXbOddgvTJzL801J7iJf75nVsO6b0ZJaH1mGZDdlqBZUoSEPhdZgQgAi1zqqU4g
         I6XqOKTkOh4ObdJNlNJVostcC4qQgYr/dvsZDH7CSrptTENCwUBtzD8QMT4ugfzFDIVx
         +YX7DABx1H2BtADwY00PAwQKJ7AmVj092+pLfSN9gWvl7gWrCoeHPQaKJL1tU98rTBoh
         WKPWAkNaQ/VHnBgByQ/m5OPWcfO4sdQdQGSsTAaFXhZwl61lbECZBeYv3b1O2jLsLPfL
         JX5Vzu6ZMheUH+gr51vThfikb9simzYZ1HwjTxxnNBOg+RJWmyo1WS14hu+TvuRQlU/b
         iC6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=eQXzm8BQRHCgGScNDJ9ph6XbAyK4pO8RWnMrgDPmD5A=;
        b=O+XqTbo9V/tjg2tg//v2743lbkLp1prw0ucyJqinN/nbu6vOFBbiCZGlENzYOEkBIX
         N0beoflfT8pJSyAk4117fqeunawXoEVbWdxFNRsOAR5ptg8pCxQ142JOW/vQIKf2qLev
         ELXsPukp/dFZeNa4CyDlvnEIZ+/RQS6pfXK64cG+pIhpX7ACPzjjprkPXFRR61OGoY/m
         +OS9re4q7+iay1owEZlt/f7v8WoZ1fTvqJTQVnyAsCt40ZDo/vF1kiRO/vq1IowFdDWA
         siy/7XxOE6CKiWjj2NPDnZiC9hOLaYoEXHBHGdGq1QCMuho9hOeeDwxqtwgwoxLiPg12
         UMEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=HG2uCC6q;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id b2si491056oib.5.2020.03.13.01.52.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Mar 2020 01:52:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id l21so6824149qtr.8
        for <kasan-dev@googlegroups.com>; Fri, 13 Mar 2020 01:52:25 -0700 (PDT)
X-Received: by 2002:ac8:304d:: with SMTP id g13mr11652419qte.221.1584089545219;
        Fri, 13 Mar 2020 01:52:25 -0700 (PDT)
Received: from auth2-smtp.messagingengine.com (auth2-smtp.messagingengine.com. [66.111.4.228])
        by smtp.gmail.com with ESMTPSA id b7sm10775613qkh.0.2020.03.13.01.52.24
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 13 Mar 2020 01:52:24 -0700 (PDT)
Received: from compute3.internal (compute3.nyi.internal [10.202.2.43])
	by mailauth.nyi.internal (Postfix) with ESMTP id 09F0022632;
	Fri, 13 Mar 2020 04:52:23 -0400 (EDT)
Received: from mailfrontend1 ([10.202.2.162])
  by compute3.internal (MEProxy); Fri, 13 Mar 2020 04:52:23 -0400
X-ME-Sender: <xms:xklrXmeeXhkaBInRAeJvwdPTGBDNdDWfZINjdPTj5PKPDcymRaZ5kg>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedugedruddviedguddvfecutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfgh
    necuuegrihhlohhuthemuceftddtnecunecujfgurhepfffhvffukfhfgggtuggjsehttd
    ertddttddvnecuhfhrohhmpeeuohhquhhnucfhvghnghcuoegsohhquhhnrdhfvghnghes
    ghhmrghilhdrtghomheqnecukfhppeehvddrudehhedrudduuddrjedunecuvehluhhsth
    gvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdomhgvshhm
    thhprghuthhhphgvrhhsohhnrghlihhthidqieelvdeghedtieegqddujeejkeehheehvd
    dqsghoqhhunhdrfhgvnhhgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgrmhgv
X-ME-Proxy: <xmx:xklrXqQGeMF3aqEkUEXpG_8VHo8lnHb1-r_HOJyA2c_k9VNxytPOHg>
    <xmx:xklrXsd37JqcPY49_gSXbFL4G358qsg-jQPzbVNh88U597jVvsWVAA>
    <xmx:xklrXrusreGxT7218G8J_MNPJSf0Bsid3gwZtfogJLk67p4dxTpUUA>
    <xmx:x0lrXpV_DngwScMOea9lTi_5Rhpfj41_b_LG4BtVPzvxKe-tQovZbI3Agl4>
Received: from localhost (unknown [52.155.111.71])
	by mail.messagingengine.com (Postfix) with ESMTPA id 52B1F328005A;
	Fri, 13 Mar 2020 04:52:22 -0400 (EDT)
Date: Fri, 13 Mar 2020 16:52:20 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: paulmck@kernel.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org, elver@google.com,
	andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	cai@lca.pw
Subject: Re: [PATCH kcsan 17/32] kcsan: Introduce ASSERT_EXCLUSIVE_* macros
Message-ID: <20200313085220.GC105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
 <20200309190420.6100-17-paulmck@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200309190420.6100-17-paulmck@kernel.org>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=HG2uCC6q;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::843
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

Hi Marco,

On Mon, Mar 09, 2020 at 12:04:05PM -0700, paulmck@kernel.org wrote:
> From: Marco Elver <elver@google.com>
> 
> Introduces ASSERT_EXCLUSIVE_WRITER and ASSERT_EXCLUSIVE_ACCESS, which
> may be used to assert properties of synchronization logic, where
> violation cannot be detected as a normal data race.
> 
> Examples of the reports that may be generated:
> 
>     ==================================================================
>     BUG: KCSAN: assert: race in test_thread / test_thread
> 
>     write to 0xffffffffab3d1540 of 8 bytes by task 466 on cpu 2:
>      test_thread+0x8d/0x111
>      debugfs_write.cold+0x32/0x44
>      ...
> 
>     assert no writes to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
>      test_thread+0xa3/0x111
>      debugfs_write.cold+0x32/0x44
>      ...
>     ==================================================================
> 
>     ==================================================================
>     BUG: KCSAN: assert: race in test_thread / test_thread
> 
>     assert no accesses to 0xffffffffab3d1540 of 8 bytes by task 465 on cpu 1:
>      test_thread+0xb9/0x111
>      debugfs_write.cold+0x32/0x44
>      ...
> 
>     read to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
>      test_thread+0x77/0x111
>      debugfs_write.cold+0x32/0x44
>      ...
>     ==================================================================
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> ---
>  include/linux/kcsan-checks.h | 40 ++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 40 insertions(+)
> 
> diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> index 5dcadc2..cf69617 100644
> --- a/include/linux/kcsan-checks.h
> +++ b/include/linux/kcsan-checks.h
> @@ -96,4 +96,44 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
>  	kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE)
>  #endif
>  
> +/**
> + * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
> + *
> + * Assert that there are no other threads writing @var; other readers are
> + * allowed. This assertion can be used to specify properties of concurrent code,
> + * where violation cannot be detected as a normal data race.
> + *

I like the idea that we can assert no other writers, however I think
assertions like ASSERT_EXCLUSIVE_WRITER() are a little limited. For
example, if we have the following code:

	preempt_disable();
	do_sth();
	raw_cpu_write(var, 1);
	do_sth_else();
	preempt_enable();

we can add the assert to detect another potential writer like:

	preempt_disable();
	do_sth();
	ASSERT_EXCLUSIVE_WRITER(var);
	raw_cpu_write(var, 1);
	do_sth_else();
	preempt_enable();

, but, if I understand how KCSAN works correctly, it only works if the
another writer happens when the ASSERT_EXCLUSIVE_WRITER(var) is called,
IOW, it can only detect another writer between do_sth() and
raw_cpu_write(). But our intent is to prevent other writers for the
whole preemption-off section. With this assertion introduced, people may
end up with code like:

	preempt_disable();
	ASSERT_EXCLUSIVE_WRITER(var);
	do_sth();
	ASSERT_EXCLUSIVE_WRITER(var);
	raw_cpu_write(var, 1);
	ASSERT_EXCLUSIVE_WRITER(var);
	do_sth_else();
	ASSERT_EXCLUSIVE_WRITER(var);
	preempt_enable();

and that is horrible...

So how about making a pair of annotations
ASSERT_EXCLUSIVE_WRITER_BEGIN() and ASSERT_EXCLUSIVE_WRITER_END(), so
that we can write code like:

	preempt_disable();
	ASSERT_EXCLUSIVE_WRITER_BEGIN(var);
	do_sth();
	raw_cpu_write(var, 1);
	do_sth_else();
	ASSERT_EXCLUSIVE_WRITER_END(var);
	preempt_enable();

ASSERT_EXCLUSIVE_WRITER_BEGIN() could be a rough version of watchpoint
setting up and ASSERT_EXCLUSIVE_WRITER_END() could be watchpoint
removing. So I think it's feasible.

Thoughts?

Regards,
Boqun

> + * For example, if a per-CPU variable is only meant to be written by a single
> + * CPU, but may be read from other CPUs; in this case, reads and writes must be
> + * marked properly, however, if an off-CPU WRITE_ONCE() races with the owning
> + * CPU's WRITE_ONCE(), would not constitute a data race but could be a harmful
> + * race condition. Using this macro allows specifying this property in the code
> + * and catch such bugs.
> + *
> + * @var variable to assert on
> + */
> +#define ASSERT_EXCLUSIVE_WRITER(var)                                           \
> +	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
> +
> +/**
> + * ASSERT_EXCLUSIVE_ACCESS - assert no other threads are accessing @var
> + *
> + * Assert that no other thread is accessing @var (no readers nor writers). This
> + * assertion can be used to specify properties of concurrent code, where
> + * violation cannot be detected as a normal data race.
> + *
> + * For example, in a reference-counting algorithm where exclusive access is
> + * expected after the refcount reaches 0. We can check that this property
> + * actually holds as follows:
> + *
> + *	if (refcount_dec_and_test(&obj->refcnt)) {
> + *		ASSERT_EXCLUSIVE_ACCESS(*obj);
> + *		safely_dispose_of(obj);
> + *	}
> + *
> + * @var variable to assert on
> + */
> +#define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
> +	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
> +
>  #endif /* _LINUX_KCSAN_CHECKS_H */
> -- 
> 2.9.5
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200313085220.GC105953%40debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net.
