Return-Path: <kasan-dev+bncBC6LHPWNU4DBBNWLZPZQKGQESWRU3UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 40A8018AB1F
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 04:23:40 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id 8sf911502pgd.12
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Mar 2020 20:23:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584588218; cv=pass;
        d=google.com; s=arc-20160816;
        b=GGjGWaqO1Q20iiUo9aShto/vZ7amNz5XbputqYA00vqtcCqRAtI5SApsekCyCZ8nOU
         HTd9rmd0bKBMU6UJH0MjHtiTq8jwedwC7U5c6g+0f1j6TTPANjOoG/Xlkd7LtC7bIKvh
         KCyKMNw2EyEbQULU6HAfaKOPGzIk1Y8QjLCBf58VIB9t+kKt0Xv7ccW0M2SSsBv9XyBU
         +DEQ/LQtSDyfJ4i9sMvUlH2qY0i96oQrq8hmA5My73z/zgaHbL3r8gwabuBi/1uqQQIX
         /FK4O8LREEZCUMSkdTWkaEsqXnInai9c1CFEXW8H3A38VsrzVIxEjWHw+OWQCvR1po5v
         /SGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=lqo25wRxoAP8632kI9QjS++JCvFStEtnE4qPfsi2qs8=;
        b=LSeUafGmbeJuTXP7mutBfnlDqfCa1VE2hgTsVA8Dj0VOvTgQyojZqgF+mq3/P8o/eP
         VmUHWTpxCe+iC8O+3U3uvljiXCr6FIgSzaAPQvsbwzU+hTKGUglag1kRPzSfnZoohdOn
         nEZL3VFdUXYfHCNVCa+5RqgiOF8o2wjKDzu0Iay2y/MIRPdQkRF7T4elOfl/AiIaoJRr
         ttej9cTUuG/+wmOvDHzOX1uTEdKlxztokPh0GvxqxaXioyfYWjkbYguPjjHwNWfBU4qW
         +Xf0whBxaHBD7M3Sw6IrHIgDupCSF25oehN0K8/zceZ0yJiuRXUZOhUb3mv6lzeRw0fy
         KgJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=SNnqo+bV;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lqo25wRxoAP8632kI9QjS++JCvFStEtnE4qPfsi2qs8=;
        b=RWN3O1gbynnwituI0e8u3swSQScaGQpV6//uWyfsU6N1rb8IWJHsMQEu1Mb8UXkcAs
         YepQ6Xx18Gk9kUp7nTvQcy24BugFiq6w6b4ktJpASp/6RSLNTesXVuVKu7ldfz+kQddT
         7oXmYseSdIu7OwdVqXi5VMw6oUY5nzmMgAZtKPbXlQg0dmfkWZQa9AgDOt9NxGz9YnAF
         0BEdViq4lF9C3Do+vC/CZbDuMpZeVxoCRLUuuf6pSyItobl0nBGL/UQjZVOY7KWO02+t
         KU/cTOVYNMM28aiwO3GvuEXZGUym37MSfIA2pyir4heQmAXby826R61HVdBbiJng71qp
         0wig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lqo25wRxoAP8632kI9QjS++JCvFStEtnE4qPfsi2qs8=;
        b=NjUrqJdCVhu2FqSmryCthMSjiV1LpwheSxlpeSqK5jXtsUq86BHbwxv90aMclJYYiR
         NV2BYW5oLlqR/gRnOnlaa4yM060l0pB1vkusudhfGmom7is2tFMzgtwXGWa2+BxA7esL
         jGGRmxV14JCjEP7yqreK9KLVQEsdxGN7lt76/rwj1GMrem2W1wDe9zC7VfRMp6h0e7Wt
         3XZo9qoU4NSdd+DYDiH/M6vdV3qTNbzOyI3i2AUK6+Si1etsTh/Fx0CtfbkE1bA29mNx
         EHtwDM4tXGT9OkuDaJD2EeU57nxko1py1az4o6aDdNfaStrr/MR1Ot1HzqrLaQPO7xwY
         xQRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lqo25wRxoAP8632kI9QjS++JCvFStEtnE4qPfsi2qs8=;
        b=djTNNeUT9j/3wX4kv0hoolCyGK1LmTFz03aF1Mam5LKw9biU7gBnwREAy+Ob4HyOmK
         Vf7urVSdaJnkkugxJuRZGfykcm7ubmHJc0iOrCtcZk7y0qegGdyWjBb0BAyzz5+cNOV1
         sPvt2YzxVas2XXYzlg3lmuZTogVer7E2ypjIR5nnUfvCTuq5x9ypx2Qi9N3tUGZ1nNaU
         /BvMH7z/QQQS80r2An76kWiO7nyqNOwXrvP/jSEgk9PZHeUAoYNzG0sz+CKoDyJ4uWzr
         4bC+0aUqVlUJ0JfOpcSRAKjlMAgSxPQkkqYE/JCO+2L0wdTlKtbJo88RjW3+cq5Cz28g
         tpww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3wrb7K9zIOGF0WWuvQ4L5N8EQe5Jq1JoiT2cqCfd+ZSY/LmMKZ
	snrfyL9td6DDIjSjuYB/lBA=
X-Google-Smtp-Source: ADFU+vtGX9Wk6ADbspM+x5mibRKQaCXxXTB9sPhB4Z6OaVAnDl/iHB9xSOZ614esUGHutY//VSREKQ==
X-Received: by 2002:a62:5c87:: with SMTP id q129mr1698882pfb.82.1584588214587;
        Wed, 18 Mar 2020 20:23:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb93:: with SMTP id m19ls623624pls.6.gmail; Wed, 18
 Mar 2020 20:23:34 -0700 (PDT)
X-Received: by 2002:a17:90a:de0a:: with SMTP id m10mr1622221pjv.34.1584588213963;
        Wed, 18 Mar 2020 20:23:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584588213; cv=none;
        d=google.com; s=arc-20160816;
        b=bqgK7sLe6VSs5iBIJrUK2FdQhmQOg/a9h6mY3xRXpMWJSlxyF2Qf8VHh+jNAC3hN3O
         Zh99vFObyHRdpnEjyfPX/5mPSEaxNdD7ULM3ieVYw1dZk179Hn4NvONoPmyXghc3vlnk
         390/ba+aqyAwUvC3aCoD6oZCmtXZEqHnoVfWFyPMxFuxljvHGz8o+pKlq2+cttlnIasG
         Lf7M92+g1gnJfCe48m0rK8ccHR98E9hG9c+TgIOmtHi+6Cu+VZ4T3MNfx/uTm81Cq1v0
         jY4HK+u3p/FXJRKicXcF0w3Y6c3RbwPZ7F/YL3CfJ6ZWvQLkd8zSc066EtY5DtXX9BeU
         Dehw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=G3jgg7jUsrwjzV0RJBqO0y67Hy+me0H+xWLnisPRBms=;
        b=E1zRxSJtYSZgdwvnLaqhGGRIkZWTc/b5qWnLwabqscpNn6R4VDyZ3rpOuuRk0kjDAe
         Re4EbuCSyV4PEFB2Jk9TuIjj7++ztDyKJkTEH751fPHkZR0Zc39zhZzqnpbHgNn12dLg
         E+cDnXwIWWMW8fL6kO4+MRvJFcKe2cOhkbvAJ6IrjCdHkXrBNi+L8Cuo6pwYwr+NmUxL
         G0n8/cQL/Ep5OA5bHYisgWqKhDSxx4azuSA5Bqh1XXvl6ALhOTXTe8yJoOxdqlUDbxhY
         vo3+hrFHtP9QsW7RMrJX1iS+SyQR7Rk0fsa7N8i7QJj7jU6yvoahC7AkIt3x8EDJJFcg
         VQTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=SNnqo+bV;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id q2si250495pjv.3.2020.03.18.20.23.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Mar 2020 20:23:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id i9so11210qtw.7
        for <kasan-dev@googlegroups.com>; Wed, 18 Mar 2020 20:23:33 -0700 (PDT)
X-Received: by 2002:ac8:41d4:: with SMTP id o20mr890283qtm.201.1584588212920;
        Wed, 18 Mar 2020 20:23:32 -0700 (PDT)
Received: from auth1-smtp.messagingengine.com (auth1-smtp.messagingengine.com. [66.111.4.227])
        by smtp.gmail.com with ESMTPSA id b7sm692147qkc.61.2020.03.18.20.23.30
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 Mar 2020 20:23:32 -0700 (PDT)
Received: from compute3.internal (compute3.nyi.internal [10.202.2.43])
	by mailauth.nyi.internal (Postfix) with ESMTP id 365BC27C005A;
	Wed, 18 Mar 2020 23:23:29 -0400 (EDT)
Received: from mailfrontend2 ([10.202.2.163])
  by compute3.internal (MEProxy); Wed, 18 Mar 2020 23:23:29 -0400
X-ME-Sender: <xms:sOVyXrAtF7h54i0UWXX4ulLFH8v1NTnJJdwUA6sKGBBmTK-emDNGfQ>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedugedrudefkedgiedtucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepfffhvffukfhfgggtuggjsehttdertddttddvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecukfhppeehvd
    drudehhedrudduuddrjedunecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehm
    rghilhhfrhhomhepsghoqhhunhdomhgvshhmthhprghuthhhphgvrhhsohhnrghlihhthi
    dqieelvdeghedtieegqddujeejkeehheehvddqsghoqhhunhdrfhgvnhhgpeepghhmrghi
    lhdrtghomhesfhhigihmvgdrnhgrmhgv
X-ME-Proxy: <xmx:sOVyXt2A1bQLYTtyUOMtug9KygK_DCGXkmmZzkhlhopWPw2KS3DTxA>
    <xmx:sOVyXpV1aVEObKRE9n6mhAJPdxdc_-btnKvzUYCnuGVhtUjFGG35uA>
    <xmx:sOVyXvmNet0HEsCqLWWjNa1gdMaDq0t3w7QHcVb6g12PQHMVtrJzNA>
    <xmx:seVyXrjxuIKkdAeSPGBGKPilHb3ZUzhXTEtnM5TcpAmRE_JPx5r3MdZF3GM>
Received: from localhost (unknown [52.155.111.71])
	by mail.messagingengine.com (Postfix) with ESMTPA id 184AE3060F09;
	Wed, 18 Mar 2020 23:23:27 -0400 (EDT)
Date: Thu, 19 Mar 2020 11:23:26 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, kernel-team@fb.com,
	Ingo Molnar <mingo@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>
Subject: Re: [PATCH kcsan 17/32] kcsan: Introduce ASSERT_EXCLUSIVE_* macros
Message-ID: <20200319032326.GE105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
 <20200309190420.6100-17-paulmck@kernel.org>
 <20200313085220.GC105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
 <CANpmjNO-hjVfp729YOGdoiuwWjLacW+OCJ=5RnxEYGvQjfQGhA@mail.gmail.com>
 <20200314022210.GD105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
 <CANpmjNPu67nnaWbOtA8xntBWafDm5Ykspzj43wuSdRckLGC=UA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPu67nnaWbOtA8xntBWafDm5Ykspzj43wuSdRckLGC=UA@mail.gmail.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=SNnqo+bV;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::842
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

On Tue, Mar 17, 2020 at 12:12:36PM +0100, Marco Elver wrote:
> On Sat, 14 Mar 2020 at 03:22, Boqun Feng <boqun.feng@gmail.com> wrote:
> >
> > On Fri, Mar 13, 2020 at 05:15:32PM +0100, Marco Elver wrote:
> > > On Fri, 13 Mar 2020 at 09:52, Boqun Feng <boqun.feng@gmail.com> wrote:
> > > >
> > > > Hi Marco,
> > > >
> > > > On Mon, Mar 09, 2020 at 12:04:05PM -0700, paulmck@kernel.org wrote:
> > > > > From: Marco Elver <elver@google.com>
> > > > >
> > > > > Introduces ASSERT_EXCLUSIVE_WRITER and ASSERT_EXCLUSIVE_ACCESS, which
> > > > > may be used to assert properties of synchronization logic, where
> > > > > violation cannot be detected as a normal data race.
> > > > >
> > > > > Examples of the reports that may be generated:
> > > > >
> > > > >     ==================================================================
> > > > >     BUG: KCSAN: assert: race in test_thread / test_thread
> > > > >
> > > > >     write to 0xffffffffab3d1540 of 8 bytes by task 466 on cpu 2:
> > > > >      test_thread+0x8d/0x111
> > > > >      debugfs_write.cold+0x32/0x44
> > > > >      ...
> > > > >
> > > > >     assert no writes to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> > > > >      test_thread+0xa3/0x111
> > > > >      debugfs_write.cold+0x32/0x44
> > > > >      ...
> > > > >     ==================================================================
> > > > >
> > > > >     ==================================================================
> > > > >     BUG: KCSAN: assert: race in test_thread / test_thread
> > > > >
> > > > >     assert no accesses to 0xffffffffab3d1540 of 8 bytes by task 465 on cpu 1:
> > > > >      test_thread+0xb9/0x111
> > > > >      debugfs_write.cold+0x32/0x44
> > > > >      ...
> > > > >
> > > > >     read to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> > > > >      test_thread+0x77/0x111
> > > > >      debugfs_write.cold+0x32/0x44
> > > > >      ...
> > > > >     ==================================================================
> > > > >
> > > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > > Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> > > > > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > > > > ---
> > > > >  include/linux/kcsan-checks.h | 40 ++++++++++++++++++++++++++++++++++++++++
> > > > >  1 file changed, 40 insertions(+)
> > > > >
> > > > > diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> > > > > index 5dcadc2..cf69617 100644
> > > > > --- a/include/linux/kcsan-checks.h
> > > > > +++ b/include/linux/kcsan-checks.h
> > > > > @@ -96,4 +96,44 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> > > > >       kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE)
> > > > >  #endif
> > > > >
> > > > > +/**
> > > > > + * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
> > > > > + *
> > > > > + * Assert that there are no other threads writing @var; other readers are
> > > > > + * allowed. This assertion can be used to specify properties of concurrent code,
> > > > > + * where violation cannot be detected as a normal data race.
> > > > > + *
> > > >
> > > > I like the idea that we can assert no other writers, however I think
> > > > assertions like ASSERT_EXCLUSIVE_WRITER() are a little limited. For
> > > > example, if we have the following code:
> > > >
> > > >         preempt_disable();
> > > >         do_sth();
> > > >         raw_cpu_write(var, 1);
> > > >         do_sth_else();
> > > >         preempt_enable();
> > > >
> > > > we can add the assert to detect another potential writer like:
> > > >
> > > >         preempt_disable();
> > > >         do_sth();
> > > >         ASSERT_EXCLUSIVE_WRITER(var);
> > > >         raw_cpu_write(var, 1);
> > > >         do_sth_else();
> > > >         preempt_enable();
> > > >
> > > > , but, if I understand how KCSAN works correctly, it only works if the
> > > > another writer happens when the ASSERT_EXCLUSIVE_WRITER(var) is called,
> > > > IOW, it can only detect another writer between do_sth() and
> > > > raw_cpu_write(). But our intent is to prevent other writers for the
> > > > whole preemption-off section. With this assertion introduced, people may
> > > > end up with code like:
> > >
> > > To confirm: KCSAN will detect a race if it sets up a watchpoint on
> > > ASSERT_EXCLUSIVE_WRITER(var), and a concurrent write happens. Note
> > > that the watchpoints aren't always set up, but only periodically
> > > (discussed more below). For every watchpoint, we also inject an
> > > artificial delay. Pseudo-code:
> > >
> > > if watchpoint for access already set up {
> > >   consume watchpoint;
> > > else if should set up watchpoint {
> > >   setup watchpoint;
> > >   udelay(...);
> > >   check watchpoint consumed;
> > >   release watchpoint;
> > > }
> > >
> >
> > Yes, I get this part.
> >
> > > >         preempt_disable();
> > > >         ASSERT_EXCLUSIVE_WRITER(var);
> > > >         do_sth();
> > > >         ASSERT_EXCLUSIVE_WRITER(var);
> > > >         raw_cpu_write(var, 1);
> > > >         ASSERT_EXCLUSIVE_WRITER(var);
> > > >         do_sth_else();
> > > >         ASSERT_EXCLUSIVE_WRITER(var);
> > > >         preempt_enable();
> > > >
> > > > and that is horrible...
> > >
> > > It is, and I would strongly discourage any such use, because it's not
> > > necessary. See below.
> > >
> > > > So how about making a pair of annotations
> > > > ASSERT_EXCLUSIVE_WRITER_BEGIN() and ASSERT_EXCLUSIVE_WRITER_END(), so
> > > > that we can write code like:
> > > >
> > > >         preempt_disable();
> > > >         ASSERT_EXCLUSIVE_WRITER_BEGIN(var);
> > > >         do_sth();
> > > >         raw_cpu_write(var, 1);
> > > >         do_sth_else();
> > > >         ASSERT_EXCLUSIVE_WRITER_END(var);
> > > >         preempt_enable();
> > > >
> > > > ASSERT_EXCLUSIVE_WRITER_BEGIN() could be a rough version of watchpoint
> > > > setting up and ASSERT_EXCLUSIVE_WRITER_END() could be watchpoint
> > > > removing. So I think it's feasible.
> > >
> > > Keep in mind that the time from ASSERT_EXCLUSIVE_WRITER_BEGIN to END
> > > might be on the order of a few nanosec, whereas KCSAN's default
> > > watchpoint delay is 10s of microsec (default ~80 for tasks). That
> > > means we would still have to set up a delay somewhere, and the few
> > > nanosec between BEGIN and END are insignificant and don't buy us
> > > anything.
> > >
> >
> > Yeah, the delay doesn't buy us anything given the default watchpoint
> > delay, and I agree even with *_{BEGIN/END}, we still need to set up a
> > delay somewhere. Adding a delay makes the watchpoint live longer so that
> > a problem will more likely happen, but sometimes the delay won't be
> > enough, considering another writer like:
> >
> >         if (per_cpu(var, cpu) == 1)
> >                 per_cpu(var, cpu) = 0;
> >
> > in this user case, percpu variable "var" is used for maintaining some
> > state machine, and a CPU set a state with its own variable so that other
> > CPUs can consume it. And this another writer cannot be catched by:
> >
> >         preempt_disable();
> >         do_sth();
> >         ASSERT_EXCLUSIVE_WRITER(var);
> >         raw_cpu_write(var, 1);
> >         do_sth_else();
> >         preempt_enable();
> >
> 
> Right, the example makes sense.
> 
> That is assuming there are various other expected racy reads that are
> fine. If that's not true, ASSERT_EXCLUSIVE_ACCESS should be
> considered.
> 
> > , no matter how long the delay is set. Another example: let's say the
> > do_sth_else() above is actually an operation that queues a callback
> > which writes to "var". In one version, do_sth_else() uses call_rcu(),
> > which works, because preemption-off is treated as RCU read-side critical
> > section, so we are fine. But if someone else changes it to queue_work()
> > for some reason, the code is just broken, and KCSAN cannot detect it, no
> > matter how long the delay is.
> >
> > To summarize, a delay is helpful to trigger a problem because it allows
> > _other_ CPU/threads to run more code and do more memory accesses,
> > however it's not helpful if a particular problem happens due to some
> > memory effects of the current/watched CPU/thread. While *_{BEGIN/END}
> > can be helpful in this case.
> 
> Makes sense.
> 
> > > Re feasibility: Right now setting up and removing watchpoints is not
> > > exposed, and doing something like this would be an extremely intrusive
> > > change. Because of that, without being able to quantify the actual
> > > usefulness of this, and having evaluated better options (see below),
> > > I'd recommend not pursuing this.
> > >
> > > > Thoughts?
> > >
> > > Firstly, what is your objective? From what I gather you want to
> > > increase the probability of detecting a race with 'var'.
> > >
> >
> > Right, I want to increase the probablity.
> >
> > > I agree, and have been thinking about it, but there are other options
> > > that haven't been exhausted, before we go and make the interface more
> > > complicated.
> > >
> > > == Interface design ==
> > > The interface as it is right now, is intuitive and using it is hard to
> > > get wrong. Demanding begin/end markers introduces complexity that will
> >
> > Yeah, the interface is intuitive, however it's still an extra effort to
> > put those assertions, right? Which means it doesn't come for free,
> > compared to other detection KCSAN can do, the developers don't need to
> > put extra lines of code. Given the extra effort for developers to use
> > the detect, I think we should dicuss the design thoroughly.
> >
> > Besides the semantics of assertions is usually "do some checking right
> > now to see if things go wrong", and I don't think it quite matches the
> > semantics of an exclusive writer: "in this piece of code, I'm the only
> > one who can do the write".
> >
> > > undoubtedly result in incorrect usage, because as soon as you somehow
> > > forget to end the region, you'll get tons of false positives. This may
> > > be due to control-flow that was missed etc. We had a similar problem
> > > with seqlocks, and getting them to work correctly with KCSAN was
> > > extremely difficult, because clear begin and end markers weren't
> > > always given. I imagine introducing an interface like this will
> > > ultimately result in similar problems, as much as we'd like to believe
> > > this won't ever happen.
> > >
> >
> > Well, if we use *_{BEGIN,END} approach, one solution is combining them
> > with sections introducing primitives (such as preemp_disable() and
> > preempt_enable()), for example, we can add
> >
> >         #define preempt_disable_for(var)                                \
> >         do {                                                            \
> >                 preempt_disable();                                      \
> >                 ASSERT_EXCLUSIVE_WRITER_BEGIN(var);                     \
> >         }
> >
> >         #define preempt_enable_for(var)                                 \
> >         do {                                                            \
> >                 ASSERT_EXCLUSIVE_WRITER_END(var);                       \
> >                 preempt_enable();                                       \
> >         }
> >
> >         (similar for spin lock)
> >
> >         #define spin_lock_for(lock, var)                                \
> >         do {                                                            \
> >                 spin_lock(lock);                                        \
> >                 ASSERT_EXCLUSIVE_WRITER_BEGIN(var);                     \
> >         }
> >
> >         #define spin_unlock_for(lock, var)                              \
> >         do {                                                            \
> >                 ASSERT_EXCLUSIVE_WRITER_END(var);                       \
> >                 spin_unlock(lock);                                      \
> >         }
> >
> > I admit that I haven't thought this thoroughly, but I think this works,
> > and besides primitives like above can help the reader to understand the
> > questions like: what this lock/preemption-off critical sections are
> > protecting?
> 
> I can't say anything about introducing even more macros. I'd say we
> need at least a dozen use-cases or more and understand them, otherwise
> we may end up with the wrong API that we can never take back.
> 

Agreed, real use-cases are needed for the justification of introducing
those APIs.

> > Thoughts?
> 
> Makes sense for the cases you described.
> 
> Changing KCSAN to do this is a major change. On surface, it seems like
> a refactor and exporting some existing functionality, but there are
> various new corner cases, because now 2 accesses don't really have to
> be concurrent anymore to detect a race (and simple properties like a
> thread can't race with itself need to be taken care of). The existing
> ASSERT_EXCLUSIVE macros were able to leverage existing functionality
> mostly as-is. So, to motivate something like this, we need at least a
> dozen or so good use-cases, where careful placement of an existing
> ASSERT_EXCLUSIVE would not catch what you describe.
> 

Right, I think at this point, I'm not object to merging this into
kernel, using ASSERT_EXCLUSIVE_*() does provide more chances for us to
catch bugs. That said, I think it's better if we have some comments
describing the semantics (or the limitation) of the annotations to avoid
"mis-use"s (for example, using multiple ASSERT_EXCLUSIVE_WRITER()s for
one variables in a function). But that doesn't necessarily block the
merge of this feature, we can always do that later.

Also, I think it's worthwhile to do some experiments on the
*_{BEGIN,END} interfaces. If you're interested and have cycles to work
on this, please let me, othwerwise, I can have a look at it.

Thanks!

Regards,
Boqun


> Thanks,
> -- Marco
> 
> > Regards,
> > Boqun
> >
[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200319032326.GE105953%40debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net.
