Return-Path: <kasan-dev+bncBCS4VDMYRUNBBUFBT24QMGQEWDFJNZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id CD8A69BA63A
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Nov 2024 16:03:46 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-2112b3f4338sf22077195ad.1
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Nov 2024 07:03:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730646225; cv=pass;
        d=google.com; s=arc-20240605;
        b=ajC6ibumCy81JXpWTf/IVzqvpJdLT3JEm3H65KPQKl3Y7S34LclW7SnEMgE5R13y/d
         xsqysyn/XNC/VUlLzeZChk23ioznoSvNis4zLql1CCo8HEptrBP/0E/Kgs33Yu/mWkv9
         b7VTNFTbHO+zuZmofVdaNAF60NLG8A+O0JYR+mehAk9yMQyF6P3ZSr5Z3/7dTf7JwZ1q
         rUccbPlBpil760RSYDp7URTRofsqfMz7LZ2IrRs3d8olpQMCQcvbg18bJDgBRUvaQ9zb
         pcU+vSHC/y5gxhihUbTPeLfZJi8RIEIKcddeVEXr3qwcH6AJ9DCpPUDT3lm2xkB7Z+xk
         POCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=e4K5D0a1qWGOQBWpMUvS2quBSyCu1V0KAdhHz/kQPUw=;
        fh=AmuIkZNSJZHHfbyrdk/ZQ+5GPXWNZjT4qqIZUz1xB88=;
        b=ND+hrLKwtWcZLwOw8x6kRexTarZOQAIi9c+l5NAcEdQJh0LJksMa5GVGKXiXggP6RZ
         M+NxKjomMOtZwG0hEMbtziyvnuTp53j5GhpAwyTgvR1V9A9hbraAs/UirDaeLGGvpOew
         xZVstAuNhIcfsDxVDiKoBeiH1JIh1b1dHcHRQzKqM0eaAjiKflYOD3CahWLHzTF5hYBE
         iM14H7JGPyxeNqzcIMnaIcTyccjqsoy+J/4PfVJWdvtAziDEsuHjJX37qBjnrp8G80eQ
         pH2zuMxnNIzUPm0Ksnz7KI4j16IU1EI3MM/caWWpmF0zlwljOCSJrOx/a3lgoA4AvD61
         e4zg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Qy8gOKmM;
       spf=pass (google.com: domain of srs0=b2af=r6=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=b2af=R6=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730646225; x=1731251025; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=e4K5D0a1qWGOQBWpMUvS2quBSyCu1V0KAdhHz/kQPUw=;
        b=hfFsUyoaDWkHU916uM7cmj6YUj4Z76wGz2TiowUWVNSqdfRXIpzQF33QjkxHQdf74E
         7jTOc8S7Caw3kAl8t6PFCeD2u3O+1yEVyKstxwbdFGO23bCWZVqSkmqco5JqSWNXu6Qo
         ia0XGxqKFpFTxS8b/Cc6kVxa4ZTfE6kMDyphyS240FpEDnbzrT7HP0qSaLPy/8zvZNer
         j1H6LyTsDqc+9uzvtD3RCTgzmQHq8oupzLOv1PohW9g3f4O4RDZE1ey/b6Q0+kv9phKd
         mGeQWDj74Z7j20l6mKs9/cu7nYY5GGglbzSDUrnvTTSJsAMzOHRxWkooSBWmu3PSKeEo
         NCZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730646225; x=1731251025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=e4K5D0a1qWGOQBWpMUvS2quBSyCu1V0KAdhHz/kQPUw=;
        b=huyss0CtI4SDAt5X2jlC0I5NiDu9BMa8glFpv5o+Eqecbf/NP33kwTZPLDa8WI8Jg+
         FWBo+efxm0zb2kboqZ6+7BJGVXPq42AwQNWxXpIlWJBsyYsipSmNF/JvEbVVgL9U1LBf
         de88gaJ4eE6b6ZKu3vDaInRLdGGdBR65xWkjhpgY9GqjZ80nSFgmv12Mm/8MMNeWyAyo
         MPJE4GiblSPzg3AVtJiiwSDwo+wCEOUrVHvNXKtEUi1J5Egy3KUB+UDqyWJnJV1vWxZN
         09DtaBR+DE9OlX+M5Iue4aVjczFniLiaaR6660JQiNsXntIU6RyAZ+ZQSRPS7bkVN1di
         b1ag==
X-Forwarded-Encrypted: i=2; AJvYcCUnlFUhFjxup+HQoX3omc4PN9KsPPdhLx+CqCjC6gtJhz8X22kjFvViFmRF2CMYkmeJtFm7OQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx+ibklwGyZgwrVVOFuqFtKLMG+FE7BiWox03jX+HMB5XH+myB7
	DvEUemwzwO3TEmPMywGj3lwNK89B3/1HT8JQCg3pQT9/zpR3xm2m
X-Google-Smtp-Source: AGHT+IHu+VndyM7NiQGnQr8poRUc4NyAvy9ptdSQVa+LwbVWxF2n+uM6Dyg3M9HwZ/If1C6F0K+U2g==
X-Received: by 2002:a17:90b:1c8d:b0:2e2:bd32:f60 with SMTP id 98e67ed59e1d1-2e94c5175e1mr13909014a91.32.1730646224374;
        Sun, 03 Nov 2024 07:03:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1c08:b0:2e2:c421:c3e with SMTP id
 98e67ed59e1d1-2e93b13bae5ls869458a91.2.-pod-prod-05-us; Sun, 03 Nov 2024
 07:03:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVjhG66WrMO22BRnNhbuXSdlruIsJ6vmbkrYpW3sC4+te28quMNj8vRMmLKOD5lhwjH4DDZmN2qNW8=@googlegroups.com
X-Received: by 2002:a17:90b:1d0d:b0:2e2:b513:d534 with SMTP id 98e67ed59e1d1-2e94c533121mr14707217a91.37.1730646222801;
        Sun, 03 Nov 2024 07:03:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730646222; cv=none;
        d=google.com; s=arc-20240605;
        b=FJraDxD/slW770pC3+N8aZGmKPFdroIZbxVDNNzmOPyQ4CBdgxCMedyMTfCziqyZkg
         b/UG92FYpzNJ9S++5SkIVf3grYBlK0I7DQpbgqhPoKJGX3MDE1wpqT7rA2TCRzLfqwzV
         a7js9NlQv1MtaHzEORT/okTydYJ8A6Emmx/w0dn2cr8JMD7j0DvZD0w3EMxXCccGyh8f
         JS3OjUvWkoaPBQGq7LYSumlqQGrMG7kuKCh61ncGuEHlqTEyPaWNS9HgS402eZBhtjg0
         fH8da9rV6iRIPstQNNFON0vFHhEc8X8DUTLPd2RYw4fPQWzYE1UrC1YWnxOwaFkdwIFV
         npWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=IadLORJd8TUnpt493OKxzjK06ithZB89GPZehVhaZiY=;
        fh=sgMI7tmNu/xPld+3m5xVJvRQdKiIcc7Lsrt9++K6A78=;
        b=RWyLQk1PKa1G5gqPZ4oAKuxJ6Kri2Ov8XxUR1m4BYrZPJEGwhMoYLGDr9BG0N5jdSl
         oPJvYBhYUhHScy/uagC4FtbfI1KTaRbKNOtpiDivDbIN6vnk5VN34N6YV+81qB0vlpdz
         9j4JQtPwVHWoU/I66VWXQUXeHFbowybSAb74r5qV/wazm0ep6WLZ5Z/tisqE/Jah69pS
         ero/6mHn4wkHJfxm4RvZrWviggaglycnQphp9gJmRcqrbi0fDegHSRDWuyyEDwIp+jDn
         a4RPKsjvttB+qa4qBU8tWRccEsdqkWP1chJgukvEXs+rpw+iflznKypv4QJuwTNclAch
         EJSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Qy8gOKmM;
       spf=pass (google.com: domain of srs0=b2af=r6=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=b2af=R6=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e93d93ab44si310349a91.0.2024.11.03.07.03.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 03 Nov 2024 07:03:42 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=b2af=r6=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4F9705C4A0F;
	Sun,  3 Nov 2024 15:02:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BB12EC4CECD;
	Sun,  3 Nov 2024 15:03:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 6454ECE0F53; Sun,  3 Nov 2024 07:03:41 -0800 (PST)
Date: Sun, 3 Nov 2024 07:03:41 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Marco Elver <elver@google.com>,
	linux-next@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	sfr@canb.auug.org.au, longman@redhat.com, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org, Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH] scftorture: Use workqueue to free scf_check
Message-ID: <88694240-1eea-4f4c-bb7b-80de25f252e7@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <ZyUxBr5Umbc9odcH@boqun-archlinux>
 <20241101195438.1658633-1-boqun.feng@gmail.com>
 <37c2ad76-37d1-44da-9532-65d67e849bba@paulmck-laptop>
 <ZybviLZqjw_VYg8A@Boquns-Mac-mini.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZybviLZqjw_VYg8A@Boquns-Mac-mini.local>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Qy8gOKmM;       spf=pass
 (google.com: domain of srs0=b2af=r6=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=b2af=R6=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Sat, Nov 02, 2024 at 08:35:36PM -0700, Boqun Feng wrote:
> On Fri, Nov 01, 2024 at 04:35:28PM -0700, Paul E. McKenney wrote:
> > On Fri, Nov 01, 2024 at 12:54:38PM -0700, Boqun Feng wrote:
> > > Paul reported an invalid wait context issue in scftorture catched by
> > > lockdep, and the cause of the issue is because scf_handler() may call
> > > kfree() to free the struct scf_check:
> > > 
> > > 	static void scf_handler(void *scfc_in)
> > >         {
> > >         [...]
> > >                 } else {
> > >                         kfree(scfcp);
> > >                 }
> > >         }
> > > 
> > > (call chain anlysis from Marco Elver)
> > > 
> > > This is problematic because smp_call_function() uses non-threaded
> > > interrupt and kfree() may acquire a local_lock which is a sleepable lock
> > > on RT.
> > > 
> > > The general rule is: do not alloc or free memory in non-threaded
> > > interrupt conntexts.
> > > 
> > > A quick fix is to use workqueue to defer the kfree(). However, this is
> > > OK only because scftorture is test code. In general the users of
> > > interrupts should avoid giving interrupt handlers the ownership of
> > > objects, that is, users should handle the lifetime of objects outside
> > > and interrupt handlers should only hold references to objects.
> > > 
> > > Reported-by: "Paul E. McKenney" <paulmck@kernel.org>
> > > Link: https://lore.kernel.org/lkml/41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop/
> > > Signed-off-by: Boqun Feng <boqun.feng@gmail.com>
> > 
> > Thank you!
> > 
> > I was worried that putting each kfree() into a separate workqueue handler
> > would result in freeing not keeping up with allocation for asynchronous
> > testing (for example, scftorture.weight_single=1), but it seems to be
> > doing fine in early testing.
> 
> I shared the same worry, so it's why I added the comments before
> queue_work() saying it's only OK because it's test code, it's certainly
> not something recommended for general use.
> 
> But glad it turns out OK so far for scftorture ;-)

That said, I have only tried a couple of memory sizes at 64 CPUs, the
default (512M), which OOMs both with and without this fix and 7G, which
is selected by torture.sh, which avoids OOMing either way.  It would be
interesting to vary the memory provided between those limits and see if
there is any difference in behavior.

It avoids OOM at the default 512M at 16 CPUs.

Ah, and I did not check throughput, which might have changed.  A quick
test on my laptop says that it dropped by almost a factor of two,
from not quite 1M invocations/s to a bit more than 500K invocations/s.
So something more efficient does seem in order.  ;-)

tools/testing/selftests/rcutorture/bin/kvm.sh --torture scf --allcpus --configs PREEMPT --duration 30 --bootargs "scftorture.weight_single=1" --trust-make

							Thanx, Paul

> Regards,
> Boqun
> 
> > So I have queued this in my -rcu tree for review and further testing.
> > 
> > 							Thanx, Paul
> > 
> > > ---
> > >  kernel/scftorture.c | 14 +++++++++++++-
> > >  1 file changed, 13 insertions(+), 1 deletion(-)
> > > 
> > > diff --git a/kernel/scftorture.c b/kernel/scftorture.c
> > > index 44e83a646264..ab6dcc7c0116 100644
> > > --- a/kernel/scftorture.c
> > > +++ b/kernel/scftorture.c
> > > @@ -127,6 +127,7 @@ static unsigned long scf_sel_totweight;
> > >  
> > >  // Communicate between caller and handler.
> > >  struct scf_check {
> > > +	struct work_struct work;
> > >  	bool scfc_in;
> > >  	bool scfc_out;
> > >  	int scfc_cpu; // -1 for not _single().
> > > @@ -252,6 +253,13 @@ static struct scf_selector *scf_sel_rand(struct torture_random_state *trsp)
> > >  	return &scf_sel_array[0];
> > >  }
> > >  
> > > +static void kfree_scf_check_work(struct work_struct *w)
> > > +{
> > > +	struct scf_check *scfcp = container_of(w, struct scf_check, work);
> > > +
> > > +	kfree(scfcp);
> > > +}
> > > +
> > >  // Update statistics and occasionally burn up mass quantities of CPU time,
> > >  // if told to do so via scftorture.longwait.  Otherwise, occasionally burn
> > >  // a little bit.
> > > @@ -296,7 +304,10 @@ static void scf_handler(void *scfc_in)
> > >  		if (scfcp->scfc_rpc)
> > >  			complete(&scfcp->scfc_completion);
> > >  	} else {
> > > -		kfree(scfcp);
> > > +		// Cannot call kfree() directly, pass it to workqueue. It's OK
> > > +		// only because this is test code, avoid this in real world
> > > +		// usage.
> > > +		queue_work(system_wq, &scfcp->work);
> > >  	}
> > >  }
> > >  
> > > @@ -335,6 +346,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
> > >  			scfcp->scfc_wait = scfsp->scfs_wait;
> > >  			scfcp->scfc_out = false;
> > >  			scfcp->scfc_rpc = false;
> > > +			INIT_WORK(&scfcp->work, kfree_scf_check_work);
> > >  		}
> > >  	}
> > >  	switch (scfsp->scfs_prim) {
> > > -- 
> > > 2.45.2
> > > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/88694240-1eea-4f4c-bb7b-80de25f252e7%40paulmck-laptop.
