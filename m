Return-Path: <kasan-dev+bncBCS4VDMYRUNBBWHVRXAQMGQE7ZZWVNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 436B8AB5AA8
	for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 19:01:15 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-22e815dd332sf97720815ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 10:01:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747155673; cv=pass;
        d=google.com; s=arc-20240605;
        b=cxhI1HFX/3m5Psfyxc6+2O5krOhjVyyNr/yo6clCUaIxNE03cTihg59ymfRwa5Ibr+
         vZ2wG2F0usDKs1GNNjiJ2pO9k9nTF9OAEnfk5J4PbnU5kGKvXdtJTBZqPu9Q2gDhoxRC
         k8n4pDitbnCYaEAV6S0ymv+m1awLwgk49aDRtCNqP9wiOGewvSTYwGNkfu7lkeBDGM2o
         S3Wmm/FMjXuWyK/VOcIi9LD/PWU6n+M2LBb+dCodo2JDzYEH0d1oIBWFGEjiwvn5/ITX
         YmBrdppy5SXYobE0ENV25yBt3Xh9/nXG/jkv+pemxx5O1vBvluXotU/mEeksksW8rRjV
         BxPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=RNqrq7HqYiouIPrBnZH1BDCowBjFfM36mC3Gku4CjMc=;
        fh=0faEWj/uuiS4S04FEN2R7U/X1eTcOJrnMoQbd0Ew4/w=;
        b=Qnl/8QhlRTqBwZsxjM/0OUrFHh1kBtZmLt1rW+4wsXRrTR/FkggZS1mT5avTMSwlQa
         qTMKIROgYY1ChPR+zG4JQxAJrQiEUI6af0esfvONsK72+kgCdCunzHG3YkgZDsAl189R
         E0sATP4I6Ig+NGeDD8ZOk0oK5an7EYROcGXFx423o6r5Yl8DAFCfneljOAy//yFlKr3k
         fgXPa/q/oAW5X15SuUl+6fRdahNwcz25aLnpPSukssMd24x0ZfjD7wWob4thxfxhgF1+
         07swsgXsbhk8xmQEoERZZc91KRhWRUda7Tz+lyxTn0AsWcGK9lYf8uhDSWqkMRzOCzuk
         oRiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=E0nDm1Q3;
       spf=pass (google.com: domain of srs0=ub4y=x5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=ub4Y=X5=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747155673; x=1747760473; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RNqrq7HqYiouIPrBnZH1BDCowBjFfM36mC3Gku4CjMc=;
        b=sWsDWxDYt4XQJo4tNa6XYkXKb3bE55X3gHdNU2m39iirFbDj++UXKmCRf+vvtA62K5
         pTZP9haSPsVxX2kscEeg4SSsP/3JLY/RksIKRn9UvHxVopEWrx/WwJ598JNCaB8SuxBl
         4936KrbaSJwaNT6Y5sXpdxobwKl7lUkxsv6dpyDghg6NT3Ql1bQYt7m8vC0NenZmnuCR
         4TLxw044eO5NCGy18aB9D+iZzsxLIlnRa44y+Nulg7bEajudhete/TXEKVqOUHVlikXL
         pSMbmFlHHeX5j9gpIZaOOyEyVq+tjK54kJZ/VHsWCO8yHE88ZpqDL8MnytxcgSSMICrN
         4wGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747155673; x=1747760473;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RNqrq7HqYiouIPrBnZH1BDCowBjFfM36mC3Gku4CjMc=;
        b=R3PolbYL+WU8thvxobonIBzM1dxao0/c0U2MoAuOQAmN7sMIuufI8/Ry1NysmI1dHQ
         QxuSYs3K8iQTujrKz1StOJEGmNSmFOV8X4L71P4StadwaodqsCFQOvmPrA7qccCSloRv
         Byq6TfR1K51ObKo40PNtJ4XgCIF0Tzf29vxv6V4raUaqoK7PZ5vX4fo6bZlKpR3DkfPX
         nCSAf9S1MWZG6n1tKzb4cZNewnTLDL3not3q2S2Yf+ahwzeCakm7My9n87xHTRCGbur9
         K1CeZoH2HyawSXeTWW2Kk87DLPQ+PktWI5hJJzOa7xu2c48iQ8fTxdxtmNIxtuxeG6++
         28Sw==
X-Forwarded-Encrypted: i=2; AJvYcCXxDTBeIkCfS5dkrEvf6UPE0FUfo1FFBlfE9IBsdlUtezzoWklKPcg7A4TqoSFy2gdE06uRqA==@lfdr.de
X-Gm-Message-State: AOJu0YyYHWv+xmACvRdz2qDnSxevwbjuWtifzOWkmBOz+1Jgqgledd46
	bbi7dplksSMxJRElZjSgVhN/GkE3znEIa1pXDegf0QTOED67W9mq
X-Google-Smtp-Source: AGHT+IGoIeioF/Kig72+W8zoKmf5BKgvQctOlBYRUXhTN5Q1Pe8rx2+MXJNtuUDpFqkx7f9Cp8i+pQ==
X-Received: by 2002:a17:903:2f91:b0:231:7f29:bda0 with SMTP id d9443c01a7336-231981caf3dmr1998605ad.52.1747155673275;
        Tue, 13 May 2025 10:01:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH0LHyp4XQSPUZZP5pW1d+DJzYLRjIMo/sosIwd9cqWtg==
Received: by 2002:a17:902:c1cc:b0:22e:53f2:59ff with SMTP id
 d9443c01a7336-22e84647527ls31550095ad.0.-pod-prod-06-us; Tue, 13 May 2025
 10:01:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUX14sKaDXkxdJkvuq5kX/lMc91dqlYUTJCKAsPfXykcommTqFe96GMIPyxn7qqSMNNM1zC0FxdpAA=@googlegroups.com
X-Received: by 2002:a17:903:1946:b0:223:f9a4:3fb6 with SMTP id d9443c01a7336-23198116577mr2916185ad.11.1747155671346;
        Tue, 13 May 2025 10:01:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747155671; cv=none;
        d=google.com; s=arc-20240605;
        b=QuY8UTDUsBqSzCIS6T2zckL2B7F4/IO7C3gVib5/CSgqxEvHxXZ+i66b2GrYeRFbFq
         vyIC2+zslZYiMHLD9NJY/+3iOsV/DZJx1+bGBcKCZ7O2EzTJ7a7rVhgvHBh6Mk5W+RDQ
         enQ7Uan9Nq9vDjJELzVQTkHYwwB+6N1v3xWJ9Xmo5LDRfhSEWSHeEYd6nuPEjDa2738V
         KxKnnI5UX2kDN4adfYPW21M2iMOLsIMFzJGSsfjMsbykz5URwSUvLp6zB9KaL6JMuEtX
         hhvqrG3pAfPDVGTANW7PtSxu1JaMMgK3D80ADBf8bNiaUpE4aCqZyTBgJ4AhOFIxbyaD
         D8ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=G+uhdjPBbW+SLJ5oT/j78RV3w7VML1EquUfb8UZePeU=;
        fh=rBmzTvIla8gNFmQMKabzWGhmScFoWoEhXgbh3Av6tBY=;
        b=fAkOsAseNzXMQTSE6XDNyzhqq4+Bbbsnybn7CbvWZDHo0bL/w/jnmo1urZy97nJOtH
         1O67fHAldUWyPIkPhSXS2OepRZExvgJjxVNrGdxFiRgGBB/4WfJKiVYBLzvPzObHJtna
         A0Lgi6LHgZlRtCknR5kULgOvtqPo+5cdXLkgUn3LOy5N6mnHkyOvL5L5/cfMPhJeXSH3
         2tLGlZjfkXwQXBno/38FaVBBr2E9tUfUK5y1FiGebIndJGLO4EPwcBm3qQfLChUm7IV3
         QmNGcukcnatw3FC6liAX8pP/XHCP8NgJkPz6ghvF242YGGt7FLc4NTGBTlwswnI8XzFO
         ZzOQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=E0nDm1Q3;
       spf=pass (google.com: domain of srs0=ub4y=x5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=ub4Y=X5=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22fc8225d17si1579135ad.10.2025.05.13.10.01.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 May 2025 10:01:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ub4y=x5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id BB4B843E02;
	Tue, 13 May 2025 17:01:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9910DC4CEE4;
	Tue, 13 May 2025 17:01:10 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 438B7CE0908; Tue, 13 May 2025 10:01:10 -0700 (PDT)
Date: Tue, 13 May 2025 10:01:10 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Stephen Rothwell <sfr@canb.auug.org.au>,
	linux-next@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [BUG] sleeping function called from invalid context at
 ./include/linux/sched/mm.h:321
Message-ID: <8a3b5e43-5d2a-4205-a24e-27148c968278@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <a5c939c4-b123-4b2f-8a22-130e508cbcce@paulmck-laptop>
 <87o6vxj6wu.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87o6vxj6wu.ffs@tglx>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=E0nDm1Q3;       spf=pass
 (google.com: domain of srs0=ub4y=x5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender)
 smtp.mailfrom="SRS0=ub4Y=X5=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Tue, May 13, 2025 at 09:39:45AM +0200, Thomas Gleixner wrote:
> On Mon, May 12 2025 at 16:47, Paul E. McKenney wrote:
> > I ran this on x86 with clang version 19.1.7 (CentOS 19.1.7-1.el9).
> >
> > See below for the full splat.  The TINY02 and SRCU-T scenarios are unique
> > in setting both CONFIG_SMP=n and CONFIG_PROVE_LOCKING=y.
> >
> > Bisection converges here:
> >
> > c836e5a70c59 ("genirq/chip: Rework irq_set_msi_desc_off()")
> >
> > The commit reverts cleanly, but results in the following build error:
> >
> > kernel/irq/chip.c:98:26: error: call to undeclared function 'irq_get_desc_lock'
> >
> > Thoughts?
> 
> Smells like what the top commit of the irq/core branch fixes:
> 
> https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?h=irq/core

OK, that is this one:

47af06c9d31f ("genirq: Consistently use '%u' format specifier for unsigned int variables")

This is printk() format change, which seems unlikely, but what do I
know?  Can't hurt to run a two-minute test...  Which fails.

Ah, you sent this email at 9:39AM your time, and that commit was queued
at 9:34AM your time.  The top of the stack at 9:39AM was this one:

b5fcb6898202 ("genirq: Ensure flags in lock guard is consistently initialized")

OK, early enabling of interrupts could be a bad thing, so I guess that I
don't feel so bad about failing to have spotted the problem by inspection.
And the test passes for both rcutorture scenarios, thank you!

I have to ask...  Will you be rebasing the fixes into the offending
commits for bisectability?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8a3b5e43-5d2a-4205-a24e-27148c968278%40paulmck-laptop.
