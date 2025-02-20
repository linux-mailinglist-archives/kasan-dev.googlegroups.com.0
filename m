Return-Path: <kasan-dev+bncBCS4VDMYRUNBBXG4326QMGQEKMMNKFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 59800A3E797
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 23:36:14 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-471f1b00de4sf30011091cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 14:36:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740090973; cv=pass;
        d=google.com; s=arc-20240605;
        b=jgN8hGkKTm6g5i2Mc4kAmA6tdl0kdqt3nDMShNrPuMXdSMFlIVeddl0IIdwFjMHpmZ
         swJYnIZx/47PNLocrrPAXnfLdn/NCBm/AhJc3VFEgWpStwAzNrmJlUeoHgW/07TsMXVx
         iRjMyt+AMUW8JUPtLE1aluX+nTVt9CD2Ma8Ofrz1oY9Fcrb5BnIDvHNHUHh1b8MPFEb+
         xUXNkUC+2fDZHSOSg56/+6pFJcQT6qwQIDqaGVrC/CyaHn9T41V2pYsHffUWFKg+BpXg
         U1vkFnCWqzlPEtMDJCAHcH+C4OwXIWsUDRU8gnBmLgqi3RcAcWQA51K7/n8KKaUFba23
         pcsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=uNzQe5i4rH7XEJctWG1NbqQSTMfXYfip/6WvanRNrtc=;
        fh=3GDFw43F++5//MuaJcPdTwhMN1tiEB05yjq4nU0js0E=;
        b=eT0Y9ey8s2G80IAsKPqithQe6Rzjs0Z5NC/o99bNUeXExYGXwVo3gstfWywWRZ4XmX
         6XNZf+m9xETJYaTOcIZm81PEsvuJY3BdHTBYQUuuWyIuILWWSteC6flFzthUOD1LQ0KC
         weK3SptEY/gxuagVhLF1YYWI+mATSkWkrQiyCEtBCmrb1zMvwz2o8sSdVO8rC+aQ6JuS
         38LlFJk/SLOyBhKTGsu8JCKdmbuHOkCrthgAKYBRsIuDHHqFSoAnD3JntzYD3W42sDsp
         o/JjanHQTWe+OU3zPyDS+r1EjX4TpQxKFk0QYEv9DHkgX9vRj77j8DCH1N03MH9pNraG
         rQFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FDyKg2pu;
       spf=pass (google.com: domain of srs0=edkt=vl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=eDkt=VL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740090973; x=1740695773; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uNzQe5i4rH7XEJctWG1NbqQSTMfXYfip/6WvanRNrtc=;
        b=OG+5YLSAruURsiCwPlENFdM9iN947Xr612mKfK1NHxFg1f9tnVUnXQltZ3phyCcMOI
         PhZXIfPXKWlx2mzofzrzGH6pQsrJ0+0birzAf3HZjOBZYvz5uWYVi1EoB/Bne8sx/iYy
         CWic8oRbH82hyamQMmEQpz+URQ7q9sIXBX7A0cnOmucFyU9S4USRyBqRIpyihWxNa/c9
         8/UitSUqvSP6QWrexUSl9+rYPPKd9NewQTBMNBqUFeuVCF4AOibp0waVFFn2CuTcqiYW
         qjHoZYjJR0hTCDDN3t6hv7hU8qQYF0zJaTdcif2bBg2Ii3Vjm8NMJBjzNOmVhbyr5dCV
         7wWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740090973; x=1740695773;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uNzQe5i4rH7XEJctWG1NbqQSTMfXYfip/6WvanRNrtc=;
        b=i1gCiyqyJ+RbbgxMH4aYsq9/RqJIzHskJA8j6RpeC29C7letxLsdfMlu1GtUU3Xgpy
         Ypd4gulPeiJxFNxPUY2Whjev3xb1aQzaf43U/A1aNanKr/Aa9H93goWLPHia4+Qy05b8
         mGLVMf4A81+CD0nc6Zv+ceOFKmxXHdmIzpRZh+ALm9GEYbpFD/XI1+G/kzbtgiyK86aU
         jki9NnQTbsLiB00wYVmvUhpuYTHleKM3ds/X8msRmBuGAIXhFRbhZqeulT8NFgmRIDiF
         v56rn4JPW5oCAoJhYXKCIJ5MfTzUtqUdbfzr68KFtyVgFdOmos8VhVi70VRsFLP39stx
         KomQ==
X-Forwarded-Encrypted: i=2; AJvYcCVunHMO7RhuxLnZanGolCud0Th4C7kusbm1jK1NR85muorLQVyAgG7kRBAHF8EvNoQnyeF5tA==@lfdr.de
X-Gm-Message-State: AOJu0YwSc9sjYYMp87vQc1z/gM3Ds0Orxf6i2JpNo8BY3xZcjytqGqCE
	Ki4uzLa+yfCtpHElb+LduNG2cves4Hma5ePBsYmqT/nK5j6bsBIE
X-Google-Smtp-Source: AGHT+IGTMzQHGFWN8Y8s+n+L2FFRJBTSiSu8Ygp3tUuTxw/KUnaBVT4jdCB/+uRTi1gLObyBphpTjQ==
X-Received: by 2002:a05:622a:104:b0:472:9ce:68fe with SMTP id d75a77b69052e-47222931aeemr15180051cf.36.1740090972894;
        Thu, 20 Feb 2025 14:36:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGOuEwNfiPKDu9shTvPmpg898wE6PUrSO3oM+fafbu8Zw==
Received: by 2002:a05:622a:134c:b0:471:f5a4:7d3a with SMTP id
 d75a77b69052e-4721708d465ls22519751cf.1.-pod-prod-01-us; Thu, 20 Feb 2025
 14:36:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWZXLBpdUoN70lunYh7u1wINoet1cxEQGd4a+aS/f/EsgFqxlbucJA1V4wnIk3kvfIx9MoS2db/RzM=@googlegroups.com
X-Received: by 2002:a05:620a:4155:b0:7c0:a46d:fa8b with SMTP id af79cd13be357-7c0cef0b146mr199645785a.25.1740090971855;
        Thu, 20 Feb 2025 14:36:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740090971; cv=none;
        d=google.com; s=arc-20240605;
        b=UtaTRKM44yDX5BK2MrgRxALq7RlCQ82TrEVueWDH9OVbHwGVQcFI5sPNNvW9ZJVRTO
         KH0TBjizwpK30mmEflv4LtpbaSM+6zyB1YsugQkFjkP31DwOxtrffBILKiBBWM6suIh+
         gegxC3hrDQfpQz4DOCfzUIMslm1O1LfOSZHqaJ9nDyOC8UeYhVCCaZ49ToaCHOnv2RnZ
         Gz1YUht2WILm9movOpyvpm0hDPTLFTzVhqVehM67f/wTs5kwjZm7Vw9XtkD1Y9ghqBNu
         cQ5R9nQGbyZk0fxnmU8/ifoB28Qm5f5PyFaWg1hP1joUVC2/qGkPTeS/4BOEpl8H7zP+
         8xsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jHCfDidNK+lCv42/jxuFNctpEdwsJ2rG8nLV5Agl/lI=;
        fh=6daLWNj2ng9AC7k6NsHppG+JXGUhij4U/k8Liihd2jM=;
        b=b0obxgGHCzXrJu+t/Nlv7lsTIPQkDhZ4ubKpMQBp/H8WfbEVqgq3vpPDkB+iU/AyPe
         B5AOAwVdA/hfIGzbffuK5bOxNDNOxeS7o6inhrazzM5tgP3ng9Mq0ky7teTeS5l6EQ49
         cSq6LDZOtTiHBpHy1UzIWA/ouvpxpgU2BRBHUjEhItrNIMsSkyuEYoETy7UskgUAAWHd
         HIcfocX6qyrmWUoFrKgmcmIw1j3tdj0V3mwHRHqjAUGBE1B4xRVIkF6FHFsO4iO0Ipwf
         wSp/vNL6i89lBEbANbfy7M2w70yhb7a3WmgiCfs/ncjXwUchnriKfDpzkoOd7x4ZBRVG
         DSQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FDyKg2pu;
       spf=pass (google.com: domain of srs0=edkt=vl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=eDkt=VL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c0a80886absi28259785a.0.2025.02.20.14.36.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Feb 2025 14:36:11 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=edkt=vl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 16AFA5C5513;
	Thu, 20 Feb 2025 22:35:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C1158C4CED1;
	Thu, 20 Feb 2025 22:36:10 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 5E986CE0B34; Thu, 20 Feb 2025 14:36:10 -0800 (PST)
Date: Thu, 20 Feb 2025 14:36:10 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org
Subject: Re: [PATCH RFC 15/24] rcu: Support Clang's capability analysis
Message-ID: <3f255ebb-80ca-4073-9d15-fa814d0d7528@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-16-elver@google.com>
 <a1483cb1-13a5-4d6e-87b0-fda5f66b0817@paulmck-laptop>
 <CANpmjNOPiZ=h69V207AfcvWOB=Q+6QWzBKoKk1qTPVdfKsDQDw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOPiZ=h69V207AfcvWOB=Q+6QWzBKoKk1qTPVdfKsDQDw@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FDyKg2pu;       spf=pass
 (google.com: domain of srs0=edkt=vl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=eDkt=VL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, Feb 20, 2025 at 11:11:04PM +0100, Marco Elver wrote:
> On Thu, 20 Feb 2025 at 23:00, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Thu, Feb 06, 2025 at 07:10:09PM +0100, Marco Elver wrote:
> > > Improve the existing annotations to properly support Clang's capability
> > > analysis.
> > >
> > > The old annotations distinguished between RCU, RCU_BH, and RCU_SCHED.
> > > However, it does not make sense to acquire rcu_read_lock_bh() after
> > > rcu_read_lock() - annotate the _bh() and _sched() variants to also
> > > acquire 'RCU', so that Clang (and also Sparse) can warn about it.
> >
> > You lost me on this one.  What breaks if rcu_read_lock_bh() is invoked
> > while rcu_read_lock() is in effect?
> 
> I thought something like this does not make sense:
> 
>   rcu_read_lock_bh();
>   ..
>   rcu_read_lock();
>   ..
>   rcu_read_unlock();
>   ..
>   rcu_read_unlock_bh();

If you have the choice, it is often better to do the rcu_read_lock()
first and the rcu_read_lock_bh() second.

> However, the inverse may well be something we might find somewhere in
> the kernel?

Suppose that one function walks an RCU-protected list, calling some
function from some other subsystem on each element.  Suppose that each
element has another RCU protected list.

It would be good if the two subsystems could just choose their desired
flavor of RCU reader, without having to know about each other.

> Another problem was that if we want to indicate that "RCU" read lock
> is held, then we should just be able to write
> "__must_hold_shared(RCU)", and it shouldn't matter if rcu_read_lock()
> or rcu_read_lock_bh() was used. Previously each of them acquired their
> own capability "RCU" and "RCU_BH" respectively. But rather, we're
> dealing with one acquiring a superset of the other, and expressing
> that is also what I attempted to solve.
> Let me rethink this...

Would it work to have just one sort of RCU reader, relying on a separate
BH-disable capability for the additional semantics of rcu_read_lock_bh()?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3f255ebb-80ca-4073-9d15-fa814d0d7528%40paulmck-laptop.
