Return-Path: <kasan-dev+bncBDBK55H2UQKRBQGETO7AMGQEW5USADA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CA99A4DC55
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 12:21:37 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-390e27150dbsf5354124f8f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 03:21:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741087297; cv=pass;
        d=google.com; s=arc-20240605;
        b=jhdORq0rAFaFTJzEiNtsTB7xYnx/lKBupi8Fc8XTAmy2eXUedn8hySt2nopB9ZMmkw
         4TnacezU/MX4Nm0xDlngFV4tnzZP5zfU+WGP2RMNBUPCeRupj1koFz4fXuds9O8f3M1+
         l2nbmZBYwVCa+UTfxABVwK3N7SRClRsC3CuQdXpiybmvmU9OlHu6HOP2iCssOB4uOrr9
         AnsCzPuR1b8PnFYv5PWJZzSgyaycOgxGAy9ImdF4Sc63X3R66Xe8LUQGY8tsjYS/nSLI
         DainMSJWBu6JRfRfZM0xHC441oi5pZrtKpvVMoiyjM/Dw3fsYFj/coXSX+33TN4rm1Cx
         02nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KpNU59SocZyRmAscTpee5H2TUeQ0QyCOFPaN8vSOaUU=;
        fh=KDvqBj1U7sr3abyfDi3pSs7lawl4yYwa9KePqzYw2ME=;
        b=M6PjGfwTZ5SqqvWa+GrS9a8BtsYRUraYDtBSi/omk4pfpLp4WX9UpGSdnj0Dx/faPO
         6vBzn80xg8hnByvUSgBwuWSwtknUtx1lMTCu/12laO8yDfgTLS2DkKmGVXEJ5TwN028d
         uatJiVU4j6nEBgbs+jRXap4I6MRMTX1uqDE1/aQrnGKrd98jwjbW+GVX9nG/G56ZELHj
         AAm5qmOpGyuZ8YiLoMhW3XmkFDMXNltAnDgzuLqyH2NC22i9cw02J7X6tnFGMYuvv5if
         6rv1mhhQBZls7I10G8PMnGg4nYh79vXRcfA908YAPnjHgcL0d+V9SoOSrewFAhEKQiUv
         ET2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=NLhOclrZ;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741087297; x=1741692097; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KpNU59SocZyRmAscTpee5H2TUeQ0QyCOFPaN8vSOaUU=;
        b=jaa/l323LuJ5zLi/eyKlZbcfnPslaVWNhKIakteWpQWpmOdnlIBbjjaxx5TwaT3UlJ
         wwUP7NJZcLsG/aY5BXI4fEFIfuQ+J1ubJVFOLH5Z2/Ox0zIJEqHI6yEtvvsgcO/5AwkC
         fwoAshX3xa+T02Gld2v0LUdqjhlhe/5EZLVbOx9w3pgncOcni86sdzqRX1s+zKxafL6Y
         gt/xLx7i6ga8iXHgfeDyGigfn8r5NrWev0J7KPSNSc9cMgdlq7KOkcAGxvlEvls9NhGf
         AjFAZhOggfXxs+jGJs5Qzh09ZRY20JKzWmHZBtnQ60SbTb0L6dlmnT2PhOg6IYnwak4y
         XfFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741087297; x=1741692097;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KpNU59SocZyRmAscTpee5H2TUeQ0QyCOFPaN8vSOaUU=;
        b=OEN7lesclo0nsUGTVXDO+ODhq3n9MNHVO/Yv3mXxrVd6BJKZ+RQLDGEwbt5xvCCaFb
         BTOZ3m41dryXLcsFIiy2rNLT+Q03Pn/gPUhZY6gkQ7W5t6rtTeWwXX2JiWAmOF+nT6AD
         kWNSPKAgax3xC4Qt7waeqDzjcclAzJ1StGTmQKInFFmPqDaQnyZKBKJ1IMirPTwX0I6T
         Ywz4BcheErZscgOw9wfAye4aDyTTcqV2PlqF4eyj6nI94I4pE0n8k/YI3Fss7jiZu99M
         uOC4z5GU7Yjy8KchHpRiXt07XtNa8DuOWL82y9h3b8IGNd0u+iNqd/g00ILXpCgGeCC6
         1Ixw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW236Azu/Bdf6t+1MyBlJy75CeinKWjl56Eu3fp5oxPsMwN2aEE+cYZiBy4RlThd0WciwXqPQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy/NNa1vledpNhI3B41+esM4ct0PHqqpPYSb5LDZ9wiyywUg1jw
	9kgHhWCtjl3/0eb/zruOy1lRjivPUstENPWjv9Ovnuv0HGoqEPtg
X-Google-Smtp-Source: AGHT+IGvp1BrAADTPSvYMaU7siSfX4H/h/xQ+0hTErmTm58ubMeKGfXVVAYKLdf5cFdI6WCYXA/aWg==
X-Received: by 2002:a5d:64e2:0:b0:38d:dfdc:52b6 with SMTP id ffacd0b85a97d-390eca27b9bmr13490120f8f.37.1741087296454;
        Tue, 04 Mar 2025 03:21:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHcXmgWe5MIrsW7OgQyQrjgXr4ADV9dolk0s6pthRMpnA==
Received: by 2002:a05:600c:b4e:b0:43b:c5a5:513c with SMTP id
 5b1f17b1804b1-43bc5a553eals8011125e9.1.-pod-prod-02-eu; Tue, 04 Mar 2025
 03:21:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVcmvRZy59D0FR5kGLXFvs4/I+/WSJ+Tj4aHX8kPJCBmKX9SufyKk04SMyCO7f8y7tO91cSo2Xevc4=@googlegroups.com
X-Received: by 2002:a05:600c:511e:b0:439:9aca:3285 with SMTP id 5b1f17b1804b1-43ba66dfe1amr135721605e9.6.1741087293923;
        Tue, 04 Mar 2025 03:21:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741087293; cv=none;
        d=google.com; s=arc-20240605;
        b=J6mUR+2p4N/y+pORqFBbZ3I/YpsWqluKPhkkI1WE5y4FNOkwMa8zLUsoF1WoMpcIEy
         QJhKKg8D0AuYWwbYdXU4wFASfGVP+UlPzWV0nRniuBDcK+4REVf/jsEDq6RnR5y1I60Y
         SbZQ/ZA+Gn2zbAaL7HHoI5Mv+181bDDXWA0kSQcRonsH97+rPRpLintDKxBlsGbsK23E
         onEppV5pjbwqlxV82uYlFcsNS8i1xGNLY48HLHqrVr345HxzL85WvA62GbOmjqNWdmN5
         +az6r3cWgnCEPf0F70/i7tvYJhpRpC9GryO0Zagd5T439iL8LIabjbWHI1mgmu/WOeFs
         nu2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=TnqWbk5+EzTofNzXNZf/lQYyzC/wnfe6I/8xtsT0bhY=;
        fh=7TaygT2PzvUByhK1cv83Q8e6MDKw7N3itZdt4LeniwY=;
        b=HWfIkLCHilPxaWOuy2U1DyrTHqbgp03/LIQyLZyoo/uHMRSF398JMb1CsEovt//FGp
         1pbYLj0TNdEZ/qAjPV9eBfqJ9n6bXc/imkFjheiB0LniDNMUAggWX6DuhMc9HPvtWJAf
         9URC86vbw7HKL7kG7IypnDWN1lDT6MP8v/i1c+jXU4A6ht2TGLxJ1ioM8zAv6wGu/AfJ
         o1+sL0mGFJr3Osm6P25nOeXxhPX9llByt2ufgr34JdgeQe2il+eIuHQmW47W2IeKa7E9
         pi746D/BgAQy/7f4x0lBNNp7CxM+fWKCDUVS3pZ4f/ncgbn12zYq1mfAsIh3TQYjPTEd
         XfUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=NLhOclrZ;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390e47ff679si390774f8f.5.2025.03.04.03.21.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Mar 2025 03:21:33 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1tpQKp-000000000gA-3GAm;
	Tue, 04 Mar 2025 11:21:16 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id CCF5430049D; Tue,  4 Mar 2025 12:21:14 +0100 (CET)
Date: Tue, 4 Mar 2025 12:21:14 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Jiri Slaby <jirislaby@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-serial@vger.kernel.org
Subject: Re: [PATCH v2 00/34] Compiler-Based Capability- and Locking-Analysis
Message-ID: <20250304112114.GE11590@noisy.programming.kicks-ass.net>
References: <20250304092417.2873893-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=NLhOclrZ;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Mar 04, 2025 at 10:20:59AM +0100, Marco Elver wrote:

> === Initial Uses ===
> 
> With this initial series, the following synchronization primitives are
> supported: `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`,
> `seqlock_t`, `bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`,
> `local_lock_t`, `ww_mutex`.

Wasn't there a limitation wrt recursion -- specifically RCU is very much
a recursive lock and TS didn't really fancy that?


>   - Rename __var_guarded_by to simply __guarded_by. Initially the idea
>     was to be explicit about if the variable itself or the pointed-to
>     data is guarded, but in the long-term, making this shorter might be
>     better.
> 
>   - Likewise rename __ref_guarded_by to __pt_guarded_by.

Shorter is better :-)

Anyway; I think I would like to start talking about extensions for these
asap.

Notably I feel like we should have a means to annotate the rules for
access/read vs modify/write to a variable.

The obvious case is RCU; where holding RCU is sufficient to read, but
modification requires a 'real' lock. This is not something that can be
currently expressed.

The other is the lock pattern I touched upon the other day, where
reading is permitted when holding one of two locks, while writing
requires holding both locks.

Being able to explicitly write that in the __guarded_by() annotations is
the cleanest way I think.

Anyway, let me go stare at the actual patches :-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304112114.GE11590%40noisy.programming.kicks-ass.net.
