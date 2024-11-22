Return-Path: <kasan-dev+bncBCKLNNXAXYFBBRWGQK5AMGQEOMM356I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7826E9D6159
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 16:29:12 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2ff29e23641sf15233071fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 07:29:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732289352; cv=pass;
        d=google.com; s=arc-20240605;
        b=eFy8hHEjv5lzYUP9acC0mmkuGiX2H837PyQSo6q5rgJB9C/yITakrMgS2tyGvRufID
         nPDSeZSlTLi4RzD7cjMD94VAAZjwUUUqW3e3IoL46I31DruWedbIXrve2xI4i1Gg3xA0
         OL6ML/Uv+hKvI4VFGQEVwDXqbzTr4SqgWADhkG3C0xe2wLzpTLlPSAgGXTHw/7BqYExh
         uIf6ZEJRaPtsejg6lWOnAOrE/v5UyiHMAmV7J1vdB4p6xeSclOsv+0ek9lhyjR5cd+LB
         hsYjFHZo44syrSzQo9NFhhGCaviYMLKXer37aMGo0mu/QR9+T/R+CTbe26fuz7DUeDxl
         dcOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5ebikTmHITfVvDalEiSVzC5dZLp/pSDey/zF34CtbiQ=;
        fh=1yqjsP+8i5GTs1vhT2u/nI7hq/b+BqrXB+oH27Dfeak=;
        b=UrUOX8MhY12D+L0uBKX3lc+m6jjgdpukamX95OfXXBJr09UiAB5Elkf0hLJXag1Sno
         MuBn7BbxlPDnOStkquU8oC2Flx6xV/AboeXcpYHlLfmLD+0ETuIboPWNne3a019x+eXk
         VZAvmNabWeCfTQ5eb+RCxbTykbrCn8ap2+omQtgV8H6LgnaWd6OSnR7IymYUhsobRU0/
         k7n/M3jGlGoj02JRsHaFuS1/UM0Gs8/mh7NQZmLE6bw0TsqS6kZaM58Pb8z5wJJLTByT
         lnG1kRjVIozbmlGqwutdQG2LNZWgmTio0nbocv91E0LqCyrpRJxnqdKdaNwY9bFS2d2M
         mHXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=B2OLAuG6;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732289352; x=1732894152; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5ebikTmHITfVvDalEiSVzC5dZLp/pSDey/zF34CtbiQ=;
        b=DLNuxOuXs5htfzUIpvILczIwBBqvbjqHQON/ayxG57L0qwTt56bEJbvAm5Y4/VSHp3
         lX+pIOLALBPmQ93oFS7B8Q3DWM6t6g327LgWgEONusO9o+cZvyrpBbw8yltwcoqistKP
         e8JXozAcEjNwpso21QtYm4LIJUfGFg1dGMfmNC+NZzNoPp/AdErme66tF15dyGAx3HsY
         gPY8e4mlzuBj52dgrmwveb7HlC1earxjJlv9KFf81Q4ugw+tBKoTR4dA8qZyjDe42lel
         but8sJeuqXp+t1ZHCXfvRMi2fEYMkjfiAizm1rI9gy9C5RFVt5R7qTQjwztWR0yRGxX1
         l7xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732289352; x=1732894152;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5ebikTmHITfVvDalEiSVzC5dZLp/pSDey/zF34CtbiQ=;
        b=uDMKv72LF3Ykt5NtxdCTNFHIRtXVLacJem+NdjimOOOWh+THaBejGSYZFw73oBxF4F
         UjAb0NR4sK6aw8RP71OzJLXE6kAGmqYFQYm0pG7BE9Q2icZBrl1U8bRTCmZeaUGJRBxs
         9r/DicsMC7yI4Mk/BtJFAhQegy1XMVAUvEW9Yqbyc2HeQ2Nmoi+Ll9WFnFKKhkIiXnMQ
         x6pMLOI48RD5p0hJFXlePD8KkCB76pU7L85OqvxVWz5Cwg0bRHDGJCTVZ19L4txanvWM
         fodRLtR0W52Rrgvhq0R8j3rFCk1tVmpE+XCwNFgOrGpnbMuk83/7Z59VGSh3wM7SDPCY
         7Vdg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXkP5aSWCm9Kvkv2qka0OMJWp+wmIvcTRnXcd8tTusjTPEJ0LUgBoaqsl7nSf1Q91c93DCz0Q==@lfdr.de
X-Gm-Message-State: AOJu0Yy4ARak2bQt6BngP7aOrl/5usjdDYFMsDCcpn189MdyKW6rFGZU
	y9FF5rfu+5pDRfxIt7lEQlsTaaQJeEIIKvaMDEn4Gv81WWgaFGAq
X-Google-Smtp-Source: AGHT+IHpPig5YRM/RWc3/yN988YWZIAGF0fC35Nx6BgNYTA1lwAxE/u0IJra5kVDNLOFIcJLdxyVgg==
X-Received: by 2002:a2e:be1f:0:b0:2fb:584a:8ea6 with SMTP id 38308e7fff4ca-2ffa7180cc8mr19630971fa.27.1732289351267;
        Fri, 22 Nov 2024 07:29:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d48b:0:b0:5cf:e291:4774 with SMTP id 4fb4d7f45d1cf-5d007e39939ls104407a12.1.-pod-prod-08-eu;
 Fri, 22 Nov 2024 07:29:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVeg9DW8tBX2hyNsWJ2whYl3P6CRoPIeiSfUYdXdwWjLclDUeeVbFfBO69DFXPSJ348QJwOIypy9Gw=@googlegroups.com
X-Received: by 2002:a05:6402:530a:b0:5cf:ba2e:898e with SMTP id 4fb4d7f45d1cf-5d0207b2d77mr2547544a12.32.1732289348630;
        Fri, 22 Nov 2024 07:29:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732289348; cv=none;
        d=google.com; s=arc-20240605;
        b=arueIYuwggOa3I/EUNndsDVy/JmydxCnF+R2bL8o2F8/KvHIGXP3oPtuNuGxx3by9Y
         3+TanqDS6HHJkJ67/1E+L8Y3li7mBnaJJTvdZsvwtMWbjJ2KVAcbt3o5pGZFAV2m2h0G
         zYca+/eroAdI6guJ814Uabv+PHHNLxoxgBKPctxEoPulGS1lDcyMYYi0C+2OwLebZvly
         OTc0S23/pY5nY0GRi7cUG447dzZGk5tv8uHNnZ3UJmG+ryE5v0TJG3DcGnjrQn05gHiy
         XoOaIPdEyS3/ywLY9JLGPCzkfuzPd/SGbML5wwxeX7xDpl2ZSN6axMo9bRzVW7Vo4DYU
         A4nQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=X1Gjbn7bSatPmLMP7OcwtXOBlb5rE9gVl2DfyPsZLUU=;
        fh=O9gnHCiJOGCB1ro4nYBpn3rtuNbuYYjaMMidY+M4XYk=;
        b=BZJJbk9CEstzVJ/PeyleUPEMevMBmz76DupNjz0X4e1ME9YD44Ew/gZelHAWTOWXb3
         B3CFhtmJ869JxEv1PYwnOtDZXkO8x3vofV3zj4NAtA1ZCE245FWexaysIWwUqEbrlZpo
         ByxqpebxnZIJoaisj/bHVizNobTAeXNyq9StfS/3G6OYuOWGEFQFxbHu/XFx3Glvt8lv
         7x3aG/whShSTaVvd0QbE0BmHqLRqJHVld1wN4vPtBa0t39vRLJ1oAivYacixIEAD2uKB
         sKqiM+6WnohmztBN51IaNSdo6I/hiOidM9NCsebYkwYylXEIjVbrxYgscB5LVM7oAp1Q
         2zBw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=B2OLAuG6;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5d01d520015si69636a12.3.2024.11.22.07.29.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Nov 2024 07:29:08 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Fri, 22 Nov 2024 16:29:05 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>,
	Liam.Howlett@oracle.com, akpm@linux-foundation.org,
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	lorenzo.stoakes@oracle.com, syzkaller-bugs@googlegroups.com,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Waiman Long <longman@redhat.com>, dvyukov@google.com,
	vincenzo.frascino@arm.com, paulmck@kernel.org, frederic@kernel.org,
	neeraj.upadhyay@kernel.org, joel@joelfernandes.org,
	josh@joshtriplett.org, boqun.feng@gmail.com, urezki@gmail.com,
	rostedt@goodmis.org, mathieu.desnoyers@efficios.com,
	jiangshanlai@gmail.com, qiang.zhang1211@gmail.com, mingo@redhat.com,
	juri.lelli@redhat.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de,
	vschneid@redhat.com, tj@kernel.org, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	Thomas Gleixner <tglx@linutronix.de>, roman.gushchin@linux.dev,
	42.hyeyoo@gmail.com, rcu@vger.kernel.org
Subject: Re: [PATCH] kasan: Remove kasan_record_aux_stack_noalloc().
Message-ID: <20241122152905.iyjG97GS@linutronix.de>
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com>
 <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz>
 <20241104114506.GC24862@noisy.programming.kicks-ass.net>
 <CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com>
 <20241119155701.GYennzPF@linutronix.de>
 <CA+fCnZfzJcbEy0Qmn5GPzPUx9diR+3qw+4ukHa2j5xzzQMF8Kw@mail.gmail.com>
 <20241122113210.QxE7YOwK@linutronix.de>
 <Z0CcyfbPqmxJ9uJH@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Z0CcyfbPqmxJ9uJH@elver.google.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=B2OLAuG6;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2024-11-22 16:01:29 [+0100], Marco Elver wrote:
> > Do we need to update the comment saying that it must not be used from
> > NMI or do we make it jump over the locked section in the NMI case?
> 
> Good point. It was meant to also be usable from NMI, because it's very
> likely to succeed, and should just take the lock-less fast path once the
> stack is in the depot.
> 
> But I think we need a fix like this for initial saving of a stack trace:
> 
> 
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 5ed34cc963fc..245d5b416699 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -630,7 +630,15 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
>  			prealloc = page_address(page);
>  	}
>  
> -	raw_spin_lock_irqsave(&pool_lock, flags);
> +	if (in_nmi()) {
> +		/* We can never allocate in NMI context. */
> +		WARN_ON_ONCE(can_alloc);
> +		/* Best effort; bail if we fail to take the lock. */
> +		if (!raw_spin_trylock_irqsave(&pool_lock, flags))
> +			goto exit;
> +	} else {
> +		raw_spin_lock_irqsave(&pool_lock, flags);
> +	}
>  	printk_deferred_enter();
>  
>  	/* Try to find again, to avoid concurrently inserting duplicates. */
> 
> 
> If that looks reasonable, I'll turn it into a patch.

Yes, looks reasonable.

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241122152905.iyjG97GS%40linutronix.de.
