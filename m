Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAPI33FQMGQECEAPALA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id cZ4XEAS0d2nKkQEAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBAPI33FQMGQECEAPALA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 19:35:48 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C3E188C206
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 19:35:47 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-59df8699267sf547989e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 10:35:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769452547; cv=pass;
        d=google.com; s=arc-20240605;
        b=FRUeDBZxq3C7vFwaw7a61MpmMjMCOjyyu0tJrinmTuZwr2Kg2UZsbvPAwsBzhSfrUc
         aKwm32YRxtyqlivg4iNlI3KeiUI9d2+cA5ooZA66Y5QIAoebVr2MSCYH7lATAwG5DtHx
         aOY3rB/z2pLDc4bkDcg4k/cMH8lp/S2Czm/LJHtFGNVqcI3h8qo0jiShPrX6e6dtVdWh
         5VUJxPZLwSELlcil5IVpE6onP7iKmGUIhOoQJKXmHN6XW/FSoSoWoFN/VOaK0ZLI4FRJ
         pHWj8mZ7KiEqO8bWHF5vEkfebnPzT2GYSraiTqlbyQFK+4VtMdE9A/NdL6Tzxyp7dlXp
         H2wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=OY8O8pke6Wo7WNifmm8wUAIr1BBcm9tSAm4zXD03sxo=;
        fh=22fd2K6Jm787sn/k/NfZO5gZa+Jsp8z6ByiajYfS5y0=;
        b=Q6uXVX9p+iNJxH409OaluMmsT8nH1/ghAJK1PkET2i76qodv0RMiTTFrrtk97k/eQ5
         uZ99LbpI7M0pDvtgJT8X6dObpCS3aQiY9N14I3YhOomcIXQMzrXgrhaZU4XRjyGNpFWT
         O0Etth5zp7AscuRwnSFSKaiclXHg91JSapdrq2J99T0KyBtujAppDyhVMpLdlvIxyfAa
         Wm5ByBYm3R+PfDMvl8NStAf3YTMD9wbuvTvbmNGUVlXoSzc3EL9Zr6pamv0+AJhNys3+
         6H2a5mcLFrC9saydXmR+2+UfUQaPsRg7NPQUe8VGQbLxAVL7divqMIUfiCMXjbuaIApS
         aBdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nJVzA4wB;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769452547; x=1770057347; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=OY8O8pke6Wo7WNifmm8wUAIr1BBcm9tSAm4zXD03sxo=;
        b=eRr4nQpQLmmsX3fG/cunH+8cXlkJYFfSKpzRhUn2qqfZRSezpPYX9Fay//8A9EVdPd
         0QFVBmL1P2XVxkTwtSSM0e00Ho5AvuOIeUjk5ZaZh/uBZirW6VuOSA77sucZMpa5Zi4s
         UdGO4xST95MND9+llkUKg1nL6bB6oyGULbH4ES0ft2wCrkQ43mWK5xVdI/7d9Q8EdBCx
         /pfkruJwPbHNwBt2fCLfwd1Rfj/tg/mn9O8DnnVgraoKLMFcocmT0x6clLBHpOs1vmDV
         hOj6PbFh7coMetLi5iVEehvYfwCCL4f3bpyayb5hrinz/Mfa7DI4DZpRU9cLk+WffeBk
         dtYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769452547; x=1770057347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=OY8O8pke6Wo7WNifmm8wUAIr1BBcm9tSAm4zXD03sxo=;
        b=EEHDX2gllyr1KHeo3K9J162G0K3AxyI60Q0RyUsxYUpyh7fc/ty6KBDWNmYvgZ5avw
         2XGfTo3kHB/9PLtBZvDfJ8QjXdv0w8Sdd1HXfMKW5JzrRCypGyM0CBFAKB0fAvtuC7ve
         RIL6oNPGGQVZs+c/4DZh1JRa4Q1Ze8NYgw3Il699lV80kZdu7PV7PxPvyEE+oIYQa8Y5
         JdnvDGD/0pbPSu2iPVsE+S4+nPXCL62q8HFnAcEZ/KuHq6V1375NA1Xs/STWLlBfXAEp
         Umfm0YBu3L1nOZdByms4/3XjOQ0STqC6ymRgEp0j1SnT7Oji9cflv4YQGo/OU8+AIqL5
         vpXw==
X-Forwarded-Encrypted: i=2; AJvYcCVIqs2XDRYjyjt3+xqDA776XQwo1pLU+23jIzWshUErSBThZsdrcDcnKnTU4EN6NiYYvsCQww==@lfdr.de
X-Gm-Message-State: AOJu0Yyj0wF3MyGaooAX4JsmNqyKsNdZvjOcK+gTwVbur9i8Ywdinfyw
	nlFpYocZkyeiJrl9WHhHrZM1V9kl/ykdAklZP/+m4ygv1+XwdWONbBm7
X-Received: by 2002:a05:6512:3a86:b0:59d:e306:843b with SMTP id 2adb3069b0e04-59df361a39amr2026599e87.23.1769452546492;
        Mon, 26 Jan 2026 10:35:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EKP4O0mv4LIw5Me4Uw2yP+vp2s+LQJTNzay/falosAwQ=="
Received: by 2002:a05:6512:3e1f:b0:59b:6f90:51ba with SMTP id
 2adb3069b0e04-59dd7840222ls1373958e87.0.-pod-prod-03-eu; Mon, 26 Jan 2026
 10:35:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWJMbqYNnCGtuPzxCAtfLICbxUE6omzVjvM89S475USTVMapRo2as3nzurCmWA8fn4q16AIRvJwjUU=@googlegroups.com
X-Received: by 2002:a05:6512:612:20b0:59d:e714:fece with SMTP id 2adb3069b0e04-59df3a12398mr1195336e87.24.1769452543350;
        Mon, 26 Jan 2026 10:35:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769452543; cv=none;
        d=google.com; s=arc-20240605;
        b=fnm0jKIHjaY9WsXMFzzJhjAl+lvRDqE8RMhms2ioNnBuamFOp3cDY4vuc2Hl3uyxZM
         a5MCRPeX9Kfpy9B0uEQCgikoBg94SOaElRQDqAKkOXH5H5xOs/n2FWQZF7IfJHQniIWW
         GHO8mGlTUllNb8m+k6teicyEWOC5FJIcXMFEgpcKlrdqgKLQhkrNIiP8KrvhCS0Ma2hu
         eX+W6JAMU6H/JS5Oy3ePkV25DxK1ZVxXRT7524v83NL7t7vCaqyUXlBiyiEGZ06HnAd1
         AR/6VSv0fQnGqK+MXGQPxURbHm8hrTr7BSsucm78mhF95XiQyTPzfxLLgT7rfT80thYD
         Ec+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4wtupvaEvwne0Vq+SODEHB1y4+FGimHGUXOjd7XL3Zo=;
        fh=MW9flRQYnEBBq29LgBauRChcaLuMgUGCt1Gz8M1zIek=;
        b=C0u0ItICNrbfiHJPNytF5b1PDrSiOWKkyNmjr5VAvztjjFpgqINgkzAx84XqazpGb9
         BreT3at8STRUM4HTA+/quOnqp98P36JCdaYwvtqQVCmBhSCgBCiNW0bW8MP8P4deHg5m
         gSNTQ9Ci+KCT7XKmTp7EgiMy9eQmA8ObGVVLdkwKSKltMafVcwE5NatfxWaLDqmW5gry
         eMa3Q1EQrR9+aEkO3FHHVSxuHsOTuDBvwSnKKwl9lX7D2uiJ9vsM07nnsE6t6OATlkvQ
         rkHnr35Vq42gpxngyXqS9PNJt76Q0MiVa0oMO7mov/dwnKJa0e1di4b13DIVgTLsGO2H
         QcDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nJVzA4wB;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59de490f1c6si218611e87.5.2026.01.26.10.35.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Jan 2026 10:35:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id ffacd0b85a97d-432755545fcso3568418f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 26 Jan 2026 10:35:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWcQbH6SakQi6VY6LfRhmJcBewc8yQfp6UCbLD3WUd/Fo3prcMMJSt3ze0pFQTH/Lgpl/oc0ZZZdvs=@googlegroups.com
X-Gm-Gg: AZuq6aJAxP/Xy5s5o58A8f8BDTVd8/GwltgHWrGiBBP/Quw7TYA5DZ+0U8pQn8Jbu0X
	YZVYrLpXWFv3m46xPVNMRu6B1r7tf+S8sQputoeAsK4J0yr+Kj1IXIo4hRFg3GCEnT+v/5aYxl/
	CDwXuXXrJ1U58keRMdt2RpUkdENDnGKIOc5Awbfj/8jBcUVyXV78U8rq6vEkj83zDRj6llDPioS
	3Vec22CqT1snfrt3rZ0lxoZxFKR2aDYmICW00t7A/9LzTN+mOsGwqpnFlzEX4RRVj+i0OSJDPug
	+78nTyglFcMMmfBuue9REYcUSpZfsiM7a4sYgn5IYHK4AyU+FWTCj69t/IQmybcTsxAwfV+6CrM
	X6lD/6MCzDL/66Zy+kEWQGQs6mSkKcxB0F7wXart823rr0QpAgXa6q/jYoXnCFGpnDxGEt1wurR
	jp9ASAdO0Rlb4ZcRVVoKpLvxxZ/iFxRObkooK9WI1qX0GBqPxQmmCbMWDt580=
X-Received: by 2002:a5d:5d06:0:b0:429:c14f:5f7d with SMTP id ffacd0b85a97d-435ca18f3cbmr9441304f8f.29.1769452542172;
        Mon, 26 Jan 2026 10:35:42 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:c598:7cce:ca6b:8ab7])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-435b1b6e2besm32040119f8f.0.2026.01.26.10.35.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 10:35:41 -0800 (PST)
Date: Mon, 26 Jan 2026 19:35:33 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Bart Van Assche <bvanassche@acm.org>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Christoph Hellwig <hch@lst.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v5 15/36] srcu: Support Clang's context analysis
Message-ID: <aXez9fSxdfu5-Boo@elver.google.com>
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-16-elver@google.com>
 <dd65bb7b-0dac-437a-a370-38efeb4737ba@acm.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dd65bb7b-0dac-437a-a370-38efeb4737ba@acm.org>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nJVzA4wB;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBAPI33FQMGQECEAPALA];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[infradead.org,gmail.com,kernel.org,davemloft.net,chrisli.org,google.com,arndb.de,lst.de,linuxfoundation.org,gondor.apana.org.au,nvidia.com,intel.com,lwn.net,joshtriplett.org,nttdata.co.jp,arm.com,efficios.com,goodmis.org,i-love.sakura.ne.jp,linutronix.de,suug.ch,redhat.com,googlegroups.com,vger.kernel.org,kvack.org,lists.linux.dev];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[elver@google.com];
	RCPT_COUNT_GT_50(0.00)[50];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-0.999];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,elver.google.com:mid]
X-Rspamd-Queue-Id: C3E188C206
X-Rspamd-Action: no action

On Mon, Jan 26, 2026 at 09:31AM -0800, Bart Van Assche wrote:
> On 12/19/25 7:40 AM, Marco Elver wrote:
> > +/*
> > + * No-op helper to denote that ssp must be held. Because SRCU-protected pointers
> > + * should still be marked with __rcu_guarded, and we do not want to mark them
> > + * with __guarded_by(ssp) as it would complicate annotations for writers, we
> > + * choose the following strategy: srcu_dereference_check() calls this helper
> > + * that checks that the passed ssp is held, and then fake-acquires 'RCU'.
> > + */
> > +static inline void __srcu_read_lock_must_hold(const struct srcu_struct *ssp) __must_hold_shared(ssp) { }
> >   /**
> >    * srcu_dereference_check - fetch SRCU-protected pointer for later dereferencing
> > @@ -223,9 +233,15 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
> >    * to 1.  The @c argument will normally be a logical expression containing
> >    * lockdep_is_held() calls.
> >    */
> > -#define srcu_dereference_check(p, ssp, c) \
> > -	__rcu_dereference_check((p), __UNIQUE_ID(rcu), \
> > -				(c) || srcu_read_lock_held(ssp), __rcu)
> > +#define srcu_dereference_check(p, ssp, c)					\
> > +({										\
> > +	__srcu_read_lock_must_hold(ssp);					\
> > +	__acquire_shared_ctx_lock(RCU);					\
> > +	__auto_type __v = __rcu_dereference_check((p), __UNIQUE_ID(rcu),	\
> > +				(c) || srcu_read_lock_held(ssp), __rcu);	\
> > +	__release_shared_ctx_lock(RCU);					\
> > +	__v;									\
> > +})
> 
> Hi Marco,
> 
> The above change is something I'm not happy about. The original
> implementation of the srcu_dereference_check() macro shows that it is
> sufficient to either hold an SRCU reader lock or the updater lock ('c').
> The addition of "__srcu_read_lock_must_hold()" will cause compilation to
> fail if the caller doesn't hold an SRCU reader lock. I'm concerned that
> this will either lead to adding __no_context_analysis to SRCU updater
> code that uses srcu_dereference_check() or to adding misleading
> __assume_ctx_lock(ssp) annotations in SRCU updater code.

Right, and it doesn't help 'c' is an arbitrary condition. But it's
fundamentally difficult to say "hold either this or that lock".

That being said, I don't think it's wrong to write e.g.:

	spin_lock(&updater_lock);
	__acquire_shared(ssp);
	...
	// writes happen through rcu_assign_pointer()
	// reads can happen through srcu_dereference_check()
	...
	__release_shared(ssp);
	spin_unlock(&updater_lock);

, given holding the updater lock implies reader access.

And given the analysis is opt-in (CONTEXT_ANALYSIS := y), I think
it's a manageable problem.

If you have a different idea how we can solve this, please let us know.

One final note, usage of srcu_dereference_check() is rare enough:

	arch/x86/kvm/hyperv.c:	irq_rt = srcu_dereference_check(kvm->irq_routing, &kvm->irq_srcu,
	arch/x86/kvm/x86.c:	kvm_free_msr_filter(srcu_dereference_check(kvm->arch.msr_filter, &kvm->srcu, 1));
	arch/x86/kvm/x86.c:	kfree(srcu_dereference_check(kvm->arch.pmu_event_filter, &kvm->srcu, 1));
	drivers/gpio/gpiolib.c:	label = srcu_dereference_check(desc->label, &desc->gdev->desc_srcu,
	drivers/hv/mshv_irq.c:	girq_tbl = srcu_dereference_check(partition->pt_girq_tbl,
	drivers/hwtracing/stm/core.c:	link = srcu_dereference_check(src->link, &stm_source_srcu, 1);
	drivers/infiniband/hw/hfi1/user_sdma.c:	pq = srcu_dereference_check(fd->pq, &fd->pq_srcu,
	fs/quota/dquot.c:			struct dquot *dquot = srcu_dereference_check(
	fs/quota/dquot.c:				struct dquot *dquot = srcu_dereference_check(
	fs/quota/dquot.c:		put[cnt] = srcu_dereference_check(dquots[cnt], &dquot_srcu,
	fs/quota/dquot.c:		transfer_from[cnt] = srcu_dereference_check(dquots[cnt],
	include/linux/kvm_host.h:	return srcu_dereference_check(kvm->memslots[as_id], &kvm->srcu,
	virt/kvm/irqchip.c:	irq_rt = srcu_dereference_check(kvm->irq_routing, &kvm->irq_srcu,

, that I think it's easy enough to annotate these places with the above
suggestions in case you're trying out global enablement.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXez9fSxdfu5-Boo%40elver.google.com.
