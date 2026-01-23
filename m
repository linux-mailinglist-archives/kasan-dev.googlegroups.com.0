Return-Path: <kasan-dev+bncBDBK55H2UQKRBXHJZTFQMGQEUP5QRVY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id UIZGON40c2lItAAAu9opvQ
	(envelope-from <kasan-dev+bncBDBK55H2UQKRBXHJZTFQMGQEUP5QRVY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 09:44:14 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B26E72AB2
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 09:44:14 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-382f31b01basf8107421fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 00:44:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769157854; cv=pass;
        d=google.com; s=arc-20240605;
        b=ieWdK0N+GJZqo22lOXNpDdRi57JVQOCJXURH6y5VtaEQGyVPv+w/AswQ5VQVu/YUm2
         e/MJvUglyOMVIfHLkBxnfQvuBEw1zP3F1T+d564xqfN4EqdRGR7NWONgHlvh4o/+Jyc/
         veIgsZEMVxmYs+cKWvEtG9mh0Kj9usWFjjDhuPtuoYkIXWnfBQ4YsOfMeqaKW+MkBrmO
         YpVtVnmsYz7mKoBRLR0OlJJWc58JyLwnkFE7U6diGwV2GSkwNFptoWeSpFGawlOaNN97
         Qt0+ztc16uFF+iGQm7qpPKgPK/mnV6vkss9vzc0a3NcQAinbnx7HDbpalQIi9xn2egbl
         WkHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mOrtNS0lXJtVN1aeVIFm3efTpz+TPER8RDgqTvBDWBs=;
        fh=KGHzrKo2exb/wLTmcylj7EZv1G84siDLDqWpIA01j1I=;
        b=cPomAtR4LLLSFCV+R/zDd1doKlUMJm+FQjlxbv1SutmtUAiUO32PuhttukFUsb4Qyh
         5q30UoggRxx4/zA8HXC13m7h6wrELjJrIKL10QKL4yobkjdhe4v/uEMmx6MDMXqY0aBw
         iN6fnsVkVCcti7vS45O41vvQZSXSuiXKS7YL9ZKHlx88ekFlzHevvyTE99lS69z994HA
         Z793ax1AF6WmUzUr7W2+WZrtnHE6gS50OduyCOSlaHQe6hegjTjrMBCqa4YX0wKwdPWi
         w0oi94G/81WS3vDJE3jPxnpHdj3Boq1sk92R0JX8329cYvvFjPpm0Cutn01jXsCkp9Ox
         1j0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=SaLiAaAs;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769157854; x=1769762654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mOrtNS0lXJtVN1aeVIFm3efTpz+TPER8RDgqTvBDWBs=;
        b=foJ4Lq1VYvBCWkYOOi8iHpa4pAtfZar8LCZWiN1HY/NsLRmgruVnWTeUieIrOBAF2Y
         LbGkR4JELXolh4dj97qbrvGYIYCQrTRDPeIjdOk8sI6vH+W09hUwiz3/xntDki1b3mDS
         m2ZXKTxNEf4t6VdKIV3z7cS8XevApb4JPXFZYslN85xodrUyT6tnhRWamAUbGf97nGA6
         +qEjlmONImrQ+GK9iwx+G7H5zZURqAo/sEFQWipOlhPQtYr/U7/0WVk9WO+7ktqy11HZ
         IuaJ6BrTDXq8hTQ9l6WXowxBiMrpqKr56R8nr2isR70IJo0APo4MmrjVVGBwA8lmToe0
         XW4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769157854; x=1769762654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mOrtNS0lXJtVN1aeVIFm3efTpz+TPER8RDgqTvBDWBs=;
        b=MuOAzjFABdspgg0iVvbLcyXlrhsY9Wg09jTJj6RcSN2eK+ctI6SdVOuq5AKLhCJ6QA
         jpRSg2JjevFCr56551/XT2XAY11rOgBoErEbj17ITGD/WAFjvuRsF2iEyGk2fSNeciQQ
         wxacwAMqfeJaRdnPUC1fk6new+obPi+742mSq0aF/WOzNy/GH9HBzjBywQxIw5fgBYKt
         PXDGCKg7N91ahUtxR4upVsxHPu6Xt8uYH5uH94ksU0V2PhJtXWhWtARSKH62g0oKe7qP
         cJCkOImx1jds0eMl9rSAFOJRAoP6RqQkmMj1AODY2/rkBdSmnd2QTuAxI/0K4aY5VLn0
         ApsQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWUepzYxImBNfBqhi7stTfBy5z4nVLj5Y9himKmQRxnFYQtTEC7eLv3CNkfCEwsi5t0iZhjNQ==@lfdr.de
X-Gm-Message-State: AOJu0YxaSS+knQG5VIjt9WVmsuP7DTott8vQis6CYA+yYEZg2uuqVLwQ
	yk8SbuGG9sr2wyfokI0o25GzDfh3Q1ZayDgB5zrMfmD/CoetgkOtV4i2
X-Received: by 2002:a2e:bc27:0:b0:383:16e7:9af with SMTP id 38308e7fff4ca-385d9eabd7emr7711971fa.14.1769157853499;
        Fri, 23 Jan 2026 00:44:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HLrR+u4+oCSkS1ck91OmlBed50ErZDEBNVwzujZ5EesA=="
Received: by 2002:a2e:91cd:0:b0:385:bb77:50cf with SMTP id 38308e7fff4ca-385c26ed77als6568491fa.2.-pod-prod-08-eu;
 Fri, 23 Jan 2026 00:44:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUzk3sdQnS8kxmmcsUY91KMayRUtjyv5VzPNkGI24YsATZiJTHhpHhT0ychRB4fxYG5ikDMMsyZnpQ=@googlegroups.com
X-Received: by 2002:a05:6512:2213:b0:59b:6853:f098 with SMTP id 2adb3069b0e04-59de490bf4emr735958e87.21.1769157850352;
        Fri, 23 Jan 2026 00:44:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769157850; cv=none;
        d=google.com; s=arc-20240605;
        b=IMhMKA5esyfbPp7VJOIR9e6HH3WoguiC1itEMS04kELS4o2z8akWYyJvO0lq00gpea
         UhFOUdTTB4xX0vDzoB+8Y19q160kmgMCaunn4SzKwB8zYs3RcJuEsnRTQTtC1Fa85fUC
         YJOpyEwp8qICO6HQTu2yigWi5RjblRZigoH6Q1yfUhMj91ksM71esB2vCe0Ql0WQWnTo
         onjkW92Ogv6UDcE+iOqxm1x1dQ/BLiyY7yJBoA8e904pl+owbfVDwP/ZBDC/HORobm0T
         QADg+T2FivUcokrdsrNoqwct0FLVFzYCrMdJgi5oIsj0DFkFeerMjej/CbZ0nE/+W3g+
         uNLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=GqAez6IU6i4XAwM/6EtVwplPYXTstdRVXB7SnmbYRlw=;
        fh=TUwS09QozRkuUhiwzF+zJ8cD+MuvSG0Qtmm2GF8pnTA=;
        b=cbU1d6qqbOEwxm+ym2N8XKQdDQX0WkUmtFKzrMwXMb7Xy2d5ReBzhDS2AWSOAlyFiZ
         Vb1jgSk4gi0gGQ5A9UjFbDiTKEZW8pUEFHPVNlveSarMVVG8q9okY9mzNLYifHpXwEp/
         bvR6S6Q0khfJ0CpjAlN/dfDVgrNvdCTu9HV6EGy8W16eyfXzxYIEwXbiN5f8OLsW9KLg
         qVVkpwwAnRHD3NnknBKGjfXB9L2Rleed4oa/Cw5pQKpMq7dvPhLiu2w1eCea0VZTroRY
         WiwIkdULCaSTO+NTOqJr0t9S7tuR4CI2sIHfQaMt3nCQbmUpIZMirsBB2R7PIbc5ee6L
         8Reg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=SaLiAaAs;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59de4913696si46119e87.7.2026.01.23.00.44.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Jan 2026 00:44:10 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vjCly-00000001xAQ-0DnN;
	Fri, 23 Jan 2026 08:44:06 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id A0187303018; Fri, 23 Jan 2026 09:44:04 +0100 (CET)
Date: Fri, 23 Jan 2026 09:44:04 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Christoph Hellwig <hch@lst.de>
Cc: Marco Elver <elver@google.com>, Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>, Waiman Long <longman@redhat.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Bart Van Assche <bvanassche@acm.org>, kasan-dev@googlegroups.com,
	llvm@lists.linux.dev, linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-security-module@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH tip/locking/core 0/6] compiler-context-analysis: Scoped
 init guards
Message-ID: <20260123084404.GF171111@noisy.programming.kicks-ass.net>
References: <20260119094029.1344361-1-elver@google.com>
 <20260120072401.GA5905@lst.de>
 <20260120105211.GW830755@noisy.programming.kicks-ass.net>
 <20260122063042.GA24452@lst.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260122063042.GA24452@lst.de>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=SaLiAaAs;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[infradead.org : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDBK55H2UQKRBXHJZTFQMGQEUP5QRVY];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[15];
	FREEMAIL_CC(0.00)[google.com,kernel.org,linutronix.de,gmail.com,redhat.com,goodmis.org,acm.org,googlegroups.com,lists.linux.dev,vger.kernel.org];
	MISSING_XM_UA(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.941];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[peterz@infradead.org,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-lj1-x23e.google.com:helo,mail-lj1-x23e.google.com:rdns]
X-Rspamd-Queue-Id: 8B26E72AB2
X-Rspamd-Action: no action

On Thu, Jan 22, 2026 at 07:30:42AM +0100, Christoph Hellwig wrote:

> That's better.  What would be even better for everyone would be:
> 
> 	mutex_prepare(&obj->mutex); /* acquire, but with a nice name */
> 	obj->data = FOO;
> 	mutex_init_prepared(&obj->mutex); /* release, barrier, actual init */
> 
> 	mutex_lock(&obj->mutex); /* IFF needed only */
> 

This is cannot work. There is no such thing is a release-barrier.
Furthermore, store-release, load-acquire needs an address dependency to
work.

When publishing an object, which is what we're talking about, we have
two common patterns:

 1) a locked data-structure

 2) RCU


The way 1) works is:

	Publish				Use

	lock(&structure_lock);
	insert(&structure, obj);
	unlock(&structure_lock);

					lock(&structure_lock)
					obj = find(&structure, key);
					...
					unlock(&structure_lock);

And here the Publish-unlock is a release which pairs with the Use-lock's
acquire and guarantees that Use sees both 'structure' in a coherent
state and obj as it was at the time of insertion. IOW we have
release-acquire through the &structure_lock pointer.

The way 2) works is:

	Publish				Use

	lock(&structure_lock);
	insert(&structure, obj)
	   rcu_assign_pointer(ptr, obj);
	unlock(&structure_lock);
	  	
					rcu_read_lock();
					obj = find_rcu(&structure, key);
					...
					rcu_read_unlock();


And here rcu_assign_pointer() is a store-release that pairs with an
rcu_dereference() inside find_rcu() on the same pointer.

There is no alternative way to order things, there must be a
release-acquire through a common address.

In both cases it is imperative the obj is fully (or full enough)
initialized before publication, because the consumer is only guaranteed
to see the state of the object it was in at publish time.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123084404.GF171111%40noisy.programming.kicks-ass.net.
