Return-Path: <kasan-dev+bncBDUNBGN3R4KRBF4IY7FQMGQEZE7WEOI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 1hXiFRnEcWnfLwAAu9opvQ
	(envelope-from <kasan-dev+bncBDUNBGN3R4KRBF4IY7FQMGQEZE7WEOI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 07:30:49 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id B95D2623E4
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 07:30:48 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4779ecc3cc8sf4455305e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 22:30:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769063448; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wcd2mIbaWwFBLZ1d+mgW6fL3lLE0k8LewapTVBuiFAAQM70puG66rgEfFNusu9GWlc
         nR+bBOGR0nC8SOiuv43oed5cNX9T8F431k8YvuNEkPWB05YWsl0VSpzxjTlw7/RvQVNg
         5Y8p0fCzv1CbpI+sxw6Z7DwriKqmrGFwkdR8wjCQUJ0ESzoeUXEcqQU2iVill0QlrW1Q
         17wkO1grEUqetQ/RJdK0tPg1IVLUBlgGc/om5dl6tLLBVAZK/RMsCIMNXMdfQNgMgKXV
         8qrhXoZWoA4x+UFPb4AcqhqFB67bCbFa9EF6d4MZV5rGYMUapD/Xc+burD2zZE1o0dff
         PnZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=EqmsfZjArO2bv91kmZv7CibtEZhRl2OCjtn+F/c2CKs=;
        fh=TsQQGYH2ckbUss0aDyntRNU9Jofocw4ttHzF7Iwm88s=;
        b=LiJGug2i0O1RnC9ihYGPZ+SiLFj1hs6VYjuCZAzu5f946HI+koD5RgIHjkFB+yoJ16
         HukgjpNmFfM4Fw+yryxu3wHgJJ09xVnaLeQsCfiPOzLgNkrwR0Jium56N5wawFEp7nHt
         DrD7WOrBHtdLO2PiuazO2NSN9Im2QywUlrMUCuaIufDpjzhHsnxmEXf99zO1E0c4RChq
         hD50B6mc55RyaywsHWaiWNSlhhktMbVGG2xwt2PgoZVZPGxERuHUJ/m9tsGFatYqZkNo
         CBdWbYhfxiwIUI2z92wQ6SPWQFFfrwnZWmirmNIwm/Skl49VuywgJQjyUECjAD5gwlLc
         wBjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769063448; x=1769668248; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EqmsfZjArO2bv91kmZv7CibtEZhRl2OCjtn+F/c2CKs=;
        b=qtvosLNIuw4+EnsdnbQeUWag6GfmfdAiu9j7mXMsw2hGB58Y37xls/I/8jboMRce2W
         aq/Huig3L+SNtT78Pl2SUsigresopprwEJsvlMZkT5Hr/oI9HNHLsJzvI3LjlI7rCs1u
         f0WU7pjMoCtEcC5X+2NCqaVxi1jZTxJW01uqndNLu50tmrf0V+fzoEA5zkaIY1x6AAH9
         P5TG9I/mSZ27x6uyMRyalkpWDkem0geczcsb2BLN6ZQ1ryTZY1FU5XUBUWCLG8GBxuug
         oYdjKRnsMT25o3N6eQHlnHrq6oLdgGiW3k2El85w1UrGHI7beZCTHgiFtqOKYQD02yrM
         KUKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769063448; x=1769668248;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=EqmsfZjArO2bv91kmZv7CibtEZhRl2OCjtn+F/c2CKs=;
        b=OakSiI31bJah6lApYxewZa3bJe27NHhAM9yWgPr3PlAoO4Ze0shOlawgCtvPLD+vzq
         i7he0WjigDrVV0wJr1qM1mo2Ck26r3RK0aHzVj2Jf+fafmhzx7bWCcJkx8RHYgUBCzFX
         zVX+7ou/Km21WZB4PgxSIOWDi2fTKFdP8LX77OQgPXBJ/NqgMJ/fuF8texi5GgvP1CgH
         BMmEEPnjUEJ/ofNtMLnloOG0ZEjWcFH2vltf9jp9Ckjas1/qi2LRaNnp7dBaTdKEB0fB
         3aQ5y478yPC5Ijr3w5ZNpZrNV5FBLX2byyBFJ5Sj8WH1hBt+nIwL1vYnD1ZeghlqVrv+
         Yypw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV8+8jc4dkfdiC803LPsA1nug5Aq5YZAZ4QJlHqfvHjKvX9R3mmiN4yTPY7Q/G6Z+ItpUhQag==@lfdr.de
X-Gm-Message-State: AOJu0YyZkBpwf27Np/khzKRWb0l5GpW3OnI8fZsNmgSmUu7Zw/Cz93a0
	CMjuyXDukpRuimm7u7RhkOTEdDYut/TMXQnYHX7JJK0DM9Ob/ukDOr4y
X-Received: by 2002:a05:600c:868f:b0:477:9fcf:3fe3 with SMTP id 5b1f17b1804b1-4803e9fd887mr75247815e9.0.1769063447862;
        Wed, 21 Jan 2026 22:30:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HYYjY5zWtrdIdUGQzXjim6/zuA1QfqcLSex+jT0Te8qg=="
Received: by 2002:a05:600c:190b:b0:47e:c74a:d830 with SMTP id
 5b1f17b1804b1-48046fdeaadls3330395e9.2.-pod-prod-07-eu; Wed, 21 Jan 2026
 22:30:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWUB7OPQFhc0FBREKdBoC6DCfzaGNWwbOpL7Uz3pebxi+Arlhd2KsBVLJ+wmiwdRogUUM5cFLyuoso=@googlegroups.com
X-Received: by 2002:a05:600c:4ecd:b0:477:6e02:54a5 with SMTP id 5b1f17b1804b1-4803e7e7c57mr109690805e9.18.1769063445256;
        Wed, 21 Jan 2026 22:30:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769063445; cv=none;
        d=google.com; s=arc-20240605;
        b=K+xJp1Yz6/3zR8gOJiRppvUnchDt6uHpYZ4kbrDNvlECSMb3UKbqVPVZM63jG745BS
         4VfI01wGQvnjsCT+/6REtacx28JPgFlagwnOf6T9od+dow3Gtq1Vt4TTFXdV5k0QLVvo
         tOSFzgNgfDK4pPP+nfDQTWgB8eCZTKel5zIkO5JUQwD0GH7r+keSezL5yejUmUlUtv1T
         9VMB07C1EnkB48yaIkweOoI9K5yV26IK/hDslknNE6gnlqWt9cYtynWE9krZ2/17LA8b
         7KU04KFKgepyVkQ5P8cg2Pw+HZFytYQPmY+5tUbJ/a94G+GXl0QRmnrgeqnTvIXtYHsp
         1wHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=BbRr7SK5UNpunUvbXrXx3JIOpPMVDzcAyA1Qj6gzdNM=;
        fh=j+3rwCz9TPCZzXqv1QQRFqgCfpmG7p8SMFtKeExQ/4s=;
        b=apPJMcMxcafQo1fu3mfU02XhPV3jtWFU4f1FxXJhaDx5pk8rU0CYurH4Fawr295HO0
         ZRbuDI4e6IFs44TSkyZECA3mL5cPGW5n77dnfujK9djyfYKx2/T7Pxd+sJHIW5BM8oHK
         wbV81ro+Hh9RL9U9Pp+ly3zbvhqhQvROuWPPy9zI2eM5ew0UxxFFeVZrKlROleawOE1O
         J6rYg4Au0xmrhyUmiLdWjgzyZhFQjTPoS/CmDsXi+n5chVLxGeA9X8AE40/BrZCrfOMq
         acPhPcgxhIl4pJEV0jf4mRf2eQLcanJEkW7cyUXxFhbmtd6rEjG0NhyBGbTpQXPIPdWy
         4NgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-48042b6e068si446445e9.1.2026.01.21.22.30.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jan 2026 22:30:45 -0800 (PST)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id F0E59227AA8; Thu, 22 Jan 2026 07:30:42 +0100 (CET)
Date: Thu, 22 Jan 2026 07:30:42 +0100
From: Christoph Hellwig <hch@lst.de>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>, Waiman Long <longman@redhat.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Bart Van Assche <bvanassche@acm.org>, kasan-dev@googlegroups.com,
	llvm@lists.linux.dev, linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-security-module@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH tip/locking/core 0/6] compiler-context-analysis: Scoped
 init guards
Message-ID: <20260122063042.GA24452@lst.de>
References: <20260119094029.1344361-1-elver@google.com> <20260120072401.GA5905@lst.de> <20260120105211.GW830755@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260120105211.GW830755@noisy.programming.kicks-ass.net>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted
 sender) smtp.mailfrom=hch@lst.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
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
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	DMARC_POLICY_SOFTFAIL(0.10)[lst.de : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[4];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	TAGGED_FROM(0.00)[bncBDUNBGN3R4KRBF4IY7FQMGQEZE7WEOI];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[hch@lst.de,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[lst.de,google.com,kernel.org,linutronix.de,gmail.com,redhat.com,goodmis.org,acm.org,googlegroups.com,lists.linux.dev,vger.kernel.org];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,lst.de:mid]
X-Rspamd-Queue-Id: B95D2623E4
X-Rspamd-Action: no action

On Tue, Jan 20, 2026 at 11:52:11AM +0100, Peter Zijlstra wrote:
> > So I think the first step is to avoid implying the safety of guarded
> > member access by initialing the lock.  We then need to think how to
> > express they are save, which would probably require explicit annotation
> > unless we can come up with a scheme that makes these accesses fine
> > before the mutex_init in a magic way.
> 
> But that is exactly what these patches do!
> 
> Note that the current state of things (tip/locking/core,next) is that
> mutex_init() is 'special'. And I agree with you that that is quite
> horrible.
> 
> Now, these patches, specifically patch 6, removes this implied
> horribleness.
> 
> The alternative is an explicit annotation -- as you suggest.
> 
> 
> So given something like:
> 
> struct my_obj {
> 	struct mutex	mutex;
> 	int		data __guarded_by(&mutex);
> 	...
> };
> 
> 
> tip/locking/core,next:
> 
> init_my_obj(struct my_obj *obj)
> {
> 	mutex_init(&obj->mutex); // implies obj->mutex is taken until end of function
> 	obj->data = FOO;	 // OK, because &obj->mutex 'held'
> 	...
> }
> 
> And per these patches that will no longer be true. So if you apply just
> patch 6, which removes this implied behaviour, you get a compile fail.
> Not good!
> 
> So patches 1-5 introduces alternatives.
> 
> So your preferred solution:
> 
> hch_my_obj(struct my_obj *obj)
> {
> 	mutex_init(&obj->mutex);
> 	mutex_lock(&obj->mutex); // actually acquires lock
> 	obj->data = FOO;
> 	...
> }
> 
> is perfectly fine and will work. But not everybody wants this. For the
> people that only need to init the data fields and don't care about the
> lock state we get:
> 
> init_my_obj(struct my_obj *obj)
> {
> 	guard(mutex_init)(&obj->mutex); // initializes mutex and considers lock
> 					// held until end of function
> 	obj->data = FOO;
> 	...
> }

And this is just as bad as the original version, except it is now
even more obfuscated.

> And for the people that *reaaaaaly* hate guards, it is possible to write
> something like:
> 
> ugly_my_obj(struct my_obj *obj)
> {
> 	mutex_init(&obj->mutex);
> 	__acquire_ctx_lock(&obj->mutex);
> 	obj->data = FOO;
> 	...
> 	__release_ctx_lock(&obj->mutex);
> 
> 	mutex_lock(&obj->lock);
> 	...

That's better.  What would be even better for everyone would be:

	mutex_prepare(&obj->mutex); /* acquire, but with a nice name */
	obj->data = FOO;
	mutex_init_prepared(&obj->mutex); /* release, barrier, actual init */

	mutex_lock(&obj->mutex); /* IFF needed only */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260122063042.GA24452%40lst.de.
