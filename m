Return-Path: <kasan-dev+bncBCS4VDMYRUNBBZ4TWO4QMGQENO3RLTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 31EB19C086C
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 15:08:41 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2e3ce03a701sf992681a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 06:08:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730988519; cv=pass;
        d=google.com; s=arc-20240605;
        b=IbptT3cKaFnMkO6qlVDflpTNDNKYwOwqQxfTqWerD7GN43WjW3XjnmZ+JqHZkMjGl5
         R/VA+XI89Vb5VT5m5B7qkQ+c6Im939bJ0o0ThNvZx+9ggeQRN+H9Lvun/EmN5RXL16vw
         yKHTYQHeHNKaAagFV6eGXUQSqWFnXQ6dWTHgiT17873fGdbm9deyZfugNSgywMBNFhYs
         Qu0To1VWttthH/LQpRQuo49AQOJWaYPxJCK/dMtZHJR3I6scWtiX5XiokBl9ocN38oIe
         jfsXNAFoPi/RkphGeOodFqV81BeOKDmLx5f42IcnH5d2cGQganHuLzVH/Eufw+1to5tI
         U65A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=JxRa3MFLQnSUc21ytmK6rPns8RiZad4f75n1BJdjoSQ=;
        fh=6x1tUeL4mrCiwNxHiAzl3WKd+nDHvZIw2h0v1h19Pgg=;
        b=VuJ6IxMnEm+OlKakzoSUNQSADXritEXYilEe6OuRl1ZJuA1KLD+lwBjNCpxuF4Qa6J
         JKDsPIEVLl6Itc3HTPhdGXZU/pQgoRTwrvOWrL5MgMstra9iPIy0RF9OD4PA221ImaoA
         qO/jkrPrq98OTApKyHjsAbW8aQxaMgEZ7HxyBgsrBzoJ2IJVOtV2Mq3TIUwAv/FpqgcQ
         KA/756/ieP0yxctsXm5rCQSh8wULVGZ876uQ5QvYYiFyBfONrKivOkffUn06z0jxceQ4
         aJccpFk2UyWszHXOEe9hjqBP4rwAPXWiiXJmU9e4ZeOGZtEe57Se7n3TPquYlpGoRM6I
         h02Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RhyGov7b;
       spf=pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730988519; x=1731593319; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=JxRa3MFLQnSUc21ytmK6rPns8RiZad4f75n1BJdjoSQ=;
        b=oc8XUiHy8oZOLrDdi5n3vMa00icnViWje7yqI1BtazqDv3vz5522D2jYg7x50DSddE
         3c+CP7DK88SfIb3sTUrJFts57y6NBbh0fIYrKGwOc8f/sdonxJj49QfPwczk+dpoOR8g
         bfwe2vaygKS2IgWeyEzMGiVT7udBbughoUmBcPLAS2kkKMz9y+fyLGYS4GUSi197Rsv5
         9XUkHedcbbK2RZPgJ7ZAPNv66w8UpmWa+Yd4yHy++S24bluEUakPEgoLjuyHCA7ggcmv
         3+DIaaReiotEsEVIZiWT2WQz0M2Rc2b5siyClI79y7Ue+LIEs1DexpKnuIYzkECSNm/j
         xvhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730988519; x=1731593319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=JxRa3MFLQnSUc21ytmK6rPns8RiZad4f75n1BJdjoSQ=;
        b=RtD0jsWTyAQ8a7Muq4RLwleFY0qjG5rlFzMaC39dh13tc92NxzexECGtel1Ay2nu3n
         5ZnZuI9NXDcnfdtwC1J6SiQYu9m1KoSNHH8n8oKEn816z4pm3WxZGKKJYZ8zLbkke6Wx
         gmcMRICD3M8d71nJ8RQOx9ep5rWIiGGsQS4NCqhVeCx54Dt+5Wwdn77LKlc+KOJ1vF0d
         zMe0UBbu4SX/hfzlGi9XLt8fCZ1qKaBCqYtU2H4iYRvSDUn07ZieAccq1XO+HLM/hB0u
         dIAm+iChsDn7D/yrG9Bk9gFb/dzJmt+ceQLZKal0+2Hon/8iMFmBLfmCWDQ6Mb4djDOI
         9Dvg==
X-Forwarded-Encrypted: i=2; AJvYcCWaZt/aYIjBzbPzRnbvt1ysvuLbAF+2Xua6JKMfBnFtcWwQjbdd66hi++Ig6mVwEomkGJZc7A==@lfdr.de
X-Gm-Message-State: AOJu0Yzt6YGEnji9STQMWOkeGdOv9dCpZo53C9oalxaIK/eoCzirMjYk
	UfyXSWdfGvacuS9HCGb/F9JrxTZ+tG3Zb9aBtZodzgF90X8118OE
X-Google-Smtp-Source: AGHT+IFbV+zXMn/AbNDr5ogyfZ4Dlgem+bXsMhvZb9UGMUcQvQTsQb8568mCAwn6wX+W9SBQOyiYeQ==
X-Received: by 2002:a17:90b:4a86:b0:2e1:ce7b:6069 with SMTP id 98e67ed59e1d1-2e94c529acamr34237283a91.33.1730988519389;
        Thu, 07 Nov 2024 06:08:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c:b0:2e1:9254:6f09 with SMTP id 98e67ed59e1d1-2e9a3e86a4bls866814a91.0.-pod-prod-04-us;
 Thu, 07 Nov 2024 06:08:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX2/vd1ialLXOzMHkFQlVBTMmKb3pcecbqdMpdE7XoEtgS9kNtNvtORGN55xbBgpTZnJJd7r7pDywc=@googlegroups.com
X-Received: by 2002:a17:90b:2703:b0:2d3:c9bb:9cd7 with SMTP id 98e67ed59e1d1-2e94c52aa1amr32069784a91.36.1730988517513;
        Thu, 07 Nov 2024 06:08:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730988517; cv=none;
        d=google.com; s=arc-20240605;
        b=fy6Ez5Ps6pL9WcPmsjBDdosMEwQEtWroCjDT9IYgWm8326z2HSD3xSsfB7MvWA5aX7
         LkQN7VtpvS5HPLzKIBi01OfYMTgP0xb0s8UsJ4P8FdyhJyXf1BXOY0fw4LtEvz5PMayL
         KMxz6OcY63tYxlLJVH5LTWINxAdAUQfhxTewrL+bAeC6My8NKGmE8zq8g/Ot0idna1iN
         3mOAZznpqBqDNj++YunMYws0FFm/zNl/ikKtjlJPswDGSW5wdLaGG1AOoUulD9YT2FGP
         HQmfwSdTATbexyVjxq37ZgEIxDyIfgkPw71ZriijXJMStHQRqRdvRlmxENdnXmg1zZxC
         R0QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Cj8RDYLbZsrfyPZWmzm6Taqb923JbKZUOst/9XRPvr4=;
        fh=gOeqIDRGq3LmMrDEvoXOvAyaoj8gr6AJrF8eTSaK0ck=;
        b=eag06Lt8OGFZI3HtzsqMpHjuYEB1u/eFXJ/XHPxdDjyT6o09JpijZYb5aTbNR808A8
         EVzRDum8aRAnGmwzrob254zEyZ0y5dEFDMVVstWwOORxyhPlHqoFd/32ttZOj0FoYdaB
         wbwRjFVcgnXFHq/BDDgMkaBF7hNQSCKkc9PnoiAokcf03HAnnwF/I7mPSO1W8IubRYmU
         5ycgTeHhhWv54se7zWfodYybNsBSP4KN0uJ56oZChc5gVlrYWYf5KJZoub51t+gjf0Bc
         9hCDdUbUheDcOHjHtfqy8014RaMWKwg2X0NeMMuoYjo+CGQ3ibJmBJuLyi2kT3N4EM6K
         378A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RhyGov7b;
       spf=pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e98af3347fsi467553a91.0.2024.11.07.06.08.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 06:08:37 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id A2499A4442B;
	Thu,  7 Nov 2024 14:06:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AFF6CC4CECD;
	Thu,  7 Nov 2024 14:08:35 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 17B8ECE09F6; Thu,  7 Nov 2024 06:08:35 -0800 (PST)
Date: Thu, 7 Nov 2024 06:08:35 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Boqun Feng <boqun.feng@gmail.com>, Vlastimil Babka <vbabka@suse.cz>,
	Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	sfr@canb.auug.org.au, longman@redhat.com, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org, Tomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH 2/2] scftorture: Use a lock-less list to free memory.
Message-ID: <45725c86-d07f-4422-a6fd-c9f02744ac75@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <88694240-1eea-4f4c-bb7b-80de25f252e7@paulmck-laptop>
 <20241104105053.2182833-1-bigeasy@linutronix.de>
 <20241104105053.2182833-2-bigeasy@linutronix.de>
 <ZyluI0A-LSvvbBb9@boqun-archlinux>
 <20241107112107.3rO2RTzX@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20241107112107.3rO2RTzX@linutronix.de>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RhyGov7b;       spf=pass
 (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 147.75.193.91 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, Nov 07, 2024 at 12:21:07PM +0100, Sebastian Andrzej Siewior wrote:
> On 2024-11-04 17:00:19 [-0800], Boqun Feng wrote:
> > Hi Sebastian,
> Hi Boqun,
>=20
> =E2=80=A6
> > I think this needs to be:
> >=20
> > 		scf_cleanup_free_list(cpu);
> >=20
> > or
> >=20
> > 		scf_cleanup_free_list(curcpu);
> >=20
> > because scfp->cpu is actually the thread number, and I got a NULL
> > dereference:
> >=20
> > [   14.219225] BUG: unable to handle page fault for address: ffffffffb2=
ff7210
>=20
> Right. Replaced with cpu.
> =E2=80=A6
> >=20
> > Another thing is, how do we guarantee that we don't exit the loop
> > eariler (i.e. while there are still callbacks on the list)? After the
> > following scftorture_invoke_one(), there could an IPI pending somewhere=
,
> > and we may exit this loop if torture_must_stop() is true. And that IPI
> > might add its scf_check to the list but no scf_cleanup_free_list() is
> > going to handle that, right?
>=20
> Okay. Assuming that IPIs are done by the time scf_torture_cleanup is
> invoked, I added scf_cleanup_free_list() for all CPUs there.

This statement in scf_torture_cleanup() is supposed to wait for all
outstanding IPIs:

	smp_call_function(scf_cleanup_handler, NULL, 0);

And the scf_cleanup_handler() function is as follows:

	static void scf_cleanup_handler(void *unused)
	{
	}

Does that work, or am I yet again being overly naive?

> Reposted at
> 	https://lore.kernel.org/20241107111821.3417762-1-bigeasy@linutronix.de

Thank you!

I will do some testing on this later today.

							Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
5725c86-d07f-4422-a6fd-c9f02744ac75%40paulmck-laptop.
