Return-Path: <kasan-dev+bncBCT4XGV33UIBB3H6X3FQMGQEB5ENPJA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id mOz6Am+/b2kOMQAAu9opvQ
	(envelope-from <kasan-dev+bncBCT4XGV33UIBB3H6X3FQMGQEB5ENPJA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:46:23 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F5A148CCD
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:46:22 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-4043a9496basf11733523fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 09:46:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768931181; cv=pass;
        d=google.com; s=arc-20240605;
        b=VtjLdTHSCZN087MKvfooz89KePssTszn5bDEozK6v4LDoXJFXhVO6SVxv9q0biHguo
         0UTj5Tg1RNG+IEdPyAM0JJmU4sx2fUzqGNthsAUmAarUeQJ1ps10UTeoR3wmbW67AUHZ
         r09YB97sFAS3EfGsNGnqpjXJ9xx2GERtZtRlMEyCO/ktMMybFd+GVf7yzHNR2lccYsYh
         0G5WaJeM9mtilgJb4c36rdt5RZmr+zkFJYaELqxyHHVoe2EY/hXcAcHLsA+p6C+66WEW
         5PPfdcDWWxkJwyQ0CqAe8D/ErD8ohk1JnMsQs9GtloGSlqzBEI9ILms2OLbCAVjhZcet
         JYZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=wyN5OI5K2XAaH+BvMwvA8YVb/9Q537SPA4Np/P+Ny4A=;
        fh=sxwNzwpEGIyO7bgKDhHOU4KxM4KjzpSgkhjfZ7puDds=;
        b=DoDLHkMeNvXEbVT2tMgtVYeVQlMfxxDek88iapLQN5GE9ETYfbG4kkz6lO3ZnF5I+U
         hmUfCKtFk55+9ZAMJn0EPYlI6xr9G4L/3VRDyZDPxi7R3TLuyDzC6PR8o594/G21Ti84
         pUMN3j2xdLs5LOD2qKN4NsSa+Jl8+e27xqjhF95VTVkQ+DrHljStMwLD2KitoDBD60bk
         mCmFXXlm9uiFvRdx7ArglQE6GyYYSksxD6jc1qCtF1pT1jbHqMg7/f9HdVECjacriTLK
         vmOebhoKLP4POPfUVORu8ZDznclwplMbvtVp5I+TvC5wk/nPjXU19p18nMtRH8gbwzbx
         LT8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=uB7J5VIU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768931181; x=1769535981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wyN5OI5K2XAaH+BvMwvA8YVb/9Q537SPA4Np/P+Ny4A=;
        b=RWQ3JmlqZ0UPY2JBl7/Oxn2y6b0p/9twynoEUjUl5/9G3F7iZPQYefKYYSPW9rTEJz
         mmtxg8v/I/wGsWFfbhkYoaZIftiKl/TC1HJvuH+uHAAYm4wIUmcnRnxwKh4fz5sb4PGc
         odE8djXcmpWs8loEEGPR5ObB8yTtmMc8p5q8jXnRvJtlOpL1aqzR30P/oe/eW0RwjS2E
         qvGvhlQq985Mdf9TLZjLVrSScP8biLWfYOtpNslwr6W//I6DQmdsaVTEvyTgH33Kfjg0
         FOwI9A7SbWDHGVYJepFeNv+zDZ5UarLhGXBipCkuqOCQ4WcmwPCY8u2/G7+ByOIhqbiC
         XpDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768931181; x=1769535981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wyN5OI5K2XAaH+BvMwvA8YVb/9Q537SPA4Np/P+Ny4A=;
        b=VJvmc+Eo49Ury/ydZ9MMfLUlscDpVkWqg7aq5xiTzXAcIGDs8kx6ZhRelHJgq+fg+J
         0EhEbZ7LsmyfSqi0tGyZJb4P9O9Jk3GPLxf48NRn8xvheZrY4j1n8ajhfgswDtxn1vWf
         ObhkxfiHbxdrBy8Wk9QNxMN6AUzJuDbZeXV5ITVuT34w477HWB7cMD86EFIJ/HVKtFQ5
         7KYatFhdAhAhHGout3LHVS3kPMP/+HM7y8zN59a7+1R+ExM/Q0TfKN1SOPiQc9rLy/rU
         ioaqI84eu5W9vJNa9TYQgkFbsZ8g0uyx2bx1qFSn4EPWG3v9B4Q/X8Nvjpp8Ch6LRtcl
         EE2A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXusLPcZSNUY0eevpWZv+3hVdanHWW3NZtKZSxWYGDe7uB0Hi9509yKOuY17UL8L8vpGAQy2g==@lfdr.de
X-Gm-Message-State: AOJu0Ywim51sd/kNbAhilrqAIqaBJ16YavGDKq9OmWv3MOaM/msJQs1C
	A50NWoRynlH1PB65N8qzi2eko28uhFMZ9IxgV1jCw1iyuKdevsjd12fU
X-Received: by 2002:a05:6870:224b:b0:3d2:7800:cc15 with SMTP id 586e51a60fabf-40846c5cfa9mr1239525fac.26.1768931180672;
        Tue, 20 Jan 2026 09:46:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FOfMceOyFuFakuOWEWx4Z8TerTXJXwbNAq8XfXHv0ftA=="
Received: by 2002:a05:6871:6803:b0:3ff:ac5f:8bfc with SMTP id
 586e51a60fabf-40428a3f345ls2303106fac.1.-pod-prod-09-us; Tue, 20 Jan 2026
 09:46:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWKNYQHOHLI6ZvIAn2skO+firnF5IC6Fg5X5hzvMMYmVatLJHrG0GdrY1OH/Aylz2hCf9XVH28ZQAI=@googlegroups.com
X-Received: by 2002:a05:6808:3088:b0:44f:8bff:436e with SMTP id 5614622812f47-45e8a8f79c3mr1282565b6e.12.1768931179533;
        Tue, 20 Jan 2026 09:46:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768931179; cv=none;
        d=google.com; s=arc-20240605;
        b=b+BBIqCwydkNamV4EugILAInyndM10sS9dK4tb/vtkoqvrh0UDA4eSKAyXpZ8mH8gY
         QDEJkHZBDK8Qt3uPwDsNnqVTgBTMjEx8J9hi2SEP1sg8SZfytTWxH9WUEgvo/iSzpdX0
         BAfZSoAyBTVAwA0oK24+qUM68kJwwAqf9hIE8Iplly2FEWrs+KjPoo8XXm9Jyk6EKI3D
         DONyjIBVXjR4/4+0sqicoBCeZ7tWDTAV55swjnIlANykeFm7A1TFLEW/D1snmOZG8wor
         86h5GjBifrUz9tbMB2gTW0BAn5MGS+Vp0aPYt/1V1U6uRmYegPMfM04D8Udjk4J5YrEU
         XcMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=RkdL6exjZRisK29PWXrwZU8OGWsXzYf9OGkm2KvZw8g=;
        fh=moB7Ut4dWQeRoNtFN13tw2BfBrzoeGXTJQHrcz6rpAA=;
        b=M9TSj+yVFK1f0VEqgwDKAWUUKii8CrhbsCefaEnfHCj/HXQjWQxy1rWrcGvNuop+dE
         zlliauoOyqaYQ6T3stff5JSsdbSS2hPAMmYh7EKL5pCXKXAyPSWk4s+LbXjFttAhkiF0
         OULm6WlwEJh4mXGCJTkB+61snrPig5xeoPXCT/xzyxhepVCI8YBYWxiHgGqAQfsNyk08
         CMg5smVy3eKDG7KMRdRyAMuvSYbEkPL2g06tCy+sl9E3gJ0n2qTO908JPmJCMe/5juy/
         PAzOzc3UGi1VXRr6V5yZl0aIpZRT0dfKTz+XlvAMdGLBkOO6iaC5FdhSyVLFBKd9o6km
         CF1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=uB7J5VIU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-45c9e024593si459475b6e.6.2026.01.20.09.46.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 09:46:19 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id AEB3F43509;
	Tue, 20 Jan 2026 17:46:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 532CDC16AAE;
	Tue, 20 Jan 2026 17:46:18 +0000 (UTC)
Date: Tue, 20 Jan 2026 09:46:17 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Pimyn Girgis <pimyn@google.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org, elver@google.com,
 dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com,
 stable@vger.kernel.org
Subject: Re: [PATCH] mm/kfence: randomize the freelist on initialization
Message-Id: <20260120094617.ed5a53e9ec40e8f0a91f8cb6@linux-foundation.org>
In-Reply-To: <20260120161510.3289089-1-pimyn@google.com>
References: <20260120161510.3289089-1-pimyn@google.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=uB7J5VIU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
X-Spamd-Result: default: False [-1.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MV_CASE(0.50)[];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2001:4860:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	TAGGED_FROM(0.00)[bncBCT4XGV33UIBB3H6X3FQMGQEB5ENPJA];
	RCVD_TLS_LAST(0.00)[];
	DMARC_NA(0.00)[linux-foundation.org];
	FORGED_SENDER_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MIME_TRACE(0.00)[0:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[akpm@linux-foundation.org,kasan-dev@googlegroups.com];
	ASN(0.00)[asn:15169, ipnet:2001:4860:4864::/48, country:US];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[8];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-oa1-x3a.google.com:rdns,mail-oa1-x3a.google.com:helo]
X-Rspamd-Queue-Id: 9F5A148CCD
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, 20 Jan 2026 17:15:10 +0100 Pimyn Girgis <pimyn@google.com> wrote:

> Randomize the KFENCE freelist during pool initialization to make allocation
> patterns less predictable. This is achieved by shuffling the order in which
> metadata objects are added to the freelist using get_random_u32_below().
> 
> Additionally, ensure the error path correctly calculates the address range
> to be reset if initialization fails, as the address increment logic has
> been moved to a separate loop.
> 
> Cc: stable@vger.kernel.org
> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")

It isn't clear (to me) what was wrong with 0ce20dd84089, nor why a
-stable backport is proposed.

Can we please have a full description of the current misbehavior?  What
are the worst-case userspace-visible effects of this flaw?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260120094617.ed5a53e9ec40e8f0a91f8cb6%40linux-foundation.org.
