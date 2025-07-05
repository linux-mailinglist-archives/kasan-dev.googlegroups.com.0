Return-Path: <kasan-dev+bncBAABBA56U3BQMGQE4EUD56I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id BDF66AFA224
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Jul 2025 23:54:13 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-876b1339851sf85751339f.3
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Jul 2025 14:54:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751752452; cv=pass;
        d=google.com; s=arc-20240605;
        b=IG9hvAq+LTODMipf+KNEjBqn9PuP9YV3tnKbaXmqzTzOCU3mjlLOV4iUfBEnfYa6p4
         DOZbIItDnoRRxgwuQlpueg3xMQduYEO0BXzcjpTUR4vkLeZIcJ64tLJxH6RCs9EFD5no
         7O82W6PhM51mjPAu+LZLp5/O2ZPM7qNx06Mod6tc/WmFfolnCXrlqqcYsBXNp85PHHNN
         +xtv64zvm1E6By7npgb/34gNaH00A2r+cmfzzJ6+uk/qN8SFsH4qr8HrK79VrUMkrC/j
         NQ6egFD9ghoVmRoCB5ajtIYxGg51fyObVr7mS/p85JDHIyt9FZoJ3o+mPRexKVptLGzJ
         yPHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=I1GXMew7YWEVsX8GzdLQzHIO5FHxs9ZfG5P6ndaYINU=;
        fh=5d1yfn5A3hqpQ+EZc89l30RjxQmMAidxWOJ7KFqPsSc=;
        b=cFggMZX3KK2gteEIDliW9mik44qlmwv0fqs3gbLMvUt+FrQKlgnPlkJVD6uRi2w8+e
         LupQd9EBZdKvRfcQop8rPdpJrZJn9VnV0BabGI7XGXPcH8C5knVcBxXzEcW6LTomBSUd
         fDjc+kRBElNJshX5ZjaWm4yhndQ4lo6yBVQRqfzQhEcI4OGIhWfNGpgzuKB/BCw3AWfn
         U++c74RRCKiNmbesxhIpuQTrYFUZ3NDqVIcIpO2KI8uNiXt2GdQYdoEhLfpQbaFpMkYs
         vQDmJsLEys/VJjdM/eDyBxt7AxncYnMAuhV4EYj96DXfxmQ/TMV4SyC7qL4w7SzkZyct
         akvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eXdYW4Qn;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751752452; x=1752357252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=I1GXMew7YWEVsX8GzdLQzHIO5FHxs9ZfG5P6ndaYINU=;
        b=FapbzHBvNyGTJtaV6d2qnTfiePdi5lrJZOkK6nCi1/4smnAhLGH9f6oZ5emulDsmgC
         KhN+23Fp1E8YvX1JmxE7zfbSCVUBH91fVAeyua25Sl6D7/UrfbpQT3UOSz2UEtTau1AD
         9Czhni4tTXboHgBsfdJPcvlpYGNUWyjvmNUdNNDBrjcuOdPbs2wMj5+LQTxrsgQfPAGM
         D10/CjXPjaSFx37bANTPWTqIkUVmCiZ/oW8xv/n1xiz2440lh0rGJ7f2v7yzFlOGQife
         LqgIfFlRw5eQO8KCM+Q59mhFXV2MnSiGuZBVw/B2Ns7jIaI/g0iTs9K5NH7AKUNPYfts
         Ix+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751752452; x=1752357252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I1GXMew7YWEVsX8GzdLQzHIO5FHxs9ZfG5P6ndaYINU=;
        b=EgSESft9EKOJvnJ80VOR5l5WOn3Jnkt77cSjPu2cbJKpiHHRJCwz6qWBC2ft1Iy8f/
         /H9qx0rU731AFlu0DiShWfKIntRwgXjvIiwbWR/2LFbanHBnA12AjCMh5MWVSTvefD9q
         5l7Xm+hGunqgpqN9EBIE488wu5ZlASWPecL1Ndnt5cGrGN09RFg1rQErSd4LHb8PlJAG
         SNJ3ZMX/TJSync84MdgMUEc7SNsNsEmmDqw1ehfAs5DL1VpaS4uX2pnaIODrbCTmLQrX
         2AR0mwKmXhlV4r7D9wPpJhEXXe9XdAawGXR2/3MjA9VGoI/na5HFs1sYC/OYZhUF1Z5j
         b05g==
X-Forwarded-Encrypted: i=2; AJvYcCUKMlEoxl7V94F3WRJ4EjC7JMKMq+J7WxpxRNJxj4xTUPMOqrSE2F2Xw0tg9C035pAfRRhtJw==@lfdr.de
X-Gm-Message-State: AOJu0YyhsbsswkCa5ksoN6ZkCl+KujaCQ2L5ayX3F9HG6BWHOULCxNk0
	elM7rsK6Rv+Fr6/BkF+P0DVHALDFrqxWfG7JFDlB0FQ0wGFPdBlWDz9o
X-Google-Smtp-Source: AGHT+IHZPxN+lM0JkRYacrkaw9FB1HS5GcsB/OhPcuEIaqJfBWct9k+PSDuJq/dDOUF7a3lKKgKD6Q==
X-Received: by 2002:a05:6e02:1d86:b0:3df:2d65:c27a with SMTP id e9e14a558f8ab-3e13545d5f6mr71416345ab.1.1751752451973;
        Sat, 05 Jul 2025 14:54:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeDbXiXfCEF1vSwxe5+LtSTOCo5MPS+6BJj1YOKs38dCg==
Received: by 2002:a05:6e02:1f89:b0:3dd:bec6:f17d with SMTP id
 e9e14a558f8ab-3e1391ecfe7ls8566785ab.2.-pod-prod-06-us; Sat, 05 Jul 2025
 14:54:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVGXrvdq0YzGIi96ZAFW2F/LFRuzOJSEghM3oeQKs6FHsqU60cMI6pDOO7Hcyz+aXRjdoW0Sl+OOeg=@googlegroups.com
X-Received: by 2002:a05:6602:2983:b0:867:40d9:bf7e with SMTP id ca18e2360f4ac-876e16282a1mr638592239f.9.1751752450729;
        Sat, 05 Jul 2025 14:54:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751752450; cv=none;
        d=google.com; s=arc-20240605;
        b=hYm+yB8xUDzPRrKANCIXjdSRVdOBF0Yu4XT9ZY2DaIMvkng9JCNpIwHaW8DS9UP92x
         TUSnI/KNGnIMi6NfL1m5yx4EZuUAAp1nwih/bmjmIBzpwcoP1y5R6K9DcU2negv2wdJN
         KycXt/hAErov1IZdn4pkV3q6Nz/AHAgSEQ7hQ47IyZzzb5SVssUAkn85ktzQrPD7Kf/M
         QZxdhCLCaS9Wtf+/fBK00tc1CBqMy66rpiVAYUNccaiigaIPDhDqkFxWgsHV9qKQwSkc
         bQXDBJGH1gUV8ZVF/b21BKpEbVd+Th2+mjNvon7Puo99BFWsbWnpbFOLmu3kyjyUaZX1
         qgCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+XXdPz5ZEWJMhSE2KloZwsxwNzOwx+M88hkSG0TXMsI=;
        fh=ymshoAxJ0p6GN3p3j82MEvHzKhZuKEztLOFFE4Sbfe0=;
        b=cG+HW2u/WYqnbQZNQknNAIhFfRknmhEDGfpbESVdL6EJQcQNYbolhGFEyRge45M1kz
         eccfyfz57/UADo52+s/C7wvkHuV67IANeFPw5no8+fqRPgZlIb6re4XtGa5qu+4gr79E
         PRzQdIRGE9zI+9BNi6lTx4QdeIxMFtAxhipOLlDEBuWr19PUBrU5Yx15HrrQtdzfsILG
         w85v/uW0gcPkl+qU3CHr4JbLOJ8QY7tDGI67yNpRXkhG/kxgoQX45xuOtSlHr+E9bkLK
         5m5SMnogcW3CZTV5RUyABd5PbTsRQFjfh4AySX0GpXmkX/G9hAiU1Gw0mjiRuMT/u2Dj
         9GKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eXdYW4Qn;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-876e083a190si10239639f.3.2025.07.05.14.54.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Jul 2025 14:54:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 0BF24A53998;
	Sat,  5 Jul 2025 21:54:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 60E33C4CEE7;
	Sat,  5 Jul 2025 21:54:08 +0000 (UTC)
Date: Sat, 5 Jul 2025 23:54:07 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Subject: Re: [RFC v1 3/3] mm: Use seprintf() instead of less ergonomic APIs
Message-ID: <iuee5umfb5g5awhqx3ibvvgtsk4ymwdersszrys7yhleu3catc@2ubsmycdsmn3>
References: <cover.1751747518.git.alx@kernel.org>
 <be193e1856aaf40f0e6dc44bb2e22ab0688203af.1751747518.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="sxjq76zh675ubdos"
Content-Disposition: inline
In-Reply-To: <be193e1856aaf40f0e6dc44bb2e22ab0688203af.1751747518.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eXdYW4Qn;       spf=pass
 (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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


--sxjq76zh675ubdos
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Subject: Re: [RFC v1 3/3] mm: Use seprintf() instead of less ergonomic APIs
References: <cover.1751747518.git.alx@kernel.org>
 <be193e1856aaf40f0e6dc44bb2e22ab0688203af.1751747518.git.alx@kernel.org>
MIME-Version: 1.0
In-Reply-To: <be193e1856aaf40f0e6dc44bb2e22ab0688203af.1751747518.git.alx@kernel.org>

On Sat, Jul 05, 2025 at 10:33:53PM +0200, Alejandro Colomar wrote:
> While doing this, I detected some anomalies in the existing code:
> 
> mm/kfence/kfence_test.c:
> 
> 	The last call to scnprintf() did increment 'cur', but it's
> 	unused after that, so it was dead code.  I've removed the dead
> 	code in this patch.
> 
> mm/mempolicy.c:
> 
> 	This file uses the 'p += snprintf()' anti-pattern.  That will
> 	overflow the pointer on truncation, which has undefined
> 	behavior.  Using seprintf(), this bug is fixed.
> 
> 	As in the previous file, here there was also dead code in the
> 	last scnprintf() call, by incrementing a pointer that is not
> 	used after the call.  I've removed the dead code.
> 
> mm/page_owner.c:
> 
> 	Within print_page_owner(), there are some calls to scnprintf(),
> 	which do report truncation.  And then there are other calls to

This is a typo; I meant s/do/don't/

> 	snprintf(), where we handle errors (there are two 'goto err').
> 
> 	I've kept the existing error handling, as I trust it's there for
> 	a good reason (i.e., we may want to avoid calling
> 	print_page_owner_memcg() if we truncated before).  Please review
> 	if this amount of error handling is the right one, or if we want
> 	to add or remove some.  For seprintf(), a single test for null
> 	after the last call is enough to detect truncation.
> 
> mm/slub.c:
> 
> 	Again, the 'p += snprintf()' anti-pattern.  This is UB, and by
> 	using seprintf() we've fixed the bug.
> 
> Cc: Kees Cook <kees@kernel.org>
> Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
> Signed-off-by: Alejandro Colomar <alx@kernel.org>
> ---
>  mm/kfence/kfence_test.c | 24 ++++++++++++------------
>  mm/kmsan/kmsan_test.c   |  4 ++--
>  mm/mempolicy.c          | 18 +++++++++---------
>  mm/page_owner.c         | 32 +++++++++++++++++---------------
>  mm/slub.c               |  5 +++--
>  5 files changed, 43 insertions(+), 40 deletions(-)
> 
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 00034e37bc9f..ff734c514c03 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -113,26 +113,26 @@ static bool report_matches(const struct expect_report *r)
>  	end = &expect[0][sizeof(expect[0]) - 1];
>  	switch (r->type) {
>  	case KFENCE_ERROR_OOB:
> -		cur += scnprintf(cur, end - cur, "BUG: KFENCE: out-of-bounds %s",
> +		cur = seprintf(cur, end, "BUG: KFENCE: out-of-bounds %s",
>  				 get_access_type(r));
>  		break;
>  	case KFENCE_ERROR_UAF:
> -		cur += scnprintf(cur, end - cur, "BUG: KFENCE: use-after-free %s",
> +		cur = seprintf(cur, end, "BUG: KFENCE: use-after-free %s",
>  				 get_access_type(r));
>  		break;
>  	case KFENCE_ERROR_CORRUPTION:
> -		cur += scnprintf(cur, end - cur, "BUG: KFENCE: memory corruption");
> +		cur = seprintf(cur, end, "BUG: KFENCE: memory corruption");
>  		break;
>  	case KFENCE_ERROR_INVALID:
> -		cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid %s",
> +		cur = seprintf(cur, end, "BUG: KFENCE: invalid %s",
>  				 get_access_type(r));
>  		break;
>  	case KFENCE_ERROR_INVALID_FREE:
> -		cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid free");
> +		cur = seprintf(cur, end, "BUG: KFENCE: invalid free");
>  		break;
>  	}
>  
> -	scnprintf(cur, end - cur, " in %pS", r->fn);
> +	seprintf(cur, end, " in %pS", r->fn);
>  	/* The exact offset won't match, remove it; also strip module name. */
>  	cur = strchr(expect[0], '+');
>  	if (cur)
> @@ -144,26 +144,26 @@ static bool report_matches(const struct expect_report *r)
>  
>  	switch (r->type) {
>  	case KFENCE_ERROR_OOB:
> -		cur += scnprintf(cur, end - cur, "Out-of-bounds %s at", get_access_type(r));
> +		cur = seprintf(cur, end, "Out-of-bounds %s at", get_access_type(r));
>  		addr = arch_kfence_test_address(addr);
>  		break;
>  	case KFENCE_ERROR_UAF:
> -		cur += scnprintf(cur, end - cur, "Use-after-free %s at", get_access_type(r));
> +		cur = seprintf(cur, end, "Use-after-free %s at", get_access_type(r));
>  		addr = arch_kfence_test_address(addr);
>  		break;
>  	case KFENCE_ERROR_CORRUPTION:
> -		cur += scnprintf(cur, end - cur, "Corrupted memory at");
> +		cur = seprintf(cur, end, "Corrupted memory at");
>  		break;
>  	case KFENCE_ERROR_INVALID:
> -		cur += scnprintf(cur, end - cur, "Invalid %s at", get_access_type(r));
> +		cur = seprintf(cur, end, "Invalid %s at", get_access_type(r));
>  		addr = arch_kfence_test_address(addr);
>  		break;
>  	case KFENCE_ERROR_INVALID_FREE:
> -		cur += scnprintf(cur, end - cur, "Invalid free of");
> +		cur = seprintf(cur, end, "Invalid free of");
>  		break;
>  	}
>  
> -	cur += scnprintf(cur, end - cur, " 0x%p", (void *)addr);
> +	seprintf(cur, end, " 0x%p", (void *)addr);
>  
>  	spin_lock_irqsave(&observed.lock, flags);
>  	if (!report_available())
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index 9733a22c46c1..a062a46b2d24 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -107,9 +107,9 @@ static bool report_matches(const struct expect_report *r)
>  	cur = expected_header;
>  	end = &expected_header[sizeof(expected_header) - 1];
>  
> -	cur += scnprintf(cur, end - cur, "BUG: KMSAN: %s", r->error_type);
> +	cur = seprintf(cur, end, "BUG: KMSAN: %s", r->error_type);
>  
> -	scnprintf(cur, end - cur, " in %s", r->symbol);
> +	seprintf(cur, end, " in %s", r->symbol);
>  	/* The exact offset won't match, remove it; also strip module name. */
>  	cur = strchr(expected_header, '+');
>  	if (cur)
> diff --git a/mm/mempolicy.c b/mm/mempolicy.c
> index b28a1e6ae096..c696e4a6f4c2 100644
> --- a/mm/mempolicy.c
> +++ b/mm/mempolicy.c
> @@ -3359,6 +3359,7 @@ int mpol_parse_str(char *str, struct mempolicy **mpol)
>  void mpol_to_str(char *buffer, int maxlen, struct mempolicy *pol)
>  {
>  	char *p = buffer;
> +	char *e = buffer + maxlen;
>  	nodemask_t nodes = NODE_MASK_NONE;
>  	unsigned short mode = MPOL_DEFAULT;
>  	unsigned short flags = 0;
> @@ -3384,33 +3385,32 @@ void mpol_to_str(char *buffer, int maxlen, struct mempolicy *pol)
>  		break;
>  	default:
>  		WARN_ON_ONCE(1);
> -		snprintf(p, maxlen, "unknown");
> +		seprintf(p, e, "unknown");
>  		return;
>  	}
>  
> -	p += snprintf(p, maxlen, "%s", policy_modes[mode]);
> +	p = seprintf(p, e, "%s", policy_modes[mode]);
>  
>  	if (flags & MPOL_MODE_FLAGS) {
> -		p += snprintf(p, buffer + maxlen - p, "=");
> +		p = seprintf(p, e, "=");
>  
>  		/*
>  		 * Static and relative are mutually exclusive.
>  		 */
>  		if (flags & MPOL_F_STATIC_NODES)
> -			p += snprintf(p, buffer + maxlen - p, "static");
> +			p = seprintf(p, e, "static");
>  		else if (flags & MPOL_F_RELATIVE_NODES)
> -			p += snprintf(p, buffer + maxlen - p, "relative");
> +			p = seprintf(p, e, "relative");
>  
>  		if (flags & MPOL_F_NUMA_BALANCING) {
>  			if (!is_power_of_2(flags & MPOL_MODE_FLAGS))
> -				p += snprintf(p, buffer + maxlen - p, "|");
> -			p += snprintf(p, buffer + maxlen - p, "balancing");
> +				p = seprintf(p, e, "|");
> +			p = seprintf(p, e, "balancing");
>  		}
>  	}
>  
>  	if (!nodes_empty(nodes))
> -		p += scnprintf(p, buffer + maxlen - p, ":%*pbl",
> -			       nodemask_pr_args(&nodes));
> +		seprintf(p, e, ":%*pbl", nodemask_pr_args(&nodes));
>  }
>  
>  #ifdef CONFIG_SYSFS
> diff --git a/mm/page_owner.c b/mm/page_owner.c
> index cc4a6916eec6..5811738e3320 100644
> --- a/mm/page_owner.c
> +++ b/mm/page_owner.c
> @@ -496,7 +496,7 @@ void pagetypeinfo_showmixedcount_print(struct seq_file *m,
>  /*
>   * Looking for memcg information and print it out
>   */
> -static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
> +static inline char *print_page_owner_memcg(char *p, const char end[0],
>  					 struct page *page)
>  {
>  #ifdef CONFIG_MEMCG
> @@ -511,8 +511,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
>  		goto out_unlock;
>  
>  	if (memcg_data & MEMCG_DATA_OBJEXTS)
> -		ret += scnprintf(kbuf + ret, count - ret,
> -				"Slab cache page\n");
> +		p = seprintf(p, end, "Slab cache page\n");
>  
>  	memcg = page_memcg_check(page);
>  	if (!memcg)
> @@ -520,7 +519,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
>  
>  	online = (memcg->css.flags & CSS_ONLINE);
>  	cgroup_name(memcg->css.cgroup, name, sizeof(name));
> -	ret += scnprintf(kbuf + ret, count - ret,
> +	p = seprintf(p, end,
>  			"Charged %sto %smemcg %s\n",
>  			PageMemcgKmem(page) ? "(via objcg) " : "",
>  			online ? "" : "offline ",
> @@ -529,7 +528,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
>  	rcu_read_unlock();
>  #endif /* CONFIG_MEMCG */
>  
> -	return ret;
> +	return p;
>  }
>  
>  static ssize_t
> @@ -538,14 +537,16 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
>  		depot_stack_handle_t handle)
>  {
>  	int ret, pageblock_mt, page_mt;
> -	char *kbuf;
> +	char *kbuf, *p, *e;
>  
>  	count = min_t(size_t, count, PAGE_SIZE);
>  	kbuf = kmalloc(count, GFP_KERNEL);
>  	if (!kbuf)
>  		return -ENOMEM;
>  
> -	ret = scnprintf(kbuf, count,
> +	p = kbuf;
> +	e = kbuf + count;
> +	p = seprintf(p, e,
>  			"Page allocated via order %u, mask %#x(%pGg), pid %d, tgid %d (%s), ts %llu ns\n",
>  			page_owner->order, page_owner->gfp_mask,
>  			&page_owner->gfp_mask, page_owner->pid,
> @@ -555,7 +556,7 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
>  	/* Print information relevant to grouping pages by mobility */
>  	pageblock_mt = get_pageblock_migratetype(page);
>  	page_mt  = gfp_migratetype(page_owner->gfp_mask);
> -	ret += scnprintf(kbuf + ret, count - ret,
> +	p = seprintf(p, e,
>  			"PFN 0x%lx type %s Block %lu type %s Flags %pGp\n",
>  			pfn,
>  			migratetype_names[page_mt],
> @@ -563,22 +564,23 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
>  			migratetype_names[pageblock_mt],
>  			&page->flags);
>  
> -	ret += stack_depot_snprint(handle, kbuf + ret, count - ret, 0);
> -	if (ret >= count)
> -		goto err;
> +	p = stack_depot_seprint(handle, p, e, 0);
> +	if (p == NULL)
> +		goto err;  // XXX: Should we remove this error handling?
>  
>  	if (page_owner->last_migrate_reason != -1) {
> -		ret += scnprintf(kbuf + ret, count - ret,
> +		p = seprintf(p, e,
>  			"Page has been migrated, last migrate reason: %s\n",
>  			migrate_reason_names[page_owner->last_migrate_reason]);
>  	}
>  
> -	ret = print_page_owner_memcg(kbuf, count, ret, page);
> +	p = print_page_owner_memcg(p, e, page);
>  
> -	ret += snprintf(kbuf + ret, count - ret, "\n");
> -	if (ret >= count)
> +	p = seprintf(p, e, "\n");
> +	if (p == NULL)
>  		goto err;
>  
> +	ret = p - kbuf;
>  	if (copy_to_user(buf, kbuf, ret))
>  		ret = -EFAULT;
>  
> diff --git a/mm/slub.c b/mm/slub.c
> index be8b09e09d30..b67c6ca0d0f7 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -7451,6 +7451,7 @@ static char *create_unique_id(struct kmem_cache *s)
>  {
>  	char *name = kmalloc(ID_STR_LENGTH, GFP_KERNEL);
>  	char *p = name;
> +	char *e = name + ID_STR_LENGTH;
>  
>  	if (!name)
>  		return ERR_PTR(-ENOMEM);
> @@ -7475,9 +7476,9 @@ static char *create_unique_id(struct kmem_cache *s)
>  		*p++ = 'A';
>  	if (p != name + 1)
>  		*p++ = '-';
> -	p += snprintf(p, ID_STR_LENGTH - (p - name), "%07u", s->size);
> +	p = seprintf(p, e, "%07u", s->size);
>  
> -	if (WARN_ON(p > name + ID_STR_LENGTH - 1)) {
> +	if (WARN_ON(p == NULL)) {
>  		kfree(name);
>  		return ERR_PTR(-EINVAL);
>  	}
> -- 
> 2.50.0
> 

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/iuee5umfb5g5awhqx3ibvvgtsk4ymwdersszrys7yhleu3catc%402ubsmycdsmn3.

--sxjq76zh675ubdos
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhpnv4ACgkQ64mZXMKQ
wqk1vg//Vt8t78GPcqFyDdPOtmuNVG3IaCmYiHr+QhI76XyxWTBZJE8MIGoYCrsa
07kxIfpn3/0xcVWyFKMlxoayS+0UcwNaeCNlL1QEbfh4nr860TrqSktol0u65gVF
kkzXqZmas40EA8LKrrpragR2XHS96iO8TCuwL6IT2fCKnivMp+a1q3o1DPdQ0tnt
fYBLP8Cjr8DLTeExyVy7+9wpNMvvv8//bi+voTQo0ohkMb3+WlxgRxnFWcEy+Z+7
/wTAzXx0lgBOBpz1fF4h4vDNOVgcaW7712ytUeFkm2q6phr3wAVkt1nSf9dY5H8p
gIFDblBPekrGY+qe24EUGgETmoyjajmHgsLQu8IfMfg4LBfMQ6bjeH8/Ttvovw0A
QlzXS+dTjXw1bFsY1J6IwjczQS5XYodzAbc9zdCTqwB88CUVZcUYhcS7Ed9+W2kN
egwZlh4L5+yVNTk9WvwJn4pqFFBcLtJpVtDCngc6eMovbVsid5QqDVJbCJ4cA0EQ
NiBsaa7cl53zsVAfzdiIXo7JWmeEjdfvqC5KlW2szEzG2g80Q1jCXLToJcV2/i0K
2XGNCNOoaWAKQh5vxe8y16TSYPOxP+pxz0Sbo7vTZaw7GgwOza285nTN8pMjUbDQ
qYT0dagmewcqtlPaXlol0ybzsfK+5tybzJRKnaXXSjDa8/pLIm0=
=krbL
-----END PGP SIGNATURE-----

--sxjq76zh675ubdos--
