Return-Path: <kasan-dev+bncBDEZDPVRZMARBBOHRTDAMGQERU73PUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 60844B53C4C
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 21:31:19 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4b5ecf597acsf29607271cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 12:31:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757619078; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z6FGRn4kMe0f1dL8q37EpUcKxP/dg0nV47ppOyUOXyQ4E28aClcDqWuxWgHgPMkiJj
         kb2Tp6quefwzGsFUFoPiIPwSyKhWauteNYmtmPDg9SvRL8aiPuEG3GvquWL7jawwX8m9
         +E18CB01LlQdBYQQEyPlySg9JsTJ+grEdCnImn4WSaDo89wA6l3D4J55eyLX7v9NEizN
         oPc8dUWwi/AW93a7dM+dmr2vR0BHSbMxOg3DzXsMQ6eSImSB5ktRHIV9MbnKI5kPgZSR
         2+v107CCrzRSF8bFcdfMez4N9lQ/lzZIHJl19MMoSYn9DEvWOP0KnvV/VZORm7HrM1SV
         Pe4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=AA+6H5UZX5o5pde3bfJJcv3dx49DBSWIBcH8fXX+ek0=;
        fh=abuGyTO9+w4gK2DA6ykrENSFMqGDZWGxJ6ullH5XoV8=;
        b=TeWeKps4WKJDCndH39ciPVfarSz0X8T9Fy3KLREBPdLLOQJhMID8q1T7I95G9bY5Fq
         uiVeWQNpTxHSmHqWcSjZaFwLIHbxs4wPXwIM442p5dN/cITPk8P4hFdMoU21+IElfD/C
         OjHqgW6BsUFFKGiVUxjXRRFUQz8mGd/VyG3pq/Yeuvc6Rsg2aLC8fkrl74SPjJC+OKjf
         NG0mqveeJyrWUWB7PoJ5fzCnGsvnyvKvtwT5ykI86Z9yUkQyEqsYKihzBfvVDG1npB2B
         WLdGwACFuSvLkwULHqRF+vxhwFXGOlg1jReLF1ivHbGnr6j3d/QHkJfm/so7Fyua2ZsN
         pGAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="exip/QW4";
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757619078; x=1758223878; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=AA+6H5UZX5o5pde3bfJJcv3dx49DBSWIBcH8fXX+ek0=;
        b=CNI70zA8/HB2+j72aIs/+Wz2XH7+wykFs3xP8K7b7H90Zvtw1fhBi/pHgozkY75Ia6
         pZWIXcJMKct18XRlaWYBAQJsPUNx/FcB48H0I17OZ3J7JFAviy1RT/CTDHMI/3qipoH0
         0F5WkEJtHmRjHwxrHTKHLzamcap24gIYIljmdEqBpeHFl52KKQpA6PYTL+urhNDlyxY5
         08aq6vBgaeRCCJkZKp/oc0WBB/tPtED73LMZ9y7FSwgeJtt8TQ5Qby66n3jdYjZB2Bw2
         YjXJ7GwzEgHSLCWAQcsIY7KRwL38UWMGx+OatTDCP6TyDd5drMjm6sKU1qto3slRRql5
         DNVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757619078; x=1758223878;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=AA+6H5UZX5o5pde3bfJJcv3dx49DBSWIBcH8fXX+ek0=;
        b=UdgaCjAnu05GbBvtjWvFJuWZqfKs3YdblLYXkKY9VgCKw1MQhFtWr1a6+b7d3YWj9k
         AEbWcNKdqOHukVWZsngBk5mg5kKwFqulY7+XrwHt+wcBb4JD/2KE+ddGoL4vm+VqI4KI
         UGT1qd5MWrvyrRCkWc26aADDZ8WKvbcG+6whyIvVPA2TI2jIPF9ntcwLaYf1M+qMvx73
         tzX3eRoaEiQ2SpynzNcqOvUupsv3zJasheirWSyUbYbSUgGkSKSqX7qSxqoUuT1Hw+5L
         JYjb7dxQGiEDJVALSj3/jrU/aoj8NYYDsU7dUmkck/yfZ7DFnU8N4qit20iPR6Ls/Lb/
         crsA==
X-Forwarded-Encrypted: i=2; AJvYcCX+PsPXrQfvySdD+0iWcKCybOy1hWJ7ftUedPMqRiJgO7sDK6nVvdzOrrRRpgjnGO/83HztrQ==@lfdr.de
X-Gm-Message-State: AOJu0YwgjcRpWU3D0i1kK2R1HIOZQWdYFnrlaHwICUk7iCg4DvLi+hZ4
	c8KSaSB2VOqR206FxW0uqCC/Ep89GyPsGKskZQn16uqZ2sOCYpDfJoxj
X-Google-Smtp-Source: AGHT+IHOJKmjGFbpAvlkDUb9iBHVm5kPXlvPTDr/cuKdf07WdKici2IeP6SMZeP4V96sHauHxI5h7Q==
X-Received: by 2002:a05:622a:4898:b0:4b5:e49d:806d with SMTP id d75a77b69052e-4b77d172327mr5251391cf.55.1757619077923;
        Thu, 11 Sep 2025 12:31:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdlardRW2FrfXKzH2oa5+K57Hn5yv+niQeB33qE2bxUWQ==
Received: by 2002:ac8:5946:0:b0:4b5:de61:2c8a with SMTP id d75a77b69052e-4b636cab4bdls25491211cf.1.-pod-prod-01-us;
 Thu, 11 Sep 2025 12:31:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnWdTwPxXqT7OUHW/ZOza13+uKjB31vekZF5Ud4/lFpqGcKwS9uuv2keFAzaEIEnuC7AABYXXZb7E=@googlegroups.com
X-Received: by 2002:a05:620a:a118:b0:81b:9461:21d9 with SMTP id af79cd13be357-823fd60472amr77426785a.23.1757619076522;
        Thu, 11 Sep 2025 12:31:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757619076; cv=none;
        d=google.com; s=arc-20240605;
        b=f7r0CyUXTb8hNvGELkiX7bO454fLXP+mSGcxbiOn7tC2dlI272GrYtWqh7GdPWPtek
         ngrc7S2sPvRX4O4JG5CZLVEKr962F9TsG4VaCHPbr2mQWeHwaRe00VXyWwOU6x+P78Km
         Wi1mosg90qbwBffyHYGT4vRs80GZ+t2calaRfplymOp21q+0EPHNnGOLvwnDZAqNdyPc
         gBftGV+OR4CqtmbyVov2+fZupgqB+H4sHcwz3kDebkNVECZwFdQsMVl+3kuM4qDYAAzp
         WVaoa7enVoVVl6bW7BMrlooETUTmyhXvgZhXGF/h0v1k1xdfVSSpmphMR8/SaQAh0w4Y
         4iFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=iNAkVmfmmd2STgROqHu2/avwiWpu9bFBUdDAMjZAfnU=;
        fh=KHT2kymW7tjxt6FznQi1j79NKfOkVh21sCLzL2GzzK0=;
        b=XKkBUNd8zbdeZIdNlMHt0P54fmHoOkJU/EqWMYyOq8phML4TK+1IprpRyy9JIyAVG3
         CmFaNNyDeVWzNlwGu3UYCa1nqeDHhjPlzUglwLEccCTwM9GevK3GfrUuA9R4VX+0A2kC
         VY6G4wtxdE83jX8n1kCRAnPv1SV/rgdN+4fPcWUV3AFI1o0D6JSFIBlJYdEvmCM20G8J
         iNd3nfji1TUi7cINd1z0IiounSL6xdnnA+9LgfRkpVoKW9TZIjNk7WkYnvEZrba2N8LD
         2/GuvDHVfDvGjWMyrSof3V4HUYKBmrH6uTiIJ9O86O/HxfRbqdx61gEN1hR/g6KyNzD8
         Ke/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="exip/QW4";
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b639dbd3cdsi832921cf.4.2025.09.11.12.31.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Sep 2025 12:31:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 41F1E601DC;
	Thu, 11 Sep 2025 19:31:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A4A6DC4CEF0;
	Thu, 11 Sep 2025 19:31:14 +0000 (UTC)
Date: Thu, 11 Sep 2025 12:29:53 -0700
From: "'Eric Biggers' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com,
	Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-crypto@vger.kernel.org,
	stable@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH] kmsan: Fix out-of-bounds access to shadow memory
Message-ID: <20250911192953.GG1376@sol>
References: <20250829164500.324329-1-ebiggers@kernel.org>
 <20250910194921.GA3153735@google.com>
 <CAG_fn=W_7o6ANs94GwoYjyjvY5kSFYHB6DwfE+oXM7TP1eP5dw@mail.gmail.com>
 <20250911175145.GA1376@sol>
 <20250911190302.GF1376@sol>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250911190302.GF1376@sol>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="exip/QW4";       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Eric Biggers <ebiggers@kernel.org>
Reply-To: Eric Biggers <ebiggers@kernel.org>
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

On Thu, Sep 11, 2025 at 12:03:02PM -0700, Eric Biggers wrote:
> On Thu, Sep 11, 2025 at 10:51:45AM -0700, Eric Biggers wrote:
> > On Thu, Sep 11, 2025 at 11:09:17AM +0200, Alexander Potapenko wrote:
> > > On Wed, Sep 10, 2025 at 9:49=E2=80=AFPM Eric Biggers <ebiggers@kernel=
.org> wrote:
> > > >
> > > > On Fri, Aug 29, 2025 at 09:45:00AM -0700, Eric Biggers wrote:
> > > > > Running sha224_kunit on a KMSAN-enabled kernel results in a crash=
 in
> > > > > kmsan_internal_set_shadow_origin():
> > > > >
> > > > >     BUG: unable to handle page fault for address: ffffbc384029100=
0
> > > > >     #PF: supervisor read access in kernel mode
> > > > >     #PF: error_code(0x0000) - not-present page
> > > > >     PGD 1810067 P4D 1810067 PUD 192d067 PMD 3c17067 PTE 0
> > > > >     Oops: 0000 [#1] SMP NOPTI
> > > > >     CPU: 0 UID: 0 PID: 81 Comm: kunit_try_catch Tainted: G       =
          N  6.17.0-rc3 #10 PREEMPT(voluntary)
> > > > >     Tainted: [N]=3DTEST
> > > > >     Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS r=
el-1.17.0-0-gb52ca86e094d-prebuilt.qemu.org 04/01/2014
> > > > >     RIP: 0010:kmsan_internal_set_shadow_origin+0x91/0x100
> > > > >     [...]
> > > > >     Call Trace:
> > > > >     <TASK>
> > > > >     __msan_memset+0xee/0x1a0
> > > > >     sha224_final+0x9e/0x350
> > > > >     test_hash_buffer_overruns+0x46f/0x5f0
> > > > >     ? kmsan_get_shadow_origin_ptr+0x46/0xa0
> > > > >     ? __pfx_test_hash_buffer_overruns+0x10/0x10
> > > > >     kunit_try_run_case+0x198/0xa00
> > > >
> > > > Any thoughts on this patch from the KMSAN folks?  I'd love to add
> > > > CONFIG_KMSAN=3Dy to my crypto subsystem testing, but unfortunately =
the
> > > > kernel crashes due to this bug :-(
> > > >
> > > > - Eric
> > >=20
> > > Sorry, I was out in August and missed this email when digging through=
 my inbox.
> > >=20
> > > Curiously, I couldn't find any relevant crashes on the KMSAN syzbot
> > > instance, but the issue is legit.
> > > Thank you so much for fixing this!
> > >=20
> > > Any chance you can add a test case for it to mm/kmsan/kmsan_test.c?
> >=20
> > Unfortunately most of the KMSAN test cases already fail on upstream,
> > which makes it difficult to develop new ones:
>=20
> The KMSAN test failures bisect to the following commit:
>=20
>     commit f90b474a35744b5d43009e4fab232e74a3024cae
>     Author: Vlastimil Babka <vbabka@suse.cz>
>     Date:   Mon Mar 10 13:40:17 2025 +0100
>=20
>         mm: Fix the flipped condition in gfpflags_allow_spinning()
>=20
> I'm not sure why.  Apparently something related to lib/stackdepot.c.
>=20
> Reverting that commit on top of upstream fixes the KMSAN tests.
>=20

Rolling back all the BPF (?) related changes that were made to
lib/stackdepot.c in v6.15 fixes this too.  Looks like there was a
regression where stack traces stopped being saved in some cases.

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index de0b0025af2b9..99e374d35b61d 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -638,12 +638,11 @@ depot_stack_handle_t stack_depot_save_flags(unsigned =
long *entries,
 	struct list_head *bucket;
 	struct stack_record *found =3D NULL;
 	depot_stack_handle_t handle =3D 0;
 	struct page *page =3D NULL;
 	void *prealloc =3D NULL;
-	bool allow_spin =3D gfpflags_allow_spinning(alloc_flags);
-	bool can_alloc =3D (depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC) && allow_sp=
in;
+	bool can_alloc =3D depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC;
 	unsigned long flags;
 	u32 hash;
=20
 	if (WARN_ON(depot_flags & ~STACK_DEPOT_FLAGS_MASK))
 		return 0;
@@ -678,11 +677,11 @@ depot_stack_handle_t stack_depot_save_flags(unsigned =
long *entries,
 				   DEPOT_POOL_ORDER);
 		if (page)
 			prealloc =3D page_address(page);
 	}
=20
-	if (in_nmi() || !allow_spin) {
+	if (in_nmi()) {
 		/* We can never allocate in NMI context. */
 		WARN_ON_ONCE(can_alloc);
 		/* Best effort; bail if we fail to take the lock. */
 		if (!raw_spin_trylock_irqsave(&pool_lock, flags))
 			goto exit;
@@ -719,14 +718,11 @@ depot_stack_handle_t stack_depot_save_flags(unsigned =
long *entries,
 	printk_deferred_exit();
 	raw_spin_unlock_irqrestore(&pool_lock, flags);
 exit:
 	if (prealloc) {
 		/* Stack depot didn't use this memory, free it. */
-		if (!allow_spin)
-			free_pages_nolock(virt_to_page(prealloc), DEPOT_POOL_ORDER);
-		else
-			free_pages((unsigned long)prealloc, DEPOT_POOL_ORDER);
+		free_pages((unsigned long)prealloc, DEPOT_POOL_ORDER);
 	}
 	if (found)
 		handle =3D found->handle.handle;
 	return handle;
 }

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250911192953.GG1376%40sol.
