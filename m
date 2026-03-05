Return-Path: <kasan-dev+bncBC4ZB2GTVUKBBB7ZU3GQMGQEMSMQRZA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 2M/+A4q8qWnSDgEAu9opvQ
	(envelope-from <kasan-dev+bncBC4ZB2GTVUKBBB7ZU3GQMGQEMSMQRZA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 18:25:30 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb139.google.com (mail-yx1-xb139.google.com [IPv6:2607:f8b0:4864:20::b139])
	by mail.lfdr.de (Postfix) with ESMTPS id A675F216282
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 18:25:29 +0100 (CET)
Received: by mail-yx1-xb139.google.com with SMTP id 956f58d0204a3-64ca6895833sf11614778d50.2
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 09:25:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772731528; cv=pass;
        d=google.com; s=arc-20240605;
        b=b0o4hS0q+pqHeHV0tQ8/YMnBdtgKqmoZLlao1XB5d7ORfRCbY3I4ra6Bn8izEgvrkZ
         cQnW+ujHt9t5Y+kQdCgQcS7twQ0jTM6rxZoFKtp6gypPIy8RaD2GwJ303HRNzod17K2s
         Wey8zlFga1rFMFQUXozGVij2JDPwmTXsD8A/7BM+DKkX1WwtgMlHKMvohH3cXfSDDwxp
         Va3mb1Xr7DZi94Dqh+JZOQkgAGZzZQvotSybAzFBjlU4aycJk36/Kksg1SHDrAdtg6RO
         khaV8RyygvfOzQvvogjNgZSgX68HTFx7BL7ugr1XSSYUMepf/KpZJE/93IZIsiAn71pL
         qYZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DBkfcXHoLQ366Q1zQ+ts1UheyCH29qf5ckCTxRqip/c=;
        fh=b6EVfeFZ3WkOWt4bGXnMtfTLn456LbzMO7apZqRaxQE=;
        b=Hxbm85Zbm8ytMiOJ3iJoaW0Hxw8Rpu9/YMu6vUQmj7fVeIXC2MvTisYtaorVIskIRL
         8Zs+sSwRt4l7dfdDVFJQRDrY5r9D7pFhnngyftc3wrfYEG+Ydb0IQYtbjkvDNpAqICL9
         zuVisv5s063EkcFCim1ifFTY0s1SOAYrStjvsTCctBBSJdyLnf7rJyhhMrx5255TsGHe
         EMMRdF+J6e8Cmsql74k+RcYuJvnecWqwmtiWHEVDPowzB3nRoyisdZn+ZgDwf/tsi9Cx
         BEVdMTVu74uZl7zcLgFc7FcCBJy1roGfxR5ijqh+pAFZ9itBh2HR/c1ky4oejIrd+ptU
         g4yQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dpa+omYb;
       spf=pass (google.com: domain of song@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=song@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772731528; x=1773336328; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DBkfcXHoLQ366Q1zQ+ts1UheyCH29qf5ckCTxRqip/c=;
        b=hNeOxOkrf4ebl+RU+r5U5X0yxWQ5LIzS39OLb/a08BJXT+uMaca2BAfdKYWlO9ijR7
         7bt0+2wBXmfhQbRZFBU18wtpFTpmAyxvnHfpnLTDZ95YBzC1JFWHYkycgG0rfWX2ghc6
         uATbYmaPz5/HnXxEGgpsMhNT31VkyYSgn/tNHVNBFhn3rCtSJNhie8aZAEzlW1hhj8E3
         ZrX4kasI/EKl54dpMyhZih0L0Kz1LxWyNF8g9OLNyQKurNLg156UqncdTc4nJ3nsa5Hf
         gMDyloPdTxOOInJ+MUP6AR4cISUAoKlsyY1gdaXGuxEbqFciRwlUdZ63jTmZ3Rg9KJzy
         nO3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772731528; x=1773336328;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DBkfcXHoLQ366Q1zQ+ts1UheyCH29qf5ckCTxRqip/c=;
        b=kJBMVlib2UvuFjtC0oGRk1V4J4te360W1f/FdhDGdR+CQ0s3mOeu2byICQvmOdLWEX
         zDPJgubGkwtLBOSBxOBuqJM5jfIH6eeBgs4a1f56dk00lRSmMtjE/BzsKxryW97ip7T1
         w1MXYPav2VsOFUaZ7psclNvKMilEtd/BpNfQZOOb6TafxQe18VSaIrZjxOM1j1v6sNvq
         kDbASzBi0lZ2/sCzV7XOtY4wNg5O48zXfnnxkzTaCMjayH3weYrlyim4u0M29XAxGDd2
         cUdX3aOYqZiJED3Opjh1c4hhhlqiKAfw0pA7mlZ7WE3pKn4qW6iASyfA5AeK0h62xF/o
         wSfQ==
X-Forwarded-Encrypted: i=2; AJvYcCVUBosCpJxK5oiQSvWscGveJ1nQZHOMsm08wt4JI4edIgeHBPCZySdLz8+7EarELYtVLOFsMw==@lfdr.de
X-Gm-Message-State: AOJu0YyFRmRXXAA9r7xLL9l4HywcbQWuCtLUhAn9owgtqx05Oh/WhnkW
	ZXudbh4AuGvlIZ5MdNL0ELXxho19BeJ+K74e3TseNEUW7YcETRlb9RNd
X-Received: by 2002:a05:690e:d55:b0:644:795a:391 with SMTP id 956f58d0204a3-64d10d477aemr464436d50.60.1772731528049;
        Thu, 05 Mar 2026 09:25:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GhqsW+SJKKw6xcsYM0SCHlAuIvoaqJ+l0TbMKcAzSOKw=="
Received: by 2002:a53:d987:0:b0:647:27b0:1a65 with SMTP id 956f58d0204a3-64d051b5622ls2115027d50.3.-pod-prod-09-us;
 Thu, 05 Mar 2026 09:25:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVpJhPLLK7HGVKBw1zx+KayChLEIxSekyUCgl7y3wE76mv+MaVyz185haunROHoxS+chMbVlItEV94=@googlegroups.com
X-Received: by 2002:a05:6122:a12:b0:563:702b:e2ab with SMTP id 71dfb90a1353d-56b02f06e6cmr304914e0c.12.1772731526058;
        Thu, 05 Mar 2026 09:25:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772731526; cv=none;
        d=google.com; s=arc-20240605;
        b=RNqKClLShz06PiuQHOQXt6G1BonvHdeIYLNAQnjmdSRL6dO4oVfcNQutjuH2hlK7ld
         XByIF5SXrh2S9OXciJCOoi141bkiDpmkKmw9189GfmUTz1Vc682f8R8ldFZVXXX2YLm6
         PIHxQnAd8YM4BEIjTwkEBoKMz+SH6xJXGAZmSq0PpzKBJNvZO2wujWPL6UYM5oqy7T/b
         4+eQ4r6dV3HqaM+pjwVy90LG5FTeVKULDkUAIcNj8Dl8YasCCzxERL+75YIdWwlkMkJC
         tk57IfeFQWZ/D1Luy8WnRJ0Tq6vZSiDwA7mrbXO7sUiLTg7H2UtjRGHKoUxOuOxg687f
         kGPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=51pbCajjJjxQcqWGmGHX0BbSDXEPSJxAv6lFVu3zB3o=;
        fh=EMmmqEWy6uNgx4RNxW9wJ1NEuwnss5C8quQK6gK7iIU=;
        b=GU56rUj29c9QQsB4LVsRxPz6xt4rm6QQ3vR7+iXGcWqjPaSGBaGVreQZIPtJRAmhpf
         KcnB72Z8XE4o3X9H6dkjOkrI8FAw6X0KVPmseA7zFEPQ80nHIyjUrUgTR8l8YuFNZ0Gm
         GMogbdvM3IS8CE8axyCwhd3/BMNWX/WFzRLNY5cRXN1MEnXU2AUzbt8/blo+l4gvsrc6
         uL+UvFQr3wQT/HU0T8UjWDQ0tKzFfS6vr4RKTE3lf27VEOTihNkMOwVDCnW9kgsQdLT5
         3cr4r2qKOOVRg//joLmfiYtVlWsihJVLv44koOzjyudkO7nO17UQrlq+8v5gD4usoKbc
         Y1JQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dpa+omYb;
       spf=pass (google.com: domain of song@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=song@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-56aa499b469si686753e0c.3.2026.03.05.09.25.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 09:25:26 -0800 (PST)
Received-SPF: pass (google.com: domain of song@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 78D1F60053
	for <kasan-dev@googlegroups.com>; Thu,  5 Mar 2026 17:25:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2D017C19422
	for <kasan-dev@googlegroups.com>; Thu,  5 Mar 2026 17:25:25 +0000 (UTC)
Received: by mail-qt1-f177.google.com with SMTP id d75a77b69052e-5069df1dea8so67163811cf.1
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2026 09:25:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVMm11XbJxuN5UUlylIeMvnMPn7WLfL407hDffatKAmJFMAgq1YAKpsHArnyiaKLFjg6ycN16JrTwU=@googlegroups.com
X-Received: by 2002:a05:622a:130f:b0:4f4:de66:5901 with SMTP id
 d75a77b69052e-508f1ce585emr5848801cf.5.1772731524389; Thu, 05 Mar 2026
 09:25:24 -0800 (PST)
MIME-Version: 1.0
References: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org> <20260305-wqstall_start-at-v2-5-b60863ee0899@debian.org>
In-Reply-To: <20260305-wqstall_start-at-v2-5-b60863ee0899@debian.org>
From: "'Song Liu' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2026 09:25:13 -0800
X-Gmail-Original-Message-ID: <CAPhsuW4gMUoaNqBX3vAzYezXjpY2cFkhTEbTYAEATYTFvYU5-g@mail.gmail.com>
X-Gm-Features: AaiRm509JctOsskwVada8G7pyGAI3LPOWEOIdW-Okq6l-9PihECFS_SINdqTU4Q
Message-ID: <CAPhsuW4gMUoaNqBX3vAzYezXjpY2cFkhTEbTYAEATYTFvYU5-g@mail.gmail.com>
Subject: Re: [PATCH v2 5/5] workqueue: Add stall detector sample module
To: Breno Leitao <leitao@debian.org>
Cc: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org, 
	Omar Sandoval <osandov@osandov.com>, Danielle Costantino <dcostantino@meta.com>, kasan-dev@googlegroups.com, 
	Petr Mladek <pmladek@suse.com>, kernel-team@meta.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: song@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dpa+omYb;       spf=pass
 (google.com: domain of song@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=song@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Song Liu <song@kernel.org>
Reply-To: Song Liu <song@kernel.org>
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
X-Rspamd-Queue-Id: A675F216282
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TAGGED_FROM(0.00)[bncBC4ZB2GTVUKBBB7ZU3GQMGQEMSMQRZA];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FREEMAIL_CC(0.00)[kernel.org,gmail.com,linux-foundation.org,vger.kernel.org,osandov.com,meta.com,googlegroups.com,suse.com];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	MISSING_XM_UA(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	HAS_REPLYTO(0.00)[song@kernel.org]
X-Rspamd-Action: no action

On Thu, Mar 5, 2026 at 8:16=E2=80=AFAM Breno Leitao <leitao@debian.org> wro=
te:
>
> Add a sample module under samples/workqueue/stall_detector/ that
> reproduces a workqueue stall caused by PF_WQ_WORKER misuse.  The
> module queues two work items on the same per-CPU pool, then clears
> PF_WQ_WORKER and sleeps in wait_event_idle(), hiding from the
> concurrency manager and stalling the second work item indefinitely.

Clearing PF_WQ_WORKER is an interesting way to trigger the stall.

>
> This is useful for testing the workqueue watchdog stall diagnostics.
>
> Signed-off-by: Breno Leitao <leitao@debian.org>

Acked-by: Song Liu <song@kernel.org>

> ---
>  samples/workqueue/stall_detector/Makefile   |  1 +
>  samples/workqueue/stall_detector/wq_stall.c | 98 +++++++++++++++++++++++=
++++++
>  2 files changed, 99 insertions(+)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
APhsuW4gMUoaNqBX3vAzYezXjpY2cFkhTEbTYAEATYTFvYU5-g%40mail.gmail.com.
