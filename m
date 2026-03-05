Return-Path: <kasan-dev+bncBC4ZB2GTVUKBBKXVU3GQMGQERB66OMQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id yMkvL6y6qWnNDQEAu9opvQ
	(envelope-from <kasan-dev+bncBC4ZB2GTVUKBBKXVU3GQMGQERB66OMQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 18:17:32 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C33D216066
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 18:17:32 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-50340e2b4dfsf136885221cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 09:17:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772731051; cv=pass;
        d=google.com; s=arc-20240605;
        b=MeKhfWlgXFhd4+WtrSptc3To7AyEP7gehRAMLzqbucx26GYBphdI0kmYmVPB4FbOf3
         hOb69ObOnLBOWczGfWngzGj0AJgCRIl2zpLdEPqtahKKUhhb1C7EVYoa5dctwMjftMJh
         zJXMLTTnJ+2T3rHnAfTOuYR3LrX/kFa6Szy6q6ZBw+wpELPnztxg9YW+20JCzQdCRQNj
         hJ5dQ3MfuOdXsxE65jlXN3dktcFFmJkViURsqO2+DBWWhC8LpgVTSRTO3Lb3V/yBgtJb
         U5xsfdFb84WZ6dk4JzWdW1/tg5u1lsDRS4yMOOgvn1vXZdz8GAmVj/RZzcbmnbn+z8TI
         Hb0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lBSVAvxORfYzEVD8XBcXqROcykY6W0QCIGZJndCd5G0=;
        fh=2e/3IWSRAdANojYPYQsXy1beJ12Ee6cdKIIjgd6/1Xs=;
        b=i75h7oLHREQV3j5sf7LK/L/yifB4noCarjEJN+iymOto3ZLv5Ya/o97E+MXHJqpfzB
         29ebwz+pNcPP9pDPOHbEtjZ4xRmBd/HWcqvObXP8q7LjEG/+4dH/Cky1nh435Fyi6dBV
         pvQemQs7P9WPp2DFxdnulMdVOvvk91hHUyI7gt4ctHNp6+oAG1vOOBLreQhJlZ192quK
         6CBPORaI5ZXa7catq7NueSc0tR5cA4zS3VsFKE15PjVnXHZ3HNmuINKneBU2a7mnb+ME
         AMab8sv+STp7A+9WKyyLKx3EA3NsFyTaK7xw5gAGVHUbr3OUHrzBojBYH5GCQ7HZfOlp
         9Nrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kKBAHFfL;
       spf=pass (google.com: domain of song@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=song@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772731051; x=1773335851; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lBSVAvxORfYzEVD8XBcXqROcykY6W0QCIGZJndCd5G0=;
        b=YgoSW+96XZo1Vo7p5dVN6DHsmVYK/hto/Vcg6GOGCDNWhE2nsGSMAVotbAe10lQbEo
         PdZTV3k3s6q/36WvdeKvauqN7A0CjMiYeYX3WMBAbTKYFNgySOux1uPKruNXU7/UkWEP
         1ct8tFk6ab5rZjFdmWI0cYzSOmFMvTWnS/zlf/cRJUrZ3PFwzOjMrcW0IH7BUWIl7Lp3
         x4alOIJwRq8dkxyY1TMr6nuBmEv/wgOfORjFyPInYmIDGZMYsMKsD36Q/SenC9MBntwu
         qzUz/BgryyYEomIX2AjErsWAknGBGyT4AMpmiWoKuoS4JJwogPTqoCtxFdnZzHGyXGx0
         WiIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772731051; x=1773335851;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lBSVAvxORfYzEVD8XBcXqROcykY6W0QCIGZJndCd5G0=;
        b=LaOwXbocnz3Szjt8YaTMrvcXhCxfPEEn95+hOkYewD1fxhH3mrgHQ7TO6B0sEgLOyt
         J49s6h8TshixNgW29rSk3QQCfVHYG3xskVWkNyfWXS5/GcCmh4qP1F/sftIBaUHnf/Jt
         2zLar7GMMywad7eyE2xnmFxxw+vzcvbSLfRPHXZ21Z+bHRK/Nu3s1JIng/dSGB4kvdv9
         Picp2h4Zy4NiCUUNYI8FxZLXRiwpV824aO8TF35hOA9/nN45r3HnbKy2FrHANLuWFsrW
         GN4N9kNczumUMzl0b3IlCTEvQmSU6BATN4+t8dzWI7uRpTtd/SyZviplPEkZV3F/IV0r
         RC8Q==
X-Forwarded-Encrypted: i=2; AJvYcCUcw0vfidcw3IDOrorDfimwoa2S7Io/waxYSMiDXAZFL/NPa1cV3FYRBAOKTRl0U647Gys3Ow==@lfdr.de
X-Gm-Message-State: AOJu0Yzjv9J0/xyxGbhTCZSFaEd88JHBJPBvXarh4Z4fmoYRA9bvCEid
	TWru8jniMHqQC0q8q0vYGZoohblzx0/oRbu6KS1wg6QCSm63uf61oC9G
X-Received: by 2002:a05:622a:2cf:b0:507:3d1:ac67 with SMTP id d75a77b69052e-508db3673cfmr78509901cf.57.1772731050933;
        Thu, 05 Mar 2026 09:17:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FAZRr55afP6cqYBS29PeA70pMlpckan3VvLVetrGv0yw=="
Received: by 2002:ac8:7e86:0:b0:4ee:419f:87ab with SMTP id d75a77b69052e-508e4585b50ls19764201cf.0.-pod-prod-04-us;
 Thu, 05 Mar 2026 09:17:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWOuj2U0mFFojCjSAq3L3KM8piUayNR+F46/bKR9lP+wZqJw9nS5F+Ad93XHDNzxj7kdgsJogaGqm8=@googlegroups.com
X-Received: by 2002:ac8:590d:0:b0:506:9d3e:67e3 with SMTP id d75a77b69052e-508db3ad17cmr82338381cf.70.1772731049931;
        Thu, 05 Mar 2026 09:17:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772731049; cv=none;
        d=google.com; s=arc-20240605;
        b=l3gbHBbVmglWARK8AZ3gpqqgkO+IIzCCMnoRLlMr3UuhYEszk8pBgUZpwh9IxM6h0a
         G9PghRkgkAJOpx7ocoiWUBVNOlA75xBMz+mTZF1chiWaBfmLALSpWkWi1ic36HwJ8MeN
         TjY6SDck4ZPj3L1UFHSLCTrq1BTWeGMIiSI/Uff6kBtsbwFMthFvz79FBvO6+1vhzlnH
         CaM7VfBj39BEuxhLw9bgweIpks3dRWN8Usd/M/yUIeOzBmOstWSjfSrbl5gMCA1MRkim
         Uj30x9Vy/DL35lzplLzv0eqNH2svwL+vd4nsfeNw8VficZvlwlIYE9+rmytskFdCR5U8
         s0Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SH7RrdV8/JZHeMk1NyMNCILjIO4fg1VicUgRHbjqCwo=;
        fh=PI3V9wkH+vJonDPuri0Wi+IcwcVh+ViS+/L4/QEdYJI=;
        b=Z/D+syn13+DFs5rIPSaPIhVCMAdPwwo9/IpRTClCyrEO7zluSaXsxL0hR5OHHDQfwK
         47iXjTX/H7QxuQ7KQeY9JxXLLupNZIpGIQ5Tdzr7V8maeUp6xEJliDq9W33KP1vi5AbD
         3VNSKf2PaRXqaYfZhvH3XT3naYD+HizMUNmqH3NLNwy6Nun0VL2AzSyfIiY7lPJxEPvG
         DGa5RdO055/ljxJyIOyfGFk5OffZ7mtlvzN2AoDcbmtap7/RjXMOmetu8e/s42t1m6Ss
         TerbSLzLIh3WRdHKR4bOsHLxiFZq9UOkG83k6F2KE+SF4NpCmW97Ktxj8G5LVKI1pkPP
         4LqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kKBAHFfL;
       spf=pass (google.com: domain of song@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=song@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-5074497abc2si8217791cf.2.2026.03.05.09.17.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 09:17:29 -0800 (PST)
Received-SPF: pass (google.com: domain of song@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 2B81643B87
	for <kasan-dev@googlegroups.com>; Thu,  5 Mar 2026 17:17:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0AB8FC2BC9E
	for <kasan-dev@googlegroups.com>; Thu,  5 Mar 2026 17:17:29 +0000 (UTC)
Received: by mail-qv1-f47.google.com with SMTP id 6a1803df08f44-89a1347051aso48911036d6.2
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2026 09:17:29 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVdmgsWF/KFEKMv9SJeX4gMIRaZIXBvbb2n66fwt3WNW5tmv81dih6jC8/i5p47cQD2MMXlOrQIkLo=@googlegroups.com
X-Received: by 2002:a05:6214:5293:b0:899:f8c4:51 with SMTP id
 6a1803df08f44-89a19af26a9mr96102756d6.28.1772731048200; Thu, 05 Mar 2026
 09:17:28 -0800 (PST)
MIME-Version: 1.0
References: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org> <20260305-wqstall_start-at-v2-3-b60863ee0899@debian.org>
In-Reply-To: <20260305-wqstall_start-at-v2-3-b60863ee0899@debian.org>
From: "'Song Liu' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2026 09:17:16 -0800
X-Gmail-Original-Message-ID: <CAPhsuW73MJjtSmKd=OdYJHN9P43YK-YtRiSVLLTZtM3KJQ0fFg@mail.gmail.com>
X-Gm-Features: AaiRm51q4m2a6hpsXuTCMRoLVeqh8cD3ZOQMgbjNHeSn1geaaVZbPd0t_25V_Cs
Message-ID: <CAPhsuW73MJjtSmKd=OdYJHN9P43YK-YtRiSVLLTZtM3KJQ0fFg@mail.gmail.com>
Subject: Re: [PATCH v2 3/5] workqueue: Show in-flight work item duration in
 stall diagnostics
To: Breno Leitao <leitao@debian.org>
Cc: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org, 
	Omar Sandoval <osandov@osandov.com>, Danielle Costantino <dcostantino@meta.com>, kasan-dev@googlegroups.com, 
	Petr Mladek <pmladek@suse.com>, kernel-team@meta.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: song@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kKBAHFfL;       spf=pass
 (google.com: domain of song@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=song@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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
X-Rspamd-Queue-Id: 5C33D216066
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[kernel.org,gmail.com,linux-foundation.org,vger.kernel.org,osandov.com,meta.com,googlegroups.com,suse.com];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_FROM(0.00)[bncBC4ZB2GTVUKBBKXVU3GQMGQERB66OMQ];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MISSING_XM_UA(0.00)[];
	HAS_REPLYTO(0.00)[song@kernel.org];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,mail.gmail.com:mid,mail-qt1-x83f.google.com:rdns,mail-qt1-x83f.google.com:helo]
X-Rspamd-Action: no action

On Thu, Mar 5, 2026 at 8:16=E2=80=AFAM Breno Leitao <leitao@debian.org> wro=
te:
>
> When diagnosing workqueue stalls, knowing how long each in-flight work
> item has been executing is valuable. Add a current_start timestamp
> (jiffies) to struct worker, set it when a work item begins execution in
> process_one_work(), and print the elapsed wall-clock time in show_pwq().
>
> Unlike current_at (which tracks CPU runtime and resets on wakeup for
> CPU-intensive detection), current_start is never reset because the
> diagnostic cares about total wall-clock time including sleeps.
>
> Before: in-flight: 165:stall_work_fn [wq_stall]
> After:  in-flight: 165:stall_work_fn [wq_stall] for 100s
>
> Signed-off-by: Breno Leitao <leitao@debian.org>

Acked-by: Song Liu <song@kernel.org>

This shows really useful information. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
APhsuW73MJjtSmKd%3DOdYJHN9P43YK-YtRiSVLLTZtM3KJQ0fFg%40mail.gmail.com.
