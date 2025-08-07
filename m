Return-Path: <kasan-dev+bncBCT4XGV33UIBBDPKZ7CAMGQEPW3NVCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id BCA66B1CFD2
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 02:36:30 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2d9e7fbff93sf755638fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 17:36:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754526989; cv=pass;
        d=google.com; s=arc-20240605;
        b=jvoRwQtzktUbBMBGksk1TaoRjum8QU4N2g/7+R/yTSUAmTEwB5+Vgk18ZSscX3rIqD
         gNwjP1fezr5eKTVrRQRZEz80kvlNd9DbyHLhKIOj7zJJOwoFiZIT7KjQFs0M4DyhH3qd
         lqTK0zCYq4S2L8SfN6d7pyGuRcBw2RkOQ37zOYaA15G58dFhcVc6Kd0dvwC7DTz6X13C
         TLNTwrEwgTGhdFs84xisUs0vAzsehmq4Ae17Sqe2Fzwlut73tTj+hpf2xMAwTtpSnDIg
         yp+BRzfDLRHvtPEkCVSyvkjLGN12jW1CILEsf3WRotmi3VWIjcmukRTdOC8LE8/inTGJ
         aiiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=l3V58kc/7TqayIzhrPLuhDU73pVWiOEKYKCNFSOrPE0=;
        fh=JUDS60qnyMTCLXpijhzS5qCWy8lvGWBAh/kpGVE/V5A=;
        b=Ehw+FRHIlwjR08vjA5P/cI/hS4KbOuuGWLFCtVn6YOGLHOG61m3G7g3RYhYGHfE2eG
         SAoUw/3EQVaddTbZt2L6t2tDxek13XD7vSZks0dNToUniyQOtHPLauAl/XAPueyN/Joo
         ydg1VViHPT56nsvZ/Hnak5kk2aadsptUBJw+fI4XDdHGPiqAvxKGVgSrO7i2egCzTS90
         DAQADL5Rdbn/KaFWQEgp1FXO+5cTnHZyW/RHItjyMCXD23/p5F991+Tg4vh3fALp06/H
         Q3YUbtlnToE1LTYVf8LyE9NoP4+dG5lk2G67tStV+JzinURz3VUFeIz5UTNwv4bPjMNI
         NvNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=br7YcBeq;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754526989; x=1755131789; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l3V58kc/7TqayIzhrPLuhDU73pVWiOEKYKCNFSOrPE0=;
        b=Rhyckg7yrF+wlqlIt1aU8Etx27shUA8PysKTY5X1K9oJjUlodwbcKkdTx5C7BmbR2o
         xhaMnFfxp8TrnxCzhAzWVt/oeTOvyj63yn4ZTjcXVwqHKGWKLjfUzR3ykE8fOtLPMe7e
         J3oXIOjpYUqXMNUCbibO6RWIYYwEAqwCU5MYbrZwIkh6mk2BRzlA5KugKD0uAg6/PlUK
         IGaH7nTFxz+Nl/GBmbce8N0DTNADsXlyiwGhByO1IJVt4jRTIkU0Im2WfQ+HazphSU9t
         VlRTR6krCnbtJF+2+OFPdb6Hh7jW+bPuluLO+JZD4lg0F+aYQE5GgtyJtTKpRhbDyUqj
         TuTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754526989; x=1755131789;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l3V58kc/7TqayIzhrPLuhDU73pVWiOEKYKCNFSOrPE0=;
        b=iN5+oK+KhXcCxRHLQ884wSBzqhQY/jgCEsybSWe+jKWNckutr7XjO8T7WL3hrVbUbV
         0/aqkV5NWa1TdxX1uE2UXiYJDhFk78D/My7IuoQIQ1IR80cUD2vZmeizOxEK3/wx3u+e
         Z3sLPYxk62pH92M4gpeLvccfEPD2VHFBydxceKaVUbAqdWNOZSGl5wp9AEZ+2gtwR1ue
         hprsmwnQd1pdHdoeOg+gvHEBX3zF2AyN2XdbwS1frAu3B85DiitkzRIFZOwBokATD87N
         68rHggJaKBzwFGKEDR6eAYJTxiqsFmCTnjB+6rG66uqe9QrJWDM3ERTfR9BC39SLq2kO
         +dHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVWPvtmAn6no85m0JseWL3eD7/vJQ+uLoszUiWwcibjBgyicdaWBXA+xt0wg5BgLsst2kV3CA==@lfdr.de
X-Gm-Message-State: AOJu0YzQ1BBtOKrsWEGl+sFm1LO9M+Au3x51OGpTOqDN+FKLqoU4C+Y7
	pH9qcHKV3amccX9Oot/enEfnovifhjMwmjSeVROZubhV9KVcbYfqDuTq
X-Google-Smtp-Source: AGHT+IGeHFvTvaoD2rD+gJG+/wi2557JbApZKtBYRDETyAW9OyQL0RhqVe/vvd7q732bT7KsdivXgw==
X-Received: by 2002:a05:6871:6608:b0:2f5:2bb1:e85e with SMTP id 586e51a60fabf-30c01b0f06amr977389fac.24.1754526989401;
        Wed, 06 Aug 2025 17:36:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcfi94qKFMMRgCph7lSROacoi/P8gcRq4R900HiO+G+ww==
Received: by 2002:a05:6871:88f:b0:2e9:9a5a:7609 with SMTP id
 586e51a60fabf-30bfe70c21fls275975fac.1.-pod-prod-01-us; Wed, 06 Aug 2025
 17:36:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLLQTEEc+JBUdbcNprxS25tQTaufYab+zJIOssFdubhRPiFgSJEf7Ym84vj1kEsLjYKdq7Upxd6rY=@googlegroups.com
X-Received: by 2002:a05:6808:1489:b0:434:4b1:b650 with SMTP id 5614622812f47-4358866305bmr991221b6e.39.1754526988527;
        Wed, 06 Aug 2025 17:36:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754526988; cv=none;
        d=google.com; s=arc-20240605;
        b=TfosEzonCtd18SgbRJC1PnUGH4ihVmtXsxYaI13eZQBksNIXMkqYJR9qptVSf/L1Bw
         4+ogVhUhPQKG1oP4Hp5ohVel1XL6i5ydkJvoW5tctzBMt0GXKTfz5Ny+/ByUlFLwD/eW
         no4HUraygr2FE0D26TziEoZyCYeStSHg47Z2idcdweztln4NetxWbq36JREiOJsSgW+O
         Vzi7ajCHsxUy2rf2rJilhtdd3m0TjeUrNucdkztuDukyiWjCCJZP+tzW27Kp6uAuVSZ9
         BSPL/eNF4Xw2Nhvlj6cvJ2Hw8cRld0KM7YZklTfK1vLajGHiOuJe+dy+udlKrGL94IPg
         fJaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ugXEdZ7ARK/SWzyDGP9W7HvSHCAHcHLp927oWCWgr24=;
        fh=2H4v3pNyafUT+Ubytf6ML2q+NA8gAfpa/ojVGVS5iHU=;
        b=JZ2qWvzkbGCztdu5MCLWwY1HnXo394gPoDRb1oNY7TcUOhdvgip9WzepFTap6yvZic
         tX3NgYzTAp5U0ZAQDJVH65hDFsRGwlu0wQbOclKZVW7kFZFr7AbnZ8DFZ0ae8z/vW0Sz
         s292pCYAL25bKvBZzQZ+FbyAsVV4aq1vnS/LuXkxo1x2Sz6Vg1h5uh2nVVK7DKbA21Fh
         1ZAgOO+/+aAw+7MdJTbt1kd4yDPEpFQBd1wTeZ9dUmekkfJwZytQhzornBFgvdbEAdLe
         ZH4Ok4NEPZwc4sjGbMcDY/prSqk7SDgh1Rmkc5mn09lK+50ggQsu1cQ6He/u9GCFY8z2
         rCyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=br7YcBeq;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4356ba3050asi226415b6e.4.2025.08.06.17.36.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Aug 2025 17:36:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 81086601FD;
	Thu,  7 Aug 2025 00:36:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 522C1C4CEE7;
	Thu,  7 Aug 2025 00:36:26 +0000 (UTC)
Date: Wed, 6 Aug 2025 17:36:25 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Soham Bagchi <soham.bagchi@utah.edu>, andreyknvl@gmail.com,
 arnd@arndb.de, corbet@lwn.net, dvyukov@google.com, glider@google.com,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, sohambagchi@outlook.com, tglx@linutronix.de,
 workflows@vger.kernel.org
Subject: Re: [PATCH v2] kcov: load acquire coverage count in user-space code
Message-Id: <20250806173625.f83a6fc9da16099e8ae12c85@linux-foundation.org>
In-Reply-To: <CANpmjNNvsJ_u7ky+d1tiXtwc-T3z6VB4SiMqpo6aKWBBFO3ERA@mail.gmail.com>
References: <CANpmjNPWzJZrAFT3-013GJhksK0jkB6n0HmF+h0hdoQUwGuxfA@mail.gmail.com>
	<20250803180558.2967962-1-soham.bagchi@utah.edu>
	<CANpmjNNvsJ_u7ky+d1tiXtwc-T3z6VB4SiMqpo6aKWBBFO3ERA@mail.gmail.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=br7YcBeq;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 4 Aug 2025 08:00:00 +0200 Marco Elver <elver@google.com> wrote:

> > The load-acquire pairs with the write memory barrier
> > used in kcov_move_area()
> >
> > Signed-off-by: Soham Bagchi <soham.bagchi@utah.edu>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> 
> > ---
> >
> > Changes in v2:
> 
> Btw, it is customary to send out the whole patch series on a version
> bump, even if only one of the patches changed.
> https://www.kernel.org/doc/html/latest/process/submitting-patches.html#explicit-in-reply-to-headers

Yes please, try to keep everything together.  We look at a lot of
patches!

I queued this as a -fix against the original
https://lkml.kernel.org/r/20250728184318.1839137-2-soham.bagchi@utah.edu

--- a/Documentation/dev-tools/kcov.rst~kcov-load-acquire-coverage-count-in-user-space-code-v2
+++ a/Documentation/dev-tools/kcov.rst
@@ -287,11 +287,6 @@ handle instance id.
 The following program demonstrates using KCOV to collect coverage from both
 local tasks spawned by the process and the global task that handles USB bus #1:
 
-The user-space code for KCOV should also use an acquire to fetch the count
-of coverage entries in the shared buffer. This acquire pairs with the
-corresponding write memory barrier (smp_wmb()) on the kernel-side in
-kcov_move_area().
-
 .. code-block:: c
 
     /* Same includes and defines as above. */
@@ -366,6 +361,11 @@ kcov_move_area().
 	 */
 	sleep(2);
 
+        /*
+         * The load to the coverage count should be an acquire to pair with
+         * pair with the corresponding write memory barrier (smp_wmb()) on
+         * the kernel-side in kcov_move_area().
+         */
 	n = __atomic_load_n(&cover[0], __ATOMIC_ACQUIRE);
 	for (i = 0; i < n; i++)
 		printf("0x%lx\n", cover[i + 1]);
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250806173625.f83a6fc9da16099e8ae12c85%40linux-foundation.org.
