Return-Path: <kasan-dev+bncBCB33Y62S4NBBDEQ4SZAMGQE3YE7RKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-f187.google.com (mail-pl1-f187.google.com [209.85.214.187])
	by mail.lfdr.de (Postfix) with ESMTPS id 10C378D5618
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2024 01:13:19 +0200 (CEST)
Received: by mail-pl1-f187.google.com with SMTP id d9443c01a7336-1f623f4a6b9sf358225ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 30 May 2024 16:13:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717110797; cv=pass;
        d=google.com; s=arc-20160816;
        b=i8J11aQxnU7adlteUeIoSIxqhzqsBUFwqW0KaEf6wNj8fq4URR1UhuSONH1hchhzf1
         NbMxkB1drefy+loX8qHnyHuHHv4ztckdmPWQ3Tks6xvsEKw0tPEU3k2m2fIkfSQ/FMJE
         MJd5IhVviJ/CEjz7v6NS+0oNdIQ9cAlDGLtREpa+ncB0ox7P3XBYhLuRx6yMQ9s6ucxR
         eODOuLliaGGeBRz70me46Tle8Pgq59VL6FbkzuXWg3lvsjQBd0WchIHu51Vrmrb3kxyr
         rlluX7oyiTbUFxhD41vtpK76hFY3rdi0GysEIKZBQhI7hanmsEqAmxNFl2wMGxlsUEiP
         rqow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=oikoOJYyThrPwBotWr2dInKV+ZoIyeb9rbQs0sdAuNw=;
        fh=nRdbipr2mU+GVAQDhofNeMljv6wTJDwRMKEVE3dRkrY=;
        b=RvJ9C7Vf0FnfMIej5s4wQj6SFx+grF4FQ2da791tyGcS7lN1wAx0Drle11mjW+J5nU
         AmGjGWVOILB5Z7Zus+SoVjv7ZqhpQcEfKsWAMsUUvmRzRxxDPGTNIk3E+lD/6P5RBGhf
         OIsQfqyTYx5C4M/9Zy8CvXnlOBPsXNSlrPamRmK5Y4v6TvLfXbEnBiQx/14P/NrrMvbA
         H0nQhlfR3nQQNnesgRR41LPo/ssXWXeE2Wu1UFjEJ6G1Z3iSq1i546z9oOFlepDJjuVl
         5m6208k6+4r+ezIiAaZInwtMsXa60A6AlmQl7DFc9I93X0RqK4wGWorNL0QdHqzsOKYj
         N6qg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=posJuOdl;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=mcgrof@infradead.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717110797; x=1717715597;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oikoOJYyThrPwBotWr2dInKV+ZoIyeb9rbQs0sdAuNw=;
        b=qVPcBQ+uCV8ELZjfhkKvirFo741qRw1iOMyq10zQFLBMg056kj8eyRVsWDe25U5NUF
         3T4UaGkqfmvsBsuxc+Y+pNa9BMYoM33T/Ijnu7KzQJ0FH5D+1hNac8BsF8DzMyOu7cQU
         ZU3Gu19+PQiwFiNSpz8eAVyGHr1FJaBwGRtJiS5imkQU2skQPW1cWOLCMR8KFRxB1ZMM
         GZ8sqpj7aXyi/qvdTJyCF98RrPthUbCpQXKHDOhZdrlLiYVuTX8GO0JGQmL8lm02Qy+I
         RRkgWj8WmD4XluCxQQTy9wzHSgPYs6P618OiH6ESuxeVx6nQDwSP0wkx/MUC05n5dvk0
         qU4A==
X-Forwarded-Encrypted: i=2; AJvYcCWv1TY2LrLI+Zd9fjIrDA0Cy/zgHvPpklE6Hbk8Ws92ZsVq+FhWzrGoQtgFWafSgsDUbLhk62YQsv2ECm15mgleKO7/TYdaaA==
X-Gm-Message-State: AOJu0YzgLfd0Pta4YrN9COgvTUktL/TGGRncgWOZxezGJOXNqoYHfO8F
	dklApr9WaNw0jASLREST9csFrxXiZNwKiwZ3MEBCNdUzGqi0QZBL
X-Google-Smtp-Source: AGHT+IHtiGNg/7FwNKcBroY5RXc97/Sm6/1gr5ghr4HWLoii8KZvVGRjmryk5DpVvUZkrf/DfjICjg==
X-Received: by 2002:a17:902:d586:b0:1f4:97f5:d9d6 with SMTP id d9443c01a7336-1f6371b2251mr264165ad.3.1717110797126;
        Thu, 30 May 2024 16:13:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e253:b0:24f:cd4a:af94 with SMTP id
 586e51a60fabf-2505f9c078fls1339145fac.0.-pod-prod-07-us; Thu, 30 May 2024
 16:13:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW06XkBdXNTzV7YAasI2pg/tHSwBBxhSTyysCMeZpW0VtqcEz/rRjkgfe8fwofbxJ1zJU3F+HNPaG/LgwMJG8E/y0uWIDrttd/RSQ==
X-Received: by 2002:a05:6870:1647:b0:23f:eb80:2f14 with SMTP id 586e51a60fabf-2508b80d8d2mr362563fac.5.1717110796171;
        Thu, 30 May 2024 16:13:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717110796; cv=none;
        d=google.com; s=arc-20160816;
        b=Y3vorMxjYKFL992nxFJSemBmSZSmrd/LloXt+BnjoadU8d+37yLo10p1GV5xJC13GX
         We+Myw8aLlbhHXtVANWK1hiaAJrvKK2sbd/SiXd76PPi3SI4rBEQk5c5mhAZ8vJ0qt/g
         YJ2ZrRE8+UU55oYphitEupqg5K0NIEPF6TmWz/O3hAkA1fvGOy4MXdpqvWasprDjYeQa
         LIdA/ZZ6t+dz3V/u2RBWrjUz7aeJxO74gHKWCr6zQNk8o/Uy3egKubIAqr925Ncbe3cZ
         fZrzAIvBd/UEREpfdQXLNR3m3iiw8wslvfM28HBTaWBSkUVSDdHJ3JtuSjyiCDOsRPkQ
         MMZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=89rvWf/4Tfim/r3IdL4EWF39hSjLRqnEGNhNF2V+WL8=;
        fh=yl/ALPbvnv2NBiNWlhzIcCh8NwE9xddakicEQ36fP2s=;
        b=zrZApOp1+rm8d1BQNIbdZ6YO7tyBZ+p1oVUdPBodxTUG3QkcyIbAN0cVSE2Xm55gAk
         Kbg6p/lY2EXOKLlPcLuvVukqsSJSdE8+/DBdy7/uIJ8BOt6e7KZlGOCgxL7GyKSHlAlS
         fMMD2Xo8EnAME0oLanrdWrIzYZdSjsHRrBiayDALXqcoppRbb2VPVoHvOmwgoJ8rYMMd
         JdeUaaHufKL70j9/uaWq07wANfM2DRvbBfRL6BWj88m5ek0Q5P1SikhUWpZODXwWc6VS
         g6umr1d5f1PVvcAtNb7xZd9ldZfssm3+hmInIrt9zvscqqN7fbZioGEyY45RmcmvmTXw
         OAxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=posJuOdl;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=mcgrof@infradead.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2508550b3a2si59510fac.5.2024.05.30.16.13.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 30 May 2024 16:13:16 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from mcgrof by bombadil.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1sCoxM-00000008fIm-2CRu;
	Thu, 30 May 2024 23:13:12 +0000
Date: Thu, 30 May 2024 16:13:12 -0700
From: Luis Chamberlain <mcgrof@kernel.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: linux-xfs@vger.kernel.org, surenb@google.com, linux-mm@kvack.org,
	david@fromorbit.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, kdevops@lists.linux.dev
Subject: Re: allocation tagging splats xfs generic/531
Message-ID: <ZlkICDI7djlmpYpr@bombadil.infradead.org>
References: <Zlj0CNam_zIuJuB6@bombadil.infradead.org>
 <fkotssj75qj5g5kosjgsewitoiyyqztj2hlxfmgwmwn6pxjhpl@ps57kalkeeqp>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fkotssj75qj5g5kosjgsewitoiyyqztj2hlxfmgwmwn6pxjhpl@ps57kalkeeqp>
Sender: Luis Chamberlain <mcgrof@infradead.org>
X-Original-Sender: mcgrof@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=posJuOdl;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=mcgrof@infradead.org;       dmarc=fail (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, May 30, 2024 at 07:03:47PM -0400, Kent Overstreet wrote:
> this only pops with kasan enabled, so kasan is doing something weird

Ok thanks, but it means I gotta disable either mem profiling or kasan. And
since this is to see what other kernel configs to enable or disable
to help debug fstests better on kdevops too, kasan seems to win, and
I suspect I can't be the only other user who might end up concluding the
same.

This is easily redproducible by just *boot* on kdevops if you enable
KASAN and memprofiling today. generic/531 was just another example. So
hopefully kasan folks have enough info for folks interested to help
chase it down.

  Luis

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZlkICDI7djlmpYpr%40bombadil.infradead.org.
