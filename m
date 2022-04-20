Return-Path: <kasan-dev+bncBCV5TUXXRUIBBGHH76JAMGQEXIJVE2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id F30D350875E
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 13:50:49 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id sc26-20020a1709078a1a00b006effb6a81b9sf849069ejc.6
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 04:50:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650455448; cv=pass;
        d=google.com; s=arc-20160816;
        b=LWJ49zSWJ7Og7/Tx7zlfdgWJFKISi5svwApe2KbzK5hPfTqc1+FGVt0GndxRmkeSQA
         vmaRwIC7AGV/dZHjU56II136lfnZDrjDydKwTGtyo8Kh0dVHPi7b8Xtmr1KdR6+BRWlX
         K1Kn29B1BV4qoshOHBAdOylaLkpqOGhVsyx6gAUrztf4OzwExX17cAccPfhG5FSoT1ve
         tgY6zXmpa+zEbXwLK0aL81ait9jTxNMeVh3+Win4orq9Eetsao+DBYreeP2NEM0OY1JQ
         Qq9qWPrBwz4hmCIyAxlRfz66y2Bc7eiqIJ9DcDZz0h47rBR7zW4M6KKRxMmCGw1TznM3
         5jTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KVub/MTCmH8t57y4XRcmbp0rF+C1knYMQZGfljdttFU=;
        b=z+HvSOHrm1CxsQOH+xsF9bfBgpwGUrBFFmvEobqRfevhEKPVhxJPuCVDlUOeK82tBh
         xrXYGZnncs2K/I2x4b5+bsURPB9gaXIacXmJlhjVEyo6Cb49KL42qQORDSbleLASBYih
         smqO0QCJqNMrg4RWN8CmlxJ6aWztiuIKPoGhVs1E3B7W9SSNzPgMn+aQcLAjeSRHXBEu
         Yrgyjif4WfOstAszrN8p5BSzFQ1ajKjLeSZ+34UpIxUFZ68qfmwPKeypipGucSY25a7G
         etoZYz81yR2K4ITuc4xOl4XESjeY2kO3jAMp6yGDQENVJhcyjjqd70eaxATBJWPScekI
         nFdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=p9kNFmSN;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KVub/MTCmH8t57y4XRcmbp0rF+C1knYMQZGfljdttFU=;
        b=IMxisiqRombEsZRpFrOQd8DLeFjTWg5YzUP4eFPeskzSsHkaIc+nRy7+gT8lP9naNA
         J7pcFjIjy/uAILDPnG8YNBmxR9//vxUGbTzygHocWbkXAcOPySgtyyR6kZsoZ+YHe72w
         Dh5SsjRNaC3c/BMmQiZgwX4XGEe5A1dRXA7g/8ckVavnmb33ZvmM5EObmScy8BV+PXgo
         oZ9mSxNPhKvgq+g5N4ZWmVyfwnyWkRcFb5HOl4mdjLHf+uHEcr/dQeePksC3PWPdgyUC
         3x9MWaZG4LqDxkZlSL3HMXHmH8MDnrdDm7Et3Ysx35DjLTBrvt8QnowHxHwhr55ATeQW
         +SYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KVub/MTCmH8t57y4XRcmbp0rF+C1knYMQZGfljdttFU=;
        b=eC6GHCPWbX9nXhV5EOUsyI1zZXKwnAfo9j54JcONO2enYpTiGsY6oPmpb/3T4b8yi9
         pR9UJyFqNQruRiOwwfdXB+y2s1EEjgL2s9TxUwaIUGUb5Gdfr/5EYYTSls5d4Q0tOLgx
         BDkRkg0poWAKqgXvVdTvHVK+1soDBjTY/i204p7VoI86JWsY7kACY2rX2E/LfhUPcSAq
         GiDTLSLn/zuTVPalwMjPrGt7xsJ59BTWXBP72tHZ4qUBbx+6hgxbzkvhWUN/YKk7IKTg
         LrECYENaDOs8HpNw2ptSofqnksVuPsBL/SpNNX78RNDnwbg+fHv0u5tK8o2+lj++2roY
         k+bw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531F+Qth9QMob2k5jlN7o36icR28WXZqf+hbLeYw5LbJ0NGIIPtP
	4asl8ZdJTJphkEUnv+QkIJI=
X-Google-Smtp-Source: ABdhPJxhNIWBhZAkgGEezyxrRnFU2KGW0Iz2wg86dkHiuCM3V7VocVKM5BemFosY8f5ux9iWTP876g==
X-Received: by 2002:a50:fc98:0:b0:41d:798c:c2c4 with SMTP id f24-20020a50fc98000000b0041d798cc2c4mr22563827edq.32.1650455448448;
        Wed, 20 Apr 2022 04:50:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2741:b0:41f:7eee:e393 with SMTP id
 z1-20020a056402274100b0041f7eeee393ls1565057edd.3.gmail; Wed, 20 Apr 2022
 04:50:47 -0700 (PDT)
X-Received: by 2002:a05:6402:2809:b0:423:e123:5e40 with SMTP id h9-20020a056402280900b00423e1235e40mr17264533ede.84.1650455447491;
        Wed, 20 Apr 2022 04:50:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650455447; cv=none;
        d=google.com; s=arc-20160816;
        b=AHFvsvtvPsguYRRQBF9pW1B3Hh8dP+ibIG8IKMYJv0GuT3fAUA+lp134zh0racsbie
         KMCH1JIXbUzVRhkhL3aPXwDvdaKaPJMvYvDMw25pLYtNGsXAEG8D3hGzj9Agb7kK3gVz
         /IRmu9AicMhuctkc+JKqpWMjBvSqsa2dnCwc9oyhqX/CR28dcIXUOIoYgiE2qr0kAGis
         jYMA64fejWDBaJuFDHOtXZDvO4ptsgwBWLQ9bSxtC+2ejc0m/XvrtzUTn23exDZffIPy
         dFOwWNKQtzzWxW0OibIin4edfvRohjlzc5cA/LF3cX104sT2che9DNivE5/FsNK7cZhZ
         wr7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=e//dGrepWn7jS9BGgfc47xqnbF5iiCNsWca8XJ9Scbo=;
        b=ECv51XSukXH2wr+ptCHtek2SOTa4R0NYuBLQgnG/F+hhUSqSPTQ4Vg2c3KUzUuQ28j
         jefBHpIovUofBJ+6XA7DJDi3FgLJel+xQKUyzniRR+2ObUkG73q43nzaBIxvEbEF8Em7
         6Sq7yy52RogP2G/r5kRsOKF5hBhaHf5+BEkiZAUhQJdJLatskQrAFbBX9p/BHDc5mx69
         YpIv8LI4j8smzuZ08F5wQKPYvDSqt1xfnspvofX7AhkuXs8wc8OAM6FhGQNjcq8ttfcj
         iRsQrnghruy96i1zM5vBHalIMvQbdTUlDV15dHeGT+dHbTOg6LB7sQaYu5kpSy627qSH
         vJUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=p9kNFmSN;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id t20-20020a50d714000000b00415e600c761si88461edi.2.2022.04.20.04.50.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Apr 2022 04:50:47 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nh8r4-0076rr-JF; Wed, 20 Apr 2022 11:50:42 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id AFF899861A4; Wed, 20 Apr 2022 13:50:40 +0200 (CEST)
Date: Wed, 20 Apr 2022 13:50:40 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, x86@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-m68k@lists.linux-m68k.org, sparclinux@vger.kernel.org,
	linux-arch@vger.kernel.org, linux-perf-users@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] signal: Deliver SIGTRAP on perf event asynchronously if
 blocked
Message-ID: <20220420115040.GE2731@worktop.programming.kicks-ass.net>
References: <20220404111204.935357-1-elver@google.com>
 <CACT4Y+YiDhmKokuqD3dhtj67HxZpTumiQvvRp35X-sR735qjqQ@mail.gmail.com>
 <CANpmjNPQ9DWzPRx4QWDnZatKGU96xLhb2qN-wgbD84zyZ6_Mig@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPQ9DWzPRx4QWDnZatKGU96xLhb2qN-wgbD84zyZ6_Mig@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=p9kNFmSN;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Apr 12, 2022 at 01:00:00PM +0200, Marco Elver wrote:

> Should there be any further comments, please shout.

Barring objections, I'm going to queue this for perf/core.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220420115040.GE2731%40worktop.programming.kicks-ass.net.
