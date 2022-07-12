Return-Path: <kasan-dev+bncBCU73AEHRQBBBIXTWWLAMGQEOE6Z2YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id D3EDF571B76
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 15:39:47 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id b17-20020a05651c0b1100b0025d6a404ad2sf1046123ljr.4
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 06:39:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657633187; cv=pass;
        d=google.com; s=arc-20160816;
        b=LfZChGHNN2Zr7xj8swNkqpk/4EvvJTuqynFzxB0vCK2y9KbRn+NeARk6+vRYmC+bc6
         3LzBIiKYdKJGTc6Bkc1eRxX3PLZ1l5BinJgtO6e7yJi1/lHdw07pA/mfx7z2m01gK+dW
         zlF6LzJNMNu1ZRDx/CgeXfZl8Fe5DRZoVe6vM2g75hbXkfBBzJQAhAZq2cufis5oL9AL
         gaW6KE45By9Lmo9FHofUTxA4TpKzGgdjVSUVg5qWXvHa6AxdOjKqdf5jNDa6uzJJ0UW1
         pSRWUOTfWdx5mrDgoiwaJE5vO55v02UU9QGpEZ1EAk5gSeC8DO9Q15xJlqXA8G4xZAZw
         u4uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=fTtRvIfGMwKHM55T9Eny+XZ5nDZK5FfElRMgpTsv5AM=;
        b=Q0JY4DeijfA4xA9Sv+H7pfzeP9w1PPAAMBWc9Y6z3iuXVYpQ32A0boDFI9LesYmkU7
         tjriIpr8VunuTpVWD+OGG+91cxwC3U/VZgem35wLN9AJtTfcI66eJ04Pa0Ok5dpjNAkR
         BKbrDWQdq1n2q7JpDXGDgsZtbq+QOvqg1qEAac/Nq9Z5LAhIIkLGs9MXNs3/1ozU14co
         b5D/8VQxnhUgj2rHx7ETUh8SnMjc7aKyYqJuQCFHmeOlYYuXr3B8L5LNTrXSxYPYVmY9
         r7OPVCsrKlDh63A6XEMcewlmmKi1hpb7LBKZHbFJBwmb+e1SgH+8sB1OacUu5tmdyYbR
         +23A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=xucx=xr=goodmis.org=rostedt@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=XuCx=XR=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fTtRvIfGMwKHM55T9Eny+XZ5nDZK5FfElRMgpTsv5AM=;
        b=KkDNS89um2lyPrKTKFn3Z7KR4CKg9H7NFbpq3FpqHMX3rWEkpxCmXC6eMuXokS6vdY
         +HJOtT7dhs6ZfbRqwX7lYJCPMEH/hAMPnBJ4jFjEvS1zGAgMssSzoW9f+S5YttTNMeJE
         J3oHVMlpofFMjrwtEH+dPXVdcBc3qeYCy3gUQapJ18C1s9WhTR3JwxSFZwx08sIn0gR9
         Mo0bcMlWkjeQi5aOuYaobcMKgvaixEcCcNDOY/WnRy9snnqEtTNeIIPlrc7c4SDMJwF0
         jrCOyTkyzp1aH2a+DbDaUNbEBn9x4yXdOYqiYsrBrzFtPoSPk2oE4eLPFoRsTv/SzEpq
         icTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fTtRvIfGMwKHM55T9Eny+XZ5nDZK5FfElRMgpTsv5AM=;
        b=vLm4eELlPF4IMu6DyDSpyyHGiMT/Sp8vuErBQFHJK04Jhf0wv4MLNaTihi9OfaR2GM
         PVoJIB5DA1n0AKARADLbYOYInSR3HINP54+h1Q41J8sg1ueo/+6NTMVgo+bkjDdRX5Rf
         b2pOAm2bKI9hjpiFS4EKlwNnMspa67L4V9Paq1Dh4W9EpkPkGY/MFKzOjvjEZeoRrDu0
         AFXMiM94YBaodJFuRNuu5txm1sQsQSmjrgf8n2HyuLGTdkPdcv3H4hRfXA0CrWzJB/Ju
         TmvLeCAvTrVJqVGlu6hn84ILWDLybkVJCPpSNaH1iJmMgmWzViflMAgpnO8tQ5+7aUpW
         iYCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/ueNngP4U+QFRLKDSOs7S39I9Eaa2lN1JRxQFSxcfvBSIdSA0e
	i4jeZnaoLf2T9tid6G+CMLk=
X-Google-Smtp-Source: AGRyM1vYsrTVOZvDuFTRhHh2Dv94oE1GX+gbS0KFW+HiGrJfDjxYCc0v0SyXVZfUF+wKQLiNdVE4tw==
X-Received: by 2002:a2e:b8ca:0:b0:25d:3043:cc4f with SMTP id s10-20020a2eb8ca000000b0025d3043cc4fmr13572827ljp.483.1657633187052;
        Tue, 12 Jul 2022 06:39:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3ac:b0:488:e12b:17e9 with SMTP id
 v12-20020a05651203ac00b00488e12b17e9ls322325lfp.2.gmail; Tue, 12 Jul 2022
 06:39:45 -0700 (PDT)
X-Received: by 2002:a05:6512:230f:b0:489:676f:2705 with SMTP id o15-20020a056512230f00b00489676f2705mr14318673lfu.419.1657633185673;
        Tue, 12 Jul 2022 06:39:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657633185; cv=none;
        d=google.com; s=arc-20160816;
        b=HHVJcXw6nbb4sIWRE/lQUvqrWZ6f3g0OKRF5AFffG3D/VMggAI00GzbbkzfhO2DOjj
         a91/3TdorQGLGsmsgNU8XEVnlXvynPpvqV+G3+idRaTg3LWCa67fw4EGgXg7bnm8zPSq
         nUSfW5EwVYUcfwUfpD4D5pMvlOBQx111BBWo7cTwVaapd4Wke0woLMGV7E/k3lVv3Sm6
         q2kujV+2uUeDAJeBWm+A2bneG19qRpJuvgG5SQzKGx2zL1pjPXrxhUERWMcTWgD2jhTN
         Yuq/2JQaOCIJupGzjMXPI93d9kjPBCEA8utzwYs5XzeOJ/f9o7EJ+Z8af/yP1Eo/V0wi
         GvrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=XyBivkrYxls+hwJZZJSbVJMoMyVPSC3kNuzDk5MDXcg=;
        b=Au/lYfXxuUWpuW8EIndWI8db6EteRIsAa3TsxypiF/2PDdcJ4YsMLCoagDIi3fdR6I
         lEfvXLacI6xIW5u9262FGFXA/Au7RnFwl5psVHEpwYtyMgUClO2CYlkWydRbv1GQxuYE
         PDB3lbUpym6WAtb8jEz1JefZoWmx7RA2P51b1a3hmaUJalJn/y20eEUjoZDWQAj9qQH/
         FE8q5EdFO6iroSP4qUpc9Gg5SS8f8POAuABTMZbXc3XPjDIkOpdE5qB14/wYE50UTk4G
         iB9OCSLK9t2XXsFqvq4PeECEp4fXCZEeBiGpEUlo295qdVtr/bC6P+K+zdMnXuCKriXc
         Unig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=xucx=xr=goodmis.org=rostedt@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=XuCx=XR=goodmis.org=rostedt@kernel.org"
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id u12-20020a05651220cc00b004810d3e125csi373563lfr.11.2022.07.12.06.39.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Jul 2022 06:39:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xucx=xr=goodmis.org=rostedt@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 2E1C6B817D2;
	Tue, 12 Jul 2022 13:39:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8B06EC3411C;
	Tue, 12 Jul 2022 13:39:42 +0000 (UTC)
Date: Tue, 12 Jul 2022 09:39:40 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, John Ogness <john.ogness@linutronix.de>,
 Petr Mladek <pmladek@suse.com>, Sergey Senozhatsky
 <senozhatsky@chromium.org>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>, Johannes
 Berg <johannes.berg@intel.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Naresh Kamboju
 <naresh.kamboju@linaro.org>, Linux Kernel Functional Testing
 <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220712093940.45012e47@gandalf.local.home>
In-Reply-To: <20220712114954.GA3870114@paulmck-ThinkPad-P17-Gen-1>
References: <20220503073844.4148944-1-elver@google.com>
	<20220711182918.338f000f@gandalf.local.home>
	<20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
	<20220711205319.1aa0d875@gandalf.local.home>
	<20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
	<20220712114954.GA3870114@paulmck-ThinkPad-P17-Gen-1>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=xucx=xr=goodmis.org=rostedt@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=XuCx=XR=goodmis.org=rostedt@kernel.org"
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

On Tue, 12 Jul 2022 04:49:54 -0700
"Paul E. McKenney" <paulmck@kernel.org> wrote:

> > But a quick fix that stopped the bleeding and allowed printk() to
> > progress would be useful in the short term, regardless of whether or
> > not in the longer term it makes sense to make srcu_read_lock_trace()
> > and srcu_read_unlock_trace() NMI-safe.  
> 
> Except that doesn't rcuidle && in_nmi() imply a misplaced trace event?
> 
> Isn't it still the case that you are not supposed to have trace events
> in NMI handlers before RCU is watching or after it is no longer watching,
> just as for entry/exit code in general?  Once in the body of the handler,
> rcuidle should be false and all should be well.
> 
> Or am I missing something here?

I guess the question is, can we have printk() in such a place? Because this
tracepoint is attached to printk and where ever printk is done so is this
tracepoint.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220712093940.45012e47%40gandalf.local.home.
