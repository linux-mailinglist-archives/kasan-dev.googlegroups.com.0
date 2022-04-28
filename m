Return-Path: <kasan-dev+bncBCV5TUXXRUIBB2F2VGJQMGQE7CMQLVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id BCE11512F68
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 11:24:57 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id m5-20020a2e8705000000b0024f0fca4516sf1636640lji.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 02:24:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651137897; cv=pass;
        d=google.com; s=arc-20160816;
        b=ECW2cs+xYkVcsf61LTz3K0V4FkYYQhE9dSRgZAH3QUKpXE9gEck+9VtXBUp4m9KrWK
         YtsgHrqpq03wQMFvVrRTIFWreqe67q0PbL7STr17LZIg7K1QtFTUMSE99DPmSBDWym2l
         SVjJW15ait/STj3txFCU0z+l2/P++7PMtRNLbc2Fh/jk/Mqi6ps8H3DEhDcZGBk9iqfB
         C3xq6qpwiA/HV/hqu0KsbxisJs5C2+S450aAab0a8vQCiR5miyJ8Hp1LD9fm9AXu6Un0
         8Vv/6vK+HWiUY8Z9bcwaOZbMQfn3QX0SRJ9+/iGtsmpqMZDSqQ1z8UdXPG0LTemRmNtN
         0Kcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=N2aBku3Ut3tUHKmspy35SoVcifBvLWmxguu/bGQeres=;
        b=xs5erlLdTEUQdn+hGpFKPRZIIFkiKl3OGZJOKgHEdkVm639BKHDXxuNgGcaK9n2Zwb
         y9OG2zzXJ0nnKJUKwjgMj0xMc7Zo1xzw8f3jzposFe1eITpEqudfVz98ZT5KkDBVuvuv
         Wy4kC4h0ZM40PSccOfa3XLGo8bJj62NJvR/HDtzJwVznE+3UXVN5EfICwGVhVx0GS/LB
         9G3EQbPM+KKvycK+OpvMTawalWPRcJCN34wOJUNjLweH0Dzzblr+FTvtmRb03SovzO7T
         8xX/2WhNR3+RU7Jdtt66YXjGdq14Vg+3Qe1NffwMScb7AoQ68H33T5a+Xg+MS5kpqUnc
         94HQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=jqnHwtfw;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N2aBku3Ut3tUHKmspy35SoVcifBvLWmxguu/bGQeres=;
        b=RKp/Vh8d8TKBQTItwKPGplYHLF6rfLF5FSF3kDp6Gid81W9kXLO6MXCsXJMKwJqfR5
         wLSAL9LO2SV/ineiGgmPPrnMMl6mqrlnTR4c8N0WxKsIosdBhw1lmZmKQoJECX/PeIyb
         qUWS/tKelZKJdeCePGz89kg7TfLn4p5/dPcujuS8US+GTRJRuSlcMcCCBxWqN5Y4UIz0
         3svi2G2dPkOb1MhTA4LrDmIpvxfhjc/CdzktIUhvJ9lTtlirGw/iWuLqcdqK3NwDYMkX
         fOeEt6ayztLInLJDUrb03QThuomMrmCObwMofq3hzmO3Q8XYz3q/XKB9sDaErJZcchjW
         dB9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=N2aBku3Ut3tUHKmspy35SoVcifBvLWmxguu/bGQeres=;
        b=0HO/FDUrwNhNRJ1VGBZHwVbJ7BKj4MoAocxH0Dxf36dkDIJnt3fo+V1M5KRgN3IDUs
         26JkMtMZSWk45akmciOaO4ZdIAYvu/+M7+4S6Mrqq316YIbrtyK1KmiyTPMCqPxU0HPa
         mohuxgrmlRMoOdtdm1UiR1Bb3RPgrQVeEeNBbYoGkhnxWwmTASVY0d06vuyIfUJQ7mpc
         nRqC8aK21AfU2svupi+4Ru4RCHUjvGrdP/w3kiPSZJweiumzkaQHHXfBwxQeKa+tWB0I
         9XvHXJ32g/3ob8N4YBvBvx7ndtfOys2tl7z07T4hpmBqqox0Qloq6zNSo2xIA4QoJppe
         POIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533HBcu1Vks1pVADZ5O9v9kZdgBGVLb3iEtf0FcIdj2g8DTL3b8D
	u02QIH04U5isYWdvze9dX1Q=
X-Google-Smtp-Source: ABdhPJwTadUEw3X56vVUkffUN85nyjd+HxKnx2qgg9rzNdhjfn2lQv4qAELTduOmIK7auPNdinmA4A==
X-Received: by 2002:a2e:a448:0:b0:24c:8fe8:f3c6 with SMTP id v8-20020a2ea448000000b0024c8fe8f3c6mr21137973ljn.115.1651137896917;
        Thu, 28 Apr 2022 02:24:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls1312714lfu.0.gmail; Thu, 28 Apr 2022
 02:24:55 -0700 (PDT)
X-Received: by 2002:ac2:52b4:0:b0:445:ba75:7513 with SMTP id r20-20020ac252b4000000b00445ba757513mr23650695lfm.248.1651137895771;
        Thu, 28 Apr 2022 02:24:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651137895; cv=none;
        d=google.com; s=arc-20160816;
        b=iXkWIAD8aMXEPNhi25UCU3dJv7mW24wjOLtrsTLnzydLvamPTEI58nVn/Vpvr+25BG
         4pSgCy2y37+etBj3lfzCOO/zbbesl/WPiX3ilGq4VZRVi6vUFwi9c1q5V4tH8ZxyV/+j
         Tew4s4khWess3njBfmSKcpwmW/2Ee8XAEmoRvAtIOEYdY2ex7B78sFbMGivArpqmuGgf
         VkxdkPvGtC5FEqu7k8NP2j9+4JsXv0HrVOIezi/3YtK2O3/2HGGHlrdtR0bNs10c8/8q
         9JXv931NJckODorkXP2v/Z1nUf/vpQzuoJpDLj69qQtz1o/3eh8+QhOIT0AW+Dw6UmYI
         vM6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pAUQNOu/Xvx7sFYGMIzT4ewYo8Q7kV8gZxOmlw0y+YM=;
        b=YwjGJN8tmYYvgvYOzPrKyyOZoxFBAfuB6sHF4o/jA4YsxQR6hI+zWMDQzjjuY2ICaZ
         /d5YSheZIapVAsvhpGb/Gaua2dXGfEyet2+/PQXnfqNi6juqZd0H/qfPU+kPY8nfiFPl
         ryqvcx5m1GTsdxnEjrjwff9chrrnCHYHKKoGTQHQ+6Ep1pn5azqIoYkbDXzzYC69bZYK
         YrgW2NYwCUwLxCeExdluZtFeTleMc3P7BmAaHhQITCXfKppnb3PMNwjatLeQbxqbuZgm
         z1u/6B+30ANxvRZ/wmYVp8zqfNIfvpqWzIZx32lkKKu0uZRoT0jslEn1kHmY7vYYpKbm
         RIJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=jqnHwtfw;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id h36-20020a0565123ca400b0046bbea539dasi189984lfv.10.2022.04.28.02.24.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Apr 2022 02:24:55 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nk0OF-009JKd-N5; Thu, 28 Apr 2022 09:24:47 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D7B51300C88;
	Thu, 28 Apr 2022 11:24:45 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id B93B22029F872; Thu, 28 Apr 2022 11:24:45 +0200 (CEST)
Date: Thu, 28 Apr 2022 11:24:45 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Jun Miao <jun.miao@intel.com>
Cc: elver@google.com, dvyukov@google.com, ryabinin.a.a@gmail.com,
	bigeasy@linutronix.de, qiang1.zhang@intel.com, andreyknvl@gmail.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	akpm@linux-foundation.org
Subject: Re: [PATCH v2] irq_work: Make irq_work_queue_on() NMI-safe again
Message-ID: <YmpdXfJswI9rlG3w@hirez.programming.kicks-ass.net>
References: <20220427135549.20901-1-jun.miao@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220427135549.20901-1-jun.miao@intel.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=jqnHwtfw;
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

On Wed, Apr 27, 2022 at 09:55:49PM +0800, Jun Miao wrote:
> We should not put NMI unsafe code in irq_work_queue_on().

Why not, irq_work_queue_on() is not NMI safe. Only irq_work_queue() is.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YmpdXfJswI9rlG3w%40hirez.programming.kicks-ass.net.
