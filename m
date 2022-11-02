Return-Path: <kasan-dev+bncBDBK55H2UQKRBEGORGNQMGQEEF36SDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id A7E98616301
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Nov 2022 13:48:16 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id e21-20020adfa455000000b002365c221b59sf4836366wra.22
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Nov 2022 05:48:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667393296; cv=pass;
        d=google.com; s=arc-20160816;
        b=GPJTY86SVuqkzS3Xi7tQ4JaJ72ehueUNA9G0dxpfwdkQEMjnFkAgPOOhpIToI9zWMJ
         AcZdV/jk7VmH4Lqp9irmREH2UCfCTzA4S4/asfFMwl19c9O7iUr7kO5Z0rGbOzr0bkUB
         TpgeVPAeC/nkmbWbxagxB7NDkC6nswBMPZhIndemqDj9t8+v0hglx2g8Eah63cGNSFQg
         JurP2V5pxT+aWXn6SltR+BovgcrNElFfrkn/6ayr8hvQ5VcNcLqOzFr/bhEp1vxT3pxw
         1WbFEARhfUf5iEFBI9TDb1sSCiaxBB+5m/7hb+ampe068TOrJS8B+RbWREeAphyj0OR3
         yJzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Fi20BEOXOFOe5x2hYkAUT4rkKHOh48NDrTeG6hUuKLQ=;
        b=I/zpSbi9YBQgtMQmD41p9dDcFki+1qgOyFm8CVBGPnxNSFT+P/OeiHC37I1LRDe+Gm
         Yeh8MkF87Pqt4jfb2eSkfbHBS9X53SlkDInhSoUiQTnXIaq86vouLANT1YHRnf/q9PkU
         kJsUpEHcD4/SayHJJ6GeU9NEnEPIbx6LeZTza0yNx9vX1Bf9obAgH1KtGWWOF+W85JCw
         xNJhjiFYKBPh0kPvH8obwd1PQZjIugh4J8AhWBvVqLhEfD4XwPam8go0RknMdElhMGtQ
         Q9TNON8hFEcH1Lku0mYlrdTV9alAanMK/BwZZsiU2fYZUmTgcej/oO7UK7SyEBihcYf7
         NhnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=MTVBYjpN;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Fi20BEOXOFOe5x2hYkAUT4rkKHOh48NDrTeG6hUuKLQ=;
        b=gxsJt/4NMcBooaV/k2rgOz+Am+8hvnWv3Sc2FlmAH/S4RpJO2Dgdo3TY0KoFhwa+M4
         1rt+5Yr/1uwC5XTneDQa1fnvmd+KHtOQdQhhH4IS5vHVPXx/tq+Jf/rQ/bpLQP18Z6lQ
         uknz65VPGENqjpXoYSMYCvbcQE6SXOKmSdX/Ykd5fcAVB7dfmP6RhktsIZkkYAxjAu7G
         pmxN6XrOC9mccl65mzsBSDGjOE5IpSNRjgywHsoPmdPzovud/cvmRbzxVixXvE3j2cpy
         PHtKVdrfBlz1NFp/Wjsx9QNd7Ub5hM3b43Xf3lLw66k0MB2uiYDPKknQOQ6oS93ESukl
         6J5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Fi20BEOXOFOe5x2hYkAUT4rkKHOh48NDrTeG6hUuKLQ=;
        b=TjPEFnPsfcye16634mdowk+gPHHWFZhsoS6YA8mgyP6v7N+BST2a72Lbd2L4mcCMk4
         8m9fuB88ERXfH0jGeUhsDX2i3kXik5+7vjikhItc7Ewyx0jy3FSSXBjfpymh+CrpLlA6
         rMiPVDqK8hWtqdTL986QvKCaMzDANK+3iGrbfLnre/6+VnTSaow+zFd0bMzn6jdAcSIQ
         yvNyA6Q3hBFLkCmAfhowDkcbROukTaLYc7V4bI9agYG9m6EsDhQENZ3vhowc1PMHNReU
         rq8omuEkoeOgj0GvStKCIw5aFeOFVnDZd30DVAR17W2WQ1oOJWpBhesNB3bX85d9W605
         RE/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3GrGrf3NKO9wgJO4u+chYrcSv6USr1iDQegO2eQWdqaxT2mGI3
	NSkJvIjwW8FCyFS0yztwzxU=
X-Google-Smtp-Source: AMsMyM4G+8IIl6GaKSDqIewbIiWplb41O0Z5+5hNiHOeFDsC/0R3lTuGIlV95qTAzpmEASRlU4GFDg==
X-Received: by 2002:a05:600c:5543:b0:3cf:81e8:20c7 with SMTP id iz3-20020a05600c554300b003cf81e820c7mr4410793wmb.140.1667393296202;
        Wed, 02 Nov 2022 05:48:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:43c6:0:b0:3cf:603a:2dd9 with SMTP id q189-20020a1c43c6000000b003cf603a2dd9ls468469wma.1.-pod-preprod-gmail;
 Wed, 02 Nov 2022 05:48:15 -0700 (PDT)
X-Received: by 2002:a05:600c:1d07:b0:3cf:71b7:8080 with SMTP id l7-20020a05600c1d0700b003cf71b78080mr10821149wms.84.1667393294990;
        Wed, 02 Nov 2022 05:48:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667393294; cv=none;
        d=google.com; s=arc-20160816;
        b=yqR4UOihK/x2/lefJ1z9lyaxgLeeo0MjiWTbyp9RZutB/+xyAzjl6EWD4jjPQ5hYAL
         kIuvgJJH5s+hDsFOTvM1GNegKjlBF6brZNIEb1zCp0CDrQMt6/f/FVhoJG3M+CivRG0/
         UOpM74Ls0fDMrwBMKYBlD/38M8GOUH8FfHkpsSMIho6RNrA6z07KkqSLFQk/zQfRPRwT
         k4OwjmZWpXZb9J5DkObBdq2AYumTN8bRxbik5BiUBvEn1wyoEt2PtadSjf+M+84UtPMo
         8MVRt7hYptrJZ/Ud5hEUsUJtg6dvBIzJux1i3rIf8DPBslIEG7L5YkcKgF9aaTZcldwr
         SWXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=GLmyYC068tDZ71XmeksiuAt/PZ4nQaY8vISb1JRaoX8=;
        b=uSxyB9Nn+74U/j06zm1DiBqDJj5P6R2TOGRCmtAu0CJopIw9XHavVP7Y3cyFgr2W1+
         v4PumtxWUDOMTJyms4Ra1SKa+RsV9gMUNt2SBdHiODu4JluMMi25fnWaEJ4XTOwRybig
         QYGgBExluc7rcMRY6Li873lnb30GIwhzqOYcvlHMKsq11XMyW3fs0eYBwZCCbzTOlvyc
         /27wQv9sNFjAJU4gy3hIIQJMdpNB0/SoALGQnfr3ACSPw4oBpoGpcfBwE90x2hdd67KB
         dd9TVmA3cWBcmvcnq4Y49GtHTZRxnY8RGaoVnxIC8Y9tioBVELbjw72RDD6I8EdCl5yQ
         DkgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=MTVBYjpN;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id l125-20020a1c2583000000b003cf537bb09esi57025wml.4.2022.11.02.05.48.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Nov 2022 05:48:14 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oqDAD-008Oit-5g; Wed, 02 Nov 2022 12:48:14 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id DF547300137;
	Wed,  2 Nov 2022 13:48:08 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id C878320B1E7E1; Wed,  2 Nov 2022 13:48:08 +0100 (CET)
Date: Wed, 2 Nov 2022 13:48:08 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Daniel Latypov <dlatypov@google.com>, David Gow <davidgow@google.com>,
	Ingo Molnar <mingo@redhat.com>, Dmitry Vyukov <dvyukov@google.com>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kunit-dev@googlegroups.com,
	Brendan Higgins <brendanhiggins@google.com>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] perf/hw_breakpoint: test: Skip the test if dependencies
 unmet
Message-ID: <Y2JnCDhPicfORyas@hirez.programming.kicks-ass.net>
References: <20221026141040.1609203-1-davidgow@google.com>
 <CAGS_qxrd7kPzXexF_WvFX6YyVqdE_gf_7E7-XJhY2F0QAHPQ=w@mail.gmail.com>
 <CANpmjNOgADdGqze9ZA-o8cb6=isYfE3tEBf1HhwtwJkFJqNe=w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOgADdGqze9ZA-o8cb6=isYfE3tEBf1HhwtwJkFJqNe=w@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=MTVBYjpN;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Wed, Nov 02, 2022 at 11:22:43AM +0100, Marco Elver wrote:
> Was there going to be a v2 to address (a), or is this patch ready to
> be picked up?
> 
> I assume (unless I hear otherwise), this patch shall also go through -tip?

Yes, I've got it queued, I just haven't gotten around to pushing it out
to -tip, hopefully later today.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2JnCDhPicfORyas%40hirez.programming.kicks-ass.net.
