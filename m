Return-Path: <kasan-dev+bncBCU73AEHRQBBBL4MYOMAMGQEYVPMXZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id E02935A9ACC
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 16:48:16 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 136-20020a63008e000000b0042d707c94fbsf4308196pga.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 07:48:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662043695; cv=pass;
        d=google.com; s=arc-20160816;
        b=KERsIqiQuvhAUVaqG0Sjpft84ZmjwOy+2uMfE8la3g6Ave1f/98AXUlg8VtAdBkPpn
         OQgD7/Up+JjlTdU4WzyuRGR50xC3/jViA0S/AWvxT4Bkm2Ul3FZmWDB8zQIQZgR17CVg
         DlKjtDn/PReC0OsjInhHqVW7FV//pIlwFF9Iw0Gh3fsGGkk7LY4paCHxi26mFwV+xHS5
         l4lO78G9Jfp3OsH2bplKiWzBSrpnPSByIZzyxnNZQZnqY4oew9iRsZ+geBhguFOlKHcA
         XCNAkWBJMWwA6biYYDPKmqoy5U660VB3y2whVBQt2K9TRV0Y2WIYiuZPwCC2SXdA8jHG
         QkyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=yyZX47fZJOVSAfc+Yo6gODRIBNQiIXcwty562UXtexA=;
        b=Ylb1J86e0Zk/tJGVKYcFK6Hy2OmezbIGqxQrg5UVdkJZiV60fMc8w4gZCA4FOlYl0V
         usU/K04DbT6FEg2/5vN9+wUESwuhMrEM3bjXCBKEhftw/CfvUsl2l7TR+ioPoPMLZGHr
         kmCJOL/m9Gv0GxHB6+ycvtU9nq5kZnsDac78oE7/SUUgBLgHxTDxISWrIPnB8aWePXHw
         I2Oqho8ePvHI+aehr/IYx630mgVLiGp3nyj94QLsQcjanJJYA7bknamrMhniwhcv4XVt
         eV/9AWgDB7/hlI8S6+3lglcg2wVoshTQg4/2x5cV7nMikw8EbyXtFvNG69+56noRZL74
         21kA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=hZ//=ZE=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=yyZX47fZJOVSAfc+Yo6gODRIBNQiIXcwty562UXtexA=;
        b=OhZJRkafjbG+fIr9is4kOxGLJBH448oez2HsjycpfyTdQRMfSd31+HrMaZxEZyXCLD
         xSCuKZxKw2JEMhngbAGLLx7CqAt5y9rJFmv/XZL2E1ujRkznI8WZYWweyQ7833zUsFxU
         TGgvQMNxOeq50Hw5HGL1RFpb/qiztz6uefSkQ9KVKEGwXVk4s7UmJEVQWTxWgeaMFZtf
         TSaMUIaQMkTUv0YhRLsKeg0SH+Svwq9Lay+OaXeIhFKgHdE7pIpFZTzCQhuxuunn+zMW
         fhwGHuOkrF/GFT5/kVMQ7HrUUrOygJncssLjcj2TiPG/BxNBRbj5b3sgqh53Jhtl7O4l
         zDbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=yyZX47fZJOVSAfc+Yo6gODRIBNQiIXcwty562UXtexA=;
        b=MKbRly7ZiANd5kQigpov8r3nauaaIweD9QxoB1yB0N9VjVV5rd9ZS1AmwJm1SuphKH
         vIGSCdoqLIM5RcXy9cYgtPf6109ubY06EMKOZKQkAgi66kdTFByJcsmuDgB2ESSJQ/ub
         lVO9Zrzi/nRLtbvN6gjX1TiDrGHPI/AYTOill3XsGX34mLlV5N0oJTD3f5R8GyXPvEWq
         +nsfejLP6hD5DzBsMA7CQ2xAP02W5j25YbNPyr4LNeRjdjjYuCkEyCPm2TjTUvYjogfD
         TgDVkm0rnLOUvQiQVsiOi0zNTeR4arBZD0vyEm/+/wkyqacg7lzMqlPOXITELS7oCL8U
         +UlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo01xrBVzs4DKP1lTBPtHSwhMkBIL634u7fdEL++kfN0+Hft/EQw
	aLObpjWiEi7JHGlwwX5OmaE=
X-Google-Smtp-Source: AA6agR5QdaDPFbKlpYhy16bN9FML1/bpwV6tkPlY55aOT3w88C0bU3fTuCAhs0kY9HJIszOyugcr4w==
X-Received: by 2002:a63:3150:0:b0:42b:8062:4008 with SMTP id x77-20020a633150000000b0042b80624008mr24047195pgx.584.1662043695338;
        Thu, 01 Sep 2022 07:48:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1108:b0:171:29d0:e7e0 with SMTP id
 n8-20020a170903110800b0017129d0e7e0ls1599402plh.3.-pod-prod-gmail; Thu, 01
 Sep 2022 07:48:14 -0700 (PDT)
X-Received: by 2002:a17:902:694a:b0:16e:e270:1f84 with SMTP id k10-20020a170902694a00b0016ee2701f84mr30572232plt.89.1662043694494;
        Thu, 01 Sep 2022 07:48:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662043694; cv=none;
        d=google.com; s=arc-20160816;
        b=a/jdN16twp1bhzSXN+K+zqsQ6Y4O903q0Yn6Td0v8GYALQZCKrIY0P6wmaFT8jkWfi
         kR5ekhe9Rb/Q/N/iq4x6g1Bd8y7+4xG5bQm3l2WmrwfDQY4XiuiL4Rjn+WojmUn+50Te
         abCRZs4kPVq6FC9kcvewxrxfsc2cFHnHVhvk+qmbCRclNtYMYAgtDBJ5P3Tuvz7rlXB4
         TM8il1iGN+jBSgjwZVaUewYHjHUZjj65CdhyfrYJHRXAs0YleSKls71ynkMDBGpI/KGk
         X8arEoT949u3+rAWLKcgiNljCeJbt5Yes4RVezlsrqyyolU1II5Ts3SxOZubPsgUCCNe
         u06g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=Jf8cO2t6hUZhUrp3a7pSCi1cULdqUuGpU01vQQWB5m4=;
        b=kYUAdL+zmyppYukkDsEVaNdBi+mGOpXcqoSCm3PhUIDbojq0ufpNGBBqHMeXW29xCx
         9c/gr5nGJaFDvuxOjnBC0xLs4C5GYHxQbiYX4Zeo5dfKc6BbFsecNXqA0A7M2iceHFOH
         3nXpA4oeAEy8aoFMQWMaZPpaPvhOAkG76F3pau3GCAHdbJKEgllHyC3lWz0dfHEXZOdP
         J+BW1dKRzyfbQ+wKLvO5BBCl4/UHNmVZgd9wglWfafLeLcoMjN2dHGTNKdXgvGwylOVJ
         mRiyHHzaJqjMdw3SM6BLIbEjBEs4rKIM90b9RRDQZN03fZc1PwiDncqong4lXuvSMYOg
         5DEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=hZ//=ZE=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e6-20020a170902ef4600b0017542e23802si240817plx.4.2022.09.01.07.48.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Sep 2022 07:48:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id EC7C161DD3;
	Thu,  1 Sep 2022 14:48:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1DDEAC433D6;
	Thu,  1 Sep 2022 14:48:08 +0000 (UTC)
Date: Thu, 1 Sep 2022 10:48:39 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Peter Zijlstra <peterz@infradead.org>, Suren Baghdasaryan
 <surenb@google.com>, akpm@linux-foundation.org, mhocko@suse.com,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, void@manifault.com, juri.lelli@redhat.com,
 ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com,
 axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
 kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
 linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
 linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 03/30] Lazy percpu counters
Message-ID: <20220901104839.5691e1c9@gandalf.local.home>
In-Reply-To: <20220901143219.n7jg7cbp47agqnwn@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
	<20220830214919.53220-4-surenb@google.com>
	<YxBWczNCbZbj+reQ@hirez.programming.kicks-ass.net>
	<20220901143219.n7jg7cbp47agqnwn@moria.home.lan>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=hz//=ze=goodmis.org=rostedt@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=hZ//=ZE=goodmis.org=rostedt@kernel.org"
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

On Thu, 1 Sep 2022 10:32:19 -0400
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> On Thu, Sep 01, 2022 at 08:51:31AM +0200, Peter Zijlstra wrote:
> > On Tue, Aug 30, 2022 at 02:48:52PM -0700, Suren Baghdasaryan wrote:  
> > > +static void lazy_percpu_counter_switch_to_pcpu(struct raw_lazy_percpu_counter *c)
> > > +{
> > > +	u64 __percpu *pcpu_v = alloc_percpu_gfp(u64, GFP_ATOMIC|__GFP_NOWARN);  
> > 
> > Realize that this is incorrect when used under a raw_spinlock_t.  
> 
> Can you elaborate?

All allocations (including GFP_ATOMIC) grab normal spin_locks. When
PREEMPT_RT is configured, normal spin_locks turn into a mutex, where as
raw_spinlock's do not.

Thus, if this is done within a raw_spinlock with PREEMPT_RT configured, it
can cause a schedule while holding a spinlock.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901104839.5691e1c9%40gandalf.local.home.
