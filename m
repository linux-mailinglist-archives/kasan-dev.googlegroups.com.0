Return-Path: <kasan-dev+bncBCU73AEHRQBBB4UV3GMAMGQEPE5HDBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BC4165AD976
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 21:16:04 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-12785ab6ab3sf1149929fac.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 12:16:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662405363; cv=pass;
        d=google.com; s=arc-20160816;
        b=EMoKZkfI7DSIwUMuSw4lC75S83Ktmp8L5G0FwZubtWAgfDE4QeclIjGH+nQklbjIvU
         qqHKfPVLvcB8VldkUTKYFjwG9qGavxZlNVgAp3aZLwGt0GdcEe2I5pcLNzNM2Fb7RPGx
         sqC/TRqs4KB7IU3nJTDpRlAXy0ntsFgUYoVlK6sECUQCzgzi18cxm7nJevSWM7oCtwnZ
         CxGDsyjhaqtCp/1GZVWBISpZ4ijaaUJqATLdyFXnAt35/Pvyc13yIheNzsd1lAbC83CV
         HD/zvDogErQbOSzHupSkNuYqnK2nTNFkap4zd3S2ogZmA/s1I7zXbR79v9Cn39xNnDmD
         s3dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=dPyrcu3SeLDmuAgitz+vurCimakRMgxeXmjzZLuHNXA=;
        b=iY9TCq4tqwdaux0CDCeU2fMQmkHwP0w6IuaWfSiXJQuJzHhQB2xCzHQAMH0BvIzHox
         mu1hA1ormKy1OF4tGzAeWe99UaKyazJOmdbFIliwhDlfuT74GjHeomK8JDms8VaGur9g
         VO9jEcTeSIbbd1zeLtSwnHowv+Rvx8Kq3QtVop04A5cMT30iqmeVhpH1q9FpbR/z+rMB
         WoJzOAYrhXes09EO03MFJGL7mvpzs1rtFRIo68iTp8xgtrb6025oJijBlENbcFmcdcHM
         ITRqPc454q985ej+XX18DVw0RLeuBjBMB2aqv17tPn/mVIgV+Fd5VM77w++9clJRyFn0
         +2Nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=a78l=zi=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=a78l=ZI=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=dPyrcu3SeLDmuAgitz+vurCimakRMgxeXmjzZLuHNXA=;
        b=DMqb8pYPt871XigXSICXUAImZZ2/r9Vnsv2Xq937EvrX//OpVY6HcmxuWoMmGFYO9g
         y1//ObwXt78xXxPwURdXBLVzkhnixxfBAegNFqLpWlt62s9Al/zfT0wGYRTSPFYntoQf
         ptwN9j4LcJdoDsnwjnVeTYXZPfKbjSPIE3lqpma3pmETxW1WE7KokmMeKXxI9btIdbP/
         0hxCOJh1bLzchwt+IZ6dbr20Tyj1r+X9SYASJyM/A45mB7+Rn722ycxqPE//koMlvdD9
         CuoCEFfRHGQgHuO9iag+OF9bmUix7csTdjYgz3DNksTWgIg/3cWFBjdEa9RBdvQm7CMR
         sRTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=dPyrcu3SeLDmuAgitz+vurCimakRMgxeXmjzZLuHNXA=;
        b=KiiZFZarSQ0FpObGeTOnEB6VDK5/lDYM1zcC6g01yQ0mM+yecsAv6VoCJ+sPufTTjH
         Mbid337+MRo33w6BQkcp3VHC9mfyRe8rV6Y74ktH9ZQPJB6sL8tBhll/b8KVsppBGemT
         nDLasHtlmhD/yQ8RrPXjbFZg46eYu10qonQ0xgaq0T/FCCKdviUDZpWm4QPiNLRMu59V
         nAUGmpMLu9lboC3L9v1EHNuYRzvE6PmOo5985rlsQsM6br5YdVLiXO8RvQ/iN3aRdO8p
         gbaVtajUhMeivveU2mEr8+dJ6Hw+130/Wd5cYCrVOPmJmbPwIBxcbWT914fITzCv6o4u
         ViYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0ctRugb3+WYf5e/6ukyt+edEsZvX4+SocS3n5YaCBeft+2lj4D
	Uspf1icfbLjWkYlp8MY1ERY=
X-Google-Smtp-Source: AA6agR5B5IIgAHU1gVFAPD0XzVWZjH8KSbzLw/q1rs8pwfsRxdfYK8K4aeiqC5RqvLfSqT6/fI2nRQ==
X-Received: by 2002:a9d:6c50:0:b0:638:9f91:9d8e with SMTP id g16-20020a9d6c50000000b006389f919d8emr19850344otq.217.1662405363086;
        Mon, 05 Sep 2022 12:16:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:24c2:0:b0:61c:4808:5adc with SMTP id z60-20020a9d24c2000000b0061c48085adcls2371004ota.2.-pod-prod-gmail;
 Mon, 05 Sep 2022 12:16:02 -0700 (PDT)
X-Received: by 2002:a05:6830:8d1:b0:638:9ae4:a299 with SMTP id z17-20020a05683008d100b006389ae4a299mr20070106otg.334.1662405362670;
        Mon, 05 Sep 2022 12:16:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662405362; cv=none;
        d=google.com; s=arc-20160816;
        b=Zgh3j3hMm6o82ykiHT34O5ietQWiT3ytLUDELs9ffUTGbjMeLtP8z0efAFmPqHhNi+
         wHnuH5OTSuj3LEBnbg/3T4TiDso9NJZU0NPrHn90boyebuXf58W+rU33Bpp9OAcG0NHM
         Iv06pjUstodnRaWF4vWfw6AjMbQqHP8xB19v3YXEv9XSiv4Grm/a5N/NfZ3eexVqm53k
         mszGg6mwZfYGA75eoMeSzUYgcQIYF+XM0DByVl5kTUYWdZTnx8KmDC7iGBia/z9mplED
         zZLjBM9bIOTIvh3PLez9DzFf534t1dhfUN5+yIZ19yHA89cYbcqARjvJN1x375Cg9Oe3
         rccw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=VhLWgZu0MgDN+H4Y6KMCp4dvS/ljYTxwbUIyngNvdVk=;
        b=mSJGnMYhbZTykpwC4MXi5E+RlWgjVd7vWv/fSWLeSWwPeAc/kGh821Jd5eit9LPenJ
         UzDzHY3BAq8zGPNDE95CB08L2bE0W/1Fm8vBF7nqNYQwwkURarjUeFFJAljcpbbchb8I
         DnAbv4Lo4yTC3p/9vYA91DAIkP1kFhnD+CpUCOQVtBYrKi9KbfiWd3fbsc90H9dw3Y2l
         erKAuWRZFH/FgO0kQEZbWQhoHzV8nkEjOUUHsvb8g6FssCmF0DizkfvKNsTWJS6jFxqT
         ef1iBcFhcMcjcgg5M9+5qlsxUrWa3rSPb/ufH9QPRMreo8o/d/1M6goh7b2pLXYG2shk
         50hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=a78l=zi=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=a78l=ZI=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id o7-20020a056871078700b00101c9597c72si1854859oap.1.2022.09.05.12.16.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Sep 2022 12:16:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=a78l=zi=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 455796146B;
	Mon,  5 Sep 2022 19:16:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7168DC433C1;
	Mon,  5 Sep 2022 19:15:56 +0000 (UTC)
Date: Mon, 5 Sep 2022 15:16:33 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Nadav Amit <nadav.amit@gmail.com>
Cc: Mel Gorman <mgorman@suse.de>, Kent Overstreet
 <kent.overstreet@linux.dev>, Peter Zijlstra <peterz@infradead.org>, Suren
 Baghdasaryan <surenb@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Michal Hocko <mhocko@suse.com>, Vlastimil
 Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>,
 roman.gushchin@linux.dev, dave@stgolabs.net, Matthew Wilcox
 <willy@infradead.org>, liam.howlett@oracle.com, void@manifault.com,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, Peter Xu <peterx@redhat.com>,
 David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, Marco Elver
 <elver@google.com>, dvyukov@google.com, Shakeel Butt <shakeelb@google.com>,
 Muchun Song <songmuchun@bytedance.com>, Arnd Bergmann <arnd@arndb.de>,
 jbaron@akamai.com, David Rientjes <rientjes@google.com>,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, Linux
 MM <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com,
 io-uring@vger.kernel.org, linux-arch <linux-arch@vger.kernel.org>,
 xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org,
 linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220905151633.04081816@gandalf.local.home>
In-Reply-To: <8EB7F2CE-2C8E-47EA-817F-6DE2D95F0A8B@gmail.com>
References: <20220830214919.53220-1-surenb@google.com>
	<Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
	<20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
	<20220831101948.f3etturccmp5ovkl@suse.de>
	<8EB7F2CE-2C8E-47EA-817F-6DE2D95F0A8B@gmail.com>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=a78l=zi=goodmis.org=rostedt@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=a78l=ZI=goodmis.org=rostedt@kernel.org"
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

On Mon, 5 Sep 2022 11:44:55 -0700
Nadav Amit <nadav.amit@gmail.com> wrote:

> I would note that I have a solution in the making (which pretty much works)
> for this matter, and does not require any kernel changes. It produces a
> call stack that leads to the code that lead to syscall failure.
> 
> The way it works is by using seccomp to trap syscall failures, and then
> setting ftrace function filters and kprobes on conditional branches,
> indirect branch targets and function returns.

Ooh nifty!

> 
> Using symbolic execution, backtracking is performed and the condition that
> lead to the failure is then pin-pointed.
> 
> I hope to share the code soon.

Looking forward to it.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905151633.04081816%40gandalf.local.home.
