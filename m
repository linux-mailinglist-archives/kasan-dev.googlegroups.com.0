Return-Path: <kasan-dev+bncBCS4VDMYRUNBBSUGY2LAMGQEJTX6ZRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 51A59576431
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 17:10:04 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-10c071638bbsf2976207fac.15
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 08:10:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657897802; cv=pass;
        d=google.com; s=arc-20160816;
        b=epjibS8ud5VYI8yY8PSLCiy3r8shkK9lZ8z/1j7rwaphzQrOq7eLASPs4C8tVVnbY0
         3W00Skl3/PUnsMFiWTU8K40u+PgXCXDuXLw6jzEBq5ugxh3fKlccBn7RD73StHwulZ2C
         YvMx57PGwwhlVMHPYHEYX8ny6cPqRKgGZOIAve//xlmF9YtKQj/1LF9cax8sPZsI1nhw
         hPRy8JVm+ANLzZjz9BuHIlYnEl6PAuTkAimDc+0vfEJ0MZxc0v0n+cI3780+RrRx5o5N
         A3+YOWP73g5ess/lTcKrvrOSx5Pr6hPVsLm4Jba1K5nc+++Swl6Fvroi1X8Cpqc3S8l9
         APJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=CTfPZ0KdgavGrdMhLhHVP8NZkS8vkIZkSDomJBi7zNE=;
        b=kpWjOjZ5JP3gpoFD1duB0Ig4w049TmcaA8Vz0LEEB4AFErvyw5zgA+xyK8mRpfoq1G
         CCe+zFCIf3ePJkRCRTnDOJb0NCtn315JS9sbK8afi3WOCJoZ7BGGM1XDYxGJGP9gNdQ+
         SZGIGzDK9TtxqqCTODIHFzh5OpT2OMhSUC+cMjXuTi8Rxhs7XBE/wq5KCXPWmr63Z8G/
         TqJ6UHvjVYehjpeaF8IpTLXyCMoz4j3AbNZWmHUu0G7AxU7jJeHsEV13koVm764fjg2s
         Dukjf/KKvfXSqN4tSrnPVF/mQVtu6e+HEdW9sAUNdEmWewHetKmBmdqOIWyWJGGhjueX
         05RQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=h9kv48vg;
       spf=pass (google.com: domain of srs0=krbc=xu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=krbC=XU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CTfPZ0KdgavGrdMhLhHVP8NZkS8vkIZkSDomJBi7zNE=;
        b=PB6tFRKvzBOKJFM08znwzbM3zay3UaJWh9OB5mhyRyTI/OyO4P4YTZ/ZHbMAzs1KMW
         GA8/brFx5+pE3Tl0OfK4d1jmvjp9JZ+Vexr5oYBSuF8qsFaCbJaucoXA/+/wSRsyocqs
         Hqb8YROIqh8XblC1a9JMDUtZ1v90w0Ccpgcl0F4GOxG33aLaDEXXsLKbfteqba8lL+vp
         jsBbCCXb4ZkynxRuGCWzx/Nm2DyzctIkr047kzIWbDfwehMJbOgMUU2tPL3Y+HhuGc+k
         eb9rdesnWox9bR8iIt3RQ8fPNXVgCWx7bVVXK+d4pu0poQITZZXGu+TNfIKIuZ45Kbjf
         uYQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CTfPZ0KdgavGrdMhLhHVP8NZkS8vkIZkSDomJBi7zNE=;
        b=41lgpgDV4OxvaAp3vnFIpKswKGbbbRxZjqRP1RyV+xX8b5SY0LIUbfHtYx6ZS02j0c
         n2Tji8CYeCUiQV2tCeDr8O6+zpn6zNhrW2ifR5UnADW/zIQpio1eLdrF+1zeiQ8Yp4DO
         ttAoN+S/P365ItJ291Bw8QvGSBbObThYNbV55aOEKzqV9ppH/CUZh4v7hnUwaeP/juC8
         RE5g8rm+j400i/0roBOoXsqarFRsPXCf9yn0TFc92bZC9xfjIps+c0dwLWI0Btnen7mq
         Cof6iblG6V1pc6+oUqaJz6jxs4vMLkfgBD90WEoKwrAHix+sVFAibAoJHcy+b7jg3r7o
         hNtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+r9Qz6XSfRY0NqPt8M/0ysZRlpscC9YGDb0XhFVTkTddA0imst
	fgrLXnsZe32zZIl+tGOBZEE=
X-Google-Smtp-Source: AGRyM1tL6QOnpWGgtahfPV2Ocqt3w9FJl1kzgMU0EmyRG/2a0jnA+oDVQXrwru+kpp66nT7CAxV7Zg==
X-Received: by 2002:a05:6830:3492:b0:618:dc6d:752 with SMTP id c18-20020a056830349200b00618dc6d0752mr5462151otu.294.1657897802622;
        Fri, 15 Jul 2022 08:10:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:17f1:0:b0:606:140a:e39d with SMTP id j104-20020a9d17f1000000b00606140ae39dls14420005otj.7.gmail;
 Fri, 15 Jul 2022 08:10:02 -0700 (PDT)
X-Received: by 2002:a9d:6c56:0:b0:61c:5937:86fc with SMTP id g22-20020a9d6c56000000b0061c593786fcmr6064872otq.365.1657897801994;
        Fri, 15 Jul 2022 08:10:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657897801; cv=none;
        d=google.com; s=arc-20160816;
        b=mg8vO6xD65YeHpxPYaIEcV1BQqPBR7y784rWcPFiGEhGnWMkqNr6Lo5/PfcxGoIqDt
         POBLMAp/zTW4yW8obne2qjMcWX5Bqn39Z4MAmFZHKqylpAnKcielfVR1T4EEaggFzhG7
         ALCCbSm1+s3vz9lh1DRWNjGqwg0EhIM01UrMN6oLWSbDemxYfe5HqtUWN8nIDDdLlO36
         kHCfFNzoE5hIP+ZRiBNHjMgfw3bk/AP4g66IPGkDkYX1X7VAW9aJAG8hkhY2MGPjQPN9
         jj/ycrnqYRMJOvbfTyD+Ne19Ekb4jyImuplo/vS0ZV4d9AIuiU3oE1ll4MZYPVzyk9M2
         COQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=aiCcZmbOIQ8wywQ6VGDhioMFfdLDM85QltO/NUPi0vM=;
        b=IhMVXb2X0GdjzhQ3lQFXBQMk0eeGyfgR6Qyf+eIMZOWlCltrIEqypapXLqJXfsniEE
         a2IBS/RRQFQnPEKQ7e5Hlk+yq7TJPt6FhhTuKq672zPeKoSuChCXeIN9fJSe6HUHhTR1
         MOS1TA6E89ZwyMHoWGur3Mz9Ew0t8zwv77EmVQxNsPydSAqjbzJrUn9st+iesex78IF9
         hhUu7AS9gzr2aps7+10xVRLr8qsY57SgLSl3q3fhJk18ngbW95FY2UEqM6RUS1/V4P3q
         OlqcaakQw3/DHSJbAIs1y2QcqQ198xvSEI1Ts/arVNmpyxm9RKWK7C+H2VmtuNBZxIC6
         30TQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=h9kv48vg;
       spf=pass (google.com: domain of srs0=krbc=xu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=krbC=XU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id k22-20020a056870959600b000e217d47668si656907oao.5.2022.07.15.08.10.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jul 2022 08:10:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=krbc=xu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id C538D61F2D;
	Fri, 15 Jul 2022 15:10:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2F9EFC34115;
	Fri, 15 Jul 2022 15:10:01 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id BFF325C015D; Fri, 15 Jul 2022 08:10:00 -0700 (PDT)
Date: Fri, 15 Jul 2022 08:10:00 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Marco Elver <elver@google.com>, Petr Mladek <pmladek@suse.com>,
	John Ogness <john.ogness@linutronix.de>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] printk: Make console tracepoint safe in NMI() context
Message-ID: <20220715151000.GY1790663@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20220715120152.17760-1-pmladek@suse.com>
 <CANpmjNOHY1GC_Fab4T6J06vqW0vRf=4jQR0dG0MJoFOPpKzcUA@mail.gmail.com>
 <20220715095156.12a3a0e3@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220715095156.12a3a0e3@gandalf.local.home>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=h9kv48vg;       spf=pass
 (google.com: domain of srs0=krbc=xu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=krbC=XU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Jul 15, 2022 at 09:51:56AM -0400, Steven Rostedt wrote:
> On Fri, 15 Jul 2022 14:39:52 +0200
> Marco Elver <elver@google.com> wrote:
> 
> > Couldn't this just use rcu_is_watching()?
> > 
> >   | * rcu_is_watching - see if RCU thinks that the current CPU is not idle
> 
> Maybe, but I was thinking that Petr had a way to hit the issue that we
> worry about. But since the non _rcuide() call requires rcu watching,
> prehaps that is better to use.

In case this helps...  ;-)

The rcu_is_watching() function is designed to be used from the current
CPU, so it dispenses with memory ordering.  However, it explicitly
disables preemption in order to avoid weird preemption patterns.

The formulation that Marco used is designed to be used from a remote
CPU, and so it includes explicit memory ordering that is not needed
in this case.  But it does not disable preemption.

So if preemption is enabled at that point in tracing, you really want
to be using rcu_is_watching().

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220715151000.GY1790663%40paulmck-ThinkPad-P17-Gen-1.
