Return-Path: <kasan-dev+bncBDZKHAFW3AGBB45EW2LAMGQEDF4XX3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id D957A571F06
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 17:25:39 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id i9-20020a05640242c900b0043aeffc5cf1sf1329982edc.18
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 08:25:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657639539; cv=pass;
        d=google.com; s=arc-20160816;
        b=gyKJqOAVA18qVUNcD2xEbv+SH85dyXGHy9Px11RHITCkSK2sA4OcimJzHVNll6Z9Hv
         ZqMw4SPPpieyOmgCTdMsA1hL6I1TKyYXBbxtai+3wIJbVL0EntYbcRs8hLe1R3HdsqNn
         RsIQ9cSCLWwe4xFJJkKWlTkh038EIznwzAAyg40qy4ZhTBLk85qoGO8j/uWQvKROCJ61
         7r5GYPPe/+jeYpAXBXa8dg5OyluH4rXAp153LtACJY2VJFp+5zaaXHzKrkIT2I2qUlwu
         2IsQ6hHm+NdrJV9mQp10oKVXjOpjtfk86ealOMmsI9cTOe2DYzRf8RcoGNMiKP3RQyHe
         ZDYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=a3kAF47Htw1mcjNgDIKOxqRFlLRuKTO27JlSDcX9ejw=;
        b=Y5FLuez5Eybb5a3sJoch9o2CXwPxzoTN7lJ/r5sRITmsoMx9lUvHGdo20+AeznATtO
         HcouvQn901w/vI6pe0lC9FNqHJYJ/51kKtx/PcaoIM6fm3lhcMxs08VyjhvcA/XqBEYb
         Z4fagbm6rMX2NXJqWchM7zow1PUnacEoyLGISZf8fdbY1s0U8eV5VT0uuNFaASqkDYVK
         1jqcTu1JYmxj0n/G7G+dgYUlpdTrlpMr9rpr2r17GOWji5z77StGUwovFW0GlZ3xgL2A
         8+Km/MT6q8PFtWnroFbLwqM5XMm7k2rj+jfzeSCV8W+HCNFnh0WfB2xCOrOCfindi9yI
         vp4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=mymcslXC;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=a3kAF47Htw1mcjNgDIKOxqRFlLRuKTO27JlSDcX9ejw=;
        b=tz7ElUMX8fSf7fN4VqRvp3BrmNJ4gq3Y7c+ZzXOGLr6foBi4QxPoPZwD4iuBnKN8Wd
         BC4Ntm4o1qW1ledARoUAK2qNSQWVbCqsXk2150wUsYx3LO7ir6Pp7DRnxehqzJ+0DIZc
         Kb+4VuEsjgrFZYvNg/lrjbvjt8pSq/iCj/EkDmmuQZ1WfThbUGG3E4VCD2FRHNgOyKZS
         fFeeMo4r62VRUMFGVkPIjYDMlr8zLhSCIAsFAOQuoC2Vf8yI6fkYpNlMenDU6GAP9vnZ
         qOjZy1l9o0qH20uuiYKQPDUvvxWtbpJQLazdnbPy+Eh27qTDCSSZMl2M+p65ztd+zKqp
         wgDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=a3kAF47Htw1mcjNgDIKOxqRFlLRuKTO27JlSDcX9ejw=;
        b=df19vuZT+K3Dt/7R1VuNZnFCeLjyJy6ukN47t05iaEwEX98J3Q/Pk/Ty9WdENFPPVH
         23oNFDhS19WbNkbSF8EAEsLu2LX+91qeBonZvUu5J6UeFGJrrztRkbjjMJWrmph191j2
         /2+uzuxAag2U6gq0M9nANqDR3NaHMl2J68Ou22wryyR0lguzp10LnOyNJMEIzyl4P4gc
         oBUSKlaDSlKXE38dD1M0APcHXh8fj2Xafztwu1HQ6NZMcbV3eMuFQnk3HZ9iWeiyAjxj
         VJO/v+kZZWxyg01QxZwEutpg7G75d+E4RsogCGcoCtG/tu5aYUiTpkvQ+dJ5gtcd7cwc
         OZcA==
X-Gm-Message-State: AJIora/P5nvihI0xJIF4LutT9y1lTsDuYTx5F/Sb+azNpKfW1ypssnQS
	A0E2cBNzbCNEdM+nlVuUPQo=
X-Google-Smtp-Source: AGRyM1s4wtcmNW1fB1kvwjLyy+JnojGmh3Rcdzh6D4fiTfvaptx+OGHPbnZT1TOJaAs8kG3gljhPiA==
X-Received: by 2002:a17:907:762f:b0:72b:3203:2f52 with SMTP id jy15-20020a170907762f00b0072b32032f52mr20445567ejc.395.1657639539190;
        Tue, 12 Jul 2022 08:25:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5ac1:b0:6ff:ab8:e8f with SMTP id x1-20020a1709065ac100b006ff0ab80e8fls1649096ejs.6.gmail;
 Tue, 12 Jul 2022 08:25:38 -0700 (PDT)
X-Received: by 2002:a17:906:cc5d:b0:72b:1313:cd09 with SMTP id mm29-20020a170906cc5d00b0072b1313cd09mr24701901ejb.482.1657639538169;
        Tue, 12 Jul 2022 08:25:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657639538; cv=none;
        d=google.com; s=arc-20160816;
        b=ea6D30Y41i20z+2UOCV0VqHd8/yP1cErdIRgkVK409jTOciZ3OT47WDaEf0FhIlN/6
         E4Vm7j81cSt8d0upkF2K5UX/OS76rHrDQ6l2BNf19Hq1uIYwUxzkZG4Y93+hNC3DwDmK
         8ihb6zeBNudFyPbaiHn1ezPG4P60pqdQQoptrLWPkK56wcwk0cbmGkBM2GswrwfhSR1D
         2LHlHyvccAzTGC2oQv6LsKSHbX58JqaD3iEWWhbefqHCYdfChm26ZOuKRWE34/Bq5MBq
         n8sGuXQRJQS0gfjTuPwEScr/Kp85PDcT1QG911oPOOTwHbT4Xkih6n+IpPz/0inepGHQ
         eFng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=qcyer2EH2yI36zcPfaFnFi1V+ng6GsSBGVzj7hzaLxc=;
        b=Aelv+ere/Obb5tm9BRdFAuPM8z0OlLrLfcbojfh/8QSaFNhWee3LHEd87h1JehSGqZ
         PU9x2cLmzCK33YiHvvI3LgYBx99Ca2LTinuEbQldOsElGuLJv+AQkQaHtKQ5OVVOIOfc
         pEB+rkX2tBN4VVyN3U/fgrAX3LFLKHzLAmgIZnVS9uLQ4KhrwUaPdbkJux/pzYbtpZGO
         pNX2YvKbcc2Sc/fR3ynN4zN07cPGqXeRLHcTTzMJaARIMxtH7yxeeYIeKSgXYsk4kyJB
         8ssLpL3CmSwjaGPrt3Hz5GSQPhKAw8ubt4MeQ/mi1of5QmGvptE09EOIY4l1w5yGHW26
         gsOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=mymcslXC;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id i7-20020a50fc07000000b0043a2a36df0asi323254edr.1.2022.07.12.08.25.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Jul 2022 08:25:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id C2C0F20376;
	Tue, 12 Jul 2022 15:25:37 +0000 (UTC)
Received: from suse.cz (pathway.suse.cz [10.100.12.24])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 64EAD2C141;
	Tue, 12 Jul 2022 15:25:37 +0000 (UTC)
Date: Tue, 12 Jul 2022 17:25:37 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Marco Elver <elver@google.com>,
	John Ogness <john.ogness@linutronix.de>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220712152536.GA2737@pathway.suse.cz>
References: <20220503073844.4148944-1-elver@google.com>
 <20220711182918.338f000f@gandalf.local.home>
 <20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220711205319.1aa0d875@gandalf.local.home>
 <20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712114954.GA3870114@paulmck-ThinkPad-P17-Gen-1>
 <20220712093940.45012e47@gandalf.local.home>
 <20220712134916.GT1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712105353.08358450@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220712105353.08358450@gandalf.local.home>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=mymcslXC;       spf=pass
 (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Tue 2022-07-12 10:53:53, Steven Rostedt wrote:
> On Tue, 12 Jul 2022 06:49:16 -0700
> "Paul E. McKenney" <paulmck@kernel.org> wrote:
> 
> > > I guess the question is, can we have printk() in such a place? Because this
> > > tracepoint is attached to printk and where ever printk is done so is this
> > > tracepoint.  
> > 
> > As I understand it, code in such a place should be labeled noinstr.
> > Then the call to printk() would be complained about as an illegal
> > noinstr-to-non-noinstr call.
> > 
> > But where exactly is that printk()?
> 
> Perhaps the fix is to remove the _rcuidle() from trace_console_rcuidle().
> If printk() can never be called from noinstr (aka RCU not watching).

Good point!

My understanding is that printk() should not get called when rcu
is not watching. But it might need to reduce the scope of the code
when rcu is not watching.

PeterZ actually removed _rcuidle() in this trace a patchset,
see https://lore.kernel.org/r/20220608144517.444659212@infradead.org.

Adding Peter into Cc.

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220712152536.GA2737%40pathway.suse.cz.
