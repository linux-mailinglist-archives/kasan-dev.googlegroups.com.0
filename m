Return-Path: <kasan-dev+bncBD66N3MZ6ALRBSWHQ6BQMGQERN2LPJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id D7D2D34D254
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 16:27:23 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id q17sf11161171pfh.16
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 07:27:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617028042; cv=pass;
        d=google.com; s=arc-20160816;
        b=VA6dlb17PIiS21cDxFa/5SOtpadOJIN7j46Nn3O2FUDQmf4+dZxgptT2OlZkorAzIK
         33zR4tFiTpYPR7wzHaq+KowrNRgdtnPw6fSv7ZzyM1OSf+V/nU2yPhL9rEmJdOr04YXI
         TdxSZT/29pcdp2dTedr9oogJTGllVk17NdV1VNV35vlbG/cj0lj2dNYUGXtS0AV+aKZx
         pi8Bsf76AXAMFUWW1bRm+0kIXkTR1WnzIIaa5RWxIsWwp7HjCm6KT7BkDbKYEokIqmeo
         k5sXwY3f3uli062nm3qCteg2rheUGnBtvackied0qPt2PqjK6+laNKRTIvr+Mq61ym+B
         8s8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=cen4l9hqcjiW7MG1Aqy0T8ea7e+nJQz8snSt2zQwmyQ=;
        b=f+dFLVtuOCnn5cYQEMmNOUQtZef73ybrt63xU2nalOKnWlllU1OI/OgFPvWpHu4dgv
         f/O4h5Xj/B22UmsS76hVhmVu7C1ycg5bBMpOWLh7iuKKNgbN10s/1vYpl1b9hgNMgBw/
         80TlGi3FxaFqwSyTkvSOKT/P41vSY3pV1jaa14cCxKBixCPkyaJpwqR0KDtlKQEXMkJj
         itxRnNMYfoQGZkWGCY5fdTj1Qg6gxCZmHCE6L6KDUHzNbMKvUQ0Gh7Qn5/23k7Krj1EK
         vrN4xGv/AExAj7noo6A8dTZRIrmeZ/UqGi0Bd5zgq0fhYaWbt64uKrZJksK/47S0nb0A
         yf6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SN2S1Vhj;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cen4l9hqcjiW7MG1Aqy0T8ea7e+nJQz8snSt2zQwmyQ=;
        b=mGovyRLEUUYwo8XYCAJhMIDBF785RTVwo86fdzedpTz2CU8Li1bLUMTMf9wPs2JSYX
         HNA4q3AEV8EiNlZKS1X+gd1SpmDIx9NvfXoZAJOmbFgnf0VhbVXCTurxH66hnslMe5gX
         VRJS6BtGNpvjf7hngdy9B2Pq3jxvd5iRowaseusxhI0oh99kJ1YICc7kFlbgV09gaBC3
         y5IqZELz5X4tGDAbAOR/8Ynvz7scpG/4zZJ29YByAzuSr+MSzzm2kAkzmvuFuyAS7/xW
         P6QHg8EtAGOg48xXz2heSweOAHNx37RyrqYCZ5OZzokICK1Pi5l2J0v6Va6YMiqWAWT+
         BCjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cen4l9hqcjiW7MG1Aqy0T8ea7e+nJQz8snSt2zQwmyQ=;
        b=SLmKqzuPePtBaLRWdokE7H+TWVd3eYt+RINth/UjeegaDkTr9gXhRxsziR4EEPv0Dd
         NsBZorFNFAqIcN2tFDk9zghtRCU0iudB+f9cVpq6OtJaEysoQVy+25fM+NsmNNmCSvha
         5NuJ017UPyi6TERzfo6Z0rc2t78Rm8Wo2g2KArpMcKemPFgTG8WvcJG4JzGrRc1XkDig
         6O+CaWKXKhi3wtUp3wVRvsBU4tSvdvOGUZMLWBfzQ9NeHp+A2Es9cRdxV6Pb/V/bgTqe
         jKYf+u7Z8TrGHc1V0hpULl2bT4cnjYiExADm16GxBO1gc+J3ckLUXfNhwjcZ/wWD5hFN
         NcoQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533WmjSlGFB0CbMJIjht+bJruam9xlmP5z9VEQtTH0rPB7+PGqIU
	X92MuSTbFxRSe197SnE5et8=
X-Google-Smtp-Source: ABdhPJzagCu6w1KlyYPw49kYY5VBZIIEuWf4cHCVncpgb2vs9BJhGKpFpLQxHpQ+YcicKoRYgRolXA==
X-Received: by 2002:a62:17ce:0:b029:1fc:9b43:dbc5 with SMTP id 197-20020a6217ce0000b02901fc9b43dbc5mr26254679pfx.75.1617028042481;
        Mon, 29 Mar 2021 07:27:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ed11:: with SMTP id b17ls9089878pld.10.gmail; Mon,
 29 Mar 2021 07:27:22 -0700 (PDT)
X-Received: by 2002:a17:90a:c588:: with SMTP id l8mr26309043pjt.120.1617028041899;
        Mon, 29 Mar 2021 07:27:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617028041; cv=none;
        d=google.com; s=arc-20160816;
        b=J0eDCk9nBC+zNooCgWpURKenbNC5eNrHaEBSMcQev9RkaK8wc7LaVx0XdGZwBBr73F
         RB+R4T7Y75nkZXl2PrT+zsHuGPILkL53w/Zy7DAXFOrEGUZkNH28C0UwmovLtK2XKaeC
         D+FMk33vpjL2UZX+jrEueYXBJnW8iuDq/J6ejxYb1hvfuaZPJ4WVWludvAz6Yh5L50lB
         oCmBN+BfaWLmzYLh8iMQmd1KXCVOSN3vSgF0ipbxV7q0+J2kfT56xPwAoniyDMRd8ugO
         Y3auquGD0d6XzN/6PjUyI3dd17KsjrULw/bCMifh/kHy1/nxy7VasZmLu01tjjA8iUCe
         XSmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=EqaKeR15hrRm51GbIjdwaRPlkul2MMX60iIFRxZ1Rns=;
        b=Z9tzib6du595TxMwISYdw+81wmllVgJ33erl7YK7f/T+VPx5oVz8DF3bCI6JHvss8J
         de6XlX+bfEi1Bp7HmV9N94rfp17rcD2iPKlR7nwu8NShug6NhTKo5ztm1onub/f9s6PF
         p4zHl/BFl68S/DK/+ylzPon+6c4Xd1SHaG4Z4uvdWiO+U9NzcY970QVZSYJ3aNTICa1Z
         YrWHV6+xeKpVpzuuoJR5Nzp14FzZlTMTI1OD0AirDttAIms+QJB7Uk18obYLdfMdhFDN
         OB+ymRhOS4Q9+nWKCXRFAHxpT6RI0qDBC4JilCb0vX/a2SbHaveN/ABjIWCv49jm17+d
         HbiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SN2S1Vhj;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id e200si689602pfh.3.2021.03.29.07.27.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Mar 2021 07:27:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-320-UHzIechdPAaIBPxsNiYvwg-1; Mon, 29 Mar 2021 10:27:16 -0400
X-MC-Unique: UHzIechdPAaIBPxsNiYvwg-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.phx2.redhat.com [10.5.11.13])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id C40D8874998;
	Mon, 29 Mar 2021 14:27:13 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.40.193.79])
	by smtp.corp.redhat.com (Postfix) with SMTP id B271B60916;
	Mon, 29 Mar 2021 14:27:07 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Mon, 29 Mar 2021 16:27:13 +0200 (CEST)
Date: Mon, 29 Mar 2021 16:27:06 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, alexander.shishkin@linux.intel.com,
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com,
	mark.rutland@arm.com, namhyung@kernel.org, tglx@linutronix.de,
	glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de,
	christian@brauner.io, dvyukov@google.com, jannh@google.com,
	axboe@kernel.dk, mascasa@google.com, pcc@google.com,
	irogers@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	linux-kselftest@vger.kernel.org, Jiri Olsa <jolsa@kernel.org>
Subject: Re: [PATCH v3 06/11] perf: Add support for SIGTRAP on perf events
Message-ID: <20210329142705.GA24849@redhat.com>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-7-elver@google.com>
 <YFxGb+QHEumZB6G8@elver.google.com>
 <YGHC7V3bbCxhRWTK@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YGHC7V3bbCxhRWTK@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.13
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=SN2S1Vhj;
       spf=pass (google.com: domain of oleg@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 03/29, Peter Zijlstra wrote:
>
> On Thu, Mar 25, 2021 at 09:14:39AM +0100, Marco Elver wrote:
> > @@ -6395,6 +6395,13 @@ static void perf_sigtrap(struct perf_event *event)
> >  {
> >  	struct kernel_siginfo info;
> >
> > +	/*
> > +	 * This irq_work can race with an exiting task; bail out if sighand has
> > +	 * already been released in release_task().
> > +	 */
> > +	if (!current->sighand)
> > +		return;

This is racy. If "current" has already passed exit_notify(), current->parent
can do release_task() and destroy current->sighand right after the check.

> Urgh.. I'm not entirely sure that check is correct, but I always forget
> the rules with signal. It could be we ought to be testing PF_EXISTING
> instead.

Agreed, PF_EXISTING check makes more sense in any case, the exiting task
can't receive the signal anyway.

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210329142705.GA24849%40redhat.com.
