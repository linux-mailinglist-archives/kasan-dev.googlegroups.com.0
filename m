Return-Path: <kasan-dev+bncBCS4VDMYRUNBBYUBVOGQMGQEM6VBO4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DEBC4681B8
	for <lists+kasan-dev@lfdr.de>; Sat,  4 Dec 2021 02:14:11 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id m1-20020ac24281000000b004162863a2fcsf1531719lfh.14
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 17:14:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638580450; cv=pass;
        d=google.com; s=arc-20160816;
        b=GoqBrqHgv8lpipkzNKA2FH77/cPVQ5SyhqmG/wPpmKow6z83bYx4LYfXHyUapwe7LI
         et6YYG3A1II8S/Yv1eje24fN9M/e8vK6s2UwSHjXBY5BnnGqrwUtC26cDMJ0yhGNrjA4
         ee5inbxVxNL880KGNjgKZjCPLsSw7jlDfYyLuoCTe12fSr4qH1qIO6I60xvgsjhpN4IU
         tQSL6LfbY0+fYkenJfO4/lVCOIKB9MOwryX+8OuIKUW2qRT5VQihinODpeKsU6TV8/Q+
         jVRiarmjdP1dttliakkPLLy+hMc8NLkcDhTCULdsYN1KD2cLE7zQYtPnuzXgiG+ykA+w
         RIXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=/R07IRYJy+tCjkFOHPTu7n7mZTaaU8yNe9huvrgVj7Y=;
        b=eb6U7OWcl+oDSOsjjdZXvPV3JpoQtTaQCAYSH/5nEtMskr6HS3CDwwfuOpErwaBBtn
         K+XlDPV/9PR96/jXVBzk8Y9nbaIGgekdzS5CPTYdvq0VsudAIh0XexfPguUAxqBoYIVP
         VjvuP7WeQvaf9dLOTR2X0LlOH8oJu+EWqnrd5Us9cLSf+V6Vhg6gmKfJ80Uw2lB1FvDO
         f+w4cL0R4RP5oY3lvpcFcRBTtNFvRBpiFTT3adYWFfzrZUf8WeRFDiaOALjcxkfQEciq
         xXB/YVEyR9Z1TG0kbT7W341QI2DAvPP5BC4bqD70eIg8r9I2wnF7k3hBJpVICWgCQIsD
         KXVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=asnsLpkf;
       spf=pass (google.com: domain of srs0=wkcx=qv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=WkCX=QV=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/R07IRYJy+tCjkFOHPTu7n7mZTaaU8yNe9huvrgVj7Y=;
        b=p8mZb9B/bM7cbeawm+2d7O0RtzEtLffDS7Jo0VR43KSf//q6vU55KESzvv2sJ1YWrq
         syjhOBvds+akh8RNiHu8poUxngMcJDDUG+LVolqkSCGaJ2YXSy8111qCoTyo9/FOMO/Y
         5u04sK/nj27A3ICruB7XDotBCgIlJ4IB7zS4IR07/rbEdQrxFzfNDdz/IU+AlNZotSNn
         +lMjFjrxcR5Ut5Z6JP2YEvqSqCIcco4RXfsl1lqCE2wWoClCevm+X+Fa19m+36tXJR1i
         VbxmoR1nOT/0DYgz/A+tC6uSZaFcB4NPnz2tukUInoRxwFVSqsnz6o2PSGl96oog5GyB
         aIIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/R07IRYJy+tCjkFOHPTu7n7mZTaaU8yNe9huvrgVj7Y=;
        b=magKJCIMhtANIWOyEYpRIFcczLEOnRaPmVTZjcVZxYbSJeceBbpznDhSXX17cbSSSQ
         /hT3gU6cWIdsygjqq7CjKrVrgsRgYTSgNC113ad9/r/oLQOj/lC4uCuFXe1KuKG9vD18
         3/6sg9sEU+82jxKLWqQF95kQfmD65Ua/pbY9gX6kftMSzrwjC5OsVuYzD3iG8NFMiQIL
         OaEjmu28ZTkw2NHpmTT3HmSGeLbVFS30oyMnIsgiBHcyXMywRhc5P1GLOlD247U53iKp
         /PW9EOamZQVeGz4JfsQAtVp765kQYw8WEIJMq+4WfmyiPFSTmKUOrR2DEBgmR1343Gd+
         ZdGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530QlcTE7Lzm93cV63N0ne+6RWTiqZqPJckFYbuFPNhmyAfr9ChC
	EyvVyKZ21F2qs6E/+Wz3E7I=
X-Google-Smtp-Source: ABdhPJzUF8FWRMbqhkjO36hDuRnVftz9Mp/AakRxLEKKbi4zUgwyKZ86BkErJFAnlSrw7eRMvNYdWw==
X-Received: by 2002:a05:6512:1506:: with SMTP id bq6mr21491009lfb.444.1638580450649;
        Fri, 03 Dec 2021 17:14:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls1209045lfv.1.gmail; Fri,
 03 Dec 2021 17:14:09 -0800 (PST)
X-Received: by 2002:a05:6512:3f0c:: with SMTP id y12mr13033322lfa.579.1638580449522;
        Fri, 03 Dec 2021 17:14:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638580449; cv=none;
        d=google.com; s=arc-20160816;
        b=PTw1uI9AjYHzFAph5MBySVMlYLJF7ZzVxVXsKKldLEhgRRAJsmSYWE6K71TBqGamgf
         vVsNleYyy1Z0N9nwfHvPYEz7QuxDBEEl8km/eQNegfDyl1TYqupgBoGjavtSWtLMEqO6
         udeHFpUWaJq9E8LdJtop/KoQdAXAGtphXbA/v13JR0r/h9MpT+w5ODNg0DW/9ruWyOKJ
         zXggTMgCLv1xgA4Cihto6uRKYK56+ndaMjdXuUM5SiqxyJofbbbYFoq3c3VkkpsxngHO
         cDWWi+XlBMTV9XgKucf4BaJDZwTOjsARbkt1TAibX43FoOyYvE++JkhSPpT/WzZXTq5C
         psvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tEa8TyiLZF22HFVYQp3XJH++/jBPwIDOlP4i7dZ93Vc=;
        b=Kb1n5nd58wdQHpEdYna+7Gz6HN6GutV481mogLXc71gHN+ikn5imcF4fD4hGekhRz/
         MVtZa8JQt2yCFhH7UikXSUqMDbgiN/1+cdx2zdyncKZtD0FvMttKx8kLVrOyOoMSv9Sh
         FVyAzahSNkNoiwyOOq1qS9ovX48NfOBsIHiaDvFGamTOin3bBQd4rne6MEwWb5HysMjS
         10axWjfVbuPxUpPHzSj1GgK4WUorEyO0Fx84zrXxNLlvTby4IDQOc3/iRPrScz5L3E1i
         5AI0Ck3PgzER3Q5DBu7hOgLlygbHTbJF4XNKqefKgJg7lwlLAaTiN188E7NyliIup1OJ
         qcYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=asnsLpkf;
       spf=pass (google.com: domain of srs0=wkcx=qv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=WkCX=QV=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id v8si268448ljh.8.2021.12.03.17.14.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Dec 2021 17:14:09 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=wkcx=qv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 889D1B829C0;
	Sat,  4 Dec 2021 01:14:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3B5BBC341C0;
	Sat,  4 Dec 2021 01:14:07 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id F26E45C0F91; Fri,  3 Dec 2021 17:14:06 -0800 (PST)
Date: Fri, 3 Dec 2021 17:14:06 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	llvm@lists.linux.dev, x86@kernel.org
Subject: Re: [PATCH v3 04/25] kcsan: Add core support for a subset of weak
 memory modeling
Message-ID: <20211204011406.GU641268@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211130114433.2580590-1-elver@google.com>
 <20211130114433.2580590-5-elver@google.com>
 <YanbzWyhR0LwdinE@elver.google.com>
 <20211203165020.GR641268@paulmck-ThinkPad-P17-Gen-1>
 <20211203210856.GA712591@paulmck-ThinkPad-P17-Gen-1>
 <20211203234218.GA3308268@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNNUinNdBBOVbAgQQYCJVftgUfQQZyPSchWhyVRyjWpedA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNUinNdBBOVbAgQQYCJVftgUfQQZyPSchWhyVRyjWpedA@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=asnsLpkf;       spf=pass
 (google.com: domain of srs0=wkcx=qv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=WkCX=QV=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Sat, Dec 04, 2021 at 12:45:30AM +0100, Marco Elver wrote:
> On Sat, 4 Dec 2021 at 00:42, Paul E. McKenney <paulmck@kernel.org> wrote:
> [...]
> > And to further extend this bug report, the following patch suppresses
> > the error.
> >
> >                                                         Thanx, Paul
> >
> > ------------------------------------------------------------------------
> >
> > commit d157b802f05bd12cf40bef7a73ca6914b85c865e
> > Author: Paul E. McKenney <paulmck@kernel.org>
> > Date:   Fri Dec 3 15:35:29 2021 -0800
> >
> >     kcsan: selftest: Move test spinlock to static global
> 
> Indeed, that will fix the selftest. The kcsan_test has the same
> problem (+1 extra problem).
> 
> We raced sending the fix. :-)
> I hope this patch works for you:
> https://lkml.kernel.org/r/20211203233817.2815340-1-elver@google.com

I replaced my patch with yours and am starting up testing, thank you!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211204011406.GU641268%40paulmck-ThinkPad-P17-Gen-1.
