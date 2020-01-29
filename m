Return-Path: <kasan-dev+bncBAABBTFYY7YQKGQEK2FBOIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3b.google.com (mail-yw1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A21EB14D12E
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 20:26:05 +0100 (CET)
Received: by mail-yw1-xc3b.google.com with SMTP id 12sf793487ywu.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 11:26:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580325964; cv=pass;
        d=google.com; s=arc-20160816;
        b=uZ2LbjeRBWiuzNJ8WFJcBcBRXtjSwa5FzzvAAtDsIBvU9n4W53lQaVSN29uWhBndlE
         dqoF936z4TUfEOgFQal1qKDbcLSiovg03W37hSzoxP8OAkz5cEwS0R57sXg+T0An+ugz
         shKX43WTGC1jjzDJv8GAZCxioiCv8K2NhYy9ClJdFkrSJ/qhnc2Y1+oBWfwVXSLWsk1C
         utWoHwzobM2e19Rp9qloleVVrp34Rjxy9Z6aT1UPDHxphjMBTn4Fl6IbKLxR3HlnRUTd
         dYTc57R15EPQNYn8Id+UOJJa8IBsTj6+/tZ0LBicM48MylH2kKUIQz22eETbhCgzmlUU
         OY5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=+AQNN567Poq9m4SGFxFBW06MDE9V+SDOYw49djNv8hM=;
        b=V4SNciKf+Qzqh5HT6yooVGfWmYjcuIkqc7dcY90BkMtNIf+LYl5Yo+84P9yVT7w3mm
         BoblTYL/mHclnOAFUaIkAqqIbaoI3EOTTaoCcz7gJFn6GrCmonTizJ+6zFyESGahba1r
         IwlergW1O58HGDBQABjYCm67pG+wCkEiM/v1G6zfHW4vMwsmbHinxhNspXIux2jNj9SH
         9I/DPO3nVE/VWK8zhHgs2/1mPgylPl+hNOD+xKRe6wBTeGpdWOsj1+XZSNeXQ5AGfB2D
         DbUVPeMC/jPLS05iKqhVjEejjibu/qbTJ6ocwYVxTP4gIfswtmJ6PmAVBIjFH6cW4S9U
         gxZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=jGfMBgUq;
       spf=pass (google.com: domain of srs0=gagg=3s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Gagg=3S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+AQNN567Poq9m4SGFxFBW06MDE9V+SDOYw49djNv8hM=;
        b=b+TEJ4ia6Zzeg8irLzeRXbqVl8Y62r03pLH3XHBp0MY1KJ/haUPQV7qeTff9BvmDYs
         hgfrXXDeengEHcA6EOEvD+c9Lvin0nXMKarL56VuCNuKNL0oBXPPub/QhC5YHayPyZnF
         AFPEZDvhCCSllERccLHTm8WMR/gvN4kQrFu/ILOPuRkGEnbMhk1YAkEBLpf95pb9+6xR
         AmYZrsUeaQETG3DXs1NPDhlv/Kpveg4yxkiFQM/ZxMWsBdDO+nNareEbGebavGy+3nbV
         sxt4Czr2PuaGRjGuYPo0w7w97Cc8fV3BNjMXWIg6BDWpjtyvRBE+0xaF6xh+ZXZ57urb
         ELKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+AQNN567Poq9m4SGFxFBW06MDE9V+SDOYw49djNv8hM=;
        b=NqMlsTh7wnw6qc/Of9FmDlw2yP0F+P/mo6YOGythbr/kSRhtt5V3QCuark3W++ng8K
         /m45ghZLJ8T1US3CDf1g8u/bDYBRFb0LPemmrqObE4/DCwjuw7k3dqhwQstfswjGA/WN
         mM9haRs1W0vOsFP799Dy5xRmu5aHGd0uEdnsa/wM4THUF8HBP2YLOtKzaRAt/AubIkti
         ieAbTTVBYLmYkG3TKJk4qznQSIcS0ow3ODxbAlNmd1pPP/pmTgvGCx6ryxHMZ+sB05jz
         4RhvynEuCMIwzI7q/NvT/o2nq1cUpic5fhoLKAlJAQBxILe7opog0/eIPaIWLPuDcPt+
         72Mg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVbTDk0/NIPRDT+oo8gioXJeDcVAykFaQWktHzORK6nn11ZTIBy
	sugTcjgQQm0o1didt6PcgBU=
X-Google-Smtp-Source: APXvYqxM9gbOmEdIL4EOm1+VQVsl3Ns55tiszcmAV/+jBpG56Dtbq5dJwGaonGpJve7s3Tson0Q2iQ==
X-Received: by 2002:a25:2641:: with SMTP id m62mr872482ybm.454.1580325964563;
        Wed, 29 Jan 2020 11:26:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:ad1b:: with SMTP id l27ls151970ywh.10.gmail; Wed, 29 Jan
 2020 11:26:04 -0800 (PST)
X-Received: by 2002:a81:4b42:: with SMTP id y63mr359048ywa.502.1580325964188;
        Wed, 29 Jan 2020 11:26:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580325964; cv=none;
        d=google.com; s=arc-20160816;
        b=Ecv0iuDEoL/29pwjZeYxkUZ+Ukco1eFrrhfSC64BC25gJ9zbAmEE+Gg2qUF+ipKkqC
         zZnWgGZ2ClXMJQjljTeRDYbh19JcPOTNZralHZvcTEsfKpamizJilsrLX2x5Mw2B5AG5
         WybkBjkrQiHa9lJSNGYwl/5J3V++wbRREvZoeCHuJoMQ2jf45qCvTEQ2WzQmgo294R9l
         x2VfvgKk/A7kDl6JU9vkZy/S/M3FNsiPHAmy5MBxQYfpft/EP4LWkZ7gZ9DhHK0OfvE1
         QMNI0ybu1nBjQupmJnP3OeGJgQfU9iYHPi1y9eNIBP83M/EBoHAOwiQiR7aEKB8JWYhi
         zoGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=WtGEfepyy0LbV7lFOfxrrSzZDn1Nz2ZTUtAy6mD4oJ8=;
        b=yhQGdT16QKfseVBt5duhbtoSNRuiohMrydYj10gt6R4zVSLHZwsOucpvKdcSE48F0s
         IgW+zr6DmWeanqIkYKVfUNl3ShUjZlip3YnFWU+t3Rc27ZgWGkqAjhWuxZsinNbyQkBz
         ecOu4uwYl0wOKjQj5P1OsNLN11sfl3S0jHef2cPwZp9N2InXGSCfngLUof0RyAqvLtpc
         0Yrzd5knx3C0asneeHzuOBsE/37tam9OOMNXGWg1ddGscAJ1FQjlMd+FxJ/z/KjeNo7D
         m4DUNl/ro6pwnTsxD5W9xK37hbkCWSmTiwIC5f/4VDJr76tuVqRBr9hUZgiFVvAR6OpZ
         T/Kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=jGfMBgUq;
       spf=pass (google.com: domain of srs0=gagg=3s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Gagg=3S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p187si148270ywe.1.2020.01.29.11.26.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Jan 2020 11:26:04 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=gagg=3s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.141])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2B80120661;
	Wed, 29 Jan 2020 19:26:03 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id C3B9A3521AEF; Wed, 29 Jan 2020 11:26:02 -0800 (PST)
Date: Wed, 29 Jan 2020 11:26:02 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, Qian Cai <cai@lca.pw>,
	Will Deacon <will@kernel.org>, Ingo Molnar <mingo@redhat.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] locking/osq_lock: fix a data race in osq_wait_next
Message-ID: <20200129192602.GA2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200122165938.GA16974@willie-the-truck>
 <A5114711-B8DE-48DA-AFD0-62128AC08270@lca.pw>
 <20200122223851.GA45602@google.com>
 <A90E2B85-77CB-4743-AEC3-90D7836C4D47@lca.pw>
 <20200123093905.GU14914@hirez.programming.kicks-ass.net>
 <E722E6E0-26CB-440F-98D7-D182B57D1F43@lca.pw>
 <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
 <20200128165655.GM14914@hirez.programming.kicks-ass.net>
 <20200129002253.GT2935@paulmck-ThinkPad-P72>
 <20200129184935.GU14879@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200129184935.GU14879@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=jGfMBgUq;       spf=pass
 (google.com: domain of srs0=gagg=3s=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Gagg=3S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Jan 29, 2020 at 07:49:35PM +0100, Peter Zijlstra wrote:
> On Tue, Jan 28, 2020 at 04:22:53PM -0800, Paul E. McKenney wrote:
> > On Tue, Jan 28, 2020 at 05:56:55PM +0100, Peter Zijlstra wrote:
> > > On Tue, Jan 28, 2020 at 12:46:26PM +0100, Marco Elver wrote:
> > > 
> > > > > Marco, any thought on improving KCSAN for this to reduce the false
> > > > > positives?
> > > > 
> > > > Define 'false positive'.
> > > 
> > > I'll use it where the code as written is correct while the tool
> > > complains about it.
> > 
> > I could be wrong, but I would guess that Marco is looking for something
> > a little less subjective and a little more specific.  ;-)
> 
> How is that either? If any valid translation by a compile results in
> correct functionality, yet the tool complains, then surely we can speak
> of a objective fact.

Marco covered my concern in his point about the need to change the
compiler.

In any case, agreed, if a read does nothing but feed into the old/new
values for a CAS, the only thing a reasonable compiler (as opposed to
a just-barely-meets-the-standard demonic compiler) can do to you is to
decrease the CAS success rate.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200129192602.GA2935%40paulmck-ThinkPad-P72.
