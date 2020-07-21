Return-Path: <kasan-dev+bncBCV5TUXXRUIBBKXM3P4AKGQEYKMBVSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 25EED2281A0
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 16:05:32 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id m22sf8332967vka.22
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 07:05:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595340331; cv=pass;
        d=google.com; s=arc-20160816;
        b=SJ6CIL1WeptxwB/r3JMvxfPn0iWCr8/nXOnQ2I9/vt0mEWOMa5PFj91goCOWSA5TV3
         K3ffvRjgljOd3AkVXc4rnCUT43UIQ17U6HDbJOBKzHwatsz23hUdOjWNNEsx5LA6EXze
         Q96/ZpZvt8PTndvzOS8e23aIBURZwt+oVImpcMczb36b1IcdNCzxFsY2bUpILAhC5/oN
         voZKpE4B8rZfv8ZWqPrTyxM3Q12R4Tm45qpfWy+xXjPwiKMICDO5EogtPKAVrCG6zVbN
         T9Hy+9Z0dddKM8WuWFXHHOKBfhvDpB5G7x3+tE0CQtlxehq0UHocsdDBcO1yDrtOki8h
         XHuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=lg8dAIPc0IdymZASwMB1He1wF47FQwR3f6U3IoIsz+w=;
        b=sWXgSSpoNsyZ9MuC5G7cintO7gVE8FvDrN0hah3pBQ6n4BQRnhtrYIUAJI9eQYYzWe
         wPWCBsfOJzW6CceohCl2OYU6ZqJlIsxqp7/ADHKyeuGBQUfJyFfBL7P718QnqDkSw5hH
         ZNyv4Pl159ujdnSoMPfzzBWD7sr2Q/5yBrczD0igDjGY2oRAFh9J6Oa4wPjVa/AYhjCs
         U2T+4/Xx+Ixorh0P3UeM2HeNSAY+mjQ9ZH/vWS4HCXht3jXQHGIIIMfJ0yMPCiBBFbGD
         IaqSdNhbsywkfPlBmn7rCkQKs7Epd7OSdjr24GeBWYd0dz1wjvn83PWhOPINJvsNHpud
         9iow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=Kca9vB0Y;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lg8dAIPc0IdymZASwMB1He1wF47FQwR3f6U3IoIsz+w=;
        b=ZSXdKj5r+866j4i2Zmw7oL4ySUe+yb1ER2teEY8+NBiwpJ34nC8PXHNR0eyuR8xsON
         rz4hiqH4Ew4MLMmEZjPfGirepM8EV06tNVNaweectHlFDwPxbt6QWNQGjU78kvPDujWG
         mFfO6qaMjoDU31lml19s9q9nndPMNveEiSSLA6FFiexle0nV00CP0WlMNSGuy0TFp16o
         QexNpuwI5LU/tHy97n4DECRpBoIA7sgBpdYZnH8n0GKOOEivQUvzfar1wQ86O5XHiAYO
         W/Ga1sCiyb8yAIOz6HK5oPHSnzPZ0tSHAW9p4euu8wQE86CxLlN698wlU/kg5qrUEdYg
         vizQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lg8dAIPc0IdymZASwMB1He1wF47FQwR3f6U3IoIsz+w=;
        b=Uuhv0l0o3VPLhrU0e7vc7MUnsfuOBR+DnCGkRXBbMEcEiFFhFgU/0+xy17KRln0GrY
         wtGaHk7eeaiU0NGb1TTvbeuOBq+RmGe+9ld44HFwRbNVP3FI1u/tOlB7DYmniLLPIbNQ
         MXpV1mFOxqfP0J7/Q9hMg011Q7h9HGsf5j38uPIaWeMdXioVX3Xpj8Y6epfvPeV3mj9k
         GPmGmLXrNEEtFC3XiOrIFkZaZ1zuwk56NbtPpzI473qDPv0eTroe0h0ZicbEaEfkADB+
         +LWqQlHwdKvlwLhWxKVpihnrvFjzk0TwDjQTKudOlJ5FUvKttrcB3WDG/vv41SUY5xIa
         xE7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/pARP2t37pcMuUElKvDzE9djoYVMRZgSWSRxvgRekGdt9nVMe
	lU0W7GAupBg13gKdaGbQNz4=
X-Google-Smtp-Source: ABdhPJyy/KZsBWOCxf5WrK4xrv0/hBXctkIkbX4zeDUrz0CIAsM2zCB36l5cOY0TM5rR/bMDshvDgA==
X-Received: by 2002:a1f:da83:: with SMTP id r125mr14838643vkg.98.1595340331109;
        Tue, 21 Jul 2020 07:05:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4906:: with SMTP id z6ls697385uac.6.gmail; Tue, 21 Jul
 2020 07:05:30 -0700 (PDT)
X-Received: by 2002:a9f:2256:: with SMTP id 80mr20338634uad.106.1595340330657;
        Tue, 21 Jul 2020 07:05:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595340330; cv=none;
        d=google.com; s=arc-20160816;
        b=hA/REIunYc6mxXxI6I7NWTK3wd+/YLQwg48rIw3dNfpiTTvA8yYPVUzYowHnAaR/hU
         QZFD48Tw7sj3VoJAV7g7xhRA6QX7o4bqrGFDAuJ3qaXnGGXS6+AEpfKnZfZYxiJt11CO
         5mX8gCKS7NgwWL1Y/CCkgtWCzTA1mEWieZJeNbGU4+HVGXQURNfTBT8p5HGtsLBmH0FC
         ByvhoBJ1XXXFUBAFr8vckGhNjD6JEXKyuEG4lG+ec48Y+VsUnSb6duxegnN3T6XP2dVW
         JPwkqVcX3Tj3vDLgSOosqN6esi9Kx3CvRudgyfzgGON2Fg/xF/wIHLnLVPX86zuR9Tcw
         0lHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ECmtTwPcomeUswGmRukW4GbqA5iIbD8q9cRC6UN4mms=;
        b=MgpHsG1am8dkI+8b/sXkZtfo2sk32RlWFDsu44DTSbjJMKJre7O4shsDYBt1iQQbfo
         wM9l0Hzwxp5mGnCbPOhUZ0IUuY12uVdoTbIjdsln73WHpLJgsZM9dk/OdYWepnyi8pZ2
         cc7pchoGUTy+YzUoie051YsBGnio32GNZQtGb7PUEPLSBZbIkSgSBtNQ/902iujEMgrz
         VURPFYZTCd7AmgiSMb9n1R7WNhCwymdN0IrA3xQ5sy0o4SqHIn3XU6+uaOPO7HRCq/51
         9/rIKbSy7H/txMKDMmcEkGnOQBNzt8XoqZjBeCxQzzdye1spcyxyRMpGZJHkSOQvSSa+
         na9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=Kca9vB0Y;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id l129si1398141vkg.2.2020.07.21.07.05.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Jul 2020 07:05:30 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jxstY-0008M4-Ut; Tue, 21 Jul 2020 14:05:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id BB6A4304E03;
	Tue, 21 Jul 2020 16:05:23 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 8590720DCCA0B; Tue, 21 Jul 2020 16:05:23 +0200 (CEST)
Date: Tue, 21 Jul 2020 16:05:23 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, will@kernel.org, arnd@arndb.de,
	mark.rutland@arm.com, dvyukov@google.com, glider@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 3/8] kcsan: Skew delay to be longer for certain access
 types
Message-ID: <20200721140523.GA10769@hirez.programming.kicks-ass.net>
References: <20200721103016.3287832-1-elver@google.com>
 <20200721103016.3287832-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200721103016.3287832-4-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=Kca9vB0Y;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jul 21, 2020 at 12:30:11PM +0200, Marco Elver wrote:
> For compound instrumentation and assert accesses, skew the watchpoint
> delay to be longer. We still shouldn't exceed the maximum delays, but it
> is safe to skew the delay for these accesses.

Complete lack of actual justification.. *why* are you doing this, and
*why* is it safe etc..

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721140523.GA10769%40hirez.programming.kicks-ass.net.
