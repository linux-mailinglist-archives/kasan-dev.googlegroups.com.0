Return-Path: <kasan-dev+bncBCV5TUXXRUIBBB5ZT33QKGQEJ5UBRSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id A04171F9C96
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 18:06:32 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id x186sf12483581pgb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 09:06:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592237191; cv=pass;
        d=google.com; s=arc-20160816;
        b=mXSjc9OHFDuzCSyIbCSXaaHLb8Mq8ovRc+qfcwAWXMoLtT4axtvPxoFlbRy5oYFVRw
         8gzA0piROl2qHYvrz3XPYojqULimcCViD2tyevI4/olfRGsW9ZoMKt3k1mLXk+SHOmm+
         A1wIRuK2zec3nHtY+cpY5rjQhlQq1NVNKaIcwjSeX82ypoy9OcuzI5zlmrQHgFHZn5ZK
         pJlea+jcVY41GS6ymHGfpkwMI1sM8UuOD1aPt9M5HdMRniMrOI3dyvB9EANUSsRDyhOo
         bYA5DNFuLPR6dHxD4kzf1+wwN1cLBejXsqWN3uK0OP7/inpFYtBgfYeul6rgSfOgg98h
         avVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1EixWfLUOBeeUPkCT0+kubhE+BRznKgYi53hKEiYU6M=;
        b=T8jqyBe35tb46oTDEJhyEo6vko47ZG1h2WHcdngwK/knvSbBmgRXqX5Bo4clpRE3ly
         LkURwEtfahNihXmYJsCnkkv2h3AcUmaOymyG/zrugJNQz9KJv//mVV3ptJPSWp1+2ek2
         p+x0OqDFqklp0cfuivQ2i3b3KKM5Mstedwa3lWZP2qql7EskmKKCNoxba8Hou43sFik8
         zxhL7Zca+q0yvgJ+TGwXUN9poJUCGZ9dOM5J2ZvfKiLVrhYDWxP6IB20KA0cNoxUDWqZ
         5Mu6XZHLBDawbZ3WjWeqMcBUKQq3wYsCgX5l+TxEz4UVNSU9EIgmvOPXuITrdGu7nvyU
         Xcsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=AKdMnBO7;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1EixWfLUOBeeUPkCT0+kubhE+BRznKgYi53hKEiYU6M=;
        b=ckud9gMuPx73lEugoj+s708PwQ6dfKGus4uo7t90TTwgiiwA6BGjBBppEXKJpFXBeJ
         X2gNif/k3GZ+vU/i6QiiQqfopSWiwD8AeeSwDNdTWCxuuxpuwFq9iswG7d6P3jfPflng
         4pFgAeoQ9V9brpZwVrBX9V+7JEEOHL/YqF7LVrlTNXmP1QRkXGyM8url/IGDFxZjRvZG
         xuGD/ag2mu8Z7Oj4hPuXE11He8LlxJcAiGaMTuE6M/elkrWwZLFaFb/9ExhWR0CmJhMN
         Y5leUIS7mR24msa3ycufo3MPeS7N4LSzrEvuIVO+szAo7s6yYsutQvIA0N1NxXP4ICEI
         e1SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1EixWfLUOBeeUPkCT0+kubhE+BRznKgYi53hKEiYU6M=;
        b=gO2/Jp8eVoGWuJN+4PyUBM7lnqdS4ohPynGfzUd/jppwJ7g66Fdx5Thws9/PsFS52T
         Lps3wRecAE4gBAKkr/c0CU2n+YI6PsmO2smv7g4SG2IDa0Fr1rdBAGjFtNkaCamjGPv+
         AJpDviSDeXKtrI6wBvHG7dN8BeO0TP9b3bP6LqLqeVGjzjIMgC3OrAind6W1iI8VxTcy
         ja8Yz6vqLCMtT9aD/jVC5Cg8G7c8rUHVTz9/PyOq2f8GrPpj66iVv61pyetUHP462OtD
         gagMJtJp0SQO8O79KWxuidg/aft0cNrEe+mmYHmKF1DJjGxcnrx7sMVtusVmrzwIfaeV
         mu+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310Z3zjLh8pEsVDOGmtC7P825eJEB0JpTkOnlss0EpkHCNw3ccK
	nBtT3w36S0cJSlVfFwa6CyI=
X-Google-Smtp-Source: ABdhPJwWXJMJfmRysjz07pubVvq/Myn4IGK+xhU3p+vCrFX82+NWE4eSSjX63uo1MhAlvEzMFkRhOA==
X-Received: by 2002:a63:4f1b:: with SMTP id d27mr21278684pgb.389.1592237191251;
        Mon, 15 Jun 2020 09:06:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:147:: with SMTP id 65ls5015466plb.9.gmail; Mon, 15
 Jun 2020 09:06:29 -0700 (PDT)
X-Received: by 2002:a17:902:c40c:: with SMTP id k12mr22186134plk.11.1592237189413;
        Mon, 15 Jun 2020 09:06:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592237189; cv=none;
        d=google.com; s=arc-20160816;
        b=JXAT5FT/6ym2KFXJq8jFF0J06x5fiNUwKBP6xQOTf//rPS3YLDc+tMeei2p7zZ6QNY
         5FObfDvF5zE6+aQ5Zc5cWJM2D0nuOOz2/ebjeJoS3QCdasWl09lwQuAADx7DcO42SvGm
         d3Ha/yAgqZz9wZrJVjwf+Qag+ADZR/xAcHwvfwMOEBFltyfrnT/0bUss04uqY9CafJKI
         9okMTEE9aL2oHbrVUHi5a3BQdAOd83bd7c1MEmpRBe8htOEPiH7rOfFylAcyMq2wQZ3G
         rGsr5YpRbtXsBOmHGkoft80i4x0HyKTo5rZJgzyczxQVGqS55sFzj7gRCa3492YAqTcC
         3alg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qrKBJFe3yFlrMjIAOwsfJ20n17pd7jkHQNcwSDFSIXk=;
        b=ngGjkekNiy3qghQbr/Gh3P5gRcqrf0LOTgdPOAelGDUFZCsT700fi2VIcKmC6tGjW3
         mpgpj0LF1rnBOnJrZlRqMxJVqcWn7E3Bjqgg8W+QMD1Bm2eifmBfyOZ0zsPooXtnomrq
         pUzEdZkhBTdGzxD+HvvlmNCPER6bMyZYIcfVY541BKRXbsUMn52BI4Ck4G9ffsIh763X
         EBe/x8/8E44iM/pHFeHxUj4+jS4IFApL/c4/ytKv8qIey7HeZ9N+vEWxkNQicc6yoPhA
         1+NhDRN1FcCUYUyTA0cnIOmaAVUqUQGZgEidohmujgtKYpOGGV82gONn0cQ66zu6OUX8
         doXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=AKdMnBO7;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id u2si218771plq.0.2020.06.15.09.06.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 09:06:29 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jkrcy-0001cG-IV; Mon, 15 Jun 2020 16:06:28 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 15C6B30604B;
	Mon, 15 Jun 2020 18:06:27 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id F175221441C0D; Mon, 15 Jun 2020 18:06:26 +0200 (CEST)
Date: Mon, 15 Jun 2020 18:06:26 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200615160626.GB2531@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200603164600.GQ29598@paulmck-ThinkPad-P72>
 <20200615153052.GY2531@hirez.programming.kicks-ass.net>
 <20200615155220.GE2723@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615155220.GE2723@paulmck-ThinkPad-P72>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=AKdMnBO7;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jun 15, 2020 at 08:52:20AM -0700, Paul E. McKenney wrote:
> On Mon, Jun 15, 2020 at 05:30:52PM +0200, Peter Zijlstra wrote:
> > What shall we do with this patch?
> 
> I plan to submit it to the v5.9 merge window.  Do you need it to get
> to mainline earlier?

Yeah, we need it this round, to make KASAN/KCSAN work with the noinstr
stuff that just landed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615160626.GB2531%40hirez.programming.kicks-ass.net.
