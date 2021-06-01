Return-Path: <kasan-dev+bncBDV37XP3XYDRBONN3GCQMGQE4OLDH2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 940E6397716
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jun 2021 17:48:10 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id s3-20020a92c5c30000b02901bc737e231esf10498592ilt.13
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jun 2021 08:48:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622562489; cv=pass;
        d=google.com; s=arc-20160816;
        b=y5S+iD86zAAky4iInw4pahw+Cky4n+GRG4eK5695OBHbo9/VHphGBPG08+gjpES/dY
         H3Pway89DcUylOL9ccaZ7I2jGVaWv+YKgRCMwgAFnIjg7hiSVsEPLqNrOUAH688QW/EK
         tuhnJ44p7CTOzyZuy4xCS1gXiOOzbI8hiPK/XqG9N3HrKiZold5qFlcXhXd4jNtlPZFB
         JCsyVSe5i9RfI12jZ5CCzTbqcS/JZ3OmhYMDrSlPkBFYzYzMY1FNn2NvzRso+maZg9/G
         IZJT7JqyIU1mifrD3c1n1Crxos4aSFwp6YOYNwlStFlDn4Z8aoLhVrROxfqaAWsuHKkW
         czgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Wc+/u/ip4/v61XjIPUWOEGFRXGviLE+kL5jOJDrdHjk=;
        b=P5HHCdX1cEpEW7adIBAB4/G2Kgr5tXqBqCQP9a3pr+NT40o4wF9EolrzgrH/xaBTTO
         6LSXErW37MTHlwvXhrhQuhpp2mKavPu8alRziqDZ1vpSZQU5DkPoZEUjsW3d4y8bLwmi
         gwWmIQi+iYJcwhbDUFQ7U/E5DihIypHORA12/HH+p5a/R1UnkC0wP/lM1DYPMrqCWcUX
         ninr1Kfq2Wz5EXQ28PjQctaOtx5eNqrAOGkg5B/2pqLHgAVqgIy3U5sjXSLYnbeQml2A
         9uxQRfQqPf2KsuTL5kXpHn+FyRMEos5v5WVERMvTsxrQTlKo5k04bVY3Ps3+492n04K+
         grWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Wc+/u/ip4/v61XjIPUWOEGFRXGviLE+kL5jOJDrdHjk=;
        b=kW2n0/zAq4IGgZDIkKrJFae0/uA68Qmpli4ZzqoBy6yKBOYKaTce+4jBnfgwwqNtgF
         OvwjGusxEUIpk/jbgjwF1SLc6wGBqmcFOcW5uaagjMTnIRyM7bH1cJbRVtJQ4ACaEQ/j
         58/MNPBaiDtF9vF4u1aE4UseqfqXyBz9lsEOPXZZiu7Zt+vqvDFow223qFJJyseynOlp
         lb3rUX3MKyzRDoILuE1EYUrgwVAGck1G6QCM29f7ScVAuiuT82PcGvu2FDz6q+ThkJqF
         6d0xZhdcea3P4Cn6HQtzh6NebtpOlNdVMfhW8u264Xsaxy0noQndD/AG3FF88F4WCUbY
         /61A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Wc+/u/ip4/v61XjIPUWOEGFRXGviLE+kL5jOJDrdHjk=;
        b=FXuYzLTMXqENS57FKe46XexEQk5oGdouzbz0suy8vGgQpFg3/4jzeQlZNuj38pS0X3
         No/hm2l1kzN3dFkj94YUAq+ZyJFlv0P9wZIYlp8maBlWG3h7S14f36tHTd1ElzLTrKps
         Sy0Inzkv74DFgkeybLC+htBf26GwKb3wsedelWe6Gm02qA1B2REvNtoMCEgum/kIODPi
         X42UWE9QCJFacar4xs0trnKSpWB/jqH2LFfzyxasz836hyNTpH5JEi1fchmkF7PX2XSG
         7hQk81QHYStVhr0M3+BIS3/5d+m3OW2UvUQl+6L6Fp8X6SFwroktRPtcH7Bk3ng28nWI
         Qw1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lubYNviYOFsT9iB6vImN+jPOlGoS7r3LCCB1UXHWKyOmsbBo2
	hqU06MEli6M3WRhn496rQW0=
X-Google-Smtp-Source: ABdhPJxlakWnX8M9v6DLva2k875TPDhzkHe/srZcC18hxCM0WbxGtm3Rgm2xaOQft3id2GS/UWFhuQ==
X-Received: by 2002:a6b:7f09:: with SMTP id l9mr8298635ioq.169.1622562489251;
        Tue, 01 Jun 2021 08:48:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:d002:: with SMTP id x2ls2792694ioa.11.gmail; Tue, 01 Jun
 2021 08:48:08 -0700 (PDT)
X-Received: by 2002:a05:6602:21ca:: with SMTP id c10mr21923884ioc.10.1622562488790;
        Tue, 01 Jun 2021 08:48:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622562488; cv=none;
        d=google.com; s=arc-20160816;
        b=YXNqqhZaAZ3Ngv77wpo4r2ZdSQ+hNpZU7WWbBNjBLS9CAlwdBzhrGy14Vs2NbbGRG5
         PRqgDH0eRX9/XIaKOKlN2fXngMo9MbKZsaUZ0D9alpXFy0tdubpbQmiCBVS863yS0wh4
         shn+z6y0loR399fcrjy1sjPyGp3vD+yXyojuUcpsfINoHSatjN6g0wnmP7RziAXqEKrR
         EcIbM/jWCuTAGseKPcdY5HY+rm5sZ5PkFp1RCPviGnjfQ/19wXuNvIesiJRQ8bXRUpUt
         wzNY/+7wR5K8X7H8BnAVCIxa9emnF1xTJ/u8dbBrFO+qDXmVl4FSK66bOZzbWoTHs/iE
         f+EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=kl0N01IyZNIa0lhApBVCtQd6VfmCUaVxROjjqyW/OLM=;
        b=0KFKvmfQnlP/8QKVuxEeIPmM+xlZeLzYK8K1jrVR3Xyi1OSXd/b6jyUwA61ZyedRU5
         q4H09YdxO49F4FXc4s9IAGRulVTGDxSzKAJsXsxeNkqQO/MzIg6OWtXfqfM7dVuG5GRu
         LsT6BsTC7JtywXV80cD2Tb8wtOj8ClD/8RcsZ26zOWVa8wNhhSf46QMrh8BMr20dF1o4
         evIXNPUYqp+DjpUcuns2el/09uSXu+I9v2VC++WhWcaK3E/hAo9cadR9tWmoWm+tywjw
         p9OKbTYmdwiQsDZC+Qjmle4enN6JD0TfLkQHVJ6hKP/Azo54TyUXUf6NTjIln64oAckt
         Oheg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v124si1342444iof.2.2021.06.01.08.48.08
        for <kasan-dev@googlegroups.com>;
        Tue, 01 Jun 2021 08:48:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EE39E6D;
	Tue,  1 Jun 2021 08:48:07 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.0.106])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9E2D53F719;
	Tue,  1 Jun 2021 08:48:06 -0700 (PDT)
Date: Tue, 1 Jun 2021 16:48:04 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, Boqun Feng <boqun.feng@gmail.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: Re: Plain bitop data races
Message-ID: <20210601154804.GB3326@C02TD0UTHF1T.local>
References: <YLSuP236Hg6tniOq@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YLSuP236Hg6tniOq@elver.google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, May 31, 2021 at 11:37:03AM +0200, Marco Elver wrote:
> Hello,

Hi,

> In the context of LKMM discussions, did plain bitop data races ever come
> up?
> 
> For example things like:
> 
> 		 CPU0					CPU1
> 	if (flags & SOME_FLAG) {...}  |  flags |= SOME_OTHER_FLAG;
> 
> 	// Where the reader only reads 1 bit, and/or writer only writes 1 bit.
> 
> This kind of idiom is all over the kernel.
> 
> The first and primary question I have:
> 
> 	1. Is it realistic to see all such accesses be marked?
> 
> Per LKMM and current KCSAN rules, yes they should of course be marked.
> The second question would be:
> 
> 	2. What type of marking is appropriate?
> 
> For many of them, it appears one can use data_race() since they're
> intentionally data-racy. Once memory ordering requirements are involved, it's
> no longer that simple of course.
> 
> For example see all uses of current->flags, or also mm/sl[au]b.c (which
> currently disables KCSAN for that reason).

FWIW, I have some local patches adding read_ti_thread_flags() and
read_thread_flags() using READ_ONCE() that I was planning on sending out
for the next cycle. Given we already have {test_and_,}{set,clear}
helpers, and the common entry code tries to use READ_ONCE(), I'm hoping
that's not controversial.

Are there many other offenders? ... and are those a few primitives used
everywhere, or lots of disparate piece of code doing this?

> The 3rd and final question for now would be:
> 
> 	3. If the majority of such accesses receive a data_race() marking, would
> 	   it be reasonable to teach KCSAN to not report 1-bit value
> 	   change data races? This is under the assumption that we can't
> 	   come up with ways the compiler can miscompile (including
> 	   tearing) the accesses that will not result in the desired
> 	   result.
> 
> This would of course only kick in in KCSAN's "relaxed" (the default)
> mode, similar to what is done for "assume writes atomic" or "only report
> value changes".
> 
> The reason I'm asking is that while investigating data races, these days
> I immediately skip and ignore a report as "not interesting" if it
> involves 1-bit value changes (usually from plain bit ops). The recent
> changes to KCSAN showing the values changed in reports (thanks Mark!)
> made this clear to me.
> 
> Such a rule might miss genuine bugs, but I think we've already signed up
> for that when we introduced the "assume plain writes atomic" rule, which
> arguably misses far more interesting bugs. To see all data races, KCSAN
> will always have a "strict" mode.

My personal preference is always to do the most stringent checks we can,
but I appreciate that can be an uphill struggle. As above, if there are
a few offenders I reckon it'd be worth trying to wrap those with
helpers, but if that's too much fo a pain then I don't have strong
feeling, and weakening the default mode sounds fine.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210601154804.GB3326%40C02TD0UTHF1T.local.
