Return-Path: <kasan-dev+bncBCF5XGNWYQBRBEVA3PXAKGQEHXJ6EKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8356B1058EA
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 18:57:39 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id g13sf2786120qtq.16
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 09:57:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574359058; cv=pass;
        d=google.com; s=arc-20160816;
        b=KcImUhNuFl5Y2/OJHzWKbgX36rzfHHud1PnmboMBas/OJcrmT3ATlEqh0H8gCevtUJ
         EKMYHZxRcxciHArt5rsjggvcR+wlnELWMfOCe6wuRDe8u/unv+hTErZ5kssLCCze1BEn
         XTR7/EG/ZfiTnEc1nvs4KWc31Kor5zFG1nWhwfBYNyr0GmhRs7Uw7FG6UVYpMjz/v3mw
         yUr0Su7L4cK4tNpOEcuzRA1NrxfZHdRKoS42ZKfR5+EqyLrIQnaPLM1DoBDYG1f0fz6b
         THr1ZPdAASy6GLbFU8aScDv8VHvUyY5LGP2XOS1mHvnEa49g/JGukJ9v/zLRx4d5XSEl
         c/QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=o220BKePFDSEDeaGp8/o6Yv/MdPde3Mx3xSLn3jHLGo=;
        b=ReFqWfSR5j9z/fcWnO6joLyxPO9sILIdPt5FQ+k5iBUrnVmufjJzQAUmtdsLBcdE/V
         Aas+ru3jay5hhmHYEOCFIxWb1KArTPc6q92Ut3k/KdAeVVURFkncP5yw3PAzmgEskGlt
         PcLEx4IQjbLcCB3cCTf0SIdi8welHGs6PZSrPcPZO/ViF7v2f5CSiA4ETnzAzXCT83gO
         zMdq0ZG1M89uJ9ALSjITuXzFbJ/oay5Axs7Ts/BZrqyMdb+oKmsCa1ttLLPm2hhSqagz
         8XBMbwVY9JOXxkh2og7CHV5wPSZyFF7Ur8jJGA7u6W1Yn2ZT05Z8zggLaiWuFuEvCHY1
         uLzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=hG0sz14Y;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o220BKePFDSEDeaGp8/o6Yv/MdPde3Mx3xSLn3jHLGo=;
        b=NL61DOErMH/n1zxF5zQHZ/gipFAlJDw4cY7Q+D2rQgLIm2y9gvln/k93bKIxJhECvD
         xty5TBcfjZe3RJtmwGViF9e1ICE0nKNMt1SqP34ZZDBkT4CV5yWiIlByt7EssHzTubzy
         z0AQDpWomHxv9i1Xj/CmZAFavpe7wzgguQ1OzISSm/bOEYVlC5bKuwnyPa58T9DE9smn
         cTP9HhME7VPD7Wq8Qrd1cHcGPjDFrkcQcWh1mSbTkdjxA0jGSLOtitXTsWdkhi1PiCeP
         QZhIOPzMyLmuKwD/j3R7lDgqB+nooZKXOy9UdZzxJIVP3lQeFA3KfnKxBB7oO6QvbGGW
         xrxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=o220BKePFDSEDeaGp8/o6Yv/MdPde3Mx3xSLn3jHLGo=;
        b=Rh+EWl9aXBNU65qF2Zlx31aOU0uBxLct9cjghoS/yj13n1n1WodlvdBHMjR6JTpltu
         tC7kvA+OW9Rm61I/Ta03P9wG6vKj+3BxyvXNElw2fleQ6V7tXQHsLaNyfzha8YSVm3lw
         vozV0Qz7UPZfZoJ5Oim/pir9SYZbtAY7qJNvilC5WV5D4os0Pomzu7PEJsLm1gdKRm/Y
         Q21p7pVDhWFMmVIMpdgK+vmyxuxtf/tS1Jkc8tksYjxJyVhFYaCXGeTMJTeWIZvsXonO
         F9RHdx9udIFSxgv/Jym/HzKHPHyGhE/0unoZx3q6y1sTRWzSG9g6LHApFqxyySlan/49
         QLZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVWRAumeL/HSPd4F+b3jiO2p3I3H9b4YXSGfjffLSUE1x8D9qPU
	huA6Ci6I7yQ0bGG0IenFBB0=
X-Google-Smtp-Source: APXvYqzjeemEmQbb/WtcIZhkvKd4tQ5MSrv5Xaaa25H5CfGyYMwAGknvDVvfUETa7bFDHPMxcWB82w==
X-Received: by 2002:ac8:288a:: with SMTP id i10mr9930394qti.139.1574359058412;
        Thu, 21 Nov 2019 09:57:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:25f6:: with SMTP id y51ls2129213qtc.7.gmail; Thu, 21 Nov
 2019 09:57:38 -0800 (PST)
X-Received: by 2002:ac8:46cd:: with SMTP id h13mr1495788qto.101.1574359057985;
        Thu, 21 Nov 2019 09:57:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574359057; cv=none;
        d=google.com; s=arc-20160816;
        b=uBTiUXWnTaGt62ZRLEsid3Tma4OghDapaXhsePNpp8SmCGbGmqyVPma/aJ0TkwVyE+
         ZIgFhuZdKUq2s89apfhk0AF6ThB/eqGea5r4L6BXSJ/IRaPRleITNUOEQUPMCb7WnJsk
         fjTYCkC3YqVd/Ih05CLZXKwBSl6m4cu4S3W2my91ImAKXiq91RQtl8OlzEIM3qhU8qtZ
         mJlri2gqRa1gL8/xu74sShq1Dv3m4omI6CcDUqzo+T4WddzxRAUnMUyCQx0v8CJZAa3D
         LNBc8JTsr9ofSZPPR63n4ktCY3SsqZBwGb8BxBaTkahIsJy/yxNjeHe0ImqF95qYr4Ex
         UI7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BsdpXUBK/+PDo/bGd1kVifJ4d8KCjaa55rIEdqK/BXE=;
        b=ULXbzvMm5ybwopmyvNepVN+9RBW3OFW5YSP5edhaNXHTUIdBMEzqSQH5TI44BHvwPW
         PQYdxmGmmEzrqY73jDo8UfLG0eJ0je6s2dz5VUNh5HaRQZ4z8wAKhIdojiAKb4CX1b2p
         etAu57GbMSeJctGTQ1TalOxiijvTYpLRyBywu80G3oQRogu8fYle1rd3Rowt1jQHPjmw
         T615kJgLCzOhZRw2DhBkMAkP43cKURIcty6TpM2ibA4HX07FHqQ9h7df/29IweGeRsbA
         U1HS/doqOjpIBaHeNF3L7EpN0ox8Z9YsO88u9kbgw4uehYT6LMbQzS+KLcZX8LFGLS0U
         q8ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=hG0sz14Y;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id n11si256993qtp.1.2019.11.21.09.57.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Nov 2019 09:57:37 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id q17so1962831pgt.9
        for <kasan-dev@googlegroups.com>; Thu, 21 Nov 2019 09:57:37 -0800 (PST)
X-Received: by 2002:aa7:96c5:: with SMTP id h5mr12206977pfq.101.1574359057218;
        Thu, 21 Nov 2019 09:57:37 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id k4sm4213316pfa.25.2019.11.21.09.57.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Nov 2019 09:57:35 -0800 (PST)
Date: Thu, 21 Nov 2019 09:57:34 -0800
From: Kees Cook <keescook@chromium.org>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: Re: [PATCH 1/3] ubsan: Add trap instrumentation option
Message-ID: <201911210942.3C9F299@keescook>
References: <20191120010636.27368-1-keescook@chromium.org>
 <20191120010636.27368-2-keescook@chromium.org>
 <35fa415f-1dab-b93d-f565-f0754b886d1b@virtuozzo.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <35fa415f-1dab-b93d-f565-f0754b886d1b@virtuozzo.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=hG0sz14Y;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::541
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Nov 21, 2019 at 03:52:52PM +0300, Andrey Ryabinin wrote:
> On 11/20/19 4:06 AM, Kees Cook wrote:
> > +config UBSAN_TRAP
> > +	bool "On Sanitizer warnings, stop the offending kernel thread"

BTW, is there a way (with either GCC or Clang implementations) to
override the trap handler? If I could get the instrumentation to call
an arbitrarily named function, we could build a better version of this
that actually continued without the large increase in image size.

For example, instead of __builtin_trap(), call __ubsan_warning(), which
could be defined as something like:

static __always_inline void __ubsan_warning(void)
{
	WARN_ON_ONCE(1);
}

That would make the warning survivable without the overhead of all the
debugging structures, etc.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201911210942.3C9F299%40keescook.
