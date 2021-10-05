Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJOG6GFAMGQEGA4HAAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 49DAE422B26
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 16:37:26 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id i5-20020a056512224500b003fd2d62dcaasf6957665lfu.23
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 07:37:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633444646; cv=pass;
        d=google.com; s=arc-20160816;
        b=tJq8wFFO+WXYdHfQ2Wr4ZHdZcz5yioJJA5ls7FUcJotoLUALUTxrfIy6al7Y+ljhz4
         LV21C2sdoA9ALw+naHsvTbiC4hFtMinGJju2esXnkcaWfeZO+ydEFBesz9GJkrRgY3KM
         60hx51d4yQEVIMILQenQ2FmQc0NCKdXwz6kc8HruEP5CWFIDiVWP7T9KPN7n6FGzlRWR
         olL7BRipaVA4sHfK1BMGaP3z+nO1N/+6MvZM/0Bb0bLvbDqbc5lkTLYgDBJa7UWXLjOH
         ++Ez+GM0YIt6mhgprWTUOiX0MylF9yKd06VqGAdmchRorXpQBO2t2hvoNILmyajKtBxP
         vCTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xkqpNBW3BjzimBf/KN2oMpmj9pLAwe0DtBortAKrn3E=;
        b=S26Chsrq1mpBQgfg2UcrtxTZ4Ijn2XN89ORC8I2638Th6YlAjC1p2KpgaboelrnC1+
         EFLuQIVkQ8xEMq0FD/lFQC1QGsUd5zYaWb/u9FTGuXWuRp6Cmb8kijNUoKnalwz81UNy
         HlGy3JLmugKgGv11Rk/2KQCdLHS4IJXFX5L60RjSZZSuLmH5xE21i/gqwsCAZxpsHtfV
         KbiDzP59duxhyIEsWt/aahNxvHSsMRo+Bh1ysLuCQ6NRIJaKKDfWBJjcLSXAYAhvgBgh
         +u7TCKFqzFLeI6j7IrdfC88489Aze0Kx5a3sUxm0lwRJmzMLvgiNdPmmNx9zCAO5xruT
         249A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=mP1JnpeU;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xkqpNBW3BjzimBf/KN2oMpmj9pLAwe0DtBortAKrn3E=;
        b=IrlzRY8NnHs4Oxi55I3TdjAGs/j0XHgasLyMV1+ZXYVClIM1a378wSKkUh0iT+FHMM
         YvEoTRc2T2ddl5zRjG/wVc8QdVLQgNWrIrK6nGQQPfHp6Prln4YnYOVnqqJbctl3cgP1
         9mnklKlZmrYZbohw/9QLSuJBkAfBBbz0SKu2kxuFS+5xLvBTv1bWlDnx/HQSPqkwaNxH
         yxu8m/malUTe3ohVnaZOlerzo/ejy0lgd/9uvR6g+LsDaFvlHH+8QyrJfzldpcvonL1o
         yCh2CBpEJS6I1pNSYFsleAdfb6OAXKy1IPAIkIywcnQTNn1WlofQZKwnJWQ/UzLxr3uT
         S0SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xkqpNBW3BjzimBf/KN2oMpmj9pLAwe0DtBortAKrn3E=;
        b=RNHrOrtmyeT6480SEBTCeiOiI9nlT5dqQp3cP5sl2UnWWG6pBDaLu451G3IAmkLGFI
         zZnVP6IGYZYoWOvwmgGyLyTvJgWaaleI8NSYSEvXK9/8/vd2HCnvCLxgZ6Drj0xQkJAF
         syMjV11xyOXpKhiXhvqvWvAPBOfqMaZg207SAU6yi6+B7WGuLRErDTYMiz2SBFTqsr9Z
         K9W/HhSPTCwMUvKpFLzO8wap5RZ4bHLX2fJAW6ujHNYK7YYa4T5d80eC0W3ktBzDHTST
         4UpsSTcWJx2sZKtCXPhLl1FeCW7Y1QlnHfIjkCp6HNH6iprvbMVKc2ZEyImLZ/93k/Rb
         2mLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533IwDIBuRm6B2wBiGjOIFfDOqAgeAkA2W/+Q2Ey2eedX/+8ypDF
	DhVF99IrCH5TSIzWNJIaSwA=
X-Google-Smtp-Source: ABdhPJxs858n4MtNcZebJMQP3KGQ5Ft+KIvSW4AVLGSxa4Vv9v4bw7tUH8XpZPo04nug5f0kHzlM3w==
X-Received: by 2002:a2e:5750:: with SMTP id r16mr23067403ljd.371.1633444645858;
        Tue, 05 Oct 2021 07:37:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:168c:: with SMTP id bd12ls3874186ljb.5.gmail; Tue,
 05 Oct 2021 07:37:24 -0700 (PDT)
X-Received: by 2002:a2e:b8d5:: with SMTP id s21mr23635912ljp.300.1633444644905;
        Tue, 05 Oct 2021 07:37:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633444644; cv=none;
        d=google.com; s=arc-20160816;
        b=F2ssKVa4v9HlD/NNgKLjLcsR2pQ8ObCS5BA52Sb9hwduLBZv6V0/vLW11L0222kVvV
         tMF+/LQsRNnZ6UfLI2SvtX5aIWnnwwU76OH7TmuNW14aOPVtyA1eNI4tDxADaimUT4fH
         mH9mAlGI6EBjKX7dVeOaZGIce8bMukGYcnyVE44FNHdidUXPC0XQgSP+Tu9cHitxOdCN
         hWFzvcX+hCBkj6Ph4LkBk7BorqkWqeziLSPrO+VqSTFlwOd7L13VTIkVuBW2DBuGFBBG
         NI+IzJYARGahTC0kr5W2PO8WQprNNJEF8va3S8zaE6Cy7e7PGjWEqc9ptS6f0ZMh9Tax
         Lr8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=NXVT547q11vxBmN0JnCHuyJ+/+kUBjr0nC1nL/Y5gs8=;
        b=lYMDJVPDtT3eGbMV2LXNxCGC1/Rx0vuOSGY+lrwTri96X5W6UbHEeTyuTr6ol3GfjH
         oLI7fEGADhfmckhhmG9pg4CcVENIOCuYbVMBzA4t9YN6OzA5T93R3ZuuAhZKRTURCbwd
         v9UK4mNtifLO0bOvIfEt/pJ2zXuZo+rtH1ZNiGhl/3Mp5wH9o322EQ3p9ZOoaaV/eP4W
         fHtRbVt7OMaw9BXhCqoYiuWuSfxYtQt0RtuM/yScucycMC9YRJkhSGHEsvDHwDgZiDK7
         GJiuYGKsldAPpf7gGlFD9aSbZldhauDE9X6wX5fjnwg8BkzIRb7a4HvHguk+FcpiBBnR
         mklg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=mP1JnpeU;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id z12si1096164lfd.13.2021.10.05.07.37.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Oct 2021 07:37:24 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mXlZI-00846d-FS; Tue, 05 Oct 2021 14:37:20 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 9DD7930019C;
	Tue,  5 Oct 2021 16:37:19 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 7D60D2038E211; Tue,  5 Oct 2021 16:37:19 +0200 (CEST)
Date: Tue, 5 Oct 2021 16:37:19 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E . McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH -rcu/kcsan 23/23] objtool, kcsan: Remove memory barrier
 instrumentation from noinstr
Message-ID: <YVxjH2AtjvB8BDMD@hirez.programming.kicks-ass.net>
References: <20211005105905.1994700-1-elver@google.com>
 <20211005105905.1994700-24-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211005105905.1994700-24-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=mP1JnpeU;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Oct 05, 2021 at 12:59:05PM +0200, Marco Elver wrote:
> Teach objtool to turn instrumentation required for memory barrier
> modeling into nops in noinstr text.
> 
> The __tsan_func_entry/exit calls are still emitted by compilers even
> with the __no_sanitize_thread attribute. The memory barrier
> instrumentation will be inserted explicitly (without compiler help), and
> thus needs to also explicitly be removed.

How is arm64 and others using kernel/entry + noinstr going to fix this?

ISTR they fully rely on the compilers not emitting instrumentation,
since they don't have objtool to fix up stray issues like this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YVxjH2AtjvB8BDMD%40hirez.programming.kicks-ass.net.
