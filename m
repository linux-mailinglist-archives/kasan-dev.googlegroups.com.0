Return-Path: <kasan-dev+bncBDBK55H2UQKRBKECWWTAMGQESHW3DGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 38C607707B0
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 20:19:21 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-3fbe356b8desf14558815e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 11:19:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691173160; cv=pass;
        d=google.com; s=arc-20160816;
        b=SdgnyMPAA0+77fT99VNvTgD2gaqxAtLWrWZftDKE3TmlL8nD/kR8b0x3yFwVwq1b+3
         NqQQN0xo9ZRybAa6SxyNXzXSZ5e9XNWJkBsXsUnva7a25PmY9VRKBJ2hl71do9uKfPqG
         apXGAVY/uJs2eFw/XwZgRkltmqupNGWNjyEWglWhL800k3CO9S2sLoB/CnYeMbZOZjVK
         ATw9QRx501pp2ohlVrOGkMO6aXQyp4MtMPc2br8j6sYTCcqfm9xJEk1+d7WlRK/Q9M9o
         Z7CeNPVbkOjxZ7uwseNZm9EihTJplH94EG0ZrCQDDTC8OuimBpMDzO+RIAefkA/3PsPL
         HA9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PV/YcyZAvz4gRTBNu9xU/3RNguVYLhP5xt6KRuKc8dw=;
        fh=hSSNDiGS3tK8WhaqsnK30F/9W261ajxs+ySojVDfeOk=;
        b=QjZua8h8fTO5/IrmxvvC7OGbgywggpE9XhU0obpXW+XA/CKmjY/iFlKjr0jznqnXFI
         MeLdsIne1lc/Nq+3bQrlYgLDpwk3cKsbfCxJV8DzDOz5LuvQcQTXI2uNUsG9IBZwX2hE
         UBGhYRJNIlcwBSHx/kCTZRg6Czg4PISiWGT3EMMYBhzJMxpQgexagLUBbuLLa57/lpQ0
         oGXFIAVYGYC9Go1Vtraj2t9oYuhvWG/0q3NXSWpNrOVZnXUnwj8PNMdmJqrKtxFBOsA6
         SPFsD2cVMfCXiL38TmjmobchR11YcztoLAH81BQXobSOQY/E1AOTGoq1rm2PZHQPgEg/
         85Rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=PnNUDq2P;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691173160; x=1691777960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PV/YcyZAvz4gRTBNu9xU/3RNguVYLhP5xt6KRuKc8dw=;
        b=HMYFBfvm9mJ1MMdh2oMzaPwP123Zznh8mPsOEpD4n83/zaxiwy+We9e80w+QvSs6hL
         huwSm7gBvkZpWof+179EBndp6LwpB28yruvhFaGaqlT0shRnBU4w+eNTQ1gsjcPTg/TH
         1UGcgbTGN52Ez3P3HS5d8pasN4fqAhf0RyTiZKOjJJa1IwXkMq9A7aob4xBLBWAX8JNe
         QeNtKkICL3Asemsj0uRC89zikZsuK/zJ77AQFmuKRfJX8wCColoH+y+1kDOtGyhrCa6V
         C9cEyRGdzOs0qVdQimph0MGbCHP6YDD4j89j0EDrwIyKNpjpo61zvsAj0n48se+XALsX
         FVEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691173160; x=1691777960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PV/YcyZAvz4gRTBNu9xU/3RNguVYLhP5xt6KRuKc8dw=;
        b=XGZFKhX6nfSv8UxwfL62WsUgv9nwyZL5xnRrdzc/ATf+c8cyH9jJqIoGoGPX5t/E+v
         KvHxViaURwVdUh+WaUzUVjTDSazl2p/0Pzu5Pu1qraTI7BGyTv7dPehekj8glTe7niJ0
         6ECOK9fRkQ2+lsTnEXizgsgjdvzGiNae7Avq7EOhxtKwhvdHy5Diy1SbBxkE+Eeb/klu
         Fdc6FIhOC58e5FbCY6KKjRtF9tU3c9jO4Ea2pWPlANA+y8lpK+OD0CO/jHciUhyenLLu
         FWzjsbKzsZELS8ATmqaWt8NC3ZtBtXa3opVZXXU0axE3Na7uVok3EEelf+QLgNOBjVcR
         Re4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwonhkaFZU5ttaSK1N48XDObC593GxGbEBI/RygQmQ5+TzGIxIN
	juu4ZsJYFpZe8rasJ/AY1lo=
X-Google-Smtp-Source: AGHT+IGlPyTvpTAJE0GBYB/ZcFJ0uhwyAbWrVFDVRvytLR68LxlbY8GKGJdhSE4ZCbEKHUsFnAxI2g==
X-Received: by 2002:a7b:ca4e:0:b0:3fe:1820:2434 with SMTP id m14-20020a7bca4e000000b003fe18202434mr2147281wml.1.1691173160370;
        Fri, 04 Aug 2023 11:19:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b05:b0:3fa:ec98:7f12 with SMTP id
 m5-20020a05600c3b0500b003faec987f12ls104872wms.2.-pod-prod-06-eu; Fri, 04 Aug
 2023 11:19:18 -0700 (PDT)
X-Received: by 2002:a1c:f70f:0:b0:3fe:21a9:2feb with SMTP id v15-20020a1cf70f000000b003fe21a92febmr2021817wmh.33.1691173158480;
        Fri, 04 Aug 2023 11:19:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691173158; cv=none;
        d=google.com; s=arc-20160816;
        b=xPkOM19GpaxdvEI5QscEaR/SCD+Oa4DEe2k7MGLARRXBJzFgzEOE3W74AXfanbqjfl
         gr4YUZJhsMDgNEBKM3O4A9CN4tbCp+sU8dM33OS/GEScVJ/ni2Ih676WlHe88YJVaiOf
         l7JTu9G2D/gmqY/AuoYSUpPQ0Y8NJvrE2pvubAS5RflNIGQl+B02JpXLEG+Smpw68T3+
         MsVHqVxqDsu5EEG+A/9XNq3+oSH9PZF1u3NaApWrMrR6MEKtNwjq/5FJ+942ztV+wWqg
         87oMTJDu8hgOQimG4PiUL4CWMys8ggUqq6qb78/yD2mXjJW+/+7ZMxvxpStGB77G3K8Q
         gJ8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=98qOA2hy/eGle7yAA5GlRvkVWWpa8WdU1Y+K5iryPA0=;
        fh=hSSNDiGS3tK8WhaqsnK30F/9W261ajxs+ySojVDfeOk=;
        b=0QwnNu7df+Yn0XlPcO0iYNNR0HFZhDlO93h06mD8xiKTy0E6t+URogIUkJ4z9N2qPd
         l8/P1fY3W7xlGcN8H60EOm052MvOxXMhBhQNumSfiEbfvVLy8ofXR1QVPouH96KxyjlY
         AAgTXTKORNP+mmqydHSbBC2JsSuke59yFeJcx4S952at8UM0UZrU2Vh97oOu0X1npkEX
         3/UJRa4rYWxjd1U6f4xzXNkkiPEO8voqdg7/5gJmH/4YSQIsq6iCw7c4ziqP0VuaM1is
         qFTRmMESqmpG0otbiIoa6zi/Vc4xTi6pcE/mPnjCvAaSMKzw1sUKMhjYyKXdknXzGfw9
         dctw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=PnNUDq2P;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id o35-20020a05600c512300b003fe2591111dsi436165wms.1.2023.08.04.11.19.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Aug 2023 11:19:18 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1qRzOM-00BKBq-3m; Fri, 04 Aug 2023 18:19:14 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id EF129300235;
	Fri,  4 Aug 2023 20:19:12 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id CB5C92130B4DC; Fri,  4 Aug 2023 20:19:12 +0200 (CEST)
Date: Fri, 4 Aug 2023 20:19:12 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Kees Cook <keescook@chromium.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Mark Rutland <mark.rutland@arm.com>, Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	James Morse <james.morse@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>, Miguel Ojeda <ojeda@kernel.org>,
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v2 2/3] list_debug: Introduce inline wrappers for debug
 checks
Message-ID: <20230804181912.GN212435@hirez.programming.kicks-ass.net>
References: <20230804090621.400-1-elver@google.com>
 <20230804090621.400-2-elver@google.com>
 <20230804120308.253c5521@gandalf.local.home>
 <CANpmjNNN6b9L72DoLzu5usGGjLw5Li8rnfu0VuaCsL-p2iKTgg@mail.gmail.com>
 <20230804135757.400eab72@gandalf.local.home>
 <20230804135902.7925ebb6@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230804135902.7925ebb6@gandalf.local.home>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=PnNUDq2P;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Fri, Aug 04, 2023 at 01:59:02PM -0400, Steven Rostedt wrote:
> On Fri, 4 Aug 2023 13:57:57 -0400
> Steven Rostedt <rostedt@goodmis.org> wrote:
> 
> > On Fri, 4 Aug 2023 19:49:48 +0200
> > Marco Elver <elver@google.com> wrote:
> > 
> > > > I've been guilty of this madness myself, but I have learned the errors of
> > > > my ways, and have been avoiding doing so in any new code I write.    
> > > 
> > > That's fair. We can call them __list_*_valid() (inline), and
> > > __list_*_valid_or_report() ?  
> > 
> > __list_*_valid_check() ?
> > 
> 
> I have to admit, I think the main reason kernel developers default to using
> these useless underscores is because kernel developers are notoriously
> lousy at naming. ;-)

Well, that and I detest novella length identifiers.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230804181912.GN212435%40hirez.programming.kicks-ass.net.
