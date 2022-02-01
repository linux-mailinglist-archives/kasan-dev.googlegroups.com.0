Return-Path: <kasan-dev+bncBCV5TUXXRUIBBNUZ4SHQMGQEIZTS2VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id E375A4A5A12
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Feb 2022 11:34:31 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id y19-20020a2e9793000000b0023f158d6cc0sf4728646lji.10
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Feb 2022 02:34:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643711671; cv=pass;
        d=google.com; s=arc-20160816;
        b=U7kC57LW1jy4qjRAyuHkTPM20TumatnrTXGFfpiA1cFT6lDiKGmp0/gCpdZ34p6gh+
         hb9zoGu7/eieqQaR4mRavVqSuenchM648rMlm5vFqE+IBEQYI7gc0LhpgeZhK0J+FXyy
         a0aGTG1BITcODP5Qvp0axp7NjBVOYMLuEbxj9812f83Q0RqztHyqC5kLeTILXni4siKk
         6PALihR9HunpAUUwDvE2Io0Sy0OAdy515BcvrIXoQnVpzQRYdKVuh5VYNHf/YDPNdDZC
         Gjj6dfwiTGYMR8M/6yrWCgqL3hFDU06C1QET165VD95DI796wyf0Zhxab5qNxw7954zr
         P/+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mmy2yyHR8k47i8sXszH14BOJ+7xSBvuoQhGzSNeSGDw=;
        b=fGCTd062OwRU19NEfD0yVw7tTDjuA1CuCCmetx3t56qXKXefxN3GGYUSaZLzeFUhel
         fSnYBAeLVmfDYREd6X6b3zU9xhG/tYIyL/hRxl2opfA0j9NiPI7r8QRP0H2j0kpoxQxF
         cV6zx4CRBjK/r56AeCH2LkihAVI0pLRRUJCWKOsZ3NF9jEkb/NmSITqN9fBOk/DleCz/
         yvxUJ8Np9a9yjoYAhoMA2ag2WdXpDvR4aEEolM5XSK/mhwJRSsA2rL1QYAFa0ob1NB8+
         fcZuWK3osDm/Q+HiWw3W/OEWut352bEBRMxMw6moqt49Pc/lrkNI2ImJAyR29WOl9C8k
         o1sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=cAjE6EEe;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mmy2yyHR8k47i8sXszH14BOJ+7xSBvuoQhGzSNeSGDw=;
        b=qJ00FIaHtcNO28PXdMT2x5I+c+g8XLZVu4GA1F/442Ouht8GcqFdlkoiKfZVSI7HmY
         ln0Vrk/dZuJxrvOzZSIWX4bmP5XpnG0MFKfpIMQ/Ko9BUXPO2hkaRV9ZMLrITEv42LKp
         scs1NJvlmxkIYCAZOf2ZWTzSZIiVqrMf3Qr4alQ1Yf6dFCbDPDxmXGTG6Rp6o4paSRUK
         zIOCIF1IUmMKNlGe3wEI6s7jIvPdXHtsz1Vtqm+Jucjz4U3pKn5XbSIxr6jKkQAK6/ig
         H0lHAxTFRSHVPww2/2FJBUTDg10RlC311snladRX6uLQv4QjJ0cbez4o6qVomrAZbskc
         /OEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mmy2yyHR8k47i8sXszH14BOJ+7xSBvuoQhGzSNeSGDw=;
        b=FefKC0l6fSroMAomtFO2m00aeV8CmRJ2VvBORIfi10MS0HNLH8+mudpNKHfw1qRfq3
         aa55wSBaj6HT8UH8OKARaeaNN0rL/nYNmZoCGheI/xDwuBAoX30jv8ULny+fs0QS1e+8
         /RufZMrVrh8qEBif8MwLGYRzzrBNUEeqjc4QS+IF8yiJuhFzMHOsZqTGPjydl3xD1sLb
         uWtLgevXpUYEzZtdto85u7rYAQoZJJ+t5qQPh1rSgmeo06xlcWwJjq+WMAnkL6lS18YO
         moIEHIb0m3O41OLMte3LrI+jtp8MbTVteq8yWakuXcIIdCwicxda69WajoyBaxsUsWoh
         BObw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533nc6E9gKd7M3rAM0a8wA5eREYpUK01B1v+Zx1fAGnAaBFHTe7P
	bGw9gylwA3GJmNMntaXk4gg=
X-Google-Smtp-Source: ABdhPJzWjDEnYUhdau7CG6VBHF6m9d5FYbSxmy+6A1UCLbFbc77X6zbvtF6yYtLb8wqjuGklF1Qp0Q==
X-Received: by 2002:a05:6512:310:: with SMTP id t16mr18999923lfp.138.1643711671227;
        Tue, 01 Feb 2022 02:34:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e11:: with SMTP id e17ls1201lfr.1.gmail; Tue, 01 Feb
 2022 02:34:30 -0800 (PST)
X-Received: by 2002:a05:6512:2245:: with SMTP id i5mr18432064lfu.289.1643711670226;
        Tue, 01 Feb 2022 02:34:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643711670; cv=none;
        d=google.com; s=arc-20160816;
        b=mTCucs9ANQHLfC9rVedxwTeEegCtRH4XVRyiiWCYWpk2rZHEMkn/hzKpZYlXNMpY8s
         ZVfjOUPeoyJiDmyRByTvz9I7eG+9DbXWTLKSx8hm2zcTd1J1RrgE/2BrxznBHT9cREIa
         zxylOzg7YUU0DHUxWGLr495A4ilvhWcBVTJh+QVp3OM2gbQxUeAdvahbRKbOrfmQKiXz
         rcYcrBybdBCBRtUpsnUzWYcHTysrwX+4qy/QsmNmdRmzBPnvZItuRID/h2znfknbUulp
         tOGJPcWQjFNEhRSGikow60KWQaY27ErAZbW5LadWbTuLKIT5EnzNxQ9G9pu/CIXT0Tbl
         m08Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UOz2viW0BElLS+TGumDBU674xDtw0fIIZshAd52tWL8=;
        b=wsfBhMrXEZ7ga8YMz54S4JT17azSV6VBcghlRqvSDblWFk3+yDpE9KxvjeLXQy3LQG
         x2zoFUEcId5T2pZIhi4QeULpdC2Bi5MRlKWgVeKMBoywNXyuesEux612lnwIC+trRPrB
         WVllOWfpyrJixPcFFHLs6RYtM5RK36VpedrwbKDwnT7KYZcCGiwTBvlCXHrWFNw1wAtG
         9JA96fwYSowA6XsQSpaVBlChQm25Y2x91f48kl3+QYi45ipdf2/noDY75paLA5NQo3Cq
         6/4b5tn9I6GWuWmCkP2Q8FgDCdDEq16TMZSUXY6amJH31QyOKjrGMGKCDa+hQD/qdWHi
         NqzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=cAjE6EEe;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id p12si822067lji.3.2022.02.01.02.34.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Feb 2022 02:34:29 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nEqUT-00C02S-3T; Tue, 01 Feb 2022 10:34:25 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 061D898623E; Tue,  1 Feb 2022 11:34:24 +0100 (CET)
Date: Tue, 1 Feb 2022 11:34:23 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Kees Cook <keescook@chromium.org>,
	Ingo Molnar <mingo@kernel.org>,
	Elena Reshetova <elena.reshetova@intel.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 1/2] stack: Introduce CONFIG_RANDOMIZE_KSTACK_OFFSET
Message-ID: <20220201103423.GT20638@worktop.programming.kicks-ass.net>
References: <20220131090521.1947110-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220131090521.1947110-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=cAjE6EEe;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jan 31, 2022 at 10:05:20AM +0100, Marco Elver wrote:
> The randomize_kstack_offset feature is unconditionally compiled in when
> the architecture supports it.
> 
> To add constraints on compiler versions, we require a dedicated Kconfig
> variable. Therefore, introduce RANDOMIZE_KSTACK_OFFSET.
> 
> Furthermore, this option is now also configurable by EXPERT kernels:
> while the feature is supposed to have zero performance overhead when
> disabled, due to its use of static branches, there are few cases where
> giving a distribution the option to disable the feature entirely makes
> sense. For example, in very resource constrained environments, which
> would never enable the feature to begin with, in which case the
> additional kernel code size increase would be redundant.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Nathan Chancellor <nathan@kernel.org>

For both patches:

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220201103423.GT20638%40worktop.programming.kicks-ass.net.
