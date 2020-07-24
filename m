Return-Path: <kasan-dev+bncBAABB5WG5X4AKGQEC5G3UMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B534B22D1E2
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 00:40:55 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id s2sf6787714qvn.19
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 15:40:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595630454; cv=pass;
        d=google.com; s=arc-20160816;
        b=BNXeqv/xGDe6U7U+uThp/ViXDe+oJB2uVMW8EHg57UpURwjlwytTEi1t9gGfez0fWu
         Ww6oWWDtpacEstd6M9I3PojdAOiI8pEQemfX217Bs/Lwke4Jy44dbCLUpmwE6TKEU8hW
         TMiRJd52+Ap4vxOr6t9ndbtCVwGqWVn3eCzfhcGyh6tFfXRP5ACVK9UkgpjSPGc3tYxh
         jzuq41u84B5PjOFwS2l19CNxaIRVRw8Jim7xYavSUve5w6tbJCCyfVaws9X9MS9oe+WZ
         0s+ozeskqvP0s1L0p9yuBYfadDnOHpCRM4TimNJO45+2C6DNkEryollEhVwmpVI5Wca4
         UHrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=wdvR7bAiWGBrLuHXkWe8m+hsbW/PBvybADHbBM6AbGI=;
        b=y7cIVR3RLX0tH8m2NXpoEHP+qn9ENgONaWBdFhWICxInT1x0HiUtoL4lPELi0iCYgq
         ae15qmUfE7E91L2mqzdkDJVCyyEL4B3IHbvrTllcK/a0Ftyamt97AuOffAr9LrFneWVp
         A0pRKHo3sUiMMRhhxNFrkLcD+Rx/Ulj15dwuNR3fYiFy2DjKGducOEPKSdDg/CpeySgk
         WLddzan0A2JlXYAYWVsCnXc78S21oxYppM9YdujNIyciSxwIP6dM+rO8LsTfKnm4GEIC
         BX0Lb1zQ0zmM9XQBs5Q+QLYZHxn+uz0UDzvqCsmVsrk5MJEqikEZvgGwNSWjBJCVmDzx
         3thw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=12lC1cOL;
       spf=pass (google.com: domain of srs0=u8vg=bd=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=U8VG=BD=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wdvR7bAiWGBrLuHXkWe8m+hsbW/PBvybADHbBM6AbGI=;
        b=KhH/xhsMnYoTzxbSdBTLWP7KQHMF6GmneHZ1PmELWRzbafN62EYkF9A+TX6LXlL/4C
         s9r8fqo842M38MnbnqGNf0IQr9QQaMuDunKoQ5ygZLZ77/Ay/3meL4IzCLFnl/Qq4LaM
         ipS6jDgZj76Lt/A6HjoYKHjW+cTtIlbuHvbYK0NLivyMSNDRNpENgg/76Nm+WWOPeBlF
         dVTU7PhV/RODJlyCX8dVe6NikJbT7K57LDcFJsXsCqsb7DV5CwzS4iuLggiM+uAYnDhb
         dRNelK4Wq9dXWC1gyEZKH7hK/gzCq6lSFBqDOxhuZqtpvh84+ur5u7U/byvl6u1JtnQx
         XzKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wdvR7bAiWGBrLuHXkWe8m+hsbW/PBvybADHbBM6AbGI=;
        b=Wb56QVAq5YHi/0cSTm7w6IzndkXyu/GCM/ExBa61T2Cxtli//xHdt2rsHvGaKEnIM3
         kaKn3RKi7+kN5dO1crOCH6xwJraKAIUJX8RtAXgM/RYHmDRaOLSsMyC1OdhDIaXQLpF1
         EfE16N5LxiLSzmW+9npxcPlWQLv3AE41iwwqwNx7DktHzUxcRwgBxsKd5wfb80gx60vt
         YUsLs0cPkUm2jRNfQfQqUoFRATy6znLxRG4n0Im+gi5ZRncu8XE5fCSzjPb4ww+tWX1P
         vb894LB6N0IJ7OSyjJG+w0+6wVs7opW0bvVyzasI3QGvLJAeDCkiryg+Qifs0HpSY7Tv
         Gutg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Qgi9XkxFHbgSTlT9jUsABTnYdh1fTesZmRrQzrMHMww5MOarN
	w7oM5vUXLkec8Eq563sqbhQ=
X-Google-Smtp-Source: ABdhPJxWNzQqlY+pznHYCpjgfNYt+Uvc2ktk4vzY1FVSlIgB267+qvldolli1zRqIjA0JUHFdYwaMA==
X-Received: by 2002:a05:620a:9c6:: with SMTP id y6mr12143524qky.27.1595630454061;
        Fri, 24 Jul 2020 15:40:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:507:: with SMTP id u7ls4055120qtg.10.gmail; Fri, 24 Jul
 2020 15:40:53 -0700 (PDT)
X-Received: by 2002:ac8:24c6:: with SMTP id t6mr11999265qtt.39.1595630453816;
        Fri, 24 Jul 2020 15:40:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595630453; cv=none;
        d=google.com; s=arc-20160816;
        b=vUMVqo+TGJFkFx10Ab2jFvvQ2Ii2PUN4WfTNbKL+hMiimjHmbp/YYfmxuUfgLe0ysJ
         SQdHgFgFK0T5xcpefZYBThqhkBfezTSsBh2LIBaFjFEzDr/2VLiWuCwQGU7iC81zQ8bH
         HdMIxHUDVUeq1slzQetkAQ4M0xFzmirtyK44dLelJqRGIGVhyNvM2HBJUjeRpnWpADZN
         s6RhUghrivi4144G99l2e5Wq4GDcepZlZHLMCpDrVR5J/8FyjAngMC8PPJ4XkQyB9U1q
         IllG8/GkKpKXsriq45a4oQ9fY82girilqt1QJ15vMAa5Y1vGZBK0SKOCUz2xSEfSZEtY
         pIfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=PDKHk0kihdUTDa9+ATNvXMhTBfjhh5e6v/M3Q/NYIWw=;
        b=WgDZOuLtBGLz1BXYBwg5sS6oSmg7cmFeOhJpWB9E/4Wwvd5/U4D8lTjFRqhqFmNDAM
         d5eV9oikamZ6/+eGm+uB4TZ2oxbxibFcT9NqfYO8mVE1AT6J71RyiBhhHrClYAYbqSAW
         oyzEoYtncM1b5Ts1UTkgUuSQxmGXO+nQaouvTlAybLR6EZWSmFh1Uj+SBgh9q6C4jcl5
         J5wu5N5dyvP5cmqEgm0ZlQvBsPjEN6rV46ek+g9FzWsZ3NiLlyVOfAID1+YyVT2oflWU
         ln8GPT/ZnZpsyCAvznWiDoVmUIybpx/617AJpEJvtb5v0n0PZimdCNS97qWDtSKsiXd4
         yaxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=12lC1cOL;
       spf=pass (google.com: domain of srs0=u8vg=bd=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=U8VG=BD=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z19si355569qkz.2.2020.07.24.15.40.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 24 Jul 2020 15:40:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=u8vg=bd=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-111-31.bvtn.or.frontiernet.net [50.39.111.31])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9E220206EB;
	Fri, 24 Jul 2020 22:40:52 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 882023522749; Fri, 24 Jul 2020 15:40:52 -0700 (PDT)
Date: Fri, 24 Jul 2020 15:40:52 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, will@kernel.org, arnd@arndb.de,
	mark.rutland@arm.com, dvyukov@google.com, glider@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH v2 0/8] kcsan: Compound read-write instrumentation
Message-ID: <20200724224052.GX9247@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200724070008.1389205-1-elver@google.com>
 <20200724083920.GV10769@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200724083920.GV10769@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=12lC1cOL;       spf=pass
 (google.com: domain of srs0=u8vg=bd=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=U8VG=BD=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Jul 24, 2020 at 10:39:20AM +0200, Peter Zijlstra wrote:
> On Fri, Jul 24, 2020 at 09:00:00AM +0200, Marco Elver wrote:
> 
> > Marco Elver (8):
> >   kcsan: Support compounded read-write instrumentation
> >   objtool, kcsan: Add __tsan_read_write to uaccess whitelist
> >   kcsan: Skew delay to be longer for certain access types
> >   kcsan: Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks
> >   kcsan: Test support for compound instrumentation
> >   instrumented.h: Introduce read-write instrumentation hooks
> >   asm-generic/bitops: Use instrument_read_write() where appropriate
> >   locking/atomics: Use read-write instrumentation for atomic RMWs
> 
> Looks good to me,
> 
> Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Applied with ack, thank you both!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200724224052.GX9247%40paulmck-ThinkPad-P72.
