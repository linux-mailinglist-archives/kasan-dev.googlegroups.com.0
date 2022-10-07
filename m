Return-Path: <kasan-dev+bncBC7OBJGL2MHBB25AQGNAMGQEP4SBO7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id ADAE85F7B3B
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 18:14:36 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id e1-20020a2e9841000000b002602ebb584fsf2106906ljj.14
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 09:14:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665159276; cv=pass;
        d=google.com; s=arc-20160816;
        b=Saopc4b//7mkajEAKgfwNbLChByng09Cdskziw7QaYo5Uu7ijJ+mAwQQ2jelVIdrjV
         ZQojvg/+wQXtjbMxwmKgVyO6PM7Dk2SHxLQsgqTJGwtpo+kWCytqKcXreHbes+lUsgpk
         wp0kdWq8um9Sdcqg+qHc/AySbXVSUnpivTA9ZGxrA/Oat++AVuQQYoxuGWB8tyRy98Xl
         Rm6p2i33BaVxSjpIdymntunXU4aa1HRgPS/mAwt6hSv8udwlgCM6N/oWS4YC2hRKxwvW
         DptjMgZMut4UgLs2x6BJz3d3V881gAY8kVWSrMpE4Jtj+lOOo47/yB9+yul/mQN9bi+0
         5kOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=pD7NeYNB/QT9EkkiILQQl7pk4Bd9SaT0PsFas/EqSGE=;
        b=ty8rWhnpgsRSXEQsibFdPfsXqW06Gm2LbJTHVbJs8SseOBCiqef0DSTXJ5n76CMHPf
         3QZZnavECb12EvwGfwhr/De6OAKShEdb2hEGatFp1Wq7rtyVmi385BCM0VfDPBNjimak
         kziwx0ONQQnufQgR9SwKJIYUhuKWsyByVfcEeovWrD2x+3lSBnOJsiatg/YggGSEniXl
         6gx3907g86ToFlkd1eiMhpFFTIH5h6JX/oU9FUE1i4/+dTmLFY7wmjW4CpFH//GrK0+E
         rdQ1E/c/g8fiGRQvOAnUf/DDN1dqZmOqLRKLDLCMWozdDQsVi0CMXEiBAFk2jdR4fkct
         0Bhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FLiXrIyC;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=pD7NeYNB/QT9EkkiILQQl7pk4Bd9SaT0PsFas/EqSGE=;
        b=EWPlcIut714iciTXvksOj/6vXjze59VKqpJ+MN0TjKYn+vaYafXYbLiD9EA3482ygu
         soIw1O3ZGSlh/QdWx2be45kFZsrRWJvklTQvkTIQqywnJkn0muqU1+o1dtUJdQVxI5sc
         uto0tAp87U81HKZd15wmKx7OJLXYFuU+W4k6UvJG+O7yhUYX9nYOfArbo14cKABw8RCK
         0nrmFav/KjtXsvUDSMbmplxk8UekgaV/sgChvqLhSh/k3fRcbMMtGqp5FPubdj1e0l5L
         fQwYrCgOl6XFIg8YclkBgoo7gp9HaNHF/sNkyhbttqhg7c6dhfCu8dmqMxykbSapvlhy
         A66w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pD7NeYNB/QT9EkkiILQQl7pk4Bd9SaT0PsFas/EqSGE=;
        b=KcXfve5rS37bBxtIf6P95u7qfSTDHY6v1cStyFXTeTEWpaQm9lUzvTUwyvtSKP7lk6
         iJRAQ+U7sQepsQO2qHiF7tCyNogTN9XUxzwr2ZF09UrshDLmJ30ZU+LJw7ksxuxLyb1P
         vljzO2R2GtTuuq7kPJ5AfndGkHF/L51HcA/3Ickjxd/ehGKjN7lVZn9LAFGnPZVGmINu
         l/0PLEv/y8IRaEqJYDj/1HBeLwvbV2PlN3Ln8GkBkCekwH3rgzuYD2Y4XBu8UUnCFqpx
         TYw01Z5nP5AHfxEliyuY8kQLjNsVHFWp7y72QUsWIM7lDdngCIzd1yp/Hk7tkJn+hTAW
         2mLg==
X-Gm-Message-State: ACrzQf2+DSxFqtNVzQLMyZ6eFcP76Ab2bmYexSJPtpqCNQGwBP7qwXSt
	/xVh8stC6MzBrur9UAqT6a8=
X-Google-Smtp-Source: AMsMyM5mxF4yXUiugM4AnupJsB1SvfQaKXkwNU3gpH9A6t2o8nSFEoOxC8LY/I5VHfU4CPXiqTU5DA==
X-Received: by 2002:a05:651c:17a7:b0:261:c0b1:574b with SMTP id bn39-20020a05651c17a700b00261c0b1574bmr2080188ljb.40.1665159276030;
        Fri, 07 Oct 2022 09:14:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4ec6:0:b0:4a2:3951:eac8 with SMTP id p6-20020ac24ec6000000b004a23951eac8ls1671303lfr.0.-pod-prod-gmail;
 Fri, 07 Oct 2022 09:14:34 -0700 (PDT)
X-Received: by 2002:ac2:4550:0:b0:4a2:6e28:5d38 with SMTP id j16-20020ac24550000000b004a26e285d38mr2028552lfm.103.1665159274504;
        Fri, 07 Oct 2022 09:14:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665159274; cv=none;
        d=google.com; s=arc-20160816;
        b=U71P2i4tmt4I7m8vwLCL4hfmyL7hEmUa8SBH9UenYNPK2FR54st/fRGnZ+N5AlTOdJ
         yodnQ/q/FcM9g+TkUu5ofbiAjTl5LjFDxR5majCHHntOtMju1QZKOkpWFaqHYR90r8YF
         nJna8rDb97cszER0gg5I+fECQdmu04xIL/aq1oVEqx4qM9zTlipiGu+hXEV2hWO+ji5m
         ZFZ4fvO10qkwL8/iAIDeKIoVLcSeSb0ueVz6jHz7fNqKgGMLAzEcakIKS9rilMEw46jV
         JZb8JoTagYCUSSf956uurfYj5lILxglxAH67L+LERjJ8PbK5ROFzRiOQiNu+iYv4K7xc
         BNQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=gwCgcEFb6EqweOCGJwFjwMplx0cMo00I0pQaRZheEns=;
        b=lv1mEKl5el+gWSrM/jG/55U177aY4+ZSPwstbCvyz/dJxe0/OyJDK3Y2RzAUskgXTI
         zzQaIY4fZsH/Oggl27aojStDWtRfpNAisWkHfVGgg1HEUUCMS+AOz+0FAwGVs/qMslLh
         tvcRvcUJ7kBku/3aaXdUt0n7Spe+Ogl1S931JzFdJeVJcsAsJqjD3hjSGiE0nst7MPqj
         npP8K9fxZKUjJ48qPwzgdrO5uIZ2Z6HwLVkdZK4YHkjmCHOnT8ccc9Wy0t383rcfYEmz
         56JxA1sEkJXzcmKyF7cwg0uNdLguVZhJuBaxeBXDgd8eOV1jCWz1hLesRGOf8Wg0BKX+
         k94g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FLiXrIyC;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x62a.google.com (mail-ej1-x62a.google.com. [2a00:1450:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id g6-20020a056512118600b004a222ff195esi127920lfr.11.2022.10.07.09.14.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Oct 2022 09:14:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62a as permitted sender) client-ip=2a00:1450:4864:20::62a;
Received: by mail-ej1-x62a.google.com with SMTP id a26so12379178ejc.4
        for <kasan-dev@googlegroups.com>; Fri, 07 Oct 2022 09:14:34 -0700 (PDT)
X-Received: by 2002:a17:906:da86:b0:77a:52b3:da48 with SMTP id xh6-20020a170906da8600b0077a52b3da48mr4502878ejb.373.1665159274119;
        Fri, 07 Oct 2022 09:14:34 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:4e4:454c:b135:33f2])
        by smtp.gmail.com with ESMTPSA id pk18-20020a170906d7b200b00741383c1c5bsm1379772ejb.196.2022.10.07.09.14.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Oct 2022 09:14:33 -0700 (PDT)
Date: Fri, 7 Oct 2022 18:14:27 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs
Message-ID: <Y0BQYxewPB/6KWLz@elver.google.com>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
 <Yz7fWw8duIOezSW1@elver.google.com>
 <Yz78MMMJ74tBw0gu@hirez.programming.kicks-ass.net>
 <Yz/zXpF1yLshrJm/@elver.google.com>
 <Y0Ak/D05KhJeKaed@hirez.programming.kicks-ass.net>
 <Y0AwaxcJNOWhMKXP@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y0AwaxcJNOWhMKXP@elver.google.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FLiXrIyC;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, Oct 07, 2022 at 03:58PM +0200, Marco Elver wrote:
> On Fri, Oct 07, 2022 at 03:09PM +0200, Peter Zijlstra wrote:
> > On Fri, Oct 07, 2022 at 11:37:34AM +0200, Marco Elver wrote:
> > 
> > > That worked. In addition I had to disable the ctx->task != current check
> > > if we're in task_work, because presumably the event might have already
> > > been disabled/moved??
> > 
> > Uhmmm... uhhh... damn. (wall-time was significantly longer)
> > 
> > Does this help?
> 
> No unfortunately - still see:
> 
> [   82.300827] ------------[ cut here ]------------
> [   82.301680] WARNING: CPU: 0 PID: 976 at kernel/events/core.c:6466 perf_sigtrap+0x60/0x70

Whenever the warning fires, I see that event->state is OFF.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0BQYxewPB/6KWLz%40elver.google.com.
