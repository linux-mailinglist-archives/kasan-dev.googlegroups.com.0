Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5HU5SNQMGQEZREGFEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id C5566631BBF
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 09:44:37 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-13cce313cd3sf5436894fac.20
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 00:44:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669020276; cv=pass;
        d=google.com; s=arc-20160816;
        b=aEYuD0AG3jfX7UvB32UFf0kydBpXt7kdzn/v9qB40GhqqtckBjQ/15jKIg1stSKo29
         pKALT9h6iGl9G8vW4aZiMBj5ns6QCdJzT0p0bPiAqz8OakZfzubCiD1ozdT9B1NsgGE6
         DvobXI+7wGCNl7CVZeVci7rjzyGYjUXxApLNVtUq8SMqrgNL3SRaWxvs5Oo3ymxMdqPZ
         gkQ4OTaQbYj2z/2Pru10eGCgTLPlsg5rH9CV32hQMaM1depZYYinVIV+FaonWCPGBE0r
         cAr3RHr0bDNB2K3O4gJrFjnTS7xqYlCyVthLKlXPCBNzfcWTt46/m35h7tGsw9+rN33I
         BYIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UhajuL8QpSIyqrZTCjLRBkKogXmZryVzPi+aRcCsGT4=;
        b=HOD0rDrcJDt/YNO7Pf0mC9wwvPvPodrtQ9oeZLSukYLYu+oGtQ2LHYp2d/ExF1u4rB
         ntLURd6fB4ag+bBbTQqkvAieX+XSGFbfuAYJi52EZPD9alrzA8X6uTI/12npKA5bFoQ8
         t9ptQ3G6QEd6Ot+ljU+31poINIeR+ejqczGNNkhK2r4hvQktZ1hlBUzae3bi6xTwRx5w
         C1w2hiWcuAMH4wqs48c9MxcWrTYc1FhAP7RWxVKDY+CHh4bRu6VTIONFUiY4JjaF3S5n
         v2JmoFB6vKtDa1f5w5VbWqSN5hD9iB0Q4xxPuDHMgbPP52rCJCfc7whPMtzQI5JMCAnt
         BTew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mh4hjbsI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UhajuL8QpSIyqrZTCjLRBkKogXmZryVzPi+aRcCsGT4=;
        b=CX1fIVxwdO0HVC6+5FJ/EAcoNoC/QGttsG+/ce4HBMGhqusBZX2COZutiE7Y99d2b0
         psf7QAREmwWM+fCLJo5B7ZjEFJDqU03YhXpyaF9cI68pbsPZB2x9Vn5Hz/K1JbGKm89s
         EIwJaGbGeOxWiuezHhCWqTOYfVU5GeBr83GvQ3BZUQ1mkZnx4u2hX7N71h5mvKjBC3+q
         9HdrJKSE6mKEECz5YuXN/Tigs6JIblV87kyPvyCpYREicXihWmRwvFIgd4knvL3xMQt3
         afjPRB/5Jqj65hlOvSdhw8zI2hU479mmleol7jrCyVwz7/ybl1EkynsIX6be8ZWc6qFc
         5EQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=UhajuL8QpSIyqrZTCjLRBkKogXmZryVzPi+aRcCsGT4=;
        b=i8BQDuksGuN0Rgf/D3Hm4FqA+dBoNIJ2zyiLQBO7T3l58/d/4TFqkR1flmjJkvvkYR
         duJbztn9h4oTv6GgZ5dVJ7rK5NNNQkI+bp/tBigC5sr72zEWMIOk3LUeglCOEAJyKfqY
         /41hz0YoFL1zw5CUL6LGHLbjfZwvN92QG/BMiYHt6eOB90yll+FhrslgPVK+Tc1dmbWb
         rPEeKfUGYVbqDk1BoGUscgdM+VWl9KW+I1TAtcfeQPNcoz8RWgkR1SzT6TFRXRkuFfol
         5KG7DWuij72RiZi/MPm2IUbzeT14GallmjTUyHWnthM9Yv2cifJF46ZwriU3LpRmHpMl
         LuOA==
X-Gm-Message-State: ANoB5pkdY6FPRP19W2pY8bkvhgagkSZPnr/8etS0ztm33YbR2uvNlacK
	OPqocR+Oz4GDLhx39irdFOc=
X-Google-Smtp-Source: AA0mqf4aPTmsNhpBqqkrEhhMA8X2SJxamxNFEmTAehqdq0+NwZ2zRItPEkUM+R5EynvIObg9xLxIQA==
X-Received: by 2002:a05:6870:ed43:b0:13c:29c0:7d7c with SMTP id ex3-20020a056870ed4300b0013c29c07d7cmr1065255oab.17.1669020276653;
        Mon, 21 Nov 2022 00:44:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1a81:b0:142:db0f:4803 with SMTP id
 ef1-20020a0568701a8100b00142db0f4803ls751237oab.2.-pod-prod-gmail; Mon, 21
 Nov 2022 00:44:36 -0800 (PST)
X-Received: by 2002:a05:6870:d5a8:b0:13d:8222:316c with SMTP id u40-20020a056870d5a800b0013d8222316cmr12724367oao.50.1669020276174;
        Mon, 21 Nov 2022 00:44:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669020276; cv=none;
        d=google.com; s=arc-20160816;
        b=qDs7hWjJfz7ySvGYkzu8YTP2ysji4/Vl9rDp0d5pK0dWvhsNN4XwKMcy4ys3ZtfohG
         ittye74VO1Z32wqkcybwhUFI67gj6hg2P88vJCW47sc8D6JCmwtl5dk7++XR73jaMtW6
         83L36PlHg8EMjbDxzKbt2USCHjECQ4vS7FXay50FjZ73y2OnLqKUL4efVErcvh9HQh5K
         xMPGYhdngF95LUNshFSFdaWpaEJM8Io63fAVtcB+3XAKA7hUz+ZZmmFa1/ZWzRWVe9A0
         kRRtgieLxfUDDw9mzSqbdqiv+dvbKstWMJLaEL9XDXE+8AsSF2ykeGMxOSYxAOpXBOBQ
         KVRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MOA8LWvdV7vpIMbp9gmLxG/AXDKNs21CCNUeFEEyCbw=;
        b=C+Kt6F+3Py9qLiLfJBp9NGBDPHx0/5Q0Vfi+AvTDle1BWWozwvjoqtiuanP3VwD6kt
         ykoZ0TAsQrpYvMDc4Dd7Gpk9Y/P4wvsQOWcQy9rQ3+UxKTMW6PfRJ6BDJyzOgDGwmHCW
         RVW3vjeVXNFhYSUJuelhH9E4dTQaJBHXPmGEJBz8WfWSdI1vrJDCoEZt9fmx0R5m2tpJ
         Z7CelkLqG1DqUOqleUebnD41A12pDCy6iwcsgjYNAE3uRAN0TEd6TJG7EL47gJL2Hk+f
         4OByR3V+PwLMXpJFS7XGQoYrDkjGhSch403evmPxeveJS9Mmm9DIKrI25PoopqaMm32Q
         W0dQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mh4hjbsI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id g8-20020acab608000000b0035522fd7d98si577959oif.1.2022.11.21.00.44.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Nov 2022 00:44:36 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id y83so4668059yby.6
        for <kasan-dev@googlegroups.com>; Mon, 21 Nov 2022 00:44:36 -0800 (PST)
X-Received: by 2002:a25:75d7:0:b0:6ea:c9e3:fcc3 with SMTP id
 q206-20020a2575d7000000b006eac9e3fcc3mr6559879ybc.553.1669020275636; Mon, 21
 Nov 2022 00:44:35 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYuFxZTxkeS35VTZMXwQvohu73W3xbZ5NtjebsVvH6hCuA@mail.gmail.com>
 <Y3Y+DQsWa79bNuKj@elver.google.com> <4208866d-338f-4781-7ff9-023f016c5b07@intel.com>
 <Y3bCV6VckVUEF7Pq@elver.google.com> <41ac24c4-6c95-d946-2679-c1be2cb20536@intel.com>
 <CA+G9fYs3NLZgorPT33vu6XQ3HA6BpN_hL6GZWbfnirGYt1tNaQ@mail.gmail.com>
In-Reply-To: <CA+G9fYs3NLZgorPT33vu6XQ3HA6BpN_hL6GZWbfnirGYt1tNaQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Nov 2022 09:43:59 +0100
Message-ID: <CANpmjNOrZgBsgk1xxxz8-DrpnT0F0zyjin67=8_Ss7YZK-5_Mw@mail.gmail.com>
Subject: Re: WARNING: CPU: 0 PID: 0 at arch/x86/include/asm/kfence.h:46 kfence_protect
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: Dave Hansen <dave.hansen@intel.com>, Peter Zijlstra <peterz@infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, X86 ML <x86@kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	regressions@lists.linux.dev, lkft-triage@lists.linaro.org, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mh4hjbsI;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
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

On Mon, 21 Nov 2022 at 08:28, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
>
> Hi Dave,
>
> On Fri, 18 Nov 2022 at 05:24, Dave Hansen <dave.hansen@intel.com> wrote:
> >
> > On 11/17/22 15:23, Marco Elver wrote:
> > > Yes - it's the 'level != PG_LEVEL_4K'.
> >
> > That plus the bisect made it pretty easy to find, thanks for the effort!
> >
> > Could you double-check that the attached patch fixes it?  It seemed to
> > for me.
>
> I have applied the attached patch on Linux next 20221118 and tested [1].
> The reported issue has been fixed now.
>
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> Tested-by: Linux Kernel Functional Testing <lkft@linaro.org>
> Tested-by: Naresh Kamboju <naresh.kamboju@linaro.org>
>
> OTOH,
> I request you to walk through the boot and test log [1] (new see few failures).
>  not ok 7 - test_double_free
>  not ok 9 - test_invalid_addr_free
>  not ok 11 - test_corruption
>  not ok 18 - test_kmalloc_aligned_oob_write
>  # kfence: pass:19 fail:4 skip:2 total:25
>  # Totals: pass:19 fail:4 skip:2 total:25
>  not ok 6 - kfence

Fixed by https://lkml.kernel.org/r/20221118152216.3914899-1-elver@google.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOrZgBsgk1xxxz8-DrpnT0F0zyjin67%3D8_Ss7YZK-5_Mw%40mail.gmail.com.
