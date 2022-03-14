Return-Path: <kasan-dev+bncBCBMVA7CUUHRBXEJX6IQMGQET5UWXVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6510E4D8FB1
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Mar 2022 23:42:38 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id a2-20020a056e020e0200b002c6344a01c9sf10163506ilk.13
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Mar 2022 15:42:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647297757; cv=pass;
        d=google.com; s=arc-20160816;
        b=eBIHE9oIPn9k8VCnKQbA458V+owAx/0Cjk8nRmQIMO93+tBmNcEBS2DL4ivraD6n9R
         6nRsF9/+/ZPbippipmGYZgSv6afRs8MWzW6LaO4QLrcAI/IyVSR0f0sjUNdcUBEqZB/L
         /JrXDYw9ZnuhAhh4We14dYTP3U0Rg01If/wJdEB7f19mt/x3mETibsew5lIu+ZIRgCjK
         UGTSJZvvV8g1QYvn6mNSuUGjf6xOZewB+LQSNYVq6ssKkSg11IUoQG+Pbcj3thGqldpI
         LfBnJ3GQlpBiikIuPvjKmXKuL0qs0LjziOyxrrhMWJSDG/dkVWFV1I4mpszHg/B4qEZO
         MnTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=n42kOcfBm73APLl8TFQkOD4Xrk9tCHRnNo1LrstMJuA=;
        b=MAHT6NVCfyM4oLG+yEHekXEauXzHR5G6GvYr7JRwS4aOfmr7ELHGla2FZu/9IUP7RQ
         ogJeIlwPm70SgqLthWxIkznjvWMnV99/1GZKL7HwnW+fRKQJvzyDrw+YKzXCh5y1k7Dk
         IPEkYv1EcbDcF0ZYhlF+1hQqQAbcEELSDD9XJs6Wx/uNkIASGZVdBJwnNGHugXTAtQbv
         vDZbiuF67F0T/daGh9NX+JWsp9DMTHe4gZkrZhAkKLzZ0GoYznEUkC7tsnD8sSlqPOT2
         g4qDODcYOn2aKBpHcTBeoyU7jcuHIoF4L3KZwoU+bu7Yj0Kxrsva4s1tYKNqShUmzZBm
         c2Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iRIgugiE;
       spf=pass (google.com: domain of frederic@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=n42kOcfBm73APLl8TFQkOD4Xrk9tCHRnNo1LrstMJuA=;
        b=Ea/t3c+sVToHRoZXPdQs3lyCLCIho8G8VthhuTvWeTzZ2ePeGcuQ4B5WEloHs6few1
         IiMcgnhif0mWYR18yWv0JB4gM8NCaLxyyz8qRyOilPh6GIHghEeU+6qTpL7MawfGHZPO
         Jh5EgL8Sv9DMl2wv/r72FjSXjw1rZyRk+TizYwTsBO8FdNPVK7WuKoyycuqfL4M9bKau
         jrYG3Enfj5iNdDlCUD1krWlciv4ek28Y7pxDWnvcB0J9E4FxWiOp2SONYKr2q3DyV/RH
         rtMftLz9oxI5g/I4kDZ82ndws3fsdS25VHOzVCqT3PEH1f1nMPvhuEHDpH5SmBsvPOO/
         Mxng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=n42kOcfBm73APLl8TFQkOD4Xrk9tCHRnNo1LrstMJuA=;
        b=0CmoDKkzEeZiY5sy3F8zEmb0l9NzHpgipNsQDvl/grUjBTneljU2lCyv1+q2FHFbbw
         iBUz+OUnE69v/EnCgAPk2Eitw0aOmt8XOD5cnw1ybtf9+gQfKJayfaiGDLKMX/GGvOK3
         u2+wAiZNdylCii1G3Ouno1iLx1dt7kPsO2NMkgfYNbht/q2Jzn2c1i7a4N/x/00lH4p4
         YS4ZAZBqDGG95B3Uo58NWvjp2Wkb253MX1GeetPzpBjr/hTR1iabr+W+ntTlb36yXB7h
         ai+R+tuXUv3uannUs7saOp4mgcpSsahBJko+UF+DL3EMJ8p0UhmbonkOiWFjaaBqyvig
         mHBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531WaIo2Q0d5oV8mSngF7EAU9vMz0ME7CG6RGuLqbt3y6KIqBZr3
	jmV27J5pJIjhIH0wkt/8BC4=
X-Google-Smtp-Source: ABdhPJw93OyNnBVYjZQnLKmN+hIeIuWl0jqay7Ab2vOaLdkjGJmkqoZJK3HxzPQCevc12Mhb+q75ng==
X-Received: by 2002:a05:6602:1591:b0:60f:6acc:6979 with SMTP id e17-20020a056602159100b0060f6acc6979mr20999185iow.173.1647297756937;
        Mon, 14 Mar 2022 15:42:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:60e:b0:2c6:3f8b:f630 with SMTP id
 t14-20020a056e02060e00b002c63f8bf630ls1769765ils.10.gmail; Mon, 14 Mar 2022
 15:42:36 -0700 (PDT)
X-Received: by 2002:a05:6e02:16ca:b0:2c6:7495:700f with SMTP id 10-20020a056e0216ca00b002c67495700fmr20705917ilx.161.1647297756525;
        Mon, 14 Mar 2022 15:42:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647297756; cv=none;
        d=google.com; s=arc-20160816;
        b=j3J6defFQM5uuVPUI47t8Bquc0dJJyY1WmvhUl9UiuUSVs6RcPriVb48wiahDc3Zel
         dI730eK2WBcfoRMB3GzPb4BYRTroLzPcStFngxp+0EuQ84vIXP6I7uaNoaefPn+DoszE
         CmQ/Mh9GUwZJSUTWUYb8c+Re3PZuQcAQnWQTO56tUsvHYazHTjSPuN9qqMIaRsvIS6cX
         VfaohzWryOHC/YJTUZBbRIu1BTEYVJaTkxGZrtZ0wNZs9/h1vaGwouMu+9noc/chsj/w
         iTUtMWLsz7t6jAb9A+9de0iEWpUiizZFYam7z6DzbVAn5kI0BywPjU7nLKxMRjBeO+PZ
         ZPMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8w2DcMGcvfrr99dSetwd/hRjO9tBLBhRHHWNmWp8Qmk=;
        b=X5XlMaLGvaHmlgCzqFitmb9G0O0aMd87DKFNuDGSmjmrdphDx81Hgsv8TMpMAKlmaM
         LhgUfsLSYBnPVM22nLU+k9lx5/U2+fLUXIlKYQrV51wUhSa8IrKWmtKG4yfdLtyc81CR
         mEDUu9B6fPL1FTrdrW+vDf1rv9KT2gxXXKHZ+bGEdJwco6PK+qJQ0BlMojwWrbBJWiHH
         ZHaL1D7Lv7hRqRLZXjBU7r9DiKBCazKjhR6tZSHQXqWk3Ms/bWVbYK+AexV2WaHpJZwj
         UArMLkpF/g9WB3eK5/7QklsjPjiODmhjFc2UB+zBUoXkVRMmGL9DWvRx8Tz/t4hcA5WJ
         88gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iRIgugiE;
       spf=pass (google.com: domain of frederic@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id a4-20020a5d9544000000b0061154a59e0dsi1766218ios.0.2022.03.14.15.42.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Mar 2022 15:42:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 213CD6144A;
	Mon, 14 Mar 2022 22:42:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 03AADC340EC;
	Mon, 14 Mar 2022 22:42:34 +0000 (UTC)
Date: Mon, 14 Mar 2022 23:42:32 +0100
From: Frederic Weisbecker <frederic@kernel.org>
To: Valentin Schneider <valentin.schneider@arm.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org, Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>, Mike Galbraith <efault@gmx.de>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v3 0/4] preempt: PREEMPT vs PREEMPT_DYNAMIC configs fixup
Message-ID: <20220314224232.GA274290@lothringen>
References: <20211112185203.280040-1-valentin.schneider@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211112185203.280040-1-valentin.schneider@arm.com>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iRIgugiE;       spf=pass
 (google.com: domain of frederic@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Nov 12, 2021 at 06:51:59PM +0000, Valentin Schneider wrote:
> Hi folks,
> 
> This v3 is mostly about the naming problem - get your paintbrushes ready!
> 
> Patches
> =======
> 
> o Patch 1 is the meat of the topic - note that it's now in tip/sched/urgent
> o Patch 2 introduces helpers for the dynamic preempt state
> o Patches 3-4 make use of said accessors where relevant.
> 
> Testing
> =======
> 
> Briefly tested the dynamic part on an x86 kernel + QEMU.
> Compile-tested the kcsan test thingie as a module.
> 
> Revisions
> =========
> 
> v1: http://lore.kernel.org/r/20211105104035.3112162-1-valentin.schneider@arm.com
> v1.5: http://lore.kernel.org/r/20211109151057.3489223-1-valentin.schneider@arm.com
> 
> v2 -> v3
> ++++++++
> 
> o Turned is_preempt_*() into preempt_model_*() (Frederic)
>   It breaks my rule of "booleans must answer a yes/no question" but is the best
>   I could come with using a "preempt_" prefix
>   
> o Added preempt_model_preemptible() (Marco)
>   Now used in kcsan_test.c
>   
> o Dropped powerpc changes
> 
> Cheers,
> Valentin
> 
> 
> Valentin Schneider (4):
>   preempt: Restore preemption model selection configs

Seems like this one has been applied from the previous series.

>   preempt/dynamic: Introduce preemption model accessors
>   kcsan: Use preemption model accessors
>   ftrace: Use preemption model accessors for trace header printout

So for the rest:

Acked-by: Frederic Weisbecker <frederic@kernel.org>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220314224232.GA274290%40lothringen.
