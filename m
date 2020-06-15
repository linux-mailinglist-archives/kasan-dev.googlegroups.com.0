Return-Path: <kasan-dev+bncBCV5TUXXRUIBBQUXT33QKGQEIS74ILY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 02D301F9B03
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 16:55:00 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id p22sf20842289ybg.21
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 07:54:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592232899; cv=pass;
        d=google.com; s=arc-20160816;
        b=xpQjZ0YkRvkNTt7r+EL3K8u/ofbcYzrI8HtmoilTxCO3hoRgm55crbGIMAihuDJD+T
         12Ufp6kJFISvmIqYBY3d3jwOHoSs18sMDHq/ns7dkefYzDgQpZu8PHXn5zwjVdXh6K3j
         +2jmInHUWYzbLiRf5U89lZxpawSlLrUI7Ga6j5WFQMJhBdTnHXmg/rBY401fsqHKbcNA
         N9dXiSkrprCnP9XDolaeaDbgBOvUuc/hJAEtVQlizCZy9TeM5CeMQLNe9FFeLb6vIJv6
         LSMQ4MYOA1BJwK220bmckQK/dACtvnEUiyGts3V1/mOoFqMnIyJZ8fRjkxyEQvjaVkfB
         lbgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LgJBfK69putdNWMDtoE2yU3Y0DAJoViSD/UGQ34GHeU=;
        b=FL0+Za8RTp0ynxCBKgXIHqKsLh/pVQa2Jd06YcmpOvERvqLD6TV5/joBbm4VyMT+Bj
         B8u38y7uTX28zzJUWv8kVTxmr10RK0y9XAZaCDWX4ys9G8uV6+9q7ObvIZltDE1UBFRR
         4+CjF/ItHLV+eH6f6FrMU8fCGXO2AbigvIM4bBcchetzvp2NRkE/qNB12ZHw6dI3rTvc
         rzljNvbQaMNUtVTwtfd+zTD0JnjglaUUzqkM2wDw5bDM1uOb7sCNEJW9Zpz8HyJeZW1B
         CEQeJvishtJd2zQeSispAbGNmfI/7Yqv5mKdC0TB/QDvIDjeU21k6yOF6Z5rYam1snHD
         M0ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=ecmGxFrs;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LgJBfK69putdNWMDtoE2yU3Y0DAJoViSD/UGQ34GHeU=;
        b=g/P5AKd35isgwJPDlk44deGCFq2RmbQvrvi97mNMpBwNcmTeGqzppY8NS67DOvwyGR
         96yrGPUv4JVwo4alVoecRdanZqb5IWZ0ouA7MwMrbqoZkpnGAyGqJsMWJEkqR2/KCRI6
         M6LeWgwvJ9wSqsp8Vzx29cOQAqE2h72nzXh+8Sife0DbnpIiz1qlEEuoQTWwXlIlrK0u
         lRJd3c3DXtRd1jlpW5xk/X7bvbiVerD6o04M6Pl8QinN+JRjPBhh0HFJW33bkCWUjZBa
         m5oOyaiImCdSyTdjhXTOu0msQJcp5vYuirmxDYVb6cH+sKlRgtzd2i26nVJzYzZamGh2
         KlUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LgJBfK69putdNWMDtoE2yU3Y0DAJoViSD/UGQ34GHeU=;
        b=Yb1DK4EP/CNPby+GCGY2jTLCzkDIsxCfcACqpkB/gjAO7Xmd6HdwOOhoK0251Q4o0L
         rTb6dO5NWyG9sXgk7UEso3JmbMuKFhUupxZ+qP+QBQEWsC5VB/j9h4Da8rXfcw2km9Nf
         RNrQTvKcQR9ajEf03+jbsM17BNOV9hxJzc3Zy475ewppcBFf5KQnNaPEwgD/8sieEOQa
         XWMBeiphfSfTDfbzwQsMnAV2nHJhw3yjtSHT04tChIzbjr8aN22CSxvYExMhb0WCaL04
         qJyOtis80UwZrRGdpyF9SczK2GYLw9fGhp4i0DzfSkiCD3iygmuFKRBX2kWcZZDltDR8
         qqiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533rMhWE5Ma8Z263Z3s+XcwJdavnHdS3YvAgWtgSRwZvWIXYWyel
	vrqMZOet2pq8zjcVPPQtcKk=
X-Google-Smtp-Source: ABdhPJzanYIQlFtt5ZrWE4WubvGBkcKigTn8snl3lpveUVu67JTg6FtUZEZWPKKTWghhCLqd0D5TRQ==
X-Received: by 2002:a5b:843:: with SMTP id v3mr47445878ybq.106.1592232899056;
        Mon, 15 Jun 2020 07:54:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2e50:: with SMTP id b16ls5769973ybn.6.gmail; Mon, 15 Jun
 2020 07:54:58 -0700 (PDT)
X-Received: by 2002:a05:6902:1005:: with SMTP id w5mr29627713ybt.173.1592232898710;
        Mon, 15 Jun 2020 07:54:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592232898; cv=none;
        d=google.com; s=arc-20160816;
        b=wyCAgsxFzwkRlwWsaAfM2SsJW9gDt7LqGckSRDUFXx5xaRMmzFYefK1psT1mG+PZAZ
         k7wc/+jcGzdhsuVdtapB4hLgJ0HAqwn7ks4h1Iq5VWwfcn68joAhWclUBWPmHVF0BhV5
         /G4aobIQYRnePsspJ6njYHZ2VKJ0STkkRIq6u9Jtl0cuG8HWGmh8A7MGLUx0hsnLk9Q3
         Tsnj8RiAhu8aJrVt119wFcQo91qlP+0yBhMz0yrQT7v6tiOjMvupwsbehyWRop+uQ4++
         T98gq6SM3oDXvaSj1irbblauq89dYiFwpSZup0ZZs3Oohrnp7DYkRS1OtLkx3uZeSzIU
         mMSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4zGfMuE5j27OryPVO0IL9HdYeTzioBh7k+J5vYWJu6A=;
        b=wxjdLEAbAoOidN/N8SFJ0794kpE2opx2/hL4IKDzW/8pPp0ukNisKSX9ActXVNXYlv
         CEco/QcjaFWYVojb2cdgwW9WtQBFQV/fCTnWS6iEbzJhfyPcndzWl5+atKGjpBEW5r9z
         pk6NI3tf+2/AHV8xxD9psuY3oP05hxzsn397WyyBmsfcBerZZBvkqy+28tQkAVThdBv7
         o93XVPzXGyZSJK+gu682ATd0g2PCpID3iCPc3WSdENtpDtpnVqiloZYpSwvGp567oy75
         NTmNGeiSDllK105HBgTRZKlvGb+5xLXpUJCDqrUnKM9gl9WA+H7hEZ/hDhmwJJLp16jF
         OLLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=ecmGxFrs;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id v16si1020841ybe.2.2020.06.15.07.54.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 07:54:58 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jkqVe-00072A-5A; Mon, 15 Jun 2020 14:54:50 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C3DD930604B;
	Mon, 15 Jun 2020 16:54:48 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id AFEF8203B8070; Mon, 15 Jun 2020 16:54:48 +0200 (CEST)
Date: Mon, 15 Jun 2020 16:54:48 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200615145448.GV2531@hirez.programming.kicks-ass.net>
References: <CAAeHK+zErjaB64bTRqjH3qHyo9QstDSHWiMxqvmNYwfPDWSuXQ@mail.gmail.com>
 <CACT4Y+Zwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA@mail.gmail.com>
 <CANpmjNPNa2f=kAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA@mail.gmail.com>
 <CACT4Y+Z+FFHFGSgEJGkd+zCBgUOck_odOf9_=5YQLNJQVMGNdw@mail.gmail.com>
 <20200608110108.GB2497@hirez.programming.kicks-ass.net>
 <20200611215538.GE4496@worktop.programming.kicks-ass.net>
 <CACT4Y+aKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh=jgX0ZvLw@mail.gmail.com>
 <20200612114900.GA187027@google.com>
 <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
 <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=ecmGxFrs;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jun 15, 2020 at 09:53:06AM +0200, Marco Elver wrote:

> For KCSAN the crash still happens in check_preemption_disabled, in the
> inlined native_save_fl function (apparently on its 'pushf'). If I turn
> fixup_bad_iret's __this_cpu_read into a raw_cpu_read (to bypass
> check_preemption_disabled), no more crash with KCSAN.

Yeah, I can't see anything weird there with KCSAN + KCOV + NOP :-(

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615145448.GV2531%40hirez.programming.kicks-ass.net.
