Return-Path: <kasan-dev+bncBCU73AEHRQBBBB4WW2LAMGQEL3WDSZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id DE1E0571D59
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 16:54:00 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id o15-20020a05651c050f00b0025d7ab3943dsf381423ljp.14
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 07:54:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657637640; cv=pass;
        d=google.com; s=arc-20160816;
        b=uH1ngWJdgTIYLqb+xdomxCd/D3kAyR9C8Cihr4y+bbRsg+demG4aqOO4Suicupq9zQ
         8T6Gg2iQVOIoSEySd+vzSi3ws0iO6Sf2txrNPLhkFg760QzkqxLTL8z6tg2LABaVGoMA
         cBEGOAv6r+buY+KOYtsDKQZHNUn2QVKefTihQFtiPwrRnImua//gPvCMzIw8SylVwElG
         WTlwgbKtRGltoulV8ek71IigccY2w+B9F59AbVWXe0cOoFTlvrh2+JmRomManejXGnnX
         hB5cAXQIOakheL5LNw9eFVviSkyIx8b7It9i3ItsaMEKv9PdyyLRMGD56LCSfh/nCTbn
         8JBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=QplKcOyhRJKShvhNEe0xcLYRw2g4xZhQv0YeMjnqXr0=;
        b=z96xpIs+pU824dZR9AhE55+B/T7Xz4NjLm6BImFInN1Onewn2Fx9ITExbPBzbLCPoC
         ABLFhetmsIPgHbHyGxMYXi4MylyGZP0gtiuntRvDqZrTYfWmzJYgLPfDM5w/fwWNFdYC
         9fPbt7S5Rhx2CwMuW1AEf3zJU/fVx/gfqEtW0PBtLiJGYRN7sG5STMc5pffX0ivJFRpn
         2POKXiW1PLekh6Yvp6dCQcHc0Chhd0VhiWizbA+8U/oOEfBdL5F3Ck5W4+01gD2eqJx8
         Oyn/O2DVz9PkQbmWCvqZMcat2Nasw5TQ6PRa9cOFKMakJWIxtHdqKPZMpuqSKt0xEble
         8Oxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=xucx=xr=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=XuCx=XR=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QplKcOyhRJKShvhNEe0xcLYRw2g4xZhQv0YeMjnqXr0=;
        b=aLQq6kxIVhw/lVmmnX/czPPiMdAMorh2O2l6pWoUc+4eDFJbC8z3fnx41TXmzKG9Ik
         FNYqJMtZd3PoGRjmrX+RtAHi/FjORa0fhFF8xa/rhXEEO+3xPC1uNNiIAI3Wvb9u4hdx
         zb8irconR+AlpR2QIQpFmxTzjtOoceU3Yf4gKHJVPwkSu3Lar/Ww76NXJArSr9ECcD94
         I40+EImDAVbSkLQb26z56UJaYktH+h8xbrCf2JwEJBe5FYUNsZ4vC+UJFN48obA6KiiV
         tB5SxU2AG/9+mCRnaLrz9SevBeAlPuQtso8hWDnxF3gfVGFpU6/ur6sPJ5kHaXeuSo6l
         JMEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QplKcOyhRJKShvhNEe0xcLYRw2g4xZhQv0YeMjnqXr0=;
        b=d6/OZxTILqWjhGBh1ifsVZIRzpdyJZRt0yCOWlIU1QCgTcnf+YPAbZl1IT048MVlTZ
         6Do+E83d1dhQIfgpHdmFJ2o40AdwNzUAMBYKz7Dvgn4CiHYxGKl9CR6xfTki9L1qBFTP
         YzaZqgTwe3vMVJGl/Cc4G/aoCtcNl0hD9b0H7/2tJuAT24tOtmmhZ7IlbYoKeCd07bvk
         o9g0laQjEbbm/fLHIuIUCk7A6Xn/aA0mxafBn9xyhwDclFnEtUy4jRjZHh4tWBRk+/FR
         zFpYA96nE3X7KdprP5rPvuB10AH+i4bnnJvedVpJ63rZqZyzEMjfcnaf+IlUjs05zmbv
         1zeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8wQ30mqQ8Pgng1KHw2rm+u1I54QLYjHBxaiSWNfLL+mEX1n6NC
	M86t17R1jYOUUl4N6MFvd24=
X-Google-Smtp-Source: AGRyM1vJ/OtvxqQhw71AAaUvIvHVvpGqepnGxVfQLi4IPbrhafZDnVwRlMH2TshoxVNdi1YDYf3IPg==
X-Received: by 2002:a05:6512:151e:b0:481:348b:100a with SMTP id bq30-20020a056512151e00b00481348b100amr15080741lfb.253.1657637640231;
        Tue, 12 Jul 2022 07:54:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e34d:0:b0:489:dd8c:5436 with SMTP id c13-20020a19e34d000000b00489dd8c5436ls504640lfk.1.gmail;
 Tue, 12 Jul 2022 07:53:59 -0700 (PDT)
X-Received: by 2002:a05:6512:32c5:b0:481:1822:c41f with SMTP id f5-20020a05651232c500b004811822c41fmr15920994lfg.373.1657637638991;
        Tue, 12 Jul 2022 07:53:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657637638; cv=none;
        d=google.com; s=arc-20160816;
        b=p3kpvr5YZg85+f6JRniaQaKa2VGO2xjO1NX0xMW5zH6aVIpmY0ZEABRDIR43V8oqPN
         HKcHW22fmhytgU+RYusbDQSoxyGBMaWkdXQHU4VBTQcIFIEp3y+VBEGTlEMRbG+gRV5f
         3qD9VQBhz6cYgTAKWZu77yOug2bHL5vydvoYUQuxo6H405+j7oIbDD7hfA9NpRbXMleo
         +b+aGfXMvdT5Wknt8lpVAYzNMKrI29D5JlSTT7ykJXaV+CAtUmGSO+WXsBL5kEws/fFU
         +8i+ds8S/pkfinF/tcOwbXvwDA9dgWD924wMYbIUjXOMwS5KqcO0yjyESRxa09wfy3L2
         Qz6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=iNdkETl2DbYNSfoo0oNyffpmXOZ2zdxUHRhLmFxPLCk=;
        b=lJcuP/IHKIoyp6Zerjv7JuVcm91CYI6anq8q+MMP4QXwitIjYhDe5R92TohMCgBjst
         /ak4FERtNbLCjmAAp/VzE1FE/YKrJzl0Y0hBoEPGEjxCt7W/vyQneZ7QHjvBP4FM67AH
         jMN15LAJGOwsV6hz5y+JK2J0cUyfxh6YtxIuGiLlDPAOlhmK1c0pphNrC+LzHLlmF28F
         qwgkZOHnUK/JAH9x7T+BcI7v6E1i2TNd7WZjEJ3nMngsuono8dbHYI94wSazG2Ze7Nso
         L5xW8oZh3UVPU0fRUeLJM78Cz2sWnf530vbn1z6lxxgz5geg3YqzQHQcSHmwfD7h2+qA
         Dlgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=xucx=xr=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=XuCx=XR=goodmis.org=rostedt@kernel.org"
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id n10-20020a05651203ea00b0047fb02e889fsi372615lfq.2.2022.07.12.07.53.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Jul 2022 07:53:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xucx=xr=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 588D2B819B0;
	Tue, 12 Jul 2022 14:53:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C0597C3411C;
	Tue, 12 Jul 2022 14:53:54 +0000 (UTC)
Date: Tue, 12 Jul 2022 10:53:53 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, John Ogness <john.ogness@linutronix.de>,
 Petr Mladek <pmladek@suse.com>, Sergey Senozhatsky
 <senozhatsky@chromium.org>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>, Johannes
 Berg <johannes.berg@intel.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Naresh Kamboju
 <naresh.kamboju@linaro.org>, Linux Kernel Functional Testing
 <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220712105353.08358450@gandalf.local.home>
In-Reply-To: <20220712134916.GT1790663@paulmck-ThinkPad-P17-Gen-1>
References: <20220503073844.4148944-1-elver@google.com>
	<20220711182918.338f000f@gandalf.local.home>
	<20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
	<20220711205319.1aa0d875@gandalf.local.home>
	<20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
	<20220712114954.GA3870114@paulmck-ThinkPad-P17-Gen-1>
	<20220712093940.45012e47@gandalf.local.home>
	<20220712134916.GT1790663@paulmck-ThinkPad-P17-Gen-1>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=xucx=xr=goodmis.org=rostedt@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=XuCx=XR=goodmis.org=rostedt@kernel.org"
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

On Tue, 12 Jul 2022 06:49:16 -0700
"Paul E. McKenney" <paulmck@kernel.org> wrote:

> > I guess the question is, can we have printk() in such a place? Because this
> > tracepoint is attached to printk and where ever printk is done so is this
> > tracepoint.  
> 
> As I understand it, code in such a place should be labeled noinstr.
> Then the call to printk() would be complained about as an illegal
> noinstr-to-non-noinstr call.
> 
> But where exactly is that printk()?

Perhaps the fix is to remove the _rcuidle() from trace_console_rcuidle().
If printk() can never be called from noinstr (aka RCU not watching).

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220712105353.08358450%40gandalf.local.home.
