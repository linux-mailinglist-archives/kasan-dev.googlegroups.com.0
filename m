Return-Path: <kasan-dev+bncBCS4VDMYRUNBBIOAXG4QMGQECAAV4OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B134B9C254A
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2024 20:01:55 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3a3c72d4ac4sf26008625ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2024 11:01:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731092514; cv=pass;
        d=google.com; s=arc-20240605;
        b=e+u1EyRa1+T6LoNamVSPWs+83Claaoj6mgVCQs1ECjjvkYpEZDSFWtfw98wQd9IVKD
         /gra2n9FrGXGlWxCbDceym2C4zM8tkBPq55zuLDHpJsUcqpY2FFPMfe0JmlDiATBHb6Z
         zcjWYSXSi3jjv/aYFk5gL5I1y5rAEZYuwW93nC7NdVdBUoqmpxh4fsPqRTB6IO24oNWD
         qrZ9Cglx21beYRD4bliZk+lHGiMM1dc5cC1au4wdr1sfVVxDn11XOroIMRZLAPtBsU5m
         A486N8l2Xmoj/zBY5e8DU57lCzijBqJYkJb5R8BhUFc4TDhGd5yyWcw/vwq14kAW1G1H
         TMvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ICAxKPvOQIx6o/tnH6kVn95qKq7cIyX8X49SvVG0enc=;
        fh=tDDKIFm1Qp2doK4VFZdDU+y76C4RH6fFTPhgt+ma4LM=;
        b=K/xXWAnPP8d4t6gXNmJ15cMK8qm2blzzkPCl56IHd3qrvMeOiSk/16Yy7c+bbgktg6
         oxULIrDaIOdPdcHMLLKCWNHEEUSqkRpfE1aZFH2Y/gi5A22YuBGrOfpQdWIo8P8zt67p
         tJoJ/4j6Lu7+//OliLiP/yi2Eu+YhsB+U7grifHsn7nyOk/+7KKkJodpxKdub7Ef0MRO
         sJagdFiddiZInlQoCsHwTxFyzmV+Npfh4jA8LkC832yG2mB/saZDDbuWSeD0CTn416TA
         L7/uELIZVtga7PYgJJiDQpjHOVv6rA6aoiqSOIDAnFQBmmcC2Rfusr4JFSNjeZHP3Gy0
         hBZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=atUA5kVz;
       spf=pass (google.com: domain of srs0=eyrl=sd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=eyrL=SD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731092514; x=1731697314; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ICAxKPvOQIx6o/tnH6kVn95qKq7cIyX8X49SvVG0enc=;
        b=CVD06xJzYaSEiS8gRCO7EePmXlx1MhyDO95HhZLlpKVyAJGI2X32x6SB4yO16LstIr
         ALsC+XbhZd8HKcFB9RQ5xEA0V7b5oqzNTUV6Q35DeGF3h9mbyeppCLlDvkFmqJYOukkw
         Z3rssuQ1/cEzpNLo/TQCtIs0IzImib1TW9ESxAPYX/AKtxNfxQSVBNlkNOslZ08pDRN6
         vpgMf9aIU0aQNvy3TV+2weFrWeED0hNSebqtJ7LUa7gbniVroP1hBSzQkOLCioUc6A/X
         pUlZhU+5tUOwKTJxdo1i5VFixFY++YjC+NHssoIv6/UKHlG/+5sJCt8PF0OuAZeF8AE9
         JSMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731092514; x=1731697314;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ICAxKPvOQIx6o/tnH6kVn95qKq7cIyX8X49SvVG0enc=;
        b=nUcofHeXakRkmVRvFY3PO/5d1Q9Wx9ZIlZGa1jIyft2HFRmcHhPk6M45MeIx3JkGoO
         Mp7H+laavoA+FIYQ15YELBhfOiMz2Qz3OzOGLoKcHgTeZRevU3IKTkmxh43E5F0jYYqd
         zDwuH0e3pksCAyjppENOPZsQRrwIYYf38vofO5isReRNr2nWSnvQ9q8z/raijlCKlrYl
         jgCXezExy/DP5Dh8oEUgoBWOtE/BCVc7vMOlv8jCzlnCpcw653Mkj5xhN82fikTTWxUh
         zABTq3DUFH9wz3pNZg/glfVMpMbYGJP8FFZMA2Kq50c8JUX8ne5Chnh9Yj/U3XuMijTG
         YlYg==
X-Forwarded-Encrypted: i=2; AJvYcCXgCx2i4NH0LZJ3Qybca3G8qQwaU3w2ykGio8eVb79b0Smk5V8gmS4rBweZOVtNb53qkpuj5Q==@lfdr.de
X-Gm-Message-State: AOJu0Ywd0kA4SeGOovdij9tdis5gKuuWpOq3NwYBGXU+0Q+iv++dIhkP
	o7kp8Nuu1ahsFNBdHGjUdJD+WN/wwNPise+OsI7srHfiJmL0Hv7T
X-Google-Smtp-Source: AGHT+IHThFGADNHUkPFkuPkgBRvUcgn4+5xq1OCN16tCfnxadtKclgzg16Wr4QWEjn51L1wsccDSRQ==
X-Received: by 2002:a05:6e02:1486:b0:3a6:e297:500b with SMTP id e9e14a558f8ab-3a6f18d2ec3mr47938585ab.0.1731092513560;
        Fri, 08 Nov 2024 11:01:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:de05:0:b0:3a6:ca2e:6fc7 with SMTP id e9e14a558f8ab-3a6e815b896ls14199685ab.1.-pod-prod-01-us;
 Fri, 08 Nov 2024 11:01:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXSXIyY14PeMbBq2v/ilqGPYkroDq1udqBB/FHMaCJbYy+rB81PiNzmuNvP6T1rKHmzrF6qMQlCRS4=@googlegroups.com
X-Received: by 2002:a92:c264:0:b0:3a6:bb77:a362 with SMTP id e9e14a558f8ab-3a6f199037bmr48391375ab.4.1731092512373;
        Fri, 08 Nov 2024 11:01:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731092512; cv=none;
        d=google.com; s=arc-20240605;
        b=gmjzYI8NwCBjGylyDOjoRJRWTZPOm43atSyRDjnpJuvGZiHuZHjlTS6RVEiHm8Gv9Y
         qIj5qHcwJGRkSxKK/oIJOV2HGfipBmwpfu3F/BN2iJtZHt9qQHPXgZ6jAsOYK9v20GZC
         B+2wQwfwJEn4of2hwc/ZCdFHnlz4CLuTxsScZggKnKLY/ah3fzMbx9iF7H90Zsuwryns
         mwm9SLiae3Tc3Eu8BFGotj23CYqJXLSoWVBuxkhhGK7MIbWmbMuODRF4+B9p13wHDb0K
         s71qBqehtjzbz+V6LQXD7UIInI3M7JQW7gujll6gsP2Y6t7FMyG8kAxShU+jA+b79Boa
         wlCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+W8C/Wwov3G/nw10LNm7KNP0KgokEyn5THiu/DZKsdA=;
        fh=BiLYs9vVjiuEzcXh91wsIzFEmjAlfnOIIRfh9PacPoM=;
        b=VZfy+uh5juXylvTb3Sd2Dui/44Yh8WJRE1rbDKBP7/cw4ZboqiAvz2lsTJSSOrB3k9
         Lcx6V7LP0xBLlTRonriVczfbigmXWeyG5J1i+KSwOnW/WiZupZOTQdCheM9/x5Jq8A5J
         nGcpzgkwnvX8e/uxkha/hky/KlzdOUjDvDrczS+p3w2sfb37UA1DOGLEwlgmZr7uSJzV
         7bEvvYLTGBpgjg2D3oSWkNhfdGBMYQcY8e1HqxVTVBPMnniw/6QSzQtGl87yLFAJtNWT
         AzOMyEsKUUljdSchfRnMbCfZ2xXbEa+0A8hUZgBwJ9FuV0njlsnbOtwYJJrmwuD3v5qr
         FimA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=atUA5kVz;
       spf=pass (google.com: domain of srs0=eyrl=sd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=eyrL=SD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a6eacb9379si1884595ab.2.2024.11.08.11.01.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Nov 2024 11:01:52 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=eyrl=sd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 12280A44A39;
	Fri,  8 Nov 2024 18:59:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5DBFCC4CECD;
	Fri,  8 Nov 2024 19:01:51 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id E5DEBCE09E4; Fri,  8 Nov 2024 11:01:50 -0800 (PST)
Date: Fri, 8 Nov 2024 11:01:50 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org,
	cl@linux.com, iamjoonsoo.kim@lge.com, longman@redhat.com,
	penberg@kernel.org, rientjes@google.com, sfr@canb.auug.org.au
Subject: Re: [PATCH v3 0/4] scftorture: Avoid kfree from IRQ context.
Message-ID: <8c55831f-ca63-4ee5-9351-b8921562a35a@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20241108104217.3759904-1-bigeasy@linutronix.de>
 <Zy5OX5Wy0LsFPdjO@Boquns-Mac-mini.local>
 <18b237cf-d510-49bf-b21b-78f9cebd1e3d@paulmck-laptop>
 <20241108184510.O8w42_-e@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241108184510.O8w42_-e@linutronix.de>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=atUA5kVz;       spf=pass
 (google.com: domain of srs0=eyrl=sd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=eyrL=SD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Fri, Nov 08, 2024 at 07:45:10PM +0100, Sebastian Andrzej Siewior wrote:
> On 2024-11-08 10:33:29 [-0800], Paul E. McKenney wrote:
> > Sebastian, I am guessing that the Kconfig change exposing the bugs fixed
> > by your series is headed to mainline for the upcoming merge window?
> 
> Yes. It is in tip/locking/core.
> 
> > If so, I should of course push these in as well.
> 
> That would be nice ;)

Very well, I have started testing and if that goes well (as I expect
that it will), I will rebase them and put them into -next.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8c55831f-ca63-4ee5-9351-b8921562a35a%40paulmck-laptop.
