Return-Path: <kasan-dev+bncBDZ7JWMQ2EGBBSUHZ6GAMGQEWPBZ6LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BF5C45348F
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 15:44:27 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id i5-20020ac85c05000000b002ae12b76e64sf15750782qti.6
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 06:44:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637073866; cv=pass;
        d=google.com; s=arc-20160816;
        b=hwloqgtrgGpePh1gmGAe8niCMetkqeZ42fZHuY9gzKLL3frp/36bUeU9PlxyO+V5lf
         CfVG3Lg5LKa3h6FtyJhzl6ulEnHCzDdDN9gPQ1Q+cB9pnDaHx7H/zqhDjdRUA90c8Q15
         abqXv0VQp8lLG+7lnVMIwDygZhP2gLWNNplrtma0d1b1y63A1TR9af6FsBMb7Zak8q6c
         U7cYMjwfjW02nWzpqeephAFiCkMdvE0/3kuahi+BbS7cz2o1aGcB53/x5qU/QIztneVg
         Sksucfxl6R6XCWM/QjjLv0aNCP7EHOqmbn/dZs9slP8RH07WNoTIlin3T/yTasty/0Ka
         9TLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=S2wl3rLK843Iw2LTcBO8KPwFLAWqbkdAkWRz6yD8uPE=;
        b=Cf40789f1/XRR3VRUXjAXElAxB3ZdTlI6G7CeDoyDsGLhzX2IdjytCzVRsQFQ71Tlo
         C4eUrdQHRL4rpFWlkYp3R6/he4htMACbVhG3TQJQelOAsc8Jp27EoNa4ayoN9rzoa5gC
         s605ppLORvTXdaV7of57WWxkqgkoUhZWdVjtod5yFMzuIzn2O2XWTfYAuizWcs+7usIg
         ILW08Sn727ERCHnQ0Y7U0OzlwrL4hrm3yRrp5R5IUe5vywaL9ynz4ffO30GHxP6GChnT
         pbAWL9sxuGbQwa3taF3bOko8ya/Fir5Dug0z6tLyqdLuol4N4WklZ0ZPhIeHdey4Ee3R
         6JRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nH67jlwP;
       spf=pass (google.com: domain of acme@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=acme@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S2wl3rLK843Iw2LTcBO8KPwFLAWqbkdAkWRz6yD8uPE=;
        b=aP7KTxY9QtFmZeR+p4GckjUViM5jmCx2W42oC6AuDaN4Y1TocH0rTOyj6cT8Xo1YXA
         uWOz+488FdL5xRisLD5q7eZH+EuMb6sioVXEDmCEGpJjckkv2AsWEJ4vKGyI1A2ukIJw
         KSfo0sgFG55dX162Z9OiDtiTKxLPYundl0db/659T8UxtocVMa8okVr0CW3LlmInrKul
         Eog0mZYYZdYdKgPrDKYfkLWxpn0W3fTh13TSZfpUtSwKAV0NgNlUGIi6fNVTruNW0MbC
         P1FufOUYjR1ohwF2n620O2ffw3WQ4Q9bFSSUQX85u0m5lcQOCKzCNtTLF1DCoBgYO/Eg
         I7Tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=S2wl3rLK843Iw2LTcBO8KPwFLAWqbkdAkWRz6yD8uPE=;
        b=zFqtBrGYk6H/Z1aHGwcmT2YPOomBkOCbnLrTIAOs9gjGPyh1DhCMlykzHXoIhVVmc4
         MGl+RSNOvb23BhCN10csChvSTYF01ti8qTw+K/M7vR5Nc8i2VbsVKSGzwRBcO+IbBIML
         r2B+3j3pAWRfznf9WzalUA27Lin1oPlkoAwi30dwuZMMj8RWEvUjtytVfM2rbhYm0wXD
         gaCXI1LS2D072RKKejq21jq6GUon1IwAnSRBCLHWTddo5t0lRgoTiCQ5PDnLVEpNfWpu
         /LlH3ahzlqKCZ78k0N2dRR1SAH1QVGwjGk/5vwnVVDjFj9/P/Vqp7DVPEEkwsCx+r9ef
         fzgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532cR12FimgjHp+MFBeAWyxd9Tz31kgT6PL9lj2E5b9SHqy5h69A
	029ePc79l9S7ESwNTg4ooF0=
X-Google-Smtp-Source: ABdhPJx5EUKm/nsfFLnw1BrzJ9lZMmlL6zlH9hkiLYKaaecIWDKmgi7vqpCSo8aGoqFLgRmbM1rZSQ==
X-Received: by 2002:ac8:7f02:: with SMTP id f2mr7901131qtk.147.1637073866288;
        Tue, 16 Nov 2021 06:44:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:318e:: with SMTP id bi14ls5862063qkb.9.gmail; Tue,
 16 Nov 2021 06:44:25 -0800 (PST)
X-Received: by 2002:a05:620a:4312:: with SMTP id u18mr6595885qko.483.1637073865899;
        Tue, 16 Nov 2021 06:44:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637073865; cv=none;
        d=google.com; s=arc-20160816;
        b=Q22udQVSHgJzriU9Hp4GBKF0UCjT3GAWkP0BPUV/M3k2oYPgLhxFDLC+jma24hGzra
         sm+IrwMv0X8yFite6KZqTM5yQuBghorGIl8hiiRe9gJW5e1giWPr0im21OmGsOSBS3ly
         UovkPGP4z4gy9f3185/anTmoFdACUGhRtu5uugCK9Jz5rUHObl0Djl/HFAbZVPbQIBy1
         YV+Y/JpzyZOjLjtxdMiBmJx/luYXbYMuHB1eTa7hQrfvwDHqEEFyXJJKxcOp8wDeeVcJ
         gHywG9Mcmu2jOtfxu7AwQDH9wXDmhjaHzVLKzIU214ufNReJ6jGBkQmzqUIRRiKYv50I
         M0XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=absgpRNsO3Dr96NMYcbxz2Z1N47ktKOi06buUIwox1M=;
        b=nSEkbVdIboNbCrpi8lAllOkCpYPsTd8ldf+NBzCWhGKfxQKnHTuMnRCdAfGcqs6BDk
         2MoSab299TUcZJpcdH5qXqBMSk36mcuIZlywW12FMMIKzyIAzbCrns7Ejc8e459S0ywT
         BCcXMGRBlCZofoa+BKivoO+os2cEGgbg1hhBgZcQ21Ah46TtEeirh4EVsGATywsjHKbI
         U8arJZ/Zbjd7/McH6CKu7dpTDWOV5y9/4zE5iuq9dmjWuksosky5QQZe9/2YuicPzZU9
         Em6l/QjOPNS0bfSGIJ9JRpIh3IDmeQ0bCreQTF0BXmwwkbrUK0S7wQz+88kZ770Up/7l
         Hyig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nH67jlwP;
       spf=pass (google.com: domain of acme@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=acme@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y15si485359qkp.0.2021.11.16.06.44.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Nov 2021 06:44:25 -0800 (PST)
Received-SPF: pass (google.com: domain of acme@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id AC8F36140D;
	Tue, 16 Nov 2021 14:44:24 +0000 (UTC)
Received: by quaco.ghostprotocols.net (Postfix, from userid 1000)
	id 7924C4088E; Tue, 16 Nov 2021 11:44:21 -0300 (-03)
Date: Tue, 16 Nov 2021 11:44:21 -0300
From: Arnaldo Carvalho de Melo <acme@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Fabian Hemmer <copy@copy.sh>, Ian Rogers <irogers@google.com>,
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] perf test: Add basic stress test for sigtrap handling
Message-ID: <YZPDxTv7TwzYTOGU@kernel.org>
References: <20211115112822.4077224-1-elver@google.com>
 <YZOpSVOCXe0zWeRs@kernel.org>
 <YZO4zVusjQ+zu9PJ@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YZO4zVusjQ+zu9PJ@elver.google.com>
X-Url: http://acmel.wordpress.com
X-Original-Sender: acme@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nH67jlwP;       spf=pass
 (google.com: domain of acme@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=acme@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

Em Tue, Nov 16, 2021 at 02:57:33PM +0100, Marco Elver escreveu:
> On Tue, Nov 16, 2021 at 09:51AM -0300, Arnaldo Carvalho de Melo wrote:
> > Em Mon, Nov 15, 2021 at 12:28:23PM +0100, Marco Elver escreveu:
> > > Add basic stress test for sigtrap handling as a perf tool built-in test.
> > > This allows sanity checking the basic sigtrap functionality from within
> > > the perf tool.
> > 
> > Works as root:
> > 
> > [root@five ~]# perf test sigtrap
> > 73: Sigtrap                                                         : Ok
> > [root@five ~]
> > 
> > Not for !root:
> [...]
> > FAILED sys_perf_event_open(): Permission denied
> > test child finished with -1
> > ---- end ----
> > Sigtrap: FAILED!
> 
> Ah, that shouldn't be the case. It's missing exclude_kernel/hv, and this
> test should work just fine as non-root. Please squash the below as well.
> Let me know if you'd like a v2.
> 
> Ack for your change printing errors as well.

Squashed, thanks!

- Arnaldo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZPDxTv7TwzYTOGU%40kernel.org.
