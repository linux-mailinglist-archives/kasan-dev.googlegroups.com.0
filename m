Return-Path: <kasan-dev+bncBDBK55H2UQKRB54QYSTAMGQEVB5I6FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id CCF657728A0
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 17:06:32 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-3f5df65fa35sf25960525e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 08:06:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691420792; cv=pass;
        d=google.com; s=arc-20160816;
        b=DKBQgR9A9LX/f9u22WrlwkkK4YlAF8UDkBFQsV4f3Y1Xzck6oDh/ysiIPRpM+asHx0
         T295n6gbbgkN6NeG9LLNmaLcAXLz5ry2dhcjN6HqPoNzpXeVg75RazvTD1nndICOWWNT
         GOxeoDlqyadPFxrrjFoJDiHXPo4WnS73lpDzR7LNGB3Y2dkX+aCwxd3BwL5WSgKQrxlD
         yLjP+pfXuDhtgmeXEovG8BkgnSPEKu9DgujjwQ730TEDBlxYf7jNmgdN4oTkMtkBKmL5
         +4kHW94c+3JB2HaxGbWCTAcRaxrJRXUuBrlA1/XnIIFvGuGNN0340DMTgu460IelGY8S
         U2cA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gzhkUHCa70BE0qkIoGjnMzjuRiMG9WP+EauebhRT5Co=;
        fh=3T48dBajmuzuZqkU7TBWQfXJzDUTzUOImv3KVSY0ZcY=;
        b=BD60JmdF5RtaYup88LzeQMTlBw6Vt1WYFsm/k0XjH8bsmTzpWbMLI5oBnLxE1aLxp2
         3ZYVyN2swaZTN1D46R9I/J97W3K7id7V9X0TSXO1OoJQ+5pODMFfMQrvb52Qnwq9y1K2
         +e7CtJw5Gz4Y6Q4zxPGudufm5f72Xb68z1ExnIWDpTXRr8v578aWCdbiZoj2kYUYGXrc
         gqIdgK5p2T+Lf8Xkhrqt1XjJHpqppfoK3q/2QG+2hXOiDRRqmH9nu7BfyAB3NpBls6k2
         TNqiiqFBm8QqSGe2bka/BJk/T31KSTvVz5do8pMlE2ANUhsGuYmeba1pN6AvciNpXG3y
         BnZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=L84dIEOG;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691420792; x=1692025592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gzhkUHCa70BE0qkIoGjnMzjuRiMG9WP+EauebhRT5Co=;
        b=pDANs3Brt6RXk/MdK1HBGNuKXd3bsLsEXnjeiLacgZKxnOesfQTe76cDN1PAQXYL/V
         eDNH5P0H6bKami9NmAEJ4B2K9QH3+kKbpmkL+BIzLwnWxmwkb5HNa8f1jz/nHOfSAw6J
         4dDS1dU5Qiaa52gx7NY8nPbF9q31mItjpJDa6rfiRBs5a/kzrti98gd50DEL5fQbewDm
         +QXJpvg/ikOWvLnKGbHLbGbRFuZPUnLDigG+ROHmZo+jSW1kaHMoTvyqMhxYrmVtw8Dg
         Hv+gTAKeyvVXwrXLGPxEV5i3bGzM9SEEhcyXck9bVj55XYuXJaDQLZbL7RGGv7wFr+lt
         pzNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691420792; x=1692025592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gzhkUHCa70BE0qkIoGjnMzjuRiMG9WP+EauebhRT5Co=;
        b=krhnOclAm3hOOF6dgJL11pohWVMU68Va0XssLVI5dTeZim+rUiGV+6TrsQZYOvNrEY
         EQAg9h9baZQsQdEL1wKp+U+yn7BeVrmBv3nR3WdG2SsA7X14Lc32Kv1/0AHm3z+cvV/5
         IglIE7qHp0IRbRXTUtqq0NsfLY3V+FjVMtclSF2OcEnzTex08zd8iqahhFPMnxH0upgU
         vzAMzIwaFUTFgdidb1LnbVF+ucG0MP27wTCTH6UZ50djNXxH0/bOFp7QOPuO+JRpg+T6
         1Pog49B4QbuS+LRCbqbeBM+qZj/dIyZtVh/TuCLWYg/DevoY0L6ey+3urNcJJGmyDAhC
         IcjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyU9NrU9vnG1h+83cAQ3pdDS9Pgy9rm+KY1o1x12XMxXtRC5nfH
	7tsJi4M7Ji2LA3bkh9knWCk=
X-Google-Smtp-Source: AGHT+IEEnFtMQtn9PKCsRGiGsamZqXvmqbGcjIZEn4ga7yk6uu7dM2KKMSDRp3Fu9R53uR6FNxY4UQ==
X-Received: by 2002:a1c:7c05:0:b0:3fe:1923:2c3 with SMTP id x5-20020a1c7c05000000b003fe192302c3mr6168417wmc.30.1691420791942;
        Mon, 07 Aug 2023 08:06:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e742:0:b0:315:9d1e:ee24 with SMTP id c2-20020adfe742000000b003159d1eee24ls751081wrn.0.-pod-prod-06-eu;
 Mon, 07 Aug 2023 08:06:29 -0700 (PDT)
X-Received: by 2002:a5d:5487:0:b0:314:1ca4:dbd9 with SMTP id h7-20020a5d5487000000b003141ca4dbd9mr5420132wrv.27.1691420789839;
        Mon, 07 Aug 2023 08:06:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691420789; cv=none;
        d=google.com; s=arc-20160816;
        b=N5sLbY+qPaRq7OGoBrjSIhFEte42xp9zI1+yFiB+CDvf7xVPfA95Gp1RMokqwp7PBM
         PaffK+oGZ77Ry+oEJC85krOUOK+HAPz7lbwpwLp/sN/ViF8deWhiK/XL8zRoyyxuYR2O
         gasNPPivif5ccwKd+ozUsRW6QVkO5wezDD+f1mVB2HAW1Z5+kovms/ka0Pj/qS+I5pKH
         KScPmaO0wJJcmRJiOKbbNI4/+dcF1PDzyKaPYPCew6kjHb4LFpXVuROjv+YQ9P51vRlo
         z/+M9OFS0e4YrRddygk03z0XiEJv4MpvKU661B+LzIvUO6Wsl4AGmf2UiWR187AUbp3w
         GBOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zOz2Sl6sETEspUjEfHGN0Doq9IKMqDh9com1ZKQ2ccQ=;
        fh=3T48dBajmuzuZqkU7TBWQfXJzDUTzUOImv3KVSY0ZcY=;
        b=rS0bnjgcGdNiGGUp5+88AeCl6h2Eu03t/GkwvsI9r7lZoqHcixSUH1Zhjee7DFIzPI
         KO1hjmwuNPRovrlUEvesqJ+M7ZFC6+DAVJcc4P2OnKBQOGV+dqWgHGEDANvIlt5JEX5y
         fBDq95aI/d1ifBZux/TdEQQxmpK/ii5ZCOLjm9zHS4cUQNJCkqsIjKAzm0iclIifYDvR
         jyTMzh9nxIw8EgK9hURFUuKW/uj+e0JqFHbymBLTxqcX+op3xLxU+WThU5pzmJv4LaTj
         5q0ZW+6ErnmqOG8BwpOSl3q2YzwnPe5iWsuhvRPvMPZ7+vreJmuo9wyqF1aiG/rIS2JN
         nPOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=L84dIEOG;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id l27-20020a05600c1d1b00b003fe275df1c4si620530wms.0.2023.08.07.08.06.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Aug 2023 08:06:29 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1qT1oI-003w69-37;
	Mon, 07 Aug 2023 15:06:19 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 6B7E7300473;
	Mon,  7 Aug 2023 17:06:17 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 4840C2028F056; Mon,  7 Aug 2023 17:06:17 +0200 (CEST)
Date: Mon, 7 Aug 2023 17:06:17 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Florian Weimer <fweimer@redhat.com>
Cc: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Kees Cook <keescook@chromium.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Mark Rutland <mark.rutland@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>, Marc Zyngier <maz@kernel.org>,
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
Subject: Re: [PATCH v2 1/3] compiler_types: Introduce the Clang
 __preserve_most function attribute
Message-ID: <20230807150617.GB569857@hirez.programming.kicks-ass.net>
References: <20230804090621.400-1-elver@google.com>
 <87il9rgjvw.fsf@oldenburg.str.redhat.com>
 <CANpmjNN4h2+i3LUG__GHha849PZ3jK=mBoFQWpSz4jffXB4wrw@mail.gmail.com>
 <87pm3zf2qi.fsf@oldenburg.str.redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87pm3zf2qi.fsf@oldenburg.str.redhat.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=L84dIEOG;
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

On Mon, Aug 07, 2023 at 02:36:53PM +0200, Florian Weimer wrote:

> I think the GCC vs Clang thing is expected to work today, isn't it?
> Using the Clang-based BPF tools with a GCC-compiled kernel requires a
> matching ABI.

Nope, all bets are off. There is no module ABI, in the widest possible
sense.

There's all sorts of subtle breakage, I don't remember the exact
details, but IIRC building the kernel with a compiler that has
asm-goto-output and modules with a compiler that doesn't have it gets
you fireworks.

We absolutely do even bother tracking any of this.

There's also things like GCC plugins, they can randomly (literally in
the case of struct randomization) change things around that isn't
compatible with what the other compiler does -- or perhaps even a later
version of the same compiler.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230807150617.GB569857%40hirez.programming.kicks-ass.net.
