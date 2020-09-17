Return-Path: <kasan-dev+bncBDDL3KWR4EBRB5NOR35QKGQEZCE7WNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 15B1326E1B8
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 19:06:00 +0200 (CEST)
Received: by mail-vs1-xe39.google.com with SMTP id g5sf693930vsg.14
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:06:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600362359; cv=pass;
        d=google.com; s=arc-20160816;
        b=MKHP4oXADMc7JVNi6YNV1K+GVhclugk80wpVNu7uKho6PP1Cs9TQb4ubHASrCIftEs
         DUqiAFHVS+77pwrrBWPBq01QxXP6b/7T1hAwENXziKWEGaEtv40zeOqDTXDXJ2h5fqn6
         jZAhLDAA+ImDNr9QTNgqTqySyYBi0WQ0TQhHhb2rFV1LM95T5mwChBGg1oBBGms44XmS
         hOQhrs6U/e3d7/SjcpgZSB4pAAhVWr8Ypx6N+/ILe1r03XIY5UXNMCMBXq/THZO6VxXr
         swjjeBZLKkAm6tHeeVSE3m8J5yvhncPPl3O8vz5YGak1R07ebBoe4224nSejeUlPwZPk
         8GuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=LK1sT7SLsNb0IQA/a494nT5+LAfR2czNKL5lAOMVTxs=;
        b=fb1ARhsfGl85PY0VrAhrqnHiBR9pjSxzxawrs39ki1f5ed/Dr55GOiSWx0jFFqydg4
         qu7ptBdbw9/u3UZH5p4QPhWMlFQGJXyhOyJSKbSvPFJkKa584f206OYT3PenUlqh0fY8
         kYbeCBbcPWZw9Ra7O10zzj1Tvj6BRTlANr8iaFcOVOI18J+lbUOCUymJVZ4LboQGwTE/
         CWCu3Z5+WFdh9lXBGTT1YnjPDqkqI/0dBPwE7cFxc7shTEtnaR5YtjkYOe4yGwIaRVuC
         jTMd0J20c1fUOlKyQABKJ9fE9S8Ku1TxcowJmvbXAB9mlSCJBNyVGai5YYbTeAwquvzE
         m6WQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LK1sT7SLsNb0IQA/a494nT5+LAfR2czNKL5lAOMVTxs=;
        b=Vl+1D3kazKS4cBLwN5IXpQiCPAvymHTCziRgli6KyFVCn71SKOYJMlgxyUlxMgDTrU
         6IfNbR1cJGyrJE8UUYh0V6/dglP3Au+YlcwGr9+Vstcr9PWHYiCRcMB2LD+eVfIhnK9b
         E0Asdu+03i6gDcr21nWRX5sk3a/flRXgxyg6OXcTC3MPGs9SezENHF6YJJtmZpRCPZK4
         eAoE6rKwX29DJz+LUSLkBU9Fpg5aza1kYZbGkHnwt6DG9Fro5LpUY66S2EslLkQpsToH
         zOwvSXrz/IilO2Tbof12Ous93xxFJruJQNizRbhHGcH4lyIwRWGKbg1TubPggZlI8iLi
         Q3dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LK1sT7SLsNb0IQA/a494nT5+LAfR2czNKL5lAOMVTxs=;
        b=Bd0uvYrSqDjuM1SFlxsPimAGUyOq/A83YdEjLBmohJrtqRhD7Aoj+lkDu7AODCRYBL
         x+EoYjwDX1Zjz8VJ0aqojYKu/KNKdqrAAh3HtyQXL7AAC++TR+lTY5Y+NNzqgBN2V661
         X+/dCpZefnUFvpPxMbMQdSjeqWDHu66tCi+kX3FX5RVeFm3ndG8SMt0vPKmw+Gvif2rb
         QtCGYF90r1hnurxZC2HOY6UoJ2ishclGP1DJ0RNMWlA5zIr7HtuEpXYfy5I+IEouXbhf
         WEiqt/vAQowABNRlypMG5kMxWJkTMskD8D3GkdWxkpQH4RvC5r1uHxqRQoWjByejeHBB
         cXfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532n7tCGwOJwtjtMfjGWeqfQQsp/iwOgsM31Jxmk/S7XT0pok4kq
	4b599fnsB/ufShddGPAb1lI=
X-Google-Smtp-Source: ABdhPJxW6+m0QsNRehQMHr3jqlz6CbI7dDfoW3cm54lfwfv4kBGgdWaklV8OlOqvUPa4G4QXQ3IAfw==
X-Received: by 2002:a67:1804:: with SMTP id 4mr8687678vsy.54.1600362357379;
        Thu, 17 Sep 2020 10:05:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:3813:: with SMTP id f19ls151106vka.9.gmail; Thu, 17 Sep
 2020 10:05:56 -0700 (PDT)
X-Received: by 2002:a1f:5a1d:: with SMTP id o29mr9133515vkb.13.1600362356754;
        Thu, 17 Sep 2020 10:05:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600362356; cv=none;
        d=google.com; s=arc-20160816;
        b=hRsjIIyb/d0TP3evsXOKH/Muz1jdBo3aBEcwU2H950LXNPVxmw3CDsF7Haccafe02D
         L0zXd+Pv0AHw4bfsIuF3aSY56LGQBYqMvjGVaaVZZ9TSD+Y+HVu0KDBrztZzVgJN9owl
         UB2kFV4/jt5M/B/XUAa+Fz13a/Mn+6XTMFAD1t/ykFFuH1T1B3wgmsQraDTlK1E+nOmT
         UoRfQeb2VdCojXWbIv+8a9ZdwbxH/85x34sqOVaPcfmokIfhDFwveTrHbbfg3vkqLnki
         FfmvnpNqQLmKYe6eZ0gehz0Yh6SoCwYYGfaFdUPPsc8DXLiWfVAtdHaCcJpP0zcckcyr
         p5Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=XwJFuGQ3YR0fyy9vIUbKrgVduA4H7z+T9vlMG4icGb0=;
        b=vkR3JoPETcMdgzCGBXeT+r+QwFYNuHyzsMZcC8erZdlMWcMoCMf6XtLYqIcResHRxk
         Tx1fXowv6bczrtjOwxhIpYbMHgngXqSBu1MnhVOc+3rm9FH0K0ozQYlRUls7Y+JY5wni
         iOi5vm2PutfqQcHxxEwvqu5TYt5Dp52E8AziOc0cj85FXwOxuay7x8yi4HmgiatPe08k
         UMhOj3n7rMlTDgn2HW3dn8/DLXK7uC9AQGhIq07+HNkBJW7IBS/Ro2T5Mldy3/0IBblm
         waBAgu8r9yyH9S2E16QOGAyhUyCxgbA56yuSXKEaqQNG0noiCGf4j1lF1F8/dpYqIq2K
         P95g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y65si24345vkf.1.2020.09.17.10.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 10:05:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4108E206A2;
	Thu, 17 Sep 2020 17:05:53 +0000 (UTC)
Date: Thu, 17 Sep 2020 18:05:50 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 23/37] arm64: kasan: Add arch layer for memory tagging
 helpers
Message-ID: <20200917170550.GN10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <b52bdc9fc7fd11bf3e0003c96855bb4c191cc4fa.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b52bdc9fc7fd11bf3e0003c96855bb4c191cc4fa.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 15, 2020 at 11:16:05PM +0200, Andrey Konovalov wrote:
> This patch add a set of arch_*() memory tagging helpers currently only
> defined for arm64 when hardware tag-based KASAN is enabled. These helpers
> will be used by KASAN runtime to implement the hardware tag-based mode.
> 
> The arch-level indirection level is introduced to simplify adding hardware
> tag-based KASAN support for other architectures in the future by defining
> the appropriate arch_*() macros.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917170550.GN10662%40gaia.
