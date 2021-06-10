Return-Path: <kasan-dev+bncBD6MT7EH5AARBUMPRGDAMGQEWVGVSHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 51DB83A31C9
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 19:11:46 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id q11-20020ac2510b0000b029030783d1d1f0sf813359lfb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 10:11:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623345106; cv=pass;
        d=google.com; s=arc-20160816;
        b=DQsn5ZalLM+bwVz35bbwT8bHWpUr7AoIzEBFCGny7PgZx2lKZ1m1xTGUdG1yJXDXcF
         /MSzdoJW/avQpCMPFk1UXwmJ9ekiIIZZUWBfe2Z8Sah4fqGJrGZSSVF7wWp3wj4qbsWd
         mW7O20Qy8zfg7wQmLEB1lD6sMNYEnyUsXRNDKb/i6Q8YUOAfku42UXh72pN9+p0VLj2d
         j2vfpBXg4aEtRUUYSdzitQCruNw1pv1Q0NYEZqXS9EkQHg8W7FzLMHc1uR+p35MNSlNF
         tgRW4itUXoYvFMAk2H53QpD4AxNUOPj3ZfYnRQoK942qFV0cMmSLtqP+dXieL3vklAYD
         kvng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=CIOC6Fpxm397BAFIIZYR/CexeVjOOvSb9joGaz3nXWU=;
        b=hFcm+1HRYL8I4T2hQnowtLFZAbCU5Nh6WhLBIK5lZ1t251CZYkD+VS7NCHRrMoyVwE
         ThXBFyIYwJ12P/23swRxtQJeaXV64BXNcPF2CxgelMmZPEQDgE+5GDD9aPpJ/KD6Cfoo
         DcbMCnFlyuKsZRZQQBInP44AXUfiUYlLyxtcD6FOkoILq6q6B9RZA/bV6Ez1n/bZ2dpA
         UbMc8+2/ZMnOQNPcHV4D6jnQ/tFnhdTEPeQVdtZ105fxveGYXuinZmFCRfG2z+Zu2Pod
         WuB4EzvnIce2nnvYGMriie5tNZMLUHqFOdtg1fM1/ySg9thK2VZqCz4BVouMaowbiRav
         mErQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.10 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:references:date:in-reply-to:message-id
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CIOC6Fpxm397BAFIIZYR/CexeVjOOvSb9joGaz3nXWU=;
        b=Wmx/NXy6MOwIPy3HPDpXr9Lm8dEIF54FCC+3GdcIq00AiVE2BWhaGKpPngqSDQSxLJ
         1of9aNTHJkRyQBRGQEwGnIo+Q/wb6ErrgwLv/CA88YFl6hWjmDmNS6Qsb18qSBlf8BOy
         LlcXdFBKzBqAA7hP+brksBV1nvTsfvq8SIIeBAKUl55EiEulvFMf769G+i4UDJ/n3mqW
         KclPQzCdtsbQN+cKA5JXgraTf/WoBBAAjqZBriTzW1ZP3wlphZ/rMBFEn0HE16UWWNR8
         585NeOeQZG9xwP07Vt/Mnd3SBWgVVL445hyIHUq4Nx87k8XSQLWxdtwZnLkf2IoVP9lf
         QpRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:references:date
         :in-reply-to:message-id:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CIOC6Fpxm397BAFIIZYR/CexeVjOOvSb9joGaz3nXWU=;
        b=Z6JH7k3prbRzEb9NqyL7EpfNNGEydoxFBZfYCJ8+LvqWphDpRBEtOEok5N4zWvRYES
         K9WPdVsK512VB7Ggc8LRB4cqMOmVVDmBWunaFFZZ3jzZCjuyejGZkQq3QuOfUZIO7hg8
         UIKvzlDNKVaQIM4b9g8mYPNfkGwjraT/F8knYq4QdfplJMiIQkO9yZJqymNRN2DqcQ7i
         /VCl+0yB9nsKTJ5E6oNTSoHiI/56ekz4FZ71T8UxFsXb2giJVZrzdQBjJRZiAIUwfSX5
         tRF7eBgVJ/1Ta1J6/uZYiXsybyK13XkgnwCh/E2RaTnd+DOk/BkXx2d0AhtFq+/qQ0mz
         zJrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ay/BqTLEIFtOua0DEp8oYfToOvtWkhJTdTHhMtV2Pmyos8nTc
	1ixfEKaqWNumkMHu+XAsweo=
X-Google-Smtp-Source: ABdhPJxsQ7AtXKVmco0EBtf3dZSBUyJN00RagOUAEeHIQq5fNlaaAbFRwFCqwDprDhOIRz35mjJ0EA==
X-Received: by 2002:a19:441a:: with SMTP id r26mr2711930lfa.104.1623345105868;
        Thu, 10 Jun 2021 10:11:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0e:: with SMTP id f14ls4763181lfv.3.gmail; Thu,
 10 Jun 2021 10:11:44 -0700 (PDT)
X-Received: by 2002:a05:6512:169b:: with SMTP id bu27mr2642613lfb.327.1623345104746;
        Thu, 10 Jun 2021 10:11:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623345104; cv=none;
        d=google.com; s=arc-20160816;
        b=p/XmhwHY2+hwzdkvxLSeHtjOP1OK7U6nq6Tu1dAaDB6c/9J9xN9v0NDM4lXGlUMKyh
         m6ETiE5c9bip5gFIsFAq/e2xTb0LtyzT16QFexkByiEIuyEyxfAik0zc7G3vvVZLSqOV
         bOJyJPwvwYDzyPnYkWPUyu1v5YIbzHUaoVCd2NqW84/8zorQimL8BfolZzbEB1co84RV
         RNVrxYcO9gFgK79WMAigQkI5LLMYIVPwHDcxFl6wrFaOAE0Pi9NgkTTWZuojaPxXEnR4
         iw+YTB2Z7t03i3baagi0Jd9bDNTPaWmSuc+zHlisqD6VdfjiI83yiZvcLkW/jV92n62o
         2mvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from;
        bh=E64XrvicBITmlwSSNw4R3jhU4QKDo8lqDRvph+vTRFo=;
        b=bcBVmKiUB+Z6o2GNP7FVTKWUL3EOS9mu+CI0E1AY4FFoVgMCVEF9KC0KKi0bcipzWO
         CIVnFiI0n4ENBNf7p13qGirsMUpDpH1xhJMPqILt3oH/EG6nPcHHyspaSyiI806p7MoY
         +Nn6fjcqYKrP4SWG1+bqjTsQQDveXSN8e8ICnr+rqyt1CVOg3RMGf1rg5m6kQ9xj3gkC
         mlfRglbGI/vb4VlefJiAuMgSDBkhgLvVOuKl637OAaVoLDsFCatFEQE6qpgDK5MJC9G/
         2JFRmCFVR7TSb4QP29bW+e7aftil3zki+99gFlozc5BLkrvf1tBNvlVNSI4c39aXQP/s
         0KVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.10 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
Received: from mail-out.m-online.net (mail-out.m-online.net. [212.18.0.10])
        by gmr-mx.google.com with ESMTPS id a21si158151lfl.10.2021.06.10.10.11.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Jun 2021 10:11:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.10 as permitted sender) client-ip=212.18.0.10;
Received: from frontend01.mail.m-online.net (unknown [192.168.8.182])
	by mail-out.m-online.net (Postfix) with ESMTP id 4G19W10RlZz1s3pn;
	Thu, 10 Jun 2021 19:11:41 +0200 (CEST)
Received: from localhost (dynscan1.mnet-online.de [192.168.6.70])
	by mail.m-online.net (Postfix) with ESMTP id 4G19W05vXlz1qr46;
	Thu, 10 Jun 2021 19:11:40 +0200 (CEST)
X-Virus-Scanned: amavisd-new at mnet-online.de
Received: from mail.mnet-online.de ([192.168.8.182])
	by localhost (dynscan1.mail.m-online.net [192.168.6.70]) (amavisd-new, port 10024)
	with ESMTP id jeCLGjcaYHdm; Thu, 10 Jun 2021 19:11:39 +0200 (CEST)
X-Auth-Info: tTD/jRVROUkeu+CRr/dYNOPU0H88WKfaxb3K8PZ1hjL42mqxsQYgvXW0pSyHF28S
Received: from igel.home (ppp-46-244-161-203.dynamic.mnet-online.de [46.244.161.203])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.mnet-online.de (Postfix) with ESMTPSA;
	Thu, 10 Jun 2021 19:11:39 +0200 (CEST)
Received: by igel.home (Postfix, from userid 1000)
	id 8C8602C36A1; Thu, 10 Jun 2021 19:11:38 +0200 (CEST)
From: Andreas Schwab <schwab@linux-m68k.org>
To: Guenter Roeck <linux@roeck-us.net>
Cc: Alex Ghiti <alex@ghiti.fr>,  Palmer Dabbelt <palmer@dabbelt.com>,
  corbet@lwn.net,  Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu,  Arnd Bergmann <arnd@arndb.de>,
  aryabinin@virtuozzo.com,  glider@google.com,  dvyukov@google.com,
  linux-doc@vger.kernel.org,  linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org,  kasan-dev@googlegroups.com,
  linux-arch@vger.kernel.org,  linux-mm@kvack.org
Subject: Re: [PATCH v5 1/3] riscv: Move kernel mapping outside of linear
 mapping
References: <mhng-90fff6bd-5a70-4927-98c1-a515a7448e71@palmerdabbelt-glaptop>
	<76353fc0-f734-db47-0d0c-f0f379763aa0@ghiti.fr>
	<a58c4616-572f-4a0b-2ce9-fd00735843be@ghiti.fr>
	<7b647da1-b3aa-287f-7ca8-3b44c5661cb8@ghiti.fr>
	<87fsxphdx0.fsf@igel.home> <20210610171025.GA3861769@roeck-us.net>
X-Yow: There's a little picture of ED MCMAHON doing BAD THINGS to JOAN RIVERS
 in a $200,000 MALIBU BEACH HOUSE!!
Date: Thu, 10 Jun 2021 19:11:38 +0200
In-Reply-To: <20210610171025.GA3861769@roeck-us.net> (Guenter Roeck's message
	of "Thu, 10 Jun 2021 10:10:25 -0700")
Message-ID: <87bl8dhcfp.fsf@igel.home>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: schwab@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of whitebox@nefkom.net designates 212.18.0.10 as
 permitted sender) smtp.mailfrom=whitebox@nefkom.net
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

On Jun 10 2021, Guenter Roeck wrote:

> On Thu, Jun 10, 2021 at 06:39:39PM +0200, Andreas Schwab wrote:
>> On Apr 18 2021, Alex Ghiti wrote:
>> 
>> > To sum up, there are 3 patches that fix this series:
>> >
>> > https://patchwork.kernel.org/project/linux-riscv/patch/20210415110426.2238-1-alex@ghiti.fr/
>> >
>> > https://patchwork.kernel.org/project/linux-riscv/patch/20210417172159.32085-1-alex@ghiti.fr/
>> >
>> > https://patchwork.kernel.org/project/linux-riscv/patch/20210418112856.15078-1-alex@ghiti.fr/
>> 
>> Has this been fixed yet?  Booting is still broken here.
>> 
>
> In -next ?

No, -rc5.

Andreas.

-- 
Andreas Schwab, schwab@linux-m68k.org
GPG Key fingerprint = 7578 EB47 D4E5 4D69 2510  2552 DF73 E780 A9DA AEC1
"And now for something completely different."

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87bl8dhcfp.fsf%40igel.home.
