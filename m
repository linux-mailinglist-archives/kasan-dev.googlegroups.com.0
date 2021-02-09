Return-Path: <kasan-dev+bncBDDL3KWR4EBRB2HTRGAQMGQECTZ2WMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 831D4314E93
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 13:02:49 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id k73sf9949599otk.10
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 04:02:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612872168; cv=pass;
        d=google.com; s=arc-20160816;
        b=MSoI8nz6LSbWDLhBFxozIL2a2ZA6bFsudDKf0UsqFaE1YUFuQe2O5xEX2FaXiE/Ctl
         etSfobwyx3W5hqwWtoPp5z8PuvL8QGShGHLMgA82lAKxoLayu2HiClWslFwJ6LZ5qt+U
         AnQWKGIIGW6VWR3KKgtFr+60YfH+SrMYrNG9NF/iMNa9ncZe34TyXa0ThuwcfST5T1WZ
         pT665iclMj0BFL2h20e/6f48DSRJs5s2jjG99Iau/ztJt9xzSHwPVQC1uOyC391pf6fX
         rJXLow0ZLLg0h+OfBBptPKPhbArJgXxY51cbYFbVTXSXsFZrlPexCphp3JweymTuUDoB
         JxsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=JCXX8iCVd2WyDFWGgPpYU35Ah4eEF39V3/lENc9pZqg=;
        b=W1O4V7SDEu4OzZY9uqcduw9/UU2GS7m4Dr4ygm9ywLe4bt/IeKjQJ4TJHjqqDDOpvA
         2P218x7LRoptkgaBOuzVsVHf7hsUUbC7+Rk7G/TCEu3z0UVxWv8mTx7oJbp2kxGZFKhv
         AnlwGELtjJbiew0b2GGMSVEeJTX4B08YqlYG1onuU6HuJ0QwHHRotDIhkA7lkrUdv1s/
         p9vXsXAzWsd15q8rDtHeFFJpSykgyAA5aMcW2FD0ZyyN+BLW/fKWoqmRlvNPpMrLT9Ov
         2AGpSuSqA4Za+P+0IFwNoI7IdXC55/N36ehbdTFp4nfRkwJGmOcngdJTclusMh0mKkFb
         oV8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JCXX8iCVd2WyDFWGgPpYU35Ah4eEF39V3/lENc9pZqg=;
        b=PO3zQWIkMjCrIGE66YxiUKtxQikYuvLnMS7+TJZVjYpgGtJOygd0G8OoQyqzIr/MHb
         V1FrdEnijIGNBT09oounbOepfb8NEoBiWgqiwDPWIpa/AoJL5U23pgoE75SsmEXitzMe
         Qzy/2hM20BGVrUMqrApg/4dxx3tOtWHgYOxqMwkYivlXdEOETwd5NJPQ3aSnjU4WKqGV
         16gGwl/1Xw+epFd+kRhInakrXOkpUAOjhODzhOLpE4a1N+XdlO1Zu47/UlzeoEbh4MDF
         I2MpUVZ/5h9Bk7j69GbSS2SAta4WN8uxB6SjGGgHoiLl+25yWeuReiGMB3A1y2/lPBMT
         S5mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JCXX8iCVd2WyDFWGgPpYU35Ah4eEF39V3/lENc9pZqg=;
        b=knaElfB+Cr3yy0DyL00nW3AZ6a+OEnokRq/73K7AdK/ppZgi/nCThR/L213ydAjhiA
         fhu599FSa5vAUYoUk6s8aCjn1rHa4/xUw6HC7tOAHNxBORawYn1e67aUZrBvp8ZlWSZl
         0dtX1SbKaJTQYw7nQBR1ZcIYiNaHzr7FuaoVNjIwM5pYBxKsAWLhEPEwx2dHke2oYV4T
         fcneZbrOnzQqICBq/uCNmPV44XgNlbpfuAsHc/hnnqGhXLZQk+SM6qDPv+w349UN2Ykq
         fsi1wcAeappSyywkySUGMJpoREOZeFd1n1z92Me33Ip588gYnnuln7VzYzDOm0tvZwBc
         Rtgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53234oDkW8bkxJmJzWRQqRkb8sdv77A9lCPgYoVA+SxryS5YAFsI
	UNDhbMAgmFMRYtlIzOtJNno=
X-Google-Smtp-Source: ABdhPJxb764vaz2nvXE1bTxq8InojjAxi+eq0klciiwjTNwRvyvy0oV0oRlKkcLnO5RPbpW5Bfwk2Q==
X-Received: by 2002:a9d:578a:: with SMTP id q10mr9203147oth.114.1612872168487;
        Tue, 09 Feb 2021 04:02:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:c5:: with SMTP id x5ls836311oto.7.gmail; Tue, 09
 Feb 2021 04:02:48 -0800 (PST)
X-Received: by 2002:a9d:7f86:: with SMTP id t6mr13049456otp.362.1612872168083;
        Tue, 09 Feb 2021 04:02:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612872168; cv=none;
        d=google.com; s=arc-20160816;
        b=X6cPKx2iIpZDyo5koAxQJsKUJyIqG5slNbbXq/Cw0ArLIkjcs1yOKAPypFQ9+lEcga
         Y/9R3vTu4hjkIQaW/qf9Ied4XUOVauTy0W07XbXnyK6hcqXv7UoJXGenCfg04uJAxhcY
         hy6MokmgtEXnM0uLJT8zb32/vFaTI2hByfLsCEZ+5fyyGSkNfNqmogJHKxEtdjCM1aH4
         iVSJmfhkhv+giFzhENl9WPSd9gIPb61HGZPGHSOHFIVDdHcsu1UdIRZ8BDdJp1pMFjXb
         VL3d+fe/YdHqMSO8WLLIsLgBOiPyfhUQK7mVhd/w7/eW/4xfFKItjsp45KAxaPFV219h
         d1QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=z9doR+9vOK9RlBmYZzsCIcnjA2plivTcsj2FzX3H/J8=;
        b=y62mXalXzIdbAmemsO5+DXEYvwekn3uESeY7fyE/sFKCYDXrsCprszmjnu4NgIGr7P
         rTAnV9l3K/7cBpLwyolKGjXnAIY71JhoOYDhHUoODEpw8JmeMN6PX/Q9C7ovvOgLKU0F
         0vMGF4IQQsmB1wfHNh+VQCrzb2QTrRPgKebvjhZwY9ol8NQIVuNp6R+01J5nuuhgRR3N
         enV+4CWSHYtqA8qZxgjwDjkLyWJ4j1idw89wefaFcpFTosPLghBaefluW4lkucsWbQue
         4kJhDeWlcTuZkbEKokNoDSbupyOro9XGJp2od0kSHUhXMJCJ8SID5XjnGER2kJr+YiTW
         1MVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y192si478954ooa.1.2021.02.09.04.02.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Feb 2021 04:02:48 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9C57E64DB1;
	Tue,  9 Feb 2021 12:02:44 +0000 (UTC)
Date: Tue, 9 Feb 2021 12:02:42 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v12 7/7] kasan: don't run tests in async mode
Message-ID: <20210209120241.GF1435@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-8-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210208165617.9977-8-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Feb 08, 2021 at 04:56:17PM +0000, Vincenzo Frascino wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Asynchronous KASAN mode doesn't guarantee that a tag fault will be
> detected immediately and causes tests to fail. Forbid running them
> in asynchronous mode.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

That's missing your SoB.

> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 7285dcf9fcc1..f82d9630cae1 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -51,6 +51,10 @@ static int kasan_test_init(struct kunit *test)
>  		kunit_err(test, "can't run KASAN tests with KASAN disabled");
>  		return -1;
>  	}
> +	if (kasan_flag_async) {
> +		kunit_err(test, "can't run KASAN tests in async mode");
> +		return -1;
> +	}
>  
>  	multishot = kasan_save_enable_multi_shot();
>  	hw_set_tagging_report_once(false);

I think we can still run the kasan tests in async mode if we check the
TFSR_EL1 at the end of each test by calling mte_check_tfsr_exit().

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210209120241.GF1435%40arm.com.
