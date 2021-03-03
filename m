Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBGV37WAQMGQE43SCRJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BC3E32B65E
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 10:57:47 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id p136sf26279604ybc.21
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 01:57:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614765466; cv=pass;
        d=google.com; s=arc-20160816;
        b=kiHQMehbFfb9rS9EV7NfGWdJcnsG+1mPgm2mTEL7t/oxWcMxa1MZFepgU0XMaichjk
         bTR9o4EYNmgTHaoW5jQWnlVf8xrwhtcVnixZt0q1SOKuTWqSGR66ATmiVRFygzqV2fTL
         BLqGzZGtBMuTLPb7nXarGmDUihvg5IN1jU5PmF0tomn8XpzGIuhRV+m3jMX9CcCxyBLj
         DBYL+Gx8YtC8GQpmghqjSR+inn82XoMUMfaJ/DrCgf3r6DdqZcCsgE8k3fqSWOpfttuv
         NAReE+lYYYozhOjnhHSlzvTHsm4iG+XtoP6xx11roeLgs6nmRv74qTh11nolob6zVec4
         TZvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jO8i0h1kv6mzqr09kCgPW6Dmu3m3AcVnOF6MD63ra4U=;
        b=AUnnXC6M487ORqFBYSSI38LKFPUewqUAbxjH7lvl/HHATAL2aZC49L/s+6MNtM44Vy
         d37BIu5fOIRxTJfgzxyCnEHRwWamWXtxpyDcU70kYU813bovQUVay9XVNPBvcTsMJwRO
         VpVJzc4I/8y5NGZiFo9W1DlfmW0CAHgj6yHgdoGDgzwZp5foWdAw7/N6Inn1CjpAosit
         dzuq3RUS4QEExSOUAbiLChUaejbGKz6A6aKAeMahjES2VO/J1g+5JYUsdOk9eyAJ07Za
         Xjnx60IY+K2xJrqDsUZIiVcuhzmODqmysDTlo+CzPzpGP96g/ZF3OfyzYFjC+GPlwYkO
         6/Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=R69mIedG;
       spf=pass (google.com: domain of srs0=ywzk=ib=linuxfoundation.org=gregkh@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ywzk=IB=linuxfoundation.org=gregkh@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jO8i0h1kv6mzqr09kCgPW6Dmu3m3AcVnOF6MD63ra4U=;
        b=MMudhu/M+f/EzKm6OA/hFZIs7f0wkzE/20ISGIDuUUBdtsU/jVlfFamSyrz/LQpU6E
         DvCyaXQtmSv88pA/vblklYzxqEO059fGeQQvO/wwiCOPYe08kiBk53dh6wdCe6fuHPZK
         IDkZky2OitFYThmIt41Djs7/GHdZj1UNq5P/3TjpKPpv68SNO6SRBpIGbrv2rVnCB+Tg
         KMi3pP3eidp7MR7fRWF0gwg3cqUo1QfxkFUTuuUcw9Pb/z95V1ub9YY+xS3ksYB32Lta
         /4+WTSyYFffFtYNFtpxt9bOUANpFJvCYIwHegfrqmcupWjx7eubUcqUJ08vkHJd+4TNk
         0uPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jO8i0h1kv6mzqr09kCgPW6Dmu3m3AcVnOF6MD63ra4U=;
        b=JzWDLpB/VcxgdT7NcFqy7cAexpe/P+n36tyKclxD9H4pXk6FaU62dtHeKSEOm4hau+
         wnaLSWY8Oc6iqflO7cOcV0K6xIWkWwbC/BgfqEdIZEGBtIylL1dzMjAxNul02VkTxyry
         Rr93xWsTX3/zHI8V4Td4ct2wuQfI7JbWfIBxv6xit4qO04EhbjHOR/ZLFER/D8BDXhFt
         tSwXH97rif+AexxkXDDxH4qhDUfJeqruIxadLLM4WyfI3HMY7tW0rG2iN+QULy4/9SPh
         /ZvB4yaVLRDay/UC7nkmB22Q6fZzXjNmPEq9WZhQbFl1i358tzWt5L9c/C7xRYIe/Nmv
         Gy1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532jmFJhiv5VEt8Le3W+gVsRz4P/G0WZXAJRcdYbYfcZ7lXLSZtQ
	U2+sym4X2ia3f/AasVm85y0=
X-Google-Smtp-Source: ABdhPJwmHnrDChg2OZKybLBXMM1PiHOjUfGRksZX/uDX2FWrAApOANoXHz2oblR+zyDGFZQFSNx4PQ==
X-Received: by 2002:a25:6e02:: with SMTP id j2mr36485761ybc.247.1614765466204;
        Wed, 03 Mar 2021 01:57:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7807:: with SMTP id t7ls833632ybc.10.gmail; Wed, 03 Mar
 2021 01:57:45 -0800 (PST)
X-Received: by 2002:a25:23c6:: with SMTP id j189mr36640205ybj.211.1614765465704;
        Wed, 03 Mar 2021 01:57:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614765465; cv=none;
        d=google.com; s=arc-20160816;
        b=UUo7BW2qE+YSEt5bqGQcjyLEgGA7NSLghRckbSjWvEuEhOhjWPSiI3LxxuMb6QxZI9
         iPCHtERCjtIEThJ7Jwe4k8wshsWj35BD51HNcqkudsqYnU1I9kBBRblRllovg1kPjoUT
         nKw8NJkdCvz/FqXeKgcn3EL4xXjPUIT+79TRA4kxbsNnORXKPRPdo20azp9S0qzrAcgZ
         C0ZjdY4KWif8MH9XFVYo90494RanG2CyGeYq5p+SQU8IMoSc9zKFe/eaIQ6nbPzS1+Sm
         wJqpL23BwxegAzPcF9URMK/ftDoL8YgG8rDCoIBa5D8xNDWQ9HIxbvLEXucbjjbSLhGa
         Ovcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=TPOKksZPqHtf/59t33ZFY1fVS4UP6MXyD1fempJlKQ0=;
        b=pYWvdFYSAck1SgSnYunSnV06VHQnCmsj+CSaGw69/ZnefWc8lGWlgKa686jokGwGs3
         3fxyuSy2vL4tFXHAk6o4T6q9mWvP310A0C7ePNZIZyt3ytTV+DqtBE49esIzRhPNdh4i
         xwN50fqvB4KwJO0ZSZxHLe8mEOjidElpywTXuo72XZjxgJaq0aYaF4Hi7AruW4x9OG73
         OFmrNQLvH7DjxN94023P/k+AO/bLS+7PAzgxabq+Q7XvbsTurlb0mdyBtzhaffE0MKTy
         x3C+8pEBb52SntSoTLy9ZGjvT4wt6tRC5mV0Gm8Wdq+UllWA7pIRqQP+4yuDwInH7dbK
         r3uQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=R69mIedG;
       spf=pass (google.com: domain of srs0=ywzk=ib=linuxfoundation.org=gregkh@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ywzk=IB=linuxfoundation.org=gregkh@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e143si1515452ybb.5.2021.03.03.01.57.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 01:57:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ywzk=ib=linuxfoundation.org=gregkh@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id BDA1F64EE6;
	Wed,  3 Mar 2021 09:57:43 +0000 (UTC)
Date: Wed, 3 Mar 2021 10:57:41 +0100
From: Greg KH <gregkh@linuxfoundation.org>
To: Marco Elver <elver@google.com>
Cc: rafael@kernel.org, paulmck@kernel.org, dvyukov@google.com,
	glider@google.com, andreyknvl@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	stable <stable@vger.kernel.org>
Subject: Re: [PATCH] kcsan, debugfs: Move debugfs file creation out of early
 init
Message-ID: <YD9dld26cz0RWHg7@kroah.com>
References: <20210303093845.2743309-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210303093845.2743309-1-elver@google.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=R69mIedG;       spf=pass
 (google.com: domain of srs0=ywzk=ib=linuxfoundation.org=gregkh@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ywzk=IB=linuxfoundation.org=gregkh@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Wed, Mar 03, 2021 at 10:38:45AM +0100, Marco Elver wrote:
> Commit 56348560d495 ("debugfs: do not attempt to create a new file
> before the filesystem is initalized") forbids creating new debugfs files
> until debugfs is fully initialized. This breaks KCSAN's debugfs file
> creation, which happened at the end of __init().

How did it "break" it?  The files shouldn't have actually been created,
right?

> There is no reason to create the debugfs file during early
> initialization. Therefore, move it into a late_initcall() callback.
> 
> Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> Cc: "Rafael J. Wysocki" <rafael@kernel.org>
> Cc: stable <stable@vger.kernel.org>
> Fixes: 56348560d495 ("debugfs: do not attempt to create a new file before the filesystem is initalized")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> I've marked this for 'stable', since 56348560d495 is also intended for
> stable, and would subsequently break KCSAN in all stable kernels where
> KCSAN is available (since 5.8).

No objection from me, just odd that this actually fixes anything :)

Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YD9dld26cz0RWHg7%40kroah.com.
