Return-Path: <kasan-dev+bncBDIPVEX3QUMRBDWS4G3AMGQE5OMVI6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AB7696BF97
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 16:05:04 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2da8c2eeecasf927131a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2024 07:05:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725458703; cv=pass;
        d=google.com; s=arc-20240605;
        b=R14Hq8mqKezAFjVNZ2xbDeJtZEu12QtbrZ0frury8qV9ch6EsRJ04zJcUsiREA5dWX
         FMf7ANFDousA4+mGVM4TKF0LvhvEhTyTRK2I0nmu2HQMkPSTQ6QpBKiwcqzJLXS/qc4l
         tZsLsbc2csURjw24MGxmq+5nNRhSVXdjgP6VTi+HE1lok5rPlkJMimw2YMgQ72zKHXBO
         /a6hn+XRUdykECvkuBwrzrgJl96K16BrM0iC4wLPYk69l4hGhBzWJ+TAbzXXq0Wzy4ae
         h/8Nyoh9jLKa9w6P5wH+9gxMs+J0L1CCfWixGrQXNX4y4kIeCBcsxDZoWx4f45ZURR8g
         5gnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:dkim-filter:sender
         :dkim-signature;
        bh=BcDWw8EOMuwHyE73R2rw6cmk/zrpPOl2wHPCckOPlIc=;
        fh=U/dYARmy+IoasCuvBKu7lKOZ5zrpPP8mTiWHaxa5tG8=;
        b=TvkWYvXayPUsvPxIvYHs3XtLhK1KUq5fc+izh4owYz7bMQbmpYa60qmrC8x1319Xjy
         CgE90reCS/P5yD0m+3rhrl5JkXQyNhEWcbDDZYPgk7yrtJOpR4fhb4b+qj4TA6hgajJz
         pd5upVQdgVWUB9YEz/UocytsCIWyltmJoZApbOvGo9IPAXKQVK1oBrbfoSQbO64vu45F
         2dGI8tYv6bbwUPu3umRq9WUlGOj2ImpRbK/3yyca1GOX4M1O+XYRYmyLaOCzlzHR1OQr
         D7lalR3dI7qvTz04G7/yqrk5LPdsqedpXv4VSRHaQQqtuL5dXFRy8u+X29jOOFO/fx6H
         qfZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=QSXeqYqW;
       spf=pass (google.com: domain of corbet@lwn.net designates 2600:3c01:e000:3a1::42 as permitted sender) smtp.mailfrom=corbet@lwn.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lwn.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725458703; x=1726063503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-filter:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BcDWw8EOMuwHyE73R2rw6cmk/zrpPOl2wHPCckOPlIc=;
        b=nkI7KfYG+uuqnWVBNyLyeZT91cug9wtgg+Nt8sFwksIsPr3vb2s7CvNvl35xDcN/fA
         TiaCB/bACBuF2mMYXVg7zeS2cQ8fv8J/LCROHP85MP0Q2gVXuJNCPlNcSIptJq56gKnp
         iIGqVnR9VCZbbsii2gw1EL0JeOTFOYIoxZlljwUJV8TThFezjEq1D2Wgz9bCJETZOiAv
         qnkULcCXuJnAYOZdPvFsNyw5jSzsbvw9QKR0s44V8tOqEEqVWfXQeKrDHKU8WZh6Y49p
         905M2vBBsums6sN0+ghU4OXqoJgMvw31tpekbGDY7WppgT/1DCJ6QO49nZTJSQ6gkleo
         dAJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725458703; x=1726063503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BcDWw8EOMuwHyE73R2rw6cmk/zrpPOl2wHPCckOPlIc=;
        b=wZj4oOGjSwDe7sDdQYaqv63brU+IJ1QilVya8J0yslKli2+Oi0QDT9DKeqahdXg02G
         4Qvz77Tl3HZ/bBZPATcyJcVpiHuL7Yut8kXssYxnk5KHqtbIUo7PKPNfSPRETfS5w5wD
         E8oKT57VnN3ngscOAemuXGWLDKkJtDeQPsZ2vagZv7oMi0DledZ12PyxJ/nkzTg3TgHa
         6dX7WN1DE7bDDL6Bk3M8huW+KoAjZ9T9QGUbw9TvAXt9Md40i13kUCq4pGyt40b9ZwVY
         Npz/0bLDz54tjBqPEvVd3WifLUvTpMg903mWnpZI4cFVi/pI/gwEcEBiRmoZc3k07hhx
         k0Tw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUn8zrtHtYnwCMwMog1/7lYpKOYQmsFHUWvMOnUFDk8DaqZNPtlZSJ3RPcIaC+PHzKI44ah5g==@lfdr.de
X-Gm-Message-State: AOJu0YzPA8pjhuk47n80Y3UkOFMGSqj99JwWbcXGiMQcsd2vfDAX2l96
	2IjV5Sdxn1zxPIKalKch5CNbFLdKFlij8DQ+crd16Bgq7hLxvYtu
X-Google-Smtp-Source: AGHT+IFUaTvs7Nh1gQOo0xnmYaXd5z/oVPqK4ZBYBSUbyGgXI5KB7K2GfspXH8TPLJIewrXrRWqTBA==
X-Received: by 2002:a17:90a:c28a:b0:2d8:8ead:f013 with SMTP id 98e67ed59e1d1-2da55929d85mr6660979a91.7.1725458702497;
        Wed, 04 Sep 2024 07:05:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a45:b0:2da:6346:d569 with SMTP id
 98e67ed59e1d1-2da6346d7a2ls1109830a91.1.-pod-prod-04-us; Wed, 04 Sep 2024
 07:05:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAQrqAFNbkeQg9h4dPTMbc/G9TmRPDT3Iddzo+mIypJazc4JyQMB61pna7DJVRJ4pQldCsh9aHHsI=@googlegroups.com
X-Received: by 2002:a17:90b:350d:b0:2d3:c9bb:9cd7 with SMTP id 98e67ed59e1d1-2da55a77e52mr6873212a91.36.1725458701357;
        Wed, 04 Sep 2024 07:05:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725458701; cv=none;
        d=google.com; s=arc-20240605;
        b=A2GtBv+eg05YF8QI4LpolzBcdeEwNIPpD5WxctWtNWk+l/pUF64OLFqLb4tXw4Phvs
         6hzD1cznNE6FWHsXA7WpMRytqRUI/M1sGpvTQ4q1tDdMhHTGagy398AQpYGS/dkdUVF9
         g5gzZ9jeB9asgo64xzLgrcUTh2kMlrGS5nxmC8ByIa5xuxQ493Vb3tPf4d/fiIILJRmm
         9TWPK+PRPtX/o8al/GMKW77T78VYmuidsnQcxh+BHiax8bsNCftwFBbV8pnP85dtg1hi
         HKDIFl3s9CB3xSIHIudECVRPLgAq7v6/cfRkoPa5E5It1XDyt81Hgsfg5BbaHXKPaxOw
         Ye1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature:dkim-filter;
        bh=bPJsyN4OVHJPkKS+55oOZsTfbS95iFLn1DvzX0Lx3OY=;
        fh=6hApI4cJMwXleAHKvukLx/JCiBN9IAEp2MAuzMIHfT4=;
        b=kefMLcPnn/ztH0gTpj6+wfgQCaIhcLsrXqqZXctcEo1omwfZ7dVf25QR8axHbcp70p
         ze9HYvXtrGL5oTxlw5YZ3KUsYGrGT24O69G+JkteLT+Aj2ZyGB+L6PyfyryH413Uvj56
         CXaC9dtbNKY0yq3RRKADrrio9OOj7Qowbi6Llb/CFxOQvRrQg9nSdwewXjG9cHiAzfs/
         MiR2mXFMN54T0s91/gr++O4G5DIa3mjHuYMedu4h1/m96DVbXB90lh9zoNS2z0qL45Ra
         kkgDZCjzkx5NqSjxygPMjq4SFmQ4O79YmgqVsk9u9NpvqjKkDiwhloLx+H/IL5Y3HqTm
         1NSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=QSXeqYqW;
       spf=pass (google.com: domain of corbet@lwn.net designates 2600:3c01:e000:3a1::42 as permitted sender) smtp.mailfrom=corbet@lwn.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lwn.net
Received: from ms.lwn.net (ms.lwn.net. [2600:3c01:e000:3a1::42])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d8a1c35e18si343635a91.3.2024.09.04.07.05.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Sep 2024 07:05:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of corbet@lwn.net designates 2600:3c01:e000:3a1::42 as permitted sender) client-ip=2600:3c01:e000:3a1::42;
DKIM-Filter: OpenDKIM Filter v2.11.0 ms.lwn.net 724B642B1D
Received: from localhost (unknown [IPv6:2601:280:5e00:625::1fe])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by ms.lwn.net (Postfix) with ESMTPSA id 724B642B1D;
	Wed,  4 Sep 2024 14:05:00 +0000 (UTC)
From: Jonathan Corbet <corbet@lwn.net>
To: Haoyang Liu <tttturtleruss@hust.edu.cn>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
Cc: hust-os-kernel-patches@googlegroups.com, Haoyang Liu
 <tttturtleruss@hust.edu.cn>, kasan-dev@googlegroups.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] docs: update dev-tools/kcsan.rst url about KTSAN
In-Reply-To: <20240725174632.23803-1-tttturtleruss@hust.edu.cn>
References: <20240725174632.23803-1-tttturtleruss@hust.edu.cn>
Date: Wed, 04 Sep 2024 08:04:59 -0600
Message-ID: <87cyljms50.fsf@trenco.lwn.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: corbet@lwn.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lwn.net header.s=20201203 header.b=QSXeqYqW;       spf=pass
 (google.com: domain of corbet@lwn.net designates 2600:3c01:e000:3a1::42 as
 permitted sender) smtp.mailfrom=corbet@lwn.net;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=lwn.net
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

Haoyang Liu <tttturtleruss@hust.edu.cn> writes:

> The KTSAN doc has moved to
> https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md.
> Update the url in kcsan.rst accordingly.
>
> Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
> ---
>  Documentation/dev-tools/kcsan.rst | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> index 02143f060b22..d81c42d1063e 100644
> --- a/Documentation/dev-tools/kcsan.rst
> +++ b/Documentation/dev-tools/kcsan.rst
> @@ -361,7 +361,8 @@ Alternatives Considered
>  -----------------------
>  
>  An alternative data race detection approach for the kernel can be found in the
> -`Kernel Thread Sanitizer (KTSAN) <https://github.com/google/ktsan/wiki>`_.
> +`Kernel Thread Sanitizer (KTSAN)
> +<https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md>`_.
>  KTSAN is a happens-before data race detector, which explicitly establishes the

Applied, thanks.

jon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87cyljms50.fsf%40trenco.lwn.net.
