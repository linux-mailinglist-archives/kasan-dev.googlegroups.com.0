Return-Path: <kasan-dev+bncBDIPVEX3QUMRBZMYZC7AMGQE4LOUOQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 783BDA5E78C
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Mar 2025 23:36:23 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-2c2b9ab3829sf354869fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Mar 2025 15:36:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1741818982; cv=pass;
        d=google.com; s=arc-20240605;
        b=T96mMk3DMPBQQsO+OIL1Zmde7Vc583ebn8hqSShB48IUepsV0oJ88R645i/AgH6Oe3
         nl9BJFk/FGwB5VS9exInW10sogrG3EvKh6eCW8kVVGSMmonmLUT3yLlIZSD8XJFpsPNf
         /nDybqwUNrTsZXLTSW0O+urfT+lz12+8UWgFE/bT5hEekcGqgIYU2OY2t4lY/IAltOog
         Zv0gXsV9lx30jDlCk003or2g1yaPU0n+AdozyyG6qiBs8aox7dwLAUPGp+vc/kVWjT0/
         a3Jb8oi+vE1Zx8Lb+sEDhVCCpiq4pjnrSH/MoUSCs80NKbz2qPGlYfmhObcahRVXv85j
         VjfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:dkim-filter:sender
         :dkim-signature;
        bh=BvAl4WtlI78y45Xbs8R5IEukveaQjMGKeSdYE3FfyKE=;
        fh=MzQYTEcX6G/xZhmNSn8G7okdEwzUUVj/YFujc5gRV14=;
        b=CpC1WmvDl0S6zwI/WX5mNBRMIJUojJlA9QwEpaDF55Rnyfy0HrqJ/PIN1kkmSp0BxS
         F5j9HR4GBoPZCEvuADH4SfFtmnH1SPJCJJSmZrzH2ZcvV9MqH5KdVc5i5IqnG7x4ZkK7
         PrZ4E1FLS5Rrqde1mC1B2JlmWJ/ZPx7w8rBiXjHj8fdiaKy/dQpFgtVJquWqRe3ns3lx
         anNZTRB9c9RkSVlJU3ipsdEHz4oCtFbc8fqGxFJjxipuvQkIQmV6FmjB5tKcbnNdjMQE
         fw64MXUQapljdvLhQ6Q2EbWCMdBDZSiHLVC11N7EnMlBieEwQcfGY1hafwrSrKCuscoK
         oDzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=mCGKV3ac;
       spf=pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) smtp.mailfrom=corbet@lwn.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lwn.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741818982; x=1742423782; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-filter:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BvAl4WtlI78y45Xbs8R5IEukveaQjMGKeSdYE3FfyKE=;
        b=Q1WuNTCrS+iu1SVqVW4IFBu+47IWXajgPvtevGnY4ve+UlZSUWaC7UNZfrTxpa7L9b
         eWZPQuQ4NEhbZYVDPVUjiCKxyrBt2985OAnpRyAWV5E2kmnZXhum+znrg/4bTGhtVHWY
         EUQR/RrZM7QSWw4iW14eSldpCC0t/dt5B9qJri0WJvWRlP+WE1dHr4yl08eSAIcmWbBN
         eH0Yhpkgv7NtfWKtwp9XCvhp1Cv+Wq6+k6y735iJqmVlfr1Z+KqpM4HkEu/sFvpJCb3q
         8QnTU4UQ1v5/KbRDIl6UKykY37XFjOB+LdJ5ngxfRhuN5/TCHTaJFUYK2QMu1Q75wt/G
         Ffiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741818982; x=1742423782;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BvAl4WtlI78y45Xbs8R5IEukveaQjMGKeSdYE3FfyKE=;
        b=s8HH1oK4b1evNjS8dL1g44Fg16aV38VQt8YITsZphkBe9vBpUyuGSur81BFg5L135H
         IIsRH5vd8va86gY35Q0ixviPpa0vxe4q7GppCcoBSKWwTilEIUX5fyJWgLC+AxQDNxH7
         wGQ5fDOlbutQ9QVSyP9QRrwuiCo1pu8TL89ty4bWWX5+K+O89J+/m0sbY4sWsERd4F0V
         tsOT3O0lpznK+Nz93X5NFYsb1dDjmJmyIvcwsYHQEejiUG76nd8HjhzB5G7y535USvDa
         OCsKEJrc/qitOoGfolH+CnuleEgUghBtDv5dxf+3sBCifksQmsy/ehoMTvdW1Habv+YD
         zNMg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUQAG7L4NLxIXGpYuh7puVge5bLg3kv/iwwNq4V35k6tTvNnAlzSik3VZBFzQ6YBOx0Vll/lQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx30WKWWbR2BasdmnIDMsvM3phDshUT8lEhHfn3XGktzN3VgFY6
	PzLeu/hNTt9aTK+m6yFlnMPevZ7pT2acydp8M/b+WW9F+0KMF9ls
X-Google-Smtp-Source: AGHT+IF9PuOnPWkCxnc9X3FSRWO9sGtgO/5/v50+qBxNsRo838t7IMrTkXIQKoY4XDCHOXbabtuTkg==
X-Received: by 2002:a05:6870:1f13:b0:2c2:3ea8:eb3d with SMTP id 586e51a60fabf-2c261388fddmr14202976fac.33.1741818981914;
        Wed, 12 Mar 2025 15:36:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFSVhxL5YhnGqkaCe9ZwzeSp2BUXe3wxHFqX2XWyqmsRw==
Received: by 2002:a05:687c:2197:b0:2c1:58ea:4cc1 with SMTP id
 586e51a60fabf-2c66753387cls239973fac.2.-pod-prod-05-us; Wed, 12 Mar 2025
 15:36:21 -0700 (PDT)
X-Received: by 2002:a05:6870:1f13:b0:2c2:3ea8:eb3d with SMTP id 586e51a60fabf-2c261388fddmr14202959fac.33.1741818981170;
        Wed, 12 Mar 2025 15:36:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1741818981; cv=none;
        d=google.com; s=arc-20240605;
        b=KU+vJC2mCCq2oiVCzdc006cvAk8RgdIxQC89K21drFxSuc9DqH6M2VgJUkigPTOzmU
         i4QYHYd6U/oSaiv9gRa/4RPP8M7K1vuB5pfX6TlvuG/6SuuYyIeR2uqBBHVgSScVsrnQ
         2CV3EGda+D/esE3AF+9wcTWWO3uNISY/Jb5nq/eMlYLLkENUEUDciwF9vtrPZjBuGfRx
         z/sl5Xc5mVZQOEgRqnzufnb//An7P16Z4VMfj7124QieNwZ4D+Yw1/YOKWCnKaICsOT7
         1pebPTVXr0v1gibW4GT2nxuHWPNdRd+qURkEOj8iouPIBl08bZAiVLKUn9CZS4WtP3Fn
         o6/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature:dkim-filter;
        bh=GTMfbvfPe3rGQpfvz+NRGN74Tvu8HffllNDpfQa9owA=;
        fh=WrZ5wTTyVzVvcceYn5rGgUtJoXVyt08yOcsps/1BfWo=;
        b=gG37rqF++bw6cttP1TQIV3nmdxCrWX/3FYjGsLuOyy702d/IuXfKjY0tGk7ebQ0thK
         q/+rzpHP6M7TcyKR0SUG68WInqybUMrHdyeKfj8SL6v4O/ifnnLHRehFZ+V4aaYLf+DC
         mh9LGcsr/Z7cqZdaDmNNaVh865Hjiqk+B33VHH+kCx7m0cGzwmVFQ8wYKYsNvpFsg+d+
         OVR3exll6lwcn+ygsjO1v6APR++HmdNk+An9ZyjR+wz9NLDdRisD+Z2Rt8ZzEoOsew0b
         q3I7mQYQAt4TvmwI6jW71218yyG/O1DbxPbZc953EDBvCaUxES7cFw2ocNXVHeUhW01/
         FEUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=mCGKV3ac;
       spf=pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) smtp.mailfrom=corbet@lwn.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lwn.net
Received: from ms.lwn.net (ms.lwn.net. [45.79.88.28])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2c670fbb73fsi3009fac.1.2025.03.12.15.36.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Mar 2025 15:36:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) client-ip=45.79.88.28;
DKIM-Filter: OpenDKIM Filter v2.11.0 ms.lwn.net 0FB7E41063
Received: from localhost (unknown [IPv6:2601:280:4600:2da9::1fe])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by ms.lwn.net (Postfix) with ESMTPSA id 0FB7E41063;
	Wed, 12 Mar 2025 22:36:20 +0000 (UTC)
From: Jonathan Corbet <corbet@lwn.net>
To: Ignacio Encinas <ignacio@iencinas.com>,
 linux-kernel-mentees@lists.linux.dev, skhan@linuxfoundation.org, Marco
 Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com, workflows@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, Ignacio Encinas
 <ignacio@iencinas.com>
Subject: Re: [PATCH] Documentation: kcsan: fix "Plain Accesses and Data
 Races" URL in kcsan.rst
In-Reply-To: <20250306-fix-plain-access-url-v1-1-9c653800f9e0@iencinas.com>
References: <20250306-fix-plain-access-url-v1-1-9c653800f9e0@iencinas.com>
Date: Wed, 12 Mar 2025 16:36:19 -0600
Message-ID: <87o6y5lvvg.fsf@trenco.lwn.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: corbet@lwn.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lwn.net header.s=20201203 header.b=mCGKV3ac;       spf=pass
 (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted
 sender) smtp.mailfrom=corbet@lwn.net;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=lwn.net
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

Ignacio Encinas <ignacio@iencinas.com> writes:

> Make the URL point to the "Plain Accesses and Data Races" section again
> and prevent it from becoming stale by adding a commit id to it.
>
> Signed-off-by: Ignacio Encinas <ignacio@iencinas.com>
> ---
> I noticed this while reviewing the documentation.
>
> The "fix" isn't perfect as the link might become stale because it points
> to a fixed commit. Alternatively, we could lose the line number
> altogether.
> ---
>  Documentation/dev-tools/kcsan.rst | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> index d81c42d1063eab5db0cba1786de287406ca3ebe7..8575178aa87f1402d777af516f5c0e2fc8a3379d 100644
> --- a/Documentation/dev-tools/kcsan.rst
> +++ b/Documentation/dev-tools/kcsan.rst
> @@ -203,7 +203,7 @@ they happen concurrently in different threads, and at least one of them is a
>  least one is a write. For a more thorough discussion and definition, see `"Plain
>  Accesses and Data Races" in the LKMM`_.
>  
> -.. _"Plain Accesses and Data Races" in the LKMM: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/explanation.txt#n1922
> +.. _"Plain Accesses and Data Races" in the LKMM: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/explanation.txt?id=8f6629c004b193d23612641c3607e785819e97ab#n2164
>  

This seems like an improvement over what we have, so I've applied it.

It would be best, of course, to get the memory-model documentation
properly into our built docs...someday...

Thanks,

jon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/87o6y5lvvg.fsf%40trenco.lwn.net.
