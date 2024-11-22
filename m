Return-Path: <kasan-dev+bncBCT4XGV33UIBBAWJQC5AMGQE2OM5NBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 6316A9D5966
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 07:28:20 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6d40cc92ff6sf23540366d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 22:28:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732256899; cv=pass;
        d=google.com; s=arc-20240605;
        b=QTJxbt2SfSRACoh9yvl2RBtdXO5NSCLeaVQfTLhz9Kf63+ZVyhWdPj9GQyNAisbIYj
         lEvp5CfbaHQazogfX+c9mm6VvDuL+w4r7LXV1mu5Ls1jdAdNNu/j3ALYoNw7Bk2dTVRQ
         wx4w3m7p1sgxasQYf/mP6ngvbBJwe+Z+DbJrHDT6q9/yOg6WHjn6U4+K8u9s66+eHV2Q
         NHX+N0wB4kvQ9oGUzIYq2bgwgtXuHfcho2HQDZMo6A81O78CMxVydJVvj8Godmqr6JoC
         JVSvA9KEfiZwonypBhDQ2TKUmcP4ta7TBHFjELruFYvmZx97R2kXTbby3BV0lHyj2J/q
         Ic1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=fr9hvvs4dsLowYaDfcDDVkiRFnpHkeytdvL4kBfCfjA=;
        fh=T+/ZieBdMmrmsecZOYjTwTusmEAMuHVGnDFotVLuuWk=;
        b=bcqm5aGl/v81qdJ/34M2tT+1JMFc+O6Tlq7O4KGB1hAuj5Iofs4nC8JLgrv7/CMne3
         wjL5V545IlATsG6oOn8/4T2NqZqPJU1dPWnkagafX4GW/zYEwugNabjyv/9kvkh5IqD2
         B8/CnPqDZqb5WcFe0g2A9nSuN4DitFoo0chHuV1wegPIlgB3ZFZQ+QAnsCc99MsNtLit
         ODMTTdi7KsMY3yCEYQpIUK5Mu1jTRtISqjuPqQiahafjnreTw9tVpjcigC1GowR6eWk7
         X6X0lbADPILKl1gqbnPSwCwJBiyeoUS6ZtPxbwsD48VaftKI12TaIDahD7Rqr+0oq5f6
         O5gA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=MMrOLjp+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732256899; x=1732861699; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fr9hvvs4dsLowYaDfcDDVkiRFnpHkeytdvL4kBfCfjA=;
        b=ElY3BMK3ssNm2LUuB+nFHRzBCM1Zt6oGHsV0Mt91pHjWq72C98JWWUtJAeUVj89sMw
         vRfYiQNowUq8pHj7iW/9GJMdfIVPUlS/uZS1n7IZHhqTzlzFyxn7pcrb2dv0lhaP4wqp
         sa0Ekz0a92Xd92pNNDgys6CMV5wfuTSPzQ6XHcEzt+1IR2o+Ys5EU8zA7MRJLQ1RfN2n
         Q8sb5bLEl8Iaz/8kHSsABNhaVitF0l06kMGertlE9KKDwC0IDmzkcRh6LJd8xsyCSCHs
         mut6SzfQe/qlDwIj66EzyBdScC+Ho4KWtXfQE+eBz7DBQkd3CQ5cw1kzmlMNArjG2yYS
         4BSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732256899; x=1732861699;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fr9hvvs4dsLowYaDfcDDVkiRFnpHkeytdvL4kBfCfjA=;
        b=QEFWD+FWuW1ocke9/QCGKwJQ3xzbjuWHOAtR09YMXGk60EfQh8zIyhcG2cai/o8saH
         pravAeolhNW5Nw6OS0UtjUQVJWUjyvn34X0YS6cIDOZDZKCOy2LnXQ+8l7/C5B7GaHlt
         lu2dNXSDHevUELQ2B9BeF7HoorDtby9+M/12sMzqQ9DK2UybetPhJxL3j3Og9VsBHIpw
         jJCWXITom0nBM5sU5GxQU0nAJqfmwnX3beH8vZXL0H5LiqusjtLE2pzmbH3lXjgr5kiL
         0GmHv2KoCz27ichp9IXU7Iz+JipLd1cCa7AKeuCnz1jY/KXu9ej3Sj+xXF+vpfNU7bWx
         XF/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbmeNX5E5kfbkjHBJefbDTCMduLFZWMWar0nuMw7q1/rC33Fmf6/ylEQyGQLVIBGTWKTA+AQ==@lfdr.de
X-Gm-Message-State: AOJu0YxnGxPy5IWXSAll+Blng0sE08AE/t7Sh3kaiMGcaHNABno12gCR
	IHA+B++fqw4481xaThwSlNjtLOGYFPSI80/rZp1mKfzyMEGq6aHA
X-Google-Smtp-Source: AGHT+IGkfhcRKLdsTeiRFZpUntghYz/AUvB58tqd42/93HR2/E9v+vHXQufM16eyCnbVuh1yTroRKA==
X-Received: by 2002:a05:6214:130e:b0:6d1:9e72:596a with SMTP id 6a1803df08f44-6d4513429e7mr23605356d6.37.1732256898971;
        Thu, 21 Nov 2024 22:28:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2481:b0:6cb:2dc5:6bb5 with SMTP id
 6a1803df08f44-6d4423e09f2ls19938936d6.2.-pod-prod-02-us; Thu, 21 Nov 2024
 22:28:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUCLTZCO543Eu72CVOvTEn8Toe5e14D7yIyCtwZpwTmhnxwjUS0spP9ZPN25DNuhhziVV4FDNWAG7U=@googlegroups.com
X-Received: by 2002:ad4:5cc2:0:b0:6d4:10b0:c23c with SMTP id 6a1803df08f44-6d450e69ae6mr27438876d6.9.1732256898100;
        Thu, 21 Nov 2024 22:28:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732256898; cv=none;
        d=google.com; s=arc-20240605;
        b=lNjaBXIkac4JIEexvVJEHSl9xRyCbzn40PNfoZF0XZZ+ZIAVw84TNMpnS8hoqDGPb2
         n8UnvbKJfzF7g1qEUu+OjfmSoyv63/zLWoGfm7p7KAHC1VATbjR2z1e6yx59dX4MnC4T
         qlcixR4B7M7fAqemgBvtnIbvTmy3znjKj6QQD/9znubt9XNjZC0U3/B/9qDE2RUS1lYP
         3vCc0rdCwnPXeZpYhcLEL+1d2iEcBOOVpnGUmigAM1xfbNR9MbsXy0Bmbx/uj8QKk14A
         dDsL6fraFZeEx3G4u/ghKJfpFVTZu0worI5uC2PcKjpIBNHINUe/IJChy7C2Btk5O2LM
         Zvow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=AtAeF4gu0OxJSGWt2nvhwrLSebaYyvMf3uhW3V4TkG0=;
        fh=oj0iVWfa/xAfcwlpCXdlllTJqvP9dox30R845Vdl+OQ=;
        b=MTank0PG5n0TrUYCiM9HTlQgQOwP5Po+q+7isAK65aGLqPmZ4ewa7mICLz7pgU6Poi
         vszV5PJsLD7YFlHkH+XA8zGgMAsJLvBFMraUrxdH/6u01WSloYfSYHxIaebl1nqkBPzY
         APFbQstukTg0E90jBOL+TeOCUIQKvxqZxA7OFgtpBY6IkdjNypAeSEz5sN6jgHmqU3ek
         Jkm2GpiYp88cab940k47lpW5wUZ/fYDDynBwDiFrAM0285bx/cBKSONW39L0YvnfgTkS
         Oiu3RmM0kFNh3g0offLr5XJD8+3g0Vr8hMeaGvoesiXKfP3jKHbKGbxLL+2fXBQu0iaN
         lkyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=MMrOLjp+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6d451b75a5fsi515106d6.7.2024.11.21.22.28.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Nov 2024 22:28:18 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B091A5C58C3;
	Fri, 22 Nov 2024 06:27:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BB7CFC4CECE;
	Fri, 22 Nov 2024 06:28:13 +0000 (UTC)
Date: Thu, 21 Nov 2024 22:28:09 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Jared Kangas <jkangas@redhat.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 dvyukov@google.com, vincenzo.frascino@arm.com, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kasan: make report_lock a raw spinlock
Message-Id: <20241121222809.4b53e070a943e100bb6f7ba0@linux-foundation.org>
In-Reply-To: <20241119210234.1602529-1-jkangas@redhat.com>
References: <20241119210234.1602529-1-jkangas@redhat.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=MMrOLjp+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 19 Nov 2024 13:02:34 -0800 Jared Kangas <jkangas@redhat.com> wrote:

> If PREEMPT_RT is enabled, report_lock is a sleeping spinlock and must
> not be locked when IRQs are disabled. However, KASAN reports may be
> triggered in such contexts. For example:
> 
>         char *s = kzalloc(1, GFP_KERNEL);
>         kfree(s);
>         local_irq_disable();
>         char c = *s;  /* KASAN report here leads to spin_lock() */
>         local_irq_enable();
> 
> Make report_spinlock a raw spinlock to prevent rescheduling when
> PREEMPT_RT is enabled.

So I assume we want this backported into 6.12.x?

If so, please help us identify a suitable Fixes: commit.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241121222809.4b53e070a943e100bb6f7ba0%40linux-foundation.org.
