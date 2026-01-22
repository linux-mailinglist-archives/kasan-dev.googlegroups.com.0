Return-Path: <kasan-dev+bncBCSL7B6LWYHBB5ONY7FQMGQEEYOGMGI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id ONVKFvfmcWkONAAAu9opvQ
	(envelope-from <kasan-dev+bncBCSL7B6LWYHBB5ONY7FQMGQEEYOGMGI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:59:35 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id F22E663A9F
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:59:34 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-5019f8a18cdsf24798251cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 00:59:34 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769072373; cv=pass;
        d=google.com; s=arc-20240605;
        b=hZhOaFfgIDelmMspi1IPNd0SUEjNJJjjoiRInapuzC/G0cy7zninvvgr+aIUU1paAG
         QHxynk/rGFf39ESulYI6QT9t6EIBqx/1Hw4lPmOOklCbQW2/Nof9kvhyWzWTfAiRkEfU
         1oaxazdih9mzkmRwK1vWwXeu2APYkvjnEsoVNy/8qR7jzq3KhKAiRHpoov4CqEzCPMjh
         Tfx5fVaDaAE+3UXFVYEFSQ7dVy84QGjWgJQMykynVkw6Uyv4cPwxQNvnz9iPuY5H2PlS
         GWGZrjIgKdknKO08CJaK6IS52cKMzBhUsvh7vHElYPq0l4ZfoqCb3GwzGddSg1yoZGVG
         /OUQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date
         :mime-version:references:in-reply-to:from:sender:dkim-signature
         :dkim-signature;
        bh=YHQ8qnE1hjmXsYQp9ETmAP3QV9iv9vwtDY/lV13JJck=;
        fh=rfw1ezAE1+jAQjzlT1Q1O8BdUMFdYImn0MJAG/n3ZSg=;
        b=BCrvjcGjQXWx5An7fzNIc/Qxafbcuat52Wo9w0Py7btdwGjhj66Bg450AeHO3New7n
         HwfHSp70LJpi97+FFgXFbJkPQwUtu5abjeISLSZNXdptNNUQBuYkdJAT1dgJf2AHquCe
         BQTvP2sHVgHE8cRbi9wwBJn5T6c0PgEGwkiJF3iwQt3MJzbOgsNfimjJlfBG2+YxQLtG
         DuohR7Q6dvCPjj7BmREkAxXubm98p8lse7vidzxjITCcNQ6jHuGUu01C8nhfovARznIO
         2XeeywLq6BXYmWmmI/gncay/ZbbRDZ47w9nvxNr3Dvmnb1aKpteOLyZ0dm4OmzpwdJgs
         3S2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VqlqNHbo;
       arc=pass (i=1);
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769072373; x=1769677173; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:mime-version
         :references:in-reply-to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YHQ8qnE1hjmXsYQp9ETmAP3QV9iv9vwtDY/lV13JJck=;
        b=odQOCYqwH6JfDXoR1FJDgSmxpIYtFPYceufEp9ad0slczMSKJPJJpSkfSOOLGX75J5
         tnvtFvUQzdBuykCY3i1crvogykovZpRydp8YiLY4FrbvuTHER1Y4lvsq/i+dkWopOylv
         eIwpfAi6+Rl/XEM+DnNWkw23R+EXxMolEYmMHiXV6CLWidHciHaW9gataArsfHEw2ORH
         /CE2tCQun3vplj3oxnp3UE9skP3whq+/quz5AB5Nj2po6CVlIb13/ffVYRM3ud7dLDQs
         FrQsBGSciTUpgV6rTFtbH5BEgCAGV25IUtr4SMLf2jj0aZ1Q/YAQxmAJsI94XgHxFbLL
         mZHg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769072373; x=1769677173; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:mime-version
         :references:in-reply-to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YHQ8qnE1hjmXsYQp9ETmAP3QV9iv9vwtDY/lV13JJck=;
        b=Zl8Jsr1BxW9Jr7A3lhAetIVPb0k4UeU2bVIa5ilsxLLo/AfREaFY2Ua56ooLw38MR/
         m8mYbRG+U8IOPB+hqaxekuwgm52W7+0yIPUlAijxPhloctFSgwpj10Y66z6ho31zA+Ni
         2486AW2ikcu/Hm7eLoyVvrepw4xrNIOUslSMFVxIF3ps5PorZplVJwmxIZjQ0WMvozAf
         Cu56blX/bWk3Djogp2GhDPwT0WDmZopRFQDybUbrEVwx2LIKBixQUKvuZ50ja4/+IdyD
         hTm7sxqLgrhHRfgkQRI0iOcuC+b1HCBvRpd5eHOa4lzDG7ZYG8qHbJH4zkkBY93QzQuR
         fdPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769072373; x=1769677173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:mime-version:references:in-reply-to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YHQ8qnE1hjmXsYQp9ETmAP3QV9iv9vwtDY/lV13JJck=;
        b=BWLe18/D6pwkqXKBNdlJGBL2asB9uchogqwsaj+y6kjen1/7ACdWP9Ns/LxB/E9Q/G
         33R5TV3P1HJgbJ8+PdLEGSVbib/1srgwqJiYLfX4SyQMZCfnR6RYNzvvM4+4WqKcbyka
         q0aXHhnpu0H2eXQ6JIxI2BOnONVU4dCLXX481cT9CXyvZlY5Era6/Gahxrp7JZoPkvzM
         SrxhMMGH/06Abrk82NE/PYnHwprztolxA+EQdDtRZRJDfxYsKyaODT4flAbS4ByTQbIX
         gbYiwJtxA3mxqkAWKUAlyT32UYPF+RftFfeWV0pW1gUSY1yt7tUwPT7otPKh17Pcfsdh
         ulZw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCV5mBM/TkBkA+Vdyzuu/5jK2z1pxBjJs69XmN5J/sLTTf6sH8ktrybqVMvKwtYvHzrsF2O8MQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxlq4mUg8R3jhWjEDCfDhpMgf3XjIMKHu+gaj8ZcDcRae9pujxH
	rRzHZHGUa3kxLW7SvQiqmvrwEuLiKezPdgUXE1Lxpu3EgK8y6+GcX9MO
X-Received: by 2002:a05:622a:1ba3:b0:501:452c:b6ae with SMTP id d75a77b69052e-502d857fe96mr106723931cf.57.1769072373534;
        Thu, 22 Jan 2026 00:59:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HmffMlHqCS0SjaGtrApBYRUYpEa+lKf3HFnyaLcB6NQQ=="
Received: by 2002:a05:6214:2481:b0:882:3acc:d7a with SMTP id
 6a1803df08f44-8947ddff5e8ls15144636d6.0.-pod-prod-07-us; Thu, 22 Jan 2026
 00:59:32 -0800 (PST)
X-Received: by 2002:a05:6214:2024:b0:893:89e0:4e4a with SMTP id 6a1803df08f44-89463e12c32mr129063236d6.38.1769072372751;
        Thu, 22 Jan 2026 00:59:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769072372; cv=pass;
        d=google.com; s=arc-20240605;
        b=HtV1+Iw/zCcqXk2QowdiPWw7HeVqUfaui1FFWhxZNZve0svO4y7SzR5w+jeu5NBxJ5
         LNsl3T2NZ7ZC+vlCvsKl8J17qwEivxTQhc3+0FQCHW0mjI2JMutFrWV1D0+Ip2oqYmjx
         M2im/8eE1rtf0luKqHdK/v9jcSaCYVNYX+VjnEI3jqSV8XA+3Hj/9hwa4oBLz1UEDxVu
         AS8IEzmVCXsffY8G7SCu5M9YMqLAoQvkH4ma6aBueey0GjGIbEytAuuDl2kL3hqQ1HVu
         TfMbKEDyAnxHh5/7h8QK4kUuVfRc3xSCxVl0r07tKF4WH5FM9cMGUMdauPhXZqgruzAt
         zSXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:mime-version:references:in-reply-to
         :from:dkim-signature;
        bh=Wi+aiksRUdYPRu7nOjHBlGLDUjwQ5QAqfYPQCOfFmHk=;
        fh=8Ul80+h8TF6IMFdoC+h20AfJA7V/zorm5A/H6rkclXE=;
        b=W+sALsTjZUd/nFHRPYs0T2DOqA2ISpgTD9aKpw7sduthQV2H5G0NNblwrUtZl2UkPw
         QgpX9Jeo1FDm9xjOA3FOB/KidP0WttRYbz5z6Fy0X0MquH9sw5d31UfP4l4l1rarxp+q
         7kObpKgPNBzxdjLVkxUK5bWGSwxoQX6PnBQbVgGLfIUc6dlI2FLQfy3CrweLMlDDIMB7
         9heu1NUAPtAzP6e8b05HvrQXql9J/iHvi261pPVZeTNBKLEdBC3WRBheEAZSA51/kfRH
         kUZp/yfEgLHInzOmi/6dxbINQiPjlX7MI4eNRA+9FR2lFyjLYRfKhvl7EFQC/wZt1quU
         TXUA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VqlqNHbo;
       arc=pass (i=1);
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8942e5e59bbsi6959956d6.3.2026.01.22.00.59.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Jan 2026 00:59:32 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-78f9b964c3eso1794737b3.1
        for <kasan-dev@googlegroups.com>; Thu, 22 Jan 2026 00:59:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769072372; cv=none;
        d=google.com; s=arc-20240605;
        b=TzlpvRnFTi893lI7t3vjIxY4XcAKCZB8BEflNkSlY+j+QI9CYvL5rCp+dbnxLtTFzw
         9FfWWqkFDcdLcttQePopQCKzq6Wui2toddYm5r19zqMAGuOdBoJ32RpXvLc5zX3et+3K
         yQUKTdcdCtQo8PEL8V2oxiJgMx+nQFGTOXFMmE7qihjm/jHbR0JczsvDuGoH/p6zOIBn
         23J1VvybBJHBE9jkboZAZU6E6mrXiLPuUVVmGREJcc06UbJHPskXc1U4GLxPUlSTo5si
         MOIPUw5kzc+oIZXHu4/W/hLWqS2xCuCJYeiYDX7G/mYu+YXsY5CzQhvmnmvjPpUf/kX8
         cBwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:mime-version:references:in-reply-to
         :from:dkim-signature;
        bh=Wi+aiksRUdYPRu7nOjHBlGLDUjwQ5QAqfYPQCOfFmHk=;
        fh=8Ul80+h8TF6IMFdoC+h20AfJA7V/zorm5A/H6rkclXE=;
        b=gNehA8DrtdHCmbtcpvDdZHSjXc01q8CyT4kNeI8mxQnlA78rUL6aS/EFSHzYViqZTW
         TeqhFYDsxw+j3UA6r+Ot+dE5r4FzCrOwwHGTG621f2TBinoMXw3xYUBYWOEBNVVX8xco
         DiHkmJDLjDNX2DqPgRWlRA2yg2kvOa1GEWP0zR0cFgPu6fQDdHFzKCkDsjnazjEdmST5
         LxNzyAJQcORXbXyIi9nvIdxPZpjkBvPjzMJ96/WsJv9u111A6HLjBTe3nuVmegdZXqHy
         Fq5nwBuCASpGDarVaPsyQL0s0KBmanSFcMDNmyRMG5D9MPfj2IZQOrYahGgbF5sTiNvr
         Ub+A==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Gm-Gg: AZuq6aJAY0DHUKztY4mBlgVtumR3JDaCq1Yu9mhXHxp3uzTtv9TykevzNnF4yR0UY6e
	zH8C8rLMiI8zgh3QZysGNUXY/HB5bt9jTzNLpDDIkgqL4200XPPt3SYn9Jb9VqfDepV/TsCNenC
	U7IDzCACkK3cgEo6BK5CpddILZZc77tvejvic1zSLrTo5hOtIGS18C+4tj56DXn+El/YbHC603T
	YDZuZdmJCrm5kXmVq9MJrpWRX0C7hK0JpAg5NTlg5Sy9yU93efaSvWxVygzlOu4rYP8sCQq
X-Received: by 2002:a05:690e:190e:b0:649:47f1:26d8 with SMTP id
 956f58d0204a3-64947f12a86mr3259191d50.6.1769072372283; Thu, 22 Jan 2026
 00:59:32 -0800 (PST)
Received: from 95991385052 named unknown by gmailapi.google.com with HTTPREST;
 Thu, 22 Jan 2026 00:59:30 -0800
Received: from 95991385052 named unknown by gmailapi.google.com with HTTPREST;
 Thu, 22 Jan 2026 00:59:30 -0800
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20260122041556.341868-1-maninder1.s@samsung.com>
References: <CGME20260122041606epcas5p4fb3f5c418b79bf19682e60022d7f1718@epcas5p4.samsung.com>
 <20260122041556.341868-1-maninder1.s@samsung.com>
MIME-Version: 1.0
Date: Thu, 22 Jan 2026 00:59:30 -0800
X-Gm-Features: AZwV_Qh0e4MZqYcnvCKaN8uGthW0KvntY5zaxHw78pviBg4F1BIOJs3rDhFDIDI
Message-ID: <CAPAsAGyhr+iakYskfFXhOFHv7VBqhzD3sb51_MHMxDaQA9cZnA@mail.gmail.com>
Subject: Re: [PATCH 1/1] kasan: remove unnecessary sync argument from start_report()
To: Maninder Singh <maninder1.s@samsung.com>, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VqlqNHbo;       arc=pass
 (i=1);       spf=pass (google.com: domain of ryabinin.a.a@gmail.com
 designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCSL7B6LWYHBB5ONY7FQMGQEEYOGMGI];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_TO(0.00)[samsung.com,google.com,gmail.com,arm.com,linux-foundation.org];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MISSING_XM_UA(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[ryabininaa@gmail.com,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[9];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[samsung.com:email,mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: F22E663A9F
X-Rspamd-Action: no action

Maninder Singh <maninder1.s@samsung.com> writes:

> commit 7ce0ea19d50e ("kasan: switch kunit tests to console tracepoints")
> removed use of sync variable, thus removing that extra argument also.
>
> Signed-off-by: Maninder Singh <maninder1.s@samsung.com>

Acked-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAPAsAGyhr%2BiakYskfFXhOFHv7VBqhzD3sb51_MHMxDaQA9cZnA%40mail.gmail.com.
