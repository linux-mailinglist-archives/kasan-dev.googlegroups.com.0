Return-Path: <kasan-dev+bncBC5L5P75YUERBHHK4HWQKGQEA5NITPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id CF9F3E8DF9
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 18:21:32 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id x5sf2582378ljh.9
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 10:21:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572369692; cv=pass;
        d=google.com; s=arc-20160816;
        b=CVl2LHUdzbEheC+Vjic1qtJbyNSS2ei0NCaEyjEyehlXiCFmRrA8tmyRTV+kKUZzbT
         GSu6DpWu6j2d8anJ+AWjqTxYhE1U2hNKcpcjAnCgdaS5GzvSyxxrcVg7tiggjVfF4YeB
         sKjy85Mec6lr+UlDJ9zMEZGNP47x34HRfre0ZVSPAEpra9OPbaHb/DS+4bojOP6F8aCA
         hYoPvXTYpzUM/nxf6LgSh8afJfaYqB4yoKgjM6L8wqlGWAk1GUVHfA3v3w3IdrK2fTJg
         6fkFYj3Lze1S/PuxNTCTyleAbbDbHq+X3CY+2/moUIQbnKG1+R69ly1JjZgiNBzTMdTR
         E9dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=aaOHKg6Q7AV6Csx4gpwOzM9Xhf8wgv4+g4lNHHusWX4=;
        b=lyUFERRtNJo3jNgYXmDwWIJWnPWe72vgZpuzCpzzss7Ep98asjNX3cEwmhDq4k3dm7
         edkjaSSCqNcRGNviUnnfYpuTr+wRHmx8L9a1louhRwXLjtMzEoLAtv+y6Di8MbRIVX4w
         CqQVxQTWzjazJuMEI492KaldzTufZVuVp95eDPNaI98nD9cXZplENNLe3YM2WM7jUExC
         IPETJftWKxdFuaUqOixvIKerT+Amt/MUnCo6hxp3hvyB/EBIFMUEyd0qm171030P88mk
         /J2n0dDggI6J+OPD5ppb+dBa2TWTCC3/k3DMRB6kYLAO6aO8Yp1s9ggoKPeCm58e6uIQ
         RRbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aaOHKg6Q7AV6Csx4gpwOzM9Xhf8wgv4+g4lNHHusWX4=;
        b=eDTetuC7JBZpcsG44g4YLLINya0eQm8EYmrKrqP4WwsJHIsz8TzwhXbtReWGZj5uOi
         2/ksTzJ+7LKOegMYDLj9bdbvy6NiTj5kueMpEq0I3im6t/kG/4a/MRf8iJVWCc+nTSX4
         46x9DHDBTRxjX2KSc7XS9CotET49RD11D8DC7GUIM/Q446ebV9wzZfqRlTwAxo/dEsiZ
         FEXyE3ikHlxayOafUWBFHOw4G9stIR0PthnNBWRYqNMWPGGXrIpS/TDPZKRmY04qgmqT
         IFq3b40llexRkmcqRWWKUeVR4qXsywy0BS+GKhS2ANLqREmGYa6kW3eVlUWXw67DOEIh
         /Nag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aaOHKg6Q7AV6Csx4gpwOzM9Xhf8wgv4+g4lNHHusWX4=;
        b=H3JXc2zE4ucL6jYV9HZ3jjs/+9SU47yRFD3Vorn9PAXN47gynIANnindrtyOg7YECO
         qWrW3o0kZO/Lep498mhHHpwPB764e0PgIHX8MlHaIG58Pk1V+GlqTUGFI7wPOV4BwdDu
         8pQ7VIrcfuaicAcTHZ3LJhMYWacZxpdGG2rSY077NwTe53VsB55FF4PgQe9hauK0f+Mj
         pE7k1mZ76UD52gvZ2zVNIXksCAjPZG921QHz6R2yjsU2QJmq1a+9EN0tQGu5GnGP+xwG
         x0wv+3CF8SV6zX9wE8W1zmre5Jo9RurY5PtGiuYGfOxC1XEvVZjFCVYmStFwDdsst0Td
         2UHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWZPU7TJSsRntSb5Tlq1FNWLE9+uAan7jr8yRZudcVhHUWyLWPf
	qbOJEnf30c9x0dyl71RzJQ0=
X-Google-Smtp-Source: APXvYqw/YjrsVfY87K7gMKHOnPjzLsKUfQn+x11/SHrzCDdzQavcembIem64f3FG6J0BQ+lJMAp95A==
X-Received: by 2002:a05:651c:331:: with SMTP id b17mr3462834ljp.133.1572369692467;
        Tue, 29 Oct 2019 10:21:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a94:: with SMTP id p20ls214520lji.9.gmail; Tue, 29 Oct
 2019 10:21:31 -0700 (PDT)
X-Received: by 2002:a2e:90d2:: with SMTP id o18mr3486967ljg.161.1572369691887;
        Tue, 29 Oct 2019 10:21:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572369691; cv=none;
        d=google.com; s=arc-20160816;
        b=P95XG4imFWX7mfXh1XJFT7sl/M6AXrNmcvi2oe+J2Ujj5vNNJfWH7NQo2qWeWyWO73
         a5TxbAWagz0OhKtvKQizBl3jwA8GaV+BWA91NF7SBmAsqf6PgSYyaez8fKXnwCJ9Db3n
         EQn7Mgjr0GRaCtzp6ru1Axp2igShciIvLavTmvBB5megHoRcSAfyJtni62SIYTTq2yFc
         1AFvOa7rw0l+sPbbZ8oB479O74bVLX4KDQ486+3CfWmq2xRRL8ibrrO2HrvZSEyfRrYB
         Jus8eWzoO0BoRM2F6hIxshqjyxfPBYB8SNk5MFEK3UDyIm/No3Fek5GT7xjuksblkJfR
         rpcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=W9Ma28DLhAhSYou0Kym5hF5RHDF83Wkc16w46Iisa8A=;
        b=HMmniLL8wioAKQ5Gr3qpdxedKJuc3joonVa9W1y0KzQHkiPAUdBUI4eIMoaiudSWoS
         gwZsO1eJAERT0SrzHHtPXFkJxmqjGaGw4aZYaP5+lgk98VgQmPTfUfsdArIEhWtp8ALR
         +WqNEuJ4o5/0aQJi6uzJUuqQDXvJ13o2Xg66UJMa2BCcg+oJGZwA55Tn1BcowJdlnSRr
         d2WN9SIv4HEd/ecjWZVRWGQAWdtjTYmHfW4rGeokHG6QwhWpzNs6TOyiXvKK840zPMrQ
         xW0Tsp7yb7B50ebGkhAmeadL5Y661qZv2YV6QZicn5aV0BbWH0+GOSzGZbgZ0i8xiQN3
         m1nA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id r71si608607lff.5.2019.10.29.10.21.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Oct 2019 10:21:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92.2)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iPVBI-0006h5-VT; Tue, 29 Oct 2019 20:21:21 +0300
Subject: Re: [PATCH v10 4/5] x86/kasan: support KASAN_VMALLOC
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org,
 linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com,
 christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com,
 Andrew Morton <akpm@linux-foundation.org>
References: <20191029042059.28541-1-dja@axtens.net>
 <20191029042059.28541-5-dja@axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <a144eaca-d7e1-1a18-5975-bd0bfdb9450e@virtuozzo.com>
Date: Tue, 29 Oct 2019 20:21:03 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191029042059.28541-5-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 10/29/19 7:20 AM, Daniel Axtens wrote:
> In the case where KASAN directly allocates memory to back vmalloc
> space, don't map the early shadow page over it.
> 
> We prepopulate pgds/p4ds for the range that would otherwise be empty.
> This is required to get it synced to hardware on boot, allowing the
> lower levels of the page tables to be filled dynamically.
> 
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> 
> ---

> +static void __init kasan_shallow_populate_pgds(void *start, void *end)
> +{
> +	unsigned long addr, next;
> +	pgd_t *pgd;
> +	void *p;
> +	int nid = early_pfn_to_nid((unsigned long)start);

This doesn't make sense. start is not even a pfn. With linear mapping 
we try to identify nid to have the shadow on the same node as memory. But 
in this case we don't have memory or the corresponding shadow (yet),
we only install pgd/p4d.
I guess we could just use NUMA_NO_NODE.

The rest looks ok, so with that fixed:

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a144eaca-d7e1-1a18-5975-bd0bfdb9450e%40virtuozzo.com.
