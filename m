Return-Path: <kasan-dev+bncBC5L5P75YUERB2MKZPXAKGQEBVLNGFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id EA45E10091E
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 17:23:05 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id l184sf13317933wmf.6
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 08:23:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574094185; cv=pass;
        d=google.com; s=arc-20160816;
        b=y1IA4rWq18mL+HLGeUrROC9buPeXG3713erzhSUiFyH2qRD+XSp17G1rR3W2hyvsil
         H9gJ+C5I/oOgb1INXs8Vwb8o6NvygtKgGumknHe+0fL5B6RIlV13OZs3tSnZr+rJ7ksz
         95HG9lK+tzStscW6sXc9TneyQGPo3p2TcI6c7Zlnjs/DSl66MkjJfQ4E2jsokXJytqKA
         6f+l1baKV/WSSsUgWhE6UXH1tk4k8KFc8CTOWx8UQyVa21iVIFzMBSL2bHAE3ZuSJ01o
         teu3h4I/GyrCR4wRvs5oR8q4iYsKp23QODaKBn77oSwXRPPupqeJflymK9zL3p9ajT6R
         im6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:to:subject
         :sender:dkim-signature;
        bh=arYTu2rfEFqEsKxYzifBdsHAO3OXXVRoMf8b54X105s=;
        b=Xk/y58qdHvgvt76RfxafARlu+CDvuReTXxj7bw5XyAWX+6Xv+l0bSWO0JZYDwqE0DP
         dXq4XUf6szA6TNQpSW0QlFpqtnFIgkEo3Ah6aqH0CgBgQX88BiSPMt4Y4QsW8m7oPOLE
         Llfp9OPMgJdYSvU6clIuevf0Fv4SVuS9Bl8pNLi7Xvj+pp+7QJ0k3tofVLAnReLopXOG
         lBYt0SDPtBbZOse9wsFDWMtM97i5ptfYSSd+Y4QiUjrvn7G416EwTuC7UNsH3v3SYsrX
         qBM3vWpbL4huFs6on7goJVzeDvzXWJZvV5xFNHalBP1hQLlEgIW6GjqvCSECZD10n4Vo
         mk0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=arYTu2rfEFqEsKxYzifBdsHAO3OXXVRoMf8b54X105s=;
        b=JO+U/P8tt0Y/EuluYoW57dldVmca62NnDvQOgLVUf8UUhWGFoAp0Elsbvp8XyfD04H
         ghYokgYexBnfZgPlu3wbQuY+g/AKi5jKeLNcLxV/VyA39bUKO9uxRG3j91q013D0cx8b
         yatmOr5lFogNHpXJig/h4LcsmVr2XplsCyUr8BjogTFcIb9zLUyP3coiV0Uk33s1WLLI
         MZvIYk4n4OntUfRWLcoxOFHDhzhitUAHhUZ0+okQkirAvIMmDrMsG28Dcyx6BlTA+XGz
         +k1UrDpI0bZGwlYhNOUnIidShJ0I0eH+2W350pvkC/sApzjUuWM62TGQ+E2XRJQFglPU
         06jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=arYTu2rfEFqEsKxYzifBdsHAO3OXXVRoMf8b54X105s=;
        b=o6vILbRAl492xp0YLnWOSCDX52gY4ayqwFTTafkhB7XCMNlADU5ZF0nUdKxXN/dU0f
         IcYQcmusfmapJ5bBwVUVNr76+H54NG6m9hz1BUpq7uO7GRwJa3drGktlyQNAXCq+X4Fx
         dvPsAgQzwsl1AomHaIlrc94cisD7eAVFkwll5mWOpGgBEhmzaeOvdh/7750x+WfW+U5A
         HXCQDRiphSmGc/3sazHDmNl+aKfkaRhumqvBLTbd3eMi6xaDtSwzqPvBPA+tL1xuO7gy
         YpUllSknH5BoyU6tuQbG9dH77M1etZs0M6Vql12cqZbghSa5ryNJOtMTOW+XQcXk2tpj
         7zoQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUsQDpCf3Czqyy/z5XGSqb33jxETof8kigTu43GplOTSDenRhb/
	2JdgmoHR0vIEJvGi/ARJmlM=
X-Google-Smtp-Source: APXvYqyltfxN2mktwviuYYH9hjgZDhiAnxx0Qmh2xquk81dFXjTls5wHsGxZ0yhxPrq4/YbdJeqzsQ==
X-Received: by 2002:a5d:6947:: with SMTP id r7mr15116787wrw.129.1574094185560;
        Mon, 18 Nov 2019 08:23:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1008:: with SMTP id a8ls14739010wrx.3.gmail; Mon,
 18 Nov 2019 08:23:04 -0800 (PST)
X-Received: by 2002:adf:f088:: with SMTP id n8mr22403935wro.115.1574094184896;
        Mon, 18 Nov 2019 08:23:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574094184; cv=none;
        d=google.com; s=arc-20160816;
        b=YXJYCXv9fH3/TIM8+dkmgF9MxZaFao5n6kpm/gZphbP/rn/SvEzWJT5csUeO76tIrd
         MvrdweGRFaBOys45IHYTIbEVcda0mGj1dMOIuoQQUfRvM1VXob3/MsdAReb8cAQeR6CQ
         F+acVxkW1Av5wxg+wPNuZq/mdDUnKQ8znlAq36/xAcgK/HANbTvg9Z8rCoSFPg7mYmfM
         D0rWAFVQQejiayQM1XFXdQtmJdO6MHjRlhpdtjkCoj4WANyizrQG0wgNBM5bN5ockXM+
         W9KhNzD6ap9ISsbSG7BdyDNnDWjVN7yr6nxTT+EhhIrZxv2FyiNWOOdpjZCSoHn1fXWS
         7HSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=Q2AValsgA1TZ0fV59sbFvWBFnQEXN0EQYl7tQn0DiFw=;
        b=rmPpymI3PRYsQFjTUul8t96vvYEgfBot1HvrGq6La1jR42RJ6jwStwFDSf0IfXSWUc
         PiK2rjUYfBBQUMJrtxl/xf9gTUTAqK6/YZiKmmecItioZEDfINRDPZgyBEvzEAzuBDZb
         0xo2W/HoTCJULw6lBHWsqcTxajth/sIi+nVG+vtsieIA1nIPD/ISR3ADrT16oDnGYmt2
         Rt2mJmhaWCExNfgl0AtPZ9rFFwYZ5V9UWXldYqvIylXPKj7eDoNpgwnBgaU3m8yS9EpC
         jX0alokGkEB479zvSh5S6LV6xUm6ECEKGWBZQ3HubSU4xiN+p1Gv7d1FOB6QLcDpmQC2
         CXKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id w10si862707wru.4.2019.11.18.08.23.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Nov 2019 08:23:04 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iWjnP-0006u4-8v; Mon, 18 Nov 2019 19:22:35 +0300
Subject: Re: [PATCH v4 1/3] kasan: No KASAN's memmove check if archs don't
 have it.
To: Nick Hu <nickhu@andestech.com>, glider@google.com, dvyukov@google.com,
 corbet@lwn.net, paul.walmsley@sifive.com, palmer@sifive.com,
 aou@eecs.berkeley.edu, tglx@linutronix.de, gregkh@linuxfoundation.org,
 alankao@andestech.com, Anup.Patel@wdc.com, atish.patra@wdc.com,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-riscv@lists.infradead.org,
 linux-mm@kvack.org, green.hu@gmail.com
References: <20191028024101.26655-1-nickhu@andestech.com>
 <20191028024101.26655-2-nickhu@andestech.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <73f11f1e-6df7-c217-e05d-049d04717600@virtuozzo.com>
Date: Mon, 18 Nov 2019 19:22:23 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <20191028024101.26655-2-nickhu@andestech.com>
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

On 10/28/19 5:40 AM, Nick Hu wrote:
> If archs don't have memmove then the C implementation from lib/string.c is used,
> and then it's instrumented by compiler. So there is no need to add KASAN's
> memmove to manual checks.
> 
> Signed-off-by: Nick Hu <nickhu@andestech.com>
> ---

Acked-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/73f11f1e-6df7-c217-e05d-049d04717600%40virtuozzo.com.
