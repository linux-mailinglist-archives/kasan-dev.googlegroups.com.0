Return-Path: <kasan-dev+bncBC3JRV7SWYEBBBP2Q3ZAKGQEXLGHTCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id CD9A015843D
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 21:28:54 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id m18sf6134341pgn.18
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 12:28:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581366533; cv=pass;
        d=google.com; s=arc-20160816;
        b=i9oynl5HVCi0tMoE93AvYsLPmR76mlA+r8GaCE6MgT5BPsJJ4H//cPIms0yOIGjvAV
         4VAe6ayegI2RTIcqO0tUMG+PI+2fX0k/Bnhnxu0QSP25BqBdd+IkwPa6/W2wj9825g3i
         uDY22yhGJemhzr2/KwOFYjq40ePJwfd9HoWfhP+jS1/THqA0+mM1Rgs/lOwU4Ia4f8mt
         6a7YQw5iYqoI9Usl6qc47NV5yjWQV/UNqKF1VVawJ4bsq71JCQ/c6nv1+bkx9byzWxdf
         dr/CybJWGhZEm2WH1FFe8ZqPAiaLoM6Zp98/ocIAjgQMYnJJCx7uCFXJEgaOdD/2O9Ak
         p+Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:sender:dkim-signature;
        bh=hZXmQnV8iz0pGsN5dRUyCLXnXzN5clPePGmDLCiKb58=;
        b=O34qilNnDPuRis7dUIydmw62eY1eeYv3u/zMCmIzifXAsSJwCxGncvBvBlplp5rdZW
         memg/vsNTUlv6AzfeesGNU1ceiCPS00D3ipIGIIs8W+Z8qAG2rJOadsdLDBaSm/58KwF
         NK5Iny/GH8iWS8a6AWsPXWN/c3P8h+z2d8T8Yb63jws5+WwEyqNXTh12LwYatvzAY41m
         LjxhYPO3bV5MKbqnAXG0YoOc0DUihcPPJ80Wzkd9KnwAINRe3L7D32gugpSSSmyZOV1C
         /qjc6UCAsh+GBoiH1jB0ePree4zVDY0cqfSS4cAct0MKhxiIcr6aAkpHBEJ0l7EcN1Tv
         KfWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=PYvlJVCx;
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=boris.ostrovsky@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hZXmQnV8iz0pGsN5dRUyCLXnXzN5clPePGmDLCiKb58=;
        b=VYieVKEFN5ER0ekdWGiCX7l6SZwK6wjvqjZmQFpOTZf5haA8NUvJBgAOYW6vHiOLhN
         P6X6JpCB75+QGPpUxzBTz2yyZdmxrJnQYKBgaEpW5PhJsYOXp6u4V/Bf4ioDY67NcABe
         8Kt7SUq06MBhe6T+mzrqBYihZDM56K6ZkmFvpzQat/ujscDnADVtjlRcDQkePbgLbU5+
         W//+Chunf6sv5eQrOWzTk/Q3b0wFMLX9VzCweklYd1xxlwf23QXR7hvogXf0DCEW6Xee
         XTcSe4fqFivPujYdAssZmc4kdS9s3rmWBiBiM07gTgliJVYzwKVN9oln81FBCJeWCcAO
         ciBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hZXmQnV8iz0pGsN5dRUyCLXnXzN5clPePGmDLCiKb58=;
        b=qkfo8oUf0lddM0S+HqAmPZpOV6etxdupG8RN8SGZRSI9E6sFl59d6w3M0dr2tzNTME
         r5QBPfoO6zTdnrOmXzzvhiBhdN+fTG5MMiBc8O1sgkmAuZ9Vp6MBPPR2reUPi/kQTNJt
         eI6gNOx0+j1oz4kiukrKWvdUd9mU1WbfTpwO/EvMaN5fG30vjnZilnoHcmfmF+rckM+9
         CFg5h7TYz/fONxjcYXC7DW5a8+e039MBr+a3MF1K+LO7U78eZeYLPolA6adeZTa0no4r
         BevWuWYhzibbisle9x70LLzbH0siZVC95t7hBVs8lWnz97cDYL9lhkgkI/S7QUhwfmfk
         QbhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX67uPwOkPlPp++OACPzcnuOvqrNYaC82+9ggTCX5SQ92yslFVw
	/GhRwh8Yi9GQ3YmdcC5zAkc=
X-Google-Smtp-Source: APXvYqw3LmAtphurJ7M5WMKguwi9w3Uo9lDM+JMe0DAWg/AGJPwCt3NH1ot8ImYefoAGr9g8IL1NiA==
X-Received: by 2002:a63:f648:: with SMTP id u8mr3460219pgj.148.1581366533542;
        Mon, 10 Feb 2020 12:28:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9887:: with SMTP id s7ls4231637plp.9.gmail; Mon, 10
 Feb 2020 12:28:53 -0800 (PST)
X-Received: by 2002:a17:90a:e291:: with SMTP id d17mr1016918pjz.116.1581366533120;
        Mon, 10 Feb 2020 12:28:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581366533; cv=none;
        d=google.com; s=arc-20160816;
        b=F6YrODNQDBtGWyh7QiHwEjNcSJqIB/M9bkaIrL4SCWGr97R3ww9V3z3tTVtr3zKVH/
         0+qM7f24WFXXZqr1fM3l2Bo4xuWRfFF3XlBgDAc8URnNZAd1khIuUgqHwqgcSYW3nA5U
         lraUfBZaxKYXtCWLpeMHBSmfF7fUP8KOIkbo1dychdvXAJujrfwZduZjlZ6RZiVgfpg1
         X6qxAug0r4V0uW0YJFj5pyWRxDwMXz0u7jgdSQZ5UFAGox2lpBcst5GFGxoTjur54EQV
         O9zUgwrC/B5hgzZeidbCU+A3eNfu8W6svwHawzQtqCgqm6AFUqgFwG+A43b9Bm+ADTXs
         IImg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :dkim-signature;
        bh=0p/9Qs6uC0BaB+0SCy7KvfzsMvYfbq6Mgk/yMvp8PgY=;
        b=aHfvonqjFVCiutMc97MbmPPXsdo8gewf2PetSf3JNLYIAaGvvFIyWl1EvKmy7I/NB5
         WeJJO7Ds2ymfBK5LqdN3e4zyGE4AHwhNNioamv1FSQ8MlWJAkwxpdstVBOiyA2Iw0o3r
         6Z6maI5ZVdngFa/5anPQIyBAcExlBHiXfk+yKBJq5iry1Qmgb+0SVYNpPUxnTlyQdueI
         wdGvNaFSrBuY3rn9h0sFEb2yOvZWOylGaXs3/QnI3OpeQ+gHtJgJbVKwTnP+Jar79KAI
         lhlQuw0Q1uGjr+6QT/R53XS2rCqWy5MMe1l3ZVJ8SfxGGakrAq644a3miAbjQSoiuVvx
         uJsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=PYvlJVCx;
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=boris.ostrovsky@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2130.oracle.com (userp2130.oracle.com. [156.151.31.86])
        by gmr-mx.google.com with ESMTPS id j10si77724pgg.2.2020.02.10.12.28.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Feb 2020 12:28:53 -0800 (PST)
Received-SPF: pass (google.com: domain of boris.ostrovsky@oracle.com designates 156.151.31.86 as permitted sender) client-ip=156.151.31.86;
Received: from pps.filterd (userp2130.oracle.com [127.0.0.1])
	by userp2130.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 01AKSnft095974;
	Mon, 10 Feb 2020 20:28:49 GMT
Received: from aserp3030.oracle.com (aserp3030.oracle.com [141.146.126.71])
	by userp2130.oracle.com with ESMTP id 2y2k87y4x4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=FAIL);
	Mon, 10 Feb 2020 20:28:49 +0000
Received: from pps.filterd (aserp3030.oracle.com [127.0.0.1])
	by aserp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 01AKS7tZ173240;
	Mon, 10 Feb 2020 20:28:48 GMT
Received: from aserv0121.oracle.com (aserv0121.oracle.com [141.146.126.235])
	by aserp3030.oracle.com with ESMTP id 2y26htm1rt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 10 Feb 2020 20:28:48 +0000
Received: from abhmp0002.oracle.com (abhmp0002.oracle.com [141.146.116.8])
	by aserv0121.oracle.com (8.14.4/8.13.8) with ESMTP id 01AKSlLV016847;
	Mon, 10 Feb 2020 20:28:47 GMT
Received: from bostrovs-us.us.oracle.com (/10.152.32.65)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Mon, 10 Feb 2020 12:28:47 -0800
Subject: Re: [PATCH v3 2/4] x86/xen: add basic KASAN support for PV kernel
To: Sergey Dyasli <sergey.dyasli@citrix.com>, xen-devel@lists.xen.org,
        kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Juergen Gross <jgross@suse.com>,
        Stefano Stabellini
 <sstabellini@kernel.org>,
        George Dunlap <george.dunlap@citrix.com>,
        Ross Lagerwall <ross.lagerwall@citrix.com>,
        Andrew Morton <akpm@linux-foundation.org>
References: <20200207142652.670-1-sergey.dyasli@citrix.com>
 <20200207142652.670-3-sergey.dyasli@citrix.com>
From: Boris Ostrovsky <boris.ostrovsky@oracle.com>
Autocrypt: addr=boris.ostrovsky@oracle.com; keydata=
 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
 Jg6OxFYd01z+a+oL
Message-ID: <1d99ff54-dc81-85a8-0ecb-c3ee4d418f2e@oracle.com>
Date: Mon, 10 Feb 2020 15:29:26 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.1
MIME-Version: 1.0
In-Reply-To: <20200207142652.670-3-sergey.dyasli@citrix.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9527 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 phishscore=0
 bulkscore=0 adultscore=0 malwarescore=0 suspectscore=0 mlxscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2001150001 definitions=main-2002100148
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9527 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 lowpriorityscore=0
 suspectscore=0 bulkscore=0 phishscore=0 mlxlogscore=999 mlxscore=0
 malwarescore=0 impostorscore=0 clxscore=1011 spamscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2001150001 definitions=main-2002100148
X-Original-Sender: boris.ostrovsky@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=PYvlJVCx;
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates
 156.151.31.86 as permitted sender) smtp.mailfrom=boris.ostrovsky@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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



On 2/7/20 9:26 AM, Sergey Dyasli wrote:
> Introduce and use xen_kasan_* functions that are needed to properly
> initialise KASAN for Xen PV domains. Disable instrumentation for files
> that are used by xen_start_kernel() before kasan_early_init() could
> be called.
>
> This enables to use Outline instrumentation for Xen PV kernels.
> KASAN_INLINE and KASAN_VMALLOC options currently lead to boot crashes
> and hence disabled.
>
> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>

Xen bits:

Reviewed-by: Boris Ostrovsky <boris.ostrovsky@oracle.com>


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d99ff54-dc81-85a8-0ecb-c3ee4d418f2e%40oracle.com.
