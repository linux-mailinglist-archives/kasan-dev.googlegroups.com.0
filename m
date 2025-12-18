Return-Path: <kasan-dev+bncBAABBZNJR7FAMGQEILXX5MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DB90CCB54F
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 11:18:16 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-b6097ca315bsf895770a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 02:18:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766053094; cv=pass;
        d=google.com; s=arc-20240605;
        b=Va3MNVad7x+l6fxpDwasKMkxeRblP7syUdNtkYiRqtQKJfwzJNbg+kkM72OUjHfeR1
         tqMLNmh/bBezUB2TtUjBu8QAXb0XaByHq0yvFcbxPZHGUvECmd+RR4GLN2yTab6ckhLL
         Lo5mOvCadt2rJSC6Bo080ONPbRWCaGt0tpBri7pR35ErE63f9/z1KXEkFxCnoqyi0sdF
         m8DEkc9Yg1fz+q00vAgQ0ytu0Y1c7lnNWQeEF9LaYu6b7m4HTa12u6eT2Mv4wC8plE0x
         04KnAE4SN8Dw1QL4jnZVaj+YMqWNdegYZGbdOvNgni2gi6tm7WOY9HzSTA8WDzPqiQQ2
         JiiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=eQjIxrp+XstXFWzsfXOeByLTwlz3uuEYUPxDTjaNQMk=;
        fh=C+aXj8T5AWkhgkEZc+Tg0bMteIgyK5YzQhR9MdkKVNs=;
        b=YEqhFl1Cj81FwpGHUidBoxtt2DaDaLXACKGa2wCUrYQxas8y/hIFL0VGluInvE2CNw
         LR0VngvM7UDWvMQfW1foeYB4OSprsrAq4nIIrqph7DFz7nfXidalMhj/IokUau8tyuGc
         Z786oXWg/fawye2fndowzcUo8H9u8a8I21jA/XHwHdsUSPxomHIh44aW969IstYm9e8r
         ozSOJQMPfS0YHGreN42xclPN2nCyvqLDFpI9qSPMM8C3YDhpqgZoCrEKrVW3JKIwqKjA
         qU4utJY51kog/CeE4u8als9rb1VoL4ZjXwlS7OIOuoUxa/La9hfSMRadbY8FTQjZqSK7
         LvHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@honor.com header.s=dkim header.b=bZp9bjqT;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.192.198 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766053094; x=1766657894; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eQjIxrp+XstXFWzsfXOeByLTwlz3uuEYUPxDTjaNQMk=;
        b=YXkTlWRFTAx+CQOQ9t2mW9y/CKB6VVbnisXdMpn4w5KOfpML3g6/hTEadECMX54kNR
         7qL3f6bNq2eYKUmpiEd2TVHVx7Jxcqjqgm3J3rMftQcUrdUSVF3ReiOIB+l8RHMlx/lU
         9Hyq58FAcSFTzaraMkLotAY+KCTR+GmL6DNpqAQ+9OU2/VC3h2O1ss6P81LJlXtpzEjj
         Yn1w6apCUacHl0F3jGL7nJRS++B1PxQe540sw60r4BIN4JN14udIK9kzeyVgsBmFGkVH
         z/MJeQITCZB2NIcIRMIOpeEpxNfsOZq2WfoZ7y0tgMcDgxJl0lLzJgo9HW9GEA2yXMFA
         6gUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766053094; x=1766657894;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eQjIxrp+XstXFWzsfXOeByLTwlz3uuEYUPxDTjaNQMk=;
        b=PNoMzLe8Ko5O9DP0zbR9d0ZUrVvyEuhC7pYTytlxwkN06UxA7YMhoBk3baU8gJEhh4
         SiZQPdiblL7vCWtQIqWWdol2iJ6Ho1zhnWZ5yrMvwagspoNnwocvntubFUz17FTXrMUJ
         MJkTUwz4Y8BGuwwI+nhByRBVu7HrdBHAt6rXhbkOnPpYRWIfd6y6JVRWD3YKjepzApwV
         Fhi74d64UGxC6yFVK3t1uRtleEomnHANPqBUmz7uVHhrRzcauElFevVf4V+sJ9rRMQfU
         UaLMF8P9lPlN1L70PVqxJZ6lk6jtnYlFY+qxDUy6xvR4yC/0D0XSPoWmAM6OB1pjLCms
         eZmQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVaWqIuPyO2ql28FZxczJ3/0GhtAM0yqKJ5grA+27dVS8Z8z3HPBJOaGytBgKKRIdzFZO3ZoA==@lfdr.de
X-Gm-Message-State: AOJu0YyLwSdKxcteYmS9dbJdvrYu4yXHhQNucSJu3OhKc95jQehpqsB7
	ZXlmMHWsPH5fF21qtnYjJ+nX0nfg4CEFRnVGJe8S1/dAwQcRUxaWHU4S
X-Google-Smtp-Source: AGHT+IE3U4Hcz4Gsg0gUYxKyZVl1d1vO6PjNMEitau0rjWBl2RDygPhjnUCjD4230bih070oaoK9dQ==
X-Received: by 2002:a05:701b:2808:b0:119:e56c:189f with SMTP id a92af1059eb24-11f34ac184emr15381356c88.7.1766053094173;
        Thu, 18 Dec 2025 02:18:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWazFpz0Ihgj/c2xq7vhTSIH+TUglwzYrdzbiYXCoakEcg=="
Received: by 2002:a05:7022:69a3:b0:11b:519:fc3e with SMTP id
 a92af1059eb24-1205687f01als1833194c88.0.-pod-prod-03-us; Thu, 18 Dec 2025
 02:18:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWG12TKxRnrdmPEBcEpKqGDT7mRHI2N+IAgPhQdrAyGbq7kCOJSp3ex7tnzM23kOFlwBPK7SDzcsf4=@googlegroups.com
X-Received: by 2002:a05:7301:df44:b0:2a4:7fb3:7a96 with SMTP id 5a478bee46e88-2ac3014694emr13687341eec.36.1766053092770;
        Thu, 18 Dec 2025 02:18:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766053092; cv=none;
        d=google.com; s=arc-20240605;
        b=E3RppRO0DzEPCtL+3u6R7Nj2MRXehLQu8BHoL1v56q4GmGEHTJWDJoMPxwmUDsGXfQ
         ZdanNf/sW6AYciqRD5tZDoXt7DjO3cDdNLNbsdMzm2MRDUkyIEmGsc9b3VfL+3KRm3ZA
         T0aCQH9Xm+aF1sJiA+kjNTyNeK3HRQ5zFCarKwv9e+YtFpLvGDA2k6dkXQTWpPduidNE
         yIo7OjZDiTLKJColsgB6n6oRPpg8v/Bme1P+JSKAijYMY3uNiCdQS+4tZ3iJuNonRSIK
         WQ6HUSwgPhV6ADQyzKk6C9sts0BEu8XtMUya1hkr5QmIuDSchA5k22cm/gTEAvYuiq79
         Jhag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=SEzXO+vDjo81UC3xUG8gWrkW2zdxYChfvJ+fHaee1Vs=;
        fh=sRLLPD1NR0EEBTnxwxNZlNZHRxniOboIlZTQ47sl21w=;
        b=iw31mJ7Nib8RolxpkIyKtHZTInVZhNvsRTrCwzdEziB8+Pl4kpWFK+9QI2xVwDNgI2
         z8fiBXEE7hrZNyYWfKVNSjVb1F2gsVNGIDa9nWl3GVJ27W8uE9JLl7AyuADr5CZv0ij+
         NETG7E5brK5kh4cJ5ehxIMh02tKbwv5hgYe1ZMqOaluB79w1INO6Tz/CUknRFVkFkFfV
         8J1NH9RmrRmYO1+XWUZ9qJzpxfRHD1sqDWsQFlKPqVG9GCj58XNKGV4qjWBeY3CmPH+u
         Xi9aE24yal1p1HhYopE3m3SOyFTcoUqfXWGRK8tInaYzSoCbm1TvSnWJRMcjpWmLHrMe
         Wn9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@honor.com header.s=dkim header.b=bZp9bjqT;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.192.198 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
Received: from mta22.hihonor.com (mta22.honor.com. [81.70.192.198])
        by gmr-mx.google.com with ESMTPS id 5a478bee46e88-2b04e8c7f60si19949eec.3.2025.12.18.02.18.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Dec 2025 02:18:12 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanlinyu@honor.com designates 81.70.192.198 as permitted sender) client-ip=81.70.192.198;
Received: from w013.hihonor.com (unknown [10.68.26.19])
	by mta22.hihonor.com (SkyGuard) with ESMTPS id 4dX6543NsJzYlQ4R;
	Thu, 18 Dec 2025 18:16:08 +0800 (CST)
Received: from w022.hihonor.com (10.68.16.247) by w013.hihonor.com
 (10.68.26.19) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 18:18:08 +0800
Received: from w025.hihonor.com (10.68.28.69) by w022.hihonor.com
 (10.68.16.247) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 18:18:07 +0800
Received: from w025.hihonor.com ([fe80::5a3b:9b85:bbde:73b9]) by
 w025.hihonor.com ([fe80::5a3b:9b85:bbde:73b9%14]) with mapi id
 15.02.2562.027; Thu, 18 Dec 2025 18:18:02 +0800
From: yuanlinyu <yuanlinyu@honor.com>
To: Marco Elver <elver@google.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, Huacai Chen
	<chenhuacai@kernel.org>, WANG Xuerui <kernel@xen0n.name>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "loongarch@lists.linux.dev"
	<loongarch@lists.linux.dev>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>
Subject: RE: [PATCH v2 2/2] kfence: allow change number of object by early
 parameter
Thread-Topic: [PATCH v2 2/2] kfence: allow change number of object by early
 parameter
Thread-Index: AQHcb+kJOevioCwokUWRSuHGy2xym7UmkpaAgACVZ/A=
Date: Thu, 18 Dec 2025 10:18:02 +0000
Message-ID: <7334df3287534327a3e4a09c5c8d9432@honor.com>
References: <20251218063916.1433615-1-yuanlinyu@honor.com>
 <20251218063916.1433615-3-yuanlinyu@honor.com>
 <aUPB18Xeh1BhF9GS@elver.google.com>
In-Reply-To: <aUPB18Xeh1BhF9GS@elver.google.com>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [10.165.1.160]
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-Original-Sender: yuanlinyu@honor.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@honor.com header.s=dkim header.b=bZp9bjqT;       spf=pass
 (google.com: domain of yuanlinyu@honor.com designates 81.70.192.198 as
 permitted sender) smtp.mailfrom=yuanlinyu@honor.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=honor.com
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

> From: Marco Elver <elver@google.com>
> Sent: Thursday, December 18, 2025 4:57 PM
> To: yuanlinyu <yuanlinyu@honor.com>
> Cc: Alexander Potapenko <glider@google.com>; Dmitry Vyukov
> <dvyukov@google.com>; Andrew Morton <akpm@linux-foundation.org>;
> Huacai Chen <chenhuacai@kernel.org>; WANG Xuerui <kernel@xen0n.name>;
> kasan-dev@googlegroups.com; linux-mm@kvack.org; loongarch@lists.linux.dev;
> linux-kernel@vger.kernel.org
> Subject: Re: [PATCH v2 2/2] kfence: allow change number of object by early
> parameter
> 
> On Thu, Dec 18, 2025 at 02:39PM +0800, yuan linyu wrote:
> > when want to change the kfence pool size, currently it is not easy and
> > need to compile kernel.
> >
> > Add an early boot parameter kfence.num_objects to allow change kfence
> > objects number and allow increate total pool to provide high failure
> > rate.
> >
> > Signed-off-by: yuan linyu <yuanlinyu@honor.com>
> > ---
> >  include/linux/kfence.h  |   5 +-
> >  mm/kfence/core.c        | 122
> +++++++++++++++++++++++++++++-----------
> >  mm/kfence/kfence.h      |   4 +-
> >  mm/kfence/kfence_test.c |   2 +-
> >  4 files changed, 96 insertions(+), 37 deletions(-)
> >
> > diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> > index 0ad1ddbb8b99..920bcd5649fa 100644
> > --- a/include/linux/kfence.h
> > +++ b/include/linux/kfence.h
> > @@ -24,7 +24,10 @@ extern unsigned long kfence_sample_interval;
> >   * address to metadata indices; effectively, the very first page serves as an
> >   * extended guard page, but otherwise has no special purpose.
> >   */
> > -#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 *
> PAGE_SIZE)
> > +extern unsigned int __kfence_pool_size;
> > +#define KFENCE_POOL_SIZE (__kfence_pool_size)
> > +extern unsigned int __kfence_num_objects;
> > +#define KFENCE_NUM_OBJECTS (__kfence_num_objects)
> >  extern char *__kfence_pool;
> >
> 
> You have ignored the comment below in this file:
> 
> 	/**
> 	 * is_kfence_address() - check if an address belongs to KFENCE pool
> 	 * @addr: address to check
> 	 *
> 	[...]
> 	 * Note: This function may be used in fast-paths, and is performance
> critical.
> 	 * Future changes should take this into account; for instance, we want to
> avoid
>    >>	 * introducing another load and therefore need to keep
> KFENCE_POOL_SIZE a
>    >>	 * constant (until immediate patching support is added to the kernel).
> 	 */
> 	static __always_inline bool is_kfence_address(const void *addr)
> 	{
> 		/*
> 		 * The __kfence_pool != NULL check is required to deal with the case
> 		 * where __kfence_pool == NULL && addr < KFENCE_POOL_SIZE.
> Keep it in
> 		 * the slow-path after the range-check!
> 		 */
> 		return unlikely((unsigned long)((char *)addr - __kfence_pool) <
> KFENCE_POOL_SIZE && __kfence_pool);
> 	}

Do you mean performance critical by access global data ?
It already access __kfence_pool global data.
Add one more global data acceptable here ?

Other place may access global data indeed ?


I don't know if all linux release like ubuntu enable kfence or not.
I only know it turn on default on android device.


> 
> While I think the change itself would be useful to have eventually, a
> better design might be needed. It's unclear to me what the perf impact

Could you share the better design idea ?

> is these days (a lot has changed since that comment was written). Could
> you run some benchmarks to analyze if the fast path is affected by the
> additional load (please do this for whichever arch you care about, but
> also arm64 and x86)?
> 
> If performance is affected, all this could be guarded behind another
> Kconfig option, but it's not great either.

what kind of option ? 
It already have kconfig option to define the number of objects, here just provide
a parameter for the same option which user can change.

> 
> > --
> > 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7334df3287534327a3e4a09c5c8d9432%40honor.com.
