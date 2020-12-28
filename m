Return-Path: <kasan-dev+bncBDCZTXNV3YCBB3GIUX7QKGQEHTZW4MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-f191.google.com (mail-qt1-f191.google.com [209.85.160.191])
	by mail.lfdr.de (Postfix) with ESMTPS id F1C652E340B
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Dec 2020 05:51:57 +0100 (CET)
Received: by mail-qt1-f191.google.com with SMTP id v9sf4510316qtw.12
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Dec 2020 20:51:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609131117; cv=pass;
        d=google.com; s=arc-20160816;
        b=TGeZpRtYXfQrpdi1+GbYpeQ8FMQy7eI/oQ1Zias81U2h/vJEoAJYls96dtNUxO9jJz
         Sq+tRYhm/pM9gjs04Wc+sdPgX+g4kCa9P33aJW/rP5zaTwn+FjXc1VeGj5OTnP4btt6i
         nidsSiRrKPFIxbOlsySi8idh028Ko7LtK3htdDFxt9pi0/9uSlWQKoayXw0ISJNfGEcu
         d8Yi8+qK6f34DOaYXmAWXd51tKYoJweHwOmSh/CxSmwwjS2rF2u2XR40AE3CA9GYrVHl
         nz8ZsI8ikLamD1G5MGwFjbhRdhrLzRjVkVfSRBDkvzktsKiIDDKot/J+oov7Fl0L7bxG
         X5sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:dmarc-filter:sender;
        bh=6FITKyB3irp2kxUTg+BWWeRmTLuJJm7/TVVw8zxGx+A=;
        b=idkbSsNLm1olJ843mNpk/V1ub69st+0BQlYHNMqlUoPNMspZYcWWc624/75UrCPZfN
         D4CvPU/L/mK4D62au66Rl41eEKCWZwTqiNNxXuVL0f2kvXDXXaDISehYF4Xh7Zsif2dB
         cuJaAHyJ9T/IE6dVsIORlyk/iDQGcCR6/ub46rkX8bSSkUTMi3PcH9NBarfJ7/IUu6Gb
         8A6qZ+DB11tIvmks3uOQ85qfLBE2dq/d6gAW/ezkwbWE/IhSZgcDmYrNxE5sUFNl6tME
         WzxDEsn9a7Ax12Y3PIFePsXmOPN85BcZam13FC6OS1PGWHPldOB0jhRl1pJWi1WTDAtz
         SQhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mg.codeaurora.org header.s=smtp header.b=TYS2ayRx;
       spf=pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 69.72.43.15 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:dmarc-filter:subject:to:cc:references
         :from:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6FITKyB3irp2kxUTg+BWWeRmTLuJJm7/TVVw8zxGx+A=;
        b=DhyDRtHQlzrXvduodj/qBxvi/DHYR892jUtYWwma/79w5ELwexgOXV9XJBxqkLYcQJ
         dSD2Ofp7Z4c9A1mTAzfBOYoiIGV3QozhijkgZkW7KBEMI1JFM8ONNwvQaYi40I8csEKk
         Jm982tAp8bi1EKJS52mmkI/8r03saNg3yB3C0AwfanIXhcxbyrgWsarQv7o+xwncTHsn
         uR4f26b2JpfAQHnbehKW17rZ1V6gih+7pQh1+31yahvNFPmFvuy3dom1kRDo+wMFlXly
         hWu54YoJJjrBIqgz6yEtACD8Wv5sOSwqNuWN3HD3WaLn1c7GUTtchtije7lfd1WRAiSR
         QtYg==
X-Gm-Message-State: AOAM530vr8LX8F6demcKgFQpqJCxq4rpFdQOH8cgoTdcltxK/sdOFbye
	7ZbqEvZHGR/Hu/AmBXDSM9c=
X-Google-Smtp-Source: ABdhPJxguxUioo6Y6NdqnoJJuNqImpLBKHldo9ANu8p1jcVWBZPay7Pl/zmxoxss42k/Cga9OjuZ+Q==
X-Received: by 2002:a0c:bf12:: with SMTP id m18mr8062857qvi.40.1609131116769;
        Sun, 27 Dec 2020 20:51:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:c001:: with SMTP id u1ls27738643qkk.1.gmail; Sun, 27 Dec
 2020 20:51:56 -0800 (PST)
X-Received: by 2002:a37:4394:: with SMTP id q142mr42469311qka.113.1609131116347;
        Sun, 27 Dec 2020 20:51:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609131116; cv=none;
        d=google.com; s=arc-20160816;
        b=oLd4C0W3YCkilv2i+RQKXz07nIO10sEhvZNS+iA2uBZ5et3sCQ05QtJD8Tt740GExs
         tEhGu7tr9t+tv7AEvnYQk/q9yYGxUKkWOt7w8EVIkGpv6fKZJPLdpWK6VldS87+ngEXD
         eQSg6O4h9ZtIAH+rQ7wB3tyZlEikC08+XuNIWJYhXuPgTwIcq+TZDoih+lvJdNDwSq6a
         yP2QEJJXamGtel2cQjiSNM8/hXS85fBrcx90c0FKIR5QL8G7S4r1nQPJZocr9EZ6egiV
         szVDUYRk7UKlxYYfgbFzq8ARNOb4Of+eKMIAlNmMq+H/vdNsc1YnOyh0jf5NFJTjMPmB
         P++g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dmarc-filter:sender:dkim-signature;
        bh=BO8IW9Q/PT7UqzydT2jMWi2wLodhoA3BrQp/tn36dPI=;
        b=yKjNtfzRSmihmpC04bVJCsp7Ve7F8WwpgNbNGoP5DZfy6Ce0FanrlBzv4QwdZL3Sja
         mvbT5CkN5KHrbCxrkbdcc9J7AipcgO85O2TCUWwPuRGj0ZPSB+qp7LSZpCjxjnwWmLnl
         fDIkqsD2rVbEUOmZ0mhx/iSwvcMPp6G6PvDrQYWiaQfy4jQSL7j87bLkkqqUdcxU3HmA
         pXpz6ron1kSsWM4GyOl9HfFJD7RfmogacOYUMgwDkQv92xvOcA3RT2zfwjMKRUDbm31s
         XBIWOdSptCGZy9sraR6ZJ5bKhNCADHOaESzc7479kjCaXR5BMKNifC1w/8rVMkC7UaJL
         PxLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mg.codeaurora.org header.s=smtp header.b=TYS2ayRx;
       spf=pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 69.72.43.15 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
Received: from m43-15.mailgun.net (m43-15.mailgun.net. [69.72.43.15])
        by gmr-mx.google.com with UTF8SMTPS id l32si2614935qta.3.2020.12.27.20.51.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 27 Dec 2020 20:51:56 -0800 (PST)
Received-SPF: pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 69.72.43.15 as permitted sender) client-ip=69.72.43.15;
X-Mailgun-Sending-Ip: 69.72.43.15
X-Mailgun-Sid: WyIyNmQ1NiIsICJrYXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNvbSIsICJiZTllNGEiXQ==
Received: from smtp.codeaurora.org
 (ec2-35-166-182-171.us-west-2.compute.amazonaws.com [35.166.182.171]) by
 smtp-out-n07.prod.us-east-1.postgun.com with SMTP id
 5fe96463b00c0d7ad4f4d00b (version=TLS1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256); Mon, 28 Dec 2020 04:51:47
 GMT
Sender: vjitta=codeaurora.org@mg.codeaurora.org
Received: by smtp.codeaurora.org (Postfix, from userid 1001)
	id E0D2AC43462; Mon, 28 Dec 2020 04:51:46 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.4.0 (2014-02-07) on
	aws-us-west-2-caf-mail-1.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-3.7 required=2.0 tests=ALL_TRUSTED,BAYES_00,
	NICE_REPLY_A,SPF_FAIL autolearn=unavailable autolearn_force=no version=3.4.0
Received: from [192.168.0.106] (unknown [182.18.191.136])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	(Authenticated sender: vjitta)
	by smtp.codeaurora.org (Postfix) with ESMTPSA id B5DEBC433C6;
	Mon, 28 Dec 2020 04:51:41 +0000 (UTC)
DMARC-Filter: OpenDMARC Filter v1.3.2 smtp.codeaurora.org B5DEBC433C6
Subject: Re: [PATCH v3] lib: stackdepot: Add support to configure
 STACK_HASH_SIZE
To: Alexander Potapenko <glider@google.com>
Cc: Minchan Kim <minchan@kernel.org>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, dan.j.williams@intel.com,
 broonie@kernel.org, Masami Hiramatsu <mhiramat@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Konovalov <andreyknvl@google.com>, qcai@redhat.com,
 ylal@codeaurora.org, vinmenon@codeaurora.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <CAG_fn=UjJQP_gfDm3eJTPY371QTwyDJKXBCN2gs4DvnLP2pbyQ@mail.gmail.com>
 <7f2e171f-fa44-ef96-6cc6-14e615e3e457@codeaurora.org>
 <CAG_fn=VihkHLx7nHRrzQRuHeL-UYRezcyGLDQMJY+d1O5AkJfA@mail.gmail.com>
 <601d4b1a-8526-f7ad-d0f3-305894682109@codeaurora.org>
 <CAG_fn=V8e8y1fbOaYUD5SfDSQ9+Tc3r7w6ZSoJ-ZNFJvvq-Aeg@mail.gmail.com>
 <9e0d2c07-af1f-a1d3-fb0d-dbf2ae669f96@codeaurora.org>
 <CAG_fn=UXQUGiDqmChqD-xX-yF5Jp+7K+oHwKPrO9DZL-zW_4KQ@mail.gmail.com>
 <48df48fe-dc36-83a4-1c11-e9d0cf230372@codeaurora.org>
 <6110a26b-dc87-b6f9-e679-aa60917403de@codeaurora.org>
 <CAG_fn=VjejHtY8=cuuFkixpXd6A6q1C==6RAaUC3Vb5_4hZkcg@mail.gmail.com>
 <X+EFmQz6JKfpdswG@google.com>
 <d769a7b1-89a2-aabe-f274-db132f7229d1@codeaurora.org>
 <CAG_fn=UUo3tP1XtdOntNG1krvbPV7pmE9XXwMyuhL2gMUoc4Jw@mail.gmail.com>
From: Vijayanand Jitta <vjitta@codeaurora.org>
Message-ID: <dbce90d4-17e5-15a3-4336-9efede16c772@codeaurora.org>
Date: Mon, 28 Dec 2020 10:21:31 +0530
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.6.0
MIME-Version: 1.0
In-Reply-To: <CAG_fn=UUo3tP1XtdOntNG1krvbPV7pmE9XXwMyuhL2gMUoc4Jw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-GB
X-Original-Sender: vjitta@codeaurora.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mg.codeaurora.org header.s=smtp header.b=TYS2ayRx;       spf=pass
 (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org
 designates 69.72.43.15 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
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



On 12/23/2020 8:10 PM, Alexander Potapenko wrote:
>>
>> Michan, We would still need config option so that we can reduce the
>> memory consumption on low ram devices using config.
>>
>> Alex, On this,
>> "I also suppose device vendors may prefer setting a fixed (maybe
>> non-default) hash size for low-memory devices rather than letting the
>> admins increase it."
>> I see kernel param swiotlb does similar thing i.e; '0' to disable and
>> set a value to configure size.
>>
>> I am fine with either of the approaches,
>>
>> 1. I can split this patch into two
>>    i)  A bool variable to enable/disable stack depot.
>>    ii) A config for the size.
> 
> I still believe this is a more appropriate solution.
> 
> Thanks in advance!
> 

Thanks, Will work on a patch with above approach.

Thanks,
Vijay
-- 
QUALCOMM INDIA, on behalf of Qualcomm Innovation Center, Inc. is a
member of Code Aurora Forum, hosted by The Linux Foundation

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dbce90d4-17e5-15a3-4336-9efede16c772%40codeaurora.org.
