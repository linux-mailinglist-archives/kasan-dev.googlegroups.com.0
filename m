Return-Path: <kasan-dev+bncBDCZTXNV3YCBBJOW6H7AKGQE6G6D4UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-f192.google.com (mail-il1-f192.google.com [209.85.166.192])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F33A2DE006
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Dec 2020 09:41:10 +0100 (CET)
Received: by mail-il1-f192.google.com with SMTP id r20sf1382664ilh.23
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Dec 2020 00:41:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608280869; cv=pass;
        d=google.com; s=arc-20160816;
        b=bp4yQtI8nvc9fMYvammGDdsCRJEywdATOrU3kT1NKhsKMjs2wlTOhK2ePzvEyN6pxt
         dp9E5oK1sVzHBrFOGAVxZjDuTK9vNP90V0VkuUm3yPftYA9h2Q7a1/ON6ov8SOraQ+ZY
         yj0hokjs1CROI0KoKXIHaARaIOathjxKRuHHzm5dNQNvveVUVoMfX30YOSFHmdfJaIYz
         8+90kNrdy1xCT4jyGyWRRVXdJIYlT8JU8Gu5tJuJtQUROOE6QYzUwEK8QftJxzQrhUIO
         pP63V7JigQb9sJXml8aG7P1ScY7oaawB4YvIKeKiwUiwzpgMxF4cXecz/yoo/TJ6yZsX
         R/5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:dmarc-filter:sender;
        bh=P+uH7CggJuPgtzTiIV+gKcUNu0hnmJbDvwLLOC7/y0s=;
        b=hBkgUrWmHX0FJo6RNzkVhwNDBz6wwRSQVdKHqfQtnHwvyEblfO9VbssbmyGMrZY7QH
         cg1l83qw+FvDf5EFs0d1N91xenr17WQHCxrKoUN41Y/2BF2LBpD3s6+vqmHddNUm01B+
         1rhu1VF+Bhd6H1i/pKQ3lmYen/mquLzsVC8/oWD+dZJBWHJTd36AAMQ7/GF3SXzLsx85
         KcfKAb8feveZ+yuvIPQ3v8iXAqtrmN/C8Swuo7F50PR34aTFsQTWi5DkEKMIW/Xr0qVD
         q1y76wFJvmol0hWmuRcqEw3bh/UFuG4N9zG4IjXNMKk/HDZpsL8MOvn49LTR/V9YceSF
         66OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mg.codeaurora.org header.s=smtp header.b=vJRVUQMr;
       spf=pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 69.72.43.15 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:dmarc-filter:subject:to:cc:references
         :from:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P+uH7CggJuPgtzTiIV+gKcUNu0hnmJbDvwLLOC7/y0s=;
        b=b46KEGkFXznOM+fgpPgk6jrX0y50h7NWF0J+QCuqIFhfMbNS/mxJcHjC/4iJEP7U9w
         ndh+/Q5hCO9CB0ZcwxUVYFuYucPkHiQhnk/Pe62BzjCkiQUUMR/gAG18v9/fV7yLDaHo
         w3olCWA9r3v4jAoIuWTNkggkXthWdgsbMgWhSUh4P7yKUG3A9HXFBx5LoqzVlGHfBjhv
         qULSgPadut3+ShQLsjkN8MIiM6zXzqX8Y0Jvv1pJEmWQH1iiERKEbEQuQ2+gmcXC2fht
         vwyRVC8Llj/MiUrHodoPgYsvCI6Yg4fLdjIzs3vnV4LfntvOI/CBaUnjlZ3vDB9GPDiF
         Fk+Q==
X-Gm-Message-State: AOAM5319QpNJCrPUh4r57aFLlQkz2ADkrvuas+LBAlDEVCrXNoSgd5jD
	1HDjLdJGNlCHCNf1T55gFAE=
X-Google-Smtp-Source: ABdhPJyKKsuUjkNCSr7fPdLrMPrxvBllXSXt6RgFfSKUuBZWoSLehHL5oITpL6Gck7P5UykAfcd1lw==
X-Received: by 2002:a92:cec4:: with SMTP id z4mr2773386ilq.217.1608280869285;
        Fri, 18 Dec 2020 00:41:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:921:: with SMTP id o1ls7867266ilt.2.gmail; Fri, 18
 Dec 2020 00:41:08 -0800 (PST)
X-Received: by 2002:a05:6e02:673:: with SMTP id l19mr2814459ilt.102.1608280868819;
        Fri, 18 Dec 2020 00:41:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608280868; cv=none;
        d=google.com; s=arc-20160816;
        b=QJUvzdOAzdNwb6bg4mbwpIvI8RmjYjJ4u+53I8Cj98+2zAsPbxZbHIEP4qfr3xoGbo
         277VK7FZzEJmRcSlvumlsjC1vEX0zyzUKyt//9MPWUyd4PZTHPsVpSXx3NhUef44wdKL
         akIuGyAa8sZqVcJwAetSe3fF7/gz7/Kx7ptg0twOhMHLFCnkWt0MHkmfXKHoH+VJvRdW
         bcI18P30Pn89hGiqrSXwaGK1Yiy11Hbk5Y3vqOf3d5kiJg42VV+gW68D+Vf0arQlMJ7n
         xQD/hBB+wZCRVxL4aquQHKhiKT/IZNF6JOFlF6TzLXfZHkEz00q68dvZhU5N8AD+9CLL
         8R+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dmarc-filter:sender:dkim-signature;
        bh=yrrdAHl57xD1ZKFSPxrUavZvcdjFnMVSrR6E/m0F+VM=;
        b=LhBIjthm30Esx3jbBFzH1ijSi/pTWN13BWGuB0pHWxvtssvgvzqb9+F/WB49NyPInp
         UGaBPwKH5FYGHsgg9p/EOm7JxeJAAUrkMnxMv4dyvCu8dXNhaa1S/QAdYo5gy1CWM7dQ
         IvjYCY2T9DoBqkNVMjvk3N2IUTK316sfgcSS0zTZ/UJro0NjYauF7xykoWTrbFpinrzS
         AAdL3bWhD5zH4N72jdTNgN/Jzqstw8fHIvtr1GfJIyHodoW0STrUQgOwIiRSJfkaKpo2
         6lDNIqwtkvpSHQzkk0Okx81LZ9TLQY6ZQKsGSqSfUGy1F4lFb2B41SHoOPoFPbBEJuFy
         y2Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mg.codeaurora.org header.s=smtp header.b=vJRVUQMr;
       spf=pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 69.72.43.15 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
Received: from m43-15.mailgun.net (m43-15.mailgun.net. [69.72.43.15])
        by gmr-mx.google.com with UTF8SMTPS id k131si635072iof.1.2020.12.18.00.41.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Dec 2020 00:41:08 -0800 (PST)
Received-SPF: pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 69.72.43.15 as permitted sender) client-ip=69.72.43.15;
X-Mailgun-Sending-Ip: 69.72.43.15
X-Mailgun-Sid: WyIyNmQ1NiIsICJrYXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNvbSIsICJiZTllNGEiXQ==
Received: from smtp.codeaurora.org
 (ec2-35-166-182-171.us-west-2.compute.amazonaws.com [35.166.182.171]) by
 smtp-out-n04.prod.us-west-2.postgun.com with SMTP id
 5fdc6b1b3d3433393db6f3aa (version=TLS1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256); Fri, 18 Dec 2020 08:40:59
 GMT
Sender: vjitta=codeaurora.org@mg.codeaurora.org
Received: by smtp.codeaurora.org (Postfix, from userid 1001)
	id C9607C433ED; Fri, 18 Dec 2020 08:40:59 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.4.0 (2014-02-07) on
	aws-us-west-2-caf-mail-1.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-2.9 required=2.0 tests=ALL_TRUSTED,BAYES_00,
	NICE_REPLY_A,SPF_FAIL autolearn=no autolearn_force=no version=3.4.0
Received: from [192.168.0.105] (unknown [182.18.191.137])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	(Authenticated sender: vjitta)
	by smtp.codeaurora.org (Postfix) with ESMTPSA id BD45CC433C6;
	Fri, 18 Dec 2020 08:40:54 +0000 (UTC)
DMARC-Filter: OpenDMARC Filter v1.3.2 smtp.codeaurora.org BD45CC433C6
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
References: <1607576401-25609-1-git-send-email-vjitta@codeaurora.org>
 <CAG_fn=VKsrYx+YOGPnZw_Q5t6Fx7B59FSUuphj7Ou+DDFKQ+8Q@mail.gmail.com>
 <77e98f0b-c9c3-9380-9a57-ff1cd4022502@codeaurora.org>
 <CAG_fn=WbN6unD3ASkLUcEmZvALOj=dvC0yp6CcJFkV+3mmhwxw@mail.gmail.com>
 <6cc89f7b-bf40-2fd3-96ce-2a02d7535c91@codeaurora.org>
 <CAG_fn=VOHag5AUwFbOj_cV+7RDAk8UnjjqEtv2xmkSDb_iTYcQ@mail.gmail.com>
 <255400db-67d5-7f42-8dcb-9a440e006b9d@codeaurora.org>
 <f901afa5-7c46-ceba-2ae9-6186afdd99c0@codeaurora.org>
 <CAG_fn=UjJQP_gfDm3eJTPY371QTwyDJKXBCN2gs4DvnLP2pbyQ@mail.gmail.com>
 <7f2e171f-fa44-ef96-6cc6-14e615e3e457@codeaurora.org>
 <CAG_fn=VihkHLx7nHRrzQRuHeL-UYRezcyGLDQMJY+d1O5AkJfA@mail.gmail.com>
 <601d4b1a-8526-f7ad-d0f3-305894682109@codeaurora.org>
 <CAG_fn=V8e8y1fbOaYUD5SfDSQ9+Tc3r7w6ZSoJ-ZNFJvvq-Aeg@mail.gmail.com>
 <9e0d2c07-af1f-a1d3-fb0d-dbf2ae669f96@codeaurora.org>
 <CAG_fn=UXQUGiDqmChqD-xX-yF5Jp+7K+oHwKPrO9DZL-zW_4KQ@mail.gmail.com>
From: Vijayanand Jitta <vjitta@codeaurora.org>
Message-ID: <48df48fe-dc36-83a4-1c11-e9d0cf230372@codeaurora.org>
Date: Fri, 18 Dec 2020 14:10:50 +0530
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.5.1
MIME-Version: 1.0
In-Reply-To: <CAG_fn=UXQUGiDqmChqD-xX-yF5Jp+7K+oHwKPrO9DZL-zW_4KQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-GB
X-Original-Sender: vjitta@codeaurora.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mg.codeaurora.org header.s=smtp header.b=vJRVUQMr;       spf=pass
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



On 12/17/2020 4:24 PM, Alexander Potapenko wrote:
>>> Can you provide an example of a use case in which the user wants to
>>> use the stack depot of a smaller size without disabling it completely,
>>> and that size cannot be configured statically?
>>> As far as I understand, for the page owner example you gave it's
>>> sufficient to provide a switch that can disable the stack depot if
>>> page_owner=off.
>>>
>> There are two use cases here,
>>
>> 1. We don't want to consume memory when page_owner=off ,boolean flag
>> would work here.
>>
>> 2. We would want to enable page_owner on low ram devices but we don't
>> want stack depot to consume 8 MB of memory, so for this case we would
>> need a configurable stack_hash_size so that we can still use page_owner
>> with lower memory consumption.
>>
>> So, a configurable stack_hash_size would work for both these use cases,
>> we can set it to '0' for first case and set the required size for the
>> second case.
> 
> Will a combined solution with a boolean boot-time flag and a static
> CONFIG_STACKDEPOT_HASH_SIZE work for these cases?
> I suppose low-memory devices have a separate kernel config anyway?
> 

Yes, the combined solution will also work but i think having a single
run time config is simpler instead of having two things to configure.

> My concern is that exposing yet another knob to users won't really
> solve their problems, because the hash size alone doesn't give enough
> control over stackdepot memory footprint (we also have stack_slabs,
> which may get way bigger than 8Mb).
> 

True, stack_slabs can consume more memory but they consume most only
when stack depot is used as they are allocated in stack_depot_save path.
when stack depot is not used they consume 8192 * sizeof(void) bytes at
max. So nothing much we can do here since static allocation is not much
and memory consumption depends up on stack depot usage, unlike
stack_hash_table where 8mb is preallocated.
-- 
QUALCOMM INDIA, on behalf of Qualcomm Innovation Center, Inc. is a
member of Code Aurora Forum, hosted by The Linux Foundation

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/48df48fe-dc36-83a4-1c11-e9d0cf230372%40codeaurora.org.
