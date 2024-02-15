Return-Path: <kasan-dev+bncBDV2D5O34IDRBYV7XGXAMGQERQGWARY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 67CE9856D41
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 20:03:00 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-6e2f6c90d6fsf1253167a34.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 11:03:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708023779; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qvro94+11QM1kPLu8CDpuuvroW3K7eSSNMftJqFKmAugrnZG5xW4GL4fUwgwV2lZ+3
         tupS8OQp40hU87V0hBn4NwKujBzSmZ3ykU5SQc0G1xGSvhRqSVjIwNqqnVGvaYhZw3K+
         mO+jKnCh/fPfIGAWpO4nqjtoyPbs+qBffTYhMbeW8xhm8BE4K+/SuVU+z9fKjBOx3mXK
         1W8YKAH+qd+/h4keWapSv7cd1VdSNbc3oasNcB/aoxQgmb8QJNZNy7MSDPYEOIYzP6zq
         8K/TYNgdjv/j40v6eoCTsBAp0D9qlbaqWT14hbi1Dokl3BOEVIy8GRsj7k2ob3Mvvw37
         RFhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=xKvF6aM76UhKOy4PKRtrRjnHkSkxoJMjN3hw+3wguRM=;
        fh=sqdtKIoV5nraT675nMcmEkTLB0LANmFG16SYoUzGIYg=;
        b=0x6tPyWL/3zdd0x/T87xuTSsRV7AQjzTiwnkLE8tkUrm9vxFCMLlnKYp+OfXzCV0Yp
         Tux+wsbceTRGk0WdxbVrJRQhB83b55/oHq1m9Az0fRlN8rIYZwML18Hel/p1LzprtmdW
         Ynonoj2xBfrBZ2xrMCbL/NrxGOlCz8sRZBDjPzunwmgxQfR3Bdc/VK41ZBwh8jJ3yWld
         HIO6DcwgdC2JTh4lFx3MumhTEKm3ns3AyUa+4ZY8p2xjvDphrKOMj3fJaxMURw/6+H/w
         9N0IvClOzDwyhmvYPo0q4AqXbRZlZ8HJhYT7t6ZKrJBvbCXWj4gq/H3c5btm8OmWwCBn
         XGvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b="wJF/rbQj";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708023779; x=1708628579; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xKvF6aM76UhKOy4PKRtrRjnHkSkxoJMjN3hw+3wguRM=;
        b=jnicuBlNJQks2ifcR105ZCNUmmTupelOHgM+o8WxeAnDIGQ6+yHagGLi+o7vf+WeZ7
         N9CgM6X1xqm95TIaVu4I4POcjrtGWKkaPFZQ0DlNlEOOokRz2kqmhf55zfMAfhQ8xTQC
         yexGUlrAuLgQDitQoIY7v4Rdg2E1zoWNn8WOkdq77dQB5m5+Copfne5PeqA3JnLjFb/k
         2X9M8gbsVI9tQPjU2do5a8ZJkYp54gftZitaFMAeSAbgm+ahHZUdMqrpe9uQyzl50fzD
         RuCLqKl6xuZzTO5kTLBeHNJ6iNuvT/v00k5OlwNSPafc0jnchETHLnEfQT+ktkb+thme
         8TCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708023779; x=1708628579;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xKvF6aM76UhKOy4PKRtrRjnHkSkxoJMjN3hw+3wguRM=;
        b=uirWodQPG/Vs9h5OcYtb6z8K3xMCHTlEfpscduLOxCpNhTKQHuTpihQWyydhM2iDK4
         PPp9yFoOukS5VQK41tIXf4X58wRaxhXys3bbXCNGaiizWyOjJMpp2sdMP73eU5i6Foad
         p3kkAt37qmRr/0eZVpi0PAb3mJXghhOBM+lzauZq3O+1uTwALvWO6fhGboUgbebOvudg
         SMVj0K5H6Dh01AtohLTXVGD7W42f0E/SIC7q6InsmCvhqpZRZlxowWUAmrCrHPvCK5Uh
         VO6u24KbjkWHwSo0LST9s5/qNCBCH1v/8FtRbSWRHoZR+kldolaka5P2lgTBnLPgbKbY
         iecQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWAAVd9/UV0uU5kZOFmmlCPwQX714kKuzJzJgCLhJ6Xiqov4Z7XqQNngTrIinuTZqVBiZyYDc61DaiyZdHbaog6GHtYDTjEsQ==
X-Gm-Message-State: AOJu0YzQp5Ao2rap7Z8noB89S6WWlOSZHx2QischaHkkGyW5i7ndy20/
	Ai8oC2/nvuVnlKshhYurpYw9ovyHwCkTsLc1fNbslQc4XgKwWqOY
X-Google-Smtp-Source: AGHT+IHZ724RkXL2m6kSUckYRalTzqs7U9h4I47xw1YwTnyyeziRP/dC9OuK9OMiq+7X0wcIoO+Btg==
X-Received: by 2002:a9d:6a02:0:b0:6e2:ebfd:4b26 with SMTP id g2-20020a9d6a02000000b006e2ebfd4b26mr2926904otn.20.1708023778928;
        Thu, 15 Feb 2024 11:02:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:58d0:0:b0:59a:12bd:cc06 with SMTP id f199-20020a4a58d0000000b0059a12bdcc06ls56070oob.2.-pod-prod-09-us;
 Thu, 15 Feb 2024 11:02:58 -0800 (PST)
X-Received: by 2002:a05:6830:18d1:b0:6e2:dbaf:11c7 with SMTP id v17-20020a05683018d100b006e2dbaf11c7mr2853772ote.8.1708023777988;
        Thu, 15 Feb 2024 11:02:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708023777; cv=none;
        d=google.com; s=arc-20160816;
        b=L2EqD6S9WzMSVy/ERLkmPu6Mc71xzh1dLoAv72i7GkPJFMMmEPCwYPPJIzWfCJVQup
         M6UkdpYIpdJowTn5CM4CXtqqMTqcTRTRyNSOQWeVOa/nD4EzQG7OnRnAM5n5gSEjjwx9
         JcTIrasmNHbBsYnyEBnSY23fqKcEZ5xP5VUZ9+ADhYj+zRwX2q9AIhPk4R9w4fDHMY0+
         6ZvS9T//YhAY/gfoJ7coBVeL7Qe+dqscfvVYDlIyV3NRys8uhRwAfoKNSEbOOrHd3LNw
         TqZpcuJtdpX7UUlBX+y5nI3iHnVLEMZkKtX3lufDZmYP6lvmZmQ2tPmGOiB34JM34gt+
         sQOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=gdINLcaBB47zjBU/4s1ytJ3Urnla7jYI4l5DT0ooHEU=;
        fh=wfS3jg8SXFy2pbqUAYLh1a2apKmv2yehWEW/l6O0BXI=;
        b=r0oWplB2TLKyP7WY8NuwgiJCYBNAHVXSxD1ph0ZZ9n6Q07+jwCXuwYmOhzoKctxxGo
         b9uG9I8SW3WVX6oz4PorPliZTWjGbOkTMOelpSuzIrl1AT3AAK7Z3uHAEpMJDnvWWr9A
         AZAK+IaMHPS0P4rUHEJ8aXhLGwwzc5JdAtcEcxuckpXU3fwaKWXdiJ2kBEG/DcD9GYft
         GSfW6QL+ivOcvv8FumAMenTg78OT4CQb+3KEm4VpW1+oqUPexKpMquI1dg+ufKnxMHRr
         Gr27xBl8oFYRvHdHTKno2gvz4FVjiVNJRqZM+wPhc9rm0gUhzXQ/HgyvN8ahUJO7n+7c
         t8+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b="wJF/rbQj";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id f5-20020a056830204500b006e2e0db4a09si151077otp.3.2024.02.15.11.02.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 11:02:57 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.50.0] (helo=[192.168.254.15])
	by bombadil.infradead.org with esmtpsa (Exim 4.97.1 #2 (Red Hat Linux))
	id 1rah0W-0000000HRTc-0sMR;
	Thu, 15 Feb 2024 19:02:52 +0000
Message-ID: <8030a0b6-0816-4313-bf70-aa602fc1a871@infradead.org>
Date: Thu, 15 Feb 2024 11:02:51 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kasan: Add documentation for CONFIG_KASAN_EXTRA_INFO
Content-Language: en-US
To: Juntong Deng <juntong.deng@outlook.com>, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, corbet@lwn.net
Cc: kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org
References: <AM6PR03MB58480786BBA03365CE454CDB994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <AM6PR03MB58480786BBA03365CE454CDB994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b="wJF/rbQj";
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=rdunlap@infradead.org
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

Hi--

On 2/15/24 10:43, Juntong Deng wrote:
> This patch adds CONFIG_KASAN_EXTRA_INFO introduction information to
> KASAN documentation.
> 
> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
> ---
>  Documentation/dev-tools/kasan.rst | 21 +++++++++++++++++++++
>  1 file changed, 21 insertions(+)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index a5a6dbe9029f..3dc48b08cf71 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -277,6 +277,27 @@ traces point to places in code that interacted with the object but that are not
>  directly present in the bad access stack trace. Currently, this includes
>  call_rcu() and workqueue queuing.
>  
> +CONFIG_KASAN_EXTRA_INFO
> +~~~~~~~~~~~~~~~~~~~~~~~
> +

Fix punctuation (run-on sentence):

> +Enabling CONFIG_KASAN_EXTRA_INFO allows KASAN to record and report more
> +information, the extra information currently supported is the CPU number and

   information. The

> +timestamp at allocation and free. More information can help find the cause of
> +the bug and correlate the error with other system events, at the cost of using
> +extra memory to record more information (more cost details in the help text of
> +CONFIG_KASAN_EXTRA_INFO).
> +
> +Here is the report with CONFIG_KASAN_EXTRA_INFO enabled (only the
> +different parts are shown)::
> +
> +    ==================================================================
> +    ...
> +    Allocated by task 134 on cpu 5 at 229.133855s:
> +    ...
> +    Freed by task 136 on cpu 3 at 230.199335s:
> +    ...
> +    ==================================================================
> +
>  Implementation details
>  ----------------------
>  

thanks.
-- 
#Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8030a0b6-0816-4313-bf70-aa602fc1a871%40infradead.org.
