Return-Path: <kasan-dev+bncBC5L5P75YUERBQ4R3LXAKGQEAY3BFZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E84F105271
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 13:53:24 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id c11sf1878470edv.23
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 04:53:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574340803; cv=pass;
        d=google.com; s=arc-20160816;
        b=N6+ZIu5QnbVbSiO3UrKhDFvj7GYp/ubrgfJnD2kaKifnADnyC59ONNVNIDP1VCi5Y1
         V8y4KO3Cj0amgHrHFnIW3uEpu/JkobYIB4t7qAlV/iJRtaVze7pd54+U2XPwphZm9aJ2
         ixE+FnrG5Ed4BBukEyzmU/FNoBFpv4CpEE4nbK/sFr0KXX0LzCChet19vZeN3AubH6og
         NCLh8gtSvta7tc/c8nusIB6ABtWw4x4ZPTH0ow56Kv3VXFEpdXw5ncP0Q0uqSMfgBmQr
         S/k/jO6BlTo4OFnWVMrceYrLttYi/vN8RLPf7AOqXCmtCSqoBO/S19Nb8yxjALK+PIRH
         sZjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=loiIzNmc6pgh3rSD8rlDGLxu72FLQnS0hRsRK7YJajQ=;
        b=KT5kSL3mJmytEkChacD6gLoit5hPDkn5wcSONSEwdLAJC2+PzeKsC3oxOYkkjMe+eo
         wR6YcCFGP0uL7hLPq2/+gImrWf6mT+rALrSspj6zNVehOALLb1jzVdjHjs+cixNfkzVe
         CGxQJ8GmYOAxeSmXLal/lbfyt3XvhvFeLI4MbKnL52oCWLL8dFkXeV+yXbtiwL+UEc9u
         UWMYzwp6v2pRispnhYP5dZA9J6z0187BQD6WwFm0aWPP3hqcFPPF+DO8figMkt7mV0tz
         zahRLvlo+qw/gwwZdj6gyWVu3a4JXuvgI1a5Q3xCPhhUA7YlJqdmIQHbpxLqke7DSKd6
         R9Fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=loiIzNmc6pgh3rSD8rlDGLxu72FLQnS0hRsRK7YJajQ=;
        b=KKGJlxGw718egiulPu704gZZ+ZC3G4uWsG2ELRY6UqY2QMSFsW+abBWZtG7c1o5maY
         wwSdQ/gEFB+rVcBcsyxJWzKfIPVvAZAoBvHz5NCqChLdBwPM9HBI+HP5RA7PQEX3nYqi
         WVQpl2yw9zYXg0y6gzU6aLEBOf87h0MdBcyMmmyCtbZfoVUwQeR624rzVe4LY/VxqMFA
         mzyg9lJF9M1hz9Jxrj3g4Mof6PXF0PTUamrmvp9C97k5mdigd6aURixxeTOiBurcd+7l
         l2ribawtYYGUIET/hj0sHnPmp9rNe0pOMJwmXjvsBEFtWH1veoXj4A9QbZ6MTj3aI17Q
         SOvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=loiIzNmc6pgh3rSD8rlDGLxu72FLQnS0hRsRK7YJajQ=;
        b=AIReZPCD/m/yyJYgdwpl5idqrJULIdUobq2i8c+deIu7dw+C3wUBwB8NmqdXIfMc4w
         I/Tl8FN1XR+/4UdYlsw5DrOuipifeW+TuAwF2HtPPJL+E5B+sHR4/gwd9Nuk7ptecDX6
         3VvOdZ+sg/CZCFPH5R+rfLG8HI/KelKP5vKo3zXG4gIs+obMXwycW57LA0+EaYM7n2md
         ZlG05Hojd+aIhNHXx7MYYkpKyQPQ/Ulpps881PWaES3W+YFLNJgLA6PRWkqjZxn65LVU
         oTH+TiVUUxglupqePvfX8EcA4HY/OtfS0pIEyHc/r5QmkfUZ9BtsXX2TqDbsvzrFQVoc
         /EMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXLDdVdm8KpTGkyxNnxc+ZOXRT2R36y+jQkbjvBVUqk5WP5Vkp0
	ZGsFrlDUOKeqzx2nbj2Uaac=
X-Google-Smtp-Source: APXvYqxBscizA5BO8TsCmj0isV5g+UKMBy9iscbI6GJHinNGlIr8Fd5jm+uHa53qSxyFp7SrG59lGA==
X-Received: by 2002:a17:906:d93b:: with SMTP id rn27mr14033436ejb.184.1574340803893;
        Thu, 21 Nov 2019 04:53:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:2175:: with SMTP id rl21ls2748917ejb.3.gmail; Thu,
 21 Nov 2019 04:53:23 -0800 (PST)
X-Received: by 2002:a17:906:3458:: with SMTP id d24mr13900837ejb.271.1574340803279;
        Thu, 21 Nov 2019 04:53:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574340803; cv=none;
        d=google.com; s=arc-20160816;
        b=qHn0ti6s2lPYnEBxqcgoinOqab13z3P4f8TvA7NbywjAH5HH5/BzJb9f5BmVVGCpjR
         m53VwYYo/DDsTRYcq8xUS2V4zyvxhwt2fdUTfPZh/1xDhX8JPl0013W8/H81H63pIjV5
         AcNP3lSBFtQhoyJQWRnfU2jfR12T0OOUKmBlsAjdyZJ66qtaGgTM4EyFz/h5dVQ3bkNV
         +H/WBR7qZkXZK52dTshyOqSf4zl9B84Pj+mjnNrEGZ2xTOIwz64RTgzU7Q/LkC7zBQ4l
         +p3xXKv0Eq7uVyPdg+wbnLJ0ruvfndXucu/ZGW6YUJxozkIv1vWVKe/6FMCr7FSZnO1F
         ehyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=0+L8h9ensdN1j4gyCGQx+fEr6tXQsonNDbLN6tfONUA=;
        b=emwEXZCWYyDMcXKtgwpU9CvWSnfjlB1pzOeDtYPHKmMbhxxIqrplgNsAo7SzxuCiDb
         iEbVu4pVl/n7Xbm2tCcnftqy1V2DEprvC37CgTvC5cMdDZ+Y513bokhuAfiGbCl3MXDy
         PhphQVVaA9tNI2BiL2yqjhFDafqUTOxrD+innSNFZtVp4G8XinEUY36YYVdw/6Vhx/1t
         jG4h26RtqShXEOCjrTJ3EJSEPEnBVqeC35ZeAbFBAtH1xQecYsY92NilIyaJ05fpeD9O
         sDnNqBl6nvGoIPEf7G7BwesF4R7dxGqFGfDja47MRnCARQUQyU6klxyGqHAeBJi28iKQ
         iMxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id w4si127242eja.1.2019.11.21.04.53.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Nov 2019 04:53:23 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iXlxI-000251-L0; Thu, 21 Nov 2019 15:53:04 +0300
Subject: Re: [PATCH 1/3] ubsan: Add trap instrumentation option
To: Kees Cook <keescook@chromium.org>
Cc: Elena Petrova <lenaptr@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Linus Torvalds <torvalds@linux-foundation.org>,
 Dan Carpenter <dan.carpenter@oracle.com>,
 "Gustavo A. R. Silva" <gustavo@embeddedor.com>, Arnd Bergmann
 <arnd@arndb.de>, Ard Biesheuvel <ard.biesheuvel@linaro.org>,
 Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, kernel-hardening@lists.openwall.com
References: <20191120010636.27368-1-keescook@chromium.org>
 <20191120010636.27368-2-keescook@chromium.org>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <35fa415f-1dab-b93d-f565-f0754b886d1b@virtuozzo.com>
Date: Thu, 21 Nov 2019 15:52:52 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <20191120010636.27368-2-keescook@chromium.org>
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

On 11/20/19 4:06 AM, Kees Cook wrote:


> +config UBSAN_TRAP
> +	bool "On Sanitizer warnings, stop the offending kernel thread"

That description seems inaccurate and confusing. It's not about kernel threads.
UBSAN may trigger in any context - kernel thread/user process/interrupts... 
Probably most of the kernel code runs in the context of user process, so "stop the offending kernel thread"
doesn't sound right.



> +	depends on UBSAN
> +	depends on $(cc-option, -fsanitize-undefined-trap-on-error)
> +	help
> +	  Building kernels with Sanitizer features enabled tends to grow
> +	  the kernel size by over 5%, due to adding all the debugging
> +	  text on failure paths. To avoid this, Sanitizer instrumentation
> +	  can just issue a trap. This reduces the kernel size overhead but
> +	  turns all warnings into full thread-killing exceptions.

I think we should mention that enabling this option also has a potential to 
turn some otherwise harmless bugs into more severe problems like lockups, kernel panic etc..
So the people who enable this would better understand what they signing up for.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/35fa415f-1dab-b93d-f565-f0754b886d1b%40virtuozzo.com.
