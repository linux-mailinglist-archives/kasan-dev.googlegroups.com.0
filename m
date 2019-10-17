Return-Path: <kasan-dev+bncBC5L5P75YUERBYUJUHWQKGQEOSXUB5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 24A97DAA27
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 12:39:31 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id k184sf945306wmk.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 03:39:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571308770; cv=pass;
        d=google.com; s=arc-20160816;
        b=osQPsUt2STZ/QxbERnAILgiSsP792Op/tx3HCmuGD/iyUyV4WT9HFwfbRXT3EnzN6v
         bPkG8EkKhI2Sl0zajv9VigxhSgK1QDenO8BMb3KtMv+mJQOt5TWgRZUXrqumT1lNs315
         5qHaUIubG+OtgUni7rDipwm8PRJ26wGGEFU3AuGx4eypxlrLAF7NE3wUieaFRBeEP8Lz
         VWHf6V1q5uulcX138FXqo9QL49BPvNTNHU/A+QI6hjF+4tOcbIF6WxLh86mJAyxms1v3
         uI6t3W12Y2yUSOixOd5QDsKMEnQXrzs9+hcbcQk6CFbyVlzHpeGoxgwF3aih+TUBjUDh
         klJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:to:subject
         :sender:dkim-signature;
        bh=hyLpQs+0/4NWeQfHpsuP0KvaHv+gr2SlhY/bs9VcBeg=;
        b=g5z79jdxED0GqdU7oessceA5D7ioBGCcwDKHBRX+w1fqOeUBq3uBZFC9PuvcR1XcVn
         9ARoNp/nExeECTEjk+B4sjPwOwrqoGn2Hak8Vq5BiFwCAFAqz/noPfMkRRzke4aJzBDN
         Srvwp0nAId2Qv+GlAKGoof6jA1JXBUIE4eBpD9VnXDcqxsCyLP5JdQHsXpJK542OafSh
         pfHuYkKo/GVb+ygjdUugB4Q5QdAyEHTBcsQLQo8pKYZ+Jq3z4MAfDegLUiUQowe6zLyF
         SzA2M//o5AruakMKD76FmTaEP3s28TX++Kxhknfx6GIv6seST3M7w7fhrrVmMprRjhu6
         kb8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hyLpQs+0/4NWeQfHpsuP0KvaHv+gr2SlhY/bs9VcBeg=;
        b=XPbESbiYi6EgnWhYBYM/fv3wwGWNL+gFJlrBTcygy7bwkPcTBirORZJBmC/pbY44Hy
         Aivl+qYtktpA73KuA0/fx4RwD9wtAIr6o6y2JpNaq7ZwadhmZ8619KyRCFE6IWakoJZ1
         3nyiBbqfyhd1UTppaKMpvyPCCYEyMf4dzXohSrXq5c2T8rxLgu8L0BtkusRYYgBT2WCP
         kwxvg63EzDpFaS//4PzsmvhMAoRrYURXLpxzM1/b6gKFvtjpgaLCdCTA5AfMiKyoAk5o
         463RFzyczIZnwJ+tX1BQj/7ZMvira0XqVX5WvyhpIT8Bv4sMhtrcejdJOfn5BWXGjKiu
         adFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hyLpQs+0/4NWeQfHpsuP0KvaHv+gr2SlhY/bs9VcBeg=;
        b=Jh9MljtnmecChN7S6zSDmC2ZpY9xjUCSTWNtgJfgJq2M05Ls5CjaVHFdapqa0joFvc
         lt3Mn4NHcyV0WlbiQcT6BgeMXIlk84cT2Zb3PeiaK9aENJdZNYo515c91ZsSM99NLUZC
         4/dr9d60F0IqZaJOvnZKwJXPWrz2DHjIMmZNGZVoe/AVZYieJcYtepmEEo7jyzkQV34Q
         TSnIXyhO6nQDbkw8Wt+C6fEm6B8Q1hJqnGJjGLncr+tpLQZelLWBYt56kyl5SraKlHgR
         eM6OAzDJ0EmTaGo3fmDu+68058j9K8ik15yzmBoSI6d8QCyar9yzh72zNkeO3y0rCWWJ
         b9QA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWY/CF6FwIODvmlrQif1oTSS8lxRoz2kYY2xFlrx0So9axVPxo8
	mfPP1a6WgjHt6X07asNMQzk=
X-Google-Smtp-Source: APXvYqyFmtoOp/p0fM+cZ0rwhg5iIMKmHzSgyGAgMuaQ/yb+d+x7kGeKSqU0Vmx1aI3tShCXz6pJVA==
X-Received: by 2002:a1c:990a:: with SMTP id b10mr2233600wme.39.1571308770848;
        Thu, 17 Oct 2019 03:39:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:9c90:: with SMTP id d16ls748496wre.14.gmail; Thu, 17 Oct
 2019 03:39:30 -0700 (PDT)
X-Received: by 2002:a5d:5743:: with SMTP id q3mr527118wrw.394.1571308770377;
        Thu, 17 Oct 2019 03:39:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571308770; cv=none;
        d=google.com; s=arc-20160816;
        b=qhJSSP2XvNDSZj0+aOhaVxtIqKorH6K4+gtzp3Gh78w620i9/7YZrOarNfUjnzsxJd
         NxpajtlAhMCKWXIonG5QKWb0UQ9oNOkM4PD1vuTwlf/XGx+i8tCNaTIlDBjvZdKHP0T2
         HQEaWBbxjDdhdHluxk1pFRsXCVMJ6QZd6OQ7hI14TRiDWmGT5is1T0TeWXhL6CuqvwrG
         pkwDz5Ql2y57Q7n3IOoYQ8kyW5KiqwB7+J04V7ojf4xcxesPAZL78L1tW5LKsW80WpaO
         5CZq+SeRuw2vJVdc56iX8umbXhp1b2FZQ2rZ0dhO4cgzxncIFhGbw08EhGkQUwE30t44
         7ogA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=Zp5fRLEss7Fyl/pwKvu00BWLYsGYUo9c689ef2ZoZQU=;
        b=vhU1yW7/ESmO0WmYtbOp88ZMSaYcgeP08YS9hnkn9fd0mVU/3NPn5RAbSgY5Cutp0d
         s9iyhvS7+JpEGg2olE404NSomKnoiSZ6c5zMR+SR/2GlCTvOiRFks097ZnXeD3cS+vn4
         NVYZ2jaFxFn86gNKMMrPzs3WIfqLMmWCkStetoBe2uTdM7ZvwPGCHLmspWvUNbx4+xaI
         UNCoDEZ7xKVwee9LVSChmIrT/i0WvjjSFbayknzYOr2BfDnT0lr3ahcRTcVK1bx41Uhr
         uBDo5kZswwxA1phTJfeaRlMX+KlVzCO4EwP5q5Uv7Agc5TEJMozzaX9dKZZ526ERwD2q
         as+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id a133si508591wma.4.2019.10.17.03.39.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Oct 2019 03:39:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92.2)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iL3Bf-0005sq-P7; Thu, 17 Oct 2019 13:39:19 +0300
Subject: Re: [PATCH v3 1/3] kasan: Archs don't check memmove if not support
 it.
To: Nick Hu <nickhu@andestech.com>, alankao@andestech.com,
 paul.walmsley@sifive.com, palmer@sifive.com, aou@eecs.berkeley.edu,
 glider@google.com, dvyukov@google.com, corbet@lwn.net,
 alexios.zavras@intel.com, allison@lohutok.net, Anup.Patel@wdc.com,
 tglx@linutronix.de, gregkh@linuxfoundation.org, atish.patra@wdc.com,
 kstewart@linuxfoundation.org, linux-doc@vger.kernel.org,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <cover.1570514544.git.nickhu@andestech.com>
 <c9fa9eb25a5c0b1f733494dfd439f056c6e938fd.1570514544.git.nickhu@andestech.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <ba456776-a77f-5306-60ef-c19a4a8b3119@virtuozzo.com>
Date: Thu, 17 Oct 2019 13:39:12 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <c9fa9eb25a5c0b1f733494dfd439f056c6e938fd.1570514544.git.nickhu@andestech.com>
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



On 10/8/19 9:11 AM, Nick Hu wrote:
> Skip the memmove checking for those archs who don't support it.
 
The patch is fine but the changelog sounds misleading. We don't skip memmove checking.
If arch don't have memmove than the C implementation from lib/string.c used.
It's instrumented by compiler so it's checked and we simply don't need that KASAN's memmove with
manual checks.

> Signed-off-by: Nick Hu <nickhu@andestech.com>
> ---
>  mm/kasan/common.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6814d6d6a023..897f9520bab3 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -107,6 +107,7 @@ void *memset(void *addr, int c, size_t len)
>  	return __memset(addr, c, len);
>  }
>  
> +#ifdef __HAVE_ARCH_MEMMOVE
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> @@ -115,6 +116,7 @@ void *memmove(void *dest, const void *src, size_t len)
>  
>  	return __memmove(dest, src, len);
>  }
> +#endif
>  
>  #undef memcpy
>  void *memcpy(void *dest, const void *src, size_t len)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ba456776-a77f-5306-60ef-c19a4a8b3119%40virtuozzo.com.
