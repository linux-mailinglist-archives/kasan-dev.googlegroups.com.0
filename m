Return-Path: <kasan-dev+bncBCCZL45QXABBB4575L7AKGQEPEMZDWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 68E802DC9C8
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 01:01:56 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id z15sf19204245ilb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Dec 2020 16:01:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608163315; cv=pass;
        d=google.com; s=arc-20160816;
        b=0JBGf44SDDXzekevUOghJktxhpRBXO8UXcgSCpOSg1GDjCFcrNG5y7yJnY5skqoXfY
         HG8ieYjS2aivTTF71KX2Z+0k0vWWK3fEBqXYxj+URHZ5bE2HW14ePOkBd8RQsT4v4Gl1
         qQnSnIznUan6XU4CLX5BUPUamXhXxxCI2oNgTFdNp0gYVuXMuZ+rY6VNQsJvetiapOa+
         lrwI+fGvl+Cp6lNmP5sh0Y/6bY79KXBHzRRsaegDAwvzBuz2fJna+4C0oygm0HciEmjr
         q/WTBu7U/cX8gatpslY0tV0P5fcsmWjGdTMyFdPf9Cy94AbR/yQl0FiwKQSzBNHi6ile
         ZzDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=RttIgaRx74PXEC8O+Abi/8XuoSbSYiV0CRN13q5CjRE=;
        b=gyYHhGMl4rwTnbs3fs+FFJ/+j8HjArThPA+XGJqaUaAZILDihcrNU6V7YNyGsmrl5F
         4JeQE7yDT7kbzkRbrWFaBZwqaq9Xekef4Qtpyg+2VCmREfqqco150N0bc3yr0YRUxHUS
         UE7o54kkfyFmGtJ9IgoT9qQg/Nkj4ynGTKZbVAjXVY5NbJwSl7I9MXI4udT13hi1FaRS
         t93QyOBKlACw+pOcFhGQCnoMgy1NYzS77vSK9ZkojhgAo13HcxKvcy9rqJ1JrE5a7C3c
         tzx67F23mVKxDncVW5Q7rnJbdaqz3XMF3PrO8CkKjxQTyfB05h9IWz9qziJ+oodSaEYP
         E+eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b="W6i/7Mrh";
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RttIgaRx74PXEC8O+Abi/8XuoSbSYiV0CRN13q5CjRE=;
        b=oT9eZ2kPKwugf5OF4qM4DTCTbyEn+O8Aq9Mau5pDE9Uwwpwh2DsyMxocK3KXS+t4+D
         GPp1ih0zXUK0IChKRYJnAqpE49ImWw0ZqeFbI8sg+AbXBJTDH4qswl7eQLYJAZU2AbSS
         ZyLeZePFWV2ezJ+0kqhwxk726IOjZphCKWzClIOvrnjOIWaAomggJudP524ypK4CIQMV
         9HpJ5R2NoraI1DErCfikRvQgl7nRTtyF9nf7Yf0FAdtLiYgWB41abY4lW8VAKYAKiFdP
         9ga562cn1tmP2mJOuycPZ1x6EtUVYdEHAt8NaqVUrEOr0JjgtsBT5qzWXnVS0k91JLHW
         mXfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RttIgaRx74PXEC8O+Abi/8XuoSbSYiV0CRN13q5CjRE=;
        b=tqO36vfDQI0NmIBOW80K3x1uavwgSHmz5ESSH7fbIRe/Szb1qhamO0610G0ZDMuyuS
         wRPPmNNHJp/+6x3McH6sQSnAo2ULjsb2IwWQFrYuKp+no4jFRZIXulvQUr5mRMcd4jKV
         dxsP8hZXKjyhNXRsQVYdEsnFDco4TbDWAk2JgZDdHNwwRqvi3SoVeVsDYhc/WoaYhWXJ
         a9r1Lrr2CEmfZgoIzqLwsqnGooaVD5anjmKiUek+W06I6P6XvblliBqFxUTrv7SCJklv
         axPPn7BllO71ZhvzU+jlQfHH2WLEfbOih0IyuI3WjqPwR8ksu8y3OdlAiQL02LLytMzB
         AqsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Tl38YeNRPw/xyMxt6modz5aN2r5FQjEc/WpBsUl9Be+/G+K6h
	571yQ/Foj2wVHpaqtGNMSzY=
X-Google-Smtp-Source: ABdhPJyRnmoY950++UTVP8JRHEOCI6YIFWmrRXDYEmBuHrmTLiamE081VOVoT0uXfNtR/ukMQkMqUw==
X-Received: by 2002:a05:6e02:926:: with SMTP id o6mr46951129ilt.65.1608163315228;
        Wed, 16 Dec 2020 16:01:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8356:: with SMTP id q22ls3710834ior.3.gmail; Wed, 16 Dec
 2020 16:01:54 -0800 (PST)
X-Received: by 2002:a5e:dc0d:: with SMTP id b13mr45271463iok.31.1608163314792;
        Wed, 16 Dec 2020 16:01:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608163314; cv=none;
        d=google.com; s=arc-20160816;
        b=S419DjbT6+o6P9upyzpx0pLcnzibq6euH37ss3Tie013ZG0yDEznHZ0Eq7F4OW6ezx
         Onz71i+S1f6riG+EkF2MS+X0XUhNtvjPxH62m/7Thflg7C8nVnqnCmVAP7Bfs39l/P4T
         6fxVofg+lgkNdsAKXeFBicHrki+w367cwP29ivILuLlyQPkiJeGETG5u7C2eJpTqRlag
         AYcc20tjUdS0gQk4IqPNmcCMdzV7n7tV/1HvXH3VDBaDcLdbi79jQbAcC2pLb7+p0Cnq
         XvmbNlZn93tV6TdysWTomejPs5oKH0uNTO1Dac5Vg/N3UTlJ/wl/nQMtmNgeFs9Do4FQ
         nBSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=+4x3NjyoFEeEOeWfvLPZlFIbPplM7FPrIZMjgt7U85M=;
        b=lSRL20plyipiJwYZSsy4wYhkNJ3b4UAQpiBC3czDFsxca31zJFUpbSyzyFm8swKR3O
         Z99Rl1oz/zSfPtYpKCcCHmsuDHFXQcwpNRM0CX5HTSEhNppL5R3pJXmftBdMyskyS9Bl
         bMbJhTOlAYFrdcJ6su6hebUz+qf6SR6KO4Qgu8OAL2Dr9U37hTgpncGRo3582E05wmul
         TLvoz1DY1lHz8ew0P1zkZWceXPNJNBB4KLzqPmuMB/GhSLiwj34O2lpUNAvJgMT9j3ul
         M146/0RXdsiO6xI6pgDizMlfvX7ClHK80tTT8LWqLfkREPSb/EMunna7XfJ3lhJUwKrW
         NFwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b="W6i/7Mrh";
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id e26si332623ios.2.2020.12.16.16.01.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Dec 2020 16:01:54 -0800 (PST)
Received-SPF: pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::136 as permitted sender) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id p5so24261940iln.8
        for <kasan-dev@googlegroups.com>; Wed, 16 Dec 2020 16:01:54 -0800 (PST)
X-Received: by 2002:a92:9153:: with SMTP id t80mr10789891ild.216.1608163314583;
        Wed, 16 Dec 2020 16:01:54 -0800 (PST)
Received: from [192.168.1.112] (c-24-9-64-241.hsd1.co.comcast.net. [24.9.64.241])
        by smtp.gmail.com with ESMTPSA id r8sm1943738ilb.75.2020.12.16.16.01.53
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Dec 2020 16:01:53 -0800 (PST)
Subject: Re: [PATCH v4] kcov, usbip: collect coverage from vhci_rx_loop
To: Andrey Konovalov <andreyknvl@google.com>, Shuah Khan <shuah@kernel.org>
Cc: linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Nazime Hande Harputluoglu <handeharput@gmail.com>,
 Nazime Hande Harputluoglu <handeharputlu@google.com>,
 Shuah Khan <skhan@linuxfoundation.org>
References: <f8114050f8d65aa0bc801318b1db532d9f432447.1606175386.git.andreyknvl@google.com>
From: Shuah Khan <skhan@linuxfoundation.org>
Message-ID: <8ec4268d-7124-20dc-2a8e-175b5e64d06f@linuxfoundation.org>
Date: Wed, 16 Dec 2020 17:01:52 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.5.0
MIME-Version: 1.0
In-Reply-To: <f8114050f8d65aa0bc801318b1db532d9f432447.1606175386.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: skhan@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=google header.b="W6i/7Mrh";
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates
 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On 11/23/20 4:50 PM, Andrey Konovalov wrote:
> From: Nazime Hande Harputluoglu <handeharputlu@google.com>
> 
> Add kcov_remote_start()/kcov_remote_stop() annotations to the
> vhci_rx_loop() function, which is responsible for parsing USB/IP packets
> coming into USB/IP client.
> 
> Since vhci_rx_loop() threads are spawned per vhci_hcd device instance, the
> common kcov handle is used for kcov_remote_start()/stop() annotations
> (see Documentation/dev-tools/kcov.rst for details). As the result kcov
> can now be used to collect coverage from vhci_rx_loop() threads.
> 
> Signed-off-by: Nazime Hande Harputluoglu <handeharputlu@google.com>
> Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
> 
> Changes in v4:
> - Add USB/IP specific wrappers around kcov functions to avoid having a lot
>    of ifdef CONFIG_KCOV in the USB/IP code.
> 

Looks good to me. Sorry for the delay on this. It just got lost in my Inbox.

Acked-by: Shuah Khan <skhan@linuxfoundation.org>

thanks,
-- Shuah

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8ec4268d-7124-20dc-2a8e-175b5e64d06f%40linuxfoundation.org.
