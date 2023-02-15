Return-Path: <kasan-dev+bncBDEKVJM7XAHRBCW6WKPQMGQEKT2FMYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 818D8697983
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 11:08:12 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id j6-20020a056e02014600b003155e564964sf2354910ilr.10
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 02:08:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676455691; cv=pass;
        d=google.com; s=arc-20160816;
        b=cTZNYHywC2Fr3hqgEii7JZ4ZZ1A7fo0EGvcjZwHySj/VNZcEr+9fcyHMTj66HY+5Iq
         nbqKjafkZjO5Ho7EPGd6u1dlPA4HobeMHoO8slNbO7rqudgr8zvZJHUbjJuWT/x97vgT
         ++nTZu8TLd99Ys0MX/g9QwONuVbLBBCvJZEVn6niQKyeojc7GYpkdbsEXyQYYyEN4gid
         62PzYKm8KlfBYqM9/HO76feEfwDghTd0ScqmBttHj2bO20AKR1kWK2soeY1qdm5IKTjI
         Ob70VNUpXsxbTDqvQ9WURgxlMLjTNXQFgi6UcL50QNz7anZPfL6iKz2Pjd9TvSZAosWv
         u8EQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=gTaJtGsHZFNInTuxhpGUBY85gda2KU4ktMiHOWkkLa8=;
        b=TfRC61smTm7b40FTcbR2PJ3ONUk3N4d5DsI9bsA1XF/yCicgv5VxmFAqeAPHw1TPZ1
         tmi+UTMcLKl3dRtd4bd4x96UUW31zxFLo5BoNMlziHpCZV5oBWcfAM6EcDcnTotJIrdI
         EZ6wXGvG3zGfKPgPTm/ws13klGzSWXCheasGSoYHI8kvpqGh1z5LPJe+ekAgq0feI2gl
         TV/wKARDgG5lNdFFkUFTPYNWQmivBvtA/sC0tnjnBKHunH732WjzlM6FcUWg2p6+Q+KX
         nwKRz90iltn4TM6bHfVd4HJuqfjcq6RhLu4KppTgjk/NRp+Xi+lccbXdNry5OfAOVLsi
         ZZGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b=Bt7T6qqk;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b="Je1/tWD0";
       spf=pass (google.com: domain of arnd@arndb.de designates 66.111.4.28 as permitted sender) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gTaJtGsHZFNInTuxhpGUBY85gda2KU4ktMiHOWkkLa8=;
        b=FvSboNAQmDzeeA5NmYGVIICyn4lsoBsqrGjYZS5yLAa8/rdR8liIpfJxV6Y+YQ/jci
         EtmKBzu4wMMsi+5xr3tgloma6dOK+9UIwEjFlYe7xmOukST/5YfubbLoeYN3TcYDNzMZ
         GTXX6jUTRHGc+czTxvgaCzdFRpy+wpv8LrH2pHlOPxgleCs+F9lhlNrAzoBKkDu1SRgz
         hmBVfsF8B6LfRvmvJkbZC4Zb4LLRxolkbQDmbbt5ZrEYn2k8rQYPlBZClEnC2psZPvQt
         NiHPiIfND72M0VyfnMpBNDJHqSvNxpdSJOCxHTYjBnlSVjUTQi5ol2nQwOad4g58+NVL
         qwMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gTaJtGsHZFNInTuxhpGUBY85gda2KU4ktMiHOWkkLa8=;
        b=Qwjn2QKSRtz3bIzpqyh2N5G/b22RL1D78E3FGKT2V/zPBB3KJcCsslWMC3LFgaefsh
         97IWyLHow1JvAzBKLR9AzGnaca0833HYpF8VyZlE240vok/YL4INgGQWLf/1xQQ6yy1r
         qWo+DtMrJkfGAYubExCSBtxmqGzs3j8gKsz6EHoSrAWgULxXHVtBTl9qa7MFJJJkwWp7
         brA0iR0vFjGMYPrFGVbQYQlCTGlJptelfEJDz/rh/4UrtjAFnSYw9Y/+dlmgViZ00GXP
         SBfNvDNw5bKF1Bn3tf+KsstiEnOkSu0SfOnI1V3NDBjW/5v2XD8RATrU9uR10P1yyJvk
         uwOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVxTF8A9JrZoPz9u2XEv/NlNYkrYAC+S1y58QrZVLq2DtFtFCZk
	iamI9fqk+ajCp85/qdTOcWE=
X-Google-Smtp-Source: AK7set8jQFRrOKfk6q04MDKReOuRAP438pTnWYnyTCQx5ylMXwfQYAGs9GZ5P6Nnm5x3as7jLeJ1qw==
X-Received: by 2002:a5d:9c93:0:b0:73a:4169:117a with SMTP id p19-20020a5d9c93000000b0073a4169117amr615290iop.47.1676455690977;
        Wed, 15 Feb 2023 02:08:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2907:0:b0:314:1891:45e5 with SMTP id l7-20020a922907000000b00314189145e5ls6090800ilg.5.-pod-prod-gmail;
 Wed, 15 Feb 2023 02:08:10 -0800 (PST)
X-Received: by 2002:a05:6e02:1a4c:b0:310:b84b:c884 with SMTP id u12-20020a056e021a4c00b00310b84bc884mr1607002ilv.18.1676455690510;
        Wed, 15 Feb 2023 02:08:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676455690; cv=none;
        d=google.com; s=arc-20160816;
        b=RQ81Gpkmap7hcz1sqITLLVf7K2RqLHugumiVLHfYFM5MvMSPlmDG4Mmq8Rt05bIVcj
         YY83qxHODHDAGaC1fCNhr2qIqBMqB4WeI0SdQ+51xHWXjYilCWTqzhkJMHsJWK1CpZzN
         Z9ke/D88sJNY3+1tqy3/BYStgrZmy4zsmVye1mpFbl9iUOK4s/YyOUfaGbCKDecb6Tie
         C55rvAwIPjjvbczpS6nUkYUUKtfTeqOA/HObb/6uyskaR7b337nohYAHoJz1qTqwG2Ag
         3XGHFGb8kjaIwLLUKagBMC8ZBK8JxYLnNEc4hcY431a3xnpBxS4HYhlCwKXVKdMGeRKY
         kjGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=kWKcVh77gLJCUhZuCa+WynI5AAVboSYj3Oe09BQDl0U=;
        b=Ft+iUb/c9og14O+aGL5EZMV68RUqWb4QzbxrtuAsPNwhLQFpaesv7NvkqgMuax2rZC
         BJG6KSkHTzZie0/5K8QA2ypQBQC/8UcU64XPzxijQb3v8XQurndvdVuhyCLDfqZlAR/t
         I+P6RtkKoeroRML8YlPkvq6qCbzfsQRuoowYs2ZoJyw8hlPU8aYtMRPQxrFgmbinP80a
         ex8MVN97SmdNjutb4mC6uZJ7m5HHkG3tBYFeCDrhG8JG8OKdx6kZP7aBzG2mt8x9IftO
         o9atxhPm6atBlBHayEu0gVZzEYGeiOODrA5OMK7V/L8ohKwVpGlWv+D1LtC0nPk3vLRW
         RWbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b=Bt7T6qqk;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b="Je1/tWD0";
       spf=pass (google.com: domain of arnd@arndb.de designates 66.111.4.28 as permitted sender) smtp.mailfrom=arnd@arndb.de
Received: from out4-smtp.messagingengine.com (out4-smtp.messagingengine.com. [66.111.4.28])
        by gmr-mx.google.com with ESMTPS id s13-20020a056638258d00b003c2b55913f9si2433920jat.3.2023.02.15.02.08.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Feb 2023 02:08:10 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 66.111.4.28 as permitted sender) client-ip=66.111.4.28;
Received: from compute6.internal (compute6.nyi.internal [10.202.2.47])
	by mailout.nyi.internal (Postfix) with ESMTP id 112D35C0109;
	Wed, 15 Feb 2023 05:08:10 -0500 (EST)
Received: from imap51 ([10.202.2.101])
  by compute6.internal (MEProxy); Wed, 15 Feb 2023 05:08:10 -0500
X-ME-Sender: <xms:Ca_sYwj6243aaaFewEIkV7j6oDonohgF3wArjnJZw79rONDJPNjjHw>
    <xme:Ca_sY5DBosDA5DvPLiAv00BIKZnS6ADCRW5FJMKQjm0O0xoZ0A-SoyK2Im-wVHHP9
    XfJOqogqq8nCyj_ips>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvhedrudeihedgtdeiucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepofgfggfkjghffffhvfevufgtsehttdertderredtnecuhfhrohhmpedftehr
    nhguuceuvghrghhmrghnnhdfuceorghrnhgusegrrhhnuggsrdguvgeqnecuggftrfgrth
    htvghrnhepleffheffveevkeegffefffdviefgffeghffhudevteevfefgtedujeefuefg
    gfejnecuffhomhgrihhnpehlihhnuhigrdhorhhgrdhukhenucevlhhushhtvghrufhiii
    gvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpegrrhhnugesrghrnhgusgdruggv
X-ME-Proxy: <xmx:Ca_sY4EiVIfc_Fc8C7HCeMLhpDtHXpfcEkzZfYSZMd7aSG6d5f5Rrw>
    <xmx:Ca_sYxQDoifIb1cp4TMuxZKd0LN_xZVi9DugV2FnkqBWvlrmY-Tb1Q>
    <xmx:Ca_sY9wLc9mJxw8QhEduakiHsu3PjaIJBy30q4JoEhm63sCBzAWfVw>
    <xmx:Cq_sY9icOGg888G4FeLyVEIj4TX1fqCoM0id8lCphCeTo61Ycjokaw>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 475F7B60086; Wed, 15 Feb 2023 05:08:09 -0500 (EST)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.9.0-alpha0-156-g081acc5ed5-fm-20230206.001-g081acc5e
Mime-Version: 1.0
Message-Id: <6a5e9a2b-46df-4717-8f4c-aac14d06d773@app.fastmail.com>
In-Reply-To: <20230215023706.19453-1-zev@bewilderbeest.net>
References: <20230215023706.19453-1-zev@bewilderbeest.net>
Date: Wed, 15 Feb 2023 11:07:51 +0100
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Zev Weiss" <zev@bewilderbeest.net>, linux-arm-kernel@lists.infradead.org,
 kasan-dev@googlegroups.com
Cc: "Andrew Jeffery" <andrew@aj.id.au>,
 "Anshuman Khandual" <anshuman.khandual@arm.com>,
 "Dinh Nguyen" <dinguyen@kernel.org>, "Russell King" <linux@armlinux.org.uk>,
 "Sam Ravnborg" <sam@ravnborg.org>, "Stafford Horne" <shorne@gmail.com>,
 linux-kernel@vger.kernel.org, openbmc@lists.ozlabs.org,
 "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Alexander Potapenko" <glider@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Dmitry Vyukov" <dvyukov@google.com>,
 "Vincenzo Frascino" <vincenzo.frascino@arm.com>
Subject: Re: [PATCH] ARM: uaccess: Fix KASAN false-positives
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm3 header.b=Bt7T6qqk;       dkim=pass
 header.i=@messagingengine.com header.s=fm1 header.b="Je1/tWD0";
       spf=pass (google.com: domain of arnd@arndb.de designates 66.111.4.28 as
 permitted sender) smtp.mailfrom=arnd@arndb.de
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

On Wed, Feb 15, 2023, at 03:37, Zev Weiss wrote:
> From: Andrew Jeffery <andrew@aj.id.au>
>
> __copy_to_user_memcpy() and __clear_user_memset() had been calling
> memcpy() and memset() respectively, leading to false-positive KASAN
> reports when starting userspace:
>
>     [   10.707901] Run /init as init process
>     [   10.731892] process '/bin/busybox' started with executable stack
>     [   10.745234] 
> ==================================================================
>     [   10.745796] BUG: KASAN: user-memory-access in 
> __clear_user_memset+0x258/0x3ac
>     [   10.747260] Write of size 2687 at addr 000de581 by task init/1
>
> Use __memcpy() and __memset() instead to allow userspace access, which
> is of course the intent of these functions.
>
> Signed-off-by: Andrew Jeffery <andrew@aj.id.au>
> Signed-off-by: Zev Weiss <zev@bewilderbeest.net>

Looks good to me. I've added it to my randconfig build tree to
see if there are any build time regressions in odd configurations.
If you don't hear back from me until tomorrow, please add this to
Russell's patch system at 

https://www.arm.linux.org.uk/developer/patches/info.php

with my

Reviewed-by: Arnd Bergmann <arnd@arndb.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6a5e9a2b-46df-4717-8f4c-aac14d06d773%40app.fastmail.com.
