Return-Path: <kasan-dev+bncBC33FCGW2EDRBRPAZGBAMGQEFYNCDWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 3546633FA4D
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 22:10:30 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id v27sf10985312ejq.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 14:10:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616015430; cv=pass;
        d=google.com; s=arc-20160816;
        b=AiRVdcV0uUSKFvOKfAkip2V29JVCH1ttfW9XUqoDIQdwDlZ9xTnAdyFx4yK6L38v8D
         AynSzihdcpLhDwbFgSTtQZcqLryBwBIJdsqkyjFUeC7XK7lLV6+5XTaoIxOz55LfTik8
         C3FITqKZUhPvn0U+TCp3wvIyassElxaYmmkYwwpR8I8rQYOn/DJVfzolJLOwtsc2nR+I
         R3JKE2+jYpBOPHwKfB724bLt8qMVxjQMj0htMSMT/1plv9Z1yJRjElEy8iP8sbrg8MjO
         aEfoETXXna3QQWBO2ZnDwO8FDKERFQZAZi77y58kPVNCY58/RtQ3Nev+CP5HZdWAep8X
         X9GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=NS0+9KjMC3qfSw8vvDhLM6rCmSRwB3WPZUrgS3WFicM=;
        b=GTtJNaRnwiDDYWtOX0cjl/j9L4O2+7Bccl6Khp1dZ3A0kE3kjBHks7eDoOHkkKFWeM
         OXAzMd/ryL+EjNYgkajYxhgl69cPfSmvXX6K04z4GY6tXw4eIcKO7x7Z1ZdAnMVfA3uD
         NknwrO7q2irv5HJ9A6PpVBJmfU0r2trFIdELyeodK1VtNITrWKbXin20DEd5udx3acOI
         kRXHVk6ln8RfjJqA60uy7vBE1mhl9YzWtHmweFqLX+FVbhgAQPBJAcOoTnEI5XEcaVCF
         Dy8uI0PtqQuG56PqHu0+YczMBDJRfo8raOKDF8WpK3wpfVAhamvijHjv4AH5JLZ5cBWb
         wc5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b="XwKFVm/g";
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 188.68.63.162 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NS0+9KjMC3qfSw8vvDhLM6rCmSRwB3WPZUrgS3WFicM=;
        b=TQhNkFlzGaX91mBDa26rurbJsgyl+DglECnCeyYxcWebjEqZswpd2upBJX4dMrgcT5
         vcbKfi8DbVb6QHrijvFpSjRAsWJyXFYkctBLw8STOsM186XW1mE/gt2WDmPUacQPHLGX
         ac+tY/wYVJEZhwlFmMM9SWsLyc3O/qJyDe7mDSGu1AKbuL6AeYSaIlhIQjrAN1CLEEu1
         WL9aUhQsIGNgXe2zcb1WXd7P0w3iJU8rH1kEBTtZQv7a8+Jg8ZYFwcLRItUKwpT5/Tjj
         1PtUKnXqxbn3yyQQYHyhS5HfTzj7mP+Zar+thrMU+EIlN1LunWruwFvbOM+NESSOt1v8
         Zmyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NS0+9KjMC3qfSw8vvDhLM6rCmSRwB3WPZUrgS3WFicM=;
        b=t8CtK90lm5nWTn4uY/+1btYzfPYl95losI5YWLqbplYpK/+vS4Y23qn65hCb6xhfWD
         NDzTz4nFVmTZAwFfkpuDJCxBI3cADOt1JLlTjgAMaCduCcY2tzQOy+hfMDrBEAvQFOjJ
         jqivx5QOM6rmqQt168njY+hhNOhgXm6btqUDR7jXeKATZZEk6tmJy0m7pFnB24JzvCy8
         pULwfZS7/XOVtL0UHYcWBCYpBcvBilp8VqqX+M5y9usuuyqe6BtldEpClLdun73ZCghd
         yN70R2HzDrcGV+Sr+YJ2OwxkOB2hHx9VRZO8IYPQr1zstY/SaXsg9GDGkuMuVcdmRxPt
         NuWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530kcr1s5K8VB2+z1Q9pm6dC0pvia+oBvA1zrlEaSdWz/8Q+9/op
	18tSS9ePVdM22s2SVMXntiI=
X-Google-Smtp-Source: ABdhPJzC0pDGJrzB+xmXeyaMuYtesShwQC8LEbnLI+KkQhJVgjDW7ioOR5wf2AFHZBmqg3JgnC11JA==
X-Received: by 2002:a05:6402:8d7:: with SMTP id d23mr45456657edz.256.1616015430001;
        Wed, 17 Mar 2021 14:10:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:d06:: with SMTP id gn6ls72656ejc.0.gmail; Wed, 17
 Mar 2021 14:10:29 -0700 (PDT)
X-Received: by 2002:a17:906:9515:: with SMTP id u21mr38370885ejx.86.1616015429157;
        Wed, 17 Mar 2021 14:10:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616015429; cv=none;
        d=google.com; s=arc-20160816;
        b=pL9VKFWmfbxeaqod8nx4Dj1wz6Fd/hXzblJY9ikrSe54RpJom4d0b/8eC106tcbLWO
         zuEtJ3L5odFcL0K916gT3MtL2sqLHnEz8i9CmWxCZ5A2UAJUEy2CQvNDCdrRMQVuzuQM
         xAhsSmR8K8tBOkTbPsUfvvRD3KCVmDAgjn7nBdYmVDn8hD1ZVKgNhbnzspfpvVxf5Vga
         v2p4KfHBJHFh66CiahFeUSBiBGt7Faz/kvYQweiyzRemtWZFlRO/uflx8N4EB5JzOiLF
         xb81DKWXoQDCML0++7fhnCW3WZrfQcR1CocygNzQfEISRr4K5zFshp0UE78rPgXPTLbp
         TlpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=ZoV36kB83va6HhbhLUUKTr54bnv1349j/JtiJcxpElM=;
        b=j+mX3fETsVA3WUbn/HCGm6pR7Jlb5hJDHL/th7neXwFOy7UA6z6335qIUfwG1BUHDK
         JmMomeLWdoKVJVmixLFJyE9UXQClQjgBd+XZwkOPp8r0reHlG+ZajADPbsTjseLxZOg8
         D4Jcyow0LWyrSDhuRIvYrfmM/0qjnb4gkoQ3z4VoSsyZkiaS2xr/I6ZFgg+MIneuB9b/
         grIUJsgWse3nKQMf8Yrfxjo8y/pDGAmln16Gty/MxUC3bhxwA++rJEbbutt3sQGcMchk
         UUxpNRCxkpQhoUFMnucQbQy2YgOP+yIvblv1lcKnLa2fKb6FKOfns8/CqM5WNjS5KQLd
         gDow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b="XwKFVm/g";
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 188.68.63.162 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
Received: from relay.yourmailgateway.de (relay.yourmailgateway.de. [188.68.63.162])
        by gmr-mx.google.com with ESMTPS id df17si3716edb.3.2021.03.17.14.10.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Mar 2021 14:10:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of info@alexander-lochmann.de designates 188.68.63.162 as permitted sender) client-ip=188.68.63.162;
Received: from mors-relay-8201.netcup.net (localhost [127.0.0.1])
	by mors-relay-8201.netcup.net (Postfix) with ESMTPS id 4F12qm5WYCz4jFL;
	Wed, 17 Mar 2021 22:10:28 +0100 (CET)
Received: from policy01-mors.netcup.net (unknown [46.38.225.35])
	by mors-relay-8201.netcup.net (Postfix) with ESMTPS id 4F12qm576nz4jBl;
	Wed, 17 Mar 2021 22:10:28 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at policy01-mors.netcup.net
X-Spam-Flag: NO
X-Spam-Score: -2.901
X-Spam-Level: 
X-Spam-Status: No, score=-2.901 required=6.31 tests=[ALL_TRUSTED=-1,
	BAYES_00=-1.9, SPF_PASS=-0.001] autolearn=ham autolearn_force=no
Received: from mx2e12.netcup.net (unknown [10.243.12.53])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by policy01-mors.netcup.net (Postfix) with ESMTPS id 4F12qk6Zckz8tsh;
	Wed, 17 Mar 2021 22:10:26 +0100 (CET)
Received: from [IPv6:2003:ed:7f0a:3df0:4122:177f:5aab:be1b] (p200300ed7f0a3df04122177f5aabbe1b.dip0.t-ipconnect.de [IPv6:2003:ed:7f0a:3df0:4122:177f:5aab:be1b])
	by mx2e12.netcup.net (Postfix) with ESMTPSA id C7CEEA174E;
	Wed, 17 Mar 2021 22:10:25 +0100 (CET)
Received-SPF: pass (mx2e12: connection is authenticated)
Subject: Re: [PATCH] KCOV: Introduced tracing unique covered PCs
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet
 <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>,
 Wei Yongjun <weiyongjun1@huawei.com>,
 Maciej Grochowski <maciej.grochowski@pm.me>,
 kasan-dev <kasan-dev@googlegroups.com>,
 "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
 LKML <linux-kernel@vger.kernel.org>, syzkaller <syzkaller@googlegroups.com>
References: <20210211080716.80982-1-info@alexander-lochmann.de>
 <CACT4Y+YwRE=YNQYmQ=7RWde33830YOYr5pEAoYbrofY2JG43MA@mail.gmail.com>
 <01a9177f-bfd5-251a-758f-d3c68bafd0cf@alexander-lochmann.de>
 <CACT4Y+ZPX43ihuL0TCiCY-ZNa4RmfwuieLb1XUDJEa4tELsUsQ@mail.gmail.com>
From: Alexander Lochmann <info@alexander-lochmann.de>
Message-ID: <46db8e40-b3b6-370c-98fe-37610b789596@alexander-lochmann.de>
Date: Wed, 17 Mar 2021 22:10:25 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CACT4Y+ZPX43ihuL0TCiCY-ZNa4RmfwuieLb1XUDJEa4tELsUsQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-PPP-Message-ID: <161601542610.499.17322500893737558040@mx2e12.netcup.net>
X-PPP-Vhost: alexander-lochmann.de
X-NC-CID: 2WGiPwQUUoDFxYChPZmyidfLQddIA3fSFBMzr29sGlta+0MY4C/ts3lB
X-Original-Sender: info@alexander-lochmann.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alexander-lochmann.de header.s=key2 header.b="XwKFVm/g";
       spf=pass (google.com: domain of info@alexander-lochmann.de designates
 188.68.63.162 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
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



On 15.03.21 09:02, Dmitry Vyukov wrote:
>>> Does this introduce an additional real of t->kcov_mode?
>>> If yes, please reuse the value read in check_kcov_mode.
>> Okay. How do I get that value from check_kcov_mode() to the caller?
>> Shall I add an additional parameter to check_kcov_mode()?
> 
> Yes, I would try to add an additional pointer parameter for mode. I
> think after inlining the compiler should be able to regestrize it.
First, I'll go for the extra argument. However, the compiler doesn't
seem to inline check_kcov_mode(). Can I enforce inlining?
I'm using GCC 9.3 on Debian Testing.

- Alex

-- 
Alexander Lochmann                PGP key: 0xBC3EF6FD
Heiliger Weg 72                   phone:  +49.231.28053964
D-44141 Dortmund                  mobile: +49.151.15738323

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/46db8e40-b3b6-370c-98fe-37610b789596%40alexander-lochmann.de.
