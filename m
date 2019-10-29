Return-Path: <kasan-dev+bncBC5L5P75YUERBWHQ4HWQKGQEJXVZTPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 77231E8E2D
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 18:35:20 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id h4sf8898196wrx.15
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 10:35:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572370520; cv=pass;
        d=google.com; s=arc-20160816;
        b=R00OBYBAl9OXccYxFhYNxHsUnsCcpOWsn3+N4OKP1bpwDO0SYWBHroxqUXjMv7GA7o
         ZfbVfozs3d/xXwEJuWCCFapu6YYQdfVYtfmvxLIgch72y/nJoVvz54Q4cAMB0HX4RTvr
         /Fvb6kBhdbk8kGlQjYh1nujdWNZJlGVKFsRsRLCzpOMiq+IDW0eBdmGt9kHpQyMlPt8P
         8cYhHb/kVpWjeLlu0RkkGjpcxwW/ouDrd92MzJqr2jr0z3p0zdlyeOMJ2u2L/2QaziTE
         BZ01uiSET96A3RRwCtqe6e51dQ5qVR9wU6VXi6Y42tL3mzC+o3YCi6/Vht+Tq6kk6cvk
         bWNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=7nx2J/Y4wZhvz0jyjFqrDAZVJJLefceyFJ5YVFiOB1I=;
        b=GncC50P58IeDPmS6yFNdn8NjHWNuOKLYXpF/D+nsESrgDd0pwAz0ENh1SA+G49qKRA
         R3+c+Tl+IPF8U/P12HHQwMuoyK+uyOzyc+fC112d1P53QougxTOj8F1uR5u/Zvx6W7do
         C0pzFSdD2As6lINUX2tFU35qrDmQLBJqA57oOL0XYvO00ZOK/1RucCnGI2tRNVa+YZI9
         CVeiC9zLbaqwR8jNaNkXkY1kPGXypsAk78eeHvapJootNTOE7j49ozw5x2QqBtwscED+
         1epMPe+3VUFTMwkASGVrWwmsyfh9XOVf+AM1YM60J6R0/YFBH7qnVFlw05Unnlvdrk45
         ayYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7nx2J/Y4wZhvz0jyjFqrDAZVJJLefceyFJ5YVFiOB1I=;
        b=r6X0r7Am42+WDlGa1OyPur2H9ygxlUpGhPEPEK7VXwAdNevKJgLBkq4ekiWapiQ3mP
         UHcV422B2vBvJQyf7Q6QyilNQLmf0+fOzeoQDuq/NTfbHVjzJLz9Or/9++dji+vVQRbv
         7SeMn6X3AkwHrOuAYMjolD0ucBcC0AxrnOxIgs94zAi4r0svgDiqdYPafAWuVyr3r1jW
         YXQ4mD0mA/qt6btWuBf7SmRnvyf9utM0LIYkETCdk85CmyC8NlZWGzs3URrXCDCh3t+o
         IQ45I2DMu+oziX6z7j+TBopmtqoVTDBsA60BkhDxSZjj7oyTIQZ3bzFHnB44TJDzr0EU
         iJ1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7nx2J/Y4wZhvz0jyjFqrDAZVJJLefceyFJ5YVFiOB1I=;
        b=cC4BttJqcJM68mi5W/Lvl5QlsrilRu/kawB4d0DlBYJhf+pWlSVPKki1b8VOgN7gJ9
         egClzcecF920Xb0V50mp5bS+ZaOt6CVutkXI+ijcVSo3IQskhlj/1aILAMxzC0kLLXhk
         F7e7dxN4hkOUzAejvJ3iZEcXVGNvq8Ktr0SPdkV3XqAJVVKO4zP2nWT5I9VN/ug/Jzw/
         Ta39/ig5VPGAOyvveA9BJg4bMr/qEuMWPjWfVl7fRPp+VAzUVDtTe934AbA4QBu/bpt7
         sCA0ssV1wrFyWgLztHiQJaAAO9SCjWzJRmYxkdFbttX++C9ecQb9ANHsYk/5EodJPriS
         3PWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXCwXO+GI5qmUrBt9YPHHI+jHWRhbxd3juYg99gmLTjB77rTabO
	JZs2SSqAbgu4Ds8iNu+OrDE=
X-Google-Smtp-Source: APXvYqxJN3U9v3hiK7q67cCrvdjgoSBH+e+W7U5g/EURLNeGBdqIPTpDKYmYhqONUyLGNbHsDXDbtg==
X-Received: by 2002:a1c:a9cb:: with SMTP id s194mr5584452wme.92.1572370520264;
        Tue, 29 Oct 2019 10:35:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ca45:: with SMTP id m5ls6534wml.1.canary-gmail; Tue, 29
 Oct 2019 10:35:19 -0700 (PDT)
X-Received: by 2002:a7b:ca48:: with SMTP id m8mr5191527wml.133.1572370519725;
        Tue, 29 Oct 2019 10:35:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572370519; cv=none;
        d=google.com; s=arc-20160816;
        b=TZX+0wJjMPzh2VIYpG+VvjrueZw7MtdrP7ocoSv1WlG8olphNtAjHBAsZuUV5STPIP
         BjEAHflxkyGciaiHGtb8lBBozjnVD066nMU3HSam4S9r4ihbWZhFiQJmVaQv+Fv1YMAQ
         0+aNZHLQeNsSjfYhHT/xiWxLFuyF049QPvg3PDZ8lN+oLhNGlzV99ZSOh/+IWYeSuzyd
         I+q+QiJptqntnOUbNT+WhBf6B3CEjSHEoDzFiOYtMhCdG7+KL8BRd5dN89ho9+IY+vo6
         0g2cqBaLPaFSUCJudu+t6yqf2k+dNbcUEmccCR1Na65hPcTtNO5bKoFHOiy0rltq6KKn
         jDQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=FsN0fJjvUp0UEAEqtqzyu88pcSJxp4EW6EfbFjn4+GM=;
        b=TN9oY8eYY6fCdlRohivLO12BqiT0rE6WLqLzd2+x5i1DFBcu5/3SqA+QOFLlMgfh5G
         6F5nAbHJSzvlhDLiNWDlXakTdi1syQr8yjoXlCBorHHAb6r2xdOTPtySXd6ezme1Uddb
         bAcskj8SWTc3nFYMbUsXnaEl+yGDQqSaXK34M7I1NQiVRboRYvJVq1/XcNVcbw051YE5
         b5SBZ95CC7A4beP0FTf2dUBMcipIsaTAdOVYfKb+6CqfqVkIAnEE6LZdR4FYCtslahXv
         H7QJAgQ6XasOpwMqvELF1odEafej3CpcNSFlXdDLcvdNp6u7uEB2MlLJ5VRVhohuVS26
         Z/ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id n25si154266wmi.0.2019.10.29.10.35.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Oct 2019 10:35:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92.2)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iPVOe-0006jr-U1; Tue, 29 Oct 2019 20:35:09 +0300
Subject: Re: [PATCH v10 5/5] kasan debug: track pages allocated for vmalloc
 shadow
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org,
 linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com,
 christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com,
 Andrew Morton <akpm@linux-foundation.org>
References: <20191029042059.28541-1-dja@axtens.net>
 <20191029042059.28541-6-dja@axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <79d1efdc-5f11-1c20-9906-0f3cdcd60c20@virtuozzo.com>
Date: Tue, 29 Oct 2019 20:34:50 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191029042059.28541-6-dja@axtens.net>
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

On 10/29/19 7:20 AM, Daniel Axtens wrote:
> Provide the current number of vmalloc shadow pages in
> /sys/kernel/debug/kasan/vmalloc_shadow_pages.
> 

I wouldn't merge this. I don't see use-case for this, besides
testing this patch set. And I think that number should be possible to
extract via page_owner mechanism.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/79d1efdc-5f11-1c20-9906-0f3cdcd60c20%40virtuozzo.com.
