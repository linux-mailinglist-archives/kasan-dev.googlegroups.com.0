Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBR65U2AAMGQEHYONXIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D13722FF0A8
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 17:41:44 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id x19sf1819048qvv.16
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 08:41:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611247304; cv=pass;
        d=google.com; s=arc-20160816;
        b=NSJYi4w+7GWYofRPdDTDg7JYs+18cGBcJ1fzABdX0ptALQAhhfX4VywzHGNcQD2Juc
         fQWnQYnF54Lg065HKaS5COYzUeVcm0VTeR4Bs5d7bPDAOoMqiDEpIXmd+8PnKiCVs27c
         4JT6nrTBbHgo/ufBl6VwSWN9q30tfNK1WKvtd42BEI9JJ3j1G2euDe356Z/XQJ6TvB5f
         zIKAp4E2o9374qqaZLYSk1cf5dS8stnrvVDbyoq4CaRSsBp0PIMoIZP3OLgmrwON+zdo
         bR4E39JYtAhi/xM30Ex0VgrxHxOmi/Xx6TKbttVJ+hq9uhhq5S01FO85U2dyWcmLjJJf
         9jbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=v7DfrRS3KvDY62etolN3zfC/b4W7GxPYpKfSBiNNUB8=;
        b=tpe+Gio3CyqBes2xX0mEzNkME245BItrUBQh0Yck6b9RRkbLBmU0NhEmC0YlVe03z5
         0Pz2b31xmYGHWQdv0juSNmINArhGUlDT6hiueNEYUDsdny3Phq6l15tiJsu5xpdnHqL5
         l/V0t/qLYrkfq5J40cwZ/zihodbhQIiQswGWd4frQQfnkWX0Tr+bUY7Y/ZMq2VI4BK44
         usMp9sfOSo5RRUpmi88dJj4v/tTLXW+NUo3dqtFaVpSU2iUravYfftWJOeCANGi1mmcd
         umybNtNYj1htU2wpBn0JruWKeDL2pnk4ds1VEwdAR8yb8HlU9lsiRmFMNgjIIgBJwyTa
         v7Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=v7DfrRS3KvDY62etolN3zfC/b4W7GxPYpKfSBiNNUB8=;
        b=SntGDGlEcSi9CtDQRkP19/u5FV/taaBbCcucGPNcF4qHAaWz8f2fqWrjFuYLmF+mpB
         PKO4T0FnRA7r980TOlPzMTW4VGj9CpiPVpnl6pKHqFr+Aee5Iv8KDq/GUolObXAh0QUM
         AyRHcsq5vH0/16H3WJtJ+md8JjaxN5xtvQxpjQaG9pziiOdTjbsXTqWfXoota3ZjVsRa
         4/qiw7eNCvGtuq2xRc9jSo1ZoN75P8sqeNhXKOAJPjIxb7CV8BrQaTb1geeQr2dtRB4E
         fiqdGuFFRgmG7f/wODvZnLNLBi7ZfXFJONArPWxCWYpP83ufv4rT9KR+1okVHOzpWH/C
         UOpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=v7DfrRS3KvDY62etolN3zfC/b4W7GxPYpKfSBiNNUB8=;
        b=eNO/rL76Tn5V1ROZujZa/0HXjx0IUbdtXEUTneDdv3zhVpTqDS0u/RKtqd89iVdbR2
         7s0CAPR8boBv+VqqumeP7374wW7HVtsQAZZUv8EGfRhsweSISu1uIPWXjSsstYfGpA7y
         xG4ba3PJSpvGFn5WdSOegydciQLF7NTV6x2u/BuAL4tNnkX8Qr2howd0YRXDIUcVRVyA
         jS5j6ST5U5rkSFuvLn2HVSCD6ddQyDGiQPMKChnne7zxcA+CSkBK3cn16h+mbvj1bVOc
         sU0xE1+yG2uY6rtW4DL0LY6oRbyF7KIbFlor17XtnJ+Ai1tFJgcFajBVoQB4O95O5c/c
         vttA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530881ROUnc50ukkF+jgtzm6RSarLwsJtMCtPW+q8rg2/Wcq/uu3
	kf7Q+1gcBTqu2bOkvuk0FZY=
X-Google-Smtp-Source: ABdhPJwThQL+0NvlqyAdxVlLoGMPcbwvqaSvBmQoE466h3UkRehtsYDH//aU+bT0EXlamaHPGZ4jxQ==
X-Received: by 2002:a37:a250:: with SMTP id l77mr593145qke.185.1611247303979;
        Thu, 21 Jan 2021 08:41:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:5603:: with SMTP id k3ls1366379qkb.2.gmail; Thu, 21 Jan
 2021 08:41:43 -0800 (PST)
X-Received: by 2002:a37:67cc:: with SMTP id b195mr615492qkc.406.1611247303540;
        Thu, 21 Jan 2021 08:41:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611247303; cv=none;
        d=google.com; s=arc-20160816;
        b=0s2P49/CdLnUpiLbt5G/+2XNrWEHU+KVlkhzJfh0V9uSOkHl+aSscxyCCsILuoXh4a
         6WP+iXKvqOI7WPc4HWc6tWmncEHuCKjY+vHIokY/pgDqDn+gllqVYq3AmK0t+Q3ljV/M
         VuhAg3nEVY919xceQ73Q4pglwt+BdsZSG6S5IKgwH8/eDARMoftMIFZgwCihUHs/TxTk
         vW0NsazZzW+2P4wmM3dWrZ2oG/UvW8UEsow8j8wOp2rOaq7EikUDtvq5Wi/zx9dzXObq
         lf5IY6uMUc/8yETf/hdT+i0qs9akjtHqaRNrNqvjAknYS6uErXCWOk8hA0gUeUfP8w+3
         xAoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=DhUA/oWBmNfytbDaWDXzC9Tjix7KqVvatEB5g3q0WP0=;
        b=uFFYuGtambvtFcp5Ip+eBrYDc+C+rZ2YBoUz+oxKwlSklXtluLAelCqzIoCZ7O0mmD
         IBaknR1PmXa7mpaUWMPQzJ/m3MkyLdU4GlTwcQaXWbBT28cuLEvo692KhZJYjMYnMiDR
         ANiRIJYMLLxlKwPIlXC/+s7Udmdjx9LHzA3CoVX1EK2cJWxyEalVQRjN9ZH8U0LEkPQ+
         v5iQQwBOHP79cUcYD/ZzlsbiaAm17EVzV6WFIxSdHf3oP4J35hpCPTumjwPfpC4sPLNc
         4gYXhiXdY5CTPwmHVNZ0NcZ9PBHQ8F6MoNW2ytAT06JtAexu9KVazRV4JSMQ4EquVVf6
         lEeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b7si465410qkk.5.2021.01.21.08.41.43
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 08:41:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 30A9311D4;
	Thu, 21 Jan 2021 08:41:43 -0800 (PST)
Received: from [10.37.8.32] (unknown [10.37.8.32])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B62CD3F68F;
	Thu, 21 Jan 2021 08:41:40 -0800 (PST)
Subject: Re: [PATCH v4 2/5] kasan: Add KASAN mode kernel parameter
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-3-vincenzo.frascino@arm.com>
 <CAAeHK+xCkkqzwYW+Q7zUOjbhrDE0fFV2dH9sRAqrFcCP6Df0iQ@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <94819305-66e3-1873-c982-f043a341daed@arm.com>
Date: Thu, 21 Jan 2021 16:45:30 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+xCkkqzwYW+Q7zUOjbhrDE0fFV2dH9sRAqrFcCP6Df0iQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrey,

On 1/19/21 6:10 PM, Andrey Konovalov wrote:
> I'll later add a patch on top that forbids running the tests with the
> async mode.

Sorry, I misread this part, I thought you wanted me to do this. Anyway I added
the check to my last series.

Please have a look.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/94819305-66e3-1873-c982-f043a341daed%40arm.com.
