Return-Path: <kasan-dev+bncBC5L5P75YUERBV4BVLXQKGQEYZQKOSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 77673115524
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2019 17:24:55 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id u12sf3358562wrt.15
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2019 08:24:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575649495; cv=pass;
        d=google.com; s=arc-20160816;
        b=SS+CC837pdniV/IuSBze8mNhKW8rxws4VBHp6m/NmWxI72DIOg4/+AQYamHtsW9FbX
         WnhgvgXE+xZJZ3JOl18N4QYCmJm60264Zsv8cmFUTYivMVIuuOr/l0wX1ZAzohuL+hvH
         t0HqJuMD39qtdi+jusV5Gdz54D6wOLO4wHxmG8E5p+dDvDWTwU/oaa9WwfJIc5QOYRQo
         SM582km63pwJcAcoRJFqWMQhDN3RYkQGr3BAKXdF/WJUVq+JBmvCp4p2cxYgbh2qa9Wm
         AxS7nfTgTljoPP4XDqrmy8a7w53+e/kyr/5jQveYnXDoVQjaqIxiT/wCg5fJLyEdg6LL
         ttQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=HY+x4FpWMF/fRq6R2KGMBy6DmXiN7fgcpnYWaYe8SOQ=;
        b=bKAY0YALCN8B4YE0u5msX8+K9eeQhTO7aCxJathgXDBly4sQFYrJtlhh7I9A8jXarl
         EfOhpWGjN4liZ1w+MTeHFyMnXfYMKXcXr44pwPSJ6OO0eUD8UKd0Agcd5u3ZfwTESAbQ
         sN+rwpnWed38YjxwStEQvMHX00kmwnsoZPa/mSgOHmEEeiGiRf80uHuHdfWKFr4shd+r
         ezxyvtr4qSh4VzolFozXw54qTcpilKqBGzz+zME5HKT4iHapSOfpCDE5Z5l72spyYzQp
         h+kCjZNgwbdkqi1dA8LYaLAWXOl4V4FhvrQ5yY1QZNqK8PKXgb/eScm4v/PbXXVqNYKt
         BW2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HY+x4FpWMF/fRq6R2KGMBy6DmXiN7fgcpnYWaYe8SOQ=;
        b=Norx+yPQWYtQCeX3JfiIU7hY1DhDLFdddkvoSFSf5Pkp9QjCb/mBwcUg6A754JcCmW
         elsHpZsj1DA+IR9IJiKJDK7qKMrYSOVRW35Eq7ufBMJqcitSOu3iuW/n5pYK6w2v8VMr
         syKi89PEieErYOZx0utPeVXmef2aMJJStHDFhVrr3elzf4byh0ZZqLZ5mFN6frYhRH7r
         JQwGUYy3yNyDfiLei8Oe7GXbhcQZlgXqPu/rf0asShCgiO3laJiqXaBRi/urtuYnHUMP
         qdJJJf+VJC9UToo6PWEwRgwLyQWgxdNZA7nog03jrbnOawjhp1H+os+hbgC0JfwkL4hY
         TAaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HY+x4FpWMF/fRq6R2KGMBy6DmXiN7fgcpnYWaYe8SOQ=;
        b=f4AF3v6O+nX6zyvVN4GRw/Kq32xkArtxHLwph8IlcZPbt9JbCjTEOzsMw5RcVcmu7m
         Ez+81GoSE7uEvHW0iB3NKc4s53RQl+7vmJLoEtj+6al51LAaN0d5Hsbq4ug1gczEtBFb
         u+g3FDBnBGZn8vuAhtQeUjE+9x6//FIFsNOAW8pGfk0MlcBY/4FWzwJ71xC8UkVXdMZq
         vtxjukfop5UOiggQb2KET5WRjw0SQUAO/n/KIp7SrihwoBohRgTaJ9A+AFFucUNr7D1S
         2lXuLUqsp8ur+9TFfWgE1nIzM3481vyvKMB2hWdoxUbPcH2eGKOd8p5aPA+AKZ4ncG0Y
         9pOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVX1O984Q6zUjgM3OQCR559CuPPvDST2SQuZfoNtW9LaNucPaBJ
	LWRcIzuvHSdlIHvTm2TAdRo=
X-Google-Smtp-Source: APXvYqxaXuWA6v14lzIy+cv4FzAyWmg5oVwcEMFk3wppw+lqQiU6esX0NPKhLT4i2HtMna+y5QjlxA==
X-Received: by 2002:adf:dcc2:: with SMTP id x2mr15600089wrm.24.1575649495119;
        Fri, 06 Dec 2019 08:24:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ecc5:: with SMTP id s5ls2679784wro.12.gmail; Fri, 06 Dec
 2019 08:24:54 -0800 (PST)
X-Received: by 2002:a5d:6350:: with SMTP id b16mr16938484wrw.132.1575649494570;
        Fri, 06 Dec 2019 08:24:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575649494; cv=none;
        d=google.com; s=arc-20160816;
        b=062pE6/Iw/u7fSm40Rybok3Tztl5drEF9Xso0okyx9sNBlUAubo33P75c6Ib0SfGtP
         I2ZbM4wzbw9MDsFq3qoKtuwNRRpeSAAZpAsnFG1hMUC9ikcREUsBj9ciL8n3i5xTV8S8
         Oiw4Mui3sgFmDCRthgmJh/r2S429yMePSSZu+HfFcWm2TFdHw1XFARVmfEO2wQB6JF1y
         PULAi4u5m6w6cduZXZHfJiqVoyKd9fVrcyo/80g/7PlmEuD3EpsOZz2ojKLLMfIC4E0P
         giVFoxN2nmBV0uhuG097yQKytBY+xaFphczoiSE5hYXfzXAtV/76dQ6CinJTZi9QdGVZ
         K0Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=X8L4RDP78rSf1EWoVsfMpf3Netuh201aI1Lx6aydi/c=;
        b=c7ZO9zX3VIlngV7EDZlLz8pPJ0JYpi6/ZyApDMuNDjNkJx4QJJ7GSz9LqKez+lQJLV
         7Vnq7CYSqA4MAK+HRdXPqAx1zyi/Xp54IstZVnC9NcsIhSXyhgX3R1xrYKo/iyWt2gQK
         fCwHaVGGWSkg7CQAr2dLWENA7tG8XjW3ke6Ty2blCeHUmvnbfW2kLMvi1/3LDJ32RH3Z
         fokNclHub/0L9skNJBHUB1OcDxFZuu6pVrWz+/dovTw7T6ILP73LwQXVMlC3jpIR3s+5
         h18A04ccR2X4lx3QAlRkJlc1swyFOTnt03b62o19B7cgAXayRlzhTLsoUBRKYuVFe9kA
         YxQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id j65si202011wmj.2.2019.12.06.08.24.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Dec 2019 08:24:54 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1idGPO-00009Z-Ih; Fri, 06 Dec 2019 19:24:46 +0300
Subject: Re: [PATCH 3/3] kasan: don't assume percpu shadow allocations will
 succeed
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, glider@google.com, linux-kernel@vger.kernel.org,
 dvyukov@google.com
Cc: daniel@iogearbox.net, cai@lca.pw,
 syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com,
 syzbot+59b7daa4315e07a994f1@syzkaller.appspotmail.com,
 Andrew Morton <akpm@linux-foundation.org>
References: <20191205140407.1874-1-dja@axtens.net>
 <20191205140407.1874-3-dja@axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <87172e8f-9698-0805-252f-55f68ee07862@virtuozzo.com>
Date: Fri, 6 Dec 2019 19:24:31 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.3.0
MIME-Version: 1.0
In-Reply-To: <20191205140407.1874-3-dja@axtens.net>
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



On 12/5/19 5:04 PM, Daniel Axtens wrote:
> syzkaller and the fault injector showed that I was wrong to assume
> that we could ignore percpu shadow allocation failures.
> 
> Handle failures properly. Merge all the allocated areas back into the free
> list and release the shadow, then clean up and return NULL. The shadow
> is released unconditionally, which relies upon the fact that the release
> function is able to tolerate pages not being present.
> 
> Also clean up shadows in the recovery path - currently they are not
> released, which leaks a bit of memory.
> 
> Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
> Reported-by: syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com
> Reported-by: syzbot+59b7daa4315e07a994f1@syzkaller.appspotmail.com
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87172e8f-9698-0805-252f-55f68ee07862%40virtuozzo.com.
