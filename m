Return-Path: <kasan-dev+bncBC5L5P75YUERBYW4S7XAKGQE7LR62JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9835FF5AF9
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2019 23:38:26 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id y14sf3108520wmj.9
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2019 14:38:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573252706; cv=pass;
        d=google.com; s=arc-20160816;
        b=O9RrRViEhuTdybQqK+KCrbK0A++xaFPziy4rGuNI1NmMqF/czXQVdo6GpDNty7XIjf
         632PviewAROtrw3YX1c27k7AOMGzr23moQYMvq7Wcuehi4xR1q7kkE7UQns5+QyLXA9Y
         v7TT6zWc9xPPN/fXaWg2KgXEi2NA4rsOxfaOHQXYjPt6QrcJTpvLjj0eqQ5lApjHVM6W
         AawrW0pPd/S0uqp2ShQ7IOzr2ZOsJ0L1AhepjjrlESVPJzAnw/A0i+ljyW9nDLBvaZ/W
         Twajx/B0KDisREzXS8qPFfpom2980ypuSLNjSQBpcZzfjKtZ04CCyHxj+LmZJ0DRkq/k
         ++Vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=eOjxi3rOCXjUQzS+h/cIBsL5UryTjDJ5WMl6vkkfKso=;
        b=aJ5IWoKcd2/lwfGz1R318dbB1Ghq6Gw0zuOJtHxIBarAd+3EUpJl3kExBdvVjBmdeI
         rTraZHObi6vxgWsvS1MBwZvsh88YH7M+mg4RpC8CY29cJtuWpchrMN/fDqOkygTa6A3D
         YD8sdWsREkt/RQZogy7Oz+6ZRYMyBeTHuO3psyBJV9NM7rUxmJhRYfaUnZa4uYzt6hN6
         2Dks1GJ2YvbrhlqNdTa3OIBJx47C2KGx2C4CdbwmPBrEiedIthZLdwAsotHflxn94OkC
         HXXDYW9/tlb7dSl61vpWH1o43sAE8+WXo9XjU4Wjjh93P9MUEisffD3zFJ9Yfzvsf3Fa
         l6jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eOjxi3rOCXjUQzS+h/cIBsL5UryTjDJ5WMl6vkkfKso=;
        b=G3jSf93GCzzxoFWYTTGxFeNL9Vp9R75wWumZBxlfrzqXB4/In3ttVY+TfFR/E1Jpy+
         DR5Hz2AFzlJSC5bOOW+Qt3cTyLqCTkoj2h8GNFXJ0kn4H4vhk97eDyek/tdb3XvZAdlk
         xc/jfFIr9Fix/ppCO34dL3kvYZg7dR61Bpwm8HxrXnlUVi9ER0uuTpHY+UVvn+VBr02f
         exRLZWH/hv0VG34w/8XIuOLnpi58us4gx9gxPDSotzrFMhqhSoPmDq1eVW3Ne9hN2CvL
         4ICP/IMlQyW6grB8mzIcijcCobYP5C6qxYrj+4LiHGpp6sFxvUw1dvQyoLRGCzuDNnMk
         NHSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eOjxi3rOCXjUQzS+h/cIBsL5UryTjDJ5WMl6vkkfKso=;
        b=niejISGrhW5uIEaHnIS0kiMziQmX3QhUBgUuhuqcqRcZCbsGfo0OJO6JX2olcGLKzb
         JMkT2doRC2law8gmbWe2NyCkkXvDbsVNdvqtG6K2yXLR8EOvOCxZGXMVIc1V3qRTTP14
         2yMqHlp6A7fPLjlZgtBqGCgdbmInsed6UJv04IgSiYlNKiowe+XGpEA9CRafWF++On6r
         58DkdYHz8xhWcJ1nekgimm9Z5jIXt63sWJHQpPRA+GhPMBVbOLt6zlw9vUu50xhKwmTX
         iB4qitoPob9eD0tzYLIrdCktjIL3XrYapkoWg0zOrb4Z9ohbWS6DSuRbthWrQV+wfTcV
         IWjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUh2wUhGlx9AJgUf1FPhcwGtybbs4RwCcptt4MVsiI1cHe50d58
	2w3nAxnJE++ibEj2kEEP/Ic=
X-Google-Smtp-Source: APXvYqz67CoNK+J61dKZ1Va6Uza6wyws+hqS7z9qVZy7ABCrZXfEY1CwF6Luh7GYIuibWFOExUvWgA==
X-Received: by 2002:adf:f945:: with SMTP id q5mr1352549wrr.33.1573252706280;
        Fri, 08 Nov 2019 14:38:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7c08:: with SMTP id x8ls9754774wmc.4.gmail; Fri, 08 Nov
 2019 14:38:25 -0800 (PST)
X-Received: by 2002:a1c:60d7:: with SMTP id u206mr10708247wmb.101.1573252705778;
        Fri, 08 Nov 2019 14:38:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573252705; cv=none;
        d=google.com; s=arc-20160816;
        b=EZWt946SSw5Gy3qxrqm/FY7qxHfdbEs31YLV6cVv9K0/E68EuPHorE6GEgzRPhCZEJ
         X+wzO9CSA+lTz3r5zL5d3EPnNOsCWjCeZ076elZSaOC+cF02OnhAcmOFHfLqvPmIB+Cq
         t/XQ8CaVeopXOWh1Vfp4877I985gQEquBhj74qFv0HAT6o4E1Y3s/v4uxtSpaOw+QwzC
         k9JQwo1kQhc+dWSJDe4u/m0N/HYBuxPcouo9qVuBQgVaAm81g9WlqYdj+S31JRkLsj0Z
         W1LfNTkxRvFz90DB9znim7rvy1QaYaKctideSceX957baEkI3XtqvIfYMHGwkG8mvt1/
         r5jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=m5tuyIxICM+OAAcIVR1qpw8yuOZur4DTq+oSTqCnn0M=;
        b=YgvCAdvmq3jsK3JubDbP6rLaFn+RSVtvnLUZC4tFHqLnhmYHghicMoTVZxPnOpTvCV
         y0H+Jqo5QsYDXJX+/vv2errworLjYb/uAyH1FEd3aLRRa21FlGSxbnhYo6NM0h/yCeTB
         +Gv5mVpsSmC+q66ATUDYvnPwArN3i2vuEJO9ovqngzPK+1WCE/rDkEB6kZGj8clu215f
         Grmcl+D1uQNocKM0kqnktB0ZhiNW/Jpbp3p69qoizVHcyOzb/KGKvC1HG++prD9JBBWv
         R2Nut6WwUfr04+4/Y4G0Uiww583NqdN9xAUw8LsYiHbuVXmeRC0wWPdtc4+W7WAfG78z
         /2Lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id d5si390298wrm.5.2019.11.08.14.38.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Nov 2019 14:38:25 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [192.168.15.61]
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iTCtO-0006xF-D2; Sat, 09 Nov 2019 01:38:10 +0300
Subject: Re: [PATCH v11 0/4] kasan: support backing vmalloc space with real
 shadow memory
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org,
 linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com,
 christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
References: <20191031093909.9228-1-dja@axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <3f9d1163-b1e7-ebef-4099-d40093dfe947@virtuozzo.com>
Date: Sat, 9 Nov 2019 01:36:46 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <20191031093909.9228-1-dja@axtens.net>
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


On 10/31/19 12:39 PM, Daniel Axtens wrote:

> Daniel Axtens (4):
>   kasan: support backing vmalloc space with real shadow memory
>   kasan: add test for vmalloc
>   fork: support VMAP_STACK with KASAN_VMALLOC
>   x86/kasan: support KASAN_VMALLOC
> 
>  Documentation/dev-tools/kasan.rst |  63 ++++++++
>  arch/Kconfig                      |   9 +-
>  arch/x86/Kconfig                  |   1 +
>  arch/x86/mm/kasan_init_64.c       |  61 ++++++++
>  include/linux/kasan.h             |  31 ++++
>  include/linux/moduleloader.h      |   2 +-
>  include/linux/vmalloc.h           |  12 ++
>  kernel/fork.c                     |   4 +
>  lib/Kconfig.kasan                 |  16 +++
>  lib/test_kasan.c                  |  26 ++++
>  mm/kasan/common.c                 | 231 ++++++++++++++++++++++++++++++
>  mm/kasan/generic_report.c         |   3 +
>  mm/kasan/kasan.h                  |   1 +
>  mm/vmalloc.c                      |  53 +++++--
>  14 files changed, 500 insertions(+), 13 deletions(-)
> 

Andrew, could pick this up please?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3f9d1163-b1e7-ebef-4099-d40093dfe947%40virtuozzo.com.
