Return-Path: <kasan-dev+bncBC5L5P75YUERBGFCUTUAKGQETGBF2UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 87E1A4A6DB
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 18:28:08 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id d22sf16398lja.20
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 09:28:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560875288; cv=pass;
        d=google.com; s=arc-20160816;
        b=t1CYHjEJankOVG9dEGKr+eqINBK/y212fcrpJLnXEfoZ+7Ju1g96Ab3kJy88sCh4n4
         u28m7uPcZi29V0a2ZJHm5P7BetWdDEcoCAKROsnhr9oyvIqFnwGAF5doGStTUkV5oKK6
         vdMN3TdUnLvhldE22JKAEkD85R60CduKxGv/UzejSqSFhRGqiroCbX1ZQZ0z/3mOycEd
         87rUaZFkHhtblokDBQoBr8rsnQnJrWaL3I8mNCNB2Q/P7eg8l05LIKJ+aErgRE9q+MW5
         Wxubpa9BorXJy7Ay/i3pPEvMv+P6TQP10aCxerFVDastXnDBhO6XTrx5svxaqv+FjILQ
         xp3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=z6xcEo3hKaeh7WIm3js5P8c1g3YF4UCFrHzrX8fZcUk=;
        b=Ndq/65+RImFMrYb078I/NY4ci2fauxswHeE9QSKau3axhoQPWLUp9oHF1DQsAz5IJr
         oh9U/xR+OeWVJ3XLAFgYVE8KJs+QIRUIOO0ZPOMa9qn7vpLMLGewP5BAGGmP56lYa8wB
         dfLEL9j4Nd+1u5wH9kNFurN62FSdyFvyFzYMvQdVaOzxzv5k9FJYcLpiY8RHzQxnJw9J
         fO4JzDkp5d5YlumAzsGGOiatqIYraprX55IMIpmBvSYOGjmQj0S6MHZLXLR2fwsP7Hmi
         s6xlVnTSTvsd5RM7+9x05zRcfcMKc9gfltbEb9qA6vpwCvLOMdTn2f6vae6R6VSLfmmm
         h1VA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z6xcEo3hKaeh7WIm3js5P8c1g3YF4UCFrHzrX8fZcUk=;
        b=GitddzkILcJDJxQ/ADw4/mjTgeP5P8J3R1oEpBXbGJdVkyXEBbzlJSj8nZHp5Im3H8
         bpZAefDecT/xXl08OKZ31+CrsdKoqEK+WBmKqGcgNJqbpXa4rAoNmRMZf3abRopfvOHt
         gQStWkonEbN3gVAWror0pGe6gen3cDyqmEGeQujqB9Zite82g0K7oe0qFUUq2SIEvgiy
         pwHNvvW3FKB3GweLH68NP0Uvl1Z86NNOMmynwRrk6bC6faV5d5UWkRgxDzfKyFglQvFC
         D1xHxG0kLG2KZ/+93Ssb9YUFPV3m7ZiN7ipwDW/eDDXL6rDHrR4/Q4gXxAjrMoT+1WkE
         aNcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z6xcEo3hKaeh7WIm3js5P8c1g3YF4UCFrHzrX8fZcUk=;
        b=FWNKEMPECgK0LQ84ea5OyahCgVQxZXqZ4rsAlVN8gEUaNf0Sq2/gHApn1YXJ2xyrZd
         9qgMU0W6AcfX6EQ9spONv3TnETKqb1IxOHVkkM3s8G+6U25AMh6dNu0z19SWplju3T5R
         /9FoDfg3Te2vmQAoeZD8aFsMg0euNjUHIrwqJlaeTwSs11zTZfR0guT4e4gn2kW7ImMJ
         ogz/DZMNFYt4RdT+ooNm+qhxmpAnYqrZjdelpRByI6pr6FBts49uefAYZNrIovQhqTgB
         hTECxtr+dE/+Vd4VVB/LhYU2OF7zbjE1md0wkRb0wlMXUY9hs+p+xccxz3rGPwflPKS5
         tz0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV35yZ+c79dLAdPwjddxaOc8QWaul8/DLgtQcm4SefPUdSI2izt
	QvzwsS5j2r7C4k4pJM33L4I=
X-Google-Smtp-Source: APXvYqwXndPrG+xVnqn81hlHdAnnck/gJOOTu/lQpSD08XQw/b+LEkqbjIvsHgviWDeeRyPXRvij9w==
X-Received: by 2002:ac2:54a6:: with SMTP id w6mr19173402lfk.108.1560875288104;
        Tue, 18 Jun 2019 09:28:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:92c8:: with SMTP id k8ls2405277ljh.7.gmail; Tue, 18 Jun
 2019 09:28:07 -0700 (PDT)
X-Received: by 2002:a2e:8559:: with SMTP id u25mr16700090ljj.224.1560875287679;
        Tue, 18 Jun 2019 09:28:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560875287; cv=none;
        d=google.com; s=arc-20160816;
        b=grbq+LATDwn1Dau78plFDa6/P0EzK8gA0CcW42k13/ovXe1+VDsnuV7LcfxQYfhrmI
         YMPrQClocFYE5jNEECZ/ud5aOCtxo+Q1Eo8NM+3Mj/DGJV/CgarXF0VteUcTPKyF456A
         K16ICOf8rHXtRnvXSKw0PCTHqqidHRggDgoZplyK6AceIS3/a9xW8wIu7/ETnqTgoqER
         lT1lK/wTFB5B40IRZDH9I3qakGkFW6OHyiFyxU9uw6hMFozEIrjKkVicm8TdrcyGJLGD
         PDlrZXPAeB1u6cDbem6gfMh4CxE1Z+t1jAwuZe3vT+Q6sq1MShkkOopLSzt4ZSExmPdV
         UeXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=jU7PIwhw4fc5R5yu8eYhYLUBF3pk1ulWXKj0FSCGJqE=;
        b=WUurc/4dRJc59EBoOY3VQ4oyyBS1Td37l8BOLShCkNr4WnvLHUNz5aar6cWLzTiBBr
         KJRRajYi+FtXAhRFSJ4Yy/z3iqNghQ7m29K90sE/t4qZdkQYerC03w4U6zlWL1Ta8xQT
         Xr4W6v6vUu1EmQrx7ZOOx+20fl9lzjJDtzKogNbR+RxZGoXQIfN+G75pP+v2a/oZQ9Da
         brGOntd1NV28xpV+fLR9I/LTshvzW+Bg3zg3vYKV8Ml4SKmBmoEDf/4+ehhvM3ODwNPB
         3UNgPzVNHWPFRIrGg8V3AjepKWLS326YDZRyyid7f142uRixpOkiOZcY8/9jlynUTAE+
         EbWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id v29si821408lfq.2.2019.06.18.09.28.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Jun 2019 09:28:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hdGxk-0002qE-CF; Tue, 18 Jun 2019 19:28:00 +0300
Subject: Re: [PATCH] [v2] page flags: prioritize kasan bits over last-cpuid
To: Arnd Bergmann <arnd@arndb.de>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
 Andrey Konovalov <andreyknvl@google.com>, Will Deacon <will.deacon@arm.com>,
 Christoph Lameter <cl@linux.com>, Mark Rutland <mark.rutland@arm.com>,
 Linus Torvalds <torvalds@linux-foundation.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
References: <20190618095347.3850490-1-arnd@arndb.de>
 <5ac26e68-8b75-1b06-eecd-950987550451@virtuozzo.com>
 <CAK8P3a1CAKecyinhzG9Mc7UzZ9U15o6nacbcfSvb4EBSaWvCTw@mail.gmail.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <e782e546-dac7-8479-d5a0-fdacfb3359b8@virtuozzo.com>
Date: Tue, 18 Jun 2019 19:28:10 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <CAK8P3a1CAKecyinhzG9Mc7UzZ9U15o6nacbcfSvb4EBSaWvCTw@mail.gmail.com>
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



On 6/18/19 6:30 PM, Arnd Bergmann wrote:
> On Tue, Jun 18, 2019 at 4:30 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
>> On 6/18/19 12:53 PM, Arnd Bergmann wrote:
>>> ARM64 randdconfig builds regularly run into a build error, especially
>>> when NUMA_BALANCING and SPARSEMEM are enabled but not SPARSEMEM_VMEMMAP:
>>>
>>>  #error "KASAN: not enough bits in page flags for tag"
>>>
>>> The last-cpuid bits are already contitional on the available space,
>>> so the result of the calculation is a bit random on whether they
>>> were already left out or not.
>>>
>>> Adding the kasan tag bits before last-cpuid makes it much more likely
>>> to end up with a successful build here, and should be reliable for
>>> randconfig at least, as long as that does not randomize NR_CPUS
>>> or NODES_SHIFT but uses the defaults.
>>>
>>> In order for the modified check to not trigger in the x86 vdso32 code
>>> where all constants are wrong (building with -m32), enclose all the
>>> definitions with an #ifdef.
>>>
>>
>> Why not keep "#error "KASAN: not enough bits in page flags for tag"" under "#ifdef CONFIG_KASAN_SW_TAGS" ?
> 
> I think I had meant the #error to leave out the mention of KASAN, as there
> might be other reasons for using up all the bits, but then I did not change
> it in the end.
> 
> Should I remove the "KASAN" word or add the #ifdef when resending?

It seems like changing the error message is a better choice.
Don't forget to remove "for tag" as well.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e782e546-dac7-8479-d5a0-fdacfb3359b8%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
