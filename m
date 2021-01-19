Return-Path: <kasan-dev+bncBDE6RCFOWIARBV5YTKAAMGQESOWEOYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 172C82FB479
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 09:46:16 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id x20sf5596762wmc.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 00:46:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611045975; cv=pass;
        d=google.com; s=arc-20160816;
        b=zsRUUllsDHzumTjF/WWsbFJCzKMC8wRexlloYLGmUulkjUyLqLqPvLDe99dWjL1S7g
         6Pm5zywKJQoPBfLWfxaueR8yOX4lY3k1pkxtXpYLp69DTN/X5VclJPca6i1tHWoOnylG
         1IrmjGRn4aCZs7XXSgZAXSWUFfRDTd0hV5WHvF4uuYiC33LSSxPY5GpzOT0bd/Bw/f/U
         6oEYp12j/VG6qOKC2VHVQU8mOYGgtOQy4y6mdc8s47SAm2san+ZjuhXmWll3vePDb0HP
         5y/wMPlu035+KDoa3MTwtuoaS/FSwGDtl0sU+kuXR40i6UBA3b50eoyFMU0DLUPzzPk9
         UKfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=1vAWodox3wXmfeBQxAoCjcjDh5VvKNDeFOkfIZqv5Jk=;
        b=o/HHEHVTYyPnQNoKMw98w+f2ToAhUayC8ouuK461/k2eOKJbUDNScuaur7z+v47wY/
         YGffu4lvREuig4I5Z+aJ6TJtg4/qqBP6KE9rl5zcINBNO4oRu69nEL2Xm88qYt7fjETj
         i/JxWqHSJ5BziMqCXUyxpF9Pm32HQljIKs0OavRst+fgBk+eTnu0PmW6SSG2g4uV3XAb
         WlI2GSQIbGQCq4PGL1I8LRCNnLIUqQH5wsdaTpF8gbGFIbzHzcGs0y25WbctJe+vUW6c
         XfvkMLok1Fy0XB8dNAmCX16r/gBL0adgvAuJOPIRibwLQwH+c1p5qa3kRoLAItEAH7J0
         RX6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=qTT0PMiE;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1vAWodox3wXmfeBQxAoCjcjDh5VvKNDeFOkfIZqv5Jk=;
        b=r61rhs4SAWKeFprllbS7U+IaADVR4wYxXreJEC3OzU0m1Lf6r/xZi5p/XUskWCENtz
         dq/wLB5TfYt1krkwWNq7ewzz815fIkWHmgI9vpf/HOHsMH/TrR+1LrV5MEW3M2NsQvtg
         mx2DM7V+7R0A4EaSpQfdIPG8tQqyR6hjqpbjJAQ8Ll40WgPLgZYpTXFNw7se3YDiUwUC
         qOo3FnmDPBwJGzRYxU538qidqsuWUC0EUa1UECrB7iUFtRlokC4Fgk8woAziAKN8H8PE
         gsxGVxWgy44wXHz6l5S7elRwika/5aB9KxuoxwNHau0QdhjoXg1Q2Od52B+lbXhnk9zo
         YQ8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1vAWodox3wXmfeBQxAoCjcjDh5VvKNDeFOkfIZqv5Jk=;
        b=JHssq8E/EZdqQdk0ZDlWM937CCU/0vdsCwuRPEqlCLCYPl3CAns5YRHA1I8nYu7TIg
         ayvHx67eqJfGJgoHn3WTdlvnovq+d3jJbG05U/Xny9V80A4pSsR8cnieHeKuDmGxPejC
         MjfPZHfG0wHamEFNqE1kNjYbPngqGc1hVOzBfFIuqRsTEWiPQrdI16sEZ7322Y9MbaAb
         AaYpuLDfVRvPTF0m9JNoHgDF/h7yGaRPDmuJERWJSiQqQCZ47hUICNLe0yBwcYO6pNc3
         3/sayEvwqTrGzn7QhlwN5LYCqzGklb4N27xhGea8DeV35Q/FIu3uNrnCXlxgKrs51FTR
         S34g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533RdpAYnYvHXnHbNJ+Otokb0FDYUe+D8f0kNcg4ndWNdMDzeU3f
	T04DpIfQi9LDTobG0xWkYmA=
X-Google-Smtp-Source: ABdhPJyGvFQUcwHj4jeUhiJEYhQcvRPusGCZf0KyKXUGmQn14njG1VuF7GWHz+nOcmpjuO8gRAXnLw==
X-Received: by 2002:a7b:c842:: with SMTP id c2mr2994510wml.100.1611045975896;
        Tue, 19 Jan 2021 00:46:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c8c8:: with SMTP id f8ls7684102wml.3.gmail; Tue, 19 Jan
 2021 00:46:15 -0800 (PST)
X-Received: by 2002:a7b:c09a:: with SMTP id r26mr3046659wmh.64.1611045975075;
        Tue, 19 Jan 2021 00:46:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611045975; cv=none;
        d=google.com; s=arc-20160816;
        b=UtK/TzTBUkjjVWr+0h/1pko+fz8QFmZfvxwe2a7JhzHC4RKZNEHfguKl4tzEQjklvH
         9Bfya/SkH/TUyIcXfzartAXHUKjwVsDE6ZPgZE52iOqMB3nKlD/Kh4AgGChYa3v/15y/
         Jfkk44W/V3y0JS7VBLrn/BMd+vOL8jxhkQhiz/2lAJepr9H7tkta/f/+ME2ILnwDYWT/
         ouzg/xAfT/Rwzq72+x/UH25tehUmt6f6iBoSEkzsLMvIURNeQJH9QyiybkpcV0/nl825
         tSLSJUqzqcShqLNm/fFO19Sn0GsbVLYY/bKCch6sQeCeGKea0c2vhIEJUAHVOurCkXuv
         +jtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=e4c/l6pqzWgliL3bjMtUqd60Z3Rl9gWMHhhn2sakF40=;
        b=VURd1skH+LjtBzt6xMon/I4Sq4hFko0KBM3W+aVJcB63u1krDbHLkCkjk4SgMMJn5R
         e41PK4ynToFUzbMbzMN33Qwv3WegFltlN8TaCHQFG1VVIY1I0zJqgnioeAnh6o79e2Qx
         aatUfnrsxeNTDebT9tV5DL1WuSUz89/7iXvIXLIrZYeygj71qfLEfSE4fi6hvSHvZsV3
         cE5cLTmF6exOxVz9Hc3bdLTbHXkQNnLKK8C/hgCUGwQnweOscZRuBRK6P88RatIL+3D1
         yYfkH64+fJJGAjN7aTJYl4ApvM8G76PzyPP90eV8KtwiyPNybE4+jCoSc2ECOBeHCCFE
         /kpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=qTT0PMiE;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id n8si1110788wrr.0.2021.01.19.00.46.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 00:46:15 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id f17so20953177ljg.12
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 00:46:14 -0800 (PST)
X-Received: by 2002:a05:651c:205b:: with SMTP id t27mr1441258ljo.368.1611045974782;
 Tue, 19 Jan 2021 00:46:14 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
In-Reply-To: <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 19 Jan 2021 09:46:03 +0100
Message-ID: <CACRpkdY+HLXWyq=xsBPuyB4dFxyR5Xa_4aWMmG=sO4YRnpuFEw@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Krzysztof Kozlowski <krzk@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Russell King - ARM Linux <linux@armlinux.org.uk>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=qTT0PMiE;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Tue, Jan 19, 2021 at 9:37 AM Krzysztof Kozlowski <krzk@kernel.org> wrote:

> No clue but I just tried KASAN on my ARMv7 Exynos5422 board (real
> hardware) and it works (although kernel log appeared with a bigger
> delay):
>
> [    0.000000] Booting Linux on physical CPU 0x100
> [    0.000000] Linux version
> 5.11.0-rc3-next-20210115-00001-g77140600eeec (kozik@kozik-lap)
> (arm-linux-gnueabi-gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0, GNU ld
> (GNU Binutils for Ubuntu) 2.34) #144 SMP PREEMPT Tue Jan 19 09:23:24
> CET 2021
> [    0.000000] CPU: ARMv7 Processor [410fc073] revision 3 (ARMv7), cr=10c5387d
> ...
> [    0.000000] kasan: Truncating shadow for memory block at
> 0x40000000-0xbea00000 to lowmem region at 0x70000000
> [    0.000000] kasan: Mapping kernel virtual memory block:
> c0000000-f0000000 at shadow: b7000000-bd000000
> [    0.000000] kasan: Mapping kernel virtual memory block:
> bf000000-c0000000 at shadow: b6e00000-b7000000
> [    0.000000] kasan: Kernel address sanitizer initialized

This looks right, I'm happy that it works on Exynos! :)

I recently summarized the stuff we had to fix up for getting
KASAN to work on ARM in a talkative blog post:
https://people.kernel.org/linusw/kasan-for-arm32-decompression-stop

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdY%2BHLXWyq%3DxsBPuyB4dFxyR5Xa_4aWMmG%3DsO4YRnpuFEw%40mail.gmail.com.
