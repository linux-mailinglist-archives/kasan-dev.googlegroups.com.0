Return-Path: <kasan-dev+bncBCRKNY4WZECBBT662GAQMGQEZWNCZ7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id E9CEF322451
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 03:58:24 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id s6sf10712506qkg.15
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 18:58:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614049104; cv=pass;
        d=google.com; s=arc-20160816;
        b=eMQIQk1L0jVUQSK623krSQT37jZHwTOlqv8o5fG/9/Nv6RSJ/1te2lQmVasHXKmTxv
         q5yTe7LoAY1/pc2mrFAzixOEA0zhVK+ZOTSjkbsF4cTwEqVb3/Fcwstwlc/qPIo2jvzz
         CuMS4nzLvxvUabZjiVeF23b/33XDqXwGETwZadfKoC37vYBxERRW5zcF1w9mZGq9vB0x
         zZlE7PAoVL2NNU1+tJMw1MbnFzmUs/WdGA+RM0BlTOZJNSfkYaVRcP8uSF2fEftREMtK
         9JmGOEHL15F4XOE6a6msrDnrdOL3PgFdgJ0M2/O578UR7if3ezF1x9P1EamfZv60biw/
         nA8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:to:from:cc:in-reply-to:subject:date:sender
         :dkim-signature;
        bh=W6ndJtnjyPDdyMlSiobnlhSUqOXZkUw8zIrKlqE4Qo8=;
        b=vPtSO+Cctadlr+ZbIkdqCdrVoCCVO9oNcf3I7EQVxXcGXTIhgkimy4bQUYJ1gA/8PQ
         pdaqQVk39KmkwhtwA2LFN2vP0Bne/9/hllR8dozA/fPebeL7Iqbz49CHT4CkkHbrK1rR
         WzvtfmQq/4LeIlCutoeGDjhaenphP7PIAEwM6qZ/ZGLvbcoe3nyFC8kmEbCtglGoDjmy
         tRsm4y27rUeaPQCQQouAH8QbrqkfVOHxQU6C4CGvAbgT8ZwopHJDHipudLl/0EJ3+GHu
         j2NUlIPQovAu/q/39xGqk4LxH70WF8yIhgelwyxoXPXpffMrCVFdEOFFXRiHI+/Rz1lv
         QltQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=p3c4YUSB;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=W6ndJtnjyPDdyMlSiobnlhSUqOXZkUw8zIrKlqE4Qo8=;
        b=jwgDU2PYInKybnHs+aiq6Lw9M1XO6LWrOoD6XxhbmZ3gV8rFEWiE9BFhF2/90JEfaa
         nMhpTR25BbmHdwIAbPUsHvjZf0cE1I99R0e3SopkTgJuW8GI7EjYJ7iM/0OG96KPeQI0
         GQReImlTh1jxNUlPOmnl2Fv168g5PSMsEi/F/rcgpp+yUmqKjX2KGJCaMV9FzG0ep3hE
         Rt+eWuzZY4uQzqWnvI2fPKwpBp4PdWoAk5ed1EhNC7H37+ImhprjOkUyxHp70FIVf2Ug
         R6zg5O/kTiX78N2MS8nwl8VvtiswDyEY8C5qW+TKw8anXus90Ub/fFB4kzvmjNuKyGq3
         II7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W6ndJtnjyPDdyMlSiobnlhSUqOXZkUw8zIrKlqE4Qo8=;
        b=f6QuYeALUXo2m0szj3SLDu7jDvSbvY2qXgtN5pn486OFSEQwL5+RIwGDVYGWYIsqMk
         d3WFw+DsVJxTUF/DpiGd9+bytUL3Ol25i8ini9ZR6Wd+bxlZMApijJRWpc7EvZCMXk15
         GOXYuUS/8v3oCzp5SnqUAhCFzMPVrb1aowRc+MX/I1+2prOi8oYEUHR8jMY6RLhNg1zA
         aQYXlBLdbtbIWE8IsGzvX7Duyx4nRy0wn5Bnl2ubP+9U7ll5bA2QWBuOPiKgg5mINMgv
         XezbcNc27vMz6xyfoQN6SjmUV7yBDJCtJgdXSaQVliH8d3ffpUcy+gUdo8vDqfcvXLwP
         j1FA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZsXMPuK+XC0DGLM/IpX0miuWQGuZK3qT+ymDD5S3ogJ41Z/MG
	g+ZDF4jHHbuodFBw6VRWyYo=
X-Google-Smtp-Source: ABdhPJzhX+Wk6A3SW9HdenAhbnyvH4DYovkgxREZTHAT8HRKjsYJJZCpErABY4bdvfqNsauAxiq6dg==
X-Received: by 2002:a05:622a:3:: with SMTP id x3mr22968022qtw.42.1614049104063;
        Mon, 22 Feb 2021 18:58:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e6eb:: with SMTP id m11ls4720459qvn.3.gmail; Mon, 22 Feb
 2021 18:58:23 -0800 (PST)
X-Received: by 2002:a05:6214:c8a:: with SMTP id r10mr131840qvr.13.1614049103616;
        Mon, 22 Feb 2021 18:58:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614049103; cv=none;
        d=google.com; s=arc-20160816;
        b=RuR+0bkb2DPGQwgd29WdTPre1zaw624HYLMdpyQAiIWeQqaImpNmFqL4SQVLxWh8D4
         Wc08NUYdvl4b9v5SoehDUs4oVpZ6r5jPI7REh17thE1v463bNkaHlDfDoCKDYX+URjjd
         s5Il5UKwaQUfesUJxd4AeoVDmZw5xKjWtw9XCbgNJ3gZNBkKI5K7iougK59yFx8AN98n
         TKIWnpK8uVBzeOFEFWZmiym7zHgaWzkfR8C7l3mCGgw2+T5UPwvT0YoGiNMBW9wEs/89
         Z5+I/CKQ8m7ipNn0f/vrr5yI1t1tHygJREbTIGe9u49EFScu8BxR16HgdM5b3NqJYh2I
         jcsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=69faGMiqKu3nPyYAESPRzQr/N8GaW/xblPmvz3UTUyk=;
        b=kjL39BQ61edsFOV4+fQmmSUSvr1jV7iRedjNnB1m6/NUmNu/bmBD25oPssgDrSPkbq
         QkxOyoC8qZU5iCsjwGv9bcOQYib2kFiRKnKKI/oJl2X0/vwEHATr0ubaDc6UNkPnj0vk
         JW9Dj4QHdFad8eGcNAZriu1KFPMhlPhpyqySOUW0IaSpEFvGBRhfsSnoF5OYEpD8zO+C
         0VdQ+WdQIsAzXGgxQ4yp4xRHRgq7gJ4jcbXIVIeVRt4JERIIqDSTxn6H4ks+nniLBInz
         ZyBjLKdPZY+QSH6T7+z+YeoWEeTcTk3ITUndIxLVTE38PNSww/124xTXG+joqQ42UPkz
         4WHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=p3c4YUSB;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id j10si1050289qko.3.2021.02.22.18.58.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Feb 2021 18:58:23 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id p5so4094541plo.4
        for <kasan-dev@googlegroups.com>; Mon, 22 Feb 2021 18:58:23 -0800 (PST)
X-Received: by 2002:a17:90a:1990:: with SMTP id 16mr17662033pji.26.1614049103146;
        Mon, 22 Feb 2021 18:58:23 -0800 (PST)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id z28sm8702512pfr.38.2021.02.22.18.58.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Feb 2021 18:58:22 -0800 (PST)
Date: Mon, 22 Feb 2021 18:58:22 -0800 (PST)
Subject: Re: [PATCH 0/4] Kasan improvements and fixes
In-Reply-To: <24d45989-4f4e-281c-3f58-d492f0b582e9@ghiti.fr>
CC: aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
  Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, kasan-dev@googlegroups.com,
  linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org, linux-mm@kvack.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-a99773ba-c614-46dc-820a-4119dbc32ff5@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=p3c4YUSB;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Sun, 21 Feb 2021 05:42:08 PST (-0800), alex@ghiti.fr wrote:
> Hi,
>
> Le 2/8/21 =C3=A0 2:30 PM, Alexandre Ghiti a =C3=A9crit=C2=A0:
>> This small series contains some improvements for the riscv KASAN code:
>>
>> - it brings a better readability of the code (patch 1/2)
>> - it fixes oversight regarding page table population which I uncovered
>>    while working on my sv48 patchset (patch 3)
>> - it helps to have better performance by using hugepages when possible
>>    (patch 4)
>>
>> Alexandre Ghiti (4):
>>    riscv: Improve kasan definitions
>>    riscv: Use KASAN_SHADOW_INIT define for kasan memory initialization
>>    riscv: Improve kasan population function
>>    riscv: Improve kasan population by using hugepages when possible
>>
>>   arch/riscv/include/asm/kasan.h |  22 +++++-
>>   arch/riscv/mm/kasan_init.c     | 119 ++++++++++++++++++++++++---------
>>   2 files changed, 108 insertions(+), 33 deletions(-)
>>
>
> I'm cc-ing linux-arch and linux-mm to get more chance to have reviewers
> on this series.

Sorry about that, I must have missed these.  For some reason I remember hav=
ing
read the big one, so I'm not sure what happened.  They're on for-next.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mhng-a99773ba-c614-46dc-820a-4119dbc32ff5%40palmerdabbelt-glaptop=
.
