Return-Path: <kasan-dev+bncBDW2JDUY5AORBV5Y6SMAMGQEEZMLLRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 604AE5B4AD4
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 01:23:05 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-345158b6641sf44848587b3.8
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 16:23:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662852184; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tch25f0yUJPgQKlqcYHEh/Y5GPBiizlfaFKY1z5iCkIMG1sJv1hWzfbguDgtLYb4/s
         MmMt/KwNPO5Y4/kCduN8gYuTngLkJpr3VKZhXCvAHke/RBsc4Z1Ab5TabQ5m7Hf7xgli
         3zki6oqcPa6Uw9ZaXrYo8VoPmvfExWJcG2lvVC3+qp0PWYqm9xs4KjqxGOLDpVTOFRjL
         T/2H4XRkI1EE7CbSK4JQPMtx4vW5z7YzTRch5Rq7X6CQtI3VVxiv9emuOj7g1oxrEoPQ
         FcDWBGq1z/F+kbPtw3ZfesfXbNoQ9yeEDrimZ49OUMVWCdWolkzJWj2EJ3kxF8doUlSv
         IHuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=rDQOsrvkeX3eM6SGh8uUz5MWou5mCYF5G6qgnsDj+h4=;
        b=hqPYAGP0xSYXF5LnJe0o1qj2KhdXqif5kONXmRMZEsRB4zu7+d1tDNUfLrtaToyA7M
         B/0EWJUheEZiubWMPHGAVQZetV3qB7+Ibo/oebxKXnrZYJi//vYgfosWOgAZnAdAHrb6
         3BgzrR6UDKxTrE7480YOAqocbl1lOpWxl2mvz0kRK78GpW0UFkSdoOTiUFk0H53bm9eR
         4+CP1DJSP88Cyj3qi5JpTw9hLwAmnSVNiABv5GjiK0H9G2u6jE2F6wRPq/t1BUc11s94
         3sJRy381ZqkASchB2m2Nv3lZntohsUNJ6jkZVgawkipQ2bHgQqXL2fwiLwaaWM/qUKEh
         RD3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="P/X+iO8s";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=rDQOsrvkeX3eM6SGh8uUz5MWou5mCYF5G6qgnsDj+h4=;
        b=tooupmmw7EtQ02KzpDdCNAvB1RRVDbBWVL9Ljuy79CUlO0dKK6yJAmVCQPruJLgjN5
         WbBdAWETYF/EWHKA1T8HFwWk2HULuNNi44ROiilo+Q/nkPm/k4NUjUYCzhLdLB/IXEyl
         35j+Sxs/kVidCLnKsi1OrcE2wVkt9DuRK4V/BbXroBphAGx60XrxcDK91b4u1WBFRkt1
         82Q+T9KrCYmHi4BRPF/44umZwTY6XH10JsOQnMa2h0z8XfEvz1uP9/imdhDmUJJKVA/w
         jiISjsYKugT2Hk4gT9SuMZg8KzvsR1xOgiBuDfoJjRqoIHYuvOf7CsyBQ1Q/e3MtF8q7
         VlFg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=rDQOsrvkeX3eM6SGh8uUz5MWou5mCYF5G6qgnsDj+h4=;
        b=pK7guddV3Wt9a4i8fC9wGf6ne/3qVzLM1njfv5G61LXIxnHWFbMlcC2XDaCi1Qcdk5
         a80hQBNPPQq9R946nEJokLXQmlZkqgEkeMo4bVqjXk8FbrtvrZSW3mK8Y1uiSpAdhJqo
         W4EYoWkTMMBoN8RW0G5NSOxvP2Fi7jsX1f4YBGErZLHFhc09UnUoI6dZFTwQBxxTGiZB
         7Q0notE49rohyedkCQaMJwwmgQH18jP5qMfZiguugq+8ThJNwAPjz2hlzevaBSbl7f4Y
         Ut5XutqOrS0hy1W3utumvL4DGgPmZ1vt6XQhhYcv+Nz+Fch/1teIAFpblK7u8u0nrw6o
         YqOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=rDQOsrvkeX3eM6SGh8uUz5MWou5mCYF5G6qgnsDj+h4=;
        b=g80fxPm0TlushU76cnQdmoF7k4AMoebqXMe4Zbo+2EVqtpG3c2SMH0MfvulwNNNg1i
         X+aedRv9K/dJqsQJSbHP6rizbtFM4AyUMuJb71kV30B0WK4I0K93lidzyr83FmoJUKqN
         sPNo4XTsyqGyO00s8e8KOxjBvXsgmCD1Bd0VQeZ26B2PWuOlK2Wf1KxeCod+PPDEG3p1
         gx2eqSlRYMIGCzu+1O3P8iX/J29+JzkwtEbS2bEheFYHHXOykLYbGVYhHOKKAGtTz3HI
         DZ1UpOYrs2ZPTWu8/GdsgZ0vOg/ED/NdYZntduQ32BomQr1SBQ+4apbNEmzv7m6VmAPp
         jMvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2PVRlGBwbq8/LtVorxJscuqd/YCkKtJ24jtGF/YrKILnF58ty0
	sOJc5A7C+tVl3q2SrDOmdOM=
X-Google-Smtp-Source: AA6agR6qrN7no3mHCK10KQ1gYvwUiFqGD5VfOR4TbbQIIOTmSYB4iunTVt0FRz+bgHzrcZ7HWs0HoQ==
X-Received: by 2002:a05:6902:290:b0:694:453c:d824 with SMTP id v16-20020a056902029000b00694453cd824mr15741803ybh.603.1662852184126;
        Sat, 10 Sep 2022 16:23:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:58d:b0:345:1e0a:1f6e with SMTP id
 bo13-20020a05690c058d00b003451e0a1f6els3477554ywb.4.-pod-prod-gmail; Sat, 10
 Sep 2022 16:23:03 -0700 (PDT)
X-Received: by 2002:a81:7589:0:b0:345:1f2f:5db6 with SMTP id q131-20020a817589000000b003451f2f5db6mr17137367ywc.105.1662852183611;
        Sat, 10 Sep 2022 16:23:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662852183; cv=none;
        d=google.com; s=arc-20160816;
        b=NieZcZF4qn/3f2pp5kvwxufkzRGilydkdnQDLL9XiUUm40fZXu6DUc09efpybKS4uK
         q25ElMS56Ir5fxOWsS5LWPast2lV80zec0NgY6gzgk3qrobdQl1ckj855gES6GxDosR+
         PykmmlkOvsbR2hA1gHKckp7j0msmxHTfzjZmuaf4+6nFui3fOqLeykpXhDdXr3kOSpqL
         ZsreJRMV3jxCrVOnd0qjzMBW/DKCU6SZc/pdxC4KQKXaYLKs3yhWPl6Ub7pyaKaHiSxX
         Y0ORPZkWs9Set3V0sJckHgheYrMgGFQCKn1DInkVBl+CtO289KH/IPpjejzfwvxI0w2U
         RPBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gAh0um/m+ykZ+JIcJQ0J8f0pH78Jfp+soM0rxxd5C7I=;
        b=lxPdpXrv79OydGAs6bLuRerzIyRTf9LRR255OeDUp9yRDeGS0890GKkF5xK9AibeKM
         ECETDHswB0hQaJOxDqQstHJQ3ByStUDYbvUwFVBORUcQcZZ2Mjx1HaCTvktd5L70ELeZ
         QkcMRk18k1beaN09KPoflDiguxwmpUCPkywg4TRcuN2Z8L6Rx8tvk2FHwMScQh5ZWCIq
         ntPFaAzwg3wYLVn+B4MdcipAllKliEX1SaTofn3s7E1wRQkmxb0XbPL8AxZ3KdSYQBOM
         QZXy3MZmi3SL297YtxAOWzeOBSiYj1alfoqHiA182QKSMMTPTAPJD+w/NgxtoFA45Dl6
         31Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="P/X+iO8s";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id k127-20020a25c685000000b006aea4e47938si206518ybf.1.2022.09.10.16.23.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 10 Sep 2022 16:23:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id y2so1273012qkl.11
        for <kasan-dev@googlegroups.com>; Sat, 10 Sep 2022 16:23:03 -0700 (PDT)
X-Received: by 2002:a05:620a:254f:b0:6bc:5763:de4b with SMTP id
 s15-20020a05620a254f00b006bc5763de4bmr14293905qko.207.1662852183307; Sat, 10
 Sep 2022 16:23:03 -0700 (PDT)
MIME-Version: 1.0
References: <20220907110015.11489-1-vincenzo.frascino@arm.com>
In-Reply-To: <20220907110015.11489-1-vincenzo.frascino@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 11 Sep 2022 01:22:52 +0200
Message-ID: <CA+fCnZe+ZW7_aeetYGpgyrS06ajfqFB1ULYLKEL++JZx4tLWBw@mail.gmail.com>
Subject: Re: [PATCH v2] mte: Initialize tag storage to KASAN_TAG_INVALID
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Evgenii Stepanov <eugenis@google.com>, Peter Collingbourne <pcc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="P/X+iO8s";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Sep 7, 2022 at 1:00 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> When the kernel is entered on aarch64, the MTE allocation tags are in an
> UNKNOWN state.
>
> With MTE enabled, the tags are initialized:
>  - When a page is allocated and the user maps it with PROT_MTE.
>  - On allocation, with in-kernel MTE enabled (HW_TAGS KASAN).
>
> If the tag pool is zeroed by the hardware at reset, it makes it
> difficult to track potential places where the initialization of the
> tags was missed.
>
> This can be observed under QEMU for aarch64, which initializes the MTE
> allocation tags to zero.
>
> Initialize to tag storage to KASAN_TAG_INVALID to catch potential
> places where the initialization of the tags was missed.

Hi Vincenzo,

Cold you clarify what kind of places this refers to? Like the kernel
allocating memory and not setting the tags? Or is this related to
userspace applications? I'm not sure what's the user story for this
new flag is.

> This is done introducing a new kernel command line parameter
> "mte.tags_init" that enables the debug option.

Depending on the intended use, this can be extended to "mte.tags_init=<tag>".

> Note: The proposed solution should be considered a debug option because
> it might have performance impact on large machines at boot.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe%2BZW7_aeetYGpgyrS06ajfqFB1ULYLKEL%2B%2BJZx4tLWBw%40mail.gmail.com.
