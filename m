Return-Path: <kasan-dev+bncBCG6FGHT7ALRB7VER73AKGQE5QAIMIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id BE70C1D966C
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 14:35:10 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id z16sf7218441wrq.21
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 05:35:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589891710; cv=pass;
        d=google.com; s=arc-20160816;
        b=v0ae7i0u//qHhRpHKJpDJh/6X9crSOuO7ty4NpxjGhog+bP6NdbwhfAE6hCmxhMaWp
         KLW3YPqkR9CJk1Pl7mA/4Du5wt27Oxj/fpa1rNTOgypYFPMxiLbdVOpcLvoaifZkAC7+
         NDHrC0I2la1bCYJcxcH+Kt/dcLvErEuVS3GgRDCGQ0Vmgr2A0xatg1n3BYeqMHsLKbPt
         5LFD8sqKpDNp2Vy3NC6+qWNuFEkz10To3mJOpinrHjUeZCZo3nDEzURXF3XYgdo5SGdt
         lQ6GgXQBDkAuB+lpD9FfS12B9R5XwzTRlHgN8S/qQF6gnUtzRuCNs0r1fxc3Mxs6/fBi
         3Eig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=GPM/KpVfM7ruODGbW2SdqqkqAOo49OuHmn+yy7nQVXY=;
        b=Gubyyq5rGYAAnux5o8CVGSEcZ4PJ2ojuPkU1KzoC4D+mdG42Ai1eWPPH6dq17Dqjqu
         47kFjN+MS360+RLQS49c7pcB2V4v0oBqzcVQMHwC/5sxPNpfA8H2ZvARroZjSz5HImO8
         i+IEZroP21hf2rW8lTDD5rjNInrjIo28DJdoxV5T9PlIkZqU9ZeepZS6cT3H4rYzR1ak
         rEr4QqTg+QgDjSYIWsThp3SWrNVXp49WqOMOc7FGXiJ7+j1J4VZdf9YvLWsd/qzUurrV
         8WKlXwcCiHkBZxa4HUz7YamvKWyno6H4gTR2cF7liOWYepW04WBmoY1jhkPg8lxv9uQl
         FaCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GPM/KpVfM7ruODGbW2SdqqkqAOo49OuHmn+yy7nQVXY=;
        b=a2268wujqeyZaU2dFYShOp89iuLLMUK9MkLb0FOAARWMaS8slIxoCiF0n1ISBMDa87
         whwte/0Q+u8euwJQiafstIjU2MT2Q+XP5L0x8F79wXQ0vLEzsyKoaBm1ydsBqH3v1CCc
         QVrodWclEEisiboLqExJAFc16u+1gAmDi6W56Grd4rqSVqqyoDupC3VRuFN3OdtT2Sln
         vHGPltfMmrQbRQ9vKwt+VAQKzGZYneBtqaqgJLO2ZJS0mf2OHbtlVpouzYyjmUN0wXiR
         T40aUXzaY7DvebIRyvsYaVKHNJf/FKuGA8r1upy2DtTYeG4E7lWdUf/SQFF3QFUSaZZ9
         T2eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GPM/KpVfM7ruODGbW2SdqqkqAOo49OuHmn+yy7nQVXY=;
        b=ruAlGQpHX3qe1MzsVOFWX+NHm3DVut/ybP98MnBoSg1I5oly8Xdy0nRV6kF74YMUXQ
         8hdU8u5E9IJm4cemfh7pHsl0uc5WBs/s6QHHgeD4Mlc3pewXlAw/P8CgwFu2Co888hI7
         KRBLfmRrA9fSLxWXT0DT4bDzrTrJCqW4fhMWCk1M5Rq36mXkSNCTM/3pZj2Eh8aBiTHy
         2P64Pp7b96zYdvwk1zB+aYtEUF/krFi7G4pJLTg04PfLXTdqWDa46h+lk83+71a6akE+
         6cHRzHMdiCh89MUaqO7Bg0fG0wW5C8CVekqpnB283QcUl201qV/Y/iPnRCHuYdEk/sMV
         cdsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SYuNzi033cI+8QwzY+KKyMxlC7ohdAal6IAd5sznMXDUpmuze
	umAakfgtn/OCWHfBfmNgmg4=
X-Google-Smtp-Source: ABdhPJyQO5kZVv3XirruCjaAsWjB18uPG1pxq1beNTDkU0bCG8/vJGRqB2cPAgAWhMUlk2oFA8kt0Q==
X-Received: by 2002:a05:600c:2614:: with SMTP id h20mr5532844wma.155.1589891710219;
        Tue, 19 May 2020 05:35:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c770:: with SMTP id x16ls1539833wmk.3.gmail; Tue, 19 May
 2020 05:35:09 -0700 (PDT)
X-Received: by 2002:a1c:e188:: with SMTP id y130mr5639648wmg.83.1589891709766;
        Tue, 19 May 2020 05:35:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589891709; cv=none;
        d=google.com; s=arc-20160816;
        b=lb6NVaha8Du4CJS02yswLU2JY1L2YBEUPan+vwxWZ3RHt564FPpk2DvHMvgi0u8y+z
         dEZ9C9mm6i4ws0JeT7kKVXOBBZJpfafrWGaFerQfRd1sdrXKeqmV18q1sWyz5GhmSZ6u
         ej2Xwv4t6yLqO8GmuAs/jtyLqet9xXp+GzbhsTlmXdxEaV6b+Cy8RXvmwsAKyVn2dlsF
         E+nHv+KdAFpBHn1QjnSG7/FJjOSisqQc/SCJ7cqBqmypZW6JPdRVzVpgeO2djKtEv/XV
         wQ7+Qsf04j6Rgkc1JqLYGR0e1bMOKR+7byi3F7lAgt3yiSF9FN8QZk4qLzdTX2HKTJ+k
         SQlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=BeLfBGhkBKnsME5hYtbgS2ANoUZ7NuH3kgzqZkKUVtk=;
        b=rc1/AcNpldlTlX5JH9N0NwfuUbq+u979jWx+GJn4OWzTco/THqGTuvx3PLRTZrf515
         pqIgD/qfwf/+Mdolu/bZoc6SjDBH9kg2SOxWPx2u3o8pP5sSqcQgEwtuZm3o82L9wx/p
         JBuNNfDQWbtSXEOgj9UntLvj7ctZNat80qCMnYCKRU7g5VODL52qbzTbgVOB6A5yDiK5
         D+A1wxhi88u8xxUR5Kt1EQDGlmFHvLto2Q5/rw/xaWxzwO5LiX0rrJt3oPzZH1rvlkfh
         lt8I/BDsCFhmbU3FuXyj77t8lPV6xfFI4DQc+adYdv/V8771B5tOyqjwoCluHbP02etW
         LP/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id y71si72625wmd.3.2020.05.19.05.35.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 May 2020 05:35:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id E5F5DAF38;
	Tue, 19 May 2020 12:35:11 +0000 (UTC)
Subject: Re: [PATCH] tsan: Add optional support for distinguishing volatiles
To: Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>
Cc: Jakub Jelinek <jakub@redhat.com>, GCC Patches <gcc-patches@gcc.gnu.org>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20200423154250.10973-1-elver@google.com>
 <CACT4Y+arbSpBSwNoH4ySU__J4nBiEbE0f7PffWZFdcJVbFmXAA@mail.gmail.com>
 <20200428145532.GR2424@tucnak>
 <CACT4Y+YpO-VWt5-JH6aLBc3EeTy4VHc4uBc33_iQNAEkw0XAXw@mail.gmail.com>
 <CANpmjNOYx7s9EJ56mdwyGyTzED-yq3B0UvkiZ11KmCe+QMt47w@mail.gmail.com>
 <CANpmjNNzkcddHMMucH9CxpUeHoee9g5ViMLUuRPBvepo7TBHXA@mail.gmail.com>
 <CACT4Y+Y7aDUrcMgo=u_Nrt2a57e=1w1958XLT8wLm0S7H7nNtQ@mail.gmail.com>
From: =?UTF-8?Q?Martin_Li=c5=a1ka?= <mliska@suse.cz>
Message-ID: <ba3f1ffb-1fc0-00ce-b984-8737cccf0a7f@suse.cz>
Date: Tue, 19 May 2020 14:35:08 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+Y7aDUrcMgo=u_Nrt2a57e=1w1958XLT8wLm0S7H7nNtQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: mliska@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=mliska@suse.cz
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

On 5/18/20 1:52 PM, Dmitry Vyukov via Gcc-patches wrote:
> Jakub, could you please give some update. Do we just wait? That's
> fine, just want to understand because there are some interesting
> discussions in the kernel re bumping compiler requirements.
> Thanks

Hello.

We switched to stage1 and we're currently working on some infrastructure changes
related ChangeLog entries, -std= default change and others.

If you need the patches for your fuzzing, please install them locally to a GCC 10.1.0,
or to the current master.

We'll review the changes as soon as possible.
Martin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ba3f1ffb-1fc0-00ce-b984-8737cccf0a7f%40suse.cz.
