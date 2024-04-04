Return-Path: <kasan-dev+bncBDEKVJM7XAHRBIMIXSYAMGQE3OJKR5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 671C3898F30
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 21:48:50 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-dce775fa8adsf2427629276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Apr 2024 12:48:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712260129; cv=pass;
        d=google.com; s=arc-20160816;
        b=hqLonIg2rCd6nM+6zhee8aNera4g1plb0LOe53Kd5DIsEotPNhRTcFn10Ms2udbXsQ
         H7RoV1UPkCkwYr9RcX/emUO5butpq7aw5MhDzzys6R5N8KUoF7qnNhi8jwY/WZaugViw
         f0PHNq0oh+Qh7ghK6fVSu7JT5db3k4ib9XQ83r3dOd/bZGENCe4OqxTvv4zs10H3Yj5q
         xLMxeKiUk4cto0lf/qWfDseCHcAVjLMd9QHHutCGtOvfCrA6uH7t/H2FyJWSkZwhT8U5
         QH/f0XSlcj0WDnKHtQ289+Y3GJ5FmrnpwfXlPGHytxqBA3aq8x/I9RiCdhmBflJ2CNxT
         pE4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=VI9gCG42sQRJA09+/aYlXVwz9e2FP8c4lsEDTa44mOQ=;
        fh=MBFYWxv+qzEQBBXKNxEgioOA/i/yBUAlgIDNeOMrj7M=;
        b=i6fYrR5o/daLjxlh6seGKBBPaqyO7Ia2/FK5sY1xllbqBNqTuY9YOsQlmJIrNvN+0d
         LqK/BDz1bu/AjZTeDXqdxaEU0PN/ib7SPCCCMnKCObKsyJFmqPuNL8QEhc5eHYSv00Wl
         R6rY7KPOpseSuhls6GbcKfVtyfM1Wf4XoY/hAsm5XLfgdCWb/6bJqwFZ6WcCrMQnUI10
         Pd4+K15L8DJKXMy3rOBnR4NLK/vV5ESAYgFUHj++lTN3xtclGGmfBb4K6xz0WJDGn96W
         wnqzKoZplWStfkJfpxBjMBKTub4aCwM5CKXXIfaEkT7oqWZTvJkuzJAvHbQa5n6ovGZS
         urwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=hlTSVONy;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=W6wFbnK3;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.147 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712260129; x=1712864929; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VI9gCG42sQRJA09+/aYlXVwz9e2FP8c4lsEDTa44mOQ=;
        b=FS1xrZlFwNVA4E83jxfKF6Z77FiqdvZtI/BjBOAxeni6iI7F6eah9eFuBX8llPs7PD
         rW/RYLikHmfsWr+03oSCWuTgcLMrJ3vIUniWED3FvWwB7hPI3pLYCB64zklTrOctSE2I
         LvCzKvjlekqMEjgoVMu40BUKW13uwOuOzdmGnycFI+WxZs9CmVqiDAp3Xv9dkHys4CQG
         s02f0oGSK5hjPWW6aLuFk4quKsHnU6/10wYgw9NULpy8QCTC31xPpykEZVglLslhmtYT
         hKgO6voj4el7iw42uId1BYXNy9LsKol7XtGuIOr0N8/SdSe/gBFkHj395oOGtxcyeiEP
         VttQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712260129; x=1712864929;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VI9gCG42sQRJA09+/aYlXVwz9e2FP8c4lsEDTa44mOQ=;
        b=ZojEymwVAf8jlvlM9gCgwMYsyoT0p06D6+IEGp6sR1uQTnywhimXrQINkZArlDejnR
         5Sk/0Xa9Th8DoCu69irdAgLleW1nPHSfTcyZLzCBoyJZiSmEktqjReRAcdYcMUsA7aoY
         P+NnoAcZMUi0WRTSAraS/tnuS6UoDnFQ0MwGQmWL9LE0E+zpPZyaBbOikq58Z+Sftbal
         2aAHrwCxEHVF9Updg7duUpW+458kF9vSOaAXIH8VpEuiJBXkEuNaGOP7g5sPfJRlUOyB
         kOk5eLawHOEB63cMXTQTjPT7DWU/Ju2YlmV3cCgQJ9UUgMV5BUJR+aWPEzdBnq1uqBiA
         GviQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUo3e03Sp/v5NIeqjbKSN1sqHRmxawNqFkpoV8ZWHmcJlQmGg7rbZMJH5yvx/z5j4QaPN8VCBtWKDbmHtMWV5w7KqFEZcrD9Q==
X-Gm-Message-State: AOJu0YwXt3dnitzfodlVF5H3nq/+ikVf3/SJPF9R3eo/RtoZ7c189Ny+
	IuZIvALwoMhenkSuzeWUEfqXnDxw2CkPuP1nQ9YmPq1YSx9vB0ov
X-Google-Smtp-Source: AGHT+IHhba7wuXPy4hbB1Utp4GhtDwnXQlz6VAAiEaEEflvXoNpcy2kqYo6NY1BFT2Yi/bc36h5dBg==
X-Received: by 2002:a25:a004:0:b0:dd1:7908:3a49 with SMTP id x4-20020a25a004000000b00dd179083a49mr3311092ybh.23.1712260129277;
        Thu, 04 Apr 2024 12:48:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:750b:0:b0:dcb:f35a:afeb with SMTP id q11-20020a25750b000000b00dcbf35aafebls746724ybc.2.-pod-prod-06-us;
 Thu, 04 Apr 2024 12:48:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWnBIy86LqXQVyig5owlUQpb74cpb3/6fGCV7Fv9FD/KZK3sfkUIErjXu9vQVT2VZ8Vc2XElwWYkpyikpIaoRKLsoz45oHR4YsFlg==
X-Received: by 2002:a81:c250:0:b0:615:144f:1f5c with SMTP id t16-20020a81c250000000b00615144f1f5cmr3408592ywg.47.1712260128378;
        Thu, 04 Apr 2024 12:48:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712260128; cv=none;
        d=google.com; s=arc-20160816;
        b=g1dWl+EZLguFm4IY6gzAVRgPiLK09ssdps0956/V0Fuo1Qf/RXWNJYesBhWxOjgQOs
         YLSHcKxkzsW8FW92q/I3A7VCfGb0TtnWvhxs9PoT01sOUFUsiI6+JoPyKVnGedxbKX0r
         oFe/0xb33yMIB5wKxoATBCUQegKUDBBnBlIRP7N3dOw3bZVpz89fNGOaBz1/deWAoshe
         Y85n65Z8N3+1walfuzUkl4xpUnWIaiSrmHbioc6bl8rQLb3+zHfrj7WUWCbIO/u6Fqz1
         8mvMZXM6hEZazRN+Tlssa3NUK1OGlE6MD3nq9n8mprh148xunXwFo1aFO4tNadLFR54/
         6vhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=hiQ9PP65yprDlNGzHIE3Deo1U6GRa/cTqCw3rUTctos=;
        fh=DqcW1dT8fOYpGDs/X7qLssztBHjM3zTgHtx+sizf7gU=;
        b=YzSfLtS6N2T/fSbt5SSersO/z9GH+fEoYHLyUVr5BjL2X4+1FpCP5WF0OH2om/0oAD
         e+xSdJdjhVN4WH2Qdnaq9LOfsCfpRc5u4lZGqq6EqhDOztSODDWsgT+tphaEqhJQZRkm
         xbSLJeirRgeAaGHztf8Fjb403xvjofQQEnxcZto0qtN+O3Xo44jxhiMxaLnct6m/KQjC
         HPp8RqAwGxnhCpTvdcsTYrPqbHbA+wfKfD/EG4kMqOIL1StxtwMFQETLo/FNDreIq5Gu
         y0Jew7KurAeoINovMg692jNK3H6Nn8NagVJwM5gVWpMtT1wkwI1kELujAL0qrEZNGTeG
         IqVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=hlTSVONy;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=W6wFbnK3;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.147 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
Received: from wfout4-smtp.messagingengine.com (wfout4-smtp.messagingengine.com. [64.147.123.147])
        by gmr-mx.google.com with ESMTPS id t83-20020a818356000000b006151af32a32si9081ywf.3.2024.04.04.12.48.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Apr 2024 12:48:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 64.147.123.147 as permitted sender) client-ip=64.147.123.147;
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailfout.west.internal (Postfix) with ESMTP id E6DDE1C000E0;
	Thu,  4 Apr 2024 15:48:45 -0400 (EDT)
Received: from imap51 ([10.202.2.101])
  by compute5.internal (MEProxy); Thu, 04 Apr 2024 15:48:46 -0400
X-ME-Sender: <xms:HQQPZnt5JTBS6StpApXHFnfEkKCm9XBVve10x-4kVf10Z75O8M06zg>
    <xme:HQQPZodXcxrCzXtPjpnKr4gZubGF6ldn7YKmv35EzHGnPOKPF8rDDD2bOhuS8Ton8
    Vu8xR0InBdb9pZoIZE>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvledrudefkedgudegvdcutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfgh
    necuuegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmd
    enucfjughrpefofgggkfgjfhffhffvvefutgesthdtredtreertdenucfhrhhomhepfdet
    rhhnugcuuegvrhhgmhgrnhhnfdcuoegrrhhnugesrghrnhgusgdruggvqeenucggtffrrg
    htthgvrhhnpeffheeugeetiefhgeethfejgfdtuefggeejleehjeeutefhfeeggefhkedt
    keetffenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpe
    grrhhnugesrghrnhgusgdruggv
X-ME-Proxy: <xmx:HQQPZqzmk53CaKhqbY3WGvHIfiEXMRWp9R6Tvi7jbh7-iW6pZ2gSeA>
    <xmx:HQQPZmMrqwyskgQE8CrUlxP8WWCUgErhbCylI8D_mNyrn8FPtXhdpQ>
    <xmx:HQQPZn8vZEPygGFEgk81-4mpqJCgk9S7tQfJQ4avj0TMMcvzFaK7sw>
    <xmx:HQQPZmXvTiBGJ86L3CQ2ESwws12iRB4LrwQ6RxBThCvY1AVvutA3ZA>
    <xmx:HQQPZmWlQ2pxxtj4oI75Hj75ZUif2iFtJdpigJXax97tUb5HXai9zZyU>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 1F290B6008D; Thu,  4 Apr 2024 15:48:45 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.11.0-alpha0-333-gbfea15422e-fm-20240327.001-gbfea1542
MIME-Version: 1.0
Message-Id: <0f4d6888-af13-4419-974e-dbfb5eaffa82@app.fastmail.com>
In-Reply-To: <20240404111744.40135657cd9de474b43d36c7@linux-foundation.org>
References: <20240404124435.3121534-1-arnd@kernel.org>
 <20240404111744.40135657cd9de474b43d36c7@linux-foundation.org>
Date: Thu, 04 Apr 2024 21:48:24 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Andrew Morton" <akpm@linux-foundation.org>,
 "Arnd Bergmann" <arnd@kernel.org>
Cc: "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Alexander Potapenko" <glider@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Dmitry Vyukov" <dvyukov@google.com>,
 "Vincenzo Frascino" <vincenzo.frascino@arm.com>,
 "Mark Rutland" <mark.rutland@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kasan: hw_tags: include linux/vmalloc.h
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm1 header.b=hlTSVONy;       dkim=pass
 header.i=@messagingengine.com header.s=fm2 header.b=W6wFbnK3;       spf=pass
 (google.com: domain of arnd@arndb.de designates 64.147.123.147 as permitted
 sender) smtp.mailfrom=arnd@arndb.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=arndb.de
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

On Thu, Apr 4, 2024, at 20:17, Andrew Morton wrote:
> On Thu,  4 Apr 2024 14:44:30 +0200 Arnd Bergmann <arnd@kernel.org> wrote:
>
>> From: Arnd Bergmann <arnd@arndb.de>
>> 
>> This header is no longer included implicitly and instead needs to be
>> pulled in directly:
>> 
>> mm/kasan/hw_tags.c: In function 'unpoison_vmalloc_pages':
>> mm/kasan/hw_tags.c:280:16: error: implicit declaration of function 'find_vm_area'; did you mean 'find_vma_prev'? [-Werror=implicit-function-declaration]
>>   280 |         area = find_vm_area((void *)addr);
>>       |                ^~~~~~~~~~~~
>>       |                find_vma_prev
>> mm/kasan/hw_tags.c:280:14: error: assignment to 'struct vm_struct *' from 'int' makes pointer from integer without a cast [-Werror=int-conversion]
>>   280 |         area = find_vm_area((void *)addr);
>>       |              ^
>> mm/kasan/hw_tags.c:284:29: error: invalid use of undefined type 'struct vm_struct'
>>   284 |         for (i = 0; i < area->nr_pages; i++) {
>>       |                             ^~
>> mm/kasan/hw_tags.c:285:41: error: invalid use of undefined type 'struct vm_struct'
>>   285 |                 struct page *page = area->pages[i];
>>       |                                         ^~
>
> Thanks, but I'd like to know which patch this patch is fixing, please. 
> Is it mainline or linux-next?  I'm suspecting it might be a fix for
> fix-missing-vmalloch-includes.patch but without knowing how to
> reproduce this I can't determine anything.

It only showed up yesterday in linux-next. I thought about
bisecting it but ended up not doing it as it seemed simple
enough.

fix-missing-vmalloch-includes.patch looks like the right
place to me, given both the timing and contents, so please
fold my change into that.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0f4d6888-af13-4419-974e-dbfb5eaffa82%40app.fastmail.com.
