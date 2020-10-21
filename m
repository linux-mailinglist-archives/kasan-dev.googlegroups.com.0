Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBM6XYH6AKGQEMTD337Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id E37A8295158
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 19:11:15 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id f3sf1932262ljc.17
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 10:11:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603300275; cv=pass;
        d=google.com; s=arc-20160816;
        b=MG4VlSbl9cSA29vksMEvDE77Mj1gs4Lg3nq0FMkKQ1tu+2ZthRIXhbjZayoh7Exaj2
         tAbj1hE85D9G3GFkxy1PAkGCeCsw4YFjvQfqosOmZoEhbY+QO6bqB08TeAI+55TzLe5N
         twcgTkzafoOWxQWqpzkgvv8oGULF4mobIAhZBT3QepaLyVWbqeg5GLx25QE0oZ8FhnaR
         8aR6E0Bcuu3Z/uy+svmMDoUd3BEXOfDSXwIbegQeoO/WIIBBV1RvHNKD+P1L7grvr1IO
         HguLBpGSvF4h9WytOtHygcBmy7W8UP/R6a42LttcB/HcP+tss+RCs/hpZhVLfvnKgc+2
         PFLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=HcceReVoKVE2mt0f3NLggF1bhrg1xuvgNxmyq2oiR/o=;
        b=q4GRuqnTDp87IAt7EPJh87gV3g3MpqbgwpIyjtfp+0SGREDcwanz9VLKdICahlwU6L
         Iua8mtNopByvGFtdvcmXTX60d4PKixqFx35OFeHQ3uE3H1P3vzowevw9d0lHZ6cDu4bn
         qC/B+4oQQvfJFEnskeolGqwwm5ftGUqK2oi7fheCxBIiyL2gHuyZHmhq8NoXBBX7wFSl
         cRPaTFkkuYfbaWqTpxVumKXJEXVCSqI8g/UDyDDDTy9vduxHbwxiFEt+Q6cXkmudWDaq
         3V3n7Y+DJ0L3dJ1vEGTw5hi/WK88QFfIAX1JDw7UGEEOcJRPwdJFb2MrBzwU+nC0Ep5F
         rmtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=d6nJua3Z;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HcceReVoKVE2mt0f3NLggF1bhrg1xuvgNxmyq2oiR/o=;
        b=iEUVNVAYbRhpdm9EM1lxuCColTskfvdvXRYyNCtOJTJGudJ+SX76b8HQIVllbuavY8
         iDJNIPYzs22JRUtw7iCW+FQ6+b+3tTA2XLvEUjH5G9Mo0leCzgb0rpq3vMY6qt2dojSi
         nD7t51JyxZwPWCYutFeu6R4tKeBU26GR9hKQG0fLG2X6Jtvm5ZhuocMTh8VOnSMRasOJ
         i+RIPIJq6nOfJWpZa+OaR0C0DBCAw0ApmoNOj+IjYGBfegIHEjqOjioTo14SfbAeYUIv
         r5HuqKStKR6tXV+g61+M/jDx4Loy2AT2ATPJB0z98+Yhqx5hXMShDuh1lDF0pHrBLI1o
         Mltw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HcceReVoKVE2mt0f3NLggF1bhrg1xuvgNxmyq2oiR/o=;
        b=Sy/ZHUGU0DegCHX/q53Lk5Mc11sDKhOb/laOxjcGjkBW6dnthJ7iIa6wBu1pCqTzZn
         f1+3xUK9TWWJErrmQYnR2kB1yh1IGwQqJtimZO1SbZNoEetdGsqOb7EzcTASyprNvt+h
         mqLfPWfePPRQ8xXgCur5jB3Sb/NRDCjDYkAEntBZO2OFDYDhRDCiHTKBt9wuHzi1RkTR
         zXRVtnuhwfNONthvoKjvzf8YMK/hsc+sCEKQ6W1fy4aE6ZXRzE73j7uTu3PyLD4UIy0h
         5t6kldixHzhj9tE5x9vEnhMOcVnL70nefkApi/H8BFIvVA7uisbyPF8yWx6eyKTnGjlX
         6OIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533XoPwNi8s3/ITTa+H+J9EnhRauMnyY7iQ1CcvEPdGefhJNhOi5
	Ww2jtElpcnnYQKUzmglgUzI=
X-Google-Smtp-Source: ABdhPJzEo6h9zu2hWMdP1X4dRpKSk48L8iXe+7eq0UzB3ukaYjxR7HsfnU4rctvZ/Kfvc9DNdY/GGA==
X-Received: by 2002:ac2:4833:: with SMTP id 19mr1797106lft.136.1603300275423;
        Wed, 21 Oct 2020 10:11:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls416547lff.1.gmail; Wed, 21 Oct
 2020 10:11:14 -0700 (PDT)
X-Received: by 2002:a19:9d3:: with SMTP id 202mr1747139lfj.329.1603300274220;
        Wed, 21 Oct 2020 10:11:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603300274; cv=none;
        d=google.com; s=arc-20160816;
        b=AqGQ3OVR5L3rlMkkK/XB5ejA55/7jz2me3cbrZbhTNHJ5NZk7ioeCvTW/yyYqrYnQ+
         ZRUf1f2oDw6JIILNuVf5j6GdQrJ2zqNCaeTYL6DiS0un/wnByr2rJduwmcUgCP9Vzd2h
         34DxGl9iakn9tOuCFrxZ89YJ+uD1iSN7QhtCmyB21q3RC2T+gmEsYOts5xP7c9Uq2IlW
         tn6HZ04JDYAEIT9Ew8IimEZV2O+ZN8YIBd55W+Ipv8Q/vyvM3ShNDxO60gEC5O/bAgwH
         A7is9doCCpG1lF/QTV6qI3eMAOhrov0gMCluGMLlibF+o8Fz6sNS6+RvHMbXHn2ollj1
         Tncw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jZ8rX4nMXu9yVxF6VhEpyRT/HJL/yeSOHN33lmmqE3Q=;
        b=IvjEtq9iN2WZG4HQ9g4k8GqcwnlHCeaBSQKYUhuhyXnOfp9+3D0eDRzyH5hgg03Qr0
         uwBjVG791zXMVo1+3TsOw8iST04TKu2xpS6OkYWn9VrXpls5tKs8NiJjjVM7NTs1JyfG
         6rzD0Ki/ol2GOwd1n3Io4zZh/Se8+JlZdPXPm1RELspeKY/0nFjvNM2yApskc1WxGNHD
         lUzVqNzYcTN/uw4HIfUKaZYtzrhLb8rdWHfDrcVRr1nKyV2Xibi1TxOXHKXpWs/9GH1N
         KuTWyrqACCcV6IGD8fUWfWsjTE6VO3TNE4Q7OOc3zD4CVdWd75CBJMlJE8v4c3RIqdWF
         GljA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=d6nJua3Z;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id a16si89641lfr.5.2020.10.21.10.11.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Oct 2020 10:11:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id p5so4339841ejj.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Oct 2020 10:11:14 -0700 (PDT)
X-Received: by 2002:a17:906:3cb:: with SMTP id c11mr4599847eja.117.1603300273502;
        Wed, 21 Oct 2020 10:11:13 -0700 (PDT)
Received: from mail-wr1-f47.google.com (mail-wr1-f47.google.com. [209.85.221.47])
        by smtp.gmail.com with ESMTPSA id f26sm2584563ejx.23.2020.10.21.10.11.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Oct 2020 10:11:13 -0700 (PDT)
Received: by mail-wr1-f47.google.com with SMTP id h5so3916822wrv.7
        for <kasan-dev@googlegroups.com>; Wed, 21 Oct 2020 10:11:13 -0700 (PDT)
X-Received: by 2002:a19:c703:: with SMTP id x3mr1474665lff.105.1603299922233;
 Wed, 21 Oct 2020 10:05:22 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
In-Reply-To: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Wed, 21 Oct 2020 10:05:06 -0700
X-Gmail-Original-Message-ID: <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
Message-ID: <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
Subject: Re: mmstress[1309]: segfault at 7f3d71a36ee8 ip 00007f3d77132bdf sp
 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: open list <linux-kernel@vger.kernel.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, X86 ML <x86@kernel.org>, 
	LTP List <ltp@lists.linux.it>, lkft-triage@lists.linaro.org, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Ingo Molnar <mingo@redhat.com>, 
	Thomas Gleixner <tglx@linutronix.de>, "Matthew Wilcox (Oracle)" <willy@infradead.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Al Viro <viro@zeniv.linux.org.uk>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Viresh Kumar <viresh.kumar@linaro.org>, zenglg.jy@cn.fujitsu.com, 
	Stephen Rothwell <sfr@canb.auug.org.au>, "Eric W. Biederman" <ebiederm@xmission.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=d6nJua3Z;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Wed, Oct 21, 2020 at 9:58 AM Naresh Kamboju
<naresh.kamboju@linaro.org> wrote:
>
> LTP mm mtest05 (mmstress), mtest06_3 and mallocstress01 (mallocstress) tested on
> x86 KASAN enabled build. But tests are getting PASS on Non KASAN builds.
> This regression started happening from next-20201015 nowards

Is it repeatable enough to be bisectable?

             Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwg5-P79Hr4iaC_disKR2P%2B7cRVqBA9Dsria9jdVwHo0%2BA%40mail.gmail.com.
