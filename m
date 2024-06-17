Return-Path: <kasan-dev+bncBDAMN6NI5EERBAE3YOZQMGQEQ3A5DWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6259C90BFF5
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 01:57:54 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1ed969a5e4asf210865ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 16:57:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718668672; cv=pass;
        d=google.com; s=arc-20160816;
        b=02xEICN6M+ZFv4L0SoHfOkzCokKnxtCw5W/ROv4AtpsVYoIOqQ4N6xaxjAbmD/Ei8T
         FCATyeOYA3Y63XEnmPEEUl92fW4ixQhWBpp1UPAzxfmTCofhIIrSaBntCT2WzSMeztPJ
         hf5/hBwRu55VtOYDSl0i7nIsR4419nVqH77ajzqKVzNus+c/hUj+ScWP+wO96qtYmfD7
         BYk6iRXZSm4+BQIUSJ+YBtSaZpDUEgTeXsyr+VGDWKdR5zPGmQzkNk2n7qd7ajN0mgiW
         4trddMrf5SKiq+pypGutZj/mT9lpOXOPugdaOkegsgSnNR30KndAbyM8nYXQU7QsvKqb
         L7wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=vsgQ6Xyd1rHOalBFuunGWtzG6JVY7q0LkaGe+rcVxIg=;
        fh=8hlFEtyTdB66L1X+n3zzjU6VTWjSylTtwTscKSU8mGw=;
        b=TccLoRVLiKzHTR4R3Q3q6/G12m84buBFq1A60Th+gBVEjyhpfI7eiN+xY/us2hbacg
         DpfDNClUMLscLUhz8YFhUdpFH3IvuqDapqzJCqOZBf2HKG9Y+ECefYcDo5aHH98Bi351
         V+yywX5zwbdP+kPxRy8/TJ7KZr2CuH4Fz2hHfxZS0bSAcMVnncDx8w+FRoRh60n51r7c
         2Dt0tslNjLUoiSgoaNiUg0K6vvYHzHHp4AmfpN20mlpToIvCiSs9Jr7GzQ2ioRbZXmPV
         ++jyJ6sPj7iPImTXkSUr3rdG8jJ9SMTGWE+qiFBcTWgyaxqf8ZUGEzyk6NWWsKioeRo6
         MkaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=3z3WuypT;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718668672; x=1719273472; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vsgQ6Xyd1rHOalBFuunGWtzG6JVY7q0LkaGe+rcVxIg=;
        b=PIbHJaynjaneeY8JOuEf3qzTzSS5Xm44PB3evw6LEf6AKByt3e16RDsmoTv+sAQTq+
         rhu1xaRT6Qj7nSNMOMt4X2Jka+uEGVtfbI8Iae+6EQc5qvV1GFbrEOVKBGNWbAXOSizi
         36f8C5tAspmOrriVFWEWBrVyMmirj1I0ZSKTLq4xpTbIR+z223KgvFf09qtXlqjwfRaT
         in8L/zriPpHWKqZ7AXMioGvLc4w7GEeVvAkqFRaDf3TQm3XWL7GazFj+6ga9nCM//4B/
         5XZY9lTI8Rl0g4dTCBnX3wOzkEtRgetP8XzDDZbfp5UoKsD4W6+/IPFQyaDpCfm8a8AP
         sGJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718668672; x=1719273472;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vsgQ6Xyd1rHOalBFuunGWtzG6JVY7q0LkaGe+rcVxIg=;
        b=HPnBCSERHLYSBt5THQOvE1zUS65l1xgcGmSUWbrjw8FZCBu5eMuGPH7l9bslBrHCND
         YqYUrZHbMBvcp4C7p+OJHJ/L3CFWKkR8E4w7ZkyS2caHgOx0kecnqJpIWi+84YXXUBfx
         7cu1n2b02U0lSeE5oYMY6lADeOzF1ozHm0ic3Oim6prQVQBaoESfnxF0AY95ATxjLJYu
         PfvqU1snU9cbGAE8opBSX/AYP5tXiX/hFjynfJ9nXofZrNfjHejGSaap4y39oQdzfst9
         5lXClGkbpErgpGrZMIXWft32bUcxVj1XMVap4QUFkawWuMID5w/MPhutXQbcg+Rt5P6j
         A9lQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURLjQcXu2ZRqOB8HpNZqE+ahLnae0ZmnQGjpYAXn3w3Z+CZIRpC0e59clGYk43q5tu58XHx6cWK+mMwMbHlHt9dfITYeWnVw==
X-Gm-Message-State: AOJu0YyBcAKUQqX0onMt+cnPoYjyur42QRNUfvwQn5cHqMWWWnNuFJ5o
	q1ylQuhDgBycIb9zwh8hpaYRQapLVya9zhrk+182fSu3Z7nvwdlt
X-Google-Smtp-Source: AGHT+IEPisnZkPWdHRSIhKS3DuUyr4lpmfkEFA1jDi3F2IcC5WFWo4xLUbB3J7h1oh5KhjJls+ZiTA==
X-Received: by 2002:a17:902:7598:b0:1f6:e859:9190 with SMTP id d9443c01a7336-1f9927840e8mr725835ad.29.1718668672216;
        Mon, 17 Jun 2024 16:57:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d9f:b0:705:d806:37f5 with SMTP id
 d2e1a72fcca58-705d806424els2037672b3a.0.-pod-prod-01-us; Mon, 17 Jun 2024
 16:57:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXVddYBVHb7uNs5B58HvVkZSjp8uhf73rVz7ZvpQPaiFGRvBicLo43Yx9BFugt2qfWDXkxmHkv0c7ULitblxitSEYWz8+eTZXcimA==
X-Received: by 2002:a05:6a20:918f:b0:1b5:8ab9:9a24 with SMTP id adf61e73a8af0-1bae7f174f2mr11200496637.35.1718668669532;
        Mon, 17 Jun 2024 16:57:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718668669; cv=none;
        d=google.com; s=arc-20160816;
        b=F3693/N7yZA9iSz4eSA9tC40xPFL6JZWzQcbw4uJ1OsYV2i/+HcIaa9IXrJnc03vai
         MX+8gpDDBFe9XwdXVdzAzysOoN3mC9qMDO+yjBQvoDUdAiqT9bzls39k+w+yQWXqEi5O
         cqg1/M/61ujlAxkzZI/53GMcyUibFBVSvbWnejiNkkmD1tkcBe2hpAkJpdUIDAndtPWh
         9M+EoqzNITkVEOGTLohge7Vyvoym6IJ1/DJf7ZIPAazwHCuKJE8+Se/q+zO6+59M2NPo
         fEBmbeftHgnOys9D2LtAAFtj4G2g31DK00xEljEZUKKxAHtJB5TBSfmzzZjhUzV9Ag4h
         TYZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=8hTbs5uD2MYpUM4xJQu6oqiC+cvQcipUudqa5qlicnY=;
        fh=nRBybcRn8aorR6YZ7WPuOU4KxJuSPvX235NAM+tg+0Y=;
        b=zjnxxPVIg72bWBDaPwnYo5cWoObGIpuP4HitqI53kxHHz6UZnII0r+kVbra4Nwz5Ex
         qWWMYNWWsBsUhqrtKdxV6xv14JbWOXCiM7NRwbTjFC9vF4MJ3Houu3mbXhUlB1hMup+p
         EYgK4zGyeswDRtGet4w1xV4NLrC+owj9wJbZxJ94AICMH5RMGIwAtZV+0iEsduCIKZH5
         wIcG/jvg+bAw04UQ0mStfo8hVLVR60Z3Qz1hRnKvMdJ9bc+lZLsKdoGESFFxXoXRKYkx
         wfdqbMQkPWihRvUYtDF/rhBT8WcHpDEgVjTzhgEX5nLMNJlcq9ERdwJ59E0WBDlsbdi0
         00xw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=3z3WuypT;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705cc775575si420019b3a.0.2024.06.17.16.57.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Jun 2024 16:57:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Kees Cook <kees@kernel.org>
Cc: Gatlin Newhouse <gatlin.newhouse@gmail.com>, Ingo Molnar
 <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
 <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin"
 <hpa@zytor.com>, Marco Elver <elver@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Nathan
 Chancellor <nathan@kernel.org>, Nick Desaulniers
 <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, Justin Stitt
 <justinstitt@google.com>, Andrew Morton <akpm@linux-foundation.org>, Rick
 Edgecombe <rick.p.edgecombe@intel.com>, Baoquan He <bhe@redhat.com>,
 Changbin Du <changbin.du@huawei.com>, Pengfei Xu <pengfei.xu@intel.com>,
 Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>, Jason
 Gunthorpe <jgg@ziepe.ca>, Tina Zhang <tina.zhang@intel.com>, Uros Bizjak
 <ubizjak@gmail.com>, "Kirill A. Shutemov"
 <kirill.shutemov@linux.intel.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
 llvm@lists.linux.dev
Subject: Re: [PATCH v2] x86/traps: Enable UBSAN traps on x86
In-Reply-To: <202406171557.E6CA604FB@keescook>
References: <20240601031019.3708758-1-gatlin.newhouse@gmail.com>
 <878qzm6m2m.ffs@tglx>
 <7bthvkp3kitmmxwdywyeyexajedlxxf6rqx4zxwco6bzuyx5eq@ihpax3jffuz6>
 <202406121139.5E793B4F3E@keescook> <875xu7rzeg.ffs@tglx>
 <202406171557.E6CA604FB@keescook>
Date: Tue, 18 Jun 2024 01:57:44 +0200
Message-ID: <87zfrjqg07.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=3z3WuypT;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Mon, Jun 17 2024 at 16:06, Kees Cook wrote:
> On Tue, Jun 18, 2024 at 12:13:27AM +0200, Thomas Gleixner wrote:
>> In fact is_valid_bugaddr() should be globally fixed up to return bool to
>> match what the function name suggests.
>> 
>> The UD type information is x86 specific and has zero business in a
>> generic architecture agnostic function return value.
>> 
>> It's a sad state of affairs that I have to explain this to people who
>> care about code correctness. Readability and consistency are substantial
>> parts of correctness, really.
>
> Well, it's trade-offs. If get_ud_type() is in is_valid_bugaddr(), we
> have to call it _again_ outside of is_valid_bugaddr(). That's suboptimal
> as well. I was trying to find a reasonable way to avoid refactoring all
> architectures and to avoid code code.

There is not much of a trade-off. This is not the context switch hot
path, right?

Aside of that what is wrong with refactoring? If something does not fit
or the name does not make sense anymore then refactoring is the right
thing to do, no? It's not rocket science and just a little bit more work
but benefitial at the end.

> Looking at it all again, I actually think arch/x86/kernel/traps.c
> shouldn't call is_valid_bugaddr() at all. That usage can continue to
> stay in lib/bug.c, which is only ever used by x86 during very early
> boot, according to the comments in early_fixup_exception(). So just a
> direct replacement of is_valid_bugaddr() with the proposed get_ud_type()
> should be fine in arch/x86/kernel/traps.c.

I haven't looked at the details, but if that's the case then there is
even less of a reason to abuse is_valid_bugaddr().

That said it would still be sensible to convert is_valid_bugaddr() to a
boolean return value :)

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87zfrjqg07.ffs%40tglx.
