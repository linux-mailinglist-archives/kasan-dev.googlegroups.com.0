Return-Path: <kasan-dev+bncBD7I3CGX5IPRBGXD2OTAMGQEP4QS6GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C61B777A4B
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Aug 2023 16:18:03 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-51dd0857366sf14345a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Aug 2023 07:18:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691677083; cv=pass;
        d=google.com; s=arc-20160816;
        b=XwsaQynkkySSWzfYSd7chcpFMXJdrjl8wRXDjvkWfnPIMcLfZq3xzWIp2R+7pZlrO8
         T1QtILEV9DMFQFPYJMFdITOPdDAvtaASNsfibHy03gvahPkUhA50aWkCWtrjR6FDdyV2
         Vlbm1x0b2O5303Ug5kijzlYIksEOn7plQzHxzo+5BeWP5lH/n9fyuyCN+7FhVhG4N4GR
         mA7m1mC8uDDVkf0MzQxZmi8ZB9ipqynyA4TsmVk/MJPcktNZOzBb1D8/6Ub2358gEM+r
         aBlnnbro9ptu3tbkHbakHSJzc41CPeUC3uB+wbcWx16hLkIC24yHVqKayo3Lectvo8e5
         Dt8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=IRd5LWntRmoaxl9A3Op1AJqY+0CGmmbu+NO7ltOD10U=;
        fh=BisWGWtq6FUUG7y9GZbYdSqqke+VMBNrLu+Qfx30lV8=;
        b=pMe7IvO6Lc3IDWGKCqUoA5fcRtE5UMjHsY67TyKHlAS4JRbsxvU8+NUg6dsbYi0G5Z
         Yh31VlhON19kwhc07icG7YcLrWAp0vHydYDWiwwV/1gVm5rsY65MeiIXR4Nsu0JY7KZt
         B881TfF24tuKdtOrLgckI1wIDYZvQRIeXYk07cDBH3DQOYQwdwVN7b0JtEpMAfU6KCIM
         4AZaUreBvCPtK5RzaPwonwNsK1OzkqQKTc/eHPkZxQygSGIRrTveUOijW/WSVl9bq/UE
         JNV81QtOw7Y2CSxSnEIXMoCC8HkiqCBw4T3UqLI/b04zzY8il9pZ2L4vYP9apHfR3Vzb
         oZ8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=iWBAAYJf;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691677083; x=1692281883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IRd5LWntRmoaxl9A3Op1AJqY+0CGmmbu+NO7ltOD10U=;
        b=dmWn2pJnseqEglZ2HFR05L6pKTt0jRBvzdg5SdYOfJii8cF8b9DjnIdhp3rtFxzcGL
         k9zoEA9N5qXSQu9r4wyBu8QvHn13ZobwAmk3KcMeDzVFLuXp5u0Nep5QX1nafaZ8w2in
         6A6sPvoNeAbaJ30HkAJiPnm7GqNIPfCuLLtLkfEnIj8tR3ICVXAX1YCESxrYVzQVwq7G
         oBjhDzknaxk4Una4mUnbOqpfEO5xUhEqZz/4Sx262/UN1ZdXE6pw93xYEnw68dh6q3gx
         3A4bmGYgd1TmsMyu2G1lN0hym8pjYlRZDFXsKt5dBtw0sfcEDjlVsbyHpglWY6nqC6BN
         NmSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691677083; x=1692281883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IRd5LWntRmoaxl9A3Op1AJqY+0CGmmbu+NO7ltOD10U=;
        b=Y1ApYEMNr34jtzYxhxO31GJdpFlMyqcs+IUBvtSERnCMWhSY8+vXK19+GpX+KPtAff
         96KT9yfDAYtdWo9EzaQnagvsqByH2lDbOTmV8cgmC/6TkNW17IamgbVeIkBzAttZd6O4
         Y9EpOfiyqtX3GN4yvqdu2cCqFdL0N24B7Ls0/MTzEzEnm3UAjjH+K7KSfydJTn5RGL1m
         CHjzspKZcjqFKwx6vRPFZqckOzHCNzvFFFhoIhlnWdadFJoDzZcQA8zX1ympsm047iUp
         oKUg/Qn1GyM7aT4VFxY6Y7Wit94DG91NokHxCR4y+uqmq0TS/y30pAOFYYj8j2A3LMcO
         Pcqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxYGf+i9Fb5/4DMBgkImAWZ8xS7qJWqjBfshn/6fhG+Poj9E+vG
	N+Se2f57fDVANwzaW5ClrIw=
X-Google-Smtp-Source: AGHT+IFBpRt1cUkgsC19/7/KUcw3ggWiqNY0swYoKvmB+fms1pSHb/8BVM3Ff485Jiyw4/IeGM1a7w==
X-Received: by 2002:a50:9f48:0:b0:522:4741:d992 with SMTP id b66-20020a509f48000000b005224741d992mr262740edf.4.1691677082487;
        Thu, 10 Aug 2023 07:18:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc04:0:b0:2b9:5184:f05f with SMTP id b4-20020a2ebc04000000b002b95184f05fls267047ljf.1.-pod-prod-01-eu;
 Thu, 10 Aug 2023 07:18:00 -0700 (PDT)
X-Received: by 2002:a2e:920f:0:b0:2b9:eeaa:1072 with SMTP id k15-20020a2e920f000000b002b9eeaa1072mr2261086ljg.18.1691677080653;
        Thu, 10 Aug 2023 07:18:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691677080; cv=none;
        d=google.com; s=arc-20160816;
        b=FVW8L5gFA60RitXmTTtnK6kywFAkSFDCXIDJAVPke5P3zjYI20eQTnde10Po8MRQ5Z
         fyGyErBWCTwbsgziqibQ7zG49QyF5Z+FMyoASvRO+phkrKp85dGyK/xRqeLvjcEHGmDu
         tmbTzwgTitSKh1vM0mBhXMQAKmr4MK413lGkr/Dv2YOomrIc0ja8FNsPWocszeC5Cvix
         WBKfTMblw9OT9sEVZa0L2n/UsTHJEow1AUP8Kx1G0WWsi3hnBzf2zHeP3QJ7OAM0hE4M
         RhZrE9UlKqXAn5e+wvr+iZY4n9jBbbHT0EZDCLG4q3ahbUzb2WKx22JBSLBWY5Ez8k73
         JhAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ScQPJVFmfG5yKGg5DsOWT7+SxQjEiPcmHkfk8PrKVuE=;
        fh=BisWGWtq6FUUG7y9GZbYdSqqke+VMBNrLu+Qfx30lV8=;
        b=Pmc38e6RPFxUeQq6zzyqNbcvAELz3JxW8Iv5MF61i4Yzn7oyaOipuJUblnSYVOAT6I
         MIxsh7+A2HaebNQrbqIWrBLwqbZRClz0qWB997f2HKm+hv3YfGO/p/LcLkztrcUOUdau
         gE/Lc5P3wDaBKSuUtL+zWsoDT6FBWr4sNL36DrGlOvYQuQJ2ve4zN6NB0X5yyKfJ6hMz
         mG2CkIG0pps6d3LyPOVBFvWM614HQNQp482CTLEFYRYV8U5Nyx+88aKGmRC5qkHaEeUt
         Ik9OQ1kG5uHeQCqGd13lcl9KxNPOfsT7Mu7/dZ8dj9Vow0a+4i4O4iWuQBOhfePrM+3h
         AmFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=iWBAAYJf;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id b6-20020a05651c0b0600b002b6f8d5f93csi128294ljr.2.2023.08.10.07.18.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Aug 2023 07:18:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id 38308e7fff4ca-2b9c55e0fbeso14860311fa.2
        for <kasan-dev@googlegroups.com>; Thu, 10 Aug 2023 07:18:00 -0700 (PDT)
X-Received: by 2002:a2e:920f:0:b0:2b9:eeaa:1072 with SMTP id k15-20020a2e920f000000b002b9eeaa1072mr2261035ljg.18.1691677079446;
        Thu, 10 Aug 2023 07:17:59 -0700 (PDT)
Received: from [172.16.11.116] ([81.216.59.226])
        by smtp.gmail.com with ESMTPSA id l19-20020a2eb693000000b002b9b9fd0f92sm363615ljo.105.2023.08.10.07.17.58
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Aug 2023 07:17:58 -0700 (PDT)
Message-ID: <37faa9c7-94a3-3ea1-f116-6ff5cdf021cd@rasmusvillemoes.dk>
Date: Thu, 10 Aug 2023 16:17:57 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.13.0
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Content-Language: en-US, da
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Petr Mladek <pmladek@suse.com>, Marco Elver <elver@google.com>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, Steven Rostedt <rostedt@goodmis.org>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrew Morton <akpm@linux-foundation.org>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley> <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com> <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
 <ZNHjrW8y_FXfA7N_@alley> <ZNI5f+5Akd0nwssv@smile.fi.intel.com>
 <ZNScla_5FXc28k32@alley>
 <67ddbcec-b96f-582c-a38c-259234c3f301@rasmusvillemoes.dk>
 <ZNTjbtNhWts5i8Q0@smile.fi.intel.com>
From: Rasmus Villemoes <linux@rasmusvillemoes.dk>
In-Reply-To: <ZNTjbtNhWts5i8Q0@smile.fi.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linux@rasmusvillemoes.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rasmusvillemoes.dk header.s=google header.b=iWBAAYJf;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates
 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
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

On 10/08/2023 15.17, Andy Shevchenko wrote:
> On Thu, Aug 10, 2023 at 11:09:20AM +0200, Rasmus Villemoes wrote:
>> On 10/08/2023 10.15, Petr Mladek wrote:
> 
> ...
> 
>>>     + prolonging the list of #include lines in .c file. It will
>>>       not help with maintainability which was one of the motivation
>>>       in this patchset.
>>
>> We really have to stop pretending it's ok to rely on header a.h
>> automatically pulling in b.h, if a .c file actually uses something
>> declared in b.h. [Of course, the reality is more complicated; e.g. we
>> have many cases where one must include linux/foo.h, not asm/foo.h, but
>> the actual declarations are in the appropriate arch-specific file.
>> However, we should not rely on linux/bar.h pulling in linux/foo.h.]
> 
> Btw, it's easy to enforce IIUC, i.e. by dropping
> 
>   #ifndef _FOO_H
>   #define _FOO_H
>   #endif
> 
> mantra from the headers.
> 

No, you can't do that, because some headers legitimately include other
headers, often for type definitions. Say some struct definition where
one of the members is another struct (struct list_head being an obvious
example). Or a static inline function.

We _also_ don't want to force everybody who includes a.h to ensure that
they first include b.h because something in a.h needs stuff from b.h.

So include guards must be used. They are a so well-known idiom that gcc
even has special code for handling them: If everything in a foo.h file
except comments is inside an ifndef/define/endif, gcc remembers that
that foo.h file has such an include guard, so when gcc then encounters
some #include directive that would again resolve to that same foo.h, and
the include guard hasn't been #undef'ed, it doesn't even do the syscalls
to open/read/close the file again.

Rasmus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/37faa9c7-94a3-3ea1-f116-6ff5cdf021cd%40rasmusvillemoes.dk.
