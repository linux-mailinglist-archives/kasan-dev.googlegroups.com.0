Return-Path: <kasan-dev+bncBCS37NMQ3YHBBJVV534QKGQEM7CHRQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D36A24817A
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Aug 2020 11:08:55 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id bx27sf6638815ejc.15
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Aug 2020 02:08:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597741735; cv=pass;
        d=google.com; s=arc-20160816;
        b=UVuKj8HXqs27bkjEfO4xYU4OKrJ4k6tLinpos18POYk7QfHJWNT7OXvdyVDiCk36LN
         PmiXBJA1xWB6/vQa2/Oh79jIMSckXtTK8DgrSjFfXLdEsakIFS8BRRU935cu92xzWgkp
         e48eY+VRRhlnjwWJTT027o8ZBeS+twTmHJ28HKsMkJOZ1a27gkU44G2YqmyfhXPS0f1R
         xTqxcWdL4TzybYPyhlr/mmSCGjMu+BlaBGmHISm4caeter1m4Yoryaw/IHNyraDGunZC
         arHXJt8ZXz1/O6eiJKdUyGU3i2vjV08eYxPTacG/pLFOydOn7EkQpl6/0+ofOHiescXv
         k2eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:references:cc:to
         :reply-to:subject:from:sender:dkim-signature;
        bh=mLxqd48aHcxmGpSwB5dk00I8eMHhD3p/3bmutbH4B5k=;
        b=H6Dsc1CtJSZlyHanmT/f/zM6uSJBDlmLK0mVj0po3IXGvWz8itjqfvo2wO6rmpnsmw
         ZQmkI+EuYOdbZnu4E75jLcocZtkYixIPYD9RhbDXZI9Ddbb3TEx+ZjNjSDVL3PcV2bzU
         So6/QLVp8NmWbWtnnfGCfqIJsC13FIJ/hDyaW+K99lR5GpAyu+ywppsqiqpn0RSfH+8e
         knd1ABPXDyQZR35I7xIV6TtMCH0Au5G1YcBrcFrpYYBvBxOaUB8D983b2rxGkeO/VuNo
         v9nf6O80je625mtvHX8BnCRceqnItNI2snZKTdFchZ8ZmEf1D/pzx2c94g7+/GGj8rv9
         0gqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.208.65 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:subject:reply-to:to:cc:references:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mLxqd48aHcxmGpSwB5dk00I8eMHhD3p/3bmutbH4B5k=;
        b=ZNP5nNYIHhVbsZZY8PDRhalKE+EGI/CB8q+vValOMa3Cs57NEXK4sPbBxfUx7PQhc3
         vvwNrV+/AkZa6sc5kRYLvaky5FnDYFj4ckbQJKisDNS+g2uDvTZcGjTYmu1unQQYzvcD
         2QVLX65DS8Z9Yq2jO/4fTsK4837073rLvCmZtKglgslVDR3PEtuDlMSQkQZsb8lGmrLm
         gRmfAf86m/gYxPpkjp571k/niOQ2kNnT6iYH73CiPzmzMUWG/7aCTXdKBaYYWL4Ge7qi
         xNpE6xxjx8lMl2aFpMi+fXJh0HKI7mownFrH6CSDYwQVYHgctoIJoxzX2/RYZTDprT8f
         xD6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:subject:reply-to:to:cc:references
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mLxqd48aHcxmGpSwB5dk00I8eMHhD3p/3bmutbH4B5k=;
        b=OfyUcfMSdqADALwC/7FYlTGH6xbqy2UZdUVTVyY08Sg7yJXXkaSejsJ2E/wBgPxN0Z
         s2xtauZ1e9b0ZVYUmTuRefx6Us1e36itPRBMiipd6+int0aNWvTDvub8fk7QYb3cSk2G
         i36MyAQ0H11sOrpdpSON2CqphK+8N66/jUWvmX+JpPzUttzWW2UZRdVHD3u/cNhbIDgU
         eA3yTExYZWrCbAHlq7LRZ6z6czKhyDDRRaXUJjk1kPt+M0M17zOPqj8eodSKGKs0DLYp
         EHIKw8BKu3bmFVgoZd/nnYuQWTH5yhqqY3i1c1fppok0poPBufNCJ2P/bZoYF/23w0G9
         XMjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532UI5mFDV0QC8n8N2vv5l5dSs5c0kCBPiS4oHWlsQOL9e/mq8Qy
	i9LUqYIoQJuHplz1txwFglQ=
X-Google-Smtp-Source: ABdhPJwwTz7wwcffFSTQ4A1j7OuBr6I2//HC51iv+opYHpiI1odFL9bUZbyL0MWif9RMSfOYB0MYMw==
X-Received: by 2002:a17:906:dd5:: with SMTP id p21mr247069eji.416.1597741734948;
        Tue, 18 Aug 2020 02:08:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c825:: with SMTP id dd5ls9305585ejb.5.gmail; Tue, 18
 Aug 2020 02:08:54 -0700 (PDT)
X-Received: by 2002:a17:906:cc51:: with SMTP id mm17mr19611633ejb.137.1597741734234;
        Tue, 18 Aug 2020 02:08:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597741734; cv=none;
        d=google.com; s=arc-20160816;
        b=YjXEKIa4KY62tl/OMgKm6MipNi3iTLFHqBWGGWHKy1yBqUhrB1IcmuDfLdY5350o3f
         GdwNBQTCtG73yd56IGi3hObHqv0+H9ubDl1WpqUAS6Q0kWWrHnRhR1nTWjdY01JV8GdJ
         dLVwWAD00N2/RBDIrdGeTZiYNUe4QEQtvNbytHFmOI4iH3tcWuVvMMpgsEQ8KZ42sRSJ
         GamPNIpdrcf+2eU+0m2WFu/gpRxNr7BjFhD9vsbuvThXPcTJ6lsxnnmXwGjdKphYXgry
         4ogtOUAgMe6DZj3gGl0HeBPPHvJAEgB6pcTuvtw2ouBjM+TdtqYqGGEo9GK9kv8WKMvO
         cKtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:references:cc:to:reply-to
         :subject:from;
        bh=eGZFS/MFRoESH0uw3pVgleAg17asJndqbfQ7lo0he2A=;
        b=y3P1bn21mJINjdDuQIT1gt08RpaxPtqNg2y2NResZDgH/NtJUNQtfs2/EY5QX7ybHp
         my74fC1/BBM1HGUvhBgzQWLiiLI8JVhmtFkexhIKnUiJ803Tt3WAoIeGAYvjgyQNf6zu
         wtiQCjpo2xUN+vWuy00d5H+BE4J2/mU12jkvRVq3nZ1kCMJS5xF1iPJqWRQzBRnwg05S
         /9PWZhdAhnzuYvrhGdrHxg3W/lUlA9qCbQD+fVfjiAdSoUvd1fXCxCKGdLU0CxaYzpbe
         uKCidM10e9yHaTw0LK1rDgMHNf+YOgW1oN2/lslaP2ofO+/fa3pOD9jTnY4TKD+wKE10
         HwUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.208.65 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-ed1-f65.google.com (mail-ed1-f65.google.com. [209.85.208.65])
        by gmr-mx.google.com with ESMTPS id b5si749747edx.4.2020.08.18.02.08.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Aug 2020 02:08:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.208.65 as permitted sender) client-ip=209.85.208.65;
Received: by mail-ed1-f65.google.com with SMTP id t15so14611488edq.13
        for <kasan-dev@googlegroups.com>; Tue, 18 Aug 2020 02:08:54 -0700 (PDT)
X-Received: by 2002:a05:6402:12d7:: with SMTP id k23mr19002534edx.312.1597741734012;
        Tue, 18 Aug 2020 02:08:54 -0700 (PDT)
Received: from [10.9.0.18] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id o60sm838605eda.30.2020.08.18.02.08.50
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Aug 2020 02:08:53 -0700 (PDT)
From: Alexander Popov <alex.popov@linux.com>
Subject: Re: [PATCH RFC 0/2] Break heap spraying needed for exploiting
 use-after-free
Reply-To: alex.popov@linux.com
To: Kees Cook <keescook@chromium.org>
Cc: Jann Horn <jannh@google.com>, Will Deacon <will@kernel.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Masahiro Yamada <masahiroy@kernel.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, Steven Rostedt
 <rostedt@goodmis.org>, Peter Zijlstra <peterz@infradead.org>,
 Krzysztof Kozlowski <krzk@kernel.org>,
 Patrick Bellasi <patrick.bellasi@arm.com>,
 David Howells <dhowells@redhat.com>, Eric Biederman <ebiederm@xmission.com>,
 Johannes Weiner <hannes@cmpxchg.org>, Laura Abbott <labbott@redhat.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, kernel-hardening@lists.openwall.com,
 linux-kernel@vger.kernel.org, notify@kernel.org,
 Andrey Konovalov <andreyknvl@google.com>
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <202008150935.4C2F32559F@keescook>
Autocrypt: addr=alex.popov@linux.com; prefer-encrypt=mutual; keydata=
 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
 j3lCqPk=
Message-ID: <e72ac0d5-80b1-b8a3-2436-cc027f81fefa@linux.com>
Date: Tue, 18 Aug 2020 12:08:47 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <202008150935.4C2F32559F@keescook>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.208.65 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

On 15.08.2020 19:39, Kees Cook wrote:
> On Thu, Aug 13, 2020 at 06:19:20PM +0300, Alexander Popov wrote:
>> I've found an easy way to break heap spraying for use-after-free
>> exploitation. I simply extracted slab freelist quarantine from KASAN
>> functionality and called it CONFIG_SLAB_QUARANTINE. Please see patch 1.
> 
> Ah yeah, good idea. :)
> 
>> [...]
>> I did a brief performance evaluation of this feature.
>>
>> 1. Memory consumption. KASAN quarantine uses 1/32 of the memory.
>> CONFIG_SLAB_QUARANTINE disabled:
>>   # free -m
>>                 total        used        free      shared  buff/cache   available
>>   Mem:           1987          39        1862          10          86        1907
>>   Swap:             0           0           0
>> CONFIG_SLAB_QUARANTINE enabled:
>>   # free -m
>>                 total        used        free      shared  buff/cache   available
>>   Mem:           1987         140        1760          10          87        1805
>>   Swap:             0           0           0
> 
> 1/32 of memory doesn't seem too bad for someone interested in this defense.

This can be configured. Quote from linux/mm/kasan/quarantine.c:
/*
 * The fraction of physical memory the quarantine is allowed to occupy.
 * Quarantine doesn't support memory shrinker with SLAB allocator, so we keep
 * the ratio low to avoid OOM.
 */
#define QUARANTINE_FRACTION 32

>> 2. Performance penalty. I used `hackbench -s 256 -l 200 -g 15 -f 25 -P`.
>> CONFIG_SLAB_QUARANTINE disabled (x86_64, CONFIG_SLUB):
>>   Times: 3.088, 3.103, 3.068, 3.103, 3.107
>>   Mean: 3.0938
>>   Standard deviation: 0.0144
>> CONFIG_SLAB_QUARANTINE enabled (x86_64, CONFIG_SLUB):
>>   Times: 3.303, 3.329, 3.356, 3.314, 3.292
>>   Mean: 3.3188 (+7.3%)
>>   Standard deviation: 0.0223
> 
> That's rather painful, but hackbench can produce some big deltas given
> it can be an unrealistic workload for most systems. I'd be curious to
> see the "building a kernel" timings, which tends to be much more
> realistic for "busy system" without hammering one particular subsystem
> (though it's a bit VFS heavy, obviously).

I have new results.

CPU: Intel Core i7-6500U CPU @ 2.50GHz

Test: time make O=../build_out/defconfig/ -j2

CONFIG_SLAB_QUARANTINE disabled:
  Times: 10m52.978s 10m50.161s 10m45.601s
  Mean: 649.58s
  Standard deviation: 3.04

CONFIG_SLAB_QUARANTINE enabled:
  Times: 10m56.256s 10m51.919s 10m47.903s
  Mean: 652.026s (+0,38%)
  Standard deviation: 3.41

This test shows much lower performance penalty.

More ideas of tests?

Best regards,
Alexander

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e72ac0d5-80b1-b8a3-2436-cc027f81fefa%40linux.com.
