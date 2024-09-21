Return-Path: <kasan-dev+bncBC7M5BFO7YCRBNXLXS3QMGQE3BYW7BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9931497DEF9
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 23:08:08 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-7179469744dsf4873429b3a.2
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 14:08:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726952887; cv=pass;
        d=google.com; s=arc-20240605;
        b=DSbIv9eHQvlqcV7l/oyf1Fs40rXGrsQhlMPPtV81+tj2mXrkpBm6KzagRFNRTkzIRR
         XTm7brT75FLSBCxJwAMy/8XPjrZfyRGygOooJDbGIlUD0ZyP+wh8WO0K9MTv6e8wR4t3
         9z3MZopRpUqSWsBn8/M/4ZxpcjxX7OFgDqoDxlugHS2XC3jZTmU+ZR45mvZSubm6+ecb
         Z4uAisWWoopBJ7DEn2VcjiVASBjiV0nkBNnjxghBLdCWT07fBwamgOchNkT/sY0zCl15
         s+xEgqyIMc09kRvLMzZhxJk6/6UgMNNDo90l1NZAj8i4P+hRAqbZbkdLhjAGh4RaKbc7
         GvKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=yr37Q/9wK7KZ59gguTAz4jLsSqwpNPUW3p0u7iknN7A=;
        fh=M4xOjYY2LyI6/4FAAnKIzdjPEHtsTszqSwUu8JKsCPs=;
        b=drkg4Z/rk1VwyBDK3wdBWaMRkrANlaGq69+vH/5umhcmXQC2cAOdYjoLblSkHsGzTK
         gtM1PQcBfuFVFbRvEagPWL4FqGjB8sEWwRgyIFNjy4JLGa6qUuvw+8JlwSL9Txa7kLVi
         YE+YTYIvfRxWqvbf0//pzc/yBLXvLPimBGFLI2bN9y6s4EmP3t0pf8eLdhvTG7NRmFj4
         su9tRCSYDv5CeyvAAz7NLpyGe5OkBOsy3vwtXZghJGzMGe13mIVu3TVpIQdJV4lrgS6W
         tjZuMvBs/EtgNTEDmsMEcgDv5RzDb46YyrRxfSDEk4OP/HdOn7CERGN3gX4lcFtsnbw7
         FdZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GVvPnnNo;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726952887; x=1727557687; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yr37Q/9wK7KZ59gguTAz4jLsSqwpNPUW3p0u7iknN7A=;
        b=Je26UIKc8QiJ6+z8w6xqKQpdVLrNOOG/rfHpZq6DzJxISVSOXVZejS1sTIxaCFISRe
         6J/UyFdu+N1eqs2zPr1zHaPckuDX2sPjr0IA9217U7V7awmNHkKEgPlgYMDGBAGz4icP
         VP9EELsYAKIrkUDaQDVU08qM8fVbAx8ZB4kHRM8RZbIqj4X72Ne6s38d6k/4oTcPWQG3
         tmAh50eXjv/MtJKefy7VQuYGStHYzAhiIU6G0FXNmWJLM33320IXwBqimnPY0jleMg8E
         ZEVgjmgQxqWRQ1SMP2reCRRa8HcKSULZycZFbGy02ghGQUdjEmJCmn57KfPwzDNbbAzs
         QyNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726952887; x=1727557687;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yr37Q/9wK7KZ59gguTAz4jLsSqwpNPUW3p0u7iknN7A=;
        b=Afh+t1Sh/cIHYB4WSF8rGLkXKdlV8mXuYci73t42h3Ayc1NrP4hoEfTORrJF5OyuHB
         rb40k1DqV9og0WjEl7incG94lDgBBcd2tOQSHB+QMZBDGV57x5fK8h9CeO9635o+5jCR
         lmHAretJg1zP+8UV1efdvAAN06I+6o4CBqUWdBq20yxIJyh7W2Msmbfu1hHH+anHMGfn
         5aLYMVTwbsYlKHnTUSNTHmFTCqOKAQv5nmihVVhQYeuWSgZWIojJ6Ido+OvcLXs2ZYsM
         q4Uo5b1tf5ue3Bzpj36+SOiep40+shF+rol5WkFlNG56PmzMTxmG7GoMN8jdigpFmH/7
         ws8g==
X-Forwarded-Encrypted: i=2; AJvYcCVCDlFZqe0jplXSOb6bev6JIgxLOQwnX/AP0ifwyF104Dl6CePVxjfb0udAwpLjn4kgTvuIBQ==@lfdr.de
X-Gm-Message-State: AOJu0YwrkvCko4p+T39LndXhFKLOgIcp9J7IQcpBeHTwbzCXXw1wyz+F
	VJ0SMJPNpIp2aHL4YHtFZNbA30i7mYyv+O8XyO1RbYQf6xJmnYdk
X-Google-Smtp-Source: AGHT+IEcBwcbkm0QCOpn2BZ25H91RjcQpnKXThGq08lacq1HxGVVNp9X7jWrzHiYQoXWSkN82UHNuA==
X-Received: by 2002:a05:6a20:c781:b0:1c4:23f0:9665 with SMTP id adf61e73a8af0-1d30a94cb75mr9729129637.29.1726952886637;
        Sat, 21 Sep 2024 14:08:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:a8c:b0:70a:fd97:f05b with SMTP id
 d2e1a72fcca58-7198e5a580als2293036b3a.1.-pod-prod-03-us; Sat, 21 Sep 2024
 14:08:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUFWrgyuYa+OYor63EBRkR/4s2a8Ner3KFgcQ2k939KDogE3Xl6fTepftOq9QSGozPXxzWBQH4nTK8=@googlegroups.com
X-Received: by 2002:a05:6a00:148d:b0:710:4d3a:2d92 with SMTP id d2e1a72fcca58-7199c936c23mr12029664b3a.4.1726952885103;
        Sat, 21 Sep 2024 14:08:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726952885; cv=none;
        d=google.com; s=arc-20240605;
        b=gseRLG6HNusLZgXjw6B7OdJwHmVuoMOk+AsRoL+y2KfoQ5sGqaRjWGJtmq7pUm9bGs
         Y7Zmxq383M0NuK+OMdy2TrXGUo/GEkBJ4fLfZrSAEiGEksGFAJKhqUSlagG2xSxUT+p7
         dHQhv5ycyZCvN1YUnioepPKNAXJzxfLxlrKaBAdUz82n22fXXR+/ptAbJ35SRXaFuMXT
         4vxRCT5YJS+GmMKZ5N3puHR7MSUwclxK04wAfS6iiDdLtkOo/qsjTmyMSENEXXwq6BS6
         WfFMKSY9oPNtetPxnv/LImG/JqmOOsI9fNoY2/T3M+3yKt8U4w4CmffcAKULByCm7Jkn
         uXLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=1ZyEP8RqiEX4aO8buEZUbFkfwoj9qwj5TS4bmseu6C8=;
        fh=OXmBePW/HUOP1kWKo9WDUsNeh5V7kKdOk7i+4otqc6s=;
        b=YZvrjGia1V2RXQsFoEH/n9tbIUpGjK9oNfPZHIJ4HDk5we9ktpDC/2atggLRMmmpUh
         xSF3VTzF2Qghp3C/PHaE5Qv8lNljuYK1tDgAPeFeASqQRp4hXFdkX6XccHukPeRCq1ex
         qq9e6eo0QjyCJ8N/jtuYvXgA5zNqWrAwo0nWu0Oq0e2kYCubvpR2DrmNvsyy3JY4tTVI
         j29k7wwGF0G8Z36QK3U0BDyBvfVNohh9nhb4tT9AMxwLcNqfHQ1VFDKl0a3tkRclyncj
         NPWt/WwxLaCMxlX09LJBxBujShEhZfJlkI1ZuEjO27DapjMMj0184vVLh3F6ZruvRORK
         tIeA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GVvPnnNo;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71944c36cb2si749181b3a.6.2024.09.21.14.08.05
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 Sep 2024 14:08:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id 41be03b00d2f7-7ae3d7222d4so2649768a12.3;
        Sat, 21 Sep 2024 14:08:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVKXCnAQpGKzrIsDZvNGItgFxaUDGg95Wl1XA7By63VeDqu9pxUhdf5jwNGBW4Q882C1cSWIteyrt0t@googlegroups.com, AJvYcCXyT+tmeQkJU82+DOL4L/1NRTbyF8HyJwju83hLE+YjrjQoHl0VZAWFDodEPj+Eoj/Hgd/G0MedDcs=@googlegroups.com
X-Received: by 2002:a05:6a20:2d0b:b0:1cf:6533:5c82 with SMTP id adf61e73a8af0-1d30a94b2f5mr12037658637.26.1726952884555;
        Sat, 21 Sep 2024 14:08:04 -0700 (PDT)
Received: from ?IPV6:2600:1700:e321:62f0:329c:23ff:fee3:9d7c? ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71944b7cfa1sm11657785b3a.104.2024.09.21.14.08.01
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 Sep 2024 14:08:03 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Message-ID: <73f9e6d7-f5c0-4cdc-a9c4-dde3e2fb057c@roeck-us.net>
Date: Sat, 21 Sep 2024 14:08:00 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and
 test_leak_destroy()
To: Vlastimil Babka <vbabka@suse.cz>,
 KUnit Development <kunit-dev@googlegroups.com>,
 Brendan Higgins <brendanhiggins@google.com>, David Gow <davidgow@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Joel Fernandes <joel@joelfernandes.org>,
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>,
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>,
 "Uladzislau Rezki (Sony)" <urezki@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
 <6fcb1252-7990-4f0d-8027-5e83f0fb9409@roeck-us.net>
 <07d5a214-a6c2-4444-8122-0a7b1cdd711f@suse.cz>
Content-Language: en-US
From: Guenter Roeck <linux@roeck-us.net>
Autocrypt: addr=linux@roeck-us.net; keydata=
 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
 mDW4+i+XlNFUPUYMrIKi9joBhu18ssf5i5Q=
In-Reply-To: <07d5a214-a6c2-4444-8122-0a7b1cdd711f@suse.cz>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GVvPnnNo;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::531 as
 permitted sender) smtp.mailfrom=groeck7@gmail.com;       dara=pass header.i=@googlegroups.com
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

On 9/21/24 13:40, Vlastimil Babka wrote:
> +CC kunit folks
> 
> On 9/20/24 15:35, Guenter Roeck wrote:
>> Hi,
> 
> Hi,
> 
>> On Wed, Aug 07, 2024 at 12:31:20PM +0200, Vlastimil Babka wrote:
>>> Add a test that will create cache, allocate one object, kfree_rcu() it
>>> and attempt to destroy it. As long as the usage of kvfree_rcu_barrier()
>>> in kmem_cache_destroy() works correctly, there should be no warnings in
>>> dmesg and the test should pass.
>>>
>>> Additionally add a test_leak_destroy() test that leaks an object on
>>> purpose and verifies that kmem_cache_destroy() catches it.
>>>
>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>>
>> This test case, when run, triggers a warning traceback.
>>
>> kmem_cache_destroy TestSlub_kfree_rcu: Slab cache still has objects when called from test_leak_destroy+0x70/0x11c
>> WARNING: CPU: 0 PID: 715 at mm/slab_common.c:511 kmem_cache_destroy+0x1dc/0x1e4
> 
> Yes that should be suppressed like the other slub_kunit tests do. I have
> assumed it's not that urgent because for example the KASAN kunit tests all
> produce tons of warnings and thus assumed it's in some way acceptable for
> kunit tests to do.
> 

I have all tests which generate warning backtraces disabled. Trying to identify
which warnings are noise and which warnings are on purpose doesn't scale,
so it is all or nothing for me. I tried earlier to introduce a patch series
which would enable selective backtrace suppression, but that died the death
of architecture maintainers not caring and people demanding it to be perfect
(meaning it only addressed WARNING: backtraces and not BUG: backtraces,
and apparently that wasn't good enough).

If the backtrace is intentional (and I think you are saying that it is),
I'll simply disable the test. That may be a bit counter-productive, but
there is really no alternative for me.

>> That is, however, not the worst of it. It also causes boot stalls on
>> several platforms and architectures (various arm platforms, arm64,
>> loongarch, various ppc, and various x86_64). Reverting it fixes the
>> problem. Bisect results are attached for reference.
> 
> OK, this part is unexpected. I assume you have the test built-in and not a
> module, otherwise it can't affect boot? And by stall you mean a delay or a

Yes.

> complete lockup? I've tried to reproduce that with virtme, but it seemed
> fine, maybe it's .config specific?

It is a complete lockup.

> 
> I do wonder about the placement of the call of kunit_run_all_tests() from
> kernel_init_freeable() as that's before a bunch of initialization finishes.
> 
> For example, system_state = SYSTEM_RUNNING; and rcu_end_inkernel_boot() only
> happens later in kernel_init(). I wouldn't be surprised if that means
> calling kfree_rcu() or rcu_barrier() or kvfree_rcu_barrier() as part of the
> slub tests is too early.
> 
> Does the diff below fix the problem? Any advice from kunit folks? I could
> perhaps possibly make the slab test module-only instead of tristate or do
> some ifdef builtin on the problematic tests, but maybe it wouldn't be
> necessary with kunit_run_all_tests() happening a bit later.
> 

It does, at least based on my limited testing. However, given that the
backtrace is apparently intentional, it doesn't really matter - I'll disable
the test instead.

Thanks,
Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/73f9e6d7-f5c0-4cdc-a9c4-dde3e2fb057c%40roeck-us.net.
