Return-Path: <kasan-dev+bncBC7M5BFO7YCRBJWMYC3QMGQEUUO66OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id BAAF397E1F8
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 16:14:00 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2dd4d5d4639sf1218528a91.3
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 07:14:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727014439; cv=pass;
        d=google.com; s=arc-20240605;
        b=jStHv75ksBkFxRP9oh4SIvwu1wywJMQ0sDSpL64WZGEn0NeA1NDBxG1e5cztjsgDPn
         bLPlX8HeAifZFQlUV9Xea+eB6ZskF6FMkVZCu8UpSdP16+ULWTa7h9RaAIgs0RfzcqR6
         HgO3emJi8jlJhgVwL51JZqhOeCOs25Y20DOtdDi3IrvHUhlU8k4sItGmzjmhJo1OyWHN
         2p7QZi7SfcXwXthmWwIYY5U8912vFgm13g1axfXYs8PItmvBZeOE7+0rkLw5qIiFAp2j
         QQO2brqyzMBNV06aa/fpg/J5KIBOcNcjwn9wor69S3QrvhTPf4ERrexSHkkizpuVQVEa
         ulEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=rQUY6qddYFqzHOt/k+yfO0alWl8/Qirng8WADd7ucm0=;
        fh=aMOkxVLUR2ou1234ZtsCIftkmGQNRQSL/YIygfI0AQc=;
        b=EAFvZtKeFcbj0+gry9qz23dJrE4ERFL6nNGayPohQtFv25dUBDrfUsUxmL8Lp9yBfy
         AtJQHGl578H3JfQa43TusDiDLsanSFT2/OOMWUMT0obqjmm59WWzScSLQP4ZhDQSDNn0
         2rNPwvElYe7NfMyk2gsyquR0+SXgb0T6CSV3h+J/UfVolAnY/g+Kiv/K7wHBBjT9aq40
         SiCmniydj9eCbzraG5wwUkT6QXMiGQthyrqexCBE8+MSimUH4pZvtyDzOu+lSq6AIKGq
         z8Nbswd23pUNhIW+aBIzLRAPZG9Wzk1iyfTtyXImw5vOuETVp8qRZ2yIsqZAAeYfPkWP
         dspg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WpIMdyKt;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727014439; x=1727619239; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rQUY6qddYFqzHOt/k+yfO0alWl8/Qirng8WADd7ucm0=;
        b=dR9lkzHqbcl37IML7VZvsDd1sFT/KNvZs5JXkCywJd04GVbwIZeYmK6NQxeqiLk5hT
         P/EZCp4eSE6AOKmL1PwIrKL+TdoL56LsfgPnNftdBYuQilzANT4ChDYkihZ2JIbXqrvW
         WznWgXW4j3DnrsZQj26flQ4/sBGdR0Y1EyFi9pVjerAHs6Bkl1Kt+cXG61v1KnwNc3Q1
         8zG/ZoX+dsqqDwxH3XGUr3iBbkIQPRt197CNDvxZprp+MXOcwNh5vRnFOP4iGHitgU1H
         FUCBnZgAbw86g2iROu2SKQdIbD8ACeaQq8EcPwD9A5hN/OZD3ii6S7AWMv1jqcXqCrkK
         aDCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727014439; x=1727619239;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rQUY6qddYFqzHOt/k+yfO0alWl8/Qirng8WADd7ucm0=;
        b=B36G9Mx985w67p36gX24oPAjzbpLJa6oIqqf2f0WD0yS1ilcg7gGLK3n+ln0nlYKBu
         IhMnfPQJqTpnDT9Nt4gxAfjIX9xKUb05+YabRUbpBeuotIWbw4+foc6UpfrtAOjBFmA5
         OxOisyNvR44bY6msBMxMSPtDOn/6bUd78B+rYjoj6XMRkV30hQ/y+E0N5j8xqhSiiw2C
         2rRIhmvxIWOvaAWXtaz4pKwfKeIiSx/KLUJz3LpKk8T9zvwjCRbiHgFkcqPoFiUpyimm
         fBCh3gDTWByCBhc4kKOdrfRf6jdDjQjSO0Nh2kxf5f6lSC0bB7c2Ftjz5U8Epss9i5Xv
         /NMw==
X-Forwarded-Encrypted: i=2; AJvYcCUswSPrrlXllQLWBfnvl8NOfIeX4KiiJbNFKVnhAaWRtwkGjXgiUKNhRgMQUKYKpSA8wTbMYg==@lfdr.de
X-Gm-Message-State: AOJu0YzRuPa5wEWqUgPbmRlSj9VaFajqzFvaf/D9s+yHr7DG3KxyjWyJ
	BGSHlklVPKMT6VhvqTe/fvwfEzoxJ6x9L0faJ9/cavlDReXHPE8R
X-Google-Smtp-Source: AGHT+IFmy1e+gzhJuNjqhe+iPl27qCftjv+/dH9Xhz804sHTv/imLGTdlY9wBQldNNjhLtakP8o2Rw==
X-Received: by 2002:a17:902:dacf:b0:202:2af7:b50b with SMTP id d9443c01a7336-208d83afc24mr54101975ad.5.1727014438812;
        Sun, 22 Sep 2024 07:13:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dad0:b0:207:6ea:6f60 with SMTP id
 d9443c01a7336-208cb90c196ls989565ad.0.-pod-prod-04-us; Sun, 22 Sep 2024
 07:13:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjWuWyK0QU/XnBbXFL7DxHBVujGkCxr5A6bDjgk3FgVLx/bF58qtCknrUbaZxdGYNNFX/ladiUXvc=@googlegroups.com
X-Received: by 2002:a17:903:11d1:b0:205:88bf:bfe9 with SMTP id d9443c01a7336-208d836cfd9mr100398495ad.15.1727014437279;
        Sun, 22 Sep 2024 07:13:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727014437; cv=none;
        d=google.com; s=arc-20240605;
        b=d4SytG7zuOtCX8uCGF0Q49xqE2nXtSnVdFWJIJxyy7C6cb8oMIcvr/PGx6+NUFDnQw
         LbMVHB+QSbqXlwZAB1B/YZBHLZIqEqkaWxE5WhNyP7vrdnO9s2A6LNuT9ffKyA4zie59
         lnKS+OHNDCmNKQOt8nCKuXRpa6H46ynkIklPBETwFuhLtMMXulSWKa+2LwfZLuPUP+zT
         aBkK++6JncTRctyJn2selZC1EYnDW56xSvVeY1n7s9IIsPMZ9Lr8oNOAhD/FZ0xscTGH
         MhHBW5MdRRfehyuTjBFCmQThv1LmN4CuDLxt+v1qzptL0HsyojawOilcyD3Ta9tsCAO8
         UdKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=H60osoPEQIRFYd/ZJmgRWiIyxJNfdxxhbTW+sQ2BYKg=;
        fh=Ll25HXNtmOEiYrJW3MpNPKiek30/5o23JcaFO4EWF4M=;
        b=an0b61nIpO4gJLfU2E8T7MERDPVDh5k7nvjP5zxkO0x8V6YtYxZnyhFIYpSbrBzvbW
         7SM2UipRf1WBm+H5y88O5lG20nv1FtyaxR2iECDQZv97WWuSa3hu1+tah59bfjwc58Ai
         X0oP/ExlQlVOUUVMQdqSrrZb8eByhwp5PNcE0juy6qMHfpZMQ86AHEBK0ah5p+eTBDEg
         PDtFzrfFhewmrvduwQqwPqDmQWkX39FGfy9sHYPtGG7nMSKBTDXS04uXz2yW6Ltjsk+q
         krmA9JrC4DySgne3LbeIdwkydIz5ersMPwN5XOFQXwfGNGN86j94q6dlK40aotBUnYM/
         eKAw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WpIMdyKt;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20794633456si6739745ad.7.2024.09.22.07.13.57
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Sep 2024 07:13:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-2068acc8a4fso32189675ad.1;
        Sun, 22 Sep 2024 07:13:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWzsBn4+vdWZx2YrG2q0L9VhnvYHooL7gOCjDoySdpCyeQnUQhjP2xkN4GI9vYqVywNPqf6EKywmn8=@googlegroups.com
X-Received: by 2002:a17:902:d546:b0:206:8f25:a3e with SMTP id d9443c01a7336-208d841ff88mr130901425ad.53.1727014436696;
        Sun, 22 Sep 2024 07:13:56 -0700 (PDT)
Received: from ?IPV6:2600:1700:e321:62f0:329c:23ff:fee3:9d7c? ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2079473083fsm120417355ad.258.2024.09.22.07.13.53
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Sep 2024 07:13:55 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Message-ID: <fcaaf6b9-f284-4983-a8e3-e282dd95fc16@roeck-us.net>
Date: Sun, 22 Sep 2024 07:13:53 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and
 test_leak_destroy()
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Vlastimil Babka <vbabka@suse.cz>
Cc: KUnit Development <kunit-dev@googlegroups.com>,
 Brendan Higgins <brendanhiggins@google.com>, David Gow
 <davidgow@google.com>, "Paul E. McKenney" <paulmck@kernel.org>,
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
 Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
 <6fcb1252-7990-4f0d-8027-5e83f0fb9409@roeck-us.net>
 <07d5a214-a6c2-4444-8122-0a7b1cdd711f@suse.cz>
 <73f9e6d7-f5c0-4cdc-a9c4-dde3e2fb057c@roeck-us.net>
 <474b0519-b354-4370-84ac-411fd3d6d14b@suse.cz>
 <CAB=+i9SQHqVrfUbuSgsKbD07k37MUsPcU7NMSYgwXhLL+UhF2w@mail.gmail.com>
Content-Language: en-US
From: Guenter Roeck <linux@roeck-us.net>
Autocrypt: addr=linux@roeck-us.net; keydata=
 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
 mDW4+i+XlNFUPUYMrIKi9joBhu18ssf5i5Q=
In-Reply-To: <CAB=+i9SQHqVrfUbuSgsKbD07k37MUsPcU7NMSYgwXhLL+UhF2w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WpIMdyKt;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62d as
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

On 9/21/24 23:16, Hyeonggon Yoo wrote:
> On Sun, Sep 22, 2024 at 6:25=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> On 9/21/24 23:08, Guenter Roeck wrote:
>>> On 9/21/24 13:40, Vlastimil Babka wrote:
>>>> +CC kunit folks
>>>>
>>>> On 9/20/24 15:35, Guenter Roeck wrote:
>>>>> Hi,
>>>>
>>>> Hi,
>>>>
>>>>> On Wed, Aug 07, 2024 at 12:31:20PM +0200, Vlastimil Babka wrote:
>>>>>> Add a test that will create cache, allocate one object, kfree_rcu() =
it
>>>>>> and attempt to destroy it. As long as the usage of kvfree_rcu_barrie=
r()
>>>>>> in kmem_cache_destroy() works correctly, there should be no warnings=
 in
>>>>>> dmesg and the test should pass.
>>>>>>
>>>>>> Additionally add a test_leak_destroy() test that leaks an object on
>>>>>> purpose and verifies that kmem_cache_destroy() catches it.
>>>>>>
>>>>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>>>>>
>>>>> This test case, when run, triggers a warning traceback.
>>>>>
>>>>> kmem_cache_destroy TestSlub_kfree_rcu: Slab cache still has objects w=
hen called from test_leak_destroy+0x70/0x11c
>>>>> WARNING: CPU: 0 PID: 715 at mm/slab_common.c:511 kmem_cache_destroy+0=
x1dc/0x1e4
>>>>
>>>> Yes that should be suppressed like the other slub_kunit tests do. I ha=
ve
>>>> assumed it's not that urgent because for example the KASAN kunit tests=
 all
>>>> produce tons of warnings and thus assumed it's in some way acceptable =
for
>>>> kunit tests to do.
>>>>
>>>
>>> I have all tests which generate warning backtraces disabled. Trying to =
identify
>>> which warnings are noise and which warnings are on purpose doesn't scal=
e,
>>> so it is all or nothing for me. I tried earlier to introduce a patch se=
ries
>>> which would enable selective backtrace suppression, but that died the d=
eath
>>> of architecture maintainers not caring and people demanding it to be pe=
rfect
>>> (meaning it only addressed WARNING: backtraces and not BUG: backtraces,
>>> and apparently that wasn't good enough).
>>
>> Ah, didn't know, too bad.
>>
>>> If the backtrace is intentional (and I think you are saying that it is)=
,
>>> I'll simply disable the test. That may be a bit counter-productive, but
>>> there is really no alternative for me.
>>
>> It's intentional in the sense that the test intentionally triggers a
>> condition that normally produces a warning. Many if the slub kunit test =
do
>> that, but are able to suppress printing the warning when it happens in t=
he
>> kunit context. I forgot to do that for the new test initially as the war=
ning
>> there happens from a different path that those that already have the kun=
it
>> suppression, but we'll implement that suppression there too ASAP.
>=20
> We might also need to address the concern of the commit
> 7302e91f39a ("mm/slab_common: use WARN() if cache still has objects on
> destroy"),
> the concern that some users prefer WARN() over pr_err() to catch
> errors on testing systems
> which relies on WARN() format, and to respect panic_on_warn.
>=20
> So we might need to call WARN() instead of pr_err() if there are errors i=
n
> slub error handling code in general, except when running kunit tests?
>=20

If people _want_ to see WARNING backtraces generated on purpose, so be it.
For me it means that _real_ WARNING backtraces disappear in the noise.
Manually maintaining a list of expected warning backtraces is too maintenan=
ce
expensive for me, so I simply disable all kunit tests which generate
backtraces on purpose. That is just me, though. Other testbeds may have
more resources available and may be perfectly happy with the associated
maintenance cost.

In this specific case, I now have disabled slub kunit tests, and, as
mentioned before, from my perspective there is no need to change the
code just to accommodate my needs. I'll do the same with all other new
unit tests which generate backtraces in the future, without bothering
anyone.

Sorry for the noise.

Thanks,
Guenter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fcaaf6b9-f284-4983-a8e3-e282dd95fc16%40roeck-us.net.
