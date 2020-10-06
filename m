Return-Path: <kasan-dev+bncBCS37NMQ3YHBBR4J6P5QKGQEWFULJUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id B00AB285260
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Oct 2020 21:26:00 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id r17sf2945568lji.7
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Oct 2020 12:26:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602012360; cv=pass;
        d=google.com; s=arc-20160816;
        b=gZgyKZWywku0Ne+I+86SrBfRqxZwDqiq6tpXPOp9aPznBt9XhlpgoV/zIWybYQDy54
         4jTt9WzPIJSsV1jE/PLjdSb+aDRMU2SpPpjwZhF7P7p6qHmDrlgpGsJq6bOYcIk+FOXs
         PiBwk6o+WU4uibyn1a8wZrSVaHKG7S8XO2BLKcpk/B3P67Y/4b7YTSKMdCHcZlfRlhCQ
         clhReQNqLaMnLLabCXD4tXIz25KBfx2qe3+Qu/C5s8ec5TcLRVbI9IJVvfUxVFPwBiOo
         OxAJIdVASPWKsOJDTsW91yHbdf4Kxv7GEfQ+AjQwNAINFgkbGmO5LRPcNnGJke9oToAf
         rqmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:reply-to:sender:dkim-signature;
        bh=VgjoCAfqMEI7ce73du4EAhQW59A7b6GGgc25lt4wxGs=;
        b=Bs/FMq0rsi3h+rH7GJGOIkawL9k0sueDjeAeNvKSiW/RTQufF4axiC9H31RdXV/Jn0
         T9eX1MtKONfc4BWYOn4z9yWt5DsEEtNAGs2QW3jRXcguosACKkQ0aUs4p1tOm7bXJ9qr
         NmLdN2PEeuExU6h+z4JCmFy4vmkV5LuLtgZbDRzAUybaIQgL/yg7L+7wsEyRMv35SiY2
         olSQlii4aisRDNilKmr5HAcRHEXGndhPznJSGkWwCy020Kn7yo8lxTVYLqJEpJAaHKpE
         TAQV1ZpSGvY0MYmLj2aJPSgegnCBeUdWHgwlfuIzFR11XmPB94J0CUWAR2OnNOH42A/v
         lohA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:reply-to:subject:to:cc:references:from:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VgjoCAfqMEI7ce73du4EAhQW59A7b6GGgc25lt4wxGs=;
        b=SXCVRO8WdXpoH9XmyceXqGyIrl4g0QLI9GUBTWeHE644UPBL/C9qeB2i5YyZ4pB34T
         ExtMkz94b/Yyd+fR3ErykMzEztdkhd9QrQHjCY7MWhWj5j+Cdiis/g8cCv/SpkeMrLJf
         kl71tzSztqyUbqGW/JObzzxwCQOx9k+NV240ojxYfP9vYP9Zzbyyq9eJwXHX8SFeWDvF
         /zc7YbwXxJaEXigVlE5muS6XRB1KAjiUH8mtXMUS9W/4BM0WkNF7ukAEKiT3DvMcQ0/a
         BMCP9ZXumzNmdV0WuHudDfl+0CA8wpm/cQQGsJT05pwacdJGxDssOQDN/oLmJfuiugc2
         PTMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:reply-to:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VgjoCAfqMEI7ce73du4EAhQW59A7b6GGgc25lt4wxGs=;
        b=MPw+RHAIyJs4/GsoN6+GLCjThmBg6/I0rZo3tdUtysuvl89xTt4ICco9wD1HJDHVy+
         Uv1laDcc1xYkWhF89k68nbYjQ1s8ZHm3mpTtJWVtgdCBjPnHuY2PuyqoSG2yQX2mREw9
         jR62UQR5ylROKC85V9+rF+ACPGKV4bCSWugELbfku8dQ6ewO5d0xrvZZl3uMS5nIwObM
         5rNGWyb2gC+sZzVF1V+9PYBw7xQO3QrNGnf6wW5YOGaNUm6jGn0X8xPGefiNQ2viKWhj
         skhXODlY7aCnP6l7bCBU+kuE1mLZABNldeiSbzR3ZqQQ6nF0dfltnpKk2X0CehMOlKBw
         xMww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5315pb6hpqec7CCjKwl7h23dgAp7NJBLZHWKE9hszfY6ha1PEEDr
	7iL/zXHU4jU89R+TWtAm72A=
X-Google-Smtp-Source: ABdhPJxhL30uFQsOH3oMpyibt4tGnvMUQTu2PbuG0NV5UIDwZrxZ0FpKFPiB25aDota5ndeS1pM/fg==
X-Received: by 2002:a2e:97cd:: with SMTP id m13mr2575837ljj.221.1602012360155;
        Tue, 06 Oct 2020 12:26:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ad43:: with SMTP id s3ls1183264lfd.2.gmail; Tue, 06 Oct
 2020 12:25:59 -0700 (PDT)
X-Received: by 2002:a05:6512:512:: with SMTP id o18mr1116766lfb.328.1602012359029;
        Tue, 06 Oct 2020 12:25:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602012359; cv=none;
        d=google.com; s=arc-20160816;
        b=nsHCeEHzXXI3hBQRNCKf2DVBMO9Q+J+M1w4ZVhX+MYP33hfEkZ94D2eU8kn668Hejj
         Q8MwGuKDzEiKBBj24M8tSmkncdRX9b/xkpew/79+9ShI8hoyRkTYsY0kGVTki4OG45Xp
         KR1t2il7mVIxnzWN7Ka5hQU/79bA0VUqOdQf3Kwm6S2OwNYbTLhOHiHYFS+BzVmD6aWc
         WGgKcpCb7ZCZCFiDWrnWvr+OuPMEhtcEeb5a3QAubuIhQh5HaSL2HpCUM8irmDgdjZqV
         iGoPy631nUcPtTrfyhi5WyCu+9eUxGVDuWx0yqYatjd6ioEzLrWwiXguK76S4NhpWzzU
         UNQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :reply-to;
        bh=wQQPlPmGgdUdZBsNOY2PgtEUxgnwRbZTYG95QR6U6Rc=;
        b=D97n4Nip4Saium4MNX0/xoLfLt8gakvzKLTlCe1N+25zsa982GRfjtXUfLy18em048
         YqqBwWBn+5AmgzXvkKLv7Vi0CIDWshtkGozkk+TSiabwvI7ve2rHgnqIpfKCMwovazbA
         OXwl9ufH22HmepshaSaK35sUJx3AsViWNpcVBUT5jIwurO01Ld/HrmNBRYuZuE463M7f
         l8AGElp6UcocgpNMip5bTZB7tA8fCkWgR9gteV59zcTNRq3IrKtZANAqi0uNAr0YTmzZ
         dStUDlo5sRxR7GR2DJKxjt/fR9IalSOrh0CcJJhkgeVMfXXlT1k0HkAqeHG+SfE9Y9Gv
         G/Vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wm1-f67.google.com (mail-wm1-f67.google.com. [209.85.128.67])
        by gmr-mx.google.com with ESMTPS id j75si158497lfj.5.2020.10.06.12.25.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Oct 2020 12:25:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.67 as permitted sender) client-ip=209.85.128.67;
Received: by mail-wm1-f67.google.com with SMTP id p15so4046583wmi.4
        for <kasan-dev@googlegroups.com>; Tue, 06 Oct 2020 12:25:58 -0700 (PDT)
X-Received: by 2002:a1c:b388:: with SMTP id c130mr6364936wmf.175.1602012358471;
        Tue, 06 Oct 2020 12:25:58 -0700 (PDT)
Received: from [10.9.0.26] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id f14sm5610132wme.22.2020.10.06.12.25.50
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Oct 2020 12:25:57 -0700 (PDT)
Reply-To: alex.popov@linux.com
Subject: Re: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting
 use-after-free
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>, Will Deacon <will@kernel.org>,
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
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Daniel Micay <danielmicay@gmail.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Matthew Wilcox <willy@infradead.org>, Pavel Machek <pavel@denx.de>,
 Valentin Schneider <valentin.schneider@arm.com>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
 Kernel Hardening <kernel-hardening@lists.openwall.com>,
 kernel list <linux-kernel@vger.kernel.org>, notify@kernel.org
References: <20200929183513.380760-1-alex.popov@linux.com>
 <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com>
 <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com>
 <1b5cf312-f7bb-87ce-6658-5ca741c2e790@linux.com>
 <CAG48ez17s4NyH6r_Xjsx+Of7hsu6Nwp3Kwi+NjgP=3CY4_DHTA@mail.gmail.com>
From: Alexander Popov <alex.popov@linux.com>
Autocrypt: addr=alex.popov@linux.com; prefer-encrypt=mutual; keydata=
 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
 j3lCqPk=
Message-ID: <ace0028d-99c6-cc70-accf-002e70f8523b@linux.com>
Date: Tue, 6 Oct 2020 22:25:48 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.11.0
MIME-Version: 1.0
In-Reply-To: <CAG48ez17s4NyH6r_Xjsx+Of7hsu6Nwp3Kwi+NjgP=3CY4_DHTA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.67 as
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

On 06.10.2020 21:37, Jann Horn wrote:
> On Tue, Oct 6, 2020 at 7:56 PM Alexander Popov <alex.popov@linux.com> wrote:
>>
>> On 06.10.2020 01:56, Jann Horn wrote:
>>> On Thu, Oct 1, 2020 at 9:43 PM Alexander Popov <alex.popov@linux.com> wrote:
>>>> On 29.09.2020 21:35, Alexander Popov wrote:
>>>>> This is the second version of the heap quarantine prototype for the Linux
>>>>> kernel. I performed a deeper evaluation of its security properties and
>>>>> developed new features like quarantine randomization and integration with
>>>>> init_on_free. That is fun! See below for more details.
>>>>>
>>>>>
>>>>> Rationale
>>>>> =========
>>>>>
>>>>> Use-after-free vulnerabilities in the Linux kernel are very popular for
>>>>> exploitation. There are many examples, some of them:
>>>>>  https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html
>>
>> Hello Jann, thanks for your reply.
>>
>>> I don't think your proposed mitigation would work with much
>>> reliability against this bug; the attacker has full control over the
>>> timing of the original use and the following use, so an attacker
>>> should be able to trigger the kmem_cache_free(), then spam enough new
>>> VMAs and delete them to flush out the quarantine, and then do heap
>>> spraying as normal, or something like that.
>>
>> The randomized quarantine will release the vulnerable object at an unpredictable
>> moment (patch 4/6).
>>
>> So I think the control over the time of the use-after-free access doesn't help
>> attackers, if they don't have an "infinite spray" -- unlimited ability to store
>> controlled data in the kernelspace objects of the needed size without freeing them.
>>
>> "Unlimited", because the quarantine size is 1/32 of whole memory.
>> "Without freeing", because freed objects are erased by init_on_free before going
>> to randomized heap quarantine (patch 3/6).
>>
>> Would you agree?
> 
> But you have a single quarantine (per CPU) for all objects, right? So
> for a UAF on slab A, the attacker can just spam allocations and
> deallocations on slab B to almost deterministically flush everything
> in slab A back to the SLUB freelists?

Aaaahh! Nice shot Jann, I see.

Another slab cache can be used to flush the randomized quarantine, so eventually
the vulnerable object returns into the allocator freelist in its cache, and
original heap spraying can be used again.

For now I think the idea of a global quarantine for all slab objects is dead.

Thank you.

Best regards,
Alexander

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ace0028d-99c6-cc70-accf-002e70f8523b%40linux.com.
