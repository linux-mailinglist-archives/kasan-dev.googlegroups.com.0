Return-Path: <kasan-dev+bncBCS37NMQ3YHBBCUDUX7AKGQERMV2KGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D6A72CDF2C
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 20:50:36 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 74sf789705lfg.20
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 11:50:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607025035; cv=pass;
        d=google.com; s=arc-20160816;
        b=XtHUU02UvO3LoedcGX1hKi2+O2ndUaKSZfDkTlWFNOeGLCuVFYNiODvrodxo94/iYC
         8SVFJgtvZE5VQHBTW23S9QIkMuFwd+h+XXnxZRHDqlpKTZY7hBifE0uQOzLS0TppebWl
         xqjbl1BoB2QUVjUNsFiOy8HZMmO/x2ToXIj//m1ze9pPl/Si/fUHAVEl588nyO8oCJaQ
         f246atO98B3/rlV99ZutkcU6ZMxt7Y4rOB7rrHsEz/WtpQowGhJP2c8Umj86oMpyNc/0
         ALLsgPOIkMYwPgUcbaosULcgHiSixTbYedZMG2NjkNS76Jb/Vl/oGCAdvQOo4NvrTzut
         O/Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:reply-to:sender:dkim-signature;
        bh=5XUz+Pa++kQy5bLwOuWzsYtffTeW+MKWf0GkSZ5fn4k=;
        b=GmhDlHe0764ACQiU2v5CM4d01eXFe4lDdp0wdNyhFq+531vw0xrCvABQ/4xOeW8XSm
         GGg0NJlcpLC5bVgtbVvNuT1QbA4KH+fGLt+KSaU/fxkqSrIwmb0iP+gwrCNrum++dAX/
         Si5dT4nJHjCnoqgzz8JHJtOpHK1cvuf5zqKVR5cGxz4ICL2VmCdGVj8M3qDJmxRB3rb+
         loS+NCJ95qT+SZsyuBfdBCv5NdQtENLwPgtLvthjK2MUXHhzOESTPpR4pVE9XmwQ3agx
         Nw3dAKOWlui5edu0Wmv/76HvDoZ2VCQigwzM/IH90Jt3awsRjT/S/+V3+xePVLcs7RnG
         I96w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:reply-to:subject:to:cc:references:from:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5XUz+Pa++kQy5bLwOuWzsYtffTeW+MKWf0GkSZ5fn4k=;
        b=TrZeP/tw0o2n3UmZEa+vXh29SVXS452E8pN51gHaNBJUkT5QvG6nd9Rdx3lZwnyTn6
         2ZcHp8tptjnYHojUr5FDE1OrE3JnlBmeVmc7uTtWPL6c3QhHWmEL83NAaOi16GAt//S0
         7UOjPJ6yWsUzssXMcp32CqjYzsvjUUWts8JF5F0YcCAeu6bHra40/PrFD+IVrUJizcV/
         14e6TTEcjtQggJxtlWeiDraKuxF2F2guerDJCb6jOek2nnqle448H1n+qQpu6qkI3Z+b
         soXuADvzVcfW7shMNdel1w2LY1YjdGfs4v06mL5VKypubfWn7WRGfxwQoHe9zzx7bNE2
         lfqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:reply-to:subject:to:cc:references:from
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5XUz+Pa++kQy5bLwOuWzsYtffTeW+MKWf0GkSZ5fn4k=;
        b=eB9zjdpabGagxn+2UGZXwJ56b7Iz4eL+y00gBT49Pmoa1o2HsP8fzPaobGSgN/J96T
         Lo8L/53odYj3syM6AorBsDuKvy0jnFfRi7utyb2RPPMlfFgO6az4e6y3J7TrAE7MFF69
         1Mb8L7rVDtD68z+e27Mg828USD7WtLU2gF0LDT5l9qobRYyx4mXyVjZdczUb1SdFyiGT
         WJbBjMY25gRB+nrGsZgNNzZoqQdLb1pmgllKvFKNaEQfJw9UdVhdL/ptg44KumDjxFQF
         QoYo/Bfi4wgFa8nHJ6IRFHgbZss5u+EVQB51F+1poYvisBsKX3tv7trTFUUKHDUFRvJu
         fPHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531SYz7qr7Z992IVfVJ5gCFhuJ1y8MAg4IQUfHyUV6f9Sy8/rQt1
	dQ72ic9twvguiekdd1tpIMw=
X-Google-Smtp-Source: ABdhPJzdHMEEKyoo2KTMPsvlOkujeU5APFKM+xu3PMrnsbjiYHmfqyHkys1xuahKhqv4lO8R31XBjg==
X-Received: by 2002:ac2:5e34:: with SMTP id o20mr1857258lfg.337.1607025034283;
        Thu, 03 Dec 2020 11:50:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9059:: with SMTP id n25ls1202164ljg.3.gmail; Thu, 03 Dec
 2020 11:50:33 -0800 (PST)
X-Received: by 2002:a05:651c:10d4:: with SMTP id l20mr1736029ljn.389.1607025033086;
        Thu, 03 Dec 2020 11:50:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607025033; cv=none;
        d=google.com; s=arc-20160816;
        b=mzI8P+JF1BTx6pwMBv7ohtjIOjONyu3B8aqbCfuBLIPkoJpTXvN+WiDrx6MBuTFoKa
         67ctou5ihKWwE19qoe4lxK9xOTP9+63rWqmNLEokHYqufPhGBox+BCieAlbsDrhd/K3a
         KtfcxzIuAlaRGeC/VCou7cFfDfcf8+bc96qZ2SLvleDUdgFMqdAOuHVoSP4bR655qf2g
         4az5tXiJeBKouo1RdtnkvZTU2mVKQFNbTOI4asaFcgJ+siBrbaobX2Ygeahvnqx9xu0C
         dd9yYlM0jEQ6WUAIeORdmKKXmXUa9BjRH5owz8XmqYIwi0TG2MgAC8fkEP1m9UJnJiBK
         FUbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject:reply-to;
        bh=X2sJjf4rgVoTYeRjWgx/Ub3m34veUfOcx8dQYIctFxw=;
        b=fMgT7IGw9OBOvKJx4257AD+9Qn/AcRfdQE/7QhnFv+4L1f3OgN1cXqaCCj9qx+/kEs
         M3TFpREnthUasBWrClgo6JwgjfsfdQByqXhFodfPiErRWKag5t4hZLGzvg3lABSQanpC
         LvXt9K2cqU23pQx6ejlpdY/TnK4UsZZiEboUFqNipvMTmbUdAdPwY7W3yPFHnSWfgHWA
         Cq2elqJ1YJe1dXniu/MXmVzHOqdO495439SBJ2sk4rTQQDhADIA3rMTyWzXMvrR2oxV1
         PSXuB+alIgFeI3TfUSNJ6gWIzmdjL09YrnuLbl1elKksXTK/s6ou3rlobD6+qz8gf6jA
         34VA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wr1-f67.google.com (mail-wr1-f67.google.com. [209.85.221.67])
        by gmr-mx.google.com with ESMTPS id 206si59165lff.4.2020.12.03.11.50.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Dec 2020 11:50:33 -0800 (PST)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as permitted sender) client-ip=209.85.221.67;
Received: by mail-wr1-f67.google.com with SMTP id z7so3120687wrn.3
        for <kasan-dev@googlegroups.com>; Thu, 03 Dec 2020 11:50:33 -0800 (PST)
X-Received: by 2002:adf:a495:: with SMTP id g21mr873975wrb.213.1607025032556;
        Thu, 03 Dec 2020 11:50:32 -0800 (PST)
Received: from [10.9.0.26] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id 20sm439140wmk.16.2020.12.03.11.50.29
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Dec 2020 11:50:31 -0800 (PST)
Reply-To: alex.popov@linux.com
Subject: Re: [PATCH RFC v2 2/6] mm/slab: Perform init_on_free earlier
To: Alexander Potapenko <glider@google.com>
Cc: Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>,
 Will Deacon <will@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
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
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Kernel Hardening <kernel-hardening@lists.openwall.com>,
 LKML <linux-kernel@vger.kernel.org>, notify@kernel.org
References: <20200929183513.380760-1-alex.popov@linux.com>
 <20200929183513.380760-3-alex.popov@linux.com>
 <CAG_fn=WY9OFKuy6utMHOgyr+1DYNsuzVruGCGHMDnEnaLY6s9g@mail.gmail.com>
From: Alexander Popov <alex.popov@linux.com>
Message-ID: <1772bc7d-e87f-0f62-52a8-e9d9ac99f5e3@linux.com>
Date: Thu, 3 Dec 2020 22:50:27 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.3.1
MIME-Version: 1.0
In-Reply-To: <CAG_fn=WY9OFKuy6utMHOgyr+1DYNsuzVruGCGHMDnEnaLY6s9g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as
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

On 30.09.2020 15:50, Alexander Potapenko wrote:
> On Tue, Sep 29, 2020 at 8:35 PM Alexander Popov <alex.popov@linux.com> wrote:
>>
>> Currently in CONFIG_SLAB init_on_free happens too late, and heap
>> objects go to the heap quarantine being dirty. Lets move memory
>> clearing before calling kasan_slab_free() to fix that.
>>
>> Signed-off-by: Alexander Popov <alex.popov@linux.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>

Hello!

Can this particular patch be considered for the mainline kernel?


Note: I summarized the results of the experiment with the Linux kernel heap
quarantine in a short article, for future reference:
https://a13xp0p0v.github.io/2020/11/30/slab-quarantine.html

Best regards,
Alexander

>> ---
>>  mm/slab.c | 5 +++--
>>  1 file changed, 3 insertions(+), 2 deletions(-)
>>
>> diff --git a/mm/slab.c b/mm/slab.c
>> index 3160dff6fd76..5140203c5b76 100644
>> --- a/mm/slab.c
>> +++ b/mm/slab.c
>> @@ -3414,6 +3414,9 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
>>  static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
>>                                          unsigned long caller)
>>  {
>> +       if (unlikely(slab_want_init_on_free(cachep)))
>> +               memset(objp, 0, cachep->object_size);
>> +
>>         /* Put the object into the quarantine, don't touch it for now. */
>>         if (kasan_slab_free(cachep, objp, _RET_IP_))
>>                 return;
>> @@ -3432,8 +3435,6 @@ void ___cache_free(struct kmem_cache *cachep, void *objp,
>>         struct array_cache *ac = cpu_cache_get(cachep);
>>
>>         check_irq_off();
>> -       if (unlikely(slab_want_init_on_free(cachep)))
>> -               memset(objp, 0, cachep->object_size);
>>         kmemleak_free_recursive(objp, cachep->flags);
>>         objp = cache_free_debugcheck(cachep, objp, caller);
>>         memcg_slab_free_hook(cachep, virt_to_head_page(objp), objp);
>> --
>> 2.26.2
>>
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1772bc7d-e87f-0f62-52a8-e9d9ac99f5e3%40linux.com.
