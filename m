Return-Path: <kasan-dev+bncBDW2JDUY5AORBMWHTWIQMGQEAYZSNEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id AFE1B4D1A0E
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Mar 2022 15:09:55 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id y18-20020a927d12000000b002c2e830dc22sf12480877ilc.20
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 06:09:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646748594; cv=pass;
        d=google.com; s=arc-20160816;
        b=wxC0X5ttgMdBQmQxB+m7grJJJ09yjLdeSi/tF5QTMkqkKtHPzjsu/whTaRqcymWfLn
         tNoaMl23eRgtt/rzp88ywfyplWfN/k9/bib8QgUgA+sbQMO/YhtThWJZERCcb5uMRS4b
         c6YpGD2pL/llzPA1jbceo4BEj5w0djILB7j40KxeWM4hcBQEM2g/W0aXSkhzLGXIliov
         mCHNrichC9//gnjX3eaooQ+S9mjAh56Mm67JqflUzKxWsQNFxBvexs3sBYHz1cfuK0K0
         MgWIhW8sVobvV/o0VPzv/srQMETa3p2J9BV44urzrtsHwxCwx4To+Yb4SpYDwoeqiWTL
         jrBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=LuQkeiUPxzhtgMnlz4ZRZZf039+QID2hk2/ICNWXb0w=;
        b=yDBFvdSfImfHEZb9bjFXMTw2yviL2s2uniAQln5wWc9CBYo15R8InwQnW8g6xIOA5s
         bAO4YQNT3PLRpSHw1cw/GxJ76DS5E18h9s8NNVn7WBW6ijMnlDT8R8iiZ6SOHzzn5xWv
         hC32NnqkB0XpzgZfhEvxmnF20zXzoSHCp4OwF8kw2B7+LNwlyjvw858f0rzbKv2xUyyx
         vRIDVTtEYP5cNru1el0gBkICnbzn6nJzU/gakgYQdFyTwTDcaE6EF16dOJ0QlT1lkBdc
         kJM9CY71Xz2gi7+n3A+UL7a3Bnbto5QmqtJNKg/urjfj5lX7vHAUYDHieNG3nV2ISFEc
         WzCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=HvQ65t8f;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LuQkeiUPxzhtgMnlz4ZRZZf039+QID2hk2/ICNWXb0w=;
        b=RtPzAjfT3ijQnUSfSVL1eTl+VY56Z5IfwRdf9sybvwKLtjHKGoISTRr4w5sxrpTmRD
         IsjWkR4DMNy7EMHP2kASiAnUrs03nghaZgmAROAjjcIebm/0yzpGEDzmDme27EPW9nsq
         w0W2PyZzeTQCo76zbNhAQc+xqFVopQgco1elcjisdR+FQxqe3obaJE5g9EZ6Mp+qKUFW
         0ihw0izxFVh4QgGK0fZbktCuSb0dWn3kYeKqLtgp7unV7NozDNqxoCsLeMjfm7mp65gR
         sY9oUJ802tukdhhqBkW7ULtdcf1ZESs62qWEBYUpaW0asAVRTqRxiwGh1BxZ/uFbgDJE
         xpQQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LuQkeiUPxzhtgMnlz4ZRZZf039+QID2hk2/ICNWXb0w=;
        b=lnax/wHWuNpL2tLodauQlyYaeKgIDqacq/w2v3cj8KZT4NETEmpICk8DPgslF14isS
         U9issOdLXDrn0V+VaNBB7xhfx5EXXnuDXRKGLfbH5wYRzIG7wywFwmayxiXfyY4dz5aR
         6WStcKrSKKC3+Opt0ep5MMp2iSJWU49AivDNojdL1VbYQdfMLibewxqOpR34O1lCszwt
         jTyveHO8wuonoXv6JeOXuhFJqo/P3ZMou7wI5orllqjdP6VBhUKiiXb50cPxiGPNLG2T
         1SmVDSWNteq+rNOzt7Yod21trJSELH4vHaF5GlFZtlSm//LO/d9YhNCmMDwgW0Slqf1j
         ikMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LuQkeiUPxzhtgMnlz4ZRZZf039+QID2hk2/ICNWXb0w=;
        b=Favk0NwHOIicpBo/B5A+Xkd5Bc8vjN+ss4UL0sChLDolk4TkJBw/+5drsgEVajUVgt
         utiP6EmQz7btmQzHIGWNkuGZAQKUTjtIoAIUHipGLU/zJwPEVO5u1/I3PHglsFiB4n21
         GiT4YQJs/923TKEY7HdCrnhVdccerGZfmdVZEbBY/zIz9Q9cvUyc/Mf4zcj/ooIc44nW
         c6fes6lY0hwM4Ger0ieR4Ew/MGryhFA8HD8V13rTNsHmNbcpgIOt5em+q9E9LF8VJ8fV
         30psAeV/Mo3Z/KKxFfnR4fsBwBUGEEMG4ml4AItYGtP/rtI0JMFwdCt4UwmH15CGv4+c
         LRyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531e1XDZdV1GkilrYpeunTt0+NUJyQxjBBVpVqiiXCbzKnjgQQcw
	YlEPhdxYPqe6neC7muJxE8Y=
X-Google-Smtp-Source: ABdhPJxwG5i9EnJDOusx2HgSpvnYqS8Ag+9oi8u/zaUJ/3tZzL9SsjgDvXOBX6kyR5dJIhqvzl8HkA==
X-Received: by 2002:a6b:4911:0:b0:646:3a67:397 with SMTP id u17-20020a6b4911000000b006463a670397mr85256iob.73.1646748594728;
        Tue, 08 Mar 2022 06:09:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2406:b0:317:ae78:9ea8 with SMTP id
 z6-20020a056638240600b00317ae789ea8ls1351478jat.1.gmail; Tue, 08 Mar 2022
 06:09:54 -0800 (PST)
X-Received: by 2002:a05:6638:1c10:b0:317:affa:2f32 with SMTP id ca16-20020a0566381c1000b00317affa2f32mr11863813jab.288.1646748594068;
        Tue, 08 Mar 2022 06:09:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646748594; cv=none;
        d=google.com; s=arc-20160816;
        b=L3s082OXETXmAe/cksHnigtLvfkYSQGZyJHIqU0nMN35ipN3cVm3nsLkubbm/RhECo
         sZWodVFFIUKpd/tHUili4gIXi0TVhMkSiftsL89/XOsFt3sHSESMWEZzQBnuearREoaR
         BK5bfmyFoxdXpGpoS+DOsy5HfVctK7RKLweHfzWgcaw2hFB+Wd+nZAekIyx6xJtoR+KC
         9bHM4s33kWM5MHqeHg1YP2EIdxLEB/oVvMshHWy5OTxXJEOxSheGRAy2GyrAOh3Mh/9u
         Ln4+pAvkH6zsBW7X0EohiMXyQTzMZvROatjy5+WGrUUUJvV8cTxK7kIaMcwdo97CTnoZ
         IYgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EbG/qqfr/wurjd2//LUTHT4MZ/YTGKmKEm4o3JLwT/s=;
        b=ezsNWX1/0QDeWuuF+28AGFa9pad383zKi3RtbXAgn5B7GYEPTI6E8ypIwbsjCCuP8A
         Hq6YxU9ZLvCBaqYyH7sg8xpeR2+5eXhlc8Bi5OvtTk3dm0sB74wi7Cf8mfyj9LtynEag
         nqG7RpPfyqRvzEyMxezmCH3rc2GcZS3e40In0MRTU70GlgNqwHsYjABLa/+3q6Lh80Ee
         rYRJrBuhOKhM/echg2e9VBDCHzZjO/lwuymMTQ0plyft34uHf4+36If2BHqxGq24lf8A
         qteYKZKWj65Ky+qk61lW4Dk/a8rl1Ie8aqaBh+I5FFbBKU/peeS6oinjBzFWsm+15Ug3
         53aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=HvQ65t8f;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id g6-20020a02cd06000000b003145c195b7dsi1282691jaq.0.2022.03.08.06.09.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Mar 2022 06:09:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id d62so20948764iog.13
        for <kasan-dev@googlegroups.com>; Tue, 08 Mar 2022 06:09:54 -0800 (PST)
X-Received: by 2002:a05:6638:d85:b0:317:d2f5:8f1d with SMTP id
 l5-20020a0566380d8500b00317d2f58f1dmr4997851jaj.117.1646748593868; Tue, 08
 Mar 2022 06:09:53 -0800 (PST)
MIME-Version: 1.0
References: <cover.1646237226.git.andreyknvl@google.com> <029aaa87ceadde0702f3312a34697c9139c9fb53.1646237226.git.andreyknvl@google.com>
 <CAG_fn=WE80ueUTC3EYjGNGJc8FvAG8Ph-La9cxBXGRBX17d-6w@mail.gmail.com>
In-Reply-To: <CAG_fn=WE80ueUTC3EYjGNGJc8FvAG8Ph-La9cxBXGRBX17d-6w@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 8 Mar 2022 15:09:43 +0100
Message-ID: <CA+fCnZd-0jE22cocyL8XPC4oEuY508U-7PB1oYOkTxJiLeUTiQ@mail.gmail.com>
Subject: Re: [PATCH mm 05/22] kasan: print basic stack frame info for SW_TAGS
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=HvQ65t8f;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Mar 2, 2022 at 6:34 PM Alexander Potapenko <glider@google.com> wrote:
>
>> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
>> index d2298c357834..44577b8d47a7 100644
>> --- a/mm/kasan/report_sw_tags.c
>> +++ b/mm/kasan/report_sw_tags.c
>> @@ -51,3 +51,14 @@ void kasan_print_tags(u8 addr_tag, const void *addr)
>>
>>         pr_err("Pointer tag: [%02x], memory tag: [%02x]\n", addr_tag, *shadow);
>>  }
>> +
>> +#ifdef CONFIG_KASAN_STACK
>> +void kasan_print_address_stack_frame(const void *addr)
>> +{
>> +       if (WARN_ON(!object_is_on_stack(addr)))
>> +               return;
>> +
>> +       pr_err("The buggy address belongs to stack of task %s/%d\n",
>> +              current->comm, task_pid_nr(current));
>
> This comm/pid pattern starts to appear often, maybe we could replace it with an inline function performing pr_cont()?

Sounds good, will do if/when posting a v2. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd-0jE22cocyL8XPC4oEuY508U-7PB1oYOkTxJiLeUTiQ%40mail.gmail.com.
