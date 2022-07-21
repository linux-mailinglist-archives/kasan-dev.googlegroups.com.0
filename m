Return-Path: <kasan-dev+bncBDW2JDUY5AORBDHU42LAMGQEBW2C3CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C7C057D4EF
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jul 2022 22:41:50 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id i5-20020aca2b05000000b0033a509b7255sf1359134oik.21
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jul 2022 13:41:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658436108; cv=pass;
        d=google.com; s=arc-20160816;
        b=nLwrT2xs8wsP2TjDnoffWellwEf7dMBr8GTi9iP62nYlEA8LyerLKUlULqm/9gA/XX
         xdKKliaXboTnBanF60OlVoNMjAkHuIOWrcKob6bDnvMfAw4q6sT8ZwLhenvCP5GZK1bA
         h5xsryqBDd9D7y/6NhGC0Qw7eLPmYW1tlJz4QZtKmoiFKYZmKpciOyi4sS95fRGAY8C3
         2AbU2xur/H/J4cv5y6OFyq7oVCF8ZqyqlBo1OJnZGBT3ZCXJ2GGFkCcSTiu9I6+VqfoQ
         SqRlAUgkrZQE611M9O5zBjdeaNKa4wDPFwS/zuuoixVRq6NYd4RqQMiEm/Jou4pY4wf1
         phkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=n0IIIiv6C4EZNf1EjBj8SUyX1dQa+NXY4hPGo/EZgGo=;
        b=k+nMQ7jlHDNBlfmyJ+mvNH1WH3ZwQfLtrrvCNJvvwzqcWN4+Q1o1GoeNI4HbzSuask
         ydfiIWVfET61T800sIvQpj9IrjTeymT5Ipxu2jZ5hQ5ZeSNB65xKGqWrIRBriY+qlyzz
         7rfOVfsZ719oBXIFvj2IZQczjXJlSGWz97LOwGx4aLEwOtBN1W1Z5OjklwBQAwcjHmzY
         bnTfrIfQctAAChFKKrh2z0de2Pv+xOWaqXkWRj7b7au+hx5Y38M32/kjrkf7PiywE18S
         8qP+Cz1JzGaeVHl3/hXZu++0UfrUZR3jFvzzU2FpXiDEN7C0xhq0dVQB3q8u482UaER+
         R/xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=V6UHbJdA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n0IIIiv6C4EZNf1EjBj8SUyX1dQa+NXY4hPGo/EZgGo=;
        b=R/9VL065F0nmk6xzKB5XRxoEEVV13tTe19aRuE7loZCmtmXSdnFzwTmv/xk262M4by
         IO3HYoxVBTldeWJtGEzpMiJDZQJk7NQUb4/gKc4SG37lTpsXX2b7mekL++6Y3tbsOZsl
         9G4vmIapelnl9cZJUN6Ps3XniCFodODWTMYnuJwpK4piqAlUBIaCrX/4n2A6aI64+/7f
         9azmIq6MhTWgkgP2iMfmP3ksJRY4JsWuc3nQNDwLLlsPZWd79Fg4aWXd/ykPlHW6WODP
         WeXSvsRr0PEWqfeagIsRM/23G8eSSrvBUuHmWtRGZOnWrHn4nV5No8FLjckacGfped9B
         MqKg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n0IIIiv6C4EZNf1EjBj8SUyX1dQa+NXY4hPGo/EZgGo=;
        b=E3MkT9hkPFI3jmzTLQW310tXXesx0FQ+3XC//0YWxNRgtq/b/F696d0nwF+rcyRHa6
         HSnAdd33MvJGEnPlLTruIGQjC3GEnpk9d5qwedeha8EXqRuKQ7HUdJaFRqZI3DBzIg+G
         8ltQ0yydyHDSCPCs3EnVmq3OhF8pzw3CkUWEIqoEM/nGPwaYTkyO+11pDznCYhs5pI+R
         8w/VA8kLb/lGqcczzu00r0edavRuOq9v0zwMz98FLK2/Mq3FdVpPT9OVsI09zg7MnRbo
         yPGErSA0viHkfH698cQd71Qa+VT9oesD7yWkecGx+rLcNztbUnKLXTUAOoVt4HC32yu5
         9bfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n0IIIiv6C4EZNf1EjBj8SUyX1dQa+NXY4hPGo/EZgGo=;
        b=on1DRXwbasWi7W9uWVpHJXKZfh2SnWW/e87IZEbm672dxqU/idDDN+zUThOy2pmyC9
         V3X4L2rmqCAblx1oCj0GLIV9vqoWIrHD9t1Zx+0vbRHrZvXn4xP3tU5DIHSFoGGfunnZ
         aV6vUy3LW7Cyg1r6bMPZFo9RABHmznRo53uniqsqR34XHeFHtCUpqyBdsPkyKzsLv32v
         jENrPstT/iWCSruJjCx/qS0OSWWyckDoRTqigNGPMwGE++Zpzl8YKLwQJBhRo9kGGGOS
         gtEHbaxYVcKd/h4HbgIzXC3/fAPDAdE/LVQE9xlIGHbM5uGVy9NeXxTGJJUnUkUa5FhI
         8n9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+TcPY1aJHsG9UAUF9fYIDAXuCpYq0n6dY//bJo6EN36BXMfjpA
	qNVWf40AEngLcVqGzHNAkg4=
X-Google-Smtp-Source: AGRyM1t7+HKXkIl+AClQmLZFW6rLrymMeS3d0/8IdOJC+tQwxitqzw+Ce/xjFRbkBBTnYNP68i8t7Q==
X-Received: by 2002:a54:4411:0:b0:33a:6c6d:97fa with SMTP id k17-20020a544411000000b0033a6c6d97famr5688487oiw.30.1658436108624;
        Thu, 21 Jul 2022 13:41:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:5a86:b0:102:80:44c7 with SMTP id
 dt6-20020a0568705a8600b00102008044c7ls1548119oab.10.-pod-prod-gmail; Thu, 21
 Jul 2022 13:41:48 -0700 (PDT)
X-Received: by 2002:a05:6871:549:b0:10c:5c6:271b with SMTP id t9-20020a056871054900b0010c05c6271bmr6178400oal.94.1658436108294;
        Thu, 21 Jul 2022 13:41:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658436108; cv=none;
        d=google.com; s=arc-20160816;
        b=NeuD5frjbLAerfn4avmYhF9FVIVgxWvy03BgkBXf1ZlLL6pRtuulYCWWlXAXy2XDFj
         Yx5vJFD19rOWcGuZ2KbsfC8HhZwizqXXJN578NSAjoCJ7AP5nqI8IwHbL5g4ekmC0o5I
         sN1akvKj3Ka2m50U6VNsUXC+syOgoIbbCA1TsJaJRhmnJUrVkM6S05EO1EMT5g+TXmqL
         Ld3/FGKaDehgzqgcb3Aiw06uppHqh4AjijlEEB6aECtlaB4xoAjcMGGM0foY8NGewUZ4
         0IJ7olkEolJXprBsrXv01YXiHExMWWvVKP/rRAeFmIPC20LB7LGK2MTGiDb69uc/Qm5I
         61tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MY3kboTjNAZXbrK31xdc4/MyqehNd793LiUl2690CR8=;
        b=Z7dB4MwMAYrQ1qbChDEtYP+JiQkH5dq1a44BsTS8zxjFVUVGWXJttRBLLQuH1jdD3Y
         gP+EXa0UPa36ZhYe8pS4y4uFWL9DMv9FiWg7Mu3ooGERnzVXXap3HvY7U0a1Z18SJaII
         6hvGxfApCZMMtP8phNbN5aQbQ1DrGF+S5YnR3KLQu6t0/0kX+gmCdukYcN3ZC75j1iRz
         opz1T4BobNktFJn40eN65ZDa+P22BieXdOBluEcvtbN62K2EWP2QuVnMypZtbfjwmPgA
         hkv6wjSNrqX491LSsQZKOoks2hfBrvtI0u12lpf0rkfSUZeqFpGJkeHY0HPWK1/XsQfw
         BkWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=V6UHbJdA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id a32-20020a056870a1a000b00101c9597c72si403246oaf.1.2022.07.21.13.41.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jul 2022 13:41:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id t7so2141357qvz.6
        for <kasan-dev@googlegroups.com>; Thu, 21 Jul 2022 13:41:48 -0700 (PDT)
X-Received: by 2002:a05:6214:2a4c:b0:472:f8bf:ca74 with SMTP id
 jf12-20020a0562142a4c00b00472f8bfca74mr323196qvb.111.1658436107864; Thu, 21
 Jul 2022 13:41:47 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1658189199.git.andreyknvl@google.com> <0e910197bfbcf505122f6dae2ee9b90ff8ee31f7.1658189199.git.andreyknvl@google.com>
 <CANpmjNMrwXxU0YCwvHo59RFDkoxA-MtdrRCSPoRW+KYG2ez-NQ@mail.gmail.com>
In-Reply-To: <CANpmjNMrwXxU0YCwvHo59RFDkoxA-MtdrRCSPoRW+KYG2ez-NQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 21 Jul 2022 22:41:36 +0200
Message-ID: <CA+fCnZcT2iXww90CfiByAvr58XHXShiER0x0J2v14hRzNNFe9w@mail.gmail.com>
Subject: Re: [PATCH mm v2 30/33] kasan: implement stack ring for tag-based modes
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=V6UHbJdA;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f31
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

On Tue, Jul 19, 2022 at 1:41 PM Marco Elver <elver@google.com> wrote:
>
> > +       for (u64 i = pos - 1; i != pos - 1 - KASAN_STACK_RING_SIZE; i--) {
> > +               if (alloc_found && free_found)
> > +                       break;
> > +
> > +               entry = &stack_ring.entries[i % KASAN_STACK_RING_SIZE];
> > +
> > +               /* Paired with smp_store_release() in save_stack_info(). */
> > +               ptr = (void *)smp_load_acquire(&entry->ptr);
> > +
> > +               if (kasan_reset_tag(ptr) != info->object ||
> > +                   get_tag(ptr) != get_tag(info->access_addr))
> > +                       continue;
> > +
> > +               pid = READ_ONCE(entry->pid);
> > +               stack = READ_ONCE(entry->stack);
> > +               is_free = READ_ONCE(entry->is_free);
> > +
> > +               /* Try detecting if the entry was changed while being read. */
> > +               smp_mb();
> > +               if (ptr != (void *)READ_ONCE(entry->ptr))
> > +                       continue;
>
> I thought the re-validation is no longer needed because of the rwlock
> protection?

Oh, yes, forgot to remove this. Will either do in v3 if there are more
things to fix, or will just send a small fix-up patch if the rest of
the series looks good.

> The rest looks fine now.

Thank you, Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcT2iXww90CfiByAvr58XHXShiER0x0J2v14hRzNNFe9w%40mail.gmail.com.
