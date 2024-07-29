Return-Path: <kasan-dev+bncBDW2JDUY5AORB477T22QMGQEKHE24AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id BBDA593FA63
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 18:14:44 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-426624f4ce3sf17499145e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 09:14:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722269684; cv=pass;
        d=google.com; s=arc-20160816;
        b=IH5vNdQEPcV4icA3SAl5GiJzZgP2UwX819x/acUjslE66FX0JctWTvn4GEdnSnBuc0
         FdjrW57fZzIl3/EAIJLs/0Zvqn0HqOB6dPTwrfKCGmH2EZKW6Y9bQXutHfRbQB090dfi
         aEYr6SxXJSwjz1an4viAixy5HOv3uSVcRJ7Tt7iXZYYztg/rH8O3LDDVlVlqHTgbYQPF
         3IjhcwkSf0ZYjxpg/txNCeU6FV+GcRsP/AOkJM1t9PlACunlkxpYRCUkVmI48JR9sg87
         1FOrW2vAG15pmkMZbCv9Bn0yySXgO/PkT6UfhyB5XvNy4hbB61wXIih8wZvcCM1g+TIw
         y50g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=d2sHG2CQ8rIf5ABE1zRjefqgahDEFZHnMnd9Fs3CLio=;
        fh=H+EfCkODVKQaZ5Rdf6nTmdXj8McdHLl5vjVkxFi9XrI=;
        b=NmcZYPp7zUsFGgvjHvHL9eaYLER3sowelrW1PW++6gvkranCfnJh3W1GFyHvkBSqCH
         9bfZKlf62zKu0Qw8uLscyARy8adQ5kYnaUTcdMTmHfyGiXNiIoRmuyNw9lSHM1ujwhvY
         8cs44xXjqvy5nl22fCfA4EA+A0VpzDD0TPOFNP43DJM/MPtqugQjCJHeBcnWtg14XtOk
         a/xaSVPc4Y/XQNiih5OsFiypmWw/+QFcV3xWv2nwPesyybhWkG7uVOdK8rU7XiEZkNZx
         x6IbDKL1d7mU+eU3ns3X05XOI6qzVcfonaU/iHV/m5+1F7Mqap8pft0Ca9LmE2Ko+oEe
         N2Aw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BvBgmPvI;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722269684; x=1722874484; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=d2sHG2CQ8rIf5ABE1zRjefqgahDEFZHnMnd9Fs3CLio=;
        b=W99ZUDiF1HN4YhgeTju0RA84BRFlWU1Q8t/VKLpHFflzpsXjAgbtJVW3rsKMHMVftP
         JdSENXe6V81sRuQ9keY+TRy9IMx9Mtv6IUAYD0GzpMlv6YIkmrLkwwaLn3c680f//okM
         080n+Mder14xyqpWphOCqqm8rWmzU7EY7CNx5oR43rDxNYFZNrSDEaIcy6uTvcakkfrT
         6RqJP/ekAFfTSlRhOTww4j5NqWscCNlt0QLrrUdQwHA9KUrDn47rXG1Se7fxsOHXzXLD
         FNjGCEWLObMNoW3egYvR7E1fcrDtTlPC3ROEu/dF1EAtcT99JVbauPLXbwYeDZMCL4LG
         XJjQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722269684; x=1722874484; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=d2sHG2CQ8rIf5ABE1zRjefqgahDEFZHnMnd9Fs3CLio=;
        b=T/5lgra/bm69NPWDQL99fG4/8P6m2e8a3csAjD2Nmvb9QQYp1q4Cy7p8gdPZ4ojYWV
         mH2VS87zebteFZ8qW3o7ktUxUu/xzI/itFzQVIxPvZwM65oi9CbInembVpVc+0hQeaOj
         m2qSLSR0yYI+6IieVNEoH9hJRHzJbzGa8OaILJsrWOCUDcteFxiAY0KGII1p8kDmb6hB
         NityYdTFfbdMlyLgxaEpPw8OHh1LK1b0EnTDI9Cnw5jO2thxiBhlyRh5Sd05BpjfZybn
         JxmV399o4Bwm9GLCL1+naU+WbX8+JYMpeOQKodVoDDwW7T4jbEztk+aTRt1NhpKzdGXh
         DVGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722269684; x=1722874484;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=d2sHG2CQ8rIf5ABE1zRjefqgahDEFZHnMnd9Fs3CLio=;
        b=YGJccb60VbGm+jYiBpWYDbovOUGlaCQtS+Z4qLQAeQ+9pvBFlTeZ1IFAYVcYJp/LxO
         JjS4B0keeHikzhpyW5ifCkeL2Sxfh/KLR6WoCi+cCmC6lB6gpzBEsC/Ihf7wn7ddObaJ
         RbACoE3PfChfRCVweqkbQb4sKho45OsuQXVjSl9phWlNLIn+g7sEJ8lowqjd4QeMuC+W
         CMiVEipBekzkYAQESbE/a5/k1FXs1Euk130+KgxPd4ri8kkgBQ023+jycPUjMFrWpbbg
         pz/5dZc03qcuzYPZOuFgN+mRXDXG1F6q0OUdhhw3XZWWNiuwP6GvhvBdO2y+v1LVjp1j
         T/Iw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXrWjdMWN1JX8f3aZLqisX76+zbriDlcI8vzlgkcjq0Bi9io7X+lR7T6GDGzDEGjxoONmSDIGFQiw1847DwB7ijufSwQTXCVA==
X-Gm-Message-State: AOJu0Yy4UNIRoCfrlyEGqtUZctZCsAKZQ+1Ar6T+qObYHsleRw/UHOza
	b8z7/KsBXBy5O36DJqSOc5vMI14kPPh5cHP8Mz6VEMQXTpKRHVAq
X-Google-Smtp-Source: AGHT+IGM4FTbnRYMPtUbcUx94mzmO9WOaFwmZL8WwhnQCzIi+kYHZcMw3T5tVCQay0abtF/0t5vTcg==
X-Received: by 2002:a05:600c:4fc8:b0:426:5fbe:bf75 with SMTP id 5b1f17b1804b1-42811e12d1bmr57588305e9.23.1722269683929;
        Mon, 29 Jul 2024 09:14:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ba5:b0:428:1007:62f6 with SMTP id
 5b1f17b1804b1-42810076470ls12665705e9.2.-pod-prod-08-eu; Mon, 29 Jul 2024
 09:14:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW83k/Izz+VZLIN2VOzxxQ9H6PAI8L38d4b4g/mOysYiKL4lpEimcgE0ONatAwAsCKC1PUC3G98LchqWZYfoOWgn4l4pIyOwlPqwA==
X-Received: by 2002:a05:600c:5486:b0:428:1dac:1890 with SMTP id 5b1f17b1804b1-4281dac1b4amr30259635e9.32.1722269682120;
        Mon, 29 Jul 2024 09:14:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722269682; cv=none;
        d=google.com; s=arc-20160816;
        b=XMdhj0YIQJx00c+afRTjVHuwNCQuY2Uz2JkT4+A6/QmdiSxhLdl33vedKXDDqUSuTq
         BjusU4/E6CwBo5fhenPq+Yj0o9naI67fBTENMw0hpszrm1bftgLC2KggWQkPEXr4UTXq
         SIemGsMqF6nzxCfngb4CiZZLgJpbovFSWCOLN+OreHJx1lFauoplBADtx4IbLgnH2daZ
         sB0fIRw4+B8HOYSrfKalCalYZfAfdwI4xBP9SFWL2MAZ3RJHrH01kvDM340wbDWRSG+a
         XEMtTyo2DbOujeztNdNLXNSeX5wbnRAJMCq08J5tqZSK8inveggkhm7vskROIyVIYlCU
         qcxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NCb9Ld2V+tyLAS+OJSGqh04B0fBxFGet5NP9pLw4hEo=;
        fh=+q2QWTvBbfbJ+nh84ssWtgIOg+sXQY9+CVqepSUIQzk=;
        b=jhz55/WcQDdC6Uly+zwbhmUz6NzcitSdoXTMoFoRAYN9Zn5S5AZrnRhA/un6aNmrKx
         99Wfn48ETPlYiaeqzHJ2dzh5HABykCnNJAa5euPwOA6x08mLQzcfZ7bTMOs43GuM+qwD
         nOFnmSKETLyDAgRNvLCKyWrfQs1e/KR/9doqzsN/JFVy6fLs7cjVgMQCBpUmeeNe1xVQ
         U9bJ6ymDk2SAzygxEaD0B/1ovEPPx45dS+9v+enrjw/zyU6nB6IGJrwY82OgLIvUkzzF
         +vqlQ+70F2MniUGTBpWUxzbK4yMpPIF0UrrJM1itOcNSfcz9bedqJUlQJ7cRnq3u7/Di
         KlRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BvBgmPvI;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-427ef3f45aasi7565365e9.0.2024.07.29.09.14.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jul 2024 09:14:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-3687f8fcab5so1438070f8f.3
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2024 09:14:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU+5ZXQ7jd1pj290k0lqiaTs1Wb1abefvvI24QIKUKOdCjqbC8aXnIraI2wDu27TnHWuWnwLAm1jmNwASpM32Iy1Nd3wUiGB7QIDw==
X-Received: by 2002:a5d:64c5:0:b0:368:7f4f:9ead with SMTP id
 ffacd0b85a97d-36b5cecf32amr6545711f8f.7.1722269681301; Mon, 29 Jul 2024
 09:14:41 -0700 (PDT)
MIME-Version: 1.0
References: <20240729022316.92219-1-andrey.konovalov@linux.dev> <baae33f5602d8bcd38b48cd6ea4617c8e17d8650.camel@sylv.io>
In-Reply-To: <baae33f5602d8bcd38b48cd6ea4617c8e17d8650.camel@sylv.io>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 29 Jul 2024 18:14:30 +0200
Message-ID: <CA+fCnZcWvtnTrST3PrORdPwmo0m2rrE+S-hWD74ZU_4RD6mSPA@mail.gmail.com>
Subject: Re: [PATCH] usb: gadget: dummy_hcd: execute hrtimer callback in
 softirq context
To: Marcello Sylvester Bauer <sylv@sylv.io>
Cc: andrey.konovalov@linux.dev, Alan Stern <stern@rowland.harvard.edu>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, linux-usb@vger.kernel.org, 
	linux-kernel@vger.kernel.org, 
	syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com, 
	syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BvBgmPvI;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Jul 29, 2024 at 10:26=E2=80=AFAM Marcello Sylvester Bauer <sylv@syl=
v.io> wrote:
>
> Hi Andrey,

Hi Marcello,

> Thanks for investigating and finding the cause of this problem. I have
> already submitted an identical patch to change the hrtimer to softirq:
> https://lkml.org/lkml/2024/6/26/969

Ah, I missed that, that's great!

> However, your commit messages contain more useful information about the
> problem at hand. So I'm happy to drop my patch in favor of yours.

That's very considerate, thank you. I'll leave this up to Greg - I
don't mind using either patch.

> Btw, the same problem has also been reported by the intel kernel test
> robot. So we should add additional tags to mark this patch as the fix.
>
>
> Reported-by: kernel test robot <oliver.sang@intel.com>
> Closes:
> https://lore.kernel.org/oe-lkp/202406141323.413a90d2-lkp@intel.com
> Acked-by: Marcello Sylvester Bauer <sylv@sylv.io>

Let's also add the syzbot reports mentioned in your patch:

Reported-by: syzbot+c793a7eca38803212c61@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=3Dc793a7eca38803212c61
Reported-by: syzbot+1e6e0b916b211bee1bd6@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=3D1e6e0b916b211bee1bd6

And I also found one more:

Reported-by: syzbot+edd9fe0d3a65b14588d5@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=3Dedd9fe0d3a65b14588d5

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcWvtnTrST3PrORdPwmo0m2rrE%2BS-hWD74ZU_4RD6mSPA%40mail.gm=
ail.com.
