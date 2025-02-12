Return-Path: <kasan-dev+bncBCPILY4NUAFBBVOGWK6QMGQE64WJRGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id F12E2A32735
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 14:34:14 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-2b8ee5724ffsf163833fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 05:34:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739367253; cv=pass;
        d=google.com; s=arc-20240605;
        b=a2IiBSyQemDv5OIifznK090duO/J+O4m54yw4Kg5akWBksxybS4h1z6K6XWuog+CJW
         2AooAgzVLG7DmmZ2hQoDv5cmrP8MmkkiN59IZrX1pl0UStfqTym7cx2NrPDMKT4exPjD
         IY6DUadAWtiWxAAzOxzb2T9uMm8jc2c1UDJzFdaUvz9XbVV1//JnnvchRGpR/XyKmy8V
         6HnBldKOPM0GF5CY20oUDsxabDlHtXMcsCtexae15k+443gbI8/jA+1+VkETvaTjQEDJ
         uAhKNTOAW1conigI8RGSEwOU+QVM5CqCOZtuJIvvuBCJhL8r8KC+MN/dkhut6+uTyLnz
         82+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:sender:dkim-signature;
        bh=ipsKrFbg9mKW2+KPWtVxaozRY5pgUQvSqN9vY/gHSEA=;
        fh=YXsHH+rWn+wM87htq9Bc1lV3Ih3b3KwJH8NMHXI+L9I=;
        b=UjoFxzZ+foydE9hGMG9l2b8DSDj6/XAhEYYtsq5xaiVDGd+30YOxxCryD+QqqBtKQX
         GS31yyboUI3wUzCLtQD1GEXErlN1yApD1vrM6xLATZV70oQUzbYde3mJxaCESwL+/Ujy
         INCj+qfPuj1QrjiphRQyQh8xGBvGZCUrgbMUXMXvT78IWNuieBzWeZ8aK2pmoX1SGRhQ
         jAmGxGJnfIP74gUPTgyefBRRIbp2bchacQCQG6tyFIbuKZp+dVf2iV6M0vRASNenY3iN
         /txt2WMzN3hrWsTcpWiK8jloMLG/Z0dR20GmPTmKckEWalBQVqk/WVrYq+QUakT+IC3y
         wMGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WeDqQNk9;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739367253; x=1739972053; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ipsKrFbg9mKW2+KPWtVxaozRY5pgUQvSqN9vY/gHSEA=;
        b=wKSj6pU1J79aC1yNjSSGmoTPqapXYGAYFazYzSwVyt6IfyBR8Bx6o4yaQcxBj0e2/9
         /6a4H8gTWbs+8Z+bc5PX57uWsf+4qTyryovtrDP3l0JoGP+z6KLQCYNwS6YBe51rPruc
         tgt5x2ahpH5v6NU+ZfO7AGaH/fRNy5dbKmY9SsWQXa3yDNQEPlenon4nS8fRueFNKALL
         nu2PBh9m7XKmJQAvxJJHmQjoiOTHPYIBxQ6K+3r8CyohAekszAjaavIqNwBEu37zXIVL
         +FeEP+FrhXWLdH259T45U2Sdhb54QjsYG6GsJ20mq5w+fi3E8vIDCBBIrYSFVdaJYZHH
         E1kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739367253; x=1739972053;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ipsKrFbg9mKW2+KPWtVxaozRY5pgUQvSqN9vY/gHSEA=;
        b=NX8KFvu6uLd741XKjLgV8Vu59NVoyj0uc3AA+C0SSrSCo5G0w2HIP44wvVvPyD5nuN
         SO+TZL0arg5FJ2NYZ66YmcMKAKy1F9KyekiDVX3swlTfs3ZMi+P7dr1JIpUMrVuJOnq/
         2GI5iHiR5//BA0PjyRYkAoNEGdePjASIry95TQ6uJEoPX1oF2iS5I9rQ6OgWi5nWEdoT
         HVrvlffs9wictV4TOmwFN2mhcxZ96cvftbJTZiry8DifvXQS4ZdeAp63xJMhHVJhcE0n
         9FYJFnoZG0K/P/u58gOoUSZUDFZizGiZeJEiPWNMw9mOmkWDsLfBtm+ZZkvACZ5RGtxk
         /1zw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0hqgRdWT2lqzAnBCG7mtn+MmF9j6TXC76lyqjnags3gUpk8X87g+4bOv+30kDfvd7Dp5rMQ==@lfdr.de
X-Gm-Message-State: AOJu0YzyCDeIXq7bwP/oeFKSBVuRp322JCNVi5N7QhNDAQdrTWOGYFnW
	DvzEa9AKWpUvU3Ppj5rRGGl8YFnNHWAcmkHsOGQNWBPuxNlHKv+m
X-Google-Smtp-Source: AGHT+IEORdLdt7j+FlQu2oTDEK3pOKA94vARQjInAmAunAybpY2WGKwdUlpSCKT0OpHuzkzmenyM9Q==
X-Received: by 2002:a05:6870:912c:b0:29d:e45d:dc51 with SMTP id 586e51a60fabf-2b8d85f8009mr1872766fac.2.1739367253533;
        Wed, 12 Feb 2025 05:34:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:4b83:b0:2b8:5ad7:3608 with SMTP id
 586e51a60fabf-2b85ad740dals251633fac.2.-pod-prod-00-us; Wed, 12 Feb 2025
 05:34:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWZIjlZv4EuX+1zdz0tvViLxAGwVQuY2y/yT03n/A8p2NRH3P+GwgQHbCtZSKo7Rgi5Mxy27bAwuec=@googlegroups.com
X-Received: by 2002:a05:6808:2228:b0:3f3:b1be:ef3b with SMTP id 5614622812f47-3f3ce744f9emr1647526b6e.1.1739367252768;
        Wed, 12 Feb 2025 05:34:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739367252; cv=none;
        d=google.com; s=arc-20240605;
        b=IOLPquYuAc32iP+//POVG4HTxyKk5nN9sQduWSOaiXEQn3aI8PMarEkaqVGL2yUjIq
         2Y+DcDzWm7LjE2oEdYd7eqq6n13oCmKmD06DdCs+GRyaAqq5ypQobzMO2yXNV20qkGaY
         JXhvDqpR9K3AJ1Ah3xV2JO6DZ9eRoWm+b5KCEaOLCvVzhn3mzcaoQp3WjbxFHdc5jfwx
         /g0EFRzgHXrUrOO5D6JQ/E2vE/m3sWRhXPjqAZW615cOEk1GQ6d/cLNV2zIYaF6PEH6B
         VPfrmowt/JEQfdueaf/ey3BLyN2Xx8JlzSH/tfprV0wWheIKp5Qk9JWAKCEAXnUV6wXv
         c61Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=RjHxnqTK7Tsl4746vRmLwJhugP3RFRR70bNvY/4d+hc=;
        fh=ly8H8bZiqfKdB61hxDLP+aC3W77Mn0LpV4DrJWRNO0E=;
        b=YdQyotW8eoVdy5gy2NmTXZ2Rdf4Uwm5RYA+FNMYPMAUmJyJyFYlxlMIkF3YbMURqeq
         nr/nRrD4KriaGZbpXmVGeWUbwYJQBSWggL3k8NYpl+D1PF8vKupx16XHOtQrKKnI/bfV
         iDoBH3GhEliKF5q1+h0l00FRRmFPxDw1nPqXnSv1sf96plx9NUdJK1gLrLzW7TqlACaS
         wwdnw6qSHpUPH5ru8Ep80iMCfdZc5d/3V4QOcLoU+YP6Ou/5LXJKX8sHeIMNnhx5VzKJ
         2u27JmcvwpjJwRxcObSWC737xQM5sM4xl8On5YFNZ++IU+vb0toWyc2dc7kQ1xOtTYcA
         VyWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WeDqQNk9;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3f389ed7175si627041b6e.2.2025.02.12.05.34.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2025 05:34:12 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-qv1-f70.google.com (mail-qv1-f70.google.com
 [209.85.219.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-463-uDZlYtkJPfS7sJ62aaayGw-1; Wed, 12 Feb 2025 08:34:10 -0500
X-MC-Unique: uDZlYtkJPfS7sJ62aaayGw-1
X-Mimecast-MFC-AGG-ID: uDZlYtkJPfS7sJ62aaayGw
Received: by mail-qv1-f70.google.com with SMTP id 6a1803df08f44-6e44e2f430bso14126136d6.1
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 05:34:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXL1FWAC4lDUz8UxJ6sf4Y5cWYl7hrmFgenLl8/x9ZXALWxC6dq7eTaXqT7XZaKKZDtsD+JZ5mJuek=@googlegroups.com
X-Gm-Gg: ASbGncsC4UD+eMMRINE3dZ+pfT0r6T91j2K5ZhSknakOnSQmulaENw6AnFGOLEzsVPU
	/GWSNPrK6ehOjk2yg8oh78zC935VG3X62gGpxjmegcA3+6Umu0kB83Pb/jqJbXs9d4S5fJu2O+Z
	jUeEfff9ZPNJfbBkmA9b+Sz/an5fmSfUs6B703M9KEqgrZU11srO2AMBUXqQCvd/jMmkKr0arFh
	ZTYMgSON1spqoONAD7qT4rB3uYSIxeHVqcjkPmEQuoYjOCiPlj3dBP/1jV3gNGdWPIsjIgKhzoO
	B9067ER95SgPixUIQiwypgEXdF4v6jLHut2xQpe2nm5goNP7
X-Received: by 2002:a05:6214:c42:b0:6d8:a9a6:83ef with SMTP id 6a1803df08f44-6e46f1da496mr49185346d6.20.1739367250272;
        Wed, 12 Feb 2025 05:34:10 -0800 (PST)
X-Received: by 2002:a05:6214:c42:b0:6d8:a9a6:83ef with SMTP id 6a1803df08f44-6e46f1da496mr49184616d6.20.1739367249055;
        Wed, 12 Feb 2025 05:34:09 -0800 (PST)
Received: from ?IPV6:2601:188:c100:5710:627d:9ff:fe85:9ade? ([2601:188:c100:5710:627d:9ff:fe85:9ade])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-6e659e49ae1sm2715296d6.124.2025.02.12.05.34.07
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 05:34:08 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <cfe70f31-e650-4033-9281-baa4cdc40b96@redhat.com>
Date: Wed, 12 Feb 2025 08:34:06 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kasan: Don't call find_vm_area() in RT kernel
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Clark Williams <clrkwllms@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 Nico Pache <npache@redhat.com>
References: <20250211160750.1301353-1-longman@redhat.com>
 <CAPAsAGzk4h3B-LNQdedrk=2aRbPoOJeVv_tQF2QPgzwwUvirEw@mail.gmail.com>
In-Reply-To: <CAPAsAGzk4h3B-LNQdedrk=2aRbPoOJeVv_tQF2QPgzwwUvirEw@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: YTTw80a1osJdVDh1W_UArdEkuUkcdM-1wnVIMG_KwuQ_1739367250
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=WeDqQNk9;
       spf=pass (google.com: domain of llong@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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


On 2/12/25 6:59 AM, Andrey Ryabinin wrote:
> On Tue, Feb 11, 2025 at 5:08=E2=80=AFPM Waiman Long <longman@redhat.com> =
wrote:
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index 3fe77a360f1c..e1ee687966aa 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -398,9 +398,20 @@ static void print_address_description(void *addr, u=
8 tag,
>>                  pr_err("\n");
>>          }
>>
>> -       if (is_vmalloc_addr(addr)) {
>> -               struct vm_struct *va =3D find_vm_area(addr);
>> +       if (!is_vmalloc_addr(addr))
>> +               goto print_page;
>>
>> +       /*
>> +        * RT kernel cannot call find_vm_area() in atomic context.
>> +        * For !RT kernel, prevent spinlock_t inside raw_spinlock_t warn=
ing
>> +        * by raising wait-type to WAIT_SLEEP.
>> +        */
>> +       if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
>> +               static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLE=
EP);
>> +               struct vm_struct *va;
>> +
>> +               lock_map_acquire_try(&vmalloc_map);
>> +               va =3D find_vm_area(addr);
> Can we hide all this logic behind some function like
> kasan_find_vm_area() which would return NULL for -rt?
Sure. We can certainly do that.
>
>>                  if (va) {
>>                          pr_err("The buggy address belongs to the virtua=
l mapping at\n"
>>                                 " [%px, %px) created by:\n"
>> @@ -410,8 +421,13 @@ static void print_address_description(void *addr, u=
8 tag,
>>
>>                          page =3D vmalloc_to_page(addr);
> Or does vmalloc_to_page() secretly take  some lock somewhere so we
> need to guard it with this 'vmalloc_map' too?
> So my suggestion above wouldn't be enough, if that's the case.

AFAICS, vmalloc_to_page() doesn't seem to take any lock.=C2=A0 Even if it=
=20
takes another spinlock, it will still be under the vmalloc_map=20
protection until lock_map_release() is called.

Cheers,
Longman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
fe70f31-e650-4033-9281-baa4cdc40b96%40redhat.com.
