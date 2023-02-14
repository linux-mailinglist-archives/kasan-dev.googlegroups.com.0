Return-Path: <kasan-dev+bncBC32535MUICBBE7TVWPQMGQEB7H6SRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2743369631B
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 13:07:49 +0100 (CET)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-517f8be4b00sf156966367b3.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 04:07:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676376468; cv=pass;
        d=google.com; s=arc-20160816;
        b=F/Bt0NTWFQm5TPERpKOqBQJIdHGdXIHq0Ine8TYNgeTf4QfCd4gzmsK8XovgaRD0X5
         UO4va0qt8b6EhELnOWqPX7NYDN/GUjgU33ThzKenLvFoySEmwJIzWy02dJo5kRBZY96T
         VgtJ/AN7MxMB9urgm+Oh4UEY41geV2njbgsjCiUJcB0r3Wo/3YGEVB2hilSlHTVUTlTd
         SXIovRVP6RBdx+gC0EMoV5eilMEs7uRgm4UEl6yfzPUPIpJkmR6z1SPiLqMWCDdCYmG8
         2H+c0L4ztyB0HK0zx+l5wdlLvcfJFz4xcicmOAPq5bzHCDmoKct7gbULF2tQUyAvKxoW
         uFgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=iRHdOdz/lOm56LHrEcEl18U+MAnCuA5uBh2lAzboLXY=;
        b=Ae43QDyDvzDWJl9ZHI45v081tntDHFTA0Qjrj3CKAvt/V5EsiUvc9/oZoudzn1qfU2
         7DH2qL2tfPx7d2tUpQajI2x9wTFPza7CuBC43BgktUJT+ZvQx+znpKEuotDvkz1qf+vR
         8LBPYznIVQpe/S5J3Dk4f2P2HDOLOrTkZr/LtABopYpDjvawlhcICYzKLHJZlvNdIgKX
         B4F2/uXveD/XgoBM9AiOcrpqTeuXgpVNUZuAdkiWeRblAbtYqXB5DW6QeRbPM16v7+ke
         2efGgcoN2bfJmIoRgP2Q+u8la3i1hLJNQUqPwM5Ty/nO0pOZEK2culfIdwZfP+bhIUKe
         Y8Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=X9a7rxAD;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iRHdOdz/lOm56LHrEcEl18U+MAnCuA5uBh2lAzboLXY=;
        b=c/9A6PzEUmyplV1KOameZpNZLqj5sL3RwgHskcLH0iRCXQWfthqW2Il48BB5jfysXZ
         uu83aG5yzNNHASSl71kLIIvdL5Kw1O5NdI2iebB9uerhw6MqdWviMo82GK08WIR+oisO
         NSwVZRBYvYq219/eGzz8/p6txb9KlpYMAQhy0O9WYwp2Rg0BzPfKc9XahN25xtLX8p9/
         VPbkcJ+Ytelko/rpJHVZWNK67VpWoWmApYLSTZuIJgKF9Eea1w/mHEimDcmRkKCWPtZq
         QuR/ODR55kUWycyrUlF830bYopRjBLubWLdIHNVciebCFNn45ZdnqlCeBoNLz1utvJ8o
         J+0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iRHdOdz/lOm56LHrEcEl18U+MAnCuA5uBh2lAzboLXY=;
        b=a8jlSM7CD+C8cYsqicMazqqy+RPB7At3vMGmfe6Nc5o9TsoiGP5o03U316qMyuRoF/
         UWywf1fyiOD8rFg5MrZClAgh+FOBRxBDkpEB7aPVQDveiMchWO7Gw+HWdgqCGZFo+wId
         WXLXKcBi56tE+phXi6x7oL9KcMzZz4H3CKAikXvLx7IKx+AK3xE5ZRpa3VREqfNo52x9
         SLvlIfEJCP7tbqwzrwefKVLurhdqESiDTEZd+8eVUv5nRixH4ptDIHxyCNmTj6fUbNNg
         U9V95NrnAgEcCXoaQINRBen8cdSDFVXJ/T4UVAvFd0GkC3YEruQFt4BKAfp4nUFq5kwN
         OltQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXEtXf/q/5xxRF1GIQNdL6WCoapK6oo0dYW5RWgWC7+vSA3SOQ/
	7r4Rv/yuB9a+/RbrAZ7LdhE=
X-Google-Smtp-Source: AK7set/TEi8Pkez0GyHvVe729mvGW7P4JQrqMQ2EnfouogLVB09HHIqhAYAiUdK14lPCcMRvf7ailA==
X-Received: by 2002:a81:d349:0:b0:52e:e6ed:30a7 with SMTP id d9-20020a81d349000000b0052ee6ed30a7mr228840ywl.551.1676376467236;
        Tue, 14 Feb 2023 04:07:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:9206:0:b0:52e:b7a3:9aa with SMTP id j6-20020a819206000000b0052eb7a309aals8552484ywg.0.-pod-prod-gmail;
 Tue, 14 Feb 2023 04:07:46 -0800 (PST)
X-Received: by 2002:a81:e40d:0:b0:50f:cf49:1fa5 with SMTP id r13-20020a81e40d000000b0050fcf491fa5mr1175555ywl.3.1676376466551;
        Tue, 14 Feb 2023 04:07:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676376466; cv=none;
        d=google.com; s=arc-20160816;
        b=n+A7leTpVq22bLfiyReg8/IGLwJP+Tap/HyhAY9f056TldDxtNl6p6Q+Y4Yj1axOGe
         MiKdPETDfDSd0DctZrThi8xb5K0RlHVRp7FwGA9lW4/iAHm5TyMneHMiQofoAezbtWZF
         LF6n6/gyRpBRBDQ+gGwzZsz8WczV0gSExSjdwrJeU601W3cker7/G05jFRuPBGlWwQjB
         Z9ZnqWLszaiA2MxADUpXwiH6qfi195G204jdnG9MxiUOvATHus98GG8WI2x8xRYJVfmc
         aK3nkx7OEaQ1y3vjhU6ggCigAFYxf6pzs/NWsnKRSfedwZ9TYWPIPfLXo6OlGbg62S38
         nYNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=SnnGhci8G9bgg/cHSUev+SUa0D8kZiVN6LjQKlMVnJQ=;
        b=eEfmk3yuoYALff6ORsXsVU8VdTh5bWL0I2liFRgAQsYMYsMtoiR9WQS/J/ULGQiUpK
         HtTm2kMufzZrGH4GnH94uN2HYpIb7fJe3OIwHn5gywzWRumB6eYYw8HyvG0S0SaZ4BHF
         Uch+x+c6ucDWeqgIZ1s8sfd5BbGUNEKpDVCK5+VICZCw+MeK8wkUhSZWnNmHtAu+2rAp
         CPOGk1kGKRmjbH/3P0ahAdqOQDco9N56t0Mkdw/M3nLbU6V0a7rXqq7F6HjXDahi4ud0
         GESxX4kTcyj7JkFVXxC52zSSNeuxW9Vw5WKT6LswOP5LchqIq7ah4TuxaKA5LemnFUuW
         9qIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=X9a7rxAD;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 70-20020a811649000000b0052ecc057ca7si972820yww.0.2023.02.14.04.07.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Feb 2023 04:07:46 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-215-tjLzdJCMM5O7DyeeemhmFQ-1; Tue, 14 Feb 2023 07:07:43 -0500
X-MC-Unique: tjLzdJCMM5O7DyeeemhmFQ-1
Received: by mail-wm1-f72.google.com with SMTP id n7-20020a05600c3b8700b003dc55dcb298so8530724wms.8
        for <kasan-dev@googlegroups.com>; Tue, 14 Feb 2023 04:07:42 -0800 (PST)
X-Received: by 2002:adf:e909:0:b0:2c4:71d:244c with SMTP id f9-20020adfe909000000b002c4071d244cmr1857468wrm.25.1676376461739;
        Tue, 14 Feb 2023 04:07:41 -0800 (PST)
X-Received: by 2002:adf:e909:0:b0:2c4:71d:244c with SMTP id f9-20020adfe909000000b002c4071d244cmr1857443wrm.25.1676376461512;
        Tue, 14 Feb 2023 04:07:41 -0800 (PST)
Received: from ?IPV6:2003:cb:c709:1700:969:8e2b:e8bb:46be? (p200300cbc709170009698e2be8bb46be.dip0.t-ipconnect.de. [2003:cb:c709:1700:969:8e2b:e8bb:46be])
        by smtp.gmail.com with ESMTPSA id h18-20020a5d4312000000b002c54d970fd8sm8754308wrq.36.2023.02.14.04.07.40
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Feb 2023 04:07:41 -0800 (PST)
Message-ID: <7533a41d-4e43-cdcf-e5fd-ba10f53c9b3b@redhat.com>
Date: Tue, 14 Feb 2023 13:07:40 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH] [RFC] maple_tree: reduce stack usage with gcc-9 and
 earlier
To: Arnd Bergmann <arnd@kernel.org>, "Liam R. Howlett"
 <Liam.Howlett@oracle.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 Andrew Morton <akpm@linux-foundation.org>, Vernon Yang
 <vernon2gm@gmail.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org
References: <20230214103030.1051950-1-arnd@kernel.org>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230214103030.1051950-1-arnd@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=X9a7rxAD;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 14.02.23 11:30, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> gcc-10 changed the way inlining works to be less aggressive, but
> older versions run into an oversized stack frame warning whenever
> CONFIG_KASAN_STACK is enabled, as that forces variables from
> inlined callees to be non-overlapping:
> 
> lib/maple_tree.c: In function 'mas_wr_bnode':
> lib/maple_tree.c:4320:1: error: the frame size of 1424 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]
> 
> Change the annotations on mas_store_b_node() and mas_commit_b_node()
> to explicitly forbid inlining in this configuration, which is
> the same behavior that newer versions already have.
> 
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---

Reviewed-by: David Hildenbrand <david@redhat.com>

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7533a41d-4e43-cdcf-e5fd-ba10f53c9b3b%40redhat.com.
