Return-Path: <kasan-dev+bncBDXZ5J7IUEIBBK55UTDQMGQE5LQNRNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id A306DBCDA30
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 16:56:45 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-26e4fcc744dsf25903695ad.3
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 07:56:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760108204; cv=pass;
        d=google.com; s=arc-20240605;
        b=fW4n22jJ2ZBWODILQuD+ItWXu0rlZaOraBVr2etQVz5XjNkhD3vqa1UxYHlGdblIDS
         8cV4xrm/R+HDlyPXMLxd/BUUhjoOuyB+pMRWFgjuTZc6n2ujmgnJeUC995JscHzYqAL0
         dOPVBHI32oyfvNZBbhUWOZPS3/Cu+cmvABPzQlcv1SrJUIAa2Wq4GcgCVIlhM3mIT/k3
         s3rmzdo+ux9D9fTDobwogCQU1XfYUxDcM/R4ki2vHzDRJRPUcW2l6s0rI9Ajs2aQbeJM
         B5OVsix3YhCK+sgjmGVGw7hVruZTpFR56KucIvx13nJw8ouNuIpMu2SjLbSfRBTDEPjW
         07IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:organization:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=bzvulwb2HP0AMl7UbYZ1fewN+6/24Z+vSKjDNsR1klI=;
        fh=UteBgfSvRFgPSzp3mJwRFVcUoH1uevTeqtdIB8lJaD4=;
        b=PFychIfEoUTS/cnf23yzMoLReQim/w1O/+jJXhCOxelqxtapLHW5GJFgyamiqTIUjk
         k5Z1EK1SLnw/w8KNCoZp+9sawcs0dZh5J+/HVO+ViqEXmmt27iJJgMCb+gFfDbsmG1aM
         niE9xfU1atm2UvBvtfRFkE3iTAB3zzik/a1FtzDVm8BWbmoZCMZQvRtw3Fd+h8+25j4/
         yBdW+cDNO4dWwHMzsdHZI1z/CcQzKYwnphKcLFu/BD0cSFNT/WcjuK/9hJC28499pM25
         YjoUqpSnDIChN4DKmKYllJO5K5aogQE0WlnQSxtWnm4zavPy6meyvNlB20VvmxT3oL5y
         0CLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.210.181 as permitted sender) smtp.mailfrom=yskelg@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760108204; x=1760713004; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to
         :organization:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=bzvulwb2HP0AMl7UbYZ1fewN+6/24Z+vSKjDNsR1klI=;
        b=uRAoHluUsBa5cOidr26LZdDJR6Sk4cjeCwcKvBbRyhIDeF2L+Q+tDmEGspbNGi7x0Y
         xWEdPF1bFYk8IMQ1PgCd3Jl+2QmPK2UF154fsfboFO7D4aYk/qHHWzH90E3pEQIkksMH
         NZDyDdWMqJ0aUXh614j6rIYWeKOqvxaTpKtGtB5DEB4StHD1s9hXPKgNfx+MuQkH3STD
         ZPsYZriswQ1599w0PiNG5gnYz0IE1gArGiR3GjXx040WWD0soj9oothI7SGQrpD6kS3H
         HRvrKzM8+eQldiIwnbOnPS2BpQI1LTKDt3xsF37BUVHRUHwuAEvxBJx+6DT9TBAtRYGo
         IVLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760108204; x=1760713004;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bzvulwb2HP0AMl7UbYZ1fewN+6/24Z+vSKjDNsR1klI=;
        b=NtEhHWG9tFgngVGOEriaoqfrKgozKcVUG5Yc1NZcsNcUpRzXUjucEl4YI6yB+H9YlW
         qBRqOvUQEo3WapEhGukO+lmPZkIjynQWlRwLd2LsW/oaGz1yE+GI4FxT7j+VqhK0BMCE
         XcDnHyMAXiBTtD2NPrr2Yh/UmQY+LcwIIIi7RkwZXTF+Sd2s2ZEuk9X+VN8SHQsXXlz0
         tPeuUI9TV8foVIdw+IS4G9FPL5kIaUQEa2F6MBsMG3viTMe3YH39ECuJxt2pUabfGiJN
         OemwmNXyQxEaMZWknvqQS0IEQ60fbUkF0ZdO0zXzi7RRtnWg3VR6S9/nMZc1RX8IZC/O
         lz0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0Elw4QK3nVPlWv3ymsC38YxYJsGk3TGD+shLIOo+MP5AwCjSyVyXTS1GUCK46WjgzrooZAQ==@lfdr.de
X-Gm-Message-State: AOJu0YxC4x15I8UKZQedgbvNT/xUVtE+MF105ld+Ch7o8loCZlOYgIoV
	gdJOe55MlItXccxxkYT0HSxZ43PprLRdTn2hWtqIQMHtakp1D4d3rddS
X-Google-Smtp-Source: AGHT+IFaVIFyoXKJ+SQd17rsrsVrjg7Pjp3nfqZo+4EKqTelD0GSc8iTVSOphKfYsttb9ZyTL+XNwQ==
X-Received: by 2002:a17:903:910:b0:28e:a70f:e879 with SMTP id d9443c01a7336-29027213361mr138873585ad.1.1760108203634;
        Fri, 10 Oct 2025 07:56:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4bU3Ds4J4YM3bikyH9PPuyns6HiyBXwrf7ZQDL32igPw=="
Received: by 2002:a17:902:7609:b0:269:6ca9:a91d with SMTP id
 d9443c01a7336-290357bd9b9ls19132555ad.2.-pod-prod-01-us; Fri, 10 Oct 2025
 07:56:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqGKdVi7cYULUHBq7upB+6+HuLO7mzH59aG0I8BoRXvXNNU1H83RdXUIjwwVisQ3NlIvR0OLZckDI=@googlegroups.com
X-Received: by 2002:a17:903:1a43:b0:24c:6125:390a with SMTP id d9443c01a7336-2902721357cmr136648525ad.10.1760108201985;
        Fri, 10 Oct 2025 07:56:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760108201; cv=none;
        d=google.com; s=arc-20240605;
        b=SsIKImCDmJ60lfmf/io33jGra9P7yP0xM4pkMT67EbImGOwHqABKU1NuJBZ+fgz1ma
         XvYQhELWJMZZZbsgLznI0Nku8K6ygYQcLglGcO5EGTgKuzZM9cwWyAkFJLCWW+PkKv+o
         PLZvRdLFiJyudqEh+o+0EpuRmowAXSxwJwied1Nr/t91GgVsjoQnNCwsDVDXAzx9qGgS
         cN1Q+peh1q6aNXNzcBer8uwuqmG5sqxUpLCvqXijaysDSjAmXiYUrfnF0UFtLW3iDtXP
         rgRd13Fx4MKpdaCA9ipFBTQoFVvwx7MeothWydb/iEeW2uacCe/h7HRacQMB0iph+tVD
         mR1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id;
        bh=u14/N400ai00fHVt2vd3J2VDGyko/X+Jvfxoof1W8ko=;
        fh=Q4r5Bx9UrrmFbV29jBIUxGyZ6t7NgS7wLUwB+jhQ2Vc=;
        b=HXXT73/bo6mQBCLsD7/n+sCA+beFkW1zZaPZD4IumGscTzEJ2TP4upclGRpcveWuNE
         96udWUX5790lO0oJEz/E+lt0AHyMJUdY1U439c+HFwk/dxSrDI6q9SBZXW+vvz2+aqpP
         yNfHJbUbHRen8Hxkxtu3uEDAT7l+dB18TK6mYPvuZCykK4ocolt59iVLuM+NO+SfYv8M
         reF9kHYE8TEL8WYWeCvHxL791RKkNZX/xFYa425rn7egDSika6YQdQnjVJ9QuTZOl2Kw
         oKkvdOfc2IToQRWjf/UqWVJX+0kc3lkF4RFqBCXhkh8AeqFymks2x1Eog+9FRjtgZ3jG
         DV0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.210.181 as permitted sender) smtp.mailfrom=yskelg@gmail.com
Received: from mail-pf1-f181.google.com (mail-pf1-f181.google.com. [209.85.210.181])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b6790484369si93260a12.5.2025.10.10.07.56.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Oct 2025 07:56:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of yskelg@gmail.com designates 209.85.210.181 as permitted sender) client-ip=209.85.210.181;
Received: by mail-pf1-f181.google.com with SMTP id d2e1a72fcca58-7810214dda9so261384b3a.0
        for <kasan-dev@googlegroups.com>; Fri, 10 Oct 2025 07:56:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWAGPU/xBPfLW5m/VTpgQ09mqyKjojMeTABOkIwfr+j95tryp+l2w66xxjHDvDTeDzeEThMHHlJwWU=@googlegroups.com
X-Gm-Gg: ASbGncsWCvLbYmnv8MG0+8OOO0tJSPWa1xSuoyH/r/rkvF/u+gr+W/RfnfjXjLx1Afh
	77iIlcw3HyoLcwEZEEf+hOEMAjTgO1wotV0o/RLBYIjEs0mHXu/+5BPBmPZukFUKRZFYd/+gKNj
	R0vXtexTsM7yMqfPSeqrrU+ig1zYEdNE5jFv52l8Nd9KauddXIH48N9ekACTn0Eou4h3RLu5m0f
	+5072uyungPviYqQgGhJ5Un2hbo0YWYi+yPXcTFmk5czRBsaghHw8+HU6O6r5T2lhmPrLl22H3T
	vegm1MdC5cQs5BplviORQ0tt8rxnjeCRS5n5Tg9EY1JGFEb9SmlHS1/UbJNLaB1mMtJ2BcNw2jF
	eZOSR4LG7srg2Nn/CEY/yxEqve7yl0c72UFM5IEzfXhWafr9v8thLTHyP8iFNiQjICJIXhBI+XA
	tR2JDGhj7LTQTioiVeu2RkK+CxBQuNeDPC1N8nMtK+3vBYaQ==
X-Received: by 2002:a05:6a00:1250:b0:781:1bf7:8c66 with SMTP id d2e1a72fcca58-79387c1ae19mr7895962b3a.7.1760108201302;
        Fri, 10 Oct 2025 07:56:41 -0700 (PDT)
Received: from [192.168.1.57] ([27.173.241.182])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7992b252f23sm3232472b3a.6.2025.10.10.07.56.36
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Oct 2025 07:56:40 -0700 (PDT)
Message-ID: <5b5d6f02-3161-4490-9652-e6d23e320a57@kzalloc.com>
Date: Fri, 10 Oct 2025 23:56:34 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] arm64: cpufeature: Don't cpu_enable_mte() when
 KASAN_GENERIC is active
To: Will Deacon <will@kernel.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 James Morse <james.morse@arm.com>, Yeoreum Yun <yeoreum.yun@arm.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Marc Zyngier <maz@kernel.org>,
 Mark Brown <broonie@kernel.org>, Oliver Upton <oliver.upton@linux.dev>,
 Ard Biesheuvel <ardb@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
References: <20251008210425.125021-3-ysk@kzalloc.com>
 <CA+fCnZcknrhCOskgLLcTn_-o5jSiQsFni7ihMWuc1Qsd-Pu7gg@mail.gmail.com>
 <d0fc7dd9-d921-4d82-9b70-bedca7056961@kzalloc.com>
 <2b8e3ca5-1645-489c-9d7f-dd13e5fc43ed@kzalloc.com>
 <aOj8KsntbVPRNBKL@willie-the-truck>
Content-Language: en-US
From: Yunseong Kim <ysk@kzalloc.com>
Organization: kzalloc
In-Reply-To: <aOj8KsntbVPRNBKL@willie-the-truck>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: yskelg@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yskelg@gmail.com designates 209.85.210.181 as
 permitted sender) smtp.mailfrom=yskelg@gmail.com
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

Hi Will,

On 10/10/25 9:29 PM, Will Deacon wrote:
> On Thu, Oct 09, 2025 at 08:10:53AM +0900, Yunseong Kim wrote:
>> To summarize my situation, I thought the boot panic issue might be due
>> to incompatibility between MTE and KASAN Generic, so I sent this patch.
>>
>> However, it seems that the problem is related to the call path involving
>> ZERO page. Also, I am curious how it works correctly in other machine.
>>
>> On 10/9/25 7:28 AM, Yunseong Kim wrote:
>>> Hi Andrey,
>>>
>>> On 10/9/25 6:36 AM, Andrey Konovalov wrote:
>>>> On Wed, Oct 8, 2025 at 11:13=E2=80=AFPM Yunseong Kim <ysk@kzalloc.com>=
 wrote:
>>>>> [...]
>>>> I do not understand this. Why is Generic KASAN incompatible with MTE?
>>>
>>> My board wouldn't boot on the debian debug kernel, so I enabled
>>> earlycon=3Dpl011,0x40d0000 and checked via the UART console.
>>>
>>>> Running Generic KASAN in the kernel while having MTE enabled (and e.g.
>>>> used in userspace) seems like a valid combination.
>>>
>>> Then it must be caused by something else. Thank you for letting me know=
.
>>>
>>> It seems to be occurring in the call path as follows:
>>>
>>> cpu_enable_mte()
>>>  -> try_page_mte_tagging(ZERO_PAGE(0))
>>>    -> VM_WARN_ON_ONCE(folio_test_hugetlb(page_folio(page)));
>>>
>>>  https://elixir.bootlin.com/linux/v6.17/source/arch/arm64/include/asm/m=
te.h#L83
>>
>>  -> page_folio(ZERO_PAGE(0))
>>   -> (struct folio *)_compound_head(ZERO_PAGE(0))
>>
>>  https://elixir.bootlin.com/linux/v6.17/source/include/linux/page-flags.=
h#L307
>=20
> Do you have:
>=20
> https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/commit/?i=
d=3Df620d66af3165838bfa845dcf9f5f9b4089bf508
>=20
> ?
>=20
> Will

Oh, There was a recent patch! Thanks a lot for letting me know, Will.

The current Debian kernel is based on v6.17, so this patch isn=E2=80=99t ap=
plied yet.
I should also let the Debian kernel team people know in advance.

I=E2=80=99ll apply and test it, Thanks again, Will!

Best regards,
Yunseong

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5=
b5d6f02-3161-4490-9652-e6d23e320a57%40kzalloc.com.
