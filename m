Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6VIVOAAMGQEBPAWU5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DF2430043F
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 14:34:52 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id j25sf2132794oie.12
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 05:34:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611322491; cv=pass;
        d=google.com; s=arc-20160816;
        b=CrQe+McwcT6vCaKLjiEhQlsXeRhZzfO1vHbAXW0r6MImgkDoHc/hf4uwQnvKFpCkCA
         WUhvOEy3ozYKU7eTaxipw07Z46Pnc6MrtQwVOuYCenQFP50tTUSAF/2qNiN8yTajXcLs
         RIFdZUO/XXVuSek0AdhmwEquesOQ/FWEcvftKXJ0Bc7ErBIYuHhm7PngYy86ZvZQpgPA
         j7MhDj/wYYYE69UZvjBg5Der8d2WAA5xNRQNPGfdRWI/ykJuCxrdCwAvCjk+1m4gpMNq
         8Ufjwcze4+trycBMYlN+nHxy5nh053f1xmgeAe4lyVor7QglouWI1kzdBpjNA51NOdJe
         zAgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=GI3RTKkJ2XnrevjfbbUb7y/abXJQX2tu+az3s/9iqsw=;
        b=Ip0eCHQrexbqFp3AkuGjCyWtz5LopYlVftMo4ryzY1PnY3GSXVSUJuWOG+Vf2PVrVt
         Nd6NlXClLQWnUp0JGOeFffWEDTOowkhXlTF2FxwxDbqTgd4hxolVcfMQ1lytpijFF7oU
         gEpVyImjvysoFxv9FZWiZ0tQhQXzpl1EwpWhCbsB58+B7PTJooBQ73rpTyJSxflItYRw
         R07rNJ85Gy+Acyo0gnOCPveC1vDpCRL7nipmOkFj71FeUF3xN2+YJoGGF6GHpFP0A5hM
         hKlafbpS5LlaQr56bUzQbkC9KpnT4/ZBNyOVdcMUN4yoS3I3tfopcvVFnzFF51QfyE6s
         VF6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GI3RTKkJ2XnrevjfbbUb7y/abXJQX2tu+az3s/9iqsw=;
        b=c56B6y2V4ns3meJG96VV3BEIPFpnEvBZl+cnvu3SGG/xFv3Zp7EHC9YwR7nVf1VtDz
         fpqlmNOnV/abA/MyFY43ynqjtI8avPmVSBX9VugxEDLrkBy7I4fiTgqinQpO3rVe0zzh
         7p4cATNoECMZE4QJLyCA7Z42SVgVIWmtszmrkM94dW1QwKdRufC1LsMx16MuKXwxQHDP
         L2vavZkmvudfHJrhG0+DMtGPvIqBlj3bo/6Vygd2sBezIKTktangSLTjdemPIACYATxh
         avJx15X4Eb3Ez7KjqNIKNnamEwlOlyvGz2QlVTm2uknneoLRkxL1Yw60itkGP6hKB6eO
         FrHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GI3RTKkJ2XnrevjfbbUb7y/abXJQX2tu+az3s/9iqsw=;
        b=iQbqlm2X/zhVGKtnXx3ltlBLLngdltdW4VViuCJYxP/Htxl6egyFVWvTupUvnlPaMK
         MKkLMkotK3qqNvifrlF6KdztAjhia4uZIMfolJP4AvhSKwlgoaDKWTwyPqJQ0c4ymwIx
         AHaFHghEg7C4wQdYQrz1zfID0SudXSW8nChbkhmby/VKZft0K2ypkTWRlp1iqnh4LT2C
         Sf/kAihfgHq7IW46/VbtkO3y5E8NlkevaJt8mnjc0rRkzXUHcExC0cYkVH+h/qE7swhX
         b/diIATo0RdbL7cM79WKo0ZGBEe94Yrdb3W/E9sAKeFarkb+RCdK3OPvJFr6zWq38ABX
         Ewxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531MTb9nrz3KyvOFq+8BzluzJ6hY5tcDRCppw8k7WVca5sy5I8k0
	HvuRIVqGi9WOfJQoy8PJQI0=
X-Google-Smtp-Source: ABdhPJxKpeKDeRiyQbi30hGRpz7k1MSs7Y9tr4zZkFTwaPAsnopBk+z6DxYVJbYINGknoiZBXoCc9A==
X-Received: by 2002:aca:4e4f:: with SMTP id c76mr3183266oib.167.1611322490912;
        Fri, 22 Jan 2021 05:34:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:69c2:: with SMTP id v2ls827901oto.5.gmail; Fri, 22 Jan
 2021 05:34:50 -0800 (PST)
X-Received: by 2002:a9d:6383:: with SMTP id w3mr3245618otk.225.1611322490586;
        Fri, 22 Jan 2021 05:34:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611322490; cv=none;
        d=google.com; s=arc-20160816;
        b=Of6SNA0UwJRKdYR2QXqb036Y4T4rHgIf+PKFFoVjz0bHzmKWOy6NcaGM2PL7TI7318
         rFKFrJ2T4tiyybmnC4H/dsmz2fftPkrof7uGCMqrGjEcgJ3FzHxoUx7L+PWLwsKGbxEY
         vqo4WsozzV/evqlKVlygfDTNOFJkREQkqPhwgYrkTyk+LgrXOiJJF4/cgXMrC5yF7J8s
         LQg7hBN99JTQ2COOaN4lFknZvjpzyMHCUFN7+PryRgzodqAp2ZQ9NjYSJBijT5v0DHua
         eHKthP1iq9ImpJms3UjiDXevZLbmVGqT6nB4OGm/cfW0TNRqaIbCR3jkofAWmeSAC2gp
         teEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=lSHQKpNhQMcCOqaLH8RXIl/uvx8oBbLV6EQYKoZ/O9o=;
        b=D2lOJkjAZrbXf/+C11owDXkWWJ4FQuvrU1CsaBZ2JeEW4iwx/b6sjCKBdfvM2eCfkx
         Z6u3hX+msDaTYAONov2ESXlFQzNRlPxk6xXGU99jkGRfRrfq8cuU8HXkWvxVuTfP102X
         jKH2LquvmHsVcFn3mQ2GMNxog0aK9NQHK7duvsLhhozB74m7G48jPlaoXGru2dX+3M9l
         kmPKNt2NnbXbZFnu94JLCjHy1uuKDpMFx2g8LlhvHi3N/p4g2gWuzdmTrlXCTwuPK1kK
         L2YLJbtWkkKBAo7GKO8gxsIhl6vjoNa7bT4oE0oPwVfv49xxwOGSPVffrFIn4AdgtmAc
         bHzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e6si312829oie.2.2021.01.22.05.34.50
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 05:34:50 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 461F511B3;
	Fri, 22 Jan 2021 05:34:50 -0800 (PST)
Received: from [10.37.8.28] (unknown [10.37.8.28])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DCC263F66E;
	Fri, 22 Jan 2021 05:34:47 -0800 (PST)
Subject: Re: [PATCH v5 3/6] kasan: Add report for async mode
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
 <20210121163943.9889-4-vincenzo.frascino@arm.com>
 <20210122131933.GD8567@gaia> <6ccde9db-98cd-5a56-b93d-0b79f4df56a7@arm.com>
Message-ID: <7a04c826-6351-7a28-867c-fe415aae8aae@arm.com>
Date: Fri, 22 Jan 2021 13:38:38 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <6ccde9db-98cd-5a56-b93d-0b79f4df56a7@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 1/22/21 1:27 PM, Vincenzo Frascino wrote:
>> It looks like the original kasan_report() prototype is declared in two
>> places (second one in mm/kasan/kasan.h). I'd remove the latter and try
>> to have a consistent approach for kasan_report() and
>> kasan_report_async().
>>
> Ok, I will remove it.

I just realized that the internal interface exposes the kasan_report() inte=
rface
for the GENERIC KASAN implementation. If I remove it that does not work any=
more:

/data1/Projects/LinuxKernel/linux-mte/mm/kasan/common.c: In function
=E2=80=98__kasan_check_byte=E2=80=99:
/data1/Projects/LinuxKernel/linux-mte/mm/kasan/common.c:503:17: error: impl=
icit
declaration of function =E2=80=98kasan_report=E2=80=99 [-Werror=3Dimplicit-=
function-declaration]
  503 |                 kasan_report((unsigned long)address, 1, false, ip);
      |                 ^~~~~~~~~~~~
/data1/Projects/LinuxKernel/linux-mte/mm/kasan/generic.c: In function
=E2=80=98check_region_inline=E2=80=99:
/data1/Projects/LinuxKernel/linux-mte/mm/kasan/generic.c:170:25: error: imp=
licit
declaration of function =E2=80=98kasan_report=E2=80=99 [-Werror=3Dimplicit-=
function-declaration]
  170 |                 return !kasan_report(addr, size, write, ret_ip);
      |                         ^~~~~~~~~~~~
/data1/Projects/LinuxKernel/linux-mte/mm/kasan/report_generic.c: In functio=
n
=E2=80=98__asan_report_load1_noabort=E2=80=99:
/data1/Projects/LinuxKernel/linux-mte/mm/kasan/report_generic.c:295:9: erro=
r:
implicit declaration of function =E2=80=98kasan_report=E2=80=99
[-Werror=3Dimplicit-function-declaration]
  295 |         kasan_report(addr, size, false, _RET_IP_);        \
      |         ^~~~~~~~~~~~
/data1/Projects/LinuxKernel/linux-mte/mm/kasan/report_generic.c:306:1: note=
: in
expansion of macro =E2=80=98DEFINE_ASAN_REPORT_LOAD=E2=80=99
  306 | DEFINE_ASAN_REPORT_LOAD(1);

To do that cleanly few things need to be shuffled around, Andrey or I can t=
ake
care of it but if you agree we shall look into this after -rc1.

Thanks!

--=20
Regards,
Vincenzo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7a04c826-6351-7a28-867c-fe415aae8aae%40arm.com.
