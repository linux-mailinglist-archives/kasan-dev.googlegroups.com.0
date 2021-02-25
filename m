Return-Path: <kasan-dev+bncBC32535MUICBBG5236AQMGQETJ6DXEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id D04CA32547F
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 18:23:40 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id f7sf4316550pgp.19
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 09:23:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614273819; cv=pass;
        d=google.com; s=arc-20160816;
        b=oLd311ZZqRPBMCI1zHycalauQF14Q6YrnSj9XLZHcnVupcSdqIlHfHZTZYPdvc1/s+
         qPZjJHg3eilGZmfu1iybfxIoJIKXeT5dQex0WTKYkWWfa9PAUUv4qmyP0kz/UpYLGXwD
         D15zdOvh75U7zvPbY8/E30iYir7WAe/bBDeZen6nCn6L/sm36VWQG2k8e5Q5UPfYE83W
         cZ17bhSv9xRtOXV0DzexmEEW8WUUBDqAQqx3zxN6iAPdq48m987eWgeEEncF/aXyaS1d
         2fuBWiKeN+uqM8M8tyAARAPmsCTA+ojdcxUJozTc86KCehM9n1dlv453OG87yyTubS20
         mMEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:subject:organization:from:references:cc:to:sender
         :dkim-signature;
        bh=VXA/aHVuuBZlOi3IFs4a4r16C51gJJ2kh6mdghXiG5E=;
        b=kWFvVsQDrkYRSAXz/lii9iGi3wpEeDXYQE4XYNG1zBsDQDgfrAybA6+gqthwpZYkmO
         LVfSToRhsfC9oVEaaRMOqBKu86CQ5sP7Gk55xAmipzDhCpwuwJ8DuhnMOIgJZNNVKPjp
         FAPqBISGjV+emBFCn05HEfGOxsLp6fRBYUJb56XFjd2Xu7ligsxchKVbmcIeQw2w3/rK
         lPEfbzHT53uvD5lYsxPgDwplfh1WIpGJDfZI/A/Uua/SdGflND+Gri7qvXGS8z+ag9Hl
         1O4mKqAWort8M0zpxgbWV2T9+8DVFvRTtMDYoei6QHflUZx3Y7kKES+WQGlzRugrnOE9
         rGLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MPWTzdfb;
       spf=pass (google.com: domain of david@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:to:cc:references:from:organization:subject:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VXA/aHVuuBZlOi3IFs4a4r16C51gJJ2kh6mdghXiG5E=;
        b=svGWkzLnl3VxTtBX0ExJ7P/658zgH3pel8OVCj8Q/3GBFbvVqsvw3MWFepXsFECvKJ
         lUnQi/osIOtGQj6CAnpsse2BHwwwiw70vNe089pzd5v1mCL4xKtQuK9py2ZrKvE27diJ
         nvBRKYSuRfYkGnloMK9c1AHkx3BFOV9CEZn+adxI4hzhY69Fkx2dOOeWmPhEUHPZO+2v
         L8upQ2e1z5gO04mVb9vO+lSpIlQwt+ZF8gqPkIRFW71/F+dXjd11MT2Skca/xzClaGd5
         iqVjjbek6xB76PjfnccKyaSdTCdvKP3e2m/hv+lMiA0xnXd1clDBaCkRxnyNtxA4EctG
         7IqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:to:cc:references:from:organization
         :subject:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VXA/aHVuuBZlOi3IFs4a4r16C51gJJ2kh6mdghXiG5E=;
        b=VT0uEYbs9GGZZNXnd8V7zKMfPvpGzIgAS66S0q3sJe2W/Frk6WS2T4Mj9qFcOYJNhD
         mqlD0EWbSwdcior3/sbPXZ1GPxHlGxt1LFaEVBqZiMA9RwgLMJu2B+XbHifBCwDBxfJX
         zQxJJ5SMGIBJ17+uTuyseRWxSTLtKpSy1/36kC4xhGIx6ObPKIbKCz8B2cU2fVJZtwz5
         7ft119FXEZ6lyjsbSum8CfkqpEfBs+Ab+PhKsdWOp7wDxV/Qdqt/Iflq5UROjN+nvC/6
         XtHf6ckFUCH1j9d/gQWKSghW6ujwTDYiKye2nhSOhORfV8mDlngHBSMvVXQDBTbAXpJY
         /jGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5301gjcqB6XzC42jZEUFRv+QaFc1TPkuLjPq5+z+iJDJmY7/ERMz
	hQXfV0SqUH/L0RN9hXt2cwg=
X-Google-Smtp-Source: ABdhPJzSLcQiBWL555ifzbx6LdwLXN4rHL1r8HrC8MQT06PfdbbAbGqoXkjJEWtMorhkkpoQzz8ZPg==
X-Received: by 2002:a17:902:7404:b029:e4:503b:f83d with SMTP id g4-20020a1709027404b02900e4503bf83dmr3909277pll.35.1614273819414;
        Thu, 25 Feb 2021 09:23:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2c8c:: with SMTP id s134ls2751745pfs.6.gmail; Thu, 25
 Feb 2021 09:23:38 -0800 (PST)
X-Received: by 2002:a63:ce4d:: with SMTP id r13mr3816463pgi.204.1614273818548;
        Thu, 25 Feb 2021 09:23:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614273818; cv=none;
        d=google.com; s=arc-20160816;
        b=y7RzZbhJc6dMLL1/Xf3LiTaXmlJlYGvm5bEbv2Yqy2rFyChFBnRduc9+iQuOlkYWbF
         579jkIG0vUsJa47kEYQMasHWZMcIptEu0IawugdqzTVkP8p3d9agXzbDU82Yoiy48g19
         Ik2NBjr3YrxbaND5OzFYNLToktOxqDbi8dICiaZZMvWOl1iieFO4iiADSd1Ce4YZWd/t
         xQmGn0JSVcosGmmZhXrp7I7obyP83XwnpOFQXevEPPgfQT4OksYyHWtLOS+a6ThF2Z1n
         FEK1JQ05ykxTfnVwNhMv10zkpoOkTLztrh6U5VMCRvJFNgAVLoOcevY2rxdpN+p7ecG9
         dqmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:subject:organization:from:references:cc
         :to:dkim-signature;
        bh=uQvQXiSXUcQBP00bQ8yjoMaRgmaZ9xX5MhFh8znqtjI=;
        b=IwwZxIDRXrxsjsgK3rWkLboqju6S1bX3rPbGjHulNcxZTxMXUrD9nKTCq7MrTWLPP+
         hc763c3f8R4OuhwEYxIw/xp34sptTZtbIPZLorN9jJvcc3spdZPNIx0cCe5yqIiESDTZ
         Nij9gv9QgfkWbFo6pRSewEf8BZdBzmk0nn9kYRWHVPUXk6rIvcfIs73didXW8s+cRiMJ
         Rz6W9PO8o8h33xFZbMh6FkBlN54bmNqutMK7O3Sy8vi0ppI3MPD2LDNcZ5DWwy9uMMSZ
         O4Gh5Qb02fO8tWsxobyUObsoIvm9HqiMp6vrLvBcHniN0E0c7cT3ZM/Tx0Alga60ULVM
         JJvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MPWTzdfb;
       spf=pass (google.com: domain of david@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [216.205.24.124])
        by gmr-mx.google.com with ESMTPS id f16si317808plj.0.2021.02.25.09.23.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Feb 2021 09:23:38 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 216.205.24.124 as permitted sender) client-ip=216.205.24.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-213-q9qyAeirNUCTGppSnwk_eQ-1; Thu, 25 Feb 2021 12:23:32 -0500
X-MC-Unique: q9qyAeirNUCTGppSnwk_eQ-1
Received: from smtp.corp.redhat.com (int-mx02.intmail.prod.int.phx2.redhat.com [10.5.11.12])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id C754179EC0;
	Thu, 25 Feb 2021 17:23:29 +0000 (UTC)
Received: from [10.36.114.58] (ovpn-114-58.ams2.redhat.com [10.36.114.58])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 79BED60BE5;
	Thu, 25 Feb 2021 17:23:25 +0000 (UTC)
To: George Kennedy <george.kennedy@oracle.com>,
 Mike Rapoport <rppt@linux.ibm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Dmitry Vyukov <dvyukov@google.com>, Konrad Rzeszutek Wilk
 <konrad@darnok.org>, Will Deacon <will.deacon@arm.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Christoph Hellwig
 <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>, Dhaval Giani <dhaval.giani@oracle.com>
References: <20210223200914.GH1741768@linux.ibm.com>
 <af06267d-00cd-d4e0-1985-b06ce7c993a3@oracle.com>
 <20210223213237.GI1741768@linux.ibm.com>
 <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
 <20210224103754.GA1854360@linux.ibm.com>
 <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
 <20210225085300.GB1854360@linux.ibm.com>
 <9973d0e2-e28b-3f8a-5f5d-9d142080d141@oracle.com>
 <20210225145700.GC1854360@linux.ibm.com>
 <bb444ddb-d60d-114f-c2fe-64e5fb34102d@oracle.com>
 <20210225160706.GD1854360@linux.ibm.com>
 <dcf821e8-768f-1992-e275-2f1ade405025@oracle.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat GmbH
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
Message-ID: <24e43280-1442-3c4e-aa57-ac84b987aa58@redhat.com>
Date: Thu, 25 Feb 2021 18:23:24 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
MIME-Version: 1.0
In-Reply-To: <dcf821e8-768f-1992-e275-2f1ade405025@oracle.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.12
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=MPWTzdfb;
       spf=pass (google.com: domain of david@redhat.com designates
 216.205.24.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 25.02.21 17:31, George Kennedy wrote:
> : rsdp_address=3Dbfbfa014
> [=C2=A0=C2=A0=C2=A0 0.066612] ACPI: RSDP 0x00000000BFBFA014 000024 (v02 B=
OCHS )
> [=C2=A0=C2=A0=C2=A0 0.067759] ACPI: XSDT 0x00000000BFBF90E8 00004C (v01 B=
OCHS BXPCFACP
> 00000001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> [=C2=A0=C2=A0=C2=A0 0.069470] ACPI: FACP 0x00000000BFBF5000 000074 (v01 B=
OCHS BXPCFACP
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.071183] ACPI: DSDT 0x00000000BFBF6000 00238D (v01 B=
OCHS BXPCDSDT
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.072876] ACPI: FACS 0x00000000BFBFD000 000040
> [=C2=A0=C2=A0=C2=A0 0.073806] ACPI: APIC 0x00000000BFBF4000 000090 (v01 B=
OCHS BXPCAPIC
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.075501] ACPI: HPET 0x00000000BFBF3000 000038 (v01 B=
OCHS BXPCHPET
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.077194] ACPI: BGRT 0x00000000BE49B000 000038 (v01 I=
NTEL EDK2
> 00000002=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> [=C2=A0=C2=A0=C2=A0 0.078880] ACPI: iBFT 0x00000000BE453000 000800 (v01 B=
OCHS BXPCFACP
> 00000000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000)


Can you explore the relevant area using the page-flags tools (located in=20
Linux src code located in tools/vm/page-flags.c)


./page-types -L -r -a 0xbe490,0xbe4a0

--=20
Thanks,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/24e43280-1442-3c4e-aa57-ac84b987aa58%40redhat.com.
