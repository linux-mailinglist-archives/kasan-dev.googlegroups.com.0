Return-Path: <kasan-dev+bncBAABB45V4HYAKGQETYKQDLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5663D136BAF
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 12:07:32 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id d6sf402507lfl.3
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 03:07:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578654451; cv=pass;
        d=google.com; s=arc-20160816;
        b=DJjB9G8nSx09Q7pHOAqCltgV3IxI6C2nHxo2AZIonhaCb09PRrhrobFM4WBtVAIdg8
         sfOcBYeAfZTefngu0ZPlLI1u5mKpl/UzE9DZTaQTL1zsiFuC+MhFC6i6QOEnt0qWWObG
         HXZx32Tg37IswmKwcMP+glFvg5+3hufOvVU9MMcQSrkMII8ZiGip525NtL5nY2EpzECT
         1jiEcSTnVMyQCq/2FUXW1aqsQcjCx8sS2unLuCcF1DB18mPjj0G4RmsblAj2iwdL1aMV
         LCFUq8VsLa1MilC5Pl1RxP/d9jzYf0/T+lt3hCG7EDncyUUAGpZwxUXEyQbeafnZMCek
         ec1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:autocrypt:from:references:cc:to:subject:ironport-sdr
         :sender:dkim-signature;
        bh=uvpE4nMWE/jZMfl9HdV0xKtZT3iiM6mnSE3V2p7P+EU=;
        b=McOYc5TEPDH2JUSCQ6YFSRr59FoVquKfHXGJTefe42E1yUcEnXctrPOQtNgCPb6eni
         +PYoONwMuomiXyGi7W0nOa9HMabtQ0jfOZQMDDEf3n0G4MnLxwJbSjXyf2jcRp/fNjgs
         5GpRZ9SWDYay3+p74lcKrGWjCTcqv4QAnXixxtL0V2g6dGoVNRH0VNwT2VkVRw7J8W7B
         04jlvOTFtiX7/6fvrOmAhfnvWRqn/DW0W8sEVy3eGxP/5SN/a5QHy5yG+Ar0qpI7EPiR
         djdOby06z7uHfA+9nXvTCr4S6gRztVMJonvyEHCz+Px1nVM8WCfa5BN2ilX/p5LfM9do
         E+uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=Mj6DcP4J;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uvpE4nMWE/jZMfl9HdV0xKtZT3iiM6mnSE3V2p7P+EU=;
        b=EsyweCezfr+wbE6B+vAqB/Ya1iF7RkWpvxRjIXJc3YzLcLFVhkMty47qJXzx7wF/6f
         Vv6Na8Ruau80YkQytGY1DFJ5UKi0r55Dffbnl9HW4BMxwzT5n6+Qxnw915ntc/tEiDSd
         mba0E7qdVwTli0bzOxwAl5iVg+b3Et709Hb1KHft5YPKLQVqP1+MqxolUG4r4xTFPZXb
         L+n2CzDbThxzbJz0CTpJgKxO+VqjeB/KKdtuOFZ1tWqe0yRdL2TmZzaL3bbUpCjNAbfq
         PLW/lyKS7U20BN/YvKDVKuADaDEBZbatkSptel/5MVfrbeixolFnAiiesUS4RI58JYoS
         yLGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:subject:to:cc:references
         :from:autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uvpE4nMWE/jZMfl9HdV0xKtZT3iiM6mnSE3V2p7P+EU=;
        b=rxXLFUbR2qSordnhSPUppGD+4yMoSwkXPtROM5m2768PzIBnqG5Jl/+ar+PrvQpik2
         BQmJ8w/cTcqlnZceH2toJJ0dJSo3GEanWfzp3XRxq/XFotXhxvuMKaZqGC8lRWiu1XEs
         /DOgJYa9qmNd4Bj1HKXjSKEn3R9+O4wi7AmZfyqY8VvNUhztapHdZ3WxOUKf71Y3CLJe
         EL5nHrAQr4oWbqvl4Vjo74f1OVLXFnIIZlwecDLEgYXu0tkj3GAj5JSiTEs3ajLNu/wc
         U9u0KUMc2CzUeE7x/17RLB8n9J+WQEg7KWZlPpTLZC+b6JtZ/vk8R//eUEAubLuo/c4Q
         l5Ug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUSpXeYJuDu4UOAFz5eF7CjnChn8VqxHewT+MNlAus4gb/nLhzb
	LZ5beNMSRqLaA+EJd13Jj80=
X-Google-Smtp-Source: APXvYqyVRcOTBHGTuOJRMT5oaPr+8xGYOmOTfdU5JdBhBxXVzLhMGPCFQxzeGmX/NveCYP53ESj5aw==
X-Received: by 2002:ac2:465e:: with SMTP id s30mr2041821lfo.134.1578654451831;
        Fri, 10 Jan 2020 03:07:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1051:: with SMTP id x17ls675603ljm.8.gmail; Fri, 10
 Jan 2020 03:07:31 -0800 (PST)
X-Received: by 2002:a2e:7816:: with SMTP id t22mr2311902ljc.161.1578654451322;
        Fri, 10 Jan 2020 03:07:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578654451; cv=none;
        d=google.com; s=arc-20160816;
        b=WYHzsSP/xnrCXDqm15AUtftHI/iIewE/VxcrbFLR8NP+4tqSViv9fW0ieicR4ZjpIf
         V/Eh4nYEEBZNsayKz4TTYikYPDT0qGHtv1blCdJfNqCdibSgC1REIN+VFzfD12O/nIHC
         NhPvjXXuIStMfAJ4Y4nUPOOMvX7z0oJTUefvOPAwiUXhvQD13+11AixHRo4re9ovhuXS
         fVhyiUw0P1jCLKczbtISQ12IwgYweVrRj05wCljZ5/M2WeORo1GlRXMqlpJwJ3GFDa2v
         /24tgNC0lXfmGefheaw1hMRnDaLQ+FYQvelTaDYO+y4jIR0RGx8cV4NA6frbbLQX6wCt
         X2hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:dkim-signature;
        bh=us/K4sjkOtMDM0n6KiViMOUKwMnpNitr6DPEnfXoyPk=;
        b=IEe/U41wsk0JLas3YzWee22F+62WfDA1r0p/jVt/baGMDUwn/zKbm5VUIMpABjRiMb
         BdsWNl55bQAQ8sNvF7pKf/5QnkFvyT4ncW7bHkMvuPx37ADkCaI7zLnMvNHmTsHU9YLn
         4E6AHwUf5heGWkomICnigEiAMrzVpsD/8N2Mpa29SHnw/QiAw9e/Igm00vHKiV+XtLRA
         ZSnjHMfuLkFyAghReI2zuQzVbQytFJBr8C6KwGhIG/fPHbObyM6jHCfArW1NGrrayDwN
         /ZXujkZtAy6XDfOCYc/R6kfpZ2g0J+dPPAL6Ap7gNgAhM/w0CKLTm0qtRCyDSHP85s32
         eAWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=Mj6DcP4J;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa5.hc3370-68.iphmx.com (esa5.hc3370-68.iphmx.com. [216.71.155.168])
        by gmr-mx.google.com with ESMTPS id x5si91985ljh.5.2020.01.10.03.07.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jan 2020 03:07:31 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) client-ip=216.71.155.168;
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa5.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: twpcSmXpC1qCNCFAijV/X2KEvYkOgAGoh1Cqqhl5VEHfHZ3/f6lq8R2JA7J7utgKQoUnpZXwbN
 rQCOKXw2lHYzt6NEBUHJWRHyGPKhCZgoK5+eIprHYSQ2XuY9bZutptCiYzSpcSYx9nheSDYoZK
 KxGfjTMT0gZ7uhrfyIrY5Z86NKvvtTH2xJ5B0LrQOtHfKiJIKnVWxgbGEN6FwKIPqQ/inn3SMA
 TH9pHg4lXICcighXX2GlFnG1lCyg6Y6jrFV+9mlGG+0xW5k5MsHQbL8jSvqCZsco3BuFq1wthr
 Bzs=
X-SBRS: 2.7
X-MesageID: 11108479
X-Ironport-Server: esa5.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,416,1571716800"; 
   d="scan'208";a="11108479"
Subject: Re: [PATCH v1 2/4] x86/xen: add basic KASAN support for PV kernel
To: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>,
	<xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Stefano Stabellini <sstabellini@kernel.org>,
	George Dunlap <george.dunlap@citrix.com>, Ross Lagerwall
	<ross.lagerwall@citrix.com>, Andrew Morton <akpm@linux-foundation.org>,
	"sergey.dyasli@citrix.com >> Sergey Dyasli" <sergey.dyasli@citrix.com>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
 <20200108152100.7630-3-sergey.dyasli@citrix.com>
 <0c968669-2b21-b772-dba8-f674057bd6e7@suse.com>
From: Sergey Dyasli <sergey.dyasli@citrix.com>
Autocrypt: addr=sergey.dyasli@citrix.com; keydata=
 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
Message-ID: <e5853285-8c18-8c9d-2d40-7e7115c8d3cf@citrix.com>
Date: Fri, 10 Jan 2020 11:07:18 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <0c968669-2b21-b772-dba8-f674057bd6e7@suse.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=Mj6DcP4J;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as
 permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=citrix.com
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

On 09/01/2020 09:15, J=C3=BCrgen Gro=C3=9F wrote:
> On 08.01.20 16:20, Sergey Dyasli wrote:
>> This enables to use Outline instrumentation for Xen PV kernels.
>>
>> KASAN_INLINE and KASAN_VMALLOC options currently lead to boot crashes
>> and hence disabled.
>>
>> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
>> ---
>> RFC --> v1:
>> - New functions with declarations in xen/xen-ops.h
>> - Fixed the issue with free_kernel_image_pages() with the help of
>>    xen_pv_kasan_unpin_pgd()
>> ---
>>   arch/x86/mm/kasan_init_64.c | 12 ++++++++++++
>>   arch/x86/xen/Makefile       |  7 +++++++
>>   arch/x86/xen/enlighten_pv.c |  3 +++
>>   arch/x86/xen/mmu_pv.c       | 39 +++++++++++++++++++++++++++++++++++++
>>   drivers/xen/Makefile        |  2 ++
>>   include/xen/xen-ops.h       |  4 ++++
>>   kernel/Makefile             |  2 ++
>>   lib/Kconfig.kasan           |  3 ++-
>>   8 files changed, 71 insertions(+), 1 deletion(-)
>>
>> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
>> index cf5bc37c90ac..902a6a152d33 100644
>> --- a/arch/x86/mm/kasan_init_64.c
>> +++ b/arch/x86/mm/kasan_init_64.c
>> @@ -13,6 +13,9 @@
>>   #include <linux/sched/task.h>
>>   #include <linux/vmalloc.h>
>>   +#include <xen/xen.h>
>> +#include <xen/xen-ops.h>
>> +
>>   #include <asm/e820/types.h>
>>   #include <asm/pgalloc.h>
>>   #include <asm/tlbflush.h>
>> @@ -332,6 +335,11 @@ void __init kasan_early_init(void)
>>       for (i =3D 0; pgtable_l5_enabled() && i < PTRS_PER_P4D; i++)
>>           kasan_early_shadow_p4d[i] =3D __p4d(p4d_val);
>>   +    if (xen_pv_domain()) {
>> +        pgd_t *pv_top_pgt =3D xen_pv_kasan_early_init();
>
> You are breaking the build with CONFIG_XEN_PV undefined here.

Right, the following is needed:

diff --git a/include/xen/xen-ops.h b/include/xen/xen-ops.h
index 91d66520f0a3..3d20f000af12 100644
--- a/include/xen/xen-ops.h
+++ b/include/xen/xen-ops.h
@@ -241,8 +241,14 @@ static inline void xen_preemptible_hcall_end(void)

 #endif /* CONFIG_PREEMPT */

+#if defined(CONFIG_XEN_PV)
 pgd_t *xen_pv_kasan_early_init(void);
 void xen_pv_kasan_pin_pgd(pgd_t *pgd);
 void xen_pv_kasan_unpin_pgd(pgd_t *pgd);
+#else
+static inline pgd_t *xen_pv_kasan_early_init(void) { return NULL; }
+static inline void xen_pv_kasan_pin_pgd(pgd_t *pgd) { }
+static inline void xen_pv_kasan_unpin_pgd(pgd_t *pgd) { }
+#endif /* defined(CONFIG_XEN_PV) */

 #endif /* INCLUDE_XEN_OPS_H */

--
Thanks,
Sergey

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e5853285-8c18-8c9d-2d40-7e7115c8d3cf%40citrix.com.
