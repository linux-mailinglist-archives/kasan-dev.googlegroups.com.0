Return-Path: <kasan-dev+bncBAABB56Q53XQKGQEBAWQBFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 12463126753
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 17:42:33 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id v4sf3190676otp.21
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 08:42:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576773751; cv=pass;
        d=google.com; s=arc-20160816;
        b=pODQ972M3J+fdqOczFemiHjkfUliGoiUm0RHnf2rXs+CHNJWiXqICby2LeI+Nbc+YJ
         XCKzyPdzGVxAkEIwpfKdpUr4pwAM+t1Cm31OJ5Zj0h94JRd/Rr/uYOa/tlfhjYSlL6hU
         Krcm2kKawpIvXsZhxRKXGWXQo7V32zmfUC28CX0hPTSuxxWt4D/g5XEoTnkzm9DHfln3
         slcEeNKRb/4NBPjd7kLUHoG1jB3US6Vvc3nd/PmpnVm1qaOuIQiZoBWy8zDYFmuuOa1a
         t63u4Kr7gvzqS+qSz4rG9bg04OAzVqXD9GX4u1X7AzLu13cYVd8rLRYFCdpFWTj86Kc5
         hRXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:autocrypt:openpgp:from:references:cc:to:subject
         :ironport-sdr:sender:dkim-signature;
        bh=Wty/Iwykdgw0wwwpNoCB8x1kDD28RDJX+bEaU/JAl6M=;
        b=FGdcJ1TAlKYU47BUY4NlsdQuOmZE3uoqguSKQ6SSXkJqbYNhpa6+EoA6TLmjJwjvNz
         LAsaRFmSFhxr6czui5yB+vbAl+r4RykFLfuRBmEWxzyDq3j5Rc5gwtjW4q6f5crobiUR
         01CFqtLzSMDUU7MKpgBAhU1gOg9E19NkOwqs5gk55x8DuKVerR+7rXq3Yu3dtUAlOeGB
         k+hQJaSAIjPD0DHK76TnXxyx3Vmg5cnYB9rBPySooX+m2A3wROL5ZnNhZUQssHvGuWOj
         fwPssWWVA/SgF3G0n2dUb9Jokx0NMZrOHbuihyy4lbt46pJCO7zCaGftMJ0cG8ezXVgY
         UsJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=IJpVg6TD;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:subject:to:cc:references:from:openpgp:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Wty/Iwykdgw0wwwpNoCB8x1kDD28RDJX+bEaU/JAl6M=;
        b=AytYz7exAQUFKytg4Zq48vegFZDbWklTjqqrSHr/abLDSvJjgYYdWYORwzT0HV/FL7
         uzmKhddgYNGcQpbV3eP8ZlrWpwKMUQh4A0n1+7+rvT/IH+jaJasRfF9zXd59k+KWkRA2
         domDb5rnA8Wqx5LTELUoKlkvvECK9wr/l86dwqW2YSXguS2HcTVy5qxxAAXbvmos4Dcn
         0OWM/1dMTTumxYQcw3eNToEo0URzhbpK+9h5Wza+6J10gP7lv4cxEece+xubUbli+gzS
         K2s8B/DJeqJyDuVQ60try2YTduN6wsSNuQRzn9HCi++iZdA4XyjuPjdFnNqnwBFMhPFj
         dyUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:subject:to:cc:references
         :from:openpgp:autocrypt:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Wty/Iwykdgw0wwwpNoCB8x1kDD28RDJX+bEaU/JAl6M=;
        b=bTs8lwrrYu9ZEZBC3oWnvVdxI9kSdwiLUYDc6hXXj4hEFDNiWADg8DfQBwonXt4Xg6
         hBwV4MWGx/7e6ck6jdRpXApsjDO1RvAVyCjOqUSvOdE21y/cdvOfwOhBI9Dsj2ubXDqW
         25rm9qmGOHaiaCVIiehtxkYEYpZmgUEJILYsLcJNRDhanAz8EzWZlyAXNeIY7zN56X2f
         ihszQdabAx6fdx2RhCAwiGf6yBPEVqhul8pREENv9LEo4A1tc7CCN7RLQ54CVgcBYxoq
         1DhIjtMy7bWbgr/dnoYu0AUpnP/CfU1VX56sro6RoIlNBl5h6Cn67ecCgZ8xOjrkNX7b
         949Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUvo81itLm/njblA7dkGlPPXnjURXXUJ84LXdw8xVfaZgo8cLUj
	waUrqduH1GEU6eb6Co81tuc=
X-Google-Smtp-Source: APXvYqwJmQmHnmFPsF6i4jcqoNLirkdMX9vcYhYFoeGx8gw0aotlO/GxXKtBWTn4p2bedrA77yOw1A==
X-Received: by 2002:aca:dfc1:: with SMTP id w184mr2505712oig.76.1576773751546;
        Thu, 19 Dec 2019 08:42:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4a4:: with SMTP id l4ls1851694otd.11.gmail; Thu, 19
 Dec 2019 08:42:31 -0800 (PST)
X-Received: by 2002:a9d:6a98:: with SMTP id l24mr9931466otq.160.1576773751148;
        Thu, 19 Dec 2019 08:42:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576773751; cv=none;
        d=google.com; s=arc-20160816;
        b=FtpcgABz2Ji2RfZWJ9VfQgt21GtdKeAw+fqLidzxi6M2hPFRKNj73c0+J0c66IY8B+
         qSja4uHS/5twemRqzYVYK6YBhXMT/PqECYqvrjQ2e3EjCrjrPgZbRUqzGIXNdEMeEGpN
         hLd2HxRzfK4JFZpM3AxOU8dy9VbYhpHbtHsXrhwBoED+AhCmru+mzPKrNCoh9Vnso78d
         aqwkEVYS1SZKErPJik0qmoOgyUDvxxPteL1gR5BQHfqfB9ikOJIAD8RFx4G2EtgBDlyP
         5sFh+XeBMBheewpiTabZijBE7L54k49DgPgEnkoNBPyFFW7twNcxORYndjiL1Fi1D0ho
         NFyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject:ironport-sdr:dkim-signature;
        bh=OJ26J2uo1CqoYmUC9SOB33CKfUrdtwA8BWH5l/Goxkg=;
        b=tFvJXhSfWlSYsUcADhMPFNAzdGVQKUbj10Djq8RrWWTtiCmoTDA4i0SYMGHInsZZhW
         0c0svC1VIiYYNeM+lo5eanFWJw2RCZ2rmkv1CLngqZ2S1/Yw3Gcpq+7wY80Q/vdktKsf
         SteXJR7YXwl3KQlYB2qrDgZM4eqES0SwzbkHBEiMyvSSsVZNuGXHq7oxTXvn/qVxKTdp
         axxGe26iizVHuXZqPOBvgeGBaSiGZiZtY7/+JwW5queMoxjFzXwOQ2mU8xjFy4ASOUrJ
         p6bR7n/V2YN3GTxS1K+f23KrzyJwMLOap78PHN2JKD8CgW0HdkTFn7O4Nzk3knyh2y+X
         Fa2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=IJpVg6TD;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa3.hc3370-68.iphmx.com (esa3.hc3370-68.iphmx.com. [216.71.145.155])
        by gmr-mx.google.com with ESMTPS id w63si255518oif.2.2019.12.19.08.42.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Dec 2019 08:42:31 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as permitted sender) client-ip=216.71.145.155;
Received-SPF: None (esa3.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa3.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa3.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa3.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa3.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa3.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: PhxFWajh3PHyW3lkt6fACcwqqJ602mwhtS+p5T33XXGBBbipDbCHgbWVCb4dMrqevx7L7l9slv
 JwdLX+qZU/uK0xiu+JN5mGs4knLuv/JznuGQkjCqFJIyZRcA2BFo6bocuxrBCVk+/qofy0gNjb
 Sd9IQDfQE91HQCEMnu46ZcHvmVzf1n5FbtJY89fMs+vVHHSjgJJ1B5++ssk1frSvmcDiwZyLoQ
 kIymEsXUD+mxZMHYOXjZFz44hYmfI8l0C3QoYQDlqadUJOh7rgm+Snsjc4M6FPmWpXlJ+JvysO
 E9Y=
X-SBRS: 2.7
X-MesageID: 9933639
X-Ironport-Server: esa3.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,332,1571716800"; 
   d="scan'208";a="9933639"
Subject: Re: [RFC PATCH 1/3] x86/xen: add basic KASAN support for PV kernel
To: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>,
	<xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Stefano Stabellini <sstabellini@kernel.org>,
	George Dunlap <george.dunlap@citrix.com>, Ross Lagerwall
	<ross.lagerwall@citrix.com>, "sergey.dyasli@citrix.com >> Sergey Dyasli"
	<sergey.dyasli@citrix.com>
References: <20191217140804.27364-1-sergey.dyasli@citrix.com>
 <20191217140804.27364-2-sergey.dyasli@citrix.com>
 <934a2950-9079-138d-5476-5eabd84dfec5@suse.com>
From: Sergey Dyasli <sergey.dyasli@citrix.com>
Openpgp: preference=signencrypt
Autocrypt: addr=sergey.dyasli@citrix.com; keydata=
 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
Message-ID: <0844c8f9-3dd3-2313-5c23-bd967b218af2@citrix.com>
Date: Thu, 19 Dec 2019 16:42:25 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <934a2950-9079-138d-5476-5eabd84dfec5@suse.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=IJpVg6TD;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as
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

On 18/12/2019 09:24, J=C3=BCrgen Gro=C3=9F wrote:
> On 17.12.19 15:08, Sergey Dyasli wrote:
>> This enables to use Outline instrumentation for Xen PV kernels.
>>
>> KASAN_INLINE and KASAN_VMALLOC options currently lead to boot crashes
>> and hence disabled.
>>
>> Rough edges in the patch are marked with XXX.
>>
>> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
>> ---
>>   arch/x86/mm/init.c          | 14 ++++++++++++++
>>   arch/x86/mm/kasan_init_64.c | 28 ++++++++++++++++++++++++++++
>>   arch/x86/xen/Makefile       |  7 +++++++
>>   arch/x86/xen/enlighten_pv.c |  3 +++
>>   arch/x86/xen/mmu_pv.c       | 13 +++++++++++--
>>   arch/x86/xen/multicalls.c   | 10 ++++++++++
>>   drivers/xen/Makefile        |  2 ++
>>   kernel/Makefile             |  2 ++
>>   lib/Kconfig.kasan           |  3 ++-
>>   9 files changed, 79 insertions(+), 3 deletions(-)
>>
>> diff --git a/arch/x86/mm/init.c b/arch/x86/mm/init.c
>> index e7bb483557c9..0c98a45eec6c 100644
>> --- a/arch/x86/mm/init.c
>> +++ b/arch/x86/mm/init.c
>> @@ -8,6 +8,8 @@
>>   #include <linux/kmemleak.h>
>>   #include <linux/sched/task.h>
>>   +#include <xen/xen.h>
>> +
>>   #include <asm/set_memory.h>
>>   #include <asm/e820/api.h>
>>   #include <asm/init.h>
>> @@ -835,6 +837,18 @@ void free_kernel_image_pages(const char *what, void=
 *begin, void *end)
>>       unsigned long end_ul =3D (unsigned long)end;
>>       unsigned long len_pages =3D (end_ul - begin_ul) >> PAGE_SHIFT;
>>   +    /*
>> +     * XXX: skip this for now. Otherwise it leads to:
>> +     *
>> +     * (XEN) mm.c:2713:d157v0 Bad type (saw 8c00000000000001 !=3D exp e=
000000000000000) for mfn 36f40 (pfn 02f40)
>> +     * (XEN) mm.c:1043:d157v0 Could not get page type PGT_writable_page
>> +     * (XEN) mm.c:1096:d157v0 Error getting mfn 36f40 (pfn 02f40) from =
L1 entry 8010000036f40067 for l1e_owner d157, pg_owner d157
>> +     *
>> +     * and further #PF error: [PROT] [WRITE] in the kernel.
>> +     */
>> +    if (xen_pv_domain() && IS_ENABLED(CONFIG_KASAN))
>> +        return;
>> +
>=20
> I guess this is related to freeing some kasan page tables without
> unpinning them?

Your guess was correct. Turned out that early_top_pgt which I pinned and ma=
de RO
is located in .init section and that was causing issues. Unpinning it and m=
aking
RW again right after kasan_init() switches to use init_top_pgt seem to fix =
this
issue.

>=20
>>       free_init_pages(what, begin_ul, end_ul);
>>         /*
>> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
>> index cf5bc37c90ac..caee2022f8b0 100644
>> --- a/arch/x86/mm/kasan_init_64.c
>> +++ b/arch/x86/mm/kasan_init_64.c
>> @@ -13,6 +13,8 @@
>>   #include <linux/sched/task.h>
>>   #include <linux/vmalloc.h>
>>   +#include <xen/xen.h>
>> +
>>   #include <asm/e820/types.h>
>>   #include <asm/pgalloc.h>
>>   #include <asm/tlbflush.h>
>> @@ -20,6 +22,9 @@
>>   #include <asm/pgtable.h>
>>   #include <asm/cpu_entry_area.h>
>>   +#include <xen/interface/xen.h>
>> +#include <asm/xen/hypervisor.h>
>> +
>>   extern struct range pfn_mapped[E820_MAX_ENTRIES];
>>     static p4d_t tmp_p4d_table[MAX_PTRS_PER_P4D] __initdata __aligned(PA=
GE_SIZE);
>> @@ -305,6 +310,12 @@ static struct notifier_block kasan_die_notifier =3D=
 {
>>   };
>>   #endif
>>   +#ifdef CONFIG_XEN
>> +/* XXX: this should go to some header */
>> +void __init set_page_prot(void *addr, pgprot_t prot);
>> +void __init pin_pagetable_pfn(unsigned cmd, unsigned long pfn);
>> +#endif
>> +
>=20
> Instead of exporting those, why don't you ...
>=20
>>   void __init kasan_early_init(void)
>>   {
>>       int i;
>> @@ -332,6 +343,16 @@ void __init kasan_early_init(void)
>>       for (i =3D 0; pgtable_l5_enabled() && i < PTRS_PER_P4D; i++)
>>           kasan_early_shadow_p4d[i] =3D __p4d(p4d_val);
>>   +    if (xen_pv_domain()) {
>> +        /* PV page tables must have PAGE_KERNEL_RO */
>> +        set_page_prot(kasan_early_shadow_pud, PAGE_KERNEL_RO);
>> +        set_page_prot(kasan_early_shadow_pmd, PAGE_KERNEL_RO);
>> +        set_page_prot(kasan_early_shadow_pte, PAGE_KERNEL_RO);
>=20
> add a function doing that to mmu_pv.c (e.g. xen_pv_kasan_early_init())?

Sounds like a good suggestion, but new functions still need some header for
declarations (xen/xen.h?). And kasan_map_early_shadow() will need exporting
through kasan.h as well, but that's probably not an issue.

>=20
>> +
>> +        /* Add mappings to the initial PV page tables */
>> +        kasan_map_early_shadow((pgd_t *)xen_start_info->pt_base);
>> +    }
>> +
>>       kasan_map_early_shadow(early_top_pgt);
>>       kasan_map_early_shadow(init_top_pgt);
>>   }
>> @@ -369,6 +390,13 @@ void __init kasan_init(void)
>>                   __pgd(__pa(tmp_p4d_table) | _KERNPG_TABLE));
>>       }
>>   +    if (xen_pv_domain()) {
>> +        /* PV page tables must be pinned */
>> +        set_page_prot(early_top_pgt, PAGE_KERNEL_RO);
>> +        pin_pagetable_pfn(MMUEXT_PIN_L4_TABLE,
>> +                  PFN_DOWN(__pa_symbol(early_top_pgt)));
>=20
> and another one like xen_pv_kasan_init() here.

Now there needs to be a 3rd function to unpin early_top_pgt.

>=20
>> +    }
>> +
>>       load_cr3(early_top_pgt);
>>       __flush_tlb_all();
>>   diff --git a/arch/x86/xen/Makefile b/arch/x86/xen/Makefile
>> index 084de77a109e..102fad0b0bca 100644
>> --- a/arch/x86/xen/Makefile
>> +++ b/arch/x86/xen/Makefile
>> @@ -1,3 +1,10 @@
>> +KASAN_SANITIZE_enlighten_pv.o :=3D n
>> +KASAN_SANITIZE_enlighten.o :=3D n
>> +KASAN_SANITIZE_irq.o :=3D n
>> +KASAN_SANITIZE_mmu_pv.o :=3D n
>> +KASAN_SANITIZE_p2m.o :=3D n
>> +KASAN_SANITIZE_multicalls.o :=3D n
>> +
>>   # SPDX-License-Identifier: GPL-2.0
>>   OBJECT_FILES_NON_STANDARD_xen-asm_$(BITS).o :=3D y
>>   diff --git a/arch/x86/xen/enlighten_pv.c b/arch/x86/xen/enlighten_pv.c
>> index ae4a41ca19f6..27de55699f24 100644
>> --- a/arch/x86/xen/enlighten_pv.c
>> +++ b/arch/x86/xen/enlighten_pv.c
>> @@ -72,6 +72,7 @@
>>   #include <asm/mwait.h>
>>   #include <asm/pci_x86.h>
>>   #include <asm/cpu.h>
>> +#include <asm/kasan.h>
>>     #ifdef CONFIG_ACPI
>>   #include <linux/acpi.h>
>> @@ -1231,6 +1232,8 @@ asmlinkage __visible void __init xen_start_kernel(=
void)
>>       /* Get mfn list */
>>       xen_build_dynamic_phys_to_machine();
>>   +    kasan_early_init();
>> +
>>       /*
>>        * Set up kernel GDT and segment registers, mainly so that
>>        * -fstack-protector code can be executed.
>> diff --git a/arch/x86/xen/mmu_pv.c b/arch/x86/xen/mmu_pv.c
>> index c8dbee62ec2a..eaf63f1f26af 100644
>> --- a/arch/x86/xen/mmu_pv.c
>> +++ b/arch/x86/xen/mmu_pv.c
>> @@ -1079,7 +1079,7 @@ static void xen_exit_mmap(struct mm_struct *mm)
>>     static void xen_post_allocator_init(void);
>>   -static void __init pin_pagetable_pfn(unsigned cmd, unsigned long pfn)
>> +void __init pin_pagetable_pfn(unsigned cmd, unsigned long pfn)
>>   {
>>       struct mmuext_op op;
>>   @@ -1767,7 +1767,7 @@ static void __init set_page_prot_flags(void *add=
r, pgprot_t prot,
>>       if (HYPERVISOR_update_va_mapping((unsigned long)addr, pte, flags))
>>           BUG();
>>   }
>> -static void __init set_page_prot(void *addr, pgprot_t prot)
>> +void __init set_page_prot(void *addr, pgprot_t prot)
>>   {
>>       return set_page_prot_flags(addr, prot, UVMF_NONE);
>>   }
>> @@ -1943,6 +1943,15 @@ void __init xen_setup_kernel_pagetable(pgd_t *pgd=
, unsigned long max_pfn)
>>       if (i && i < pgd_index(__START_KERNEL_map))
>>           init_top_pgt[i] =3D ((pgd_t *)xen_start_info->pt_base)[i];
>>   +#ifdef CONFIG_KASAN
>> +    /*
>> +     * Copy KASAN mappings
>> +     * ffffec0000000000 - fffffbffffffffff (=3D44 bits) kasan shadow me=
mory (16TB)
>> +     */
>> +    for (i =3D 0xec0 >> 3; i < 0xfc0 >> 3; i++)
>> +        init_top_pgt[i] =3D ((pgd_t *)xen_start_info->pt_base)[i];
>> +#endif
>> +
>>       /* Make pagetable pieces RO */
>>       set_page_prot(init_top_pgt, PAGE_KERNEL_RO);
>>       set_page_prot(level3_ident_pgt, PAGE_KERNEL_RO);
>> diff --git a/arch/x86/xen/multicalls.c b/arch/x86/xen/multicalls.c
>> index 07054572297f..5e4729efbbe2 100644
>> --- a/arch/x86/xen/multicalls.c
>> +++ b/arch/x86/xen/multicalls.c
>> @@ -99,6 +99,15 @@ void xen_mc_flush(void)
>>                   ret++;
>>       }
>>   +    /*
>> +     * XXX: Kasan produces quite a lot (~2000) of warnings in a form of=
:
>> +     *
>> +     *     (XEN) mm.c:3222:d155v0 mfn 3704b already pinned
>> +     *
>> +     * during kasan_init(). They are benign, but silence them for now.
>> +     * Otherwise, booting takes too long due to printk() spam.
>> +     */
>> +#ifndef CONFIG_KASAN
>=20
> It might be interesting to identify the problematic page tables.
>=20
> I guess this would require some hacking to avoid the multicalls in order
> to identify which page table should not be pinned again.

I tracked this down to xen_alloc_ptpage() in mmu_pv.c:

			if (level =3D=3D PT_PTE && USE_SPLIT_PTE_PTLOCKS)
				__pin_pagetable_pfn(MMUEXT_PIN_L1_TABLE, pfn);

kasan_populate_early_shadow() is doing lots pmd_populate_kernel() with
kasan_early_shadow_pte (mfn of which is reported by Xen). Currently I'm not
sure how to fix that. Is it possible to check that pfn has already been pin=
ned
from Linux kernel? xen_page_pinned() seems to be an incorrect way to check =
that.

--
Thanks,
Sergey

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0844c8f9-3dd3-2313-5c23-bd967b218af2%40citrix.com.
