Return-Path: <kasan-dev+bncBAABBAVI6OSQMGQEGCLIZLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D85C75E03B
	for <lists+kasan-dev@lfdr.de>; Sun, 23 Jul 2023 09:17:24 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-26814a011desf18373a91.0
        for <lists+kasan-dev@lfdr.de>; Sun, 23 Jul 2023 00:17:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690096642; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jozrxc9kU/Fo/FPKWxDNqIOnnebNhL41m5fGXiuYvozJ1VGr35QJuhswS0t6pzpHpI
         gOTEhTwmxMOaGVnmMYq6qbEC81osDPW9UxmGskB20OhVlfeaGaWonxHqxhgKepgV9mLy
         mVsrWZ7xu0H1j4oTU5z5OGfo0ye2dINpUxz458lShmHr0+/EIXR9TE6I1XcDc7FF3+9f
         u0QotcYSpmURCQGfRpXrjAw8kxIAf5Ydn7XbAcEny2RUpjUUfonAzbBWDB3VcCognbxS
         1a6ENxSRWEtv80iMO2zofNvb4gPJWnu4S8w/RjBeDTFLFkJB/dau0rvLMbogXd7gWF3X
         PWxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=HGlC+q1ISPDruSATnjN/mP38D9AO8CW5o+c5ala3uFg=;
        fh=PtPKd2tcWuVtu+yL18J6sFXYyO2PPLg/Xbo07e2JVhk=;
        b=v8Gto1VTOwsG5S3LnEwtwF4ceTokofkrdyErJ3oOD9VYxJvF/DkzYDlutdoXSw2xF/
         rVA6sOjAPLiL2/X/+7WGW45PIixYOS907ZXLsLttiec11vjAS8YY+0SgXvxfGxI+OVqH
         iyM9wM+jo3CnDNvchNGk25CG4S3H2pP8zakX+MsBBxnhKaVMHC7uqtp9XDODQVKsDtWl
         N4mZWj495+pzfl04H53Y1vORGv/zUGKexThW2BIkFLPVuXHTIco8K3q8zqifKqaYwRyc
         7IRMmjpOtcUmZPHHa+C4JCKdYYCdDU/gt35OYmI53h5a8YzpwQUUdcNBLzwX7SUrH1Ry
         2Hyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690096642; x=1690701442;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HGlC+q1ISPDruSATnjN/mP38D9AO8CW5o+c5ala3uFg=;
        b=XBhVL8Cl4vw8PLCw0TmANEHVcpks3O1yh1FytzSsPd3yWyR1/i/+Bw60L4mkF5P6Aq
         HJEd3JjUjwL2rgv0juvHnnGlK6M0CtGdWgI6FSCzpEAa7ClnG0PPn5CLk5c1CZVk1K1y
         rBE1LSWabxmSWgQwFH2qhQM5MWr3+xRH+ZqAd6iCycrBmDOzTRFjvjAd/gxwtScWRyjf
         IhYllx9t1txmMSmjiclTsX+0IeZ0saSPjZ9roSS91dZMgH7J3XhguTo/jmKzQ2wqxEfq
         8eRAivaHJ60PeF9BbZmTDNnWZWowtxBQv3fStKfbtJNdZID5eW1EZFGyZIGwkNk4SPUp
         huSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690096642; x=1690701442;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HGlC+q1ISPDruSATnjN/mP38D9AO8CW5o+c5ala3uFg=;
        b=VR1mnI3BmynQxfOG3ZmB8QYqHatAsYn4BoeJmk5FkWBTJFEgHNdKnDuu4V20AYSrCM
         4eGhKLvICepVRRJYuWfrsSU+iK3qjIih1eav0EIBpCgMdw5YUw1wKWn6LJxTT+DqKtW1
         xTRHL9oD8ad72AqtNycisXs6ADX8kobbqkO5uoD59sw2KdSQXOr499S4GeJ8NI0Qc4PD
         73+u/enckXlilzeHOxofB5SZPQxqrlIodaF7Yx+55c5f9S9G3KMsdroCVrIezW9kbxTx
         Z/jk8kbnNZsWjdfBfz2OexZy/9zxxaTCWb209OaCPC4zx7/M2sAGM2UegZiJJ7c0Tvtx
         I81A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLb4OodQoZETbFP8os4mpVXPLbOwgZIpgsb1unzEbv1TWTmLHYyG
	lDTG055jKzN6NoP0JTT9pzg=
X-Google-Smtp-Source: APBJJlGA5uca5A3IwDBnDSsULtltzYB8q/XZFkpTD1Wp4eWPtzAGRpNn4a7WclVmZTbzpB1TETQHVA==
X-Received: by 2002:a17:90b:4b88:b0:263:a37:fcc3 with SMTP id lr8-20020a17090b4b8800b002630a37fcc3mr5901425pjb.5.1690096642341;
        Sun, 23 Jul 2023 00:17:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1991:b0:25e:a03a:113a with SMTP id
 mv17-20020a17090b199100b0025ea03a113als446861pjb.1.-pod-prod-01-us; Sun, 23
 Jul 2023 00:17:21 -0700 (PDT)
X-Received: by 2002:a17:90a:fe15:b0:260:fe48:360e with SMTP id ck21-20020a17090afe1500b00260fe48360emr5575781pjb.29.1690096641596;
        Sun, 23 Jul 2023 00:17:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690096641; cv=none;
        d=google.com; s=arc-20160816;
        b=ZE+u84awSujdRQJclaWXGus0e4vgfppqdMpQNrYtpCs7ykczazPvWmWilbb8hnmJ/z
         8mJueTe9sl5O4xIeNlsA24V8umyi7L9VwszbDCOefKwI9BjNZOzWqJ2kUnOSJdY27Z3O
         skPpZLQ+ReyO5phMcHunfIzVtivHldgSGZKztCYBkFXR+7rArw0xztPCcIHeCJtlQkSn
         w4VJ/uQz3viRlpvie7kOtCg8q3Ykbp8P5O76NZeXKaUIIuL0ifLb1QsdF7X0f8FfgxmF
         e/oZ2e7NrZlwc2Yv09f9sia2q4iyfier+nl6VcN5TurNnt+WTUI1kSJDRuYSU9rFam2l
         jIDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from;
        bh=D8mYybgbLg6Tuhm+M8Sxa1OjqGjBnGOw8Xs2qE+56FA=;
        fh=PtPKd2tcWuVtu+yL18J6sFXYyO2PPLg/Xbo07e2JVhk=;
        b=bjwWf9Yxdvq+m48Kpr2EIRAQEMlnxCDTjaUlTP2VtKB7hMewSt6u6VEw9wF6IXbYxv
         1z+j0u9eJNARfhZ+8jRG2o0O3/rMt6Z9DKzerdfite/rLN63Fcb8ugQbnNSadn2WwSGG
         vnDGIcgMsc9cghjh6C8n4uvWGB8KM0BcYlBqe1/aFM4CzcHNvrv2gfU228HgT6KjEr9K
         Htan4lcWhLa3r4wRWz4ZkkUTFp6w0NKJHhb99n2oQf1U6YxEmwJWiTM+K/fK0n8Q4IUb
         7tBp15c0rQL+mctPL0ssYl5vyj0gW6yEkfPE70VCjkyR6VvYjTQxTQjkcbhlLdKL+3DW
         8Dow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id nw3-20020a17090b254300b0025c1096a7a4si501267pjb.2.2023.07.23.00.17.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 23 Jul 2023 00:17:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: a2b122842dc9453ab2efd54da6651013-20230723
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:d6aab440-a297-4c57-817b-f2ac0f74afac,IP:15,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:0
X-CID-INFO: VERSION:1.1.28,REQID:d6aab440-a297-4c57-817b-f2ac0f74afac,IP:15,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:0
X-CID-META: VersionHash:176cd25,CLOUDID:3276ee87-44fb-401c-8de7-6a5572f1f5d5,B
	ulkID:230723151715MPCJT8N8,BulkQuantity:0,Recheck:0,SF:17|19|44|24|102,TC:
	nil,Content:0,EDM:-3,IP:-2,URL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OS
	I:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI,
	TF_CID_SPAM_ULS
X-UUID: a2b122842dc9453ab2efd54da6651013-20230723
X-User: lienze@kylinos.cn
Received: from ubuntu [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1175236445; Sun, 23 Jul 2023 15:17:11 +0800
From: Enze Li <lienze@kylinos.cn>
To: Huacai Chen <chenhuacai@kernel.org>
Cc: kernel@xen0n.name,  loongarch@lists.linux.dev,  glider@google.com,
  elver@google.com,  akpm@linux-foundation.org,
  kasan-dev@googlegroups.com,  linux-mm@kvack.org,  zhangqing@loongson.cn,
  yangtiezhu@loongson.cn,  dvyukov@google.com
Subject: Re: [PATCH 1/4] LoongArch: mm: Add page table mapped mode support
In-Reply-To: <CAAhV-H4+8_gBMMdLhx=uEAsCN5wK7kFONsKDyGPqm0kxW8FU=A@mail.gmail.com>
	(Huacai Chen's message of "Fri, 21 Jul 2023 10:21:38 +0800")
References: <20230719082732.2189747-1-lienze@kylinos.cn>
	<20230719082732.2189747-2-lienze@kylinos.cn>
	<CAAhV-H5pWmd2owMgH9hiqxoWpeAOKGv_=j2V-urA+D87_uCMyg@mail.gmail.com>
	<87pm4mf1xl.fsf@kylinos.cn>
	<CAAhV-H4+8_gBMMdLhx=uEAsCN5wK7kFONsKDyGPqm0kxW8FU=A@mail.gmail.com>
Date: Sun, 23 Jul 2023 15:17:05 +0800
Message-ID: <87lef7ayha.fsf@kylinos.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: lienze@kylinos.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as
 permitted sender) smtp.mailfrom=lienze@kylinos.cn
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

On Fri, Jul 21 2023 at 10:21:38 AM +0800, Huacai Chen wrote:

> On Fri, Jul 21, 2023 at 10:12=E2=80=AFAM Enze Li <lienze@kylinos.cn> wrot=
e:
>>
>> On Wed, Jul 19 2023 at 11:29:37 PM +0800, Huacai Chen wrote:
>>
>> > Hi, Enze,
>> >
>> > On Wed, Jul 19, 2023 at 4:34=E2=80=AFPM Enze Li <lienze@kylinos.cn> wr=
ote:
>> >>
>> >> According to LoongArch documentation online, there are two types of a=
ddress
>> >> translation modes: direct mapped address translation mode (direct map=
ped mode)
>> >> and page table mapped address translation mode (page table mapped mod=
e).
>> >>
>> >> Currently, the upstream code only supports DMM (Direct Mapped Mode).
>> >> This patch adds a function that determines whether PTMM (Page Table
>> >> Mapped Mode) should be used, and also adds the corresponding handler
>> >> funcitons for both modes.
>> >>
>> >> For more details on the two modes, see [1].
>> >>
>> >> [1]
>> >> https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.=
html#virtual-address-space-and-address-translation-mode
>> >>
>> >> Signed-off-by: Enze Li <lienze@kylinos.cn>
>> >> ---
>> >>  arch/loongarch/include/asm/page.h    | 10 ++++++++++
>> >>  arch/loongarch/include/asm/pgtable.h |  6 ++++++
>> >>  arch/loongarch/mm/pgtable.c          | 25 +++++++++++++++++++++++++
>> >>  3 files changed, 41 insertions(+)
>> >>
>> >> diff --git a/arch/loongarch/include/asm/page.h b/arch/loongarch/inclu=
de/asm/page.h
>> >> index 26e8dccb6619..05919be15801 100644
>> >> --- a/arch/loongarch/include/asm/page.h
>> >> +++ b/arch/loongarch/include/asm/page.h
>> >> @@ -84,7 +84,17 @@ typedef struct { unsigned long pgprot; } pgprot_t;
>> >>  #define sym_to_pfn(x)          __phys_to_pfn(__pa_symbol(x))
>> >>
>> >>  #define virt_to_pfn(kaddr)     PFN_DOWN(PHYSADDR(kaddr))
>> >> +
>> >> +#ifdef CONFIG_64BIT
>> >> +#define virt_to_page(kaddr)                                         =
   \
>> >> +({                                                                  =
   \
>> >> +       is_PTMM_addr((unsigned long)kaddr) ?                         =
   \
>> >> +       PTMM_virt_to_page((unsigned long)kaddr) :                    =
   \
>> >> +       DMM_virt_to_page((unsigned long)kaddr);                      =
   \
>> >> +})
>> > 1, Rename these helpers to
>> > is_dmw_addr()/dmw_virt_to_page()/tlb_virt_to_page() will be better.
>> > 2, These helpers are so simple so can be defined as inline function or
>> > macros in page.h.
>>
>> Hi Huacai,
>>
>> Except for tlb_virt_to_page(), the remaining two modifications are easy.
>>
>> I've run into a lot of problems when trying to make tlb_virt_to_page()
>> as a macro or inline function.  That's because we need to export this
>> symbol in order for it to be used by the module that called the
>> virt_to_page() function, other wise, we got the following errors,
>>
>> -----------------------------------------------------------------------
>>   MODPOST Module.symvers
>> ERROR: modpost: "tlb_virt_to_page" [fs/hfsplus/hfsplus.ko] undefined!
>> ERROR: modpost: "tlb_virt_to_page" [fs/smb/client/cifs.ko] undefined!
>> ERROR: modpost: "tlb_virt_to_page" [crypto/gcm.ko] undefined!
>> ERROR: modpost: "tlb_virt_to_page" [crypto/ccm.ko] undefined!
>> ERROR: modpost: "tlb_virt_to_page" [crypto/essiv.ko] undefined!
>> ERROR: modpost: "tlb_virt_to_page" [lib/crypto/libchacha20poly1305.ko] u=
ndefined!
>> ERROR: modpost: "tlb_virt_to_page" [drivers/gpu/drm/ttm/ttm.ko] undefine=
d!
>> ERROR: modpost: "tlb_virt_to_page" [drivers/gpu/drm/amd/amdgpu/amdgpu.ko=
] undefined!
>> ERROR: modpost: "tlb_virt_to_page" [drivers/scsi/iscsi_tcp.ko] undefined=
!
>> ERROR: modpost: "tlb_virt_to_page" [drivers/scsi/qla2xxx/qla2xxx.ko] und=
efined!
>> WARNING: modpost: suppressed 44 unresolved symbol warnings because there=
 were too many)
>> -----------------------------------------------------------------------
>>
>> It seems to me that wrapping it into a common function might be the only
>> way to successfully compile or link with this modification.
>>
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
>> --- a/arch/loongarch/include/asm/pgtable.h
>> +++ b/arch/loongarch/include/asm/pgtable.h
>> @@ -360,6 +360,8 @@ static inline void pte_clear(struct mm_struct *mm, u=
nsigned long addr, pte_t *pt
>>  #define PMD_T_LOG2     (__builtin_ffs(sizeof(pmd_t)) - 1)
>>  #define PTE_T_LOG2     (__builtin_ffs(sizeof(pte_t)) - 1)
>>
>> +inline struct page *tlb_virt_to_page(unsigned long kaddr);
>> +
>>
>> --- a/arch/loongarch/mm/pgtable.c
>> +++ b/arch/loongarch/mm/pgtable.c
>> @@ -9,6 +9,12 @@
>>  #include <asm/pgtable.h>
>>  #include <asm/tlbflush.h>
>>
>> +inline struct page *tlb_virt_to_page(unsigned long kaddr)
>> +{
>> +       return pte_page(*virt_to_kpte(kaddr));
>> +}
>> +EXPORT_SYMBOL_GPL(tlb_virt_to_page);
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
>>
>> WDYT?
>>
>> Best Regards,
>> Enze
> If you define "static inline" functions in page.h, there will be no probl=
ems.
>

Hi Huacai,

After failed over and over and over again, I think I've found the reason
why we can't define tlb_virt_to_page as macro or inline function in        =
   =20
asm/page.h or asm/pgtable.h. :)

I'll go through this step by step.

If I put tlb_virt_to_page in asm/page.h as following,

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
+static inline struct page *tlb_virt_to_page(unsigned long kaddr)
+{
+       return pte_page(*virt_to_kpte(kaddr));
+}
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D

and compile kernel, gcc says to me the following error.

--------------------------------------------------------------------
  CC      arch/loongarch/kernel/asm-offsets.s
In file included from ./include/linux/shm.h:6,
                 from ./include/linux/sched.h:16,
                 from arch/loongarch/kernel/asm-offsets.c:8:
./arch/loongarch/include/asm/page.h: In function =E2=80=98tlb_virt_to_page=
=E2=80=99:
./arch/loongarch/include/asm/page.h:126:16: error: implicit declaration of =
function =E2=80=98pte_page=E2=80=99 [-Werror=3Dimplicit-function-declaratio=
n]
  126 |         return pte_page(*virt_to_kpte(kaddr));
      |                ^~~~~~~~
---------------------------------------------------------------------

"pte_page" is declared in asm/pgtable.h, so I put "#include
<asm/pgtable.h>" ahead, like this,

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
+#include <asm/pgtable.h>
+static inline struct page *tlb_virt_to_page(unsigned long kaddr)
+{
+       return pte_page(*virt_to_kpte(kaddr));
+}
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D

then compile again, gcc says,

---------------------------------------------------------------------
  CC      arch/loongarch/kernel/asm-offsets.s                              =
                             =20
In file included from ./arch/loongarch/include/asm/page.h:98,              =
                             =20
                 from ./include/linux/shm.h:6,                             =
                             =20
                 from ./include/linux/sched.h:16,                          =
                             =20
                 from arch/loongarch/kernel/asm-offsets.c:8:               =
                             =20
./arch/loongarch/include/asm/page.h: In function =E2=80=98tlb_virt_to_page=
=E2=80=99:                                    =20
./arch/loongarch/include/asm/page.h:127:26: error: implicit declaration of =
function =E2=80=98virt_to_kpte=E2=80=99; did you mean =E2=80=98virt_to_pfn=
=E2=80=99? [-Werror=3Dimplicit-function-declaration]
  127 |         return pte_page(*virt_to_kpte(kaddr));
      |                          ^~~~~~~~~~~~
---------------------------------------------------------------------

"virt_to_kpte" is defined in linux/pgtable.h, consequently I add "#include
<linux/pgtable.h>" as well,

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
+#include <asm/pgtable.h>
+#include <linux/pgtable.h>
+static inline struct page *tlb_virt_to_page(unsigned long kaddr)
+{
+       return pte_page(*virt_to_kpte(kaddr));
+}
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D

and continue,

---------------------------------------------------------------------
  CC      arch/loongarch/kernel/asm-offsets.s                              =
                             =20
  CALL    scripts/checksyscalls.sh                                         =
                             =20
  CC      arch/loongarch/vdso/vgetcpu.o                                    =
                             =20
  CC      arch/loongarch/vdso/vgettimeofday.o                              =
                             =20
In file included from ./arch/loongarch/include/asm/page.h:124,             =
                             =20
                 from ./include/linux/mm_types_task.h:16,                  =
                             =20
                 from ./include/linux/mm_types.h:5,                        =
                             =20
                 from ./include/linux/mmzone.h:22,                         =
                             =20
                 from ./include/linux/gfp.h:7,                             =
                             =20
                 from ./include/linux/mm.h:7,                              =
                             =20
                 from ./arch/loongarch/include/asm/vdso.h:10,              =
                             =20
                 from arch/loongarch/vdso/vgetcpu.c:6:                     =
                             =20
./arch/loongarch/include/asm/pgtable.h: In function =E2=80=98pte_accessible=
=E2=80=99:                                   =20
./arch/loongarch/include/asm/pgtable.h:436:40: error: invalid use of undefi=
ned type =E2=80=98struct mm_struct=E2=80=99  =20
  436 |                         atomic_read(&mm->tlb_flush_pending))       =
                             =20
      |                                        ^~      =20
---------------------------------------------------------------------

The first line above shows that it compiled successfully for the
asm-offsets module.  That's fair enough.  Actually, the point is the
next one (invalid use of undefined type 'struct mm_struct').

As we all know, before the compiler compiles, it expands the header
files first.  For this example, it firstly expands from the header file
vdso.h, then the mm.h file and so on.  We can see that the line 436 of
asm/pgtable.h are using 'struct mm_struct'.  When we backtrack to a file
that has been previously expanded, it's obvious that the definition of
mm_struct does not appear in the expanded file.  Instead, it appears
afterward (mm_types.h).

To be clear, I'll exemplify this case with a cheap ASCII diagram.

                                                                 ... <-|
                    we're using 'mm_struct' here >>>   asm/pgtable.h <-|
                                                                 ... <-|
                                                                       |
                                                               |->...  |
                                                               |->asm/page.=
h
                                                               |->...
                                                       |->...  |
                                         |->...        |->mm_types_task.h
                             |->...      |->mm_types.h-|->...
                    |->...   |->mmzone.h-|->... |
            |->...  |->gfp.h-|->...             |
  |->...    |->mm.h-|->...            But 'mm_struct' is defined here.
  |->vdso.h-|->...
  |->...
vgetcpu.c

I've also tried to include mm_types.h in advance, but in this case that
doesn't work because the _LINUX_MM_TYPES_H macro already exists.
The "forward declaration" was also taken into account, in the end it was
found to be unavailable as well.

In summary, I'm afraid that rewriting tlb_virt_to_page in asm/page.h as
a macro or inline function is not possible.  The root case of this is
that both 'struct mm_struct' and 'virt_to_kpte' belong to high-level
data structures, and if they are referenced in asm/page.h at the
low-level, dependency problems arise.

Anyway, we can at least define it as a normal function in asm/pgtable.h,
is that Okay with you?

It may be a bit wordy, so please bear with me.  In addition, all of the
above is my understanding, am I missing something?

Best Regards,
Enze

>>
>> > 3, CONFIG_64BIT can be removed here.
>> >
>> > Huacai
>> >
>> >> +#else
>> >>  #define virt_to_page(kaddr)    pfn_to_page(virt_to_pfn(kaddr))
>> >> +#endif
>> >>
>> >>  extern int __virt_addr_valid(volatile void *kaddr);
>> >>  #define virt_addr_valid(kaddr) __virt_addr_valid((volatile void *)(k=
addr))
>> >> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/in=
clude/asm/pgtable.h
>> >> index ed6a37bb55b5..0fc074b8bd48 100644
>> >> --- a/arch/loongarch/include/asm/pgtable.h
>> >> +++ b/arch/loongarch/include/asm/pgtable.h
>> >> @@ -360,6 +360,12 @@ static inline void pte_clear(struct mm_struct *m=
m, unsigned long addr, pte_t *pt
>> >>  #define PMD_T_LOG2     (__builtin_ffs(sizeof(pmd_t)) - 1)
>> >>  #define PTE_T_LOG2     (__builtin_ffs(sizeof(pte_t)) - 1)
>> >>
>> >> +#ifdef CONFIG_64BIT
>> >> +struct page *DMM_virt_to_page(unsigned long kaddr);
>> >> +struct page *PTMM_virt_to_page(unsigned long kaddr);
>> >> +bool is_PTMM_addr(unsigned long kaddr);
>> >> +#endif
>> >> +
>> >>  extern pgd_t swapper_pg_dir[];
>> >>  extern pgd_t invalid_pg_dir[];
>> >>
>> >> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.=
c
>> >> index 36a6dc0148ae..4c6448f996b6 100644
>> >> --- a/arch/loongarch/mm/pgtable.c
>> >> +++ b/arch/loongarch/mm/pgtable.c
>> >> @@ -9,6 +9,31 @@
>> >>  #include <asm/pgtable.h>
>> >>  #include <asm/tlbflush.h>
>> >>
>> >> +#ifdef CONFIG_64BIT
>> >> +/* DMM stands for Direct Mapped Mode. */
>> >> +struct page *DMM_virt_to_page(unsigned long kaddr)
>> >> +{
>> >> +       return pfn_to_page(virt_to_pfn(kaddr));
>> >> +}
>> >> +EXPORT_SYMBOL_GPL(DMM_virt_to_page);
>> >> +
>> >> +/* PTMM stands for Page Table Mapped Mode. */
>> >> +struct page *PTMM_virt_to_page(unsigned long kaddr)
>> >> +{
>> >> +       return pte_page(*virt_to_kpte(kaddr));
>> >> +}
>> >> +EXPORT_SYMBOL_GPL(PTMM_virt_to_page);
>> >> +
>> >> +bool is_PTMM_addr(unsigned long kaddr)
>> >> +{
>> >> +       if (unlikely((kaddr & GENMASK(BITS_PER_LONG - 1, cpu_vabits))=
 =3D=3D
>> >> +                    GENMASK(BITS_PER_LONG - 1, cpu_vabits)))
>> >> +               return true;
>> >> +       return false;
>> >> +}
>> >> +EXPORT_SYMBOL_GPL(is_PTMM_addr);
>> >> +#endif
>> >> +
>> >>  pgd_t *pgd_alloc(struct mm_struct *mm)
>> >>  {
>> >>         pgd_t *ret, *init;
>> >> --
>> >> 2.34.1
>> >>
>> >>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87lef7ayha.fsf%40kylinos.cn.
