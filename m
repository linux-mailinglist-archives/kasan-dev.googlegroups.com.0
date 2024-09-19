Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBXMIV63QMGQEZTSV5DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0793197C44C
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 08:27:43 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-2073498f269sf7391055ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 23:27:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726727261; cv=pass;
        d=google.com; s=arc-20240605;
        b=bqAbVHya0SVKZc2rOYkBhTweujxatNHg2gmh5qyxdb1p34qrvHf77EBL1J1FFrARm3
         XO0X1fqur4do9Hm/gBNjneuzhwvumYYUr/xNr0LZ+g11Qxn9WJPNLP5QWH/LMcL+v26F
         E5WznV7d9iG07nUoyz5k7t4LGWvI3df8wW7DZVMbDAF/cz0NGQ3mBvwQelQKD3PU7dTb
         pPejj5+CFLsVsg3y1CbkplEMrTSbm99jzNLspUCGruwptca+zVqIpNTsRhFtgb3IWkKU
         eQeE5v/s4YABRkViSMuWEzqZG2myo8H4Z1pgzbPNDNHSJqnZuRIq05L3Y53Gx6JytAYH
         +EFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:message-id:date:in-reply-to:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=vdnXn8hEyr2PjWKMZ9G8xKZTHY+AimHDCUS9Bw33jX8=;
        fh=bwXplKwPfNZ3v3GZ4mrV8lbF9CA8P4sqM9apsfYIf0s=;
        b=QZ1kBA+sx5bFqBwxuA5USmlPFX3nsUnSEDwbl45WbH87UTwb7EW0kOhrRpQkGKUqUq
         y85hcis0M7YDFzQmGy6IOkTJnF5SNysCIFA8U9X55F8L5xc2guD9e3+qzMITpu0Z0ERh
         7ycwgdELfaVvMcH4gUdGkEDQv1RTmIUt/xDTtCKXxaQabwn7AWyCArv+YvoG/bHFBqTE
         lrtRz0EYN4hl4/Yg9wQEvxFNReFNx5UsUT5zfPNKvHh6Z2jGkXNx1tRBf0gQOaqwN7pV
         BTTbZxoUEleOxOnVszZMbC5jKaToaR4iBSUCN5ubExfcHDonfS1qOiTTKWabJEcR9/Fm
         9Qew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EllzgWF1;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726727261; x=1727332061; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :message-id:date:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vdnXn8hEyr2PjWKMZ9G8xKZTHY+AimHDCUS9Bw33jX8=;
        b=gcD5InBSva7bC99EUsH4JeuGJUyGNTzhJqH1jh0Ak/uoeq8iiRN9lMGmIICglJyP4r
         vW+FzCaiItTZaR1L5dWnTUuuZSPZLWAQpeBpJwMOOySupNfzI7GvbMsxc8vdom7pKuM8
         X5gpgc1UkFo3bi/05hyqMxYXrFP+kdPM7Ej9srcqurWY4HD5xZW6FuQLTUK8H4vpH5GB
         4C/4Zw/PExLeo1zgE7IETYf/smANBjayTLvXR9JRIQzZVubekpw0YNFhzNLKRMGn/sTi
         lHnssh9feV03GvQ6LYjqSEY2hONJD65cAxO3km4XFcy7cCzSifLp9kw45TldU3t/dt29
         YvbQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726727261; x=1727332061; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :message-id:date:in-reply-to:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=vdnXn8hEyr2PjWKMZ9G8xKZTHY+AimHDCUS9Bw33jX8=;
        b=IJhq62u32iJpn1hHEhU5a2t80m4bYiN+CPFwaAvaFe7M8RbaKEqlLWj3ipXAyFjv2P
         kTqej+badL+JVNkOhPYPeg3QnUxQ6o6NV2JbVajgWw5TbqmHPO1o6ZvhNY9wWT+OSStH
         trncc1+6s+mloqvEzX09iJZfOHLyo7qCirqK5FrxTKY18MXx2BtPuXIdA32d66qoWda4
         aH8VNS1+FaJGg8cbiOkTt15cyXoTK6UhDDRN8fqhZ/ugRp/FnpOEM68kTJUazyzxtCro
         t5pxigCVBbTkVFZzbSKBUJRm2C35O2yUccMSGeK/27uTo7dXgBCqcl4/UR97sTBuZWeZ
         x4dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726727261; x=1727332061;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:message-id:date
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vdnXn8hEyr2PjWKMZ9G8xKZTHY+AimHDCUS9Bw33jX8=;
        b=tngL+w1I918ta0vjVNzi4r/rkA3uD7+/QB5onZPc7y5k0lsOTqa4xvlrsZtlEAcB0t
         yw9Oknv0msrQLUhrX1Hyq5UjxGovY3u67KG8sX+OMHeqO4pAZqP/P7nUPkdkaKM4uhMw
         Ok/tyk6YF0uGaBvVTZzzLg71Ft3b/3rBmeKf+qkd0KAlYOmK7BqwFqOCOA6zdqM1yaFb
         pFTif4QlMK/Cc3+j4GRKJJN3rG8KBHfWtA+uytx9kYeO6KHXH+7keWw9N7orn8YGyCpY
         Rm5+aveznlJ3xszhyUNQYhcF586HMZ2e29CwziQ4Bh+Xq1+ZHmdG7L0YCF395BPTG5et
         3rdg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVBRUR1tW03da5n70OFT7uAfSSP9TXg/j+OnV1qKlIiSl+1Y+KYHZhDJCnLQ1A5YQ8vxVsiZQ==@lfdr.de
X-Gm-Message-State: AOJu0YztQeSrInJsSdie0C9wd4KM1xEUkU3FVwqcaryrzxTko4haeQRg
	PrqU7AUYpuxTY6Bempr5oMEjybKeVQ/+EXyNkw7I+3kgXpynSYs2
X-Google-Smtp-Source: AGHT+IFrFIFeSi9cSjUxsQIdJZkywTyRcT5BTfXWGdFoZF3H2qaiIByN3WTy4CbhXNvp3njnBrsZGQ==
X-Received: by 2002:a17:902:dad2:b0:205:9112:efee with SMTP id d9443c01a7336-2076e3b6137mr372905185ad.21.1726727261344;
        Wed, 18 Sep 2024 23:27:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d2ce:b0:205:909a:f7c8 with SMTP id
 d9443c01a7336-208cc01e1a3ls6664805ad.2.-pod-prod-07-us; Wed, 18 Sep 2024
 23:27:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXte6L6oR8a0HYcbJv84G1kIEUWKk8vQgDbuR27fNliPESpO+WX0U43ajXW0bteVgMhxC0qz5Ig8JY=@googlegroups.com
X-Received: by 2002:a17:902:c949:b0:206:b1fa:ccbb with SMTP id d9443c01a7336-2076e36a257mr346646695ad.9.1726727259942;
        Wed, 18 Sep 2024 23:27:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726727259; cv=none;
        d=google.com; s=arc-20240605;
        b=G4wNAqb2C3Tf2ggus44y/VmhCbGuuaAaasCUxFuUw87c08IExzSy/m9dadSENGs7rw
         KKRgZ7PGPIxCNWcvnrCXHZVcnENipgC+DVKAEl8c69+jn3VO2ZCFk2bsNx7VUhX0GhHz
         rD1uM3JDHltwbrozOWT5rBUXtQF7VCW/vYu62UdEdJNoDDktqWh7HPF1k9Y3TK7khtAx
         /b8xejovx++CJ0KLY/erbJCviFAVNLbLfhDrGnFCnGxc3udbX3L36kAgUCelZq2ObxBk
         bF1iqJESCyGUYvHuwwByaILbrvbk9K7XFgQTFtMS7hNAuPB4148FgnhS1c9bn27rr48f
         1llA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:message-id:date
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=2Hj+1vqgujWOrqlQpkce2sq1h+JT76BLtBiXrr9bmsw=;
        fh=7WEoxXfprZXhZU6zVoAMok4FQwpeNfQ3zpZ7uGVTo5E=;
        b=Ys5YnIVDy/aiLyHjNhR16bzOTF5V/R5kwdA0NxhV98XdUAEJNiSoDow2gUx14xXpxV
         WVRJma3FJGXweWJl/PQS5QbM7fWoy7Ie7sgXMAKTzASRXKsNQy4VT8VVB1yvoOFrNrVw
         TwkzUg0zCapt1lHxcOca3ZnyS/5uRB/OUNdl/mnLx1ET/v3mqVTYypDfEU011LLxy79k
         hGL7tnXQuDqNWzVcLHzDoSdlFYUlBTrrdur7i+Kp1wDSEk+pUBdEgn2XYY9Xf2TZchCI
         jhSbsHy6pn1Tnrd6M1+mByGp0mVmoaawV7UljdQ/53FDSvh2Oo3q2DUJrYZTmer7O8FB
         1jlQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EllzgWF1;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-207946c2c05si5039125ad.10.2024.09.18.23.27.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 23:27:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-205722ba00cso4654505ad.0
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 23:27:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUnz6z33O32by2ck/oaURJrbIsXQ5iXw/bi/vWMT5cWqKnlvy16jeWyLerG7nVpxegHTJ6DcRrvFmA=@googlegroups.com
X-Received: by 2002:a17:902:eb8a:b0:206:ca91:1dda with SMTP id d9443c01a7336-2076e39c56bmr305359875ad.17.1726727258556;
        Wed, 18 Sep 2024 23:27:38 -0700 (PDT)
Received: from dw-tp ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207945da793sm73443715ad.54.2024.09.18.23.27.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 23:27:37 -0700 (PDT)
From: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, linuxppc-dev@lists.ozlabs.org
Cc: Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Madhavan Srinivasan <maddy@linux.ibm.com>, Hari Bathini <hbathini@linux.ibm.com>, "Aneesh Kumar K . V" <aneesh.kumar@kernel.org>, Donet Tom <donettom@linux.vnet.ibm.com>, Pavithra Prakash <pavrampu@linux.vnet.ibm.com>, Nirjhar Roy <nirjhar@linux.ibm.com>, LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Subject: Re: [RFC v2 03/13] book3s64/hash: Remove kfence support temporarily
In-Reply-To: <d9d8703a-df24-47e3-bd0d-2ff5a6eae184@csgroup.eu>
Date: Thu, 19 Sep 2024 11:53:15 +0530
Message-ID: <87jzf8tb58.fsf@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com> <5f6809f3881d5929eedc33deac4847bf41a063b9.1726571179.git.ritesh.list@gmail.com> <d9d8703a-df24-47e3-bd0d-2ff5a6eae184@csgroup.eu>
MIME-version: 1.0
Content-type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EllzgWF1;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::630
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
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

Christophe Leroy <christophe.leroy@csgroup.eu> writes:

> Le 19/09/2024 =C3=A0 04:56, Ritesh Harjani (IBM) a =C3=A9crit=C2=A0:
>> Kfence on book3s Hash on pseries is anyways broken. It fails to boot
>> due to RMA size limitation. That is because, kfence with Hash uses
>> debug_pagealloc infrastructure. debug_pagealloc allocates linear map
>> for entire dram size instead of just kfence relevant objects.
>> This means for 16TB of DRAM it will require (16TB >> PAGE_SHIFT)
>> which is 256MB which is half of RMA region on P8.
>> crash kernel reserves 256MB and we also need 2048 * 16KB * 3 for
>> emergency stack and some more for paca allocations.
>> That means there is not enough memory for reserving the full linear map
>> in the RMA region, if the DRAM size is too big (>=3D16TB)
>> (The issue is seen above 8TB with crash kernel 256 MB reservation).
>>=20
>> Now Kfence does not require linear memory map for entire DRAM.
>> It only needs for kfence objects. So this patch temporarily removes the
>> kfence functionality since debug_pagealloc code needs some refactoring.
>> We will bring in kfence on Hash support in later patches.
>>=20
>> Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
>> ---
>>   arch/powerpc/include/asm/kfence.h     |  5 +++++
>>   arch/powerpc/mm/book3s64/hash_utils.c | 16 +++++++++++-----
>>   2 files changed, 16 insertions(+), 5 deletions(-)
>>=20
>> diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/as=
m/kfence.h
>> index fab124ada1c7..f3a9476a71b3 100644
>> --- a/arch/powerpc/include/asm/kfence.h
>> +++ b/arch/powerpc/include/asm/kfence.h
>> @@ -10,6 +10,7 @@
>>  =20
>>   #include <linux/mm.h>
>>   #include <asm/pgtable.h>
>> +#include <asm/mmu.h>
>>  =20
>>   #ifdef CONFIG_PPC64_ELF_ABI_V1
>>   #define ARCH_FUNC_PREFIX "."
>> @@ -25,6 +26,10 @@ static inline void disable_kfence(void)
>>  =20
>>   static inline bool arch_kfence_init_pool(void)
>>   {
>> +#ifdef CONFIG_PPC64
>> +	if (!radix_enabled())
>
> No need for a #ifdef here, you can just do:
>
> 	if (IS_ENABLED(CONFIG_PPC64) && !radix_enabled())
> 		return false;
>
>

This special radix handling is anyway dropped in later pacthes.=20
So I didn't bother changing it here.

>> +		return false;
>> +#endif
>>   	return !kfence_disabled;
>
> But why not just set kfence_disabled to true by calling disable_kfence()=
=20
> from one of the powerpc init functions ?
>

This patch is only temporarily disabling kfence support for only Hash.
This special Hash handling gets removed in patch-10 which brings back
kfence support.

-ritesh

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87jzf8tb58.fsf%40gmail.com.
