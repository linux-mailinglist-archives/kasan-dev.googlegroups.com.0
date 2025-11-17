Return-Path: <kasan-dev+bncBAABBUPA5XEAMGQEWT6AMEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb140.google.com (mail-yx1-xb140.google.com [IPv6:2607:f8b0:4864:20::b140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CA83C65D3A
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 19:58:27 +0100 (CET)
Received: by mail-yx1-xb140.google.com with SMTP id 956f58d0204a3-6421142edc2sf698012d50.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 10:58:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763405906; cv=pass;
        d=google.com; s=arc-20240605;
        b=U3Me9rS23Kkf99ovWCIESXwESUAGEEhs8+G+uAINuPy8VcBTfvThpwjbhoAaxZiPF0
         h5RjLfgFa6IVawsFPyozJopcu4xyOl1vXIRgVf+g9BzJLyUCqkdCO3+tsy89Io0WzzLa
         a4TPvyFAY6mu1NG+XwXdrgCv0tfBjkgE0vJxqMBBYAEJu2umivCv7VFBTp5GuJEiCQJ6
         4GI5XrOmVpoZM/BPayWi1MrRNj71zXrOhglB8YUPLbqGALD74u/wtxvkS0jUCf+/hwhz
         nrsP7nJ/FB//S91o1d/AM40yRETBeDltZU+jxEZBoYGRfQ5NA4/PLIFb2pZWcvqA5yl4
         xVVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=nVW+NIxWU/f7e9bh6kAus8baIrRHguRcZHgEuBLUTGQ=;
        fh=ctQKmNYhxIVW10YpLOKWQi0eBz269/jL4YJrFlulalA=;
        b=ay5l1ydccNNns1AzJ9t+s+avEFjWt/IWFFvBlc0xV5wlz4MXrbaaoEj5kSDy9929zo
         JDCBPBBvBOS62UB+E3YsSBYb0EWGkQ4mQLjPCFPx5emXL1Q1qzHmwx5MmgTKGrrLQfHf
         myese+FjjCBknan9hAOKLn2Wk7jq+NoeS+VlYc2m7ZoA+UyVaS6N7qZTUZxFsN7ThX3o
         Ohumx5I580Ux4S6Cm4lX7S+Lrk3vi/M5xsJRPJCFVZEdDwGloUAoayl+urj6GpQNkrek
         jZUqUguixrofeXi7hyLv8oqC8YQSuNJgmTFLPIUJ58WP6JnoAl56kd0AGhSVTTgLBPi8
         u/Aw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=aSMS2vsg;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.124 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763405906; x=1764010706; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=nVW+NIxWU/f7e9bh6kAus8baIrRHguRcZHgEuBLUTGQ=;
        b=FIVZp76eTm2YtcLUsF13+mbS2lrUWjawfsPNjG7v5rVer5YegA+mdXAiLhjNr1oRcs
         iMBAxlTNOVBpB8BHvpdNfsgeC3guXG10sS+nonPYg+VriGN+r1w84kHpMRpMEil1cZuv
         +/w9QByIdw1l5hn1K1WP/vZ/bTW5yClrSIfILl4rRr9OvugPUtgvYAvO5Avqlj//iAoi
         XfInHhFCzJiYXRxcAHw+RyD0Gc82MGWjlJnISAdRaudNMbdVxISi/iOTsiIVk9ADnsXo
         odsk8ntXsnJPMqi8PygpSY8AvBfOEF0tnB9vrMw33Jn+K61cEZaH9ImwWwsj4hSfU2Mi
         5Bfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763405906; x=1764010706;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=nVW+NIxWU/f7e9bh6kAus8baIrRHguRcZHgEuBLUTGQ=;
        b=OrOZd65rjyWx4FApblbi65UqX8XaOpI3jWOSObKBzW+4esTFazwgzvvs/9Su7rrK3P
         4NcmU4YU+kyYQKFdPYGCmxA3OGqqdNrIbLvj7Zqm/z5rhgBkSg+R2lQ+uCeMtqnhXtOj
         n7uKEkmmuF7j0JDCeYJSw334ErZ77VqwHsvlGRuaDMqWp7j4cGTxRxg9stzQJ6CQSslh
         YcbuwIXeHwwTmMC8sdBLS2u+yWScCTy49RIZ5pOCwuS5lZJVf/pIMqjKqfWr2cVxav2+
         lHmWjsIlXqJvT9+lHGNx47vIyzlj+7WUiiZCRGELOSYPbV4HqwdGK2xr9DdS8xGVBJV8
         gdIA==
X-Forwarded-Encrypted: i=2; AJvYcCVAI+IxrClDUuqx15AAWcJyvpME8kMdiR5JFa8HsZiw4FMUCeLqZZlnmRv4FxeGunSjw7AZ4A==@lfdr.de
X-Gm-Message-State: AOJu0YziOZXAJRkavuAnS4gMW5IcovZudokHi9Yz42lQlKmxX1odE3KG
	YnSQ45mqUMScjA1nsW4gcVlBhMWE+0uerYOhb2X5OQ++Yv6vdQShIVy2
X-Google-Smtp-Source: AGHT+IEehN83QkHneSsQFP9LX7UnaBj0qtnmwDVdEQAGRmRSe1A+mUF+3ecgyU12nZ673ZNKInWJiQ==
X-Received: by 2002:a05:690e:1647:b0:641:f5bc:68e2 with SMTP id 956f58d0204a3-641f5bc72e2mr6354096d50.79.1763405905671;
        Mon, 17 Nov 2025 10:58:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ad8gqyB+2cGxrpQ9jlDmy9N4JlK1kPYqkTW8/oXByAxQ=="
Received: by 2002:a53:e30e:0:b0:63f:abbe:3977 with SMTP id 956f58d0204a3-641f684fbf6ls1620166d50.0.-pod-prod-05-us;
 Mon, 17 Nov 2025 10:58:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW5P7XFqCjUswjL2Q4MJhrKmy6+cC2oym+6CaVVxl4XpafY4b67wXTYbKUjIKo35u6UqFvEoeMHBdU=@googlegroups.com
X-Received: by 2002:a05:690e:4308:b0:640:b8ef:b77b with SMTP id 956f58d0204a3-641e770d633mr8106201d50.66.1763405904933;
        Mon, 17 Nov 2025 10:58:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763405904; cv=none;
        d=google.com; s=arc-20240605;
        b=lKnqWVAjFQOPtvkOLyo7N4umA21upXs6Htj1cOHnIzIoa2jFRPRuzH7kQTIdJI6OAB
         r//fnOSI2MUTVQl+AAMsssapi8RrHIPHBGMoXeYk6ClGnU+5bvpHNsinYT3kmhrCKzIJ
         Cv6pAS8FTdHulm2lpRYnMBP2l4aCAk0UIUJHx8XoLK2xqEJHEgQQTuJ/IdEuXa2wTCr8
         /IYMTEVKOHy28ABmxVP71Ju4mvvGqQSitzeixUPFRW17mE97u2vKj6QC6sagxX4OBpe6
         QOK3XF5IZ5mSLJV2i3BSYobcKuTpAn4efi2fZc+NOqrBdqdInUdQd1F/PYpDfYb7QLu1
         8Z5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=fhxihtRxC0rWih6zRhIQ0MI/4P4VUJvqw2WCiJpsAFs=;
        fh=k/v3HmGt1ClsgCYHhLlDuddeI/n3RsPAzSnvJM/IeI0=;
        b=FF9sxarMAJ06EMaux98ATEal92Mo0I2VoT2WfbVHg5MMXKibIXP+8ZHgSBC6DP4Prx
         3sA5kvIsCwQFyRfyKh9L0oZkrXeFBbHZVwytR3+OBEkT7AdHGCwiP/4fkGHSLxsOvOeW
         Yzbj10vajNKCDTx8wxS/FtXjjsrr6LfeHhJgQPkm6uto5MUeF8p+l6SMUZVYMbMKFE10
         9JcSDzdd8/C5LboVpq7wdMKFcEdUkAwq+P8aSyIAY01Kv5qdX89cumBVzaRLgNv4DAd9
         ZQXCOsCniht/FBo0PzGN1bjNvii1JKfW3YK69jlW6rPnatilybr44y6c7YOGa0zIo5yj
         ZeYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=aSMS2vsg;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.124 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244124.protonmail.ch (mail-244124.protonmail.ch. [109.224.244.124])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-6410eababddsi591264d50.2.2025.11.17.10.58.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Nov 2025 10:58:24 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.124 as permitted sender) client-ip=109.224.244.124;
Date: Mon, 17 Nov 2025 18:58:12 +0000
To: Alexander Potapenko <glider@google.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org,
	Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 10/18] x86/mm: Physical address comparisons in fill_p*d/pte
Message-ID: <j6s4vcbtgjas2ktnpx7etguc2nccxa3o5hz3vabes7fn7gfb5e@xxbiwnnps64e>
In-Reply-To: <CAG_fn=Ut9JUpStLiO+GsoBpn3d_EyyttcuBby=EKzuxkKdcKcw@mail.gmail.com>
References: <cover.1761763681.git.m.wieczorretman@pm.me> <da6cee1f1e596da12ef6e57202c26ec802f7528a.1761763681.git.m.wieczorretman@pm.me> <CAG_fn=Ut9JUpStLiO+GsoBpn3d_EyyttcuBby=EKzuxkKdcKcw@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 5443841a22fdb0cd19c2ceb9e40b8cdbb4f4e884
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=aSMS2vsg;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.124 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2025-11-10 at 17:24:38 +0100, Alexander Potapenko wrote:
>On Wed, Oct 29, 2025 at 9:07=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>>
>> Calculating page offset returns a pointer without a tag. When comparing
>> the calculated offset to a tagged page pointer an error is raised
>> because they are not equal.
>>
>> Change pointer comparisons to physical address comparisons as to avoid
>> issues with tagged pointers that pointer arithmetic would create. Open
>> code pte_offset_kernel(), pmd_offset(), pud_offset() and p4d_offset().
>> Because one parameter is always zero and the rest of the function
>> insides are enclosed inside __va(), removing that layer lowers the
>> complexity of final assembly.
>>
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>> Changelog v2:
>> - Open code *_offset() to avoid it's internal __va().
>>
>>  arch/x86/mm/init_64.c | 11 +++++++----
>>  1 file changed, 7 insertions(+), 4 deletions(-)
>>
>> diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
>> index 0e4270e20fad..2d79fc0cf391 100644
>> --- a/arch/x86/mm/init_64.c
>> +++ b/arch/x86/mm/init_64.c
>> @@ -269,7 +269,10 @@ static p4d_t *fill_p4d(pgd_t *pgd, unsigned long va=
ddr)
>>         if (pgd_none(*pgd)) {
>>                 p4d_t *p4d =3D (p4d_t *)spp_getpage();
>>                 pgd_populate(&init_mm, pgd, p4d);
>> -               if (p4d !=3D p4d_offset(pgd, 0))
>> +
>> +               if (__pa(p4d) !=3D (pgtable_l5_enabled() ?
>> +                                 __pa(pgd) :
>> +                                 (unsigned long)pgd_val(*pgd) & PTE_PFN=
_MASK))
>
>Did you test with both 4- and 5-level paging?
>If I understand correctly, p4d and pgd are supposed to be the same
>under !pgtable_l5_enabled().

Yes, I do test on both paging modes. Looking at p4d_offset() I think I
got the cases reversed somehow. Weird that it didn't raise any issues
afterwards. Thanks for pointing it out :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/j=
6s4vcbtgjas2ktnpx7etguc2nccxa3o5hz3vabes7fn7gfb5e%40xxbiwnnps64e.
