Return-Path: <kasan-dev+bncBAABB26Y5XEAMGQELFWHN2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id D3887C65BF8
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 19:41:49 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4ee16731ceasf31267001cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 10:41:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763404908; cv=pass;
        d=google.com; s=arc-20240605;
        b=fONI5SCKO8qmjRv5jpP7Ie74Zog4LK924hdcwYFO5ylSTFuT8DALZiMR0i68TqXGqO
         kmnVgutqTqkKAexD5Bt9Mia4YVDydFVWGtit5wmLiPBFDaU8t7IrmYhv4k/WA30UZGVU
         yIaEs0SKTah7rC7Q2PF+ainy5M6k+0uAYJbGm/EOszPx0/bhU8Ivdrr7uWE+i/dxFh5H
         80QEd5cj2lfn2u/fNL/v6sQAMVqPPT83UYLwZEx0BNtlPmQe4Xls7G+VEC9hfvZ0R8Cu
         zS86DtHFKECJVV6ccGEdZsZDCGXtlCt2aYaoB925Zw62j28YH7L4VEzhiU3My+i/Nc+E
         hVCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=tPMmm6CEE5QhcidgHK8730RnNnnergRBRzRfT+XegBk=;
        fh=TqtQmKS/Xa9okTFyl9s90lwXlB04xWihMb8izCXKBl4=;
        b=Z0Ia1t8td8+ZX58kP9va7zAZ+2VJ8fe2AsRWkhINksD5GjzQt1iXq1i/WDIceQtWQo
         FQPDPEbk1yd+mLzH+ovUYl4KZ8oUmSVig3Wxo7PrxcQ/IzvfHaP65R5hR0UNv23PiiEq
         FbFZXMwotcF74U8atmtulzJwMaFZn6WNyrsvBrZZaTPfg+1c3I52GVBOK8Pbr63ym6Ut
         +gFoVhKazXhmZ4SFWtcFKYw43MU7nqdrbnzh88JdKumYiu5dKulIBw8CJHIC7p7ULOOx
         Yb9cgGv3hJsWREiZhfqAPVu99jLIYiuAPaT0/vR9vByMX2j7WReIrBggixGtjEM6ifSU
         ApuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=JhmaQYtS;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.127 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763404908; x=1764009708; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=tPMmm6CEE5QhcidgHK8730RnNnnergRBRzRfT+XegBk=;
        b=sOazHmnUnibfLaU9gxeZpjW7tNRYMQaivi3ZhI/78vv9FuNCVTkF5it+gJGNR0Yp3G
         ER7f1+7ooCT+DZooPaDhAzm5ijY79OP+8K2KQtwluOpQo1jtti/BZxieW1sto41ESWVx
         hTHe/pKrHKPBL8bjpyRXqM3WB5YtdhjCt7fNhWny+ANWSgTSMT0WoEZI4vJvO9KLc/Wb
         L6Qfh9KB2qBmKpchjteUMM2bfy7/oYvp/7Yl8AGmNgoAV56rngioPkQwNNKoEJnNkfMa
         lzQZ1GlPoFq+tK4HsYBOjJsm+ePIwdE88Oq3ZBISLAGqvVf1LYwLBDNBY6215O2VYPEP
         7jQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763404908; x=1764009708;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tPMmm6CEE5QhcidgHK8730RnNnnergRBRzRfT+XegBk=;
        b=iP6PMAmFgiG6TeRAp2NYzteEJd4RyoNiBdFoEwVvdnShT7Qnw7KbXc0sDbaYs4t/nr
         U33A+psxe+gRuaLi/FcaaU57SUeev39PQlcvf4r8sZbc18JlXNdS4Ii8sta7wKriYi8P
         vNacVFUYS1jXyiAnlhS4wo153kYrNhqI5PxoswX9pQVJtzdZfNPQdkBCw2EMv/TUS2eW
         IHBDyren1Tg7T4iOA5/Hoo0vK1SaE2qGJ4SBrgnt96n/Dwdr1TBnv/hvEBk2/4ds3/DA
         dMAxo4jwj1E1/WFkcxN9OlwVmL/xKTJlcNInJTHJ+cVeH+2rWhlIJ2/ko36W7swNca7s
         Kwhg==
X-Forwarded-Encrypted: i=2; AJvYcCVwFq3hzYcj7DTy1iOkJPiSHt0kSPZTrT8UWJrliAwJyT/yBN8zPtxlrLCIDst17mp5nXbJXg==@lfdr.de
X-Gm-Message-State: AOJu0YwxrS9groZx0oV9juVmacJQm1Zqx8j+SY3o7Qte8jmf5Sd4DM5P
	wx73jLaWrv5EZ3SEByvSAHinjn66NdQ0DPc7iBptwpZ0xmXWXeenYV5j
X-Google-Smtp-Source: AGHT+IEh8Sihnd9n4Fntnr4JKsAJfEZ0gNUxvd9ROWbqmp8/nY/slQUfjclujdoJNi7rS1J5NRA5Sg==
X-Received: by 2002:a05:622a:1108:b0:4ee:1e6d:2834 with SMTP id d75a77b69052e-4ee1e6d2afcmr62626561cf.82.1763404908148;
        Mon, 17 Nov 2025 10:41:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aaEvykYNXJ2AunWEPsr6BW++YruwQ+GEdfkfsu4wwqKA=="
Received: by 2002:ac8:59ca:0:b0:4ec:ff8d:d89 with SMTP id d75a77b69052e-4ee1546a7dcls39299281cf.1.-pod-prod-02-us;
 Mon, 17 Nov 2025 10:41:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVjSnI0hGOA7uXzdCYnqIw8QAGOyCXvde+UlPy6fmGEFhx3e/GAMPGvSWRj68iBqED64TODASkpK/s=@googlegroups.com
X-Received: by 2002:a05:622a:1456:b0:4ed:b134:38ea with SMTP id d75a77b69052e-4edf20f53d2mr183280771cf.41.1763404906853;
        Mon, 17 Nov 2025 10:41:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763404906; cv=none;
        d=google.com; s=arc-20240605;
        b=Pm8j1QpiCkwhhkUwAAkxgG4iwCOUXNVMyRPLTjxuyLI8+OPf3FSuwDwHhAK1BC4nb3
         Jews7PegEJF7n2k4sfWb07vXDyPXfQdR9RefkvF6RYll5ITKl5EGgB5scauz8MTRNHKE
         Uar8xYP+l7qepfzGDBu6YSHrJufKSZcc14SddR8SKVbW2fQOiWqrYLCV2sJ5SGl4Lkl3
         kJQrWMsFEZnkgUYwrDjizL7C9S4nLqEMaBX3oJ7arqkYSkaOAZLKmvc/NM500W9+2T1o
         UuDatsjXgwzq7JY59pkBYU4KVRqLCJv2TsZeL/D5aqjGtcjupTYBJbFpqIkPoRltW/45
         0N1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=drgz0EubZvWbKD4XfDQItOg+MBM3cOXzoADsisa0KIg=;
        fh=k/v3HmGt1ClsgCYHhLlDuddeI/n3RsPAzSnvJM/IeI0=;
        b=kbJWWHJQCOq7qfsQeBQHk91qTc8PpQKXyHVc9g1TviMiXs7lAN/lBGgE1NKvsg0TnD
         ZHXwdZgDUbQuldK2Z61XE9KLiXYMSEv5khHKqpS7dDfSx22ABzxZktnT5voIO+Im9pdG
         LVP+hI0oHFILBypabE7vJEHRNEJL/BsXwTwhcwL0sPUMbcRCSLTRJpXeOWDC2PNUTu0i
         k/+ywxDCG/Y4hFvMAF/v9UPubRK4lga+fBhDQi1EIp0MT6shyWYTNmtEJyPDp4mu3XGO
         p69NZDbf8E+aDxakU3sCK4gqdTsf6kEeVubQbuYHl+Zt13+6AIJFiuCe/2qV+aiTW4gh
         D6Tg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=JhmaQYtS;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.127 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244127.protonmail.ch (mail-244127.protonmail.ch. [109.224.244.127])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4ee0478d222si2779871cf.6.2025.11.17.10.41.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Nov 2025 10:41:46 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.127 as permitted sender) client-ip=109.224.244.127;
Date: Mon, 17 Nov 2025 18:41:35 +0000
To: Alexander Potapenko <glider@google.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org,
	Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 06/18] x86/kasan: Add arch specific kasan functions
Message-ID: <6nifmxti2xfbnrdtxbosojfw52sofc7zkyjcbcyeawz5lt372f@h6ksdfqddk4z>
In-Reply-To: <CAG_fn=XFXFAvKS2+bc66FR+gw7rfSybETAOBUR_vneaVdF5F9A@mail.gmail.com>
References: <cover.1761763681.git.m.wieczorretman@pm.me> <5be986faa12ed1176889c3ba25852c42674305f4.1761763681.git.m.wieczorretman@pm.me> <CAG_fn=XFXFAvKS2+bc66FR+gw7rfSybETAOBUR_vneaVdF5F9A@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 24219ab0aedf934d23c98a54e0e420cc21587fb9
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=JhmaQYtS;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.127 as
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

On 2025-11-11 at 10:31:13 +0100, Alexander Potapenko wrote:
>> +#ifdef CONFIG_64BIT
>> +static inline void *__tag_set(const void *__addr, u8 tag)
>> +{
>> +       u64 addr = (u64)__addr;
>> +
>> +       addr &= ~__tag_shifted(KASAN_TAG_MASK);
>
>KASAN_TAG_MASK is only defined in Patch 07, does this patch compile?

Seems I forgot to remove it from patch 7. It's originally defined
in the mmzone.h file and looked cleaner there according to Andrey.

Thanks for noticing it's still in patch 7, I'll get rid of it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6nifmxti2xfbnrdtxbosojfw52sofc7zkyjcbcyeawz5lt372f%40h6ksdfqddk4z.
