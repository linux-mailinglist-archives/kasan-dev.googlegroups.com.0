Return-Path: <kasan-dev+bncBCSL7B6LWYHBBUWVWDDAMGQE6PRKHJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id D7122B85C84
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 17:52:51 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3eb8e43d556sf1012931f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 08:52:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758210771; cv=pass;
        d=google.com; s=arc-20240605;
        b=Bc7yY+VKT5ay+6yjd+KMzJwP6FTjsFmxAndvDNA0SB4HxzFV4EnLlfW1ogkYiqhANk
         zayuYzyde2IMoexFq93+gneXmYKZQXWvcGdhOCVzKrmH74C+95Rhtf/YBRw5J4M24OYo
         JTjpPsyiA9sev15f8zjpz248vVtO+RtBf/F27FU+Widv92QjokFPmNtM5xBxyj4HmpR1
         k1DG5S+ojrciJ8aGt8I93pryG2mrlfC/e0u2bJ0iu696eXkTujsbiu2qBnDfC6/GGVJs
         AIa9jjwV8FhcwbQmkhpZHOvEEePZe4Xe/i2zMlV0gyV51H4RrjgPOFv77k35f3d138nz
         /2MQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=TbIlx3+PN5bX8B5k+bfuW95Z0dBr71ccscfLXiVazAk=;
        fh=2zv8uXAHvfR+90t4K/oEPfzbwsXO1Kml37EgdyPDLag=;
        b=iABEjAdaCZQ3Si9BzP/L4zYQhwFth6d/faWKEXwu9MIkA4k4g5C+quswh/IL9fYuZJ
         SyRD4+ozvAhJOcqMILcF+geLhZkDRTyW9YsHpVCRlDd/NYXh6HryS869lHwjqXb8Lode
         jwlg96coTevLkyHTgPfKTm6J6PLUYh2n1d3/Byknrc57nNDrXyA5zHYoZhHxfHtEfuk3
         LlJpuMm6RyJ/DF5We7IXQ75HnPN9lBQQx0ZiGMU3GRINU1noW/4eljXDF+zYp6clcC3n
         3t1Eh6+J5whMNvx06A057GH8ExKPKY7ufm04h2g8xrKQQOCpOc3dv1fMI3FV4OdWtzpP
         nTGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QgrTwk5n;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758210771; x=1758815571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TbIlx3+PN5bX8B5k+bfuW95Z0dBr71ccscfLXiVazAk=;
        b=RqQj+D7R+HBSpgm+xTeRLYjBRQIdGSJ8eUL7ly4P3TkWOXg+CxMDp80H25tbw+InMi
         jvbI8gDaEesJfbDqiMTmVqOHZrKgBmvp7LKF7EFrsKgPQETUGBLiCpT2wVwWh85vurC7
         9hnKP5Mo8/AmdxdbRttlgfSaSxVfzHRcbqr787tN54kNm3NuYBbp0HxrXFXI/Psg+/y/
         2WvQ5aut6ZmbTH24JsteB6lYneK9hijJ1lNQFa18qp4AibEzRTN4LI3oZV2l8IokyONw
         kvv6LXLaj4v8KV+o3XNSmyvb0bdl/GvGlK5Cf0BB1HVx08l1q/AqQWf5nhtv7SSRJxuA
         yJAg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758210771; x=1758815571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=TbIlx3+PN5bX8B5k+bfuW95Z0dBr71ccscfLXiVazAk=;
        b=HORHz4c3wEhz00zG+yfbBZn0U0sU6RziVJ1tq5fqimbRVINMAmr/Uid088LSUqEUDW
         vRcl+QiMoE7kxe4MRQb1kDYre/3YVFUZpCZAmPXmzZpAn1G6b8B7IY7aNxvSfmp2SmmJ
         LftQGY2/3AmKSNekEgOh597U8i9GmGoFTsxHSzNFv9A2+cmf4mL85WBlc+YaaBukx+Ft
         GKiHcwQQ59IORHlWe1WOgUoUQzRTofT1Rxkd1LqrKrgbcBXF7weNq0TwT0uOwyzm237t
         TP7WOFTbiEFEmi+xY9AqlgpkCJSEnclQ6HMDbumULz/f4Q0ehivAv8xSV3mngoVS9m3y
         15qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758210771; x=1758815571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TbIlx3+PN5bX8B5k+bfuW95Z0dBr71ccscfLXiVazAk=;
        b=BeQd3FgKO3qduqibZsL1T0FGWyfnQvc/rLHLK3HKOXOa05LUgqH3WmwRbLCDgfMspD
         rK8HVv56e8NyVYeD/ERKHzuD9IyPsdYU0RuWJilof3hsAa+CMvTlPkqzihPhT396jWOz
         5nQLnmyZYzWqXIaINLzLMwCzD166GOj7CXTqNjzCGKju6m4Foxe5yCllrM3ugDTjlwAj
         7AGRbjFY8R9Lcqb8DNBCTcPrKjAnyl9Ho8hew0GTnO7cl6PbTPhXquGFrIWKiTSZmJOv
         OQHrv93yOh211uAfXsW14jzzsZEuJAezAgeYH9ELwWs878vApRAeYWUcafBO6MbHbukc
         ufeg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXx1yUXNPP4bg74hHWIFLRdvbl7K9XrVna0PlhLohPGy/HgCNBK3QQy83He+Ge2xwHtcpbctA==@lfdr.de
X-Gm-Message-State: AOJu0YwYDuwRlm9X0N4pJtnqZRtn9ANpp18ljgpAEWPhdmXdXPDrc87j
	r2Csh2QSgo6evcugNNmsGXr7657RwsvkM9t7Vwa1RNbO06IbDBkH0hED
X-Google-Smtp-Source: AGHT+IGt+4irozse/AK6epW+NGfWJqtcFdhTH8zOXm/UEj6nz46yKyWEhOedY2cl8QxXF5hPMJjQwQ==
X-Received: by 2002:a5d:64e9:0:b0:3e9:978e:48dd with SMTP id ffacd0b85a97d-3ee15e39879mr217236f8f.2.1758210770853;
        Thu, 18 Sep 2025 08:52:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd77MXp8ygzt8PwcWkjGBbf6ANMSzTpq4sEwY7ereRvUog==
Received: by 2002:a5d:5d0f:0:b0:3c9:5df6:de46 with SMTP id ffacd0b85a97d-3ee1069c1f3ls311378f8f.2.-pod-prod-00-eu;
 Thu, 18 Sep 2025 08:52:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUVvVwduNndSwowNTd8VUDj5AkGsAuS8dMhSDtyT1Hh9SP9Jxl69DtyCmRSbL/Uo/UklDX6XS0/M8Q=@googlegroups.com
X-Received: by 2002:a05:6000:603:b0:3ea:fb3d:c4d1 with SMTP id ffacd0b85a97d-3ede1b72f5fmr3607453f8f.18.1758210768063;
        Thu, 18 Sep 2025 08:52:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758210768; cv=none;
        d=google.com; s=arc-20240605;
        b=A7CjK8c1VgVgepZHsEyGLqyrludFqsVKBjdlqpeDSZRgJBy0HmJR8KjGb6OkiHkXcm
         zmi5+QYwafEORv8Rhd8x6iv9+5T3+6sy+v60WPKEmqnM/dekJUijpjBkTeCyj8YTiKDR
         NNK+Y4OmMlDuiAo81BmgsJl4EgCIzMI2y2RwGAIXCfbYgIcsbiw4diyPeDzpqNJ4Voz1
         75lmCHMv6Pvvdqu+PfSB9XEGMofz4Z1SKJCE7bJI/sYBLIMIwF/KHOhhX9bBmMIaY2+O
         Q5Bk19HrsbQ/hHcchPhzqArBrwUMbaySSC6tUF2milCVDK3ZnbuanxrUS9ozubFY7AjT
         +EoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=b4tOEHafOTi5CrXOSO1m8dEnNyNggHvPpDClq9ufaB4=;
        fh=8KVePvRhJk0zBNwx06l7hFYJJCpR0J+0lpxdhFFm3Po=;
        b=RR5zzYbBOrQ00/eTZWdcvRuHzoOh+oSTsh39FVTP3xhGyZ2USB9Rq3dyHMbp6WgERh
         8dGmuMyOwqePGiMfeoJYqNFwNkK9ZhO0wNsKxR0RIdPOEOMDWPGQQpVPNKQeRZWJ+Gec
         jabIPYLmZnUTosMkJ1GOAJZ3wYhoybYUVmxS+fzAnvPefsK9+6eNcBkD6u79ayMby6Q2
         MI1yzQ/6YYmWDiXYqik/jL0WHr7a3h0bPZX3oKuo9aNoVt2nxVV2UfOVOcIKIHPN4Mlq
         LUgbd6TYSXuJRjIvPT+BQoqIhslJKnimLfClb/NXxrSxFtWGNANQUoMOay0T/x55XbRP
         bW+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QgrTwk5n;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f80f7944dsi1658205e9.0.2025.09.18.08.52.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 08:52:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-45dd505ae02so1658985e9.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 08:52:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUlvh+mq7f6bpXwpxSPbpufVsGDbyhEWY9ZFrQo+qJXBd0f+QX49vKk9JxpVZF21RpZH55zzSf2NoQ=@googlegroups.com
X-Gm-Gg: ASbGncsq6AweR6qBBwWrW5oV0y6Na/tLDLKiyqYM6VYY45liQo1Tc6FdBfo4Ng/Hp1I
	0bR8KcnncCkZ10SeESHB1Vo0ykjdIQ968KxQSMCLoPYMz3wuEnpv6aq/smYbOXlFYHXhbYfVY2c
	4JQkXBKjIkO7f5ab0a6dBLuM8bLMwugW/uGw7KBr5j1saqmIkmnK7+jWDej18bXRFGGbgwo5H7Y
	p8cWH0fs5GHgBvIrMkey2U0rs0XVqn0uDBZ0EDRFs2tiadTBqDs56htDhDLxLeUxCUPNAZfWPPK
	3zJBwIZUV9lrAg4KIpCOU/EReB4tAFhjIOCPqxIJ5BlXg/j+lSoRQPUbcVT8BM7CLewTB9jH+9s
	RQJKMPmNDY4QN53fhiZsdq6BeHvOkezMy8grj5KyiXdJIyiA=
X-Received: by 2002:a05:600c:6308:b0:45c:b6d8:d82a with SMTP id 5b1f17b1804b1-46206283dd3mr33695135e9.6.1758210767067;
        Thu, 18 Sep 2025 08:52:47 -0700 (PDT)
Received: from [10.214.98.247] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-46138695223sm87677465e9.5.2025.09.18.08.52.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 08:52:46 -0700 (PDT)
Message-ID: <60b9d835-b164-4775-b9b4-64a523c98879@gmail.com>
Date: Thu, 18 Sep 2025 17:52:39 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 04/19] x86: Add arch specific kasan functions
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
 sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com,
 kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com,
 alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com,
 trintaeoitogc@gmail.com, axelrasmussen@google.com, yuanchu@google.com,
 joey.gouly@arm.com, samitolvanen@google.com, joel.granados@kernel.org,
 graf@amazon.com, vincenzo.frascino@arm.com, kees@kernel.org,
 ardb@kernel.org, thiago.bauermann@linaro.org, glider@google.com,
 thuth@redhat.com, kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com,
 nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com,
 justinstitt@google.com, catalin.marinas@arm.com,
 alexander.shishkin@linux.intel.com, samuel.holland@sifive.com,
 dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com,
 dvyukov@google.com, tglx@linutronix.de, scott@os.amperecomputing.com,
 jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org,
 lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com,
 kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org,
 jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com,
 ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org,
 peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com,
 ziy@nvidia.com, smostafa@google.com, ubizjak@gmail.com, jbohac@suse.cz,
 broonie@kernel.org, akpm@linux-foundation.org, guoweikang.kernel@gmail.com,
 rppt@kernel.org, pcc@google.com, jan.kiszka@siemens.com,
 nicolas.schier@linux.dev, will@kernel.org, andreyknvl@gmail.com,
 jhubbard@nvidia.com, bp@alien8.de
Cc: x86@kernel.org, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 llvm@lists.linux.dev, linux-kbuild@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <7cb9edae06aeaf8c69013a89f1fd13a9e1531d54.1756151769.git.maciej.wieczor-retman@intel.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <7cb9edae06aeaf8c69013a89f1fd13a9e1531d54.1756151769.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QgrTwk5n;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::331
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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


On 8/25/25 10:24 PM, Maciej Wieczor-Retman wrote:

> +static inline void *__tag_set(const void *__addr, u8 tag)
> +{
> +	u64 addr =3D (u64)__addr;
> +
> +	addr &=3D ~__tag_shifted(KASAN_TAG_MASK);
> +	addr |=3D __tag_shifted(tag);
> +
> +	return (void *)addr;
> +}
> +


This requires some ifdef magic to avoid getting this into vdso32 image buil=
d process,
otherwise we'll get this warning:

CC      arch/x86/entry/vdso/vdso32/vclock_gettime.o
In file included from ../arch/x86/include/asm/page.h:10,
                 from ../arch/x86/include/asm/processor.h:20,
                 from ../arch/x86/include/asm/timex.h:5,
                 from ../include/linux/timex.h:67,
                 from ../include/linux/time32.h:13,
                 from ../include/linux/time.h:60,
                 from ../arch/x86/entry/vdso/vdso32/../vclock_gettime.c:11,
                 from ../arch/x86/entry/vdso/vdso32/vclock_gettime.c:4:
../arch/x86/include/asm/kasan.h: In function =E2=80=98__tag_set=E2=80=99:
../arch/x86/include/asm/kasan.h:81:20: warning: cast from pointer to intege=
r of different size [-Wpointer-to-int-cast]
   81 |         u64 addr =3D (u64)__addr;
      |                    ^
../arch/x86/include/asm/kasan.h:86:16: warning: cast to pointer from intege=
r of different size [-Wint-to-pointer-cast]
   86 |         return (void *)addr;
      |                ^


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6=
0b9d835-b164-4775-b9b4-64a523c98879%40gmail.com.
