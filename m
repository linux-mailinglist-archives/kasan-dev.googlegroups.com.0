Return-Path: <kasan-dev+bncBDW2JDUY5AORBLVGRG7AMGQERVCJGGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id EBFECA4A6ED
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Mar 2025 01:22:07 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-43935e09897sf19548295e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2025 16:22:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740788527; cv=pass;
        d=google.com; s=arc-20240605;
        b=aOVP5CnTAPkxtYC+H3BZlJURlEtyI/HqgbWtlwsTWG2BmItOFn61FSbFv1rMS/MZtQ
         GQWPBVpfoA21J5sESq0mi6N8bfbP4cmOcjaqRu5ppDspYIDGOWSL/XgbEtk2q4MPMTm0
         XH+UGD1HR9F0A/hyXBeE8qgn3LAVyF+ERfKHT7ZxM9eUlt8m2BCnpw0NSHgQyXnZQjZZ
         IpgR7i2oJaTJgJhySToTS2A/lRVXhI+7mii4XL4F15DAylALoVMKfA2dgBByOYIvUNip
         UAi7fIW8FDHwkFvfqNCE8rkdjXarmCNyIaXCWlluxvhbJheMXFDn7ZPCyKUANWKPPBTu
         l8BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=jBEGbappBkc7Sws63G5LsExro/nGJLnTQukega9pPZE=;
        fh=BaoRzGnjbAWHMslDGF2UXVwVmHPrzCKkvvnzKTaAolY=;
        b=ZxaO1POdOmIaVjkjpoWrA80Z+oXzDw0WL7UxKFOECsWeBr21WRk/TrYifuRZuCJ7LE
         E4KDoNIGHIi8QVym4COnpvwie1ElONDG1ehDxH00Bt74F6zU5DTrF513KfUYL3TXz4G1
         2hZbinDK4FGl+QJiJcFXkZ4J2IVkD0UuLj2Wp7eIsWeSvm5dBaAnMjrUz49aYtqc/m46
         zz8udLkmzVSoQ1/DD4BTxvgMxffOCw4TBlj4/lc/SetIhDMFagUzLpoo0AHEBjbMuO3d
         8gK8wAiYpxmp+MPa3ZMpH4UCP7PKdA8uZ9G//XoSBOlfmh+kNLfRzTY8yOu3KfqZ34h8
         fyvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="WT+Wjox/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740788527; x=1741393327; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jBEGbappBkc7Sws63G5LsExro/nGJLnTQukega9pPZE=;
        b=BNSnvHe/F70twMmWvThaRnQnwqVQmj0wp8DvS2yVOxyP95+MIzQ6EbUxs5e/delKYn
         /DfrHzqVz310l5zycPc1WCq/esL+SFe+d0oInNF+rFS6pQN0iNkqWejJYmkNly3v4rmp
         6doUXj4P2swxYhqL4iezex7oKoqBXFi2E4lalgIFw1K7z+wKDWMq6R4Kx/T5tLL3/UBi
         IGJ1PbESvebbehld+d5bdmADqLbRQHCsoJfNQTp0gK5qMtZB/aNrNpo2IF0uocsingp8
         kZ1RBwxPjVxLM1+gc7McUHdZh71kNGFFrMXLzxDfqiJuptWwZc483JNmMP1Az7qGU0wz
         TThw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740788527; x=1741393327; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=jBEGbappBkc7Sws63G5LsExro/nGJLnTQukega9pPZE=;
        b=Yw0Wu657dhq0GcPR3a6TJlXaMSx1RiCOzZf3xnN8unNd8sVsiMAIUqNOw8l/DA/Iai
         n/4JRXsputUe+qgn/KwPW7TApt+Av+JC7WkZ/PhZ7ubTDdeNfHFra1zJdmI1zSWwqLlV
         q/esnviX2qIN7jA99PEBw6b+CmpbPgJQVAmIfhkCraoJZ4oC56Ifp7OZb9Ee8S8rAMyx
         xV0UZXVBYepZUEe4UQqPs0MSXLFk9CJF4vwucK8G8t5y0+db7v59wKWBME4oJjRM9p8E
         299iAk6Q9F9Hh77SDmCbXmVKX6BvNEOr6mtOPvHY4XmolO1uKkDapU0TgRSUgg0Cabvq
         fk5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740788527; x=1741393327;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jBEGbappBkc7Sws63G5LsExro/nGJLnTQukega9pPZE=;
        b=jv+wEgh9hqnF1m6QRZLZkpZ8sAsA27xPMYXr8wwYNMbku6zj5sLb7hWTbxjK6IUPS8
         vpOFymEy+D1PSjkmyouJzXUguKwFHFNE3yiY4AGpPJiS0vDFiJxzEaao8V6jpw4NFUXR
         idf5EWhtuvfCo+ViqDU6sgfVY6yktCbgD8EJ2rkUbngm/az2ecb2o/dCJV2ysaxt9Qxu
         CuAfGaGAIXeuvL6CKgXE/yGdo2M289M4XpOK6mQbh2BArlKIZ+HooG9eIfXXqzrBfoPF
         jXfxhI+INJK7zVFjIizCRx5avqb0uJv6LqduoFPJXYW/w3GpaFj45tPnk45/sPPF8oZu
         Q/Hg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXeGR2qSPM0FeXzgFVRuB2TTh16RGCwLk4hm/cLV2HNF4oABz7STGSvZtDdUt7rNSSwcdMRZw==@lfdr.de
X-Gm-Message-State: AOJu0YwMF70fBLTAbkyt4c7+dz57T3gzNfDe54cpYEYK+rCwzoKMGGhi
	H9f3JjS27SyyrKU8fiVIdWYJ21tYYL+1dorbQ1PFsHDuPNJ4G2Up
X-Google-Smtp-Source: AGHT+IFwmnRoYYxq2ukqDJhWRnof7JyzLHR9WFXf4OWYHSw0OIgkjyZzzJQS4HWrnn2l2s4J3wHL3w==
X-Received: by 2002:a05:600c:1d15:b0:439:8c6d:7ad9 with SMTP id 5b1f17b1804b1-43ba7d66351mr42825755e9.31.1740788526721;
        Fri, 28 Feb 2025 16:22:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHQSjTw8BYaNmXWEt07zDg0Rr3z4zx6DJaUQbnbj8I3RA==
Received: by 2002:a05:600c:2155:b0:439:84e0:27a6 with SMTP id
 5b1f17b1804b1-43af7934c6dls2353905e9.2.-pod-prod-09-eu; Fri, 28 Feb 2025
 16:22:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV0tHjl/ayIVOyTYSJ+BEVxK8lDnZg7D9f2k+y+JCdBEvfyUCPwTgZVXPGwb/3m3n6ktJlXbC80CXY=@googlegroups.com
X-Received: by 2002:a05:6000:1568:b0:390:f6aa:4e7c with SMTP id ffacd0b85a97d-390f6aa506dmr1397611f8f.28.1740788524241;
        Fri, 28 Feb 2025 16:22:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740788524; cv=none;
        d=google.com; s=arc-20240605;
        b=lEQQOP1ZZkPFbFIKGKFIEYzVuEEsStRO2160EABq5npMgb1yxii/aAGV/5iO8Sk6CD
         bvyu5/sJMVx7IfTJ5lMwA5mFT5wkfvWDR9V4jnsxUtEOPviE7drjwUMdn65gjiwfhUIT
         fc0B3JC0PSUSpqpoYSJvBGdDOgtEQpRqJXWrfFbplgUZ3j1jfLs9Hi4TstJy7tCf3xKI
         CquKdQAaIo4rJEqGO06as0IPqusRHZE9eyPzetLG3D9Nyy3q4yndNg29LyBa9+YHBSvN
         SmmEV2KWny6E/9QWeqkgWVe+INiXk+D8nvOJ6JUvhRmM3AZunfA58JmbyRRWE4wRNULn
         86hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=17XNK1hQwkcmGrY7OjaJII0SHza23hpB66sdZO0tw4M=;
        fh=Uspht9dGqerpZW9el9E/WHD9wjZvfbALmin1Vnx5WYA=;
        b=kYMmPF+QPhQlTg8coEV7G0Ix9z4Ik2g2FptVH/paHeEgD24UVVNxmHaI+YUyOkW3XI
         XFaYbsjbBBWerzBQ9KzAXasYAyyHgi+/+G0rTO4AebNKqqinEWNCCA5Ga5Mlu8CkhoZj
         REfmK8d+xzkgHHzclmzzyn3OQrWQR9D2PU1/OVeZZDlJiqKRpnkxQCoOl5yXLGQXzr7H
         N9YmW4t0hcIYDuPp47Y3CIZl9df2aSbNQMAdfhglVMDrK4eLWyRkaIG6WyNXRTiPGWHD
         Pg+rBjWPMENjBZsSZktqGDjq4DJ3GYg7KBj+/djvTe3TZnb4HoVMsCnf63vQDPesWPhg
         +VDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="WT+Wjox/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43ab2c50559si7603365e9.0.2025.02.28.16.22.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2025 16:22:04 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-390d98ae34dso2187441f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2025 16:22:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXX6nwOc9Lmblb3MeZUu+YLwYxfqIlUs2WbgUjMxLtlL2Co3phaucRr4WFcW9JJxqoYEAw+NE7WtXM=@googlegroups.com
X-Gm-Gg: ASbGnctg53gV9H/SqTdXEesvkNcPhkGinOkBlBQwcHttm8zPnUcqU3GGOVmy/B0YuXM
	DCNN2r8Ix+OWjCG9YK0oYwHUL9FzHWTFS7O8T2tQDNmX+o+Kv+bvnZg54ssDyrn20SU9juZcOd4
	2XGI+s2CxS041EJa2ou1aMfZr4HnVh
X-Received: by 2002:a5d:6da3:0:b0:390:eb32:3fee with SMTP id
 ffacd0b85a97d-390eca80548mr4682267f8f.49.1740788523425; Fri, 28 Feb 2025
 16:22:03 -0800 (PST)
MIME-Version: 1.0
References: <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
 <gisttijkccu6pynsdhvv3lpyxx7bxpvqbni43ybsa5axujr7qj@7feqy5fy2kgt>
 <6wdzi5lszeaycdfjjowrbsnniks35zhatavknktskslwop5fne@uv5wzotu4ri4>
 <CA+fCnZeEm+-RzqEXp1FqYJ5Gsm+mUZh5k3nq=92ZuTiqwsaWvA@mail.gmail.com>
 <qnxlqbc4cs7izjilisbjlrup4zyntjyucvfa4s6eegn72wfbkd@czthvwkdvo3v>
 <CA+fCnZdUFO0+G9HHy4oaQfEx8sm3D_ZfxdkH3y2ZojjYqTN74Q@mail.gmail.com>
 <agqtypvkcpju3gdsq7pnpabikm4mnnpy4kp5efqs2pvsz6ubsl@togxtecvtb74> <mjyjkyiyhbbxyksiycywgh72laozztzwxxwi3gi252uk4b6f7j@3zwpv7l7aisk>
In-Reply-To: <mjyjkyiyhbbxyksiycywgh72laozztzwxxwi3gi252uk4b6f7j@3zwpv7l7aisk>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 1 Mar 2025 01:21:52 +0100
X-Gm-Features: AQ5f1Job2uTJiDaFRVhtBwap-aEMFc-I22BIiCb20obah84ENVZn9xQZFsNgYZY
Message-ID: <CA+fCnZcDyS8FJwE6x66THExYU_t_n9cTA=9Qy3wL-RSssEb55g@mail.gmail.com>
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: Vitaly Buka <vitalybuka@google.com>, kees@kernel.org, 
	julian.stecklina@cyberus-technology.de, kevinloughlin@google.com, 
	peterz@infradead.org, tglx@linutronix.de, justinstitt@google.com, 
	catalin.marinas@arm.com, wangkefeng.wang@huawei.com, bhe@redhat.com, 
	ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, will@kernel.org, 
	ardb@kernel.org, jason.andryuk@amd.com, dave.hansen@linux.intel.com, 
	pasha.tatashin@soleen.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: multipart/mixed; boundary="0000000000009180c7062f3ce9f2"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="WT+Wjox/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

--0000000000009180c7062f3ce9f2
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Fri, Feb 28, 2025 at 5:13=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> I was applying your other comments to the series and came up with somethi=
ng like
> this. What do you think?
>
>         /*
>          * With the default kasan_mem_to_shadow() algorithm, all addresse=
s
>          * returned by the memory-to-shadow mapping (even for bogus point=
ers)
>          * must be within a certain displacement from KASAN_SHADOW_OFFSET=
.
>          *
>          * For Generic KASAN the displacement is unsigned so the mapping =
from zero
>          * to the last kernel address needs checking.
>          */
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
>                 if (addr < KASAN_SHADOW_OFFSET ||
>                     addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size)
>                         return;
>         } else {
>                 /*
>                  * For the tag-based mode the compiler resets tags in add=
resses at
>                  * the start of kasan_mem_to_shadow(). Because of this it=
's not
>                  * necessary to check a mapping of the entire address spa=
ce but only
>                  * whether a range of [0xFF00000000000000 - 0xFFFFFFFFFFF=
FFFFF] is a
>                  * valid memory-to-shadow mapping. On x86, tags are locat=
ed in bits
>                  * 62:57 so the range becomes [0x7E00000000000000 - 0xFFF=
FFFFFFFFFFFFF].
>                  * The check below tries to exclude invalid addresses by
>                  * checking spaces between [0x7E00000000000000 - 0x7FFFFF=
FFFFFFFFFF]
>                  * (which are positive and will overflow the memory-to-sh=
adow
>                  * mapping) and [0xFE00000000000000 - 0xFFFFFFFFFFFFFFFF]
>                  */
>                  if (addr > KASAN_SHADOW_OFFSET ||
>                      (addr < (u64)kasan_mem_to_shadow((void *)(0xFEUL << =
56)) &&
>                      addr > (u64)kasan_mem_to_shadow((void *)(~0UL >> 1))=
) ||
>                      addr < (u64)kasan_mem_to_shadow((void *)(0x7EUL << 5=
6)))
>                         return;
>         }
>
> The comment is a bit long and has a lot of hexes but maybe it's good to l=
eave a
> longer explanation so no one has to dig through the mailing archives to
> understand the logic :b

Explaining the logic sounds good to me!

I think your patch is close to what would look good, but I think the
parentheses in the long if condition look suspicious.

Please check the attached diff (Gmail makes it hard to inline code): I
fixed the parentheses (if I'm right about them being wrong), made the
checks look uniform, added an arm-specific check, and reworked the
comments (please check if they make sense).

If the diff looks good to you, let's use that.

It also would be great, if you could test this: add some code that
dereferences various bad addresses and see if the extra KASAN message
line gets printed during the GPF.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcDyS8FJwE6x66THExYU_t_n9cTA%3D9Qy3wL-RSssEb55g%40mail.gmail.com.

--0000000000009180c7062f3ce9f2
Content-Type: text/x-patch; charset="US-ASCII"; name="kasan_non_canonical_hook.patch"
Content-Disposition: attachment; filename="kasan_non_canonical_hook.patch"
Content-Transfer-Encoding: base64
Content-ID: <f_m7pg3pxi0>
X-Attachment-Id: f_m7pg3pxi0

ZGlmZiAtLWdpdCBhL21tL2thc2FuL3JlcG9ydC5jIGIvbW0va2FzYW4vcmVwb3J0LmMKaW5kZXgg
ODM1N2UxYTMzNjk5Li43ZWRkZTFhMjZhNDEgMTAwNjQ0Ci0tLSBhL21tL2thc2FuL3JlcG9ydC5j
CisrKyBiL21tL2thc2FuL3JlcG9ydC5jCkBAIC02ODEsMTEgKzY4MSw1NiBAQCB2b2lkIGthc2Fu
X25vbl9jYW5vbmljYWxfaG9vayh1bnNpZ25lZCBsb25nIGFkZHIpCiAJY29uc3QgY2hhciAqYnVn
X3R5cGU7CiAKIAkvKgotCSAqIEFsbCBhZGRyZXNzZXMgdGhhdCBjYW1lIGFzIGEgcmVzdWx0IG9m
IHRoZSBtZW1vcnktdG8tc2hhZG93IG1hcHBpbmcKLQkgKiAoZXZlbiBmb3IgYm9ndXMgcG9pbnRl
cnMpIG11c3QgYmUgPj0gS0FTQU5fU0hBRE9XX09GRlNFVC4KKwkgKiBGb3IgR2VuZXJpYyBLQVNB
Tiwga2FzYW5fbWVtX3RvX3NoYWRvdygpIHVzZXMgdGhlIGxvZ2ljYWwgcmlnaHQgc2hpZnQKKwkg
KiBhbmQgbmV2ZXIgb3ZlcmZsb3dzIHdpdGggdGhlIGNob3NlbiBLQVNBTl9TSEFET1dfT0ZGU0VU
IHZhbHVlcyAob24KKwkgKiBib3RoIHg4NiBhbmQgYXJtNjQpLiBUaHVzLCB0aGUgcG9zc2libGUg
c2hhZG93IGFkZHJlc3NlcyAoZXZlbiBmb3IKKwkgKiBib2d1cyBwb2ludGVycykgYmVsb25nIHRv
IGEgc2luZ2xlIGNvbnRpZ3VvdXMgcmVnaW9uIHRoYXQgaXMgdGhlCisJICogcmVzdWx0IG9mIGth
c2FuX21lbV90b19zaGFkb3coKSBhcHBsaWVkIHRvIHRoZSB3aG9sZSBhZGRyZXNzIHNwYWNlLgog
CSAqLwotCWlmIChhZGRyIDwgS0FTQU5fU0hBRE9XX09GRlNFVCkKLQkJcmV0dXJuOworCWlmIChJ
U19FTkFCTEVEKENPTkZJR19LQVNBTl9HRU5FUklDKSkgeworCQlpZiAoYWRkciA8ICh1NjQpa2Fz
YW5fbWVtX3RvX3NoYWRvdygodm9pZCAqKSgwVUwpKSB8fAorCQkgICAgYWRkciA+ICh1NjQpa2Fz
YW5fbWVtX3RvX3NoYWRvdygodm9pZCAqKSh+MFVMKSkpCisJCQlyZXR1cm47CisJfQorCisJLyoK
KwkgKiBGb3IgU29mdHdhcmUgVGFnLUJhc2VkIEtBU0FOLCBrYXNhbl9tZW1fdG9fc2hhZG93KCkg
dXNlcyB0aGUKKwkgKiBhcml0aG1ldGljIHNoaWZ0LiBOb3JtYWxseSwgdGhpcyB3b3VsZCBtYWtl
IGNoZWNraW5nIGZvciBhIHBvc3NpYmxlCisJICogc2hhZG93IGFkZHJlc3MgY29tcGxpY2F0ZWQs
IGFzIHRoZSBzaGFkb3cgYWRkcmVzcyBjb21wdXRhdGlvbgorCSAqIG9wZXJhdGlvbiB3b3VsZCBv
dmVyZmxvdyBvbmx5IGZvciBzb21lIG1lbW9yeSBhZGRyZXNzZXMuIEhvd2V2ZXIsIGR1ZQorCSAq
IHRvIHRoZSBjaG9zZW4gS0FTQU5fU0hBRE9XX09GRlNFVCB2YWx1ZXMgYW5kIHRoZSBmYWN0IHRo
ZQorCSAqIGthc2FuX21lbV90b19zaGFkb3coKSBvbmx5IG9wZXJhdGVzIG9uIHBvaW50ZXJzIHdp
dGggdGhlIHRhZyByZXNldCwKKwkgKiB0aGUgb3ZlcmZsb3cgYWx3YXlzIGhhcHBlbnMgKGZvciBi
b3RoIHg4NiBhbmQgYXJtNjQpLgorCSAqCisJICogRm9yIGFybTY0LCB0aGUgdG9wIGJ5dGUgb2Yg
dGhlIHBvaW50ZXIgZ2V0cyByZXNldCB0byAweEZGLiBUaHVzLCB0aGUKKwkgKiBwb3NzaWJsZSBz
aGFkb3cgYWRkcmVzc2VzIGJlbG9uZyB0byBhIHJlZ2lvbiB0aGF0IGlzIHRoZSByZXN1bHQgb2YK
KwkgKiBrYXNhbl9tZW1fdG9fc2hhZG93KCkgYXBwbGllZCB0byB0aGUgbWVtb3J5IHJhbmdlCisJ
ICogWzB4RkYwMDAwMDAwMDAwMDAsIDB4RkZGRkZGRkZGRkZGRkZGRl0uIERlc3BpdGUgdGhlIG92
ZXJmbG93LCB0aGUKKwkgKiByZXN1bHRpbmcgcG9zc2libGUgc2hhZG93IHJlZ2lvbiBpcyBjb250
aWd1b3VzLCBhcyB0aGUgb3ZlcmZsb3cKKwkgKiBoYXBwZW5zIGZvciBib3RoIDB4RkYwMDAwMDAw
MDAwMDAgYW5kIDB4RkZGRkZGRkZGRkZGRkZGRi4KKwkgKi8KKwlpZiAoSVNfRU5BQkxFRChDT05G
SUdfS0FTQU5fU1dfVEFHUykgJiYgSVNfRU5BQkxFRChDT05GSUdfQVJNNjQpKSB7CisJCWlmIChh
ZGRyIDwgKHU2NClrYXNhbl9tZW1fdG9fc2hhZG93KCh2b2lkICopKDB4RkZVTCA8PCA1NikpIHx8
CisJCSAgICBhZGRyID4gKHU2NClrYXNhbl9tZW1fdG9fc2hhZG93KCh2b2lkICopKH4wVUwpKSkK
KwkJCXJldHVybjsKKwl9CisKKwkgLyoKKwkgICogRm9yIHg4Ni02NCwgb25seSB0aGUgcG9pbnRl
ciBiaXRzIFs2Mjo1N10gZ2V0IHJlc2V0LCBhbmQgYml0cyAjNjMKKwkgICogYW5kICM1NiBjYW4g
YmUgMCBvciAxLiBUaHVzLCBrYXNhbl9tZW1fdG9fc2hhZG93KCkgY2FuIGJlIHBvc3NpYmx5CisJ
ICAqIGFwcGxpZWQgdG8gdHdvIHJlZ2lvbnMgb2YgbWVtb3J5OgorCSAgKiBbMHg3RTAwMDAwMDAw
MDAwMDAwLCAweDdGRkZGRkZGRkZGRkZGRkZdIGFuZAorCSAgKiBbMHhGRTAwMDAwMDAwMDAwMDAw
LCAweEZGRkZGRkZGRkZGRkZGRkZdLiBBcyB0aGUgb3ZlcmZsb3cgaGFwcGVucworCSAgKiBmb3Ig
Ym90aCBlbmRzIG9mIGJvdGggbWVtb3J5IHJhbmdlcywgYm90aCBwb3NzaWJsZSBzaGFkb3cgcmVn
aW9ucworCSAgKiBhcmUgY29udGlndW91cy4KKwkgKi8KKwlpZiAoSVNfRU5BQkxFRChDT05GSUdf
S0FTQU5fU1dfVEFHUykgJiYgSVNfRU5BQkxFRChDT05GSUdfWDg2XzY0KSkgeworCQlpZiAoKGFk
ZHIgPCAodTY0KWthc2FuX21lbV90b19zaGFkb3coKHZvaWQgKikoMHg3RVVMIDw8IDU2KSkgfHwK
KwkJICAgICBhZGRyID4gKHU2NClrYXNhbl9tZW1fdG9fc2hhZG93KCh2b2lkICopKH4wVUwgPj4g
MSkpKSAmJgorCQkgICAgKGFkZHIgPCAodTY0KWthc2FuX21lbV90b19zaGFkb3coKHZvaWQgKiko
MHhGRVVMIDw8IDU2KSkgfHwKKwkJICAgICBhZGRyID4gKHU2NClrYXNhbl9tZW1fdG9fc2hhZG93
KCh2b2lkICopKH4wVUwpKSkpCisJCQlyZXR1cm47CisJfQogCiAJb3JpZ19hZGRyID0gKHVuc2ln
bmVkIGxvbmcpa2FzYW5fc2hhZG93X3RvX21lbSgodm9pZCAqKWFkZHIpOwogCg==
--0000000000009180c7062f3ce9f2--
