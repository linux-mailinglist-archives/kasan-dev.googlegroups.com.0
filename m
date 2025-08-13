Return-Path: <kasan-dev+bncBDB3VRFH7QKRBV6L6LCAMGQE4VFZFPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 226B8B24C62
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 16:48:57 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-8816e763309sf680786739f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 07:48:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755096536; cv=pass;
        d=google.com; s=arc-20240605;
        b=QgWlkFw9uKXab0nd5MOPc3kHf89wQ6uM0fxb7xiJRvng+XyYOnOoZlnBSiyh2jbZt5
         NMIJHBm0NFvAGAm0vqkuCqJeoPyIoPaR6XsFD4mEKv9WlbEEcNbDwz9qOxLNSZuZbiH/
         EG+bQN8EK7JEdhMtjEGFB+5+B3Pnn+NKNes5pkMsjBJYyOz2Qo/e50c5bRCcu4xYd82R
         UW3Bcn0b+UMeQA+YvIOi/F81/KViF4a+9Om8GKlumaYqH1Zm+iSK4rmiUFiOyDrT1TCe
         mAUu9kP34w87oWfCcvZ736tcdMXqvbBZeuf1kecVnJyvZSPR5Q+jtueI64KzOijLNX9B
         v3mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:organization
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=BXtBALy7Gk3Ofy34TBD+OX1sHvQ3VkFmyLChK6aON+U=;
        fh=GIBZoDx41b4/6uAjNHudLvNlJRELbgOt/BEM496KlJI=;
        b=IDTL9ucKhX63fffPjCByoi5AVrLWIH1NLVo9eqfhfed28HPhD2mkfwy7SRA7G8M6Dx
         cgvqfv1PffbtxTe1hd0IwLyalAI7iT/jGYIgoS+UP+GtHGtYm7yEV6A7QyLXp+gI/+lM
         eLYyYr9Gnuo+HZE77I3hcb0/9Ik6XHa4qdpOu/mfeZh4xqENLOEYy6ehy1rDP6sV7Hge
         82nBkxl+8VGwXq+/3472sDxNnz6fPZ2RE2zj6coOtPui6Pv+3DaZ6V50kabGwAFFsYkX
         HWJIyJMx8Sw+jCCS6mxFiZi6ygYjtkir3V+O7aJo56qm8Y6Fw0yW5CpWCwJPyfAdHDlZ
         6KvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755096536; x=1755701336; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:organization:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BXtBALy7Gk3Ofy34TBD+OX1sHvQ3VkFmyLChK6aON+U=;
        b=XkmrQ5NHcJJkd5O7Myu5FgHf+Rldx/lfsB9jA3v95w/LC6BLXLvk8JMyEwFL22CsER
         GZCECQCuWIHtaG6Kr2iXHHPhdEH5p8thRPxcE0TcyvXNg4ChVnf9b1q5+kkLD6qQgsc4
         No4hxJN2MGkY8uVU4+cKBtUSNWovMZ0KWhTunYsn8qF5ln9lrZx4QVJ4DmNbcdGMaKby
         ZiOx05rhKJIjnzYCJnfwzrrX5RF8dbWKbXVRWomHB86VGQJBLOj9M38nIB5mvLut0E/h
         JeDK05v86WmRUOT5UaiJC6OyYWC/V34g51L9a4QJNRYTLSxFaNXLNoK6f1W8YE+RHWp0
         TEvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755096536; x=1755701336;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BXtBALy7Gk3Ofy34TBD+OX1sHvQ3VkFmyLChK6aON+U=;
        b=samBsHBv1yKXWI+r2Est5aG8kBSVFFIxqm1YBwqKgPjPnVqgUlZ2WE0eIrlZ6xEr/z
         XjoIVMnDeFpcFCKIFcs6FZsZKLplWxI+wplaQLxQQH9PLNVRXCW5RN//HVXkIJD81iTn
         fySIsZCtdFnQEAb1VMUqlq7a3uGAXBnQSFnbd/w/HPsx3nMj6F0ZEJm8jgq7/g1jub07
         5q05gUbMcQEkYUZvWj6u7fEwkdQDGT+akc5KExbOpM/gwfaDmJLp7Fz518a2KuHrxhjO
         Xw7yCJ8PRPQZ3LyU3dwaT/PLOylYeniV9MalOAQcsARMJYo0S9C5+DWTCO582+8iKBtY
         HOng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUQei5etMNQvF3U+UetrjE49UpE9+uwhkrPciOJ4/qJInXVAtCcYFveNyLv0hPSV11JjJtazA==@lfdr.de
X-Gm-Message-State: AOJu0Yyf0odf035/9QvSuYsSYyPyesk9z/LZon7OsbiRGYBfg/AeEJpP
	utPuez6dTmJZqRWmj3Q3QHq69fkQ43yYHxR4B6QrKO6B0ik7ImLZrziK
X-Google-Smtp-Source: AGHT+IFR8pYT2ud5QRQuwRR/boEdMXGU0GUQqKfZCXEDpMY1ZBzSTJf5Ng2EctZcqZzKjkU47SmNNg==
X-Received: by 2002:a05:6e02:1a8e:b0:3e5:4154:40fd with SMTP id e9e14a558f8ab-3e56739dd3amr54839925ab.1.1755096535841;
        Wed, 13 Aug 2025 07:48:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdgSVaJgF3ao+MON7b1FXsqMMiEvgcSH4VVRSb/fjuq1g==
Received: by 2002:a05:6e02:4604:b0:3e5:1e83:a822 with SMTP id
 e9e14a558f8ab-3e524aefd36ls64441825ab.2.-pod-prod-07-us; Wed, 13 Aug 2025
 07:48:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+AmNOnFrgFa9+UlQ5lfsfLbv2+lOJq9h5T+4b8mLH73BjHfDBosbiCl/ZitJdvWAWshMg2uR90gk=@googlegroups.com
X-Received: by 2002:a05:6602:6c03:b0:884:315d:e433 with SMTP id ca18e2360f4ac-884315de450mr113918339f.12.1755096533530;
        Wed, 13 Aug 2025 07:48:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755096533; cv=none;
        d=google.com; s=arc-20240605;
        b=XGPKLepDc862+oLT8CCmHhw5I1FTvwBFgbxqjaVIuzybaQ4msbET5U9WuGD5fglyGS
         6vtX8a+ElHGm0XTPD45fMfs0T2teTY4bm+1CVjt7nulHtibslpXQDEzfZp9/ZFiF/svm
         qLfXeq+NTlHuKxdN/oVBVXHyx4orx68DhqnlOssRgVBP/rsoe5Jex/jGJ3SEFo+SeZ7g
         HevzYIysTcBb7sbXHgTeta3Vgij6NvAghMF/BzjekbI5HvfTb4whNan/+xQFCvt6fMQ5
         4pV4uMambNZSmngamfuWWZmXkX98e+kg4BB+aRTqOb5WeV3qoYsiOpLqrHLGwdsdfYAv
         Y53Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:organization:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id;
        bh=F7gob46kb//JpRUK0TYl19jc1ebhca+bwFhqnvAij00=;
        fh=oaeHw1qMwC0mU/ri8FxDkoEgtWwNrwPpkGfOYJsYqwM=;
        b=MadBiYFHgEBjkd0sz3tvRqI4HlXcOJ0HyoKBHmNzxOQSNvGmsQR7NfLC4E7PfdKIUP
         LgGBw+hJJiP3eL/sbEd1d1AsMQM5z7SQi2gv1utd8KyfSFmC6DBKcGFqhuoxdVHEQyup
         A7DDDxeSOpFEzgAIGfwViP8E6F7C8HhsW+hR+EjQFBJ74w9EpK5fnmzoF9aTwzuXvqj2
         kO7c9KS6yNaQF/O3F1oceuCCUbW9aPV4USiIxg6dW91vBBmE3UxQYa5gFJz2ma4wQUhj
         +VFiouMDNh3AWUemgbr6BN/kJYTadS156hp99953cX+c4Q4IAHZGfPAJ3q1mTtsPfFdB
         ulaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id ca18e2360f4ac-883f18eccc3si61842939f.1.2025.08.13.07.48.53
        for <kasan-dev@googlegroups.com>;
        Wed, 13 Aug 2025 07:48:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 47D0114BF;
	Wed, 13 Aug 2025 07:48:44 -0700 (PDT)
Received: from [10.57.1.244] (unknown [10.57.1.244])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8166E3F5A1;
	Wed, 13 Aug 2025 07:48:34 -0700 (PDT)
Message-ID: <cae90aa0-9fa6-4066-bbc0-ba391f908fb2@arm.com>
Date: Wed, 13 Aug 2025 15:48:32 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 02/18] kasan: sw_tags: Support tag widths less than 8
 bits
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: nathan@kernel.org, arnd@arndb.de, broonie@kernel.org,
 Liam.Howlett@oracle.com, urezki@gmail.com, will@kernel.org,
 kaleshsingh@google.com, rppt@kernel.org, leitao@debian.org, coxu@redhat.com,
 surenb@google.com, akpm@linux-foundation.org, luto@kernel.org,
 jpoimboe@kernel.org, changyuanl@google.com, hpa@zytor.com,
 dvyukov@google.com, kas@kernel.org, corbet@lwn.net,
 vincenzo.frascino@arm.com, smostafa@google.com,
 nick.desaulniers+lkml@gmail.com, morbo@google.com, andreyknvl@gmail.com,
 alexander.shishkin@linux.intel.com, thiago.bauermann@linaro.org,
 catalin.marinas@arm.com, ryabinin.a.a@gmail.com, jan.kiszka@siemens.com,
 jbohac@suse.cz, dan.j.williams@intel.com, joel.granados@kernel.org,
 baohua@kernel.org, kevin.brodsky@arm.com, nicolas.schier@linux.dev,
 pcc@google.com, andriy.shevchenko@linux.intel.com, wei.liu@kernel.org,
 bp@alien8.de, xin@zytor.com, pankaj.gupta@amd.com, vbabka@suse.cz,
 glider@google.com, jgross@suse.com, kees@kernel.org, jhubbard@nvidia.com,
 joey.gouly@arm.com, ardb@kernel.org, thuth@redhat.com,
 pasha.tatashin@soleen.com, kristina.martsenko@arm.com,
 bigeasy@linutronix.de, lorenzo.stoakes@oracle.com, jason.andryuk@amd.com,
 david@redhat.com, graf@amazon.com, wangkefeng.wang@huawei.com,
 ziy@nvidia.com, mark.rutland@arm.com, dave.hansen@linux.intel.com,
 samuel.holland@sifive.com, kbingham@kernel.org, trintaeoitogc@gmail.com,
 scott@os.amperecomputing.com, justinstitt@google.com,
 kuan-ying.lee@canonical.com, maz@kernel.org, tglx@linutronix.de,
 samitolvanen@google.com, mhocko@suse.com, nunodasneves@linux.microsoft.com,
 brgerst@gmail.com, willy@infradead.org, ubizjak@gmail.com,
 peterz@infradead.org, mingo@redhat.com, sohil.mehta@intel.com,
 linux-mm@kvack.org, linux-kbuild@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, x86@kernel.org, llvm@lists.linux.dev,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, Ada Couprie Diaz <ada.coupriediaz@arm.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
 <780347f3897ea97e90968de028c9dd02f466204e.1755004923.git.maciej.wieczor-retman@intel.com>
From: Ada Couprie Diaz <ada.coupriediaz@arm.com>
Content-Language: en-US
Organization: Arm Ltd.
In-Reply-To: <780347f3897ea97e90968de028c9dd02f466204e.1755004923.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: ada.coupriediaz@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi,

On 12/08/2025 14:23, Maciej Wieczor-Retman wrote:
> From: Samuel Holland <samuel.holland@sifive.com>
>
> Allow architectures to override KASAN_TAG_KERNEL in asm/kasan.h. This
> is needed on RISC-V, which supports 57-bit virtual addresses and 7-bit
> pointer tags. For consistency, move the arm64 MTE definition of
> KASAN_TAG_MIN to asm/kasan.h, since it is also architecture-dependent;
> RISC-V's equivalent extension is expected to support 7-bit hardware
> memory tags.
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
>   arch/arm64/include/asm/kasan.h   |  6 ++++--
>   arch/arm64/include/asm/uaccess.h |  1 +
>   include/linux/kasan-tags.h       | 13 ++++++++-----
>   3 files changed, 13 insertions(+), 7 deletions(-)
>
> diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
> index e1b57c13f8a4..4ab419df8b93 100644
> --- a/arch/arm64/include/asm/kasan.h
> +++ b/arch/arm64/include/asm/kasan.h
> @@ -6,8 +6,10 @@
>   
>   #include <linux/linkage.h>
>   #include <asm/memory.h>
> -#include <asm/mte-kasan.h>
> -#include <asm/pgtable-types.h>
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define KASAN_TAG_MIN			0xF0 /* minimum value for random tags */
> +#endif
Building CONFIG_KASAN_HW_TAGS with -Werror on arm64 fails here
due to a warning about KASAN_TAG_MIN being redefined.

On my side the error got triggered when compiling
arch/arm64/kernel/asm-offsets.c due to the ordering of some includes :
from <asm/processor.h>, <linux/kasan-tags.h> ends up being included
(by <asm/cpufeatures.h> including <asm/sysreg.h>) before <asm/kasan.h>.
(Build trace at the end for reference)

Adding `#undef KASAN_TAG_MIN` before redefining the arch version
allows building CONFIG_KASAN_HW_TAGS on arm64 without
further issues, but I don't know if this is most appropriate fix.Thanks, 
Ada ---

   CC      arch/arm64/kernel/asm-offsets.s
In file included from ./arch/arm64/include/asm/processor.h:42,
                  from ./include/asm-generic/qrwlock.h:18,
                  from ./arch/arm64/include/generated/asm/qrwlock.h:1,
                  from ./arch/arm64/include/asm/spinlock.h:9,
                  from ./include/linux/spinlock.h:95,
                  from ./include/linux/mmzone.h:8,
                  from ./include/linux/gfp.h:7,
                  from ./include/linux/slab.h:16,
                  from ./include/linux/resource_ext.h:11,
                  from ./include/linux/acpi.h:13,
                  from ./include/acpi/apei.h:9,
                  from ./include/acpi/ghes.h:5,
                  from ./include/linux/arm_sdei.h:8,
                  from ./arch/arm64/kernel/asm-offsets.c:10:
./arch/arm64/include/asm/kasan.h:11: error: "KASAN_TAG_MIN" redefined [-Werror]
    11 | #define KASAN_TAG_MIN                   0xF0 /* minimum value for random tags */
       |
In file included from ./arch/arm64/include/asm/sysreg.h:14,
                  from ./arch/arm64/include/asm/cputype.h:250,
                  from ./arch/arm64/include/asm/cache.h:43,
                  from ./include/vdso/cache.h:5,
                  from ./include/linux/cache.h:6,
                  from ./include/linux/slab.h:15:
./include/linux/kasan-tags.h:23: note: this is the location of the previous definition
    23 | #define KASAN_TAG_MIN           0x00 /* minimum value for random tags */
       |

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cae90aa0-9fa6-4066-bbc0-ba391f908fb2%40arm.com.
