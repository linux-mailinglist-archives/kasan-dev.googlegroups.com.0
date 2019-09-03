Return-Path: <kasan-dev+bncBDQ27FVWWUFRBT7UXPVQKGQEQRIYDKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A49AA77A5
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2019 01:42:09 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id y12sf6281141ybg.14
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 16:42:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567554128; cv=pass;
        d=google.com; s=arc-20160816;
        b=BVr8lXTIOpuRaXjN31XOED5ufG1eGi6F5Qcolh+YrZtUdGbNGPXMdjinkKU9tin/9X
         lhypxbbxhmyDflewuEveFz/ST9GzVfT3QvCwIs/koXzgQUifeC2JFO7vjBy5nGjysdss
         HSmLUEOmaA2OKyyXR09VzWCxmcN/U1rE2nou7ENc3GpssMLpHI0wP9eY9PSUD8d/PhM4
         khI/zHxGZobVmuqADFb0GfTpgUEGb/r0FETLmL7hW3kxTPK0gdD/Lv4P5DUeaj8/esmO
         YpyoETL6bifAOrORlT3Ga4IhVZj5TQZoMbOT60vw4UyMcTJvg4W/afANyLYKxDUciekY
         HVFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=OqLKPHezAuDTEvCarkDmkZL9xcLIrk6uL/UECg8vrRs=;
        b=F0/LqceLAA+y+zMkzwQJTqckB61G8PApucGscendKUtN8Ti0zTy0QqYsOSZiOnkVLz
         ZyFManAENc/d6YHACvfqrIzHUjRNakA6I56Y1D4E81ahub6aEFvfGpFmBizLIxJqIRXM
         Yp92ecYC2Xb7Obawd+Pw/qshCS0qMrRVmXqRTACZJx+m4TUep8VfKmxOpqKrZYmqcNn6
         QWH2mntrN7CV31zvDgCRTC0gCKRSk6nCJEnksBKdXPGNtHXtRf7RnY/O5OIzzNxqy1tH
         dc4tBInRKQYZbgXLcmbF6xxPImgLNQ3Eu8t80oLMOVe9HF1JXV4uyvmA2kCTFU9SXH/D
         CUBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=AIRHruYm;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OqLKPHezAuDTEvCarkDmkZL9xcLIrk6uL/UECg8vrRs=;
        b=YR/jxEMszHarT1Z4gqpjcTK0m3kvnfJ6HEonNLEdqr6y2FHXhkk/ebnrj0lFtCRd4e
         0AEvlm3LiVmN4WCAeRMdDeZEctcbgepYh0JiPGHq3iwyYonX47nxoNnJxWz0oDlFMxuu
         BmjPU7zMbqAgbjUc8HzyHfpEEwA72QpxfUHcidnGGq1nP+FWDmqjiteBldTHrhHkSwma
         7GIJCkcgmW2bzXQh8GYt2pcOLarBn8oiwpBKGt6hL6EDvbovxIafwRYyA6J9aNYzWKio
         6je9MnY7oc1k+V1d8L+PtLHzILmovXCZTa7IpS3V2PuUNXkCrDkg++y12vHXlbrSiguu
         cwLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OqLKPHezAuDTEvCarkDmkZL9xcLIrk6uL/UECg8vrRs=;
        b=Wzee9glyVtO6ay5K6ifSuRM6NjP1KDthF9QyTTRIYZ29kwq0dJGXHCuRfe4a/GGFq9
         f1vPOZvnMxBVRLbUFgizExwKdojsx1mYbO4ctCKcq47Ocm2rbB6YwpR9OXxs5tYzTJn/
         o9i+0jSGB7Is3andVU/bSnoRpxgXIkmHbKKqOwPrrx57dqlhXi9t/FK7g60L+xGSdVBf
         eCEiqRw0jlrS0l7DBiofQ2Y5hnj4jwnUAjYiodEwyYvPzQ9+fjRReoVE9tCxi8JMxY74
         rTmNp+sGIVyUG+G8jpb+Zv33NepQFTRHDC8s6UEAhdRxENyT85zMQkYRGpU3JobX8e7Q
         Kq3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX3P1h6TFZvCoO1fIG8ipmzRNECXSXoDg/B8x4LSSTSxuM421zb
	lULeO/IqY3U0s/1JquSNXDU=
X-Google-Smtp-Source: APXvYqwZHcCqM1asPSftKGsvSNH/Mwyd6m7AXy88JG4PUXCUpuIunyaNzIjGjnZh7+490eRtKWTQCw==
X-Received: by 2002:a25:bbcd:: with SMTP id c13mr26616925ybk.103.1567554127861;
        Tue, 03 Sep 2019 16:42:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dcc8:: with SMTP id y191ls2645968ybe.13.gmail; Tue, 03
 Sep 2019 16:42:07 -0700 (PDT)
X-Received: by 2002:a25:d8c1:: with SMTP id p184mr10021071ybg.253.1567554127543;
        Tue, 03 Sep 2019 16:42:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567554127; cv=none;
        d=google.com; s=arc-20160816;
        b=OpGSCasCFKcg8+LxQ1OlJE96esKYCO9CpK5wwZZdw+0xAltco9ueU4pBbvhL2zlmPe
         JVMb8ooT7kkqFuNc4B+p3i/Sl6Ul3Bfx59pbSDOro8tgEnEh2m3tYhlDSugYv1tt7A7m
         371qLQk4DsohKYVuwXURM4sEHHcmec6U2gvw+dAi5EF7v4lwndbiqxxJvJVObSPocdCL
         PThBC7tu+V2yfFy5TN9uLJ3hJFZNx+pG0gRk7iCBHdFwpzei/OhBludkPpubN7dMv645
         TLHUAupFWDOucU/z+0W8VuuwPv2ODenO9KwI4nhy9F8MulU3y02FBa2WawMVowxq9vd/
         l8uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=d3Uvki+kfJgt1m0UONqlkiavQ6oLL7OnGA9HqPCX/bA=;
        b=wU+Yo/LPBbO7/p12Q8t7mzz4sz119mj/f1J0nA/JlHE63kb+Vd3e4MPv8q+idJPGbx
         3u75gqObCgcvQjMcUsVlyEDpZXmbzNsvWIIujRhAFS30BzvC1kUjrNUdMeXftM0/6Rl2
         aqrleJ3mxx5EdTqDRT2UrSLL/x1IG9Kpj7cBHo5FyGAzWx3r27fQQpC2JdXWCp0bdk8Z
         uWZtgmQj+Fp956gmI3BMr1w8u63EcpqmeYfjOUSFtMGE73VctP3M/kmoKAUNm7hEcU2L
         ZunYo8CqkwPU0pq8CzqQrEnqi2rTptg7w3yfWaquexnDIgBbyaCALI0uVNzM0bryMjwV
         k1bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=AIRHruYm;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id u187si550416ywd.3.2019.09.03.16.42.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2019 16:42:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id y72so4346333pfb.12
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2019 16:42:07 -0700 (PDT)
X-Received: by 2002:a17:90a:cb89:: with SMTP id a9mr1908300pju.93.1567554126677;
        Tue, 03 Sep 2019 16:42:06 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id m24sm6976787pfa.37.2019.09.03.16.42.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Sep 2019 16:42:05 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Linux Memory Management List <linux-mm@kvack.org>, the arch/x86 maintainers <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>, LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, Christophe Leroy <christophe.leroy@c-s.fr>, PowerPC <linuxppc-dev@lists.ozlabs.org>, gor@linux.ibm.com
Subject: Re: [PATCH v7 5/5] kasan debug: track pages allocated for vmalloc shadow
In-Reply-To: <CAAeHK+w_HKVh___E0j3hctt_efSPR3PwKuO5XNpf=w5obfYSSA@mail.gmail.com>
References: <20190903145536.3390-1-dja@axtens.net> <20190903145536.3390-6-dja@axtens.net> <CAAeHK+w_HKVh___E0j3hctt_efSPR3PwKuO5XNpf=w5obfYSSA@mail.gmail.com>
Date: Wed, 04 Sep 2019 09:41:51 +1000
Message-ID: <87ef0xt0ao.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=AIRHruYm;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Andrey Konovalov <andreyknvl@google.com> writes:

> On Tue, Sep 3, 2019 at 4:56 PM Daniel Axtens <dja@axtens.net> wrote:
>>
>> Provide the current number of vmalloc shadow pages in
>> /sys/kernel/debug/kasan_vmalloc/shadow_pages.
>
> Maybe it makes sense to put this into /sys/kernel/debug/kasan/
> (without _vmalloc) and name e.g. vmalloc_shadow_pages? In case we want
> to expose more generic KASAN debugging info later.

We certainly could. I just wonder if this patch is useful on an ongoing
basis. I wrote it to validate my work on lazy freeing of shadow pages -
which is why I included it - but I'm not sure it has much ongoing value
beyond demonstrating that the freeing code works.

If we think it's worth holding on to this patch, I can certainly adjust
the paths.

Regards,
Daniel

>
>>
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>>
>> ---
>>
>> Merging this is probably overkill, but I leave it to the discretion
>> of the broader community.
>>
>> On v4 (no dynamic freeing), I saw the following approximate figures
>> on my test VM:
>>
>>  - fresh boot: 720
>>  - after test_vmalloc: ~14000
>>
>> With v5 (lazy dynamic freeing):
>>
>>  - boot: ~490-500
>>  - running modprobe test_vmalloc pushes the figures up to sometimes
>>     as high as ~14000, but they drop down to ~560 after the test ends.
>>     I'm not sure where the extra sixty pages are from, but running the
>>     test repeately doesn't cause the number to keep growing, so I don't
>>     think we're leaking.
>>  - with vmap_stack, spawning tasks pushes the figure up to ~4200, then
>>     some clearing kicks in and drops it down to previous levels again.
>> ---
>>  mm/kasan/common.c | 26 ++++++++++++++++++++++++++
>>  1 file changed, 26 insertions(+)
>>
>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>> index e33cbab83309..e40854512417 100644
>> --- a/mm/kasan/common.c
>> +++ b/mm/kasan/common.c
>> @@ -35,6 +35,7 @@
>>  #include <linux/vmalloc.h>
>>  #include <linux/bug.h>
>>  #include <linux/uaccess.h>
>> +#include <linux/debugfs.h>
>>
>>  #include <asm/tlbflush.h>
>>
>> @@ -750,6 +751,8 @@ core_initcall(kasan_memhotplug_init);
>>  #endif
>>
>>  #ifdef CONFIG_KASAN_VMALLOC
>> +static u64 vmalloc_shadow_pages;
>> +
>>  static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>>                                       void *unused)
>>  {
>> @@ -776,6 +779,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>>         if (likely(pte_none(*ptep))) {
>>                 set_pte_at(&init_mm, addr, ptep, pte);
>>                 page = 0;
>> +               vmalloc_shadow_pages++;
>>         }
>>         spin_unlock(&init_mm.page_table_lock);
>>         if (page)
>> @@ -829,6 +833,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>>         if (likely(!pte_none(*ptep))) {
>>                 pte_clear(&init_mm, addr, ptep);
>>                 free_page(page);
>> +               vmalloc_shadow_pages--;
>>         }
>>         spin_unlock(&init_mm.page_table_lock);
>>
>> @@ -947,4 +952,25 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>>                                        (unsigned long)shadow_end);
>>         }
>>  }
>> +
>> +static __init int kasan_init_vmalloc_debugfs(void)
>> +{
>> +       struct dentry *root, *count;
>> +
>> +       root = debugfs_create_dir("kasan_vmalloc", NULL);
>> +       if (IS_ERR(root)) {
>> +               if (PTR_ERR(root) == -ENODEV)
>> +                       return 0;
>> +               return PTR_ERR(root);
>> +       }
>> +
>> +       count = debugfs_create_u64("shadow_pages", 0444, root,
>> +                                  &vmalloc_shadow_pages);
>> +
>> +       if (IS_ERR(count))
>> +               return PTR_ERR(root);
>> +
>> +       return 0;
>> +}
>> +late_initcall(kasan_init_vmalloc_debugfs);
>>  #endif
>> --
>> 2.20.1
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190903145536.3390-6-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87ef0xt0ao.fsf%40dja-thinkpad.axtens.net.
