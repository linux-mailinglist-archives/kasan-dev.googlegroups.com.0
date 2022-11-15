Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBK52ZONQMGQE3RXSGRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 61F44628E52
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Nov 2022 01:28:29 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id i8-20020a170902c94800b0018712ccd6bbsf10026764pla.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 16:28:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668472107; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mpq3Z4eUvApaIMH0naxO2iqcbNiTb7Y/UmWNuh8O9kPJfXTr8anTJzpoFywpkXYaRc
         7j7QVakwkLWPxWhb7MxXAnwfL9XfZxG8I4wXIRdXmwrakPT9aBysqub/4EOjb6h2aD+U
         EBGywMt1cnRXQQJBzIvV0mmgeTwdVysMUYzQHiSZMNy/BgkgDsYKTb3eQqTbMiysAsS6
         YKlZRtDQj5MG2zxgZgM77+IIyHIkvaDND9wmw0v65JRDa5l7HWXr8qpZjrhdXvZmBlLJ
         EuvehroZkAa+bfy+h38abbbubo37gvWL5odA3X0g72Exn6OaFptsURQzhhI+NKllnhF2
         dDJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=/r48ZeLXG72Kx0T1pb+kVgHl/sZsVbYEFNzSL4hySvo=;
        b=Uam/m7vWZOy+a/B+GEn/OzJxxrQ6rueCaJ39DXFnZRpDCYL2uQ+qqq+y4DLotXran5
         Cj9weIpXk1bFHW8p8eZ2Gp0Q8rCWSvuDMwVuT1pZxu3aEHx1ACvWRodeF6+gs7vS2Bdn
         ZBhgFmUEBzByl3KicfrAV6dpqrB/6CPh7XeeK5xrxf0RsBLj7c/XBzrLFNvL3WqZjfQp
         zWZqwEsXv/zBX4enwrqobBHgv62wIlLgZNE0IwvwG0EfxsxCZwQPSS1ArMJ4d4UZ9a/d
         bFH0Skg5h3mU7+szn7umbvoQhprccqgOWxLARPoSHk41s6bjmL0F7tgLFYeBNRne9qD7
         DLCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=M+ej6YNU;
       spf=pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=seanjc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=/r48ZeLXG72Kx0T1pb+kVgHl/sZsVbYEFNzSL4hySvo=;
        b=V7EzcE7A+dM2XaD6c27c1mEznlfI5f9UFKxlUrI68tSM5RJNe0FpD5IK12W9lB8Rd6
         8xiRnbwEMxbezFWf32dgAQLjUOuSlqHOLyFmd9DiJKimmli16dVuzSzXeJRV61aRe6e3
         /av2fLQ1jf21joJ+LvqohFOX7ahqcxLd61a9soKZGIfruOySClGWUzYWHBc8HzAI78gY
         DiKxSMGcO43CLOelSTTpqL3XH6ORY3a5yktBTGjlCv7MDgu32TW3ZLO7kq2aqjzGOCS1
         eu2X9cH+LUJxlNJJc477SaVsjyBvk0LaJVTIrC917vCxCYvDB6+Iky+faG57kt+J4hMj
         XWxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/r48ZeLXG72Kx0T1pb+kVgHl/sZsVbYEFNzSL4hySvo=;
        b=fnbry/Mh43eUI3PFRavT8+euaZCBUiIf//TMjeQ0qOXq2SF+Rc+RGC66dmwX8rF1+z
         S3j+6yrPt6GsCsKR73lfZ3/kun4NhXM6TZQaIuZlZQQ72HWaKT0OMGxy/ahtjkSy/ydW
         /VPXWDx0nG2m4pgAoQxW/FvHRYwI7BvonNV7wS1JyyVGbWIdlGZTXOvkjGgqa9E6m/Z5
         O/miBwxicXLRwc6ngZ0I7ZTKCAd4OQ618Ddm0S8TmBU5gcLmV3z/0Co/MfbMseAlTYkk
         cfCS20osrSBWoG+o3D3GIdIoZP/YKb7I9WFw8AimJpRFfYvvPm5TWN5Y690HP3QaLt3k
         0qow==
X-Gm-Message-State: ANoB5pmAYXdl1MYTICvTAo0E1SISEVepMVM2nDZjIKcTUHhpWC3qXoxa
	s5L1+1980U+4kI4oXr7Bldc=
X-Google-Smtp-Source: AA0mqf7Mb2zi2IPoKvSuQfGttgA57QBsQgoXFFpvqJzV4+hdLH1dfqC/ikqdXp34kChBEJAD8iAbww==
X-Received: by 2002:a17:902:f10c:b0:186:cbf1:27e3 with SMTP id e12-20020a170902f10c00b00186cbf127e3mr1486214plb.143.1668472107636;
        Mon, 14 Nov 2022 16:28:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8545:b0:186:af8a:6095 with SMTP id
 d5-20020a170902854500b00186af8a6095ls8940792plo.4.-pod-prod-gmail; Mon, 14
 Nov 2022 16:28:27 -0800 (PST)
X-Received: by 2002:a17:90a:e504:b0:20a:7ec2:c96d with SMTP id t4-20020a17090ae50400b0020a7ec2c96dmr15640642pjy.178.1668472106886;
        Mon, 14 Nov 2022 16:28:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668472106; cv=none;
        d=google.com; s=arc-20160816;
        b=fRO2QKNjzAOA3tkXVx+HQwBLDQa/qN+OFATgzjqNHjjcb6Kt3k9s6IpYFcg9sjphGD
         qrmEG+l2km5WK7lJsd1n9KXAQIV3/gNBsct9D0jrYqu2KE+m22a15OziFJ+AtBEe3Y8F
         jFWsn6G5PsF8n75movqL0NJ8Ce+lefdQIFj9Gq82Ujq30XZIryl/hjlJppjMKLi6YtHP
         lKvc3GpsbKU90PSqNYH4ASIqonVS5VLbHy4TaosanZlEm3bqRLzfvDxoTuXs7ORjHW3M
         NLY6MSEq9f9prSFQJxkbgqJy/dL0oacpokshPqVeWPw2kk4y32zW9ntjSTO7mOorf1fL
         ZVfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/YrBEvXICaKRM/i8fkul3YbdI3Fttajyw5Qa3v7k3N0=;
        b=bq0Sf9quUgrchBgDV67SM/oOYIqjhLLYW00XPWyaXEpXOWPXWyfrjNQbzY48YdtXoW
         avn3K/w0ZdjQn06IRjmXEJVfuG6OoicTM4UTnvleRQqRy9gD5KI5L/3QMUS2Nm2TH8nj
         KZHBcQDO4dNTzAiohVz/qoHFqfdDoKKwAs5YhwjpRXZhhSMLsG2EsprgM8C0DbJpkpD5
         NiUGUKjGba0foHxSaz7b3La8Eb78aFctoi8jRleSiyR9It/ewmnN2bAkB4Eigywb1+GX
         x25E6cSUthV7KF+ebyL39BWe6F8AXBpyW/POkHW1+Uz1PdPS7v3Wy53l/FZOaBKrHB+R
         PHpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=M+ej6YNU;
       spf=pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=seanjc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id s18-20020a170902ea1200b00188c5696675si230105plg.6.2022.11.14.16.28.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 16:28:26 -0800 (PST)
Received-SPF: pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id h14so11849865pjv.4
        for <kasan-dev@googlegroups.com>; Mon, 14 Nov 2022 16:28:26 -0800 (PST)
X-Received: by 2002:a17:902:b695:b0:186:6a1d:331d with SMTP id c21-20020a170902b69500b001866a1d331dmr1543431pls.168.1668472106475;
        Mon, 14 Nov 2022 16:28:26 -0800 (PST)
Received: from google.com (7.104.168.34.bc.googleusercontent.com. [34.168.104.7])
        by smtp.gmail.com with ESMTPSA id i3-20020a636d03000000b0046f6d7dcd1dsm6487819pgc.25.2022.11.14.16.28.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Nov 2022 16:28:26 -0800 (PST)
Date: Tue, 15 Nov 2022 00:28:22 +0000
From: "'Sean Christopherson' via kasan-dev" <kasan-dev@googlegroups.com>
To: kernel test robot <yujie.liu@intel.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, oe-lkp@lists.linux.dev,
	lkp@intel.com, Dave Hansen <dave.hansen@linux.intel.com>,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	kasan-dev@googlegroups.com, Han Ning <ning.han@intel.com>
Subject: Re: [tip:x86/mm] [x86/kasan] 9fd429c280:
 BUG:unable_to_handle_page_fault_for_address
Message-ID: <Y3LdJni8+ye/soOV@google.com>
References: <202211121255.f840971-yujie.liu@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202211121255.f840971-yujie.liu@intel.com>
X-Original-Sender: seanjc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=M+ej6YNU;       spf=pass
 (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::1032
 as permitted sender) smtp.mailfrom=seanjc@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Sean Christopherson <seanjc@google.com>
Reply-To: Sean Christopherson <seanjc@google.com>
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

On Sat, Nov 12, 2022, kernel test robot wrote:
> Greeting,
> 
> FYI, we noticed BUG:unable_to_handle_page_fault_for_address due to commit (built with gcc-11):
> 
> commit: 9fd429c28073fa40f5465cd6e4769a0af80bf398 ("x86/kasan: Map shadow for percpu pages on demand")
> https://git.kernel.org/cgit/linux/kernel/git/tip/tip.git x86/mm
> 
> [test failed on linux-next/master f8f60f322f0640c8edda2942ca5f84b7a27c417a]
> 
> on test machine: 128 threads 2 sockets Intel(R) Xeon(R) Platinum 8358 CPU @ 2.60GHz (Ice Lake) with 128G memory
> 
> caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> 
> 
> [  158.064712][ T8416] BUG: unable to handle page fault for address: fffffbc00012de04
> [  158.074534][ T8416] #PF: supervisor read access in kernel mode
> [  158.074537][ T8416] #PF: error_code(0x0000) - not-present page
> [  158.095763][ T8416] PGD 207e210067 P4D 1fef217067 PUD 1fef216067 PMD 103344b067 PTE 0
> [  158.095770][ T8416] Oops: 0000 [#1] SMP KASAN NOPTI
> [  158.095773][ T8416] CPU: 34 PID: 8416 Comm: umip_test_basic Not tainted 6.1.0-rc2-00001-g9fd429c28073 #1
> [ 158.107429][ T8416] RIP: 0010:get_desc (arch/x86/lib/insn-eval.c:660) 
> [ 158.107465][ T8416] insn_get_seg_base (arch/x86/lib/insn-eval.c:725) 
> [ 158.117492][ T8416] insn_fetch_from_user (arch/x86/lib/insn-eval.c:1476 arch/x86/lib/insn-eval.c:1505) 
> [ 158.117496][ T8416] fixup_umip_exception (arch/x86/kernel/umip.c:353) 
> [ 158.187382][ T8416] exc_general_protection (arch/x86/kernel/traps.c:733 arch/x86/kernel/traps.c:721) 
> [ 158.187386][ T8416] asm_exc_general_protection (arch/x86/include/asm/idtentry.h:564) 

...

> We are sorry that the testcase and reproducing steps are not available
> for this case. Hope the call trace can help to investigate, and we can
> also help to do further verification if needed. Thanks.

Luckily, it's a known issue.

https://lore.kernel.org/all/20221110203504.1985010-3-seanjc@google.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3LdJni8%2Bye/soOV%40google.com.
