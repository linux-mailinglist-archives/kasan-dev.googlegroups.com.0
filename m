Return-Path: <kasan-dev+bncBAABBNWYVKXQMGQE5IFB6IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CE61D875DE7
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Mar 2024 07:12:07 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-59fa26aae1csf435332eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 22:12:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709878326; cv=pass;
        d=google.com; s=arc-20160816;
        b=N4O4MKyW2+Jqc7tisppCa+n0wUepm0i9OLtLTDddy5XsozPxZd5l/PNsvQilmuvXYW
         YidgFf+pOE0K+LQrxgv3M9EU0GZ00TsHXOJK26OgZrnMHjFUwujh8oiJzk7x1atrDkJx
         Tpk5t0/9t//UaPKD0TPJE2c4wagANP+8b7rr/GD6ifR8XuBLBf3P/l7b/PszAXET9uX4
         zadsITH2RhpIKuiiabYFb7u809JEDB1SReBFD+cOv3FllPFw55dfmO01Hq2fSWS6dNzM
         xVKfGin+2EMFrUhju8iJB57toporAJdESNvp5vI8cYlaA2Polk7cZXvkF8zWcQvKo2Li
         zQ9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=0bqQUw5WkSgptO6Jsg741+bsKT53feipkdmlpY/jA18=;
        fh=wp5ROQctpY9L/dUl+tipo1yJRNnE8G/sEAJ6SFfJk1s=;
        b=N96Rz9R9tkK0UKBFW4P3+dlwFAfa+1iSNWCqqzsKH8J6ochar6APKzHMLFoOSNHpMm
         uHCr3VVLwNlXP1V5bcYMArgQ3ZmPinctHvAyh3fUrxWM/Vp8EqFjokuyuQPDq7wjB/+2
         7eKkezx8z+Ii2fXu0IcPURuZDaisQmqIsuyQ67PY7xCGsIpFGKtpVHnyxZ/fKAhv9FQL
         rNGdfUh5rK4+NPXAzGZCFFIfYSzeQitDaBruFIF/V9JLwbtP9v4nb75Xnb65Xrd1quTH
         13DE5318T/GzqcYG9U+fDdfB0gIru+G6L54L6wUoQdYP6Wh9ZVpTzAvBmC9CB0ZCpA+u
         QeRA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709878326; x=1710483126; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=0bqQUw5WkSgptO6Jsg741+bsKT53feipkdmlpY/jA18=;
        b=eCRoZvS7ZY94bS9sueNSg9nfCLA6O1PGT0itLsyH2E6Or02gdNd1a1nW09LDuSdSKm
         2bLMaBMlfEg6Vhd4NqNlWhENbNovTNS5JJGXCR+GG3BxT9h4RqUxQgjTma1a9a0XCXcp
         Vp7FhafQqOEw4PeAe3ooDrUTw5GmBBFnnjFGg2r0xLU3atFdwXM3zUzn1h4jKubQuTnb
         dYiliPSZTZdT1jHUtqSYceTRv9e23hetifpJJvHK2LuS4I3W1qibJVXIYKFXIcwG786z
         q/4drnV1ps//Onf99mxhYjJgSxqBHsg04jjiZYcQmYjdQGRAng9vZQmvMiBWyNfUQUU5
         8dSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709878326; x=1710483126;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0bqQUw5WkSgptO6Jsg741+bsKT53feipkdmlpY/jA18=;
        b=UpKZcn9xUtBnf/QXx3GvodrlP/UBPUiburcw0093vUDKWXA2mRgyYzuWLEVigzzo2u
         YKHrOoaZXUBd5uBzDOHA3Q1fthAIO0eEDKSTOSx7pq9/+eLNoDZyW6JDd6Dkmjv11dTf
         n41L2gkDe3jYyfJq4ursQtvrISjU3kKWoD7BmWPIZWJqRHF+ThdO90kAWSuTe0OQ2vXB
         YuOaSW3njlCV7TuEl1uCG+4X4ySr1GRSZMaVkWZj6laa91B1fgDIOM4Xit1jqOUaOYzZ
         HQ70xgWe2aN9Wp3Bp7SDElUhv5E37Fe+ttMwxpswT4fgMlE36qIb+wAwTOlOQoTdQEgF
         LVmw==
X-Forwarded-Encrypted: i=2; AJvYcCVNMOm1dxCS+wzPBI0nkhNyOIw9jusv8+S2tQo0XpOkB3X7ZrZKBAqiil8VLKItea9KHJ4wOSB6og1s19zhYB/A4BLJgvDrHA==
X-Gm-Message-State: AOJu0Yww77tCZCFUv0VsBuSmDzFzYvE8rfdM0WZpex/3s+Eq0+Vhuh6L
	PqeEiDrA68lGurWHw2oeRaQkoJap11iFIGUIR6D9NfCsB88MkbmV
X-Google-Smtp-Source: AGHT+IH5rSlpzRe4oCOZ+wG+iWRh8IgoPdbLolvetWjusb0A1CSIuy1MELtk0BkH4nP2THigj3m7xA==
X-Received: by 2002:a05:6820:80a:b0:5a1:4520:7354 with SMTP id bg10-20020a056820080a00b005a145207354mr11416374oob.9.1709878326196;
        Thu, 07 Mar 2024 22:12:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:58d4:0:b0:599:1da6:a4d8 with SMTP id f203-20020a4a58d4000000b005991da6a4d8ls1617981oob.1.-pod-prod-03-us;
 Thu, 07 Mar 2024 22:12:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWlc/kTQGG9hljlsqomb3RF5uNwX29l/AqL/fotCn2zT2zUu3ypVjFV6cPgYaI6ZZUDGv/RbVSzlhdVRjfAeahIKMhyyUJhu1H5ng==
X-Received: by 2002:a9d:6758:0:b0:6e4:e483:863f with SMTP id w24-20020a9d6758000000b006e4e483863fmr10447726otm.23.1709878325614;
        Thu, 07 Mar 2024 22:12:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709878325; cv=none;
        d=google.com; s=arc-20160816;
        b=Wdo5qJuzjGhoK8ypTf2yGyjwVEdR/jhxicZ7SlqMMmDPZ6levJNS7j7Wpoi5lLwaQ0
         ZBnc1o4707lIW8Dx+AuqbVpvAf8s5HlovanMpxTCFK9kmUJr1wjqvVwpz6ERIcqaTFMH
         jIQX7b8hUNN6FUIOAN6Rv6ffuHSjqVv+4yZgR7D3LDfPbOihZUrh83uBGnRGg2DtebvT
         jnWx+LuS1GYCiOv31mGDQnZ8mFIfVv4H1LZjkJxnc2yvYDLZy4pTBmHKQos+MEl0ZpCT
         TQ+xMTQ9sYUXkEmB6ktMoYqwVwTXM9B/x/7G3IlZPVkMGJULaTNOTwwqa1DINzs9n66u
         PdIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=ggk6dK8sGdGszEbTErHhdpg+ACGp4m0wQJlZqxHG+Pc=;
        fh=dYmgIcezpW7bgI6lPLoNFAhecg1cRbpUbQnR4Cml/tk=;
        b=dqQKPmhfwLuuriq8Y+vRrGjlq35TVEUoA1gISViGf1pKppZr7/Nmwt+P5oRPTeH4sK
         kfwavbjTJsJB6TK9dVTedJy4oY9wOljjjcCJDLDkSmHCPeSGJnCVGM3847EzcKyiyRS8
         dMvkYgj26KEpJeVfRc7D2E9d6UVkhsC55891AD8M4S70/CiDuyYr+sQ++6q4dkvjjXTG
         QVpXb2YMadAOqvtIUpjWGBY59gbWc5tc3x+G5IAlpsmY0PRI2Ie/YiJhp5lRVFLqTMRx
         W0CZXOiAUTnP+TkR3BxaCvVp9thPaqJC0ih8myy5uK9g3ODn/hz+0YqNR3p63/QJKOMF
         VtmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id a4-20020a9d74c4000000b006e4f4540408si583562otl.0.2024.03.07.22.12.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Mar 2024 22:12:05 -0800 (PST)
Received-SPF: pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from mail.maildlp.com (unknown [172.19.163.174])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4TrbNm4FxdzXhln;
	Fri,  8 Mar 2024 14:09:44 +0800 (CST)
Received: from kwepemd100007.china.huawei.com (unknown [7.221.188.221])
	by mail.maildlp.com (Postfix) with ESMTPS id C6E9E1400FD;
	Fri,  8 Mar 2024 14:12:02 +0800 (CST)
Received: from kwepemd100011.china.huawei.com (7.221.188.204) by
 kwepemd100007.china.huawei.com (7.221.188.221) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1258.28; Fri, 8 Mar 2024 14:12:02 +0800
Received: from M910t (10.110.54.157) by kwepemd100011.china.huawei.com
 (7.221.188.204) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.28; Fri, 8 Mar
 2024 14:12:01 +0800
Date: Fri, 8 Mar 2024 14:10:54 +0800
From: "'Changbin Du' via kasan-dev" <kasan-dev@googlegroups.com>
To: Borislav Petkov <bp@alien8.de>
CC: Changbin Du <changbin.du@huawei.com>, Thomas Gleixner
	<tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Dave Hansen
	<dave.hansen@linux.intel.com>, <x86@kernel.org>, Andy Lutomirski
	<luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, "H. Peter Anvin"
	<hpa@zytor.com>, Alexander Potapenko <glider@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH] x86: kmsan: fix boot failure due to instrumentation
Message-ID: <20240308061054.54zxik32u4w2bynd@M910t>
References: <20240308044401.1120395-1-changbin.du@huawei.com>
 <20240308054532.GAZeql_HPGb5lAU-jx@fat_crate.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240308054532.GAZeql_HPGb5lAU-jx@fat_crate.local>
X-Originating-IP: [10.110.54.157]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemd100011.china.huawei.com (7.221.188.204)
X-Original-Sender: changbin.du@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of changbin.du@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=changbin.du@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Changbin Du <changbin.du@huawei.com>
Reply-To: Changbin Du <changbin.du@huawei.com>
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

On Fri, Mar 08, 2024 at 06:45:32AM +0100, Borislav Petkov wrote:
> On Fri, Mar 08, 2024 at 12:44:01PM +0800, Changbin Du wrote:
> > Instrumenting sev.c and mem_encrypt_identity.c with KMSAN will result in
> > kernel being unable to boot. Some of the code are invoked too early in
> > boot stage that before kmsan is ready.
> 
> How do you trigger this?
>
I run the kernel in qemu. One of the calltrace is:
(gdb) bt
#0  find_cc_blob (bp=0x14700 <exception_stacks+30464>) at arch/x86/kernel/sev.c:2067
#1  0x0000000003daeaab in snp_init (bp=0x14700 <exception_stacks+30464>) at arch/x86/kernel/sev.c:2098
#2  0x0000000003db3d69 in sme_enable (bp=0x14700 <exception_stacks+30464>) at arch/x86/mm/mem_encrypt_identity.c:516
#3  0x000000000100003e in startup_64 () at arch/x86/kernel/head_64.S:99
#4  0x0000000000000000 in ?? ()

find_cc_blob() has instrumentation enabled and panic when accessing shadow
memory.

> -- 
> Regards/Gruss,
>     Boris.
> 
> https://people.kernel.org/tglx/notes-about-netiquette

-- 
Cheers,
Changbin Du

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240308061054.54zxik32u4w2bynd%40M910t.
