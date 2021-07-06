Return-Path: <kasan-dev+bncBDQ27FVWWUFRBWV4R2DQMGQEVPVKCXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id B3D733BC44B
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Jul 2021 02:05:47 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id g3-20020a256b030000b0290551bbd99700sf25144101ybc.6
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 17:05:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625529946; cv=pass;
        d=google.com; s=arc-20160816;
        b=kr6SAeIOp1yuKDugnqscvzKEKoq0kSCD1v9sfMA7lhT/k7Q2DAdrmS807TG0FmE2dh
         dTNBbA+SJs/yLzXytAsBJRFO+lWQ16pG3SB5YzQl5uw04KSm74dcPQigaE/kvIu9/9CS
         9hIYDKyOUmeoxsfYisIEFfPnBTemuXIE3zXtylW9MC6Y2Q5SfVeZJeQOAO2Z2iAvqvQY
         hl3Gnyuuml9ixSZ7blE+UguSQ+tS3beqDQIRfs3QPmk1g25br4tGPyW7HRRkm+mC8VXv
         zrgUiyXiDbwFWepoVfYmOv1IwWruwQ1wKRJGLJmYucZsud59nHiwZKFwtUnD6++8il9e
         3V0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=QEiGPE+tDT3LstHXwgBN7RMAG1jW1Tw7TunQlQTKU+0=;
        b=ZYgrRPljqrjdOzcXzxjGLkl1/aEeF+2LeNcKNDs5S80hiW1D0IQTahJgtoKmfeo4l+
         W1zBt50/ABn/ynXZgouYtb3mXGC6G4Gib5GFkZ9jIPqLUcD2xhbbwtTA86ATwLx88MGk
         V5y2uYJj9q2A6C5QS3ggx/MS2ELTPzysGD7zIXiA0eRJaaKoJegBO55mkUmWrlZXxcW6
         nKyRLhP4nYcC/uusvOZhBmxxjjFTKmRpDocNC8NqGFegvXsvihkAbhwE+yvji4mR/jwI
         UxDNcGKB0jVWSDfwzWziq3o+eVPapTMAyB2YSj9D1I/8URuz7CKE4Dq0ytQ11veNIyOY
         Siaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=hBdjwIEd;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QEiGPE+tDT3LstHXwgBN7RMAG1jW1Tw7TunQlQTKU+0=;
        b=K6Kei6QhGWSqi8UFyNW7AxhG7oc+2cQ7ybS0vA5bXE3jJ9h+QQZwV7qCOUpBmUKWT8
         twyZQGILb8ferrpiA4gCi6/W9NkFdr8Pu7+y5k32YNK35zghmp7+y/YkjWNJc4YsmTzg
         FLc5xupwN0jDqL2ZeUBeP5LmXzSazfkVjUhnYPm6MvwPt8Rb+rzfPUwPe8Y1/4Rz/kLO
         k9KwBr3q2lK5CGHF+ZiTK/FgY7jAAa2AsqFVPpcvNCTs6d1OFskgXL382ZcdpiGNoZ+O
         9EPVAxdOTtXCsx6Kh6oR2CeMQ/HmsbuQauVz8/GSiQRlad1iUvuxyG52drdR0RTNpZyz
         wSwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QEiGPE+tDT3LstHXwgBN7RMAG1jW1Tw7TunQlQTKU+0=;
        b=MNbZfPXex4c/gr0ziBpq/DlQB+szQb6N6Z61HnSyQ1lchlQeb6Qfgpx7txnpXrKl3j
         4H1ExIJsTMJSC1d86BXo/F7/CzRzk8R1uHtaawRAkdx2NY4224A09LJy7UCrJG8g1DaU
         CR29yQbOB5d/cJXJH5dwD8oYXiAfuW5nMgbOHu1afBT/FjgvFV/dpgFDpm0sAYjPNouQ
         zThpDrgSZafHkn+K+5ZYABDzSf3GwfQMpdqJ8lCe0TiNFRc/flBBaOvj64hqbLLs4SCE
         X3HIjJCkAHf1kMwSKSj4V5qOCcnCqUAMNF6JZGd6lvYySqx2I9DDgF5BwQb/m2WHI2qg
         c/pQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530umRgPNYSv7/PHrdNRZ0aaUgiCaFE7Hq5p+8etsxpp547EyP84
	ezp1ilOfUcAnr0wG2P1ZA9k=
X-Google-Smtp-Source: ABdhPJx9JZlHvsPjWrugJAkaBunhEuohg/OjyAp2zzsUPwbXHuAsYhOBNY3FugzpAMDQiSgXLiksOQ==
X-Received: by 2002:a25:e685:: with SMTP id d127mr20912377ybh.513.1625529946545;
        Mon, 05 Jul 2021 17:05:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7bc7:: with SMTP id w190ls4058161ybc.2.gmail; Mon, 05
 Jul 2021 17:05:46 -0700 (PDT)
X-Received: by 2002:a25:ce4a:: with SMTP id x71mr21532406ybe.121.1625529946119;
        Mon, 05 Jul 2021 17:05:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625529946; cv=none;
        d=google.com; s=arc-20160816;
        b=r0iqMgug2OgKvuWGMzLH+IHP0WD9YDq1SAct6y2pBZrgYx6TWJqf9IYxZLit71yctW
         iwSiO4IyQHEmsQMlZMp2wldymggoSh7D7AgP1qPeYhJ7sOEhxadMHQAXUH1yP/oz9aPQ
         7L6kWCkDTNf98CQ+Jw1cI8NOn3teoavPZv+u3C/qJoeVuWrZkvJZFhDrZaqlHVVoEK1Q
         hOC8wAc3eJGrQuPEQotwcjNf78rrCZsnHi3nythQAbCntDMvMuiXg9aJOelPpSfcUijV
         vyDSSFUWErOwh3NGUNfpPBvXZMMlPD9VHUKKEkI6SSa5PpJn0KNHOrITsNsI1V0Jejcs
         ufYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=f7ZB2u7cN1xFre4uiL7GzLzkfmTR/fW1AGUvpXkWqYQ=;
        b=i90KUjwmRhFjNDaylgzhNIH6t8bBoAaftvdecezUL2wSKwYoYeGVbp7/Xsnll8RjXK
         3rY9avV0l1ieiAjFohGh/XfT6xL0sjas9VhJ8CST3Q8Fb8xNXNxRMpQnVK7oirzOWZ6p
         SkRzYFrA9gdZuG7trkWEc8qlRlSXSbxGHDBjUQabS1CUy/v3NPBCsFKYsqWDzYOhd3Ta
         tFK2CsCNEON8YfgZHIJxT9xZq5qgUO7ZY3o5kJApcREW1IkNDImsP95UykFK7MbPtF7H
         2Axrh78kW96iP+M7eU1SGpRa2QKsb8mVxRivRGZxGMSDvJf3z65RD9lKWj/asqobf75q
         YYfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=hBdjwIEd;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id s17si736615ybk.2.2021.07.05.17.05.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 17:05:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id f5so10422857pgv.3
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 17:05:46 -0700 (PDT)
X-Received: by 2002:a05:6a00:5e:b029:30f:d0d3:214e with SMTP id i30-20020a056a00005eb029030fd0d3214emr17518723pfk.29.1625529945768;
        Mon, 05 Jul 2021 17:05:45 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id d23sm12060542pjd.25.2021.07.05.17.05.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Jul 2021 17:05:45 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Marco Elver <elver@google.com>, Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH -next 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash
 with KASAN_VMALLOC
In-Reply-To: <87bl7gxq7k.fsf@dja-thinkpad.axtens.net>
References: <20210705111453.164230-1-wangkefeng.wang@huawei.com>
 <20210705111453.164230-4-wangkefeng.wang@huawei.com>
 <YOMfcE7V7lSE3N/z@elver.google.com>
 <87bl7gxq7k.fsf@dja-thinkpad.axtens.net>
Date: Tue, 06 Jul 2021 10:05:41 +1000
Message-ID: <878s2kxq5m.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=hBdjwIEd;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as
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


> If so, should we put the call inside of vm_area_register_early?
Ah, we already do this. Sorry. My other questions remain.

Kind regards,
Daniel

>
> Kind regards,
> Daniel
>
>>
>>>  void __init kasan_init(void)
>>>  {
>>>  	kasan_init_shadow();
>>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>>> index 5310e217bd74..79d3895b0240 100644
>>> --- a/include/linux/kasan.h
>>> +++ b/include/linux/kasan.h
>>> @@ -49,6 +49,8 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>>>  int kasan_populate_early_shadow(const void *shadow_start,
>>>  				const void *shadow_end);
>>>  
>>> +void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
>>> +
>>>  static inline void *kasan_mem_to_shadow(const void *addr)
>>>  {
>>>  	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>>> index cc64ed6858c6..d39577d088a1 100644
>>> --- a/mm/kasan/init.c
>>> +++ b/mm/kasan/init.c
>>> @@ -279,6 +279,11 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
>>>  	return 0;
>>>  }
>>>  
>>> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
>>> +						       unsigned long size)
>>> +{
>>> +}
>>
>> I'm just wondering if this could be a generic function, perhaps with an
>> appropriate IS_ENABLED() check of a generic Kconfig option
>> (CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK ?) to short-circuit it, if it's
>> not only an arm64 problem.
>>
>> But I haven't looked much further, so would appeal to you to either
>> confirm or reject this idea.
>>
>> Thanks,
>> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/878s2kxq5m.fsf%40dja-thinkpad.axtens.net.
