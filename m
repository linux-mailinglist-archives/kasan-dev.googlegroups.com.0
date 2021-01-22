Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBGHLVKAAMGQEUJEMACY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id C469F300160
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 12:23:05 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id b2sf2900205pls.18
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 03:23:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611314584; cv=pass;
        d=google.com; s=arc-20160816;
        b=bkxpilO0xV5v63fPXLwFGjKtYziQgo5PgGVjcOXdGf5Ds5h9uDbnP/JdL3BmV3l482
         00eOH8aQFSjMcfwg3L3UEGBDnqsJ1G96ZlJSkP7YRelPp/bZ8uJnZtlmBlGhBTJnEYxc
         ZjHzn51ux8gsPlUJ0gHMXsjVQMQI8aRY1rXPB7p0HoksayrtEMgAoYC8cOmNr8Vf/GUd
         1wrMOqIuZEjFXEXDr1AxOfnM9TDaENnj7+rbqdyiNkjfwMHaPkWDS5s0As3LoTEkStce
         M8Sc9fQDVFJJKaiNHzwJ9gKii1DEZg1kOmYIoOvqaiVv4F5a8Xk0DulgnXqu+9HAJd++
         OiDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=M3X86YWbmVOdnqAoM2cw0ULLb4kIsF5TXrrukW4rMbs=;
        b=iv2l7UE/izjzlYZq8BX85VMKp/ZWy9FbFlGSziQiM54FZJ42shUTRfLm0MctH619Je
         sK0ot2NWfOzTV4w/Rd6g++xY87BpUEMD+NA5x9vJmtGtfHsFB9Ds8u/AKEZ1KRafpD+s
         2LBO4CuUVLw5YhA8aqYFkurjz84YcDOgVnC18dDagzS5u7Cc4jasUpjWkmHHnmtDuWUy
         qXl3cf05Te1VtuL/cPmGvvJHumafGYlLpaVgOxO4K8EU9Chyt2JOxb1dUZzgYS1B/xfJ
         VbScWOVPJMoa1pYefe7tEvtLImLbzOhXZU2k/sLzQ0v+A39mqEpkaTLY0aNRzZmLIHvm
         yhtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M3X86YWbmVOdnqAoM2cw0ULLb4kIsF5TXrrukW4rMbs=;
        b=JXehNSrzXYC9nVl3JxeQBTnEvrj+mNo/j9sJnhxNHBFhGOYrkz3Ir8gM0KzrBZS5Ty
         B6howOkGB/Dt8HxNeKkGwT8mjtMHy/bJTcTrkNmxEcmwC+g41nOwk9XUrUzRK8WBkx1n
         DMzWhN+G8FOHFR3C0CskRVwE3PIAH60ejIn6DDnIN0C+TMhdPbkkxwRRa3CI9Yahz9NP
         JGTiAilRvPQ27PXLg/jUT3Jw8WlXyTjL1bU42H3EMDbTlWD4JfBqVBKEmsngK2Ou9et0
         cXUt63Gl+0XXXnb7NBe8uSBOQIy0X6er6srb7j5iPrK8AncsUDktvgs2zsQUcSXZJgjf
         FqrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=M3X86YWbmVOdnqAoM2cw0ULLb4kIsF5TXrrukW4rMbs=;
        b=HMYCFugIgEnuEBp713Ty7iltc+HduHhjJnmnr9TLyA0rFf9ebKMI6qpT+fe+shWa3J
         EgpS63YM9ffiE2LgXAhr9HtuLkeH3nGzSpwIPdz/FZF4S/tKfINHUD863gAo0+5LTG8K
         gARYn7j3OQfA7Gwm1LekSNg+CeP4+ZUCoFb+Fgl/Ke6t8V0SWnMvRW+sj6MT63FpQSSH
         k5NK6L5zROYPAzYnUcaq9UwU8KKqHq2FGOs1avFRc/niWlGxhq2TiJY3CYulwQwzVmrp
         Nzt24yVA8yHKzXzokbrNIDqYlgMVw4DVtPULlnKnmdd3VzXvCWBP0ZjZ8sYPPkF23kqy
         scug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533bLwkR403BO6mtEH6+8p3iyd3s+bp7LITshXRbppad3NWtaTDm
	esTT4/FOTsLwgkFsYUM9xu4=
X-Google-Smtp-Source: ABdhPJxwjZAracAzSm3tb9yh/dzuPsaxthc5OxRFQN0j6NCu9Gaf4rlX2IPZqXnw3s9M1Dbm29y/Jw==
X-Received: by 2002:a17:90a:9318:: with SMTP id p24mr4940361pjo.123.1611314584262;
        Fri, 22 Jan 2021 03:23:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8bca:: with SMTP id s10ls1435576pfd.10.gmail; Fri, 22
 Jan 2021 03:23:03 -0800 (PST)
X-Received: by 2002:a62:61c2:0:b029:1b9:19f5:dcfc with SMTP id v185-20020a6261c20000b02901b919f5dcfcmr4469357pfb.27.1611314583696;
        Fri, 22 Jan 2021 03:23:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611314583; cv=none;
        d=google.com; s=arc-20160816;
        b=moDhe1AzxNi32mTCuT+M8cJi9OEaO4rF8a/vYSwUKqCmfvXrTxMti1r1ZKE1WttvPr
         vZiE/a1MegKhsLbm0zDQ4/Yopdltv5nsSBJFi4vebpXh1MGIKkTSJ7ExFqN46yPhK55F
         6Dc6yp4MFLl81QaxI+obHy2nZ2w0VSEtH+cTuMPCFexPQDRc3UqNluikMuO2HGGw72a1
         c7GLJKycwXd89Seycnyi7w+TRpLwa72N6wryfiGOpkJ5xgLuLsGpHbiVXoCxG1foBSlc
         GOZDZBkT9ZRBcs8C1DXNj0qsnGIGQ/vw1pSaNlqJhrO54VD7bbV4x1kaFJDFHSMtuJSb
         tDzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=jiT9bs4YY/86461CfRJ57WyByWHDJJcbUNHyAbCtq2g=;
        b=s8XGXuFPGJV7jQ2QHVK9HoMvzXbzmQ1M51SI2XI6q6Sf8BwrOKMU3IMtBOGKevBxQ4
         ldy3aQcC7YS8gB66+b94uob2B5rSTtPGW47PmOIQC1uq5sz1JRzCnwWY8vjGd+XA7DU2
         IMoFKQUZ6v65RqHrjhdO0BGF3qeL75t1rNmCtNy4QPsZYhhokuwzKXf8emKpQUIv5ltd
         WJpWgiln6hqisKkG87s6V6imBB4WBZgbgMSKjEfq3b1FMO2swrjnv25rFsOBIxK1s9V0
         ekIbYwoCflZMqQlfAlOzMp9eICrbEDe0BnQkbhfQdKnK8CVXs6w2uMRGrWQy4z497s8F
         ZEUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id mm22si237324pjb.3.2021.01.22.03.23.03
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 03:23:03 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A04411509;
	Fri, 22 Jan 2021 03:23:02 -0800 (PST)
Received: from [10.37.8.28] (unknown [10.37.8.28])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id AE78F3F719;
	Fri, 22 Jan 2021 03:23:00 -0800 (PST)
Subject: Re: [PATCH v5 6/6] kasan: Forbid kunit tests when async mode is
 enabled
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
 <20210121163943.9889-7-vincenzo.frascino@arm.com>
 <CAAeHK+yaFtXUDVExoyqkYysOPdxLVhfY53nb-msFYEJLZx6k8Q@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <1586f5ed-c70d-ceb1-88c4-803ea8674dc0@arm.com>
Date: Fri, 22 Jan 2021 11:26:51 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+yaFtXUDVExoyqkYysOPdxLVhfY53nb-msFYEJLZx6k8Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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


On 1/21/21 5:40 PM, Andrey Konovalov wrote:
>> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
>> index 7285dcf9fcc1..1306f707b4fe 100644
>> --- a/lib/test_kasan.c
>> +++ b/lib/test_kasan.c
>> @@ -52,6 +52,11 @@ static int kasan_test_init(struct kunit *test)
>>                 return -1;
>>         }
>>
>> +       if (!hw_is_mode_sync()) {
>> +               kunit_err(test, "can't run KASAN tests in async mode");
>> +               return -1;
>> +       }
> I'd rather implement this check at the KASAN level, than in arm64
> code. Just the way kasan_stack_collection_enabled() is implemented.
> 
> Feel free to drop this change and the previous patch, I'll implement
> this myself later.
> 

Fine by me, will drop 5 and 6 in v5.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1586f5ed-c70d-ceb1-88c4-803ea8674dc0%40arm.com.
