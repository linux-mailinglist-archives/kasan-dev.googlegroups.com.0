Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBSNFUT7AKGQEUYSC5XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id BA5032CDB3B
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 17:31:06 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id n8sf1491964plp.3
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 08:31:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607013065; cv=pass;
        d=google.com; s=arc-20160816;
        b=uIIWKgZajpI8FcJUYDxm7Av59v52xtbFEOBNFkMH6soDDBJXfN4YGx57KpRQ2GSGDt
         xp+U4vb3U1m5kMVy7bTRh9/ORO3l5aTHz57o5AgZtOOW9AqRqddpOJoPlMjVNdioRjLd
         4eDChuBq1gGER163AKiYWxU09Qw5L2hIjzYuLwzzcls1V/5FZ7mXmZZwUuVZabpjbKwI
         ZooAsiIF7NctRavOIT+AtfmJzcE8h+BTMEXddF7prqlPdNDX9hAPLPanLwkkt213s17w
         NX1hJ7mr9ydjMWWfV5sGD2rbWjdVdddU2aqUelOGioSd7F+tDZmITo0qFE/rY+6G8ji8
         Slhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=87VuQ46YZYABqnT9cf3y5k4hbRsWnR9F3W8m5r6Ogx0=;
        b=ks05eDFJiZ7WwS9lKCpA0TNoGkaYZT/WC5Kq6NKxDb5vh7LxJUISVyC6QEo9evXOib
         t2x3SkL6Qo0Zvx+CoMPtxnFmJ1PID3SeSqR57Hwh8ibOcSJV26KBLXrMbjaeX1IPaqhs
         VZ7QWPi+Y8ysANa42kkAIRFBbkm+gSVniVNxS65N6T+J0qEMJRF5HAwVf2+dKsalFEDS
         or3/2x21SuQU2bVBj2vQqUABqNXzEvJPv1YFjI98OKxo4woNN56agVC1tQm7zueDlHrR
         WoBgsKUD7O+LEm7oEM8JPqKKPLkEEO3fTitnA/cDI8MhrWx4OXWc5MW3bvs/f4pmR4c5
         WZMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=87VuQ46YZYABqnT9cf3y5k4hbRsWnR9F3W8m5r6Ogx0=;
        b=ZoO1jt5juTAjEI35hIYLK7Bw+tAkcfEx/9om0VIDVl8j5Ap6zk9UwMr0H7TVPYcARF
         NcdMz6QCIgWdwWKRMJ6djMOkoONpxsV+WQDs859D+TBnNp3R/6aqAJyBC6ynNnU8Docf
         qd3KrVgtgER0dcFbAq2EGt6cyoEkX5AdDKRBXVmKlrWZy+ugbvqJ7rbY3M3cOEuPopNv
         yqM69cxrMesJh0lOf9Tb3wIW5Ruj6k9isk6kMCiTlLm/nsyNDqyIzmsq5MqFq8pOCa2A
         ehgVSh2pNe1sxmevnDQxbfF2djODsQnSGoyGS9A72pKkXyTdMkgp6sIA9yJcoe7ZUsyt
         8T/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=87VuQ46YZYABqnT9cf3y5k4hbRsWnR9F3W8m5r6Ogx0=;
        b=JVBEM7z6lSDZ8ysJ5jQqBGv/TPXP7txNyVnfLB0dbB/OS+ThXY3uCPD22TRrF4QDxP
         KEi4SolwVUJ/AP6yIiMh3ONpCSeMw3Nr9w+6mNgIh+XsRdzmcf0SxH6wiPnewN+jO0Qk
         sPqSETa4n/W4nI6r8kCqaYqsureFBOz1R0hqlCAiAHc+TEv0xZi1YD/FWgdw1QsjxXnM
         +XC1IjTeqhqKPqIA8kPSXGoQMbyU65Ecsnn1++khZmn3FtalGdgKBekTsRZkJqaTwB52
         TmyD8NOGsjh7OyHKjN9nkLqOp0AILSbZHBpiAfJMIx7slPcYXanNcrdTCA1smxsf0UZE
         kaMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532h9zA2uesGe5PEAmPOcrkF7TiWRqp9fIVNTi6c6wtALuII6xI9
	6LuczEjDX3NKDzKagBOAReE=
X-Google-Smtp-Source: ABdhPJzsk643g9f92QOhHjbu12mb9Yh7Ns+SdSafooHj8fuQM3IZk8ep+XsOl1prK0rnU6i8SwKiVA==
X-Received: by 2002:a17:90a:de0f:: with SMTP id m15mr3857301pjv.207.1607013065253;
        Thu, 03 Dec 2020 08:31:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a503:: with SMTP id a3ls3350638pjq.2.gmail; Thu, 03
 Dec 2020 08:31:04 -0800 (PST)
X-Received: by 2002:a17:90a:7087:: with SMTP id g7mr3775674pjk.200.1607013064742;
        Thu, 03 Dec 2020 08:31:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607013064; cv=none;
        d=google.com; s=arc-20160816;
        b=jG6/sc2M8+TBa3ub62gLxKXtR2VIRtNUi3J5xz0XEarQ73dVcZ5MRorE9yzDuAaHD6
         qPYqHwLpvmgS+d33qyui3o4w+iGfmYt8gWS/PuqNEeoZISSJeR05PPkd1FWSHCLJRBpZ
         v5lcPrE9BoHTAZ3dNrvcd214BBrzF0kHtr0D9UDjsch1t3zUPSV5SjX7Xoy9ouzhPFN2
         EBffE3mHsh0qPh82Yxh4Dk4m/fBF1X0rq5JxMnNmq3r4Mhhj0bDbh67hU9HMOP+KyB0Q
         do/v9nSph1CZfLgIQkVpp0wFdH05Ui5kDjMS5lLkWZjxx3qp20XePr0RXXT4Meo2gi7g
         PpHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=YbhOMCEPP4bd8MYisBPrQGb0dlIsfdzrUQVeOS32Ifg=;
        b=Y+uiw/qFqrJXbCoWhlbvhQGAFhVASATOFYS8EuFQNEt5J39/tfX88h837pFGZnlAkH
         qCyX/HPOq4jYnFfAbN+GozWKYXzSdODNryJehx52GILPEnpV28R6ZOt2H+PzHPbCLVbb
         rhCyFXEpDLGNCGVh72x9WbnauwQPwrReOTHPzRyAqAqyg/53RUZvf0OcM+0niPPB6mLb
         lfUg9wegmC+vF+dv12obZ110KlbdIS8jHNaRS2bGzVU6hu2Ju7+pfAXCrp0uN1MaCh03
         pFhs1BRBkKUJMFXXvzGiFau5PXiyAWA9RNegoWl4lAwUV/IUTFv66287OhjSI9xfK4BA
         CWVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v8si126218pgj.1.2020.12.03.08.31.04
        for <kasan-dev@googlegroups.com>;
        Thu, 03 Dec 2020 08:31:04 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 17AF611D4;
	Thu,  3 Dec 2020 08:31:04 -0800 (PST)
Received: from [10.37.8.53] (unknown [10.37.8.53])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7BE0E3F575;
	Thu,  3 Dec 2020 08:31:01 -0800 (PST)
Subject: Re: [PATCH v2] lib: stackdepot: Add support to configure
 STACK_HASH_SIZE
To: Andrey Konovalov <andreyknvl@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: vjitta@codeaurora.org, Minchan Kim <minchan@kernel.org>,
 Alexander Potapenko <glider@google.com>,
 Dan Williams <dan.j.williams@intel.com>, Mark Brown <broonie@kernel.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>, ylal@codeaurora.org,
 vinmenon@codeaurora.org, kasan-dev <kasan-dev@googlegroups.com>,
 Stephen Rothwell <sfr@canb.auug.org.au>,
 Linux-Next Mailing List <linux-next@vger.kernel.org>,
 Qian Cai <qcai@redhat.com>
References: <1606365835-3242-1-git-send-email-vjitta@codeaurora.org>
 <7733019eb8c506eee8d29e380aae683a8972fd19.camel@redhat.com>
 <CAAeHK+w_avr_X2OJ5dm6p6nXQZMvcaAiLCQaF+EWna+7nQxVhg@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <ff00097b-e547-185d-2a1a-ce0194629659@arm.com>
Date: Thu, 3 Dec 2020 16:34:18 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+w_avr_X2OJ5dm6p6nXQZMvcaAiLCQaF+EWna+7nQxVhg@mail.gmail.com>
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

Hi Andrey,

On 12/3/20 4:15 PM, Andrey Konovalov wrote:
> On Thu, Dec 3, 2020 at 5:04 PM Qian Cai <qcai@redhat.com> wrote:
>>
>> On Thu, 2020-11-26 at 10:13 +0530, vjitta@codeaurora.org wrote:
>>> From: Yogesh Lal <ylal@codeaurora.org>
>>>
>>> Add a kernel parameter stack_hash_order to configure STACK_HASH_SIZE.
>>>
>>> Aim is to have configurable value for STACK_HASH_SIZE, so that one
>>> can configure it depending on usecase there by reducing the static
>>> memory overhead.
>>>
>>> One example is of Page Owner, default value of STACK_HASH_SIZE lead
>>> stack depot to consume 8MB of static memory. Making it configurable
>>> and use lower value helps to enable features like CONFIG_PAGE_OWNER
>>> without any significant overhead.
>>>
>>> Suggested-by: Minchan Kim <minchan@kernel.org>
>>> Signed-off-by: Yogesh Lal <ylal@codeaurora.org>
>>> Signed-off-by: Vijayanand Jitta <vjitta@codeaurora.org>
>>
>> Reverting this commit on today's linux-next fixed boot crash with KASAN.
>>
>> .config:
>> https://cailca.coding.net/public/linux/mm/git/files/master/x86.config
>> https://cailca.coding.net/public/linux/mm/git/files/master/arm64.config
> 
> Vincenzo, Catalin, looks like this is the cause of the crash you
> observed. Reverting this commit from next-20201203 fixes KASAN for me.
> 
> Thanks for the report Qian!
>

Thank you for this. I will try and let you know as well.

>>> ---
>>>  lib/stackdepot.c | 27 ++++++++++++++++++++++-----
>>>  1 file changed, 22 insertions(+), 5 deletions(-)
>>>
>>> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
>>> index 81c69c0..ce53598 100644
>>> --- a/lib/stackdepot.c
>>> +++ b/lib/stackdepot.c
>>> @@ -141,14 +141,31 @@ static struct stack_record *depot_alloc_stack(unsigned long *entries, int size,
>>>       return stack;
>>>  }
>>>
>>> -#define STACK_HASH_ORDER 20
>>> -#define STACK_HASH_SIZE (1L << STACK_HASH_ORDER)
>>> +static unsigned int stack_hash_order = 20;
>>> +#define STACK_HASH_SIZE (1L << stack_hash_order)
>>>  #define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
>>>  #define STACK_HASH_SEED 0x9747b28c
>>>
>>> -static struct stack_record *stack_table[STACK_HASH_SIZE] = {
>>> -     [0 ...  STACK_HASH_SIZE - 1] = NULL
>>> -};
>>> +static struct stack_record **stack_table;
>>> +
>>> +static int __init setup_stack_hash_order(char *str)
>>> +{
>>> +     kstrtouint(str, 0, &stack_hash_order);
>>> +     return 0;
>>> +}
>>> +early_param("stack_hash_order", setup_stack_hash_order);
>>> +
>>> +static int __init init_stackdepot(void)
>>> +{
>>> +     int i;
>>> +
>>> +     stack_table = kvmalloc(sizeof(struct stack_record *) * STACK_HASH_SIZE, GFP_KERNEL);
>>> +     for (i = 0; i < STACK_HASH_SIZE; i++)
>>> +             stack_table[i] = NULL;
>>> +     return 0;
>>> +}
>>> +
>>> +early_initcall(init_stackdepot);
>>>
>>>  /* Calculate hash for a stack */
>>>  static inline u32 hash_stack(unsigned long *entries, unsigned int size)
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7733019eb8c506eee8d29e380aae683a8972fd19.camel%40redhat.com.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ff00097b-e547-185d-2a1a-ce0194629659%40arm.com.
