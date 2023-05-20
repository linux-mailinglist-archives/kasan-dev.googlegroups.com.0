Return-Path: <kasan-dev+bncBCAP7WGUVIKBBWE2UWRQMGQEZHBMEYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 2554970AB9C
	for <lists+kasan-dev@lfdr.de>; Sun, 21 May 2023 00:44:42 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-3f39abae298sf31669881cf.1
        for <lists+kasan-dev@lfdr.de>; Sat, 20 May 2023 15:44:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684622680; cv=pass;
        d=google.com; s=arc-20160816;
        b=hKKIGcepbr9QFYmAeVjf8VYwSRW8shmuMFl+VaFrCVl2cQW6YXT4+EsvaAF1azRIW4
         HyBDIPjLxgMyXP51AuOuUJOL8nbmuSYHjgT+fGDcg7O/OOFLglvyDiuUPBcQFpVJiRHq
         mk+0LjI/QKU9vWEFuHFphZM5ua5+pfJjOQl1+WufzQ1ONoq6W1nBoWCEcaha/NJyP0E+
         tWsoqE2LmqqvWex6zajjvZ2oZVnGapDO4FqT0+bgmWYY384zr33PgGTwj6+8KSv0GOBk
         Q8CWAmPUyQSirh6ondCkJD49GXPyke5wQuOjmpa0qH3r0PIL1bLoqXI+mwbtH8cPKYni
         uz4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=c2LQyCw2GVp3dcIWdmzikWfDRSt/rVX0zvnCIT9t33M=;
        b=hEh+nUhUNTqkoCSnDsNaVt8wPqpyQ9/fessTqOKRTNXzlI9VCF8Cb/at6WOujK9MQx
         VTQCdebZGhekXg03riBYiBC/ydVRpwgMH1d72IGT27UPmOdhu5WiEOdiBB6TLmbRGW7E
         q9Z+NUFihmfctGJlRF3vrCHNtsl0vvDHm4KzXhbhaK1OryrNRGtwxldyd1Axwbm9/s+X
         SCQOF875zV4RvVygxAWOF563TjcNA4hPc2Jm0g/PY1Ac4hOqIeaxZFe1Pm5yaUY4IWB8
         2rgS3mpI+BUzCJJmC+5lA3KgDPDyPoDeX6vFEFxpaO8RVKsU7oqXBreypiWJkA1rVo2y
         6qyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684622680; x=1687214680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c2LQyCw2GVp3dcIWdmzikWfDRSt/rVX0zvnCIT9t33M=;
        b=o544RLIPw3bzOT3RQIuyW+ddZ36tIMuAb2B9urRq0dKrMSHYre23EfOFeGSabQ3j6p
         aoduEg+xqS5lNDgqWfy0k1X7KABYnDPtU4UwOxU5tR5VU385Hr+IaWj4s7cVrFdsttAi
         ldv+AHfT8bEslr1xma5S/2TeA3eNLZPy9NjKirHbYSi0M88wY5r0TaC0d4rFNCdUyS4M
         qZFP4FGofA20lzyTi9orE97HxBK6aI29SWRHiWNUBVZb1ubD/agrGpcGw/9Tz/upzmLa
         0IgzpfpmbtCMALGdNIBO6zx1HwxpMnYI0NS2ChGIk2+6B0Xkfz4CjiaDcwrQutXWrT9v
         9K2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684622680; x=1687214680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=c2LQyCw2GVp3dcIWdmzikWfDRSt/rVX0zvnCIT9t33M=;
        b=kipI9z0U1BIk1BOnMfUNobX+9Im9WyHzOrS+vrO3L8aMsOOrL2Zh9RZaGCHupkWtNW
         oXrb4OPySGFcdqx6gBj07lLuRyovgIBbPlOzC5/KPUJDoYUZRmOmKUWupyzXuwNRQxEv
         lkDsL7xL09x7/Og1QwozDR7cLykZiSw516Rfcvnuyb1+4mXeeqM+F97vFNCJoKsJyQwQ
         0DJw4RKm7gtWpOK4I/bri/UxFo0pmDa09u6yVJORD7xAaq8y6SCB6cEn5BsFBrIPEzps
         CfGbdXfxCEqlXmH9CWiz2hVw4Ui4aALqQTSgwV9Hvg5R4MIOtLxQMiDIl4Sk667yLsDS
         hk9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxPmtVADe1ThY5qazSxb3ve8JZyYUMbKslaHzP3FdbCEToYcple
	oUYw8gJsqgvXr3S64O/BtDw=
X-Google-Smtp-Source: ACHHUZ4vMLFnLnacmPR1fkaQF6fti8pRpIK/jlJ/IYzGgxb3qiRFM6E1s6tImeikvKT13uSeLz2bRg==
X-Received: by 2002:a05:622a:1002:b0:3f4:e3d3:f8ff with SMTP id d2-20020a05622a100200b003f4e3d3f8ffmr1958387qte.4.1684622680589;
        Sat, 20 May 2023 15:44:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:45c1:0:b0:3f2:2428:26ed with SMTP id e1-20020ac845c1000000b003f2242826edls6634988qto.1.-pod-prod-07-us;
 Sat, 20 May 2023 15:44:39 -0700 (PDT)
X-Received: by 2002:ac8:57cc:0:b0:3f6:a7c2:63d6 with SMTP id w12-20020ac857cc000000b003f6a7c263d6mr3575205qta.44.1684622679742;
        Sat, 20 May 2023 15:44:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684622679; cv=none;
        d=google.com; s=arc-20160816;
        b=BhUE+tCuT/tUwd8+iT3vGRMdnCeq32vkmLUi3t+QrY9F5LT8N8urpzUfYBeYNML3Q5
         ogozW4vyjyfbWquQbtPNpA+6xiFjw3j92FTEBHRVUbulJ8CdCyf6B1Dq7AJtYzRJrCeK
         6WFDa5zSVMFzUaMu/rMlm4Vvu+RQBjWFlTx7J6e96etZg6fyA6cs8yIumRrgviyBHIC3
         eI8dvKwiG+aK4snbX9uEf0NfSDKDBxRTzkbD66Dp+HFE00gqhgR+GMNq7xXZ0Regy/XK
         qnou+u61uS9Mse8zXTwv+L+ABv4kHeH742dUSIOu0KdFJ/v9Npbdo/WbIzcuJ5eF07ja
         Qm4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=WbfzFnMrGuKehyMyFVGA+gKu6pKBYeFdxj6oxBEzsfI=;
        b=ErxjF7kLAPSZBkUEMY+nITGpJAKfth5+SaYgzLX4YPNN7HBNmZby2WhYzBA2iwIgi4
         glb5wp5I5EpxsVsm5c0Av6+QJCR4yXwJ6Ls4jLhEP4gMAKOfwUwY3oT4QGB8IjqK90gC
         jh0iIhaOO7eOxK776eAe99LL/avT6DfKrCMM4Gs3RhLJkbIyKFQyM1pJxpIGzq25e5Ie
         ck8VD1cKT6aQvoj36MFaC969zDob6UGR9OawuiXfWDToXumuSqKF9AmMu/NHl/9/RFTA
         Td68cTrb7OfCDIfasapeqMMjXsuPEtIZ/FsYP0wR3IUJ1AhlaU5gYSF2ETc2h0FRQRh5
         Yu2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id eb1-20020a05620a480100b00759328e1145si103362qkb.2.2023.05.20.15.44.38
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 20 May 2023 15:44:39 -0700 (PDT)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav118.sakura.ne.jp (fsav118.sakura.ne.jp [27.133.134.245])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 34KMiMiH053860;
	Sun, 21 May 2023 07:44:22 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav118.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav118.sakura.ne.jp);
 Sun, 21 May 2023 07:44:22 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav118.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 34KMiMMB053856
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sun, 21 May 2023 07:44:22 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <9c44eba9-5979-ee78-c9c8-626edc00f975@I-love.SAKURA.ne.jp>
Date: Sun, 21 May 2023 07:44:20 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH] lib/stackdepot: stackdepot: don't use
 __GFP_KSWAPD_RECLAIM from __stack_depot_save() if atomic context
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
To: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
        syzkaller-bugs@googlegroups.com,
        Mel Gorman <mgorman@techsingularity.net>,
        "Huang, Ying" <ying.huang@intel.com>, Vlastimil Babka <vbabka@suse.cz>,
        Andrew Morton <akpm@linux-foundation.org>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>
References: <000000000000cef3a005fc1bcc80@google.com>
 <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
 <48a6a627-183d-6331-0d8d-ae4b1d4b0101@I-love.SAKURA.ne.jp>
In-Reply-To: <48a6a627-183d-6331-0d8d-ae4b1d4b0101@I-love.SAKURA.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2023/05/20 22:14, Tetsuo Handa wrote:
> On 2023/05/20 20:33, Tetsuo Handa wrote:
>> @@ -405,7 +405,10 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>>  		 * contexts and I/O.
>>  		 */
>>  		alloc_flags &= ~GFP_ZONEMASK;
>> -		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
>> +		if (!(alloc_flags & __GFP_DIRECT_RECLAIM))
>> +			alloc_flags &= __GFP_HIGH;
>> +		else
>> +			alloc_flags &= GFP_KERNEL;
>>  		alloc_flags |= __GFP_NOWARN;
> 
> Well, comparing with a report which reached __stack_depot_save() via fill_pool()
> ( https://syzkaller.appspot.com/bug?extid=358bb3e221c762a1adbb ), I feel that
> above lines might be bogus.
> 
> Maybe we want to enable __GFP_HIGH even if alloc_flags == GFP_NOWAIT because
> fill_pool() uses __GFPHIGH | __GFP_NOWARN regardless of the caller's context.
> Then, these lines could be simplified like below.
> 
> 	if (!(alloc_flags & __GFP_DIRECT_RECLAIM))
> 		alloc_flags = __GFP_HIGH | __GFP_NOWARN;
> 	else
> 		alloc_flags = (alloc_flags & GFP_KERNEL) | __GFP_NOWARN;
> 
> How is the importance of memory allocation in __stack_depot_save() ?
> If allocation failure is welcome, maybe we should not trigger OOM killer
> by clearing __GFP_NORETRY when alloc_flags contained __GFP_FS ...
> 
>>  		page = alloc_pages(alloc_flags, DEPOT_POOL_ORDER);
>>  		if (page)
> 

Well, since stackdepot itself simply use GFP flags supplied by kasan,
this should be considered as a kasan's problem?

__kasan_record_aux_stack() {
	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT, can_alloc); // May deadlock due to including __GFP_KSWAPD_RECLAIM bit.
}

Any atomic allocation used by KASAN needs to drop __GFP_KSWAPD_RECLAIM bit.
Where do we want to drop this bit (in the caller side, or in the callee side)?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9c44eba9-5979-ee78-c9c8-626edc00f975%40I-love.SAKURA.ne.jp.
