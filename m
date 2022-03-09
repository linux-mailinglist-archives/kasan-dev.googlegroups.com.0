Return-Path: <kasan-dev+bncBCCZL45QXABBBE55USIQMGQEAO6P5XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 829E24D3C2F
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 22:39:32 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id e14-20020a17090a684e00b001bf09ac2385sf2189140pjm.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 13:39:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646861971; cv=pass;
        d=google.com; s=arc-20160816;
        b=J5cN1maSMmnrjAjnYHezW9TBfOsvR8OZC82mCaHlKY13NBEf/TxANGPPAljpv3QyXu
         ZdvtwVMKj2Vn7MxSxNVhkuJH7vFxWI8gLXl7IxKsdsmxvXSHFbiyy6pNtMR4RAP5l23M
         Kv9CUTTdcKSGFhjKh87rb4FryW5NSIPfr11iXRhv1xBFD9b7B+4Q6AoZAFcgRdbz/yNR
         aYglRCgMOG65tZ3MQ5z/cy4mZquWCbCrRs5xIaVFFyU9aYuTJsKt3B1VnoBBJF9846O4
         IiiNzoGGLHo4bbqVV5fviNWnmE72b7+GQP1mOnfRpVC2J0oLrqJQuYfoBA1b/pqiXbsk
         hcsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=Wca18LLqFdIVZ51XfKxmJkk7726nd93qBodgFVQcDA4=;
        b=QCtWF3kHFhQLe0byDwaMxfXRR191Im82FJ+xzegiRbDQR5/KGSRbkzlw9UHc2+qLVn
         Y/daPcCUgpJNjsZWOPRUJBTwoJ0FvNXAoJdTxokxLyUKQicfzKBmsAhkNgHHPq1YJXAd
         tKVvdKUof72tm1nTb7RXoPlOeYQT/d2NiqjI/RoVfLm0iCrZYSnbjoMKyaj3+XzUwVsh
         V2U3R7kLiyls3IB6ZjcRiUtQK8gb7QQT7yeVzjyGM47m15VF98ze8T0k6lGc4971448I
         5BpGaKgayL2TooyAn7ymnouVxDhODo8mh4uHzxYVcRnoLokZxWa/hy3hxFIw3oxDxe8M
         KgXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b=SwKsVqpx;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Wca18LLqFdIVZ51XfKxmJkk7726nd93qBodgFVQcDA4=;
        b=IcLgsRO3oOTXxgW3IFs5OHI9/kbgSjMLvyQ4kPJrlq5AujjwR4DYUMtrbwo6s2wu/U
         bM9QOQ8nkr73P0gnjgupyE+C/7Gh1Bi8FImdI/Nk85Agnwa9O1dI10B38F7f/frXUpgC
         mv7SlGPwDo66VJsLcINTdxsFlLd0om+nOiopB9PCOsyFcnE0ro1LByaePHiV6+SxdwgZ
         8T1KeX1kegra8SGd0vi/StG/eTWSLhTCryhvtWmsHuHZ7Nl0vFFESO5Q9V0CfRjOnhoO
         WyyYiLlg1MAecbuKKm7S+7P/qD+tv8Xy1GfVLlCDK+khNUyTrpIKatRgptV0VWsmLAhc
         H/PQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Wca18LLqFdIVZ51XfKxmJkk7726nd93qBodgFVQcDA4=;
        b=OeaAiv4lvxonkPlGkFLNJdBmwi8muqBoY76JZRe4Bcs8V9igpLLOQ5ORvSh8rx/5FJ
         llw+2zpI/c3rZPFW2RVB0QqvYWP6T2f6FSoqdbxx3cj13r9a53vOUBAD35qYQCPuJS6j
         BVdt4M3lyreBvAE+f8XUTVCXx7pB/M1dyT5vXe7TG6sPyeEi994WDvzQRwVAZid6DYYx
         j+e8mN9uCJDFI+9y6UbcIaLsCAiDKqKGHWOf60ofr/7Me0y/DaJ4rhpbvnnq5QdZieDm
         nZKAotiZ6o6oHnGbTwz8g4wrfQ5PCLVlKWJ2mZ/du5PKc4wGfDF6P8s+X9t1q6+naKIp
         3/BA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hnmouUSgX5Ew+ZkZlBBQIbOjrWg5LM4Q1XXCblIEcndjQMni2
	aNoXtjehXtuU34NOeyROJyk=
X-Google-Smtp-Source: ABdhPJwsnW7xfPdIYowYtzujMkwruqbXpfqS+D+KbSMgcNEsCqWpagfFU6OA9M6jI9oVohuHH7ZD4A==
X-Received: by 2002:a17:902:7207:b0:14d:938e:a88e with SMTP id ba7-20020a170902720700b0014d938ea88emr1564599plb.42.1646861971215;
        Wed, 09 Mar 2022 13:39:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9b8c:b0:151:eadc:9992 with SMTP id
 y12-20020a1709029b8c00b00151eadc9992ls2441494plp.8.gmail; Wed, 09 Mar 2022
 13:39:30 -0800 (PST)
X-Received: by 2002:a17:90b:381:b0:1bf:50c7:a4e9 with SMTP id ga1-20020a17090b038100b001bf50c7a4e9mr1552461pjb.239.1646861970651;
        Wed, 09 Mar 2022 13:39:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646861970; cv=none;
        d=google.com; s=arc-20160816;
        b=h31FVbpWtEPgqcUAXVBUvBOJPHkFuA5u1hZy5zNSEZ4kavasQ9p9MgLkzFjXi9d6lF
         rqLxHEHAV+nt/cZcLj2UEMqYoFyv1S0qInUokFhtgbIOA2hgdtAFKgQVIh5VVY0j3tdQ
         5dXDGy87ydzKg9CYL1ozeZejwR2IWnuufvAYzlfiQoNb757AxdGwXZBH/fdoKZtakmxJ
         wU7AvA+jSnx8vJzDRTZ0hg0wPK5GSJx7CaMTkNAzkqKuPYrdIu+huh4h3Szsepc6auqQ
         Ir5yRiDNz07j5LI72yMYycE1VHQvqXaZH0ZgKCS0EQqUJZ74YZyPJ/lrGb1OdqMPpx4r
         Yq1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=zOnqPnT6Pa2ZicR2EFcXEDxd/ntBqJXzc8CY9w8hS4s=;
        b=Oyr3TiwLtydINJ14ue13DFhw/JvgDZz29YP3cjZz60JEVggvS1OVo7sC5GrLmRiToQ
         3+nU2za2nE3anhGaI2oP+WWbh0HYjV4bGBD1PPPJDFmuFgoDBURPIoiTn5Z2t7j7hCnE
         NkxGxJ5zB5EeVF8r7sC9eZII1jYN9QDbLmdTKj4LdcWuNGEfGXuZUnHxn4tcrr5SuZ0e
         A2Mgf2kLGXgWELeo6wJ1ZvlWSwneSgMPsrBLKnEWurwAPek0dqfe5IvQPnQh+hlkujVf
         sw1X8GkpkCfkrtqyYGIsvjxFC5FUTVmUPpwjhxFvFd91Y46xRQnfj8A37FMx016mAllh
         bSpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b=SwKsVqpx;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail-il1-x12a.google.com (mail-il1-x12a.google.com. [2607:f8b0:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id o64-20020a17090a0a4600b001bf0a82f880si277340pjo.2.2022.03.09.13.39.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Mar 2022 13:39:30 -0800 (PST)
Received-SPF: pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::12a as permitted sender) client-ip=2607:f8b0:4864:20::12a;
Received: by mail-il1-x12a.google.com with SMTP id j12so2497492ils.0
        for <kasan-dev@googlegroups.com>; Wed, 09 Mar 2022 13:39:30 -0800 (PST)
X-Received: by 2002:a05:6e02:1a4a:b0:2c6:6a0d:b8f0 with SMTP id u10-20020a056e021a4a00b002c66a0db8f0mr1189404ilv.85.1646861969934;
        Wed, 09 Mar 2022 13:39:29 -0800 (PST)
Received: from [192.168.1.128] ([71.205.29.0])
        by smtp.gmail.com with ESMTPSA id c6-20020a056e020bc600b002c6731e7cb8sm1158182ilu.31.2022.03.09.13.39.29
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Mar 2022 13:39:29 -0800 (PST)
Subject: Re: [PATCH 3/3] kfence: test: try to avoid test_gfpzero trigger
 rcu_stall
To: Peng Liu <liupeng256@huawei.com>, brendanhiggins@google.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 akpm@linux-foundation.org, linux-kselftest@vger.kernel.org,
 kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
Cc: wangkefeng.wang@huawei.com, Shuah Khan <skhan@linuxfoundation.org>
References: <20220309014705.1265861-1-liupeng256@huawei.com>
 <20220309014705.1265861-4-liupeng256@huawei.com>
From: Shuah Khan <skhan@linuxfoundation.org>
Message-ID: <1dfeea09-cd4a-39fc-18f4-775bec99afa4@linuxfoundation.org>
Date: Wed, 9 Mar 2022 14:39:28 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.1
MIME-Version: 1.0
In-Reply-To: <20220309014705.1265861-4-liupeng256@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: skhan@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=google header.b=SwKsVqpx;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates
 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On 3/8/22 6:47 PM, Peng Liu wrote:
> When CONFIG_KFENCE_DYNAMIC_OBJECTS is set to a big number, kfence
> kunit-test-case test_gfpzero will eat up nearly all the CPU's
> resources and rcu_stall is reported as the following log which is
> cut from a physical server.
> 
>    rcu: INFO: rcu_sched self-detected stall on CPU
>    rcu: 	68-....: (14422 ticks this GP) idle=6ce/1/0x4000000000000002
>    softirq=592/592 fqs=7500 (t=15004 jiffies g=10677 q=20019)
>    Task dump for CPU 68:
>    task:kunit_try_catch state:R  running task
>    stack:    0 pid: 9728 ppid:     2 flags:0x0000020a
>    Call trace:
>     dump_backtrace+0x0/0x1e4
>     show_stack+0x20/0x2c
>     sched_show_task+0x148/0x170
>     ...
>     rcu_sched_clock_irq+0x70/0x180
>     update_process_times+0x68/0xb0
>     tick_sched_handle+0x38/0x74
>     ...
>     gic_handle_irq+0x78/0x2c0
>     el1_irq+0xb8/0x140
>     kfree+0xd8/0x53c
>     test_alloc+0x264/0x310 [kfence_test]
>     test_gfpzero+0xf4/0x840 [kfence_test]
>     kunit_try_run_case+0x48/0x20c
>     kunit_generic_run_threadfn_adapter+0x28/0x34
>     kthread+0x108/0x13c
>     ret_from_fork+0x10/0x18
> 
> To avoid rcu_stall and unacceptable latency, a schedule point is
> added to test_gfpzero.
> 
> Signed-off-by: Peng Liu <liupeng256@huawei.com>
> ---
>   mm/kfence/kfence_test.c | 1 +
>   1 file changed, 1 insertion(+)
> 
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index caed6b4eba94..1b50f70a4c0f 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -627,6 +627,7 @@ static void test_gfpzero(struct kunit *test)
>   			kunit_warn(test, "giving up ... cannot get same object back\n");
>   			return;
>   		}
> +		cond_resched();

This sounds like a band-aid - is there a better way to fix this?

>   	}
>   
>   	for (i = 0; i < size; i++)
> 

thanks,
-- Shuah

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1dfeea09-cd4a-39fc-18f4-775bec99afa4%40linuxfoundation.org.
