Return-Path: <kasan-dev+bncBDR5N7WPRQGRB4EB36PQMGQEJBHHSYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A5BB46A10A5
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 20:39:29 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id x18-20020ad44592000000b00571bb7cdc42sf4748127qvu.23
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 11:39:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677181168; cv=pass;
        d=google.com; s=arc-20160816;
        b=y6fRt3oN9/3p4jGahBnKTRFAhKDKgz2j2wutjjTEpBpl+K2oSHXwrvL2L2Gg8GkDQX
         kAFyIeAjK0U5j2/cky3VnwmDilT1L3H9BmBeKt1TqmxD9w0mBhVzTuwkDRdY6EOLdueo
         keKbJXZb0WHTg9KJGpf5ZtJ+YjYAM5msT2+wEkGSUWPzdDk9eunUAbuQW13jSbwVU6f1
         D6Vxahdk/J8SVf1fc5vh6GbSI2chLqPhhymo67INBYJbcWvtFX7/q4LcvK5o9c3Vo4rx
         i3ANog5994HAzNoYiXU9GeNyy+LvAIh/olmBFnnJuD9Uar3ddaYd+fwXJJTN2zxwHhT0
         H5IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=pErIlT/tAzcMz15JIH0GauCITy+zzZjuFyMBa7jQRJw=;
        b=eZeD6UUTUQPy//JJra/LQt8l0h/6P0et55po9xd5tDDT6AxONGa64G/eIGrccS8Orc
         ibdEbFDEYuyy8KFn0ZxGtbGPsDixmuiujVH9iBD5vWPr0dqWcBuSvBZtoAVw86jtnnf9
         UYGkfmoz5H2cgNLH/VcdTxKYUGs3TOcejgwsQbbaAgeAa9Hq9j4e8n7eq6a3cjjYK9JY
         VM1wLQghZ05Wk/wsSn4HwVf2EPiEIVMfZcjN00WPB2vKxEKsEFIFE6OGEQPFKXlCXTEZ
         CPIDX2emGRkyDhHjxDAnVKyxIW9VHDZfCIq8JhYv/lKksymd2IlIyMdy1RFH4CVmgeRM
         YtlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=sBG7+vBY;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=axboe@kernel.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pErIlT/tAzcMz15JIH0GauCITy+zzZjuFyMBa7jQRJw=;
        b=oyUrotdg8pvBKrEI3YHK/dCi7BvC8Y5GK16phjK6d/9LtWjTt6rs6eNNOec9YPZxkb
         RrgEEPOH41ZvGKgTutJgPlAq3T49otymnikqpJ4gURYAe7Bl8BnZwHIG4i6K3rNve0DP
         yrza6J0QrHlyhn1fZ3oxIaw1C/l4VJ9Uyftwc9F0eP2KTbPc4Tw2JuHw6WoJ4r4qPmJY
         bHBktQ7wdRS0PwGj/JTYvQLMCH55pS5Y+RptFe1f3MYOuiCrNtMPvhMC4VPWpTrm3D30
         +7hZEvf/cx9PVkeE7rBg8sNQloR3ofVNISeoRKfUQc22fnT/BXeGPMWH0wBpxccHm9oJ
         xTDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pErIlT/tAzcMz15JIH0GauCITy+zzZjuFyMBa7jQRJw=;
        b=5rvoNR0qjkbkSZF8m376KzLlX48hjuHTNw63S1hlZ42w1whLcFBxGpkmLW5r4lSiDf
         V1i6/qY3BAsuu+tdb+8SfCKWO9cRVvSGfK6935tMxQklTXvwN+1TKf4JpdYieZ48Ix8j
         owv3DVxkmwjFgubgXeWmUVxoG1f2yD/IJ8rL/2LFMhY4vOZuxHyOSHWnyLJ4SWtKunYh
         RKuOnOloo7Hu8X4ijmPDr+3PjoDaUu+9MFm5GD+RQjhUHaPc8ct8wcxHHj1Gro6nI2J4
         8rOY51jwL49WO38pPV2aNfthAnjSZnn2KZwaUgP2nvCUhk0Lge2rtN8+ZrUYMHwHpaJL
         mOUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVRbttcTmp3r9wFR11fNURmGdNsww1F75+o7+OwiZ73fGwjMZnn
	4gwAtSsYgk2I5+5tF5YhtNc=
X-Google-Smtp-Source: AK7set/qbpQIK1fKPPE+UI5mFw4l5azmPIHfIX3B5iURSQ8PiS+ri9uqH+6GhboAPVt+cYrvkYwEog==
X-Received: by 2002:ad4:4e72:0:b0:56c:1865:feb with SMTP id ec18-20020ad44e72000000b0056c18650febmr2104694qvb.3.1677181168356;
        Thu, 23 Feb 2023 11:39:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4d98:b0:3bf:a3ac:d13c with SMTP id
 ff24-20020a05622a4d9800b003bfa3acd13cls750297qtb.2.-pod-prod-gmail; Thu, 23
 Feb 2023 11:39:27 -0800 (PST)
X-Received: by 2002:ac8:58c3:0:b0:3bc:ff12:e5c1 with SMTP id u3-20020ac858c3000000b003bcff12e5c1mr8797907qta.33.1677181167821;
        Thu, 23 Feb 2023 11:39:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677181167; cv=none;
        d=google.com; s=arc-20160816;
        b=zm45rtRmgYAB/9Kkh/J8CDuAP9//OJGyYISVsdFnJ0nTf/LxOZ6vY01UjUMTh85O6R
         DDRVi6rnRps0pTq6ae+xIciDX/xyGHJXml5nIxQ9nE9Btiwp074eUkq+GilB+1dpuBsO
         ylIcbDNKig9G3DE/EamNi0nB2MUNoIOkRLmu2PM34iYH/1uoCI+3qDZs3Bj3HRvSB9m2
         xVSqnRKiAOfleWCgQ/17BThpPkzYFi+1WCZ71EqpswEcO4FEbLSSqevI8+kaPr3XVUEX
         Be8C6d5qkZ+M1j3iAyEUeOrHqlqZXEVWBB3jQ4MKm3LdQVdmi+eaN+0ojD8zr0ch1RVV
         mx0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=iV6+ABNw2LaFR5D/DxEZrmLkc9SRilZ6PWsjEGStGCw=;
        b=05VpVIMbRXie888FauVG6YeSPjq0S36bel/MPs+8MuGakqiPZ/zjsEv/eu7WiuAtcX
         Jc0PurKG5c/E+hrZkDu3SXpRFVt6JBxyUufatautWLPDTRrtQX53X8sMeEHoJDBJ34H/
         OdqqnddHt1UppOWZ/a4++PlFR8LGJApSY6BrW8YlpQt/9/uovrfFlUiT8bwo86l/rNpq
         UKHvYnfrGCSva+L9XQnom0WZ2PAooIqaYwToYE8FWSBmgKdyv3agq2XfT360CVa36Byb
         FymQRmCFSI+RallQdQelkdSA0F6FBqGSaa0H9DDjNFXRQYxz5k50SQLPffv4NJrA8yZ4
         kvYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=sBG7+vBY;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=axboe@kernel.dk
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id x27-20020a05620a01fb00b007426692e029si103387qkn.0.2023.02.23.11.39.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Feb 2023 11:39:27 -0800 (PST)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id k21-20020a17090aaa1500b002376652e160so439133pjq.0
        for <kasan-dev@googlegroups.com>; Thu, 23 Feb 2023 11:39:27 -0800 (PST)
X-Received: by 2002:a05:6a20:7d87:b0:bc:6c4f:308a with SMTP id v7-20020a056a207d8700b000bc6c4f308amr16468942pzj.0.1677181167222;
        Thu, 23 Feb 2023 11:39:27 -0800 (PST)
Received: from [192.168.1.136] ([198.8.77.157])
        by smtp.gmail.com with ESMTPSA id y27-20020a637d1b000000b004facf728b19sm6325210pgc.4.2023.02.23.11.39.25
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Feb 2023 11:39:26 -0800 (PST)
Message-ID: <8404f520-2ef7-b556-08f6-5829a2225647@kernel.dk>
Date: Thu, 23 Feb 2023 12:39:25 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101
 Thunderbird/102.7.2
Subject: Re: [PATCH v3 1/2] io_uring: Move from hlist to io_wq_work_node
Content-Language: en-US
To: Gabriel Krisman Bertazi <krisman@suse.de>,
 Breno Leitao <leitao@debian.org>
Cc: asml.silence@gmail.com, io-uring@vger.kernel.org,
 linux-kernel@vger.kernel.org, gustavold@meta.com, leit@meta.com,
 kasan-dev@googlegroups.com
References: <20230223164353.2839177-1-leitao@debian.org>
 <20230223164353.2839177-2-leitao@debian.org> <87wn48ryri.fsf@suse.de>
From: Jens Axboe <axboe@kernel.dk>
In-Reply-To: <87wn48ryri.fsf@suse.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112
 header.b=sBG7+vBY;       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=axboe@kernel.dk
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

On 2/23/23 12:02?PM, Gabriel Krisman Bertazi wrote:
> Breno Leitao <leitao@debian.org> writes:
> 
>> Having cache entries linked using the hlist format brings no benefit, and
>> also requires an unnecessary extra pointer address per cache entry.
>>
>> Use the internal io_wq_work_node single-linked list for the internal
>> alloc caches (async_msghdr and async_poll)
>>
>> This is required to be able to use KASAN on cache entries, since we do
>> not need to touch unused (and poisoned) cache entries when adding more
>> entries to the list.
>>
> 
> Looking at this patch, I wonder if it could go in the opposite direction
> instead, and drop io_wq_work_node entirely in favor of list_head. :)
> 
> Do we gain anything other than avoiding the backpointer with a custom
> linked implementation, instead of using the interface available in
> list.h, that developers know how to use and has other features like
> poisoning and extra debug checks?

list_head is twice as big, that's the main motivation. This impacts
memory usage (obviously), but also caches when adding/removing
entries.

-- 
Jens Axboe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8404f520-2ef7-b556-08f6-5829a2225647%40kernel.dk.
