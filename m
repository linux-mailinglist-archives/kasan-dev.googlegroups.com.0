Return-Path: <kasan-dev+bncBCSL7B6LWYHBBMHT5ONAMGQEQWWQG2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CDD5610483
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 23:35:46 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id f35-20020a0565123b2300b004a442356475sf972543lfv.12
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 14:35:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666906545; cv=pass;
        d=google.com; s=arc-20160816;
        b=USdpfrTnpVuZcHuhqtm5WKuGhmJBSrRiPDHxBkyBxEP6lXKK3flWGe0nYk8xD+eHEI
         /Y7O+ANBvAezKzPsIQSG1mHoA62hwxCf9tJQ7v7S+9amGxZiDohSMh/IMuJ7uYOZa09P
         7leAv+xPBn+ewlaUBt0kQFqNYsjCQn97bruG0WRmFEdS2RuWwnrBefIF3Ugnx7PkR7Vx
         28MhMnkPtANcXrZ7A9NSWI2Lbr1PnSGZ3E/dhG4+lBlL35JnQwDSFgGHbwbhrsAVQcQS
         aKHznNwZlfWIMwRR1PwThuB8eNpeHYRVycFS0RIe/+iiSYY8A87Y1TJflsT6DSpbr85G
         x9FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=cfeb+nBCiplCkx01u5EaCRlyjEa2ZFUYdV7Cd1PGRcA=;
        b=IGmqNMIoUh5ffOf0Fd5yp9TD749JrplTvnD8ta9ImwRJNMPAB0n2jqX7iiqkp0cAVb
         t/r524OxuXCWGvescJelnlxM7Xouh5/HSCdiuibyll8BXF9V+rJ46lFbccZI1FH6LbiJ
         xRZ5px55UBGXwwIsOENM+H53CcwSfto3rbwUKcaOiTuLU82kETckJvo2owMrTl/ERvzQ
         GF0k8cs5cMXkT8WnMY+iwPq4gByhULLUo3WyPNa4swFa+kMHLuKvv0rxGddM/p/LbSWW
         ItPVIo4akS519qw18ReDsXVm+H7kEt00O2AuFr0IWMH+tSu5L/+pd+FM0tgdniT2MzGU
         29MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=k76nKuwu;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=cfeb+nBCiplCkx01u5EaCRlyjEa2ZFUYdV7Cd1PGRcA=;
        b=mF07DKQY7F3W91Pz4sp25znubxduMs27WRMXHmiVLDAPr9GwXjQtcEfpce8i3BOonH
         7U9J6/ySVxoJevRW39apCEMVth1fG9t1+xqzAqJ3fz28r4jWkP5dAOG0qsYT3D525NBr
         6Z1v+ppjXFyKsA7XIQz4tKpYuDEcLGbaFF7H8BEAOJg0wXM7juGWY6hoE6jwTMYST9qI
         IWt3adFOB2gaIQgPWaq2CVGZvkpCnZqS2LbdGJtZd+MXc492nZ6F14Svar/Yg1YD7T2b
         YajFDTByJ4r9sSPQDqhCJ9LSjGYxnSH4rvQZUw8HB/hMqc9yzH150LIQNHMU+1P1XEE2
         lYPw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cfeb+nBCiplCkx01u5EaCRlyjEa2ZFUYdV7Cd1PGRcA=;
        b=UTHRRUXQ1XiE/J8Eiz6PpfDY+GQ/aw5RvmRCqLQTMCpDDdfW7NiLz6Y8a7uG6JB7AU
         CbZCyz8pFFnwCm82qEjbEScMAL1F5jPA+prJLk8iz8JiDPOKAPM2Ui/D4to4PAqiRNLY
         0PAOpoW50lnO8OYxMylh9EnHo0m2DNGy9hNC92/Owm8paCf66Y5/d8Habcf7PXYiZ0yq
         CjtBLDnoohhrMgZKKsX8J8WHYSsN/RdJQZ6vzCwDw1qujG80UCAqN6/mCS5sMx0x2m8w
         Qf9eIpjUC6AvqvMplbihNL8pcI2+dni/D0bh9To4HQ7HOa5uMxtmyDyV9quzaiTgnWyV
         5Rtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cfeb+nBCiplCkx01u5EaCRlyjEa2ZFUYdV7Cd1PGRcA=;
        b=tUeEpx2qwsT2imxduoQFlVxVx/Z0Mc8yGB+XVLm0DLx0MLYBjyNylsw8VPswjPmhr7
         /bEXbqcnClxpajHCK2CZjgviX3L6U8m9VrNSZNACrVginErVRimxz09N5rhfy+wIsD2+
         p0KANKJ9C/zuqSRur0tVFvojhbxjYRtCyw/BXq4v9y6y8s+3zLUaOV9rvgHi9fq2IywT
         tNbOUx5V+uo18naJdDSPTVc2NG/qJa6yEM9EbtuGHeUBVNCRFYyPAnlFDtGS9Qvgz5rg
         hMvTT3YWwqnhGRU8eupMMNKxwy0kZUh4wRABxB9T+K+CycvmJnWcZ2XlzKmdNnQja1aj
         JqTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1UpEv+BbHJdqu3nAkMRnLz+JHm46X5fMe0bmBAKX7TJ6tPNctD
	0nG53t3BnbusaYcDk1sL7HU=
X-Google-Smtp-Source: AMsMyM7UTg0nR5NENunZMbmv0VUDx6ImSzMYQZksqXeMgb3Zy2rUd/e//8DFp8E+vTCwq11EPTz/Hw==
X-Received: by 2002:a05:6512:68d:b0:4a2:a17b:992c with SMTP id t13-20020a056512068d00b004a2a17b992cmr19707821lfe.239.1666906545261;
        Thu, 27 Oct 2022 14:35:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a80f:0:b0:26c:56b2:1383 with SMTP id l15-20020a2ea80f000000b0026c56b21383ls86100ljq.4.-pod-prod-gmail;
 Thu, 27 Oct 2022 14:35:43 -0700 (PDT)
X-Received: by 2002:a2e:be10:0:b0:26f:b35e:c29e with SMTP id z16-20020a2ebe10000000b0026fb35ec29emr20161668ljq.488.1666906543726;
        Thu, 27 Oct 2022 14:35:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666906543; cv=none;
        d=google.com; s=arc-20160816;
        b=HICeG4ZPN6LHAztf16VuE7UIGSFxXDvBBoTsHwWpMYrcKQAV9JG10yDWI3yFB2GVKA
         eY7kj3NqC8KyeU1CEJjeDhXQp8cg7orlDEDfUnHG69cKg9HlPucV0zrF0duJSM4xyIVG
         U8HrBslKGRIZv/qBfa4BubnGBxZB7Q9pO87Jdfw9cSq7TCd7b+3NT3GQpM+j0oNZ8FXj
         /5ruyCKI5kRZT6bGbpW9IVy7mENwyBm+C2iJE8UIO0Vxl5jM8GwLWfXtMmzgFlQPRi7M
         RHyjOP56S5Qbfqx4AX2J0e3yxBJvbwFtYlNg0CCyBD5+1iOw7onyXiME6XmflWlJlCb1
         W5Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=DLMSX5xAv8Of0i26zhWYF6rLIZWMK34svw6mTWTkhA0=;
        b=q7XFPl+MSo5ZHV3dNxXKstk1QEdUTEUFWBGara/M0LgdX0rYXJvRJyt3rpeOr/kOi7
         H1cQM6Qh8Si3xziMyAjqK1fI6avMAg1fi2nUJtWedQg0J6mgITf7bAkap418dZZlCQYK
         J9jMlXPgISNT7jqArqy5AMXtXElifZwsBvLjHaBHjsEthlzsgGws7QY248dW/BKfa0MQ
         jJ8WuCUlQgEbw98JBeMoEVhn2+qq6udHCo+b9kngAB+xizO1mYfOX2LxiGArlabwbW1m
         gVC8ykOxyx29ph9PaaZyrmhINFZZYVne0prQ6CSAztA/OUfx1nxBD3CmAU6MlJR1QgHw
         WySQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=k76nKuwu;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id c5-20020a056512324500b004a273a44c4asi77921lfr.7.2022.10.27.14.35.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Oct 2022 14:35:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id r12so4988092lfp.1
        for <kasan-dev@googlegroups.com>; Thu, 27 Oct 2022 14:35:43 -0700 (PDT)
X-Received: by 2002:a05:6512:2983:b0:4a0:5745:f7ca with SMTP id du3-20020a056512298300b004a05745f7camr21096993lfb.116.1666906543496;
        Thu, 27 Oct 2022 14:35:43 -0700 (PDT)
Received: from [192.168.31.203] ([5.19.98.172])
        by smtp.gmail.com with ESMTPSA id d3-20020a056512368300b00492ce573726sm318308lfs.47.2022.10.27.14.35.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Oct 2022 14:35:43 -0700 (PDT)
Message-ID: <1c3209e7-a184-22f7-096c-874a2f77ce55@gmail.com>
Date: Fri, 28 Oct 2022 00:35:44 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.0
Subject: Re: [tip:x86/mm] [x86/mm] 1248fb6a82:
 Kernel_panic-not_syncing:kasan_populate_pmd:Failed_to_allocate_page
To: Dave Hansen <dave.hansen@intel.com>, Peter Zijlstra
 <peterz@infradead.org>, kernel test robot <yujie.liu@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com,
 Dave Hansen <dave.hansen@linux.intel.com>,
 Seth Jenkins <sethjenkins@google.com>, Kees Cook <keescook@chromium.org>,
 linux-kernel@vger.kernel.org, x86@kernel.org,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 "Yin, Fengwei" <fengwei.yin@intel.com>
References: <202210241508.2e203c3d-yujie.liu@intel.com>
 <Y1e7kgKweck6S954@hirez.programming.kicks-ass.net>
 <278cc353-6289-19e8-f7a9-0acd70bc8e11@gmail.com>
 <864b4fbe-4462-9962-7afd-9140d5165cdb@intel.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <864b4fbe-4462-9962-7afd-9140d5165cdb@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=k76nKuwu;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On 10/27/22 18:12, Dave Hansen wrote:
> On 10/25/22 08:39, Andrey Ryabinin wrote:
>> KASAN tries to allocate shadow memory for the whole cpu entry area.
>> The size is CPU_ENTRY_AREA_MAP_SIZE/8 and this is obviously fails after your patch.
>> The fix this might be something like this:
>>
>> ---
>>  arch/x86/include/asm/kasan.h |  2 ++
>>  arch/x86/mm/cpu_entry_area.c |  3 +++
>>  arch/x86/mm/kasan_init_64.c  | 16 +++++++++++++---
>>  3 files changed, 18 insertions(+), 3 deletions(-)
> 
> Andrey, if you have a minute, could you send this as a real patch, with
> a SoB?

Done, It slightly different because there was a bug in vaddr->nid calculation.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1c3209e7-a184-22f7-096c-874a2f77ce55%40gmail.com.
