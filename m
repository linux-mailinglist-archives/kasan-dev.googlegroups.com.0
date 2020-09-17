Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBVO5R35QKGQESI2BY2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 19C0026E456
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 20:45:43 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id k3sf3072182ybp.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 11:45:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600368342; cv=pass;
        d=google.com; s=arc-20160816;
        b=cV2XL0INJJRVyrmfFsLnLEwA+9ZYdEuHa9L5fHlEIixjruIsuuHhUeoc/v9o4THJ4p
         dIj/lVzFsGEYVnWSX1Z3WTOS+fbtcpjYnCJjGX/h7wDhhu9O6lDp85FZMG0uisONcHXh
         YiXnA6Rap82WTYMcVmwSCQpDgB5WxI+uYK1l4sAt+Ty5fjfi0P/f//HpUf2j3mPoPHGV
         JoCmJm7a5jhdk4qTf3j9quT4/3GB1poQNwIt5+ymbr+PFAT1KMYeHJVmEBgCf5jRUgRF
         JEgyp+q4iCi33yqasHWXRCQzVPqEROAKMTqaop5XHAB8N6O98N0zaKXceIG47SAVFdSb
         z89w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=ba7aATQKV3YuCd5aseE1S3ldPQTu52lRMopKKJ9nJx4=;
        b=gHFBTrXGFYo5LWWnGTm4S9yu9hY0/WO3wncrQzrRRPgl93Ejgxuk7ozCcZiRXO3RkY
         vWssfADFx9XYgt3AnrwOyB53QX97YQJxeCltzFjAQegksOG9V84pHSwyvYrNfDA0CGU9
         ZCB2Flw3zdQhyCzT4jsX44A2P3oHgEW6FgRAfP20cdHNa4GLA3n4OGD/3ZyAcqjI+ESQ
         F+SKqnNCmtx64WDiwMahM8EHh5TgOAGVCCgCESALTo8iw4WOQwCr1vpOGgXQEpseBi6O
         xkEqmfADZzB2hXt/bnUaYawFUeBbAXzJzgtSDa8SrbIIC6hHUsI412XwBsip+eh8u8Fp
         Shjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ba7aATQKV3YuCd5aseE1S3ldPQTu52lRMopKKJ9nJx4=;
        b=TTTuGda774qJA00FKZVMyysdpkwqYjwCIN95rQMfq+AIAAAOYXsLC0m6HdRIIakAjI
         YH3tCWaDTGId8yVIVnN0erXm9rSVZxBh6TXGLzB3vrc3SASGCfozV7c5MDPS/rqN/GP9
         l43e02MDs5xzvljZyp6ioYtByZld5uzQcRweu2LUpg+99+BJlLPg44WkRqzZ8XUPhoPZ
         L/cYwX6wCR7eIpMf7fF6CS4lXXj6MFHOurqtSxO44bSEtV/c930qRlR3K2qTv96rDonK
         MBlMlkWpjNV4LsPtXP8FO004uOpGY7uVtw/Oy8XyiLGwpypRXe7xA2md03abTeA1L+oS
         7O+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ba7aATQKV3YuCd5aseE1S3ldPQTu52lRMopKKJ9nJx4=;
        b=eXyBJTPn2Ub75O1uoWm6gpLIOXRVRrNvJFIDne4SIf6KSNcLWUQtJMZfZiQYjvpdMv
         /W+wpVznfxOMvqnP2p6erJy+ZlfSeujqDm2wct/Uh9Aazfubi/sl0ZnccOACtCM3XIgX
         5o4U4XMgExBq1D659tm2J6evTzyuFw68q78NrA1zwNCwLvx1UREHi5i/kPjGxJPbpfzA
         bXZQsOu5gulT/Zqcsh0/rxywLcaH8L8F0sf7RQLM3qoSPZLoZZMrNeu5AEm0W2L22oS5
         HvM38khUW3VUdtpEzMMYW+TfFyJ3TQP/xdeyxEXH1LuP3R2fqcfYnRhxs/73KfKXZ7je
         vEdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531vB7WLm2HYvWLCMGxDBl+4bdMvWcPJzxtstWnT70e5Vt70LgHP
	cBF3t1q2CrnngBh+Ikk6/7s=
X-Google-Smtp-Source: ABdhPJwxZwA13axGSizm9CLAyco2dntjkqnsz9baDfaNXV4kbi+OEsgCxOylBppJgtLkz6mvAnhZMA==
X-Received: by 2002:a25:73ca:: with SMTP id o193mr23456268ybc.224.1600368342074;
        Thu, 17 Sep 2020 11:45:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6d05:: with SMTP id i5ls1361127ybc.1.gmail; Thu, 17 Sep
 2020 11:45:41 -0700 (PDT)
X-Received: by 2002:a25:6a41:: with SMTP id f62mr45632810ybc.498.1600368341592;
        Thu, 17 Sep 2020 11:45:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600368341; cv=none;
        d=google.com; s=arc-20160816;
        b=L/IZXOOQepFK5ajKRg1jBuvHMDCLybb7Ti9Fm/c6eP29EAD+Ayczc5m3f2L1cYFIm8
         1g53/2UD2ZrtUeaiHEVJ30kzIEffE3ELmQJdE6RvFtoVBuoXoZ3Oz1aLqY+jtKJIY3f9
         p5M8HJfTkwXVoT/8Ty/BUsvJy7WIrPoEdF7Hv6fAfr48pDA8P+YAWtVjlpBHudIK3tK5
         paqsBSLleYFCdPUt2bB2IMS/cAPWwNAEm7bNue966vCKnvUXTJu7LIMOytHSmy5gQbFT
         S4lmYrqtPnJ7DGO2k0249uF8bwwbbqEjf33pk7TJIXzMpey/dgLd5AiXrp8MxAQGDGsA
         gdVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=dyojTjTLo3HaF9o+YPdE2ww7+4ebnP/+zitS9mEqqjs=;
        b=ZSWuLul4s6OIsp8PWz0btsmFnlQC5OFCYas5/sREFb2zPhSfAVUXLifevHIF3pB1dI
         ymhaUqGXibZE8ezObHArLtrtAY4vO/s+Bdr77TonC5haVjlxB+zKfriZnSn8dlKxF7OT
         EtVdMvAGJCe9PEOElVpDH74awK0dBv75x/SAKC5uk80gIdeXdmUpr/ccejglrKyiceuc
         OOE5LetELO6Tfq4qZxu1dlQUW6KX4A2j3TTh1Nbp3QspiFsb+IqdDmipiFauTxRLMOpS
         eputtGdHsONmUCgnvMQ0lrmEP1xAHAaildaD+vjz2CpgjN+7VxtLTuz3iWnHrP+nvsG2
         5zLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s9si75384ybk.3.2020.09.17.11.45.41
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Sep 2020 11:45:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D847011D4;
	Thu, 17 Sep 2020 11:45:35 -0700 (PDT)
Received: from [10.37.8.97] (unknown [10.37.8.97])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A75B33F718;
	Thu, 17 Sep 2020 11:45:32 -0700 (PDT)
Subject: Re: [PATCH v2 27/37] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1600204505.git.andreyknvl@google.com>
 <c801517c8c6c0b14ac2f5d9e189ff86fdbf1d495.1600204505.git.andreyknvl@google.com>
 <20200917165221.GF10662@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <c7cb0642-8e20-b478-96bf-87807a29fc71@arm.com>
Date: Thu, 17 Sep 2020 19:47:59 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200917165221.GF10662@gaia>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
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

On 9/17/20 5:52 PM, Catalin Marinas wrote:
>> +void mte_init_tags(u64 max_tag)
>> +{
>> +	u64 incl = GENMASK(max_tag & MTE_TAG_MAX, 0);
>> +
>> +	gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
>> +}
> Do we need to set the actual GCR_EL1 register here? We may not get an
> exception by the time KASAN starts using it.

It is ok not setting it here because to get exceptions cpuframework mte enable
needs to be executed first. In that context we set even the register.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c7cb0642-8e20-b478-96bf-87807a29fc71%40arm.com.
