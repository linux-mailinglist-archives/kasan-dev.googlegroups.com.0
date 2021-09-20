Return-Path: <kasan-dev+bncBDDL3KWR4EBRBXGSUKFAMGQET3SS3NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id C50BC41183F
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 17:31:44 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id d202-20020a3768d3000000b003d30722c98fsf138509855qkc.10
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 08:31:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632151901; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZQ1xQZ1HgVVOI6YLtXrhHm3WoGi4IAgvZZVi9qjcZdsRPUj4bJnJLqGTxa2bIJ+5JN
         vEckSK+XNiVh5Wg6SeajIyY5gBG2pddi++xQz1DzNUJsqtvCOE7a6ZPWYdiAlr9c1Ou0
         t9VoRKgjwCc0aOxBwZXlULpxQrPD33QtFDKvGewm0JlzRvSDublRmXiVlqljkY79bbMD
         QXXcamcdJGHkwjx8dQ+BdWWkMEOqaOxWbCvZHHLA3yddRo3Zh5d9t53lOAORlavjnC1R
         t/r/rwIBDgu0w3lDOkL3vOQ9+yy+MpDEyVuDmBzP6H2aRoX+9j68nNpRhG8C4H9st9t/
         knwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mNJM4OOi2yhKTkCe/BRwlnW591sjU1g0k/tvX8dZLMY=;
        b=tVRGvo//CW82vOv9PTQi6Rf4HmJbTat892aQ/5cwI2QhxBwQdzbz2Px+W7e+TSaRTR
         +SX2m/UsR7q6YML3putKPorlu3VsX2ZKZJDSMaCs/r+UoStNryQUQ5oTKIrehbFvy4rT
         u83g+Hfiwhc4jTS++KrMbKltMjHwsYMjo5bjofeDwdXnaM2jXTRhFnNcHqJbGAA+BC2b
         sgPMIBlPQIPsItTjaR40THMNGfTxvbOweeeJLTa5VyILVs7Js5mjKZpGPKHu7szFUbBG
         KJZDihfWWI6OBgvmJKbZt/w0L1G376z9mOUbAuxgmy9P8pqayxGeXtdYekiaMhKPO2/4
         XKvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mNJM4OOi2yhKTkCe/BRwlnW591sjU1g0k/tvX8dZLMY=;
        b=UQu7B9KjnTX/y86vtHMJIIylhb4NcelIAZCt/Rs4ZrzI+hS5e1yPDneW+lV90QaKW4
         Vr7God1pihD4ocAMs2jE1+Bni8ffMIuI3rIwVWD2KIgIK357gxh7Iufd5Jmz8/0ePg3I
         UqmcZgSR6eO/wWdqAjos3QsbBK2Ly/5DWtpD4HsIpjZFwrgNWggytLYXmhk8tbcr7zX2
         4spo+5vu8fkK4zXi9mxa/skCDO7/RdSLmTaRXxjv7Kp5gaWGFOYuUcZDXBChRg8NfJYd
         h2152edD3SSwFapbkVeKWFtLr3I/ED01/wLZF/NfFgVkKWMmheQQBUUsitfwbLBIIGmP
         V8Gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mNJM4OOi2yhKTkCe/BRwlnW591sjU1g0k/tvX8dZLMY=;
        b=54IHSmShCYYeLTW/A7m6RoVEVm6n9RBpN/uaj1rIctM23b9GJPA6m8IObylg8wvyDb
         vulqOtPqqBQ6xp0D7WvcIt8CNPni1lVtC2nkRCwDygQr5ZFP/9TisxJYEYha7VK0WJLU
         mLDV6YK94L1tGSx38VRXw2cMCECdADwzvbiSqF/0SStwqjbZ1bdV3GgqpbpTBnZh756+
         w9qMqXg/zuUEg6RzEfAZjE6wR3wrJ6TS3n2D1QPcsbAFtrZj9QBm4v1mllNOsr2J+PkD
         J+FI5Raz6frnq6PAowb7dy2nohqnmSFdZb7y3SUWPuFKhVA6WxDTeGnLzFlz6LpPhAPn
         T+xQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ME1l+oE77f5zKALaH6Un0iIFP0gvEOjltoJVXNOKF5qLKN/em
	gPy2uIONtByI4WlWLV7CxFc=
X-Google-Smtp-Source: ABdhPJzKqoZgyreKXq98k0MIB5gmysQ0wLFeLEP8D9S3IImkIRWSnUrCUCg8MJPTHaXP3RBastH2vA==
X-Received: by 2002:a05:622a:1704:: with SMTP id h4mr23269345qtk.9.1632151900584;
        Mon, 20 Sep 2021 08:31:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:490a:: with SMTP id bh10ls5854478qvb.4.gmail; Mon, 20
 Sep 2021 08:31:40 -0700 (PDT)
X-Received: by 2002:ad4:55af:: with SMTP id f15mr25740228qvx.32.1632151900064;
        Mon, 20 Sep 2021 08:31:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632151900; cv=none;
        d=google.com; s=arc-20160816;
        b=f9Lr1CBR17VzGbFV828OiS6Nuy3A0JXs7JQZte7OsktEEiXOIXtQpwCpQvBD70gBrx
         JXHErZfg031rTdfaghMsotP8lXhOsEI+iRAGwtYLrIFsPFcStlGNrdSerBECWOV68YSW
         iYMZbNSVEm0VEiyQVUPS8gS8ofE/Y/FcyxoggQ/TPRy4IaSLTi7qrKfHR7k8wml1jdkd
         bqWS5mxXSTCSsAi8BurhTxmRs11vDg/tMt0QbA66oMOJpxGtwOmYvLk6O6C8GUGTcP9H
         v+D/uhGVUNIKUfLZcjNdRPF7Vel0mCJ6DA5B5dpuUA+UlMnt55GtxbSR6bBjh3O5BXtT
         Xaaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=WpLWWmRIlsWheT1p7t2onjdMNlBt9h/6od6Chz0pkhQ=;
        b=LOTesTishwf7srY1LJ0rt/AQcfSLH72OVWrVUfWX3WEjm3KWBDI803zw2F2GBB+KpN
         u4N4DdTTLuCu+UfKu05s0CEXdlfWSzk26yKgvOgeOSBNzQQChG/Kxgg6F48CcyI3MrKt
         g2rLf6djpLscnIXHwLEpRYbKIXswB41tAMhL63cxrMeSd+YBo0gyBdiLG4dn8W12QsKN
         OUqtFzY1afzchIqLYDgv0ejPLsTLcbvlJv/96NW9TiwPy+mDTk+2c399H1trvQZEXDUb
         AwvYMkD9/Yhwk9IH4sqbhKo7xtH9HI5oG3X4ZXkPJs2fkIQ2z/UdJFksDouA1AdAePER
         1R8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n27si22679qtl.4.2021.09.20.08.31.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Sep 2021 08:31:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 80F0E60F58;
	Mon, 20 Sep 2021 15:31:36 +0000 (UTC)
Date: Mon, 20 Sep 2021 16:31:33 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>,
	Suzuki K Poulose <Suzuki.Poulose@arm.com>
Subject: Re: [PATCH 3/5] arm64: mte: CPU feature detection for Asymm MTE
Message-ID: <YUipVXG/kObqo6MZ@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
 <20210913081424.48613-4-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210913081424.48613-4-vincenzo.frascino@arm.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Sep 13, 2021 at 09:14:22AM +0100, Vincenzo Frascino wrote:
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
> index f8a3067d10c6..a18774071a45 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -2317,6 +2317,16 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
>  		.sign = FTR_UNSIGNED,
>  		.cpu_enable = cpu_enable_mte,
>  	},
> +	{
> +		.desc = "Asymmetric Memory Tagging Extension",

I'd give this a better name as it's not entirely clear what it does. In
the ARM ARM this is described as "asymmetric Tag Check Fault handling".
Maybe just rename it to "Asymmetric MTE Tag Check Fault". Similarly in
the Kconfig if you added one.

Otherwise:

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YUipVXG/kObqo6MZ%40arm.com.
