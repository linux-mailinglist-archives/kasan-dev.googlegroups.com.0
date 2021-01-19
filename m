Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBP67TOAAMGQE7ZAMPPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 43A622FB9B2
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 15:42:09 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id o4sf7973091pjw.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 06:42:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611067328; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4aEHe3QhcIRg4jlb591uNYf23/Kptr8nkTiVoL4uvWjQsDZT4KTiHcJeugm541+Rs
         HRI3uV2q8vd1B6ajmS+cLTrtEJ4Mu2/lkkjn3zgrBaxBMpa9FsrJ/x45DSZdI5uO1Zze
         ckkZPxftGeiXXEC21OdKTYYyDmuFJwldnnNwInzYFsE1xeC5u/zf84A+NpOC6hFUNRPF
         Hw5eVX+cPPK5G9c2Aog3rqDt+UfLcFLgi+rBADtihj3+ng+dr6Q2vsxDW94CKphw+DCJ
         lwbEwNXz561LngLeKL+bOHQuOhTLAqwUIGIfZgn8N3kpOlfnZKpGggRgBzWZSImTN9bw
         SvIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=PB5SgP3xNncxKNsm8vcsehO8ASUiRqlm6IPLFjqjk/0=;
        b=agJm/kWVCduAN/Zc8h1NzEPHWYYiXFaPr9lAIQrkSpw4LTDG3gtV5D+/NVHiNDVD7s
         8PclRKSuwRbdtCuqlda98sFS1wfPXpsOgnF9G/Ko5Vz0pIIB9TtbaG9wTv63rBkSjHuX
         gNHdCcZItEUQRX71hmRqC2TD0ghulEEBxV46MmDjizMoRWA7PHLyQvEoan/LgDM1+UeR
         BAilV3W9m4oB99ZMQpRB115AnCvZAuAh9OceLYBHEkZ3mP768JM/vAA7vHTFqgfmYGtW
         YajetYpTzuS5kug4NK5DFOpXO2BqwROrzjvrfvgezDE3lRTw4zRN8hcoHmGqaum3G+Da
         8T1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PB5SgP3xNncxKNsm8vcsehO8ASUiRqlm6IPLFjqjk/0=;
        b=OwdqckdOCr/iCbXk5fVTCtDN07iTNul4m0eB+RcxAVLjrqR92dpr+LiYBs1/VHtoV+
         cRirWi3oEhW2yj63HoRw/GUa4NesTnBn1qBVgA+8i9GZIB/c56YDTY2nvKyW1EvPGdAQ
         5BHUHOp4+AeaM6Zek0/V9aY6FZ+Aqor05IVPxGXIgP1s8EIT8o1dqFVHPLy0gE8d1nJL
         IVuYAO9SUdNz0RwYPeo4os2jvPmMMJjFgzhFAkrNe9lXsPezw13/Col0mvdbGKyJjV0A
         LpOtmoztreq/g0xFkcyCAf/ztyY/X6ypIEfLYK01q9R1pq7+T9ozjZXagk0VuI2EZqVZ
         5cIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PB5SgP3xNncxKNsm8vcsehO8ASUiRqlm6IPLFjqjk/0=;
        b=bfKpvnCTaFqXdwlz8qyJqWnuEXsvPfimoXcraBzH38VQHhQbCiyuqi1ZtjA1NiarOG
         K//+L7PyU9EyMqdWyAZ26ZxvCVXVlWfV5iWwVZPIpxfiVGzu1P/RV29J/HnqleMXZdXs
         bMaacLWFlWnG5e07rCRg7azK0YwU/9OiggWBiDPCoBs2hqlYC5FzYOybL0FXkyC/J8Tz
         2iQxuiNk1Xd1ruBBo/m1Zy1ZLVszN3BR4jDOW8WsbVcaFMpXl6zWbOOWlxRdwzY2vaUL
         nPmjzSRV3ofE1vIJJ5Wz865kiPIDQWKGh+3OzVVN80W13cWT4TWQjeSaQLC61KO210WP
         DHUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530nagBb2YzHONJlmzgewnxjcQQWVZqOJ9rghIk2Zv73dntLjk9t
	hLST7/qJTMT0t/qwvKTX7l8=
X-Google-Smtp-Source: ABdhPJxsuw5R/YdLue12eCB12zNDTYIlcLiB4LfMEtUVFDZF40XbdCTHW2gUoC5J7xNUP+HFKHM1Aw==
X-Received: by 2002:a17:90a:249:: with SMTP id t9mr5742549pje.25.1611067328063;
        Tue, 19 Jan 2021 06:42:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5290:: with SMTP id w16ls2850920pjh.2.canary-gmail;
 Tue, 19 Jan 2021 06:42:07 -0800 (PST)
X-Received: by 2002:a17:902:7fc8:b029:de:74be:9238 with SMTP id t8-20020a1709027fc8b02900de74be9238mr5029467plb.21.1611067327460;
        Tue, 19 Jan 2021 06:42:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611067327; cv=none;
        d=google.com; s=arc-20160816;
        b=fXj2yo7aeHR3851WZuujSpoEvltuCTWcPUIBI77TKol2OgIE/LxwtPotwHfOVHWbLW
         mhutQA00ejAjuO9bmfhDBwo8BAZBfN1RWVKTDjcOe/vkhqx3YoAmWrv5Cnszj1EeY5y2
         fsc2IPVQ3S4WVA6ASGKKQ5v7tDFhRB+72Dj+hv9ubn5zB/a7TWW0nlUXOr4ozKQc9Z/y
         Whkzo0wdlMn7p1q+5cUK12YHBXm+qVGEHx3KhpzzgY84XbfC8RjcUkZdVJHTXsYlOnnr
         +SURp0chkTEoynu74ezqZMi+soyCCVmeVFxWQ9vFf58OHUORT10PCDUUaQMOvyWMA/SR
         WczQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=7hKuQrkejh2uk8UMCcigaHOXAn6qez47qgKgVD6EOAk=;
        b=Nr9kFH6wfXNq0U+Ufa8yljo4Nl4MG1NvRAefTU5UHFj811JP2XYhHmYmBzM0wjQVA0
         I/Er/T4Nev9q1ZjKzMAuVqk0Vf/d+g/L0RKICXoyiSRBUsjeUOQ5C7a+Lan0QKL1YJ6K
         4MH5RFDJwRDzC0fDi83QhMF7Bc8RB9hkt0hyeRcpHll9WmLbsQ8qAz7PEL63mnQpQV32
         YGo3FgQiRIrl2yE03ggIAggBLaa+KqenbrVx6ErcZV29kgWvZ1o7EQ7n/qVH7wZyrD8a
         SEqR1nMmDJBM1Vz5BFSm3b0NNaP1kkt8db8DU9mB9W5VnA/LL6GYMIqxM+nM7ppwYelK
         dXeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d1si331503pjo.1.2021.01.19.06.42.07
        for <kasan-dev@googlegroups.com>;
        Tue, 19 Jan 2021 06:42:07 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 871D3D6E;
	Tue, 19 Jan 2021 06:42:06 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E8A2A3F719;
	Tue, 19 Jan 2021 06:42:03 -0800 (PST)
Subject: Re: [PATCH v4 4/5] arm64: mte: Enable async tag check fault
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-5-vincenzo.frascino@arm.com>
 <20210119143412.GD17369@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <7db77f90-d595-c094-2f71-8ef1b05f1c7f@arm.com>
Date: Tue, 19 Jan 2021 14:45:52 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210119143412.GD17369@gaia>
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



On 1/19/21 2:34 PM, Catalin Marinas wrote:
> On Mon, Jan 18, 2021 at 06:30:32PM +0000, Vincenzo Frascino wrote:
>>  static void update_sctlr_el1_tcf0(u64 tcf0)
>>  {
>>  	/* ISB required for the kernel uaccess routines */
>> @@ -235,6 +273,15 @@ void mte_thread_switch(struct task_struct *next)
>>  	/* avoid expensive SCTLR_EL1 accesses if no change */
>>  	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
>>  		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
>> +
>> +	/*
>> +	 * Check if an async tag exception occurred at EL1.
>> +	 *
>> +	 * Note: On the context switch path we rely on the dsb() present
>> +	 * in __switch_to() to guarantee that the indirect writes to TFSR_EL1
>> +	 * are synchronized before this point.
>> +	 */
>> +	mte_check_tfsr_el1();
>>  }
> 
> We need an isb() before mte_check_tfsr_el1() here as well, we only have
> a dsb() in __switch_to(). We do have an isb() in update_sctlr_el1_tcf0()
> but only if the check passed. Now, it's worth benchmarking how expensive
> update_sctlr_el1_tcf0() is (i.e. an SCTLR_EL1 access + isb with
> something like hackbench) and we could probably remove the check
> altogether. In the meantime, you can add an isb() on the "else" path of
> the above check.
> 

Good catch, I saw the isb() in update_sctlr_el1_tcf0() and for some reasons that
it is not escaping me I thought it was sufficient, but clearly it is not.

I am happy to benchmark what you are suggesting and provide some data after this
series is merged (if it works for you) so that we can decide. In the meantime as
you suggested I will fix the "else" for v5.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7db77f90-d595-c094-2f71-8ef1b05f1c7f%40arm.com.
