Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB4V7XSBQMGQE6XSEURA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 43F9035882C
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 17:23:32 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id t22-20020a17090a4496b029014cf3d7ff6esf4349840pjg.1
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 08:23:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617895411; cv=pass;
        d=google.com; s=arc-20160816;
        b=GG8dMmat0m4r+EJ4Nn9yT3FpzhafbHQfWjvT16Ag7aKBECBeCB4Oznlkj8Abxo6NsV
         Vn39Jna1QparWvB8wDEiY99HcXIVUOC3ALTwJD1Cgs7Xs2koC/GOw235Ni01hqpgbi7F
         /8b8pT65zt7foPQQuPUZF1LUHUr+FQTD/yUi6EQLr+B2jSjyOapsVZ7Q1gg9bsPomh9b
         zZ/MomCg/7kWTYA4gj2x26wPqgsDafk3t4oSh0nYbB+6QtKSks/af3AA8eZGElPXY7kg
         a7gLwj0a+YrLDnS9oFC0sAK8enE2nEKQ8fsTJc9Z9mM73JuedG8eUZh8XmfygI004mJF
         yhvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=lMcxCvJ5xnuhtBUcCyy6QfiiN8CzxltqGU4a2mhOJqI=;
        b=NbIMDZOV09gycTjtggt1nSWftFNK6cxODUoKlRlvw/pdAkoi710smk5kbkawVlEYHc
         BtgPi4QLsFqUHHjtZY9veSKMYk36RXRAQMBzBuyw6+MPG4RSEPn3AFnmrY+bRJzmhZL4
         joZJAFAQ2eQ5YzbgnIfm/pzQ2Eya1llzbXzwKptg37KzG/c2l1wmOPKIYvyOIY44Unip
         o/P2wEQgrXbHvOJqwmo+8Z6FfsyyaPtirqzLt21Ayvcu8J0tpALwXFrY773SswHbqIo0
         VeyvsfcUkWNH8sajL/J9jt9vNtLuNU/NRezRijVpxwVQqVLshSDEAIJUGTIPzNZz5IqA
         l6Ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lMcxCvJ5xnuhtBUcCyy6QfiiN8CzxltqGU4a2mhOJqI=;
        b=NP5AW+ZAkcXT1V5Ts/dG+LumYzKO/+oitkH1nV441MZHYpAZ+vePOfC8kAy0Rhexth
         RGeBB1cXM0nYoNmNjrJTjQcx/if6/FPMxqLUWtI/9B5CZkcBz026R6rniBDU8eOJ/B6S
         aqT8Mr/w8G3Ongu8/5Nu/vHtuOUVNnevwicM2Zhah+AkrCbxINa/LPmG2qcMl4sFd9fX
         TbljnVC+Jx3ZFRiJmozICXkfsBPGOptr+cAheURmiymuD0NX62aUpLRqKZQHgCT0ZYrs
         rW18mNK6CF+6nrJcmflD/q+MhEwC2jzzjNBQJexatC46je0Kwq/Rn8cyWxILmq9YLnvD
         0wjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lMcxCvJ5xnuhtBUcCyy6QfiiN8CzxltqGU4a2mhOJqI=;
        b=kTfoBsdaezn7xPGLZUSE45LQpLCvbe7c54y37Q+fBAQJSAcqd0SLcA7dSjlHfrsJtF
         PTrfzI3DuDuFABHBYyNCb636UV6XJ4dWfJAo4aYjXWrTg08+oCdZqShWNI/iAVDvFyOy
         ZsnUYJycZXq/rC6nQs1RrZhuyRORxdkJLUD/uUrMqq2A8+riurEs2Fphe+84vlSp+u8h
         MofSoRvJEnymMhwwafi5hbeotgQgwPHR9ZYQfzF51PQsI8wmi7MlSXiyBTLX4ccnI6CI
         IZffNFQxdZxqWqwyB1NYzpumgGgrLAcZNQX0ywDOy0bOrl2EDu7UZz4OOzjTQMj9q7Yu
         /Deg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530r6jcKIgNcyRYzTieQ9UV2DAALYg/K4UsuWfx2Lq+o7B2pnkGb
	pbfkTggpAz4qsv/eC9cAs/0=
X-Google-Smtp-Source: ABdhPJxHRRQBwODcfqIa01G9XgMQtKt+n5wwqL5NvtoxQIB03E6v5Frh9Z+GTME8ZLLS1DmW6Rv0DQ==
X-Received: by 2002:a63:570e:: with SMTP id l14mr8493984pgb.159.1617895410925;
        Thu, 08 Apr 2021 08:23:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:8949:: with SMTP id v70ls2472864pgd.9.gmail; Thu, 08 Apr
 2021 08:23:30 -0700 (PDT)
X-Received: by 2002:a63:fa57:: with SMTP id g23mr8292720pgk.243.1617895410402;
        Thu, 08 Apr 2021 08:23:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617895410; cv=none;
        d=google.com; s=arc-20160816;
        b=yNeqL5MlZ5+xKtNVJRxZzAoRLZAU4SGdj0B7f3mF4WMN+ma12bjEC7dt6Tadk8pOC7
         TTRe7HRXZUmUWBq6seC3NSfzewdegGmP1lwhWgBaI/swoeS/vsiIPFjN4ZoxffGzdrMa
         8BGN2cBbMc4RyRlupC4ve2oRvfCydlfnXNN8n9bXOGAyBOPDWHPDZkKNeA0Z+fsnNS7H
         AEIZCIf1NMJNvp4eDF4wurY0/pK70wCsW0FH2/LCERRkv3ce5D/tEl1pTWNgvz4FE3Z7
         raMd+cmhtyPLSTjM4wNddUrD7CfJr2KRiN1ArKzRk0e8LEziYa7yzLonOeWG4PZ13fkK
         AoyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=YokdyMviGLbF5K6L6WhYY72MPD6gfjlTFI6U/ZUeLW4=;
        b=sBMjlXny9GueTbVPDmlStw3SPfnflPRcQxohepO4GUTYIsGszLLnIi5/ozYgvmtdd4
         zyeN3Xqn7efwy4hpny7oCI35PpoPhWgFTapdKkg9LYVT70jDL6J6QkzJo6xQB9gW+hH3
         3FvttZgdELC5WoHg1PN7ZsjqgYekbgSVJIlKPm7mP4IWC+PknhxCRT6Ekl/Kt51VzGTC
         7EaTb7tvHLRT/X3RxI7woVZlL7QwR4mpEQmAJ+uP+WarkfQMGJVtC9KswEY+9J1HMaRw
         bjnAH+mtNaRZdqDlNZfC2OvG92LW8FCZMHGXlxd5IRRbskohzmG6rAu/Udvrf2HUF3nr
         JEEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x4si554313pjq.0.2021.04.08.08.23.30
        for <kasan-dev@googlegroups.com>;
        Thu, 08 Apr 2021 08:23:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DF131D6E;
	Thu,  8 Apr 2021 08:23:29 -0700 (PDT)
Received: from [10.37.8.4] (unknown [10.37.8.4])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EE3CB3F694;
	Thu,  8 Apr 2021 08:23:28 -0700 (PDT)
Subject: Re: [PATCH] arm64: mte: Move MTE TCF0 check in entry-common
To: Mark Rutland <mark.rutland@arm.com>, Will Deacon <will@kernel.org>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Catalin Marinas <catalin.marinas@arm.com>
References: <20210408143723.13024-1-vincenzo.frascino@arm.com>
 <20210408145604.GB18211@willie-the-truck>
 <20210408150612.GA37165@C02TD0UTHF1T.local>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <e3c6fa5b-82a2-dfd9-859b-efbb9970c5e5@arm.com>
Date: Thu, 8 Apr 2021 16:23:27 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210408150612.GA37165@C02TD0UTHF1T.local>
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



On 4/8/21 4:06 PM, Mark Rutland wrote:
> On Thu, Apr 08, 2021 at 03:56:04PM +0100, Will Deacon wrote:
>> On Thu, Apr 08, 2021 at 03:37:23PM +0100, Vincenzo Frascino wrote:
>>> The check_mte_async_tcf macro sets the TIF flag non-atomically. This can
>>> race with another CPU doing a set_tsk_thread_flag() and the flag can be
>>> lost in the process.
>>
>> Actually, it's all the *other* flags that get lost!
>>

You are right, I need to explain this better.

...

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e3c6fa5b-82a2-dfd9-859b-efbb9970c5e5%40arm.com.
