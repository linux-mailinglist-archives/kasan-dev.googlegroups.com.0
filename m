Return-Path: <kasan-dev+bncBDGZVRMH6UCRBIOOUW3QMGQE2FWPAFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 0027D97AFAB
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 13:25:22 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3a09e96b72esf35599995ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 04:25:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726572321; cv=pass;
        d=google.com; s=arc-20240605;
        b=JPBTIvr7qA1Bfn7gJn2UBhElRKr1rOUyUQxFZRbPi6hUHcnD6hMlTirym7s03zHFFY
         O9sp9+mjDxpdlEMj4r9ln1V1ABIBpxqU+X4WtgjxlXvd75Y/V8R+2ejKP2tiPQXtL1Wu
         IQc7xnOpctXlqOB3A+cQ25zBZ5QraObKPH3ZS7sYZDK1j65BQlXNkJKnN5AepEeUUJyB
         l4xW29x7bTSenXNzAiDAeVeiIfe/r6W3CrRqfUn2v4xPunxK6R4DI+7qqDqV2f14TWJX
         qo9svLDGrlZSbMlHrQVVTtqIRbaZEuI9UEkW4CPYi9fW54HPqH41n2XgHS8iYhDi8SR+
         FjzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Gw69eFfcV+Sxqfa794Q4wgGMS3JxkG3vU0Z26B0HhFI=;
        fh=tGwsDsz2J3kPEyFz2YuswPk6pEf3k5MPpdxJlYdYxpU=;
        b=IMOLj0f259vjxxCIM6B57OlLp5+rtP0KxJoh8Mtt4hHn/BB/m58M7y7CZgreBLEMGM
         z9DGz/DjJnwnULOsu/J2nw9h8dJb4Waxdz5X5DPDZ/gh3l1c+gqqVAeE7nAHTf7E7UUc
         vvVGRraUO7QaFPaQ+EJdoqJtSlL73gDvKll4kOFG1lBMF31MZ5GPmGOUiZkswK/K2q1P
         PXlNQ8UQTOPZ6zRGBnUK82MdJBDlK6kA86cKPrIEqTgLnDVULsZVpaVjVmUe/LALGmkq
         EGvWLzj60er5LI3LwEtRxFkNhiD4INp0CMlOfLAk6IeyozmWe22ALeJv+U3+Kr2RMewM
         E9Kg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726572321; x=1727177121; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Gw69eFfcV+Sxqfa794Q4wgGMS3JxkG3vU0Z26B0HhFI=;
        b=fhyZ7rwUxl1GaU+JNO11wCrQFYrY6jgtBaVqGWb1zy/sm+In496IKYcARFrAmZgbms
         r7C9O77m2O2llUhVk5VZGeafdmJ/Qxz6eu1LuEY/AJnVHG6t/+orthAxbqHjcIsVyMSj
         SVj+szJ6M1RnQ0tJAcnFjTe8i3u/YFtOFaAn+qFaBgX3cT9+16cbMj02Rsr/ELkMArKs
         QHIQCzJkS0JbWevsNMgQaNzSqwjWpFPHU+H3QZqB0an3bHU/Q5BcL2KfM7FTqg819Vm+
         afpEk7DCs5cGwbb2KyNMbMxJwjYj5jn0Tr/z61bBr8Fqvf7kWfttaYKHpoma7AekWfy4
         TXcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726572321; x=1727177121;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Gw69eFfcV+Sxqfa794Q4wgGMS3JxkG3vU0Z26B0HhFI=;
        b=JnD1pc7Tuh5Uv7CJZm9gR1mX4ArQWESoJRMX5nq4+vNwac/U55BnNWY50o2heLUxJh
         GQpgY9lYnMpd8Ph0c1yBWB3y3puiVAcvIRYoBto+iUGGmF24VZebtWATrNlskKRJk0r3
         r+5PJj5SGlxho7hf8Pa2N7sfj68T79r4eZgSywHCmV92xR1oRddR3565pV8ejZBX3HoY
         Gytr4nAeyGz4eiDWh1s+vjhshG/STT9fu9qRWveKAQHdvRPtY4jU0vsuLAqvlCef61NH
         5WVdetLGQQTICjX0ZmIP7i+vhm+EZltyJjFfLg3+S0bvUBoctr4IAl0eyeUFqiB/VyHt
         7SBA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWhlQsI2c+8ntnP1UK4RBqEcYxba2gTpusKrCcXLwhw9I9TCOq7oS6yBDqeAuEO0dkLftBf5g==@lfdr.de
X-Gm-Message-State: AOJu0YxBb8HeJ2I0XZrOFRBkCpGHK+mYuuFjTzx9hUvxHnRHOtV2pvRC
	3J/R2W0ox6Xbs+fV6JZMIgsitEzIqK+dtvUsNAggf/x+12db4tsk
X-Google-Smtp-Source: AGHT+IHqr9zIF7dKBZB5BMpVg94L+DJQizo4EDs9wVaQqNkH3E5hSJIs+sbLPqtPFO8GCowMtX7i3Q==
X-Received: by 2002:a92:cdad:0:b0:3a0:4fb8:ceda with SMTP id e9e14a558f8ab-3a084931e07mr168478665ab.17.1726572321363;
        Tue, 17 Sep 2024 04:25:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:b22:b0:39d:28a7:b109 with SMTP id
 e9e14a558f8ab-3a0a6c390bfls7384785ab.2.-pod-prod-08-us; Tue, 17 Sep 2024
 04:25:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUUH0ibLidTN0kiZ7PqDPUjHtTvd20qXNkVQizGfuc9rTpIzO9mI+ln0bqRPYvIoZ3ZxsFF5d19WAs=@googlegroups.com
X-Received: by 2002:a92:cdad:0:b0:3a0:4fb8:ceda with SMTP id e9e14a558f8ab-3a084931e07mr168478425ab.17.1726572320549;
        Tue, 17 Sep 2024 04:25:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726572320; cv=none;
        d=google.com; s=arc-20240605;
        b=iyHX0OzxcqULGct3IJ6FcVtVBmQP+8ayeywwC3mPP7lfYvE76hA2mgW4C2OaFA+LsC
         oH2+9G/QzjHLJ9JlnTfSjoSXwRCheMGOS8umoDV9lJzomHgkBFdhSl4KeWpRs0cFUsE8
         h2BmZftKaWgNMcvO3G0w2LorXEmytVYTNsXNcu+qqbngDsPASDLxvwy8Sw39oXP+1a4D
         zjCEclpqyghC/Z1cmDJt5Qv9PSSQ5mmcIzfSwKju6bFGqETCh8SqoAYsl5HXzD4O5QcW
         Lco3MjN4x/S1CiqB9719WpECBRGcTV1RW8EqL6saQaMT7X0Xdj6LAaFHfozGbdcN2GvP
         VOOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=2hxEa4W1DdwEN8nWctwTAFZiii6HS1fYig8+dV+ntUk=;
        fh=ZcAw9XBLGxEuU4X7ZoRFbOsooQT9amfZlePLtmC26V4=;
        b=jf8slpHKFMDE/jcP6wVlenDu6iitYoFfiy00vdAFqUI1Bo4k0n3zNNRCTsqhWJYHkk
         hQCexnbNDIko40JxJC3sv9kOJgeNyOn5aiSve+quap/ksUiRBHUo3NrDiN/boTiT+rW6
         w1Euy87xQtVhYCR+cphJmeOWtno4XlL2uLJjd2Lp45LLe4pZgkHXLg1AZq4WhrOn9Kwo
         n1EzEqF+z3AxbygSBXk2YhV3AIYGf9hhhMdzarDIW2jO/Ztr88n7oWEeJbJvZJuknlgw
         T0ArYHEfUPtMiEnWNO6yaugvZuIKOXaVTYMF7nAlvJXuBt6IOBEzMMULG48eCanbid7g
         xy3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e9e14a558f8ab-3a092e1762fsi2788545ab.2.2024.09.17.04.25.20
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Sep 2024 04:25:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E7E381007;
	Tue, 17 Sep 2024 04:25:48 -0700 (PDT)
Received: from [10.163.61.158] (unknown [10.163.61.158])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id AA1E23F66E;
	Tue, 17 Sep 2024 04:25:13 -0700 (PDT)
Message-ID: <06703362-23d3-4554-ab33-e81960e7d41f@arm.com>
Date: Tue, 17 Sep 2024 16:55:11 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 2/7] x86/mm: Drop page table entry address output from
 pxd_ERROR()
To: Dave Hansen <dave.hansen@intel.com>, David Hildenbrand
 <david@redhat.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Ryan Roberts <ryan.roberts@arm.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, Thomas Gleixner <tglx@linutronix.de>,
 Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
 Dave Hansen <dave.hansen@linux.intel.com>
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
 <20240917073117.1531207-3-anshuman.khandual@arm.com>
 <c4fe25e3-9b03-483f-8322-3a17d1a6644a@redhat.com>
 <be3a44a3-7f33-4d6b-8348-ed6b8c3e7b49@intel.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <be3a44a3-7f33-4d6b-8348-ed6b8c3e7b49@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
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

On 9/17/24 16:49, Dave Hansen wrote:
> On 9/17/24 03:22, David Hildenbrand wrote:
>> Not a big fan of all these "bad PTE" thingies ...
> 
> In general?
> 
> Or not a big fan of the fact that every architecture has their own
> (mostly) copied-and-pasted set?

Right, these pxd_ERROR() have similar definitions across platforms,
(often the exact same) something that could be converged into common
generic ones instead.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/06703362-23d3-4554-ab33-e81960e7d41f%40arm.com.
