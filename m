Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBHUGYKBAMGQE7CNB5AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FEEA33D15F
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 11:06:24 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id v5sf22849232ioq.19
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 03:06:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615889182; cv=pass;
        d=google.com; s=arc-20160816;
        b=NDu2KRwYMMtNfAk9msQT9hZWKUs2udzfVFX72PrSSXtrnbwVWF5lu8fG2cj2nuLjDO
         N0lVB8XrrGwUFv64NF+oHnYyv97LpAb/CKkW/RtLxpZ5wQgRm7j4AbyoD+P8aqkoJQ4z
         tfagXej+dzkmRcLepNbRlFkO2DjSnS18ViELKFBYOmM8Pl8RhzM3tQAE/hz4QtKIuNLJ
         GA/RoR4FjH7RoaqPJ2/1LQiLD1fLrHyLESJwGCBbJI0agLPveFFC7ogNKa5cvopv2MWp
         pwSBy8vv5tt1dsFlXHJmrTM06OJlSTylf2tHofxWvmQUVdPHMWjav07uAWz+KHCZzdF5
         QTJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=16giEW1Ncwiwnq2zXDatXiAlr6F+hSR74Graa01p5dU=;
        b=mgGVeH6vL5Z44WB+IypYpAP/FkeuSu32ZNAWdcJZ3u/ABcXbf9fYaLf3wNqx8m++fs
         tgiTJ9Kl/A6Tl/gKo7LPjoW6TFaGhQ1krPLnys2WjbiIRtuK/XaM32U67P0ptNekRNMg
         wJwV2Fg3jj/ehpKWM2Zo2O4mPssipa4Q9jaBLlt9L7OKm46qkm9X5q+GAa+n6xXl1+/t
         gtP6wuN0Kf8Q9H+zLgzWDKz6xm46FaF08utInole88DL04LZfOJ+Q6/DC7LEVZ7uX008
         izpDY/EQt0uPNM2Utam2L078Gn2MIoJm30HbpHmTjbV0ymjV37YQp1RDzz4k6UdHWuAu
         EIQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=16giEW1Ncwiwnq2zXDatXiAlr6F+hSR74Graa01p5dU=;
        b=cP+iGEcJjS7jsSqaOGlbjnIRqCyojseHtE8iB96di6836Y/RDzPe6TEH/jpk+MdOlE
         d5OH86Q/Oz4p828P+NT58FhRQEb7N/8GJroxh4A9Pj4Lmw8DcsjiMJhJI4ER72oqlic9
         i1xTR/TYioAnAeHkXHZVzRnYODD5eCVwkdKKyx+/5mxOJV00HX8otA0ncRVjynjcWAbR
         HlZclp9F/T24tNLuNGaUYLr2CAweqUdS6gZa9E4W0U6rtaJYkcuHixrt3hd0zdFDbk+M
         E4uvPmD1mkPj+udXAfm0SzlmwKpPcw1sXIBaVEcNJktQ4T+H1+3VXoxLqyiIEEj8T6zW
         OAtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=16giEW1Ncwiwnq2zXDatXiAlr6F+hSR74Graa01p5dU=;
        b=edLcljDLJTEd4RjnzveQiMa4NzjFGkU6KDb2EjYUuSGUGSMfrhNcbNWhWE4MDv1UPp
         GhjAwHNQeeX3h4XWqflKCVHlFxxPI1rqPBLfYfbd1XTcLV/vb/TVZkBKDoOMLwLAW2OV
         VeMPW78UXZC37TndeLjM1mNLzBTOtgfkf3d2gk4Zwyawl70BG9ba1UFvUxUHg9Ay3/VI
         +iPLfRBuoPtZKFBiUi/kD/NhCkRKOEmvnQXMuQDiZFRjlsxPg5wK392E0FF7dVuGM7hl
         gdGs4WPaEj7UkhwSUmf4hLfZSYTp3ONw/pD5LimWt1v4kx+ohOUjhWrBDIFncphRQfWV
         86vA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531a61/3K4pbcIkTxNdNXY1G2SNS5hTp51lFL6SAMI3Rv9XQXzLg
	JQwr6qSyMAyT79LkEOv9YK8=
X-Google-Smtp-Source: ABdhPJzkhSL8W+Z/g6NeVP5shbyocMlup40lr+9YfsrVbeG2ODdWCaNy0ZU4/A3GcKgv9hIY6XT7OA==
X-Received: by 2002:a05:6e02:802:: with SMTP id u2mr2916140ilm.298.1615889182472;
        Tue, 16 Mar 2021 03:06:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:692:: with SMTP id o18ls4303314ils.0.gmail; Tue, 16
 Mar 2021 03:06:22 -0700 (PDT)
X-Received: by 2002:a05:6e02:1b8e:: with SMTP id h14mr3125318ili.300.1615889182169;
        Tue, 16 Mar 2021 03:06:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615889182; cv=none;
        d=google.com; s=arc-20160816;
        b=z1k1dFtBYhTQAAia4zaEid7Xbj+nZaXDMHlmI+Ayb15HOx+vrhU1EG5iqGHadhiICC
         328Ak4vLaB77zGq5+e8okodhoOed8FIIeRgtqxsrSro40IcNxaJXAc3Lu/T/F1U53Klq
         TYoIsb95PWpKNjRVihLJAXxpOAsFpiyx9cBPMymliMklzP4rOHwcriKNeLZzFOKhwShW
         L6gjmq7YnOFcRh0f9/eduja7MfBofaxITqjdlcngydOYyRvBEPAqfwgsaBloqCp9hwg9
         rFDcqVF2JkHcUl22pI627XVLHxwtnbLyL7ilBxM2qqz/fm3enxINeWxmCw6cF+zVTkG/
         mCUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=/Ead4NYAgZlcXhv3c1RbUzthtg90m6Gv+G3I6l3FY48=;
        b=NDvab4+tDUgen/8R7omLKWJwk+/jbwd+0UqOCDgDuC5pUXqRxj2HG2JuuwPfZh7Mw3
         iSo9+7YHzW2Mc4/2x/84Ft38OIzRRdLYPiOXLjZd9EQjE1amwzhA+5p5fggmVm/UpRfT
         cJhcOEaYgfH5NySC2+3Rc0oU8snkK0SXzco5CpDvudmN7UheMSvuAm79kBfuZpPHh3Po
         RWptrl+tYjZ7hMbi1uUTAz2vTbMMsY7N+rrkxjCj5yzdtz3B3e42dcsLpj57b6YGRs+y
         z8cd/XSQGtEkwXSb4tqI4y1D2LU7eL927JlmkXyBBE7t0hTFnE7SeBKKnqMCzsSCdH3z
         OUiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id w1si848113ilh.2.2021.03.16.03.06.22
        for <kasan-dev@googlegroups.com>;
        Tue, 16 Mar 2021 03:06:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 92DE3D6E;
	Tue, 16 Mar 2021 03:06:21 -0700 (PDT)
Received: from [10.37.8.5] (unknown [10.37.8.5])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8BCF73F70D;
	Tue, 16 Mar 2021 03:06:19 -0700 (PDT)
Subject: Re: [PATCH v16 6/9] arm64: mte: Conditionally compile
 mte_enable_kernel_*()
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
 <20210315132019.33202-7-vincenzo.frascino@arm.com>
 <20210315184152.GC22897@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <3f0b916b-efa5-ad35-b838-34f1edf2ba3a@arm.com>
Date: Tue, 16 Mar 2021 10:06:18 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210315184152.GC22897@arm.com>
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



On 3/15/21 6:41 PM, Catalin Marinas wrote:
> On Mon, Mar 15, 2021 at 01:20:16PM +0000, Vincenzo Frascino wrote:
>> mte_enable_kernel_*() are not needed if KASAN_HW is disabled.
>>
>> Add ash defines around the functions to conditionally compile the
>> functions.
>>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Acked-by: Catalin Marinas <catalin.marinas@arm.com>
> 
> (BTW, Andrey now has a different email address; use the one in the
> MAINTAINERS file)
> 

I did not notice the change, sorry. Than you for updating the address.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3f0b916b-efa5-ad35-b838-34f1edf2ba3a%40arm.com.
