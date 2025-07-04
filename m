Return-Path: <kasan-dev+bncBCSL7B6LWYHBBGUYT7BQMGQEACMDJLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id C7647AF92F3
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jul 2025 14:42:03 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3a4e9252ba0sf559110f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jul 2025 05:42:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751632923; cv=pass;
        d=google.com; s=arc-20240605;
        b=QyjIJSOhLauf+9oMP7AOn5oLzyS3dTo16dR8806PckfHy92x7ORWWU5amX9kLq8827
         rmpIga4Yji6JNT6Ez4UU5BZb3pgDCGSxQM4audG8EyKbDs97ik13Fonoj1rSW52onNXL
         8TKyu/IZqSswuiDrifJHIRVSwQfHnTWY2NMdhHRaUNEEbJgM+jXWe0rownvUh5uSswV/
         0/McFvVLLw6YtPUDzI/mM49QTvw+0w5dyuiXLa5V6z8R6cGWmaU8RT0lx/fMX9i+++DR
         hnPMKCFCZAxXQVjQCJIjCGpXzOnJ/i0o7gzW+v8EQ+ivyO/wyK73i2r7+FDDRKEkVMAk
         ZVJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=QVMGQz3XbW511ds7oKUj6zvjegufXQ9xQ/qfK7Ffyl0=;
        fh=PtWmc8fPSDWckh365TZyaaK3RjCFRkd0lVZ2Zx+1YlY=;
        b=BpOKKkDi7BeW+aQHEZZivcOPLYlZGkCNSuE3nSAWBMF0shd5Y6IZdotjsm9qojwTBU
         W5jFMZhKY3NAKRRE+GfbV9q5npL2s7rVpLluQwLZjQc5dcoBy937W7/Bt3PmvUyeAU9m
         nZbjO5gt0Bgc2ZxqoPauz6dIt17eK0J3HzTeBmaenOx1cxardwuX35HkWXed6/8alQY0
         834JogN6Vm8iEQ5mquPzceHr4u2jjHRjp3g5jWdfjLPzF+3NZ6+EVc1a6zfFIvu78Qac
         VDHwi7C7LA98nqRFCfPQ7NJFiXxHIfp4G5NZIDd+OHw30Kg074DvGNH9Q+sLIkjVC5ar
         tvQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="h14ATR//";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751632923; x=1752237723; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QVMGQz3XbW511ds7oKUj6zvjegufXQ9xQ/qfK7Ffyl0=;
        b=qs6KP81ttxnkAIIRXHdMT3rXv9n35ZQTGHwxl8r+o5FXTnX74Nnnk4W6dUydYg7QC5
         eDWMsYwgDWqMdsf0EK1L/4Saouc9WdneHbMWq8e2TgFQCC4Hzs4PmtAyyfShg3rgr+U2
         2Y+fu5ypPP54md1mswMSNNUkAeQcIOGA3gpGQ7eqYGcP+bQROKHqCw6ZaqudI5R8ZiRX
         qYlcZwKOVRcrpL2iAefht/H7r+XyxYAkefWtE5fV3qNWgHsuRnmIrdrIuM6J8115rnb4
         LLsXSthqRwkOiIfLxoGK2MZN2OVHdIKsUZt7mNLSpc4sYUgYaLycbLAx/Ir/eAsXRkVx
         KEYw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1751632923; x=1752237723; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QVMGQz3XbW511ds7oKUj6zvjegufXQ9xQ/qfK7Ffyl0=;
        b=AbcfDuRUMZkBXUM945gxlzFH7jpriv/kBH0VeRHnm2xEoZOlyJsguCncvhuq/lgbuK
         tEhJkEHn28wsFps5pUvGEK1EVymK5JRVTHscmADRW8YeE7LoGjEl5sZZOr9ubo3B+3p2
         6YOo1WiQNN7iKxjoQvwg/Vv1Rae4na9QeRubPll/R62k/HGvyeLsdWZn6z9jJSFK8IjS
         kYr/fcBXi1YVNShOat4vACIAJzklDXsj76Ro9LOvNydKH5KrXepL43FvBFGciWo7hGHz
         +OBH+G1Bvf5O1jMdaMH/cPyU5JG2LmisXSwtZnMvnTOh3nCCPWt1RIs1mnttsn6riUGZ
         tgPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751632923; x=1752237723;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QVMGQz3XbW511ds7oKUj6zvjegufXQ9xQ/qfK7Ffyl0=;
        b=HlTqjCSdY16GRODUxIDueSvFh2aMq3U8ygB1V86TrOl6Uzhk6Oan5I26thfFOGp7/I
         VNOR9QDAW3GTNuIiHKoxFSP0G5umiLX0f1QnFhxzVvtMVbDlWrhOZRCOgzQ6rxpV19bK
         amIlUYUDbqflmgg4Dx5cKri+qJrvA6q40A0pyz19J/moSzbYaK2NrxFh3Z85ArkL6uAt
         OcBJcYbtOGMvGbpVlnLnSCJ7lm1ePZRuBGVp/ZQBXVK8MlyRTJkgbxXw+yXiqP44DiqG
         UTVrO0aGmiVPkHUvAynii2uf40aK8MuO0BiEG3jNElb4GaFkyXVxc2al32R1qL+svM3T
         iuhg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUFt73Q+dCcuon+iAampQmcBkdlWjQuLN62nvr8Z5HruFUdzyp0Dc+q0AkYNkHo4ZEuLPFHgQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy37eEh2lm7nFv/DVkChnqbj1DmzUzaLTI0AvuKzV4sa74nGGU+
	AY+bjsqmTFT2h/mQasRUERxL1fwC0RFk1pt0MHJwQDOQRDD1433M616U
X-Google-Smtp-Source: AGHT+IFQc3QU+rC06uU4q4G+AvhLpgZ4eOxirWrKyQNlxfkGe2nsvzCTvTtR25fs8tkHm2XJ67YsEA==
X-Received: by 2002:a05:6000:4908:b0:3a5:2ec5:35a9 with SMTP id ffacd0b85a97d-3b4964f4e01mr2273256f8f.3.1751632922744;
        Fri, 04 Jul 2025 05:42:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdJc6GuR8Cka3ZdsaHvNHosAqy86hQNruuhBamVidHUAw==
Received: by 2002:a5d:64c9:0:b0:3a4:eed9:752c with SMTP id ffacd0b85a97d-3b49758e371ls251024f8f.2.-pod-prod-05-eu;
 Fri, 04 Jul 2025 05:41:59 -0700 (PDT)
X-Received: by 2002:adf:9d8c:0:b0:3b3:1e2e:ee07 with SMTP id ffacd0b85a97d-3b496626856mr1760716f8f.56.1751632919690;
        Fri, 04 Jul 2025 05:41:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751632919; cv=none;
        d=google.com; s=arc-20240605;
        b=hGKFA4W+ZuHhli4g8dXgw40eVr7EtLm7aEaX18JnWWKhUN6QHcLfngl4SPG74/GsfS
         oAe8Y2HcO309mvqX38TnTCHLn7phjfTZExeCATO39811Wp9hqeEP4uY9jCyJkE098tlZ
         U8UgRj4muMgpSbEJbo5lMiVIckCxxz4TLEwxmbHmu4rdnJX3fXm4ZFDKI1BI5I27HuNa
         gjPOWm1NoXOJv1RjEv/S+dYsp1w9QKOapaWZBABh22OP6GZWROQyacTdQ8xL/JE/ozgX
         dEuwd4kdXwcMWVn4IK+6E36yHY4WqOuuXLOxkn6ZlwvO4JhB/ZR3mYxzLCMmvyzjQWNQ
         Jqcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=xd/Gd4g9iL4ksrRFBiW3o7hZmTHOxsax9CgkAVFFH9A=;
        fh=zOWVOB8bj9ActAP0Br1ZPISmPoIdallXOsF+FAW5RYw=;
        b=cVTxFbyejEOIP8C6/MKIR8Mi9iVicgl4v1WPW0KG9JxfAwa1le0KJaFQek37qySGT7
         nysykDrk5gn+PvTyJsHT+pPiObW6HwW+Y7poVqa7KAnxTlZgKoj34sYsYyPl0nt9/9M4
         chPH4tfKE6VH0m+LvRiu5dYr4+iRl1dUbn8IIOsupN0GtMvuGMDldmeRG2+SfSnRPtDR
         43Jq6UoFUdmuaIPN7v75/ePxa0RWuiabVZbn5iLgheSqKCr5FAGXlBhKFEGPPRwUHkxm
         Pc9YJsf46wF/0Lms7nfCMMSyiFVJ5NH5LPnlAjoQQhxgSq+RYyGukldclCcujMrqQK4z
         Kw4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="h14ATR//";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-454b3b1ed4esi347855e9.2.2025.07.04.05.41.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Jul 2025 05:41:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id 38308e7fff4ca-32f00cb318fso816571fa.2
        for <kasan-dev@googlegroups.com>; Fri, 04 Jul 2025 05:41:59 -0700 (PDT)
X-Gm-Gg: ASbGnctrulYmY2mgH5jgNJrb4nxh9RpdZRT0o2IubwCVwSqffRpE8ZG7v3wMXKisPAU
	LbD5kTCWmuKztrQwgXwMBcY42hk0FcV6cgumFENPnmyiuCPcX5qO5uRPrj/jLquDONvdWZaQX3u
	SSLs0apagYiVCVMIDPG3foJHE5bqNKAQXBTvCZ2SPR29aCwB6QppDqRk7wV+DOqpV7LRwfhCu2v
	1vPiOkkQooloCTQdWoXN+V8le6PUL3sZb53GQ8IoAane2lXhsLQleA6YNJTblSKO/y9tvhpPu8+
	pR5Z7nOZbjk4OwOGc/YANn63koorPw5Ywg48NCEI9L5RBMvgvcnlkZbKCbNqn1E4NseR
X-Received: by 2002:a2e:bc14:0:b0:328:109e:f974 with SMTP id 38308e7fff4ca-32e5f5b7630mr2452791fa.10.1751632918553;
        Fri, 04 Jul 2025 05:41:58 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-32e1afc362bsm2090351fa.36.2025.07.04.05.41.57
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Jul 2025 05:41:57 -0700 (PDT)
Message-ID: <37b96f5f-d79e-47bd-9616-b6c8905bc984@gmail.com>
Date: Fri, 4 Jul 2025 14:40:39 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent possible
 deadlock
To: Yeoreum Yun <yeoreum.yun@arm.com>, glider@google.com,
 andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
 akpm@linux-foundation.org, bigeasy@linutronix.de, clrkwllms@kernel.org,
 rostedt@goodmis.org, byungchul@sk.com, max.byungchul.park@gmail.com,
 ysk@kzalloc.com
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250703181018.580833-1-yeoreum.yun@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="h14ATR//";       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::233
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 7/3/25 8:10 PM, Yeoreum Yun wrote:
> find_vm_area() couldn't be called in atomic_context.
> If find_vm_area() is called to reports vm area information,
> kasan can trigger deadlock like:
> 
> CPU0                                CPU1
> vmalloc();
>  alloc_vmap_area();
>   spin_lock(&vn->busy.lock)
>                                     spin_lock_bh(&some_lock);
>    <interrupt occurs>
>    <in softirq>
>    spin_lock(&some_lock);
>                                     <access invalid address>
>                                     kasan_report();
>                                      print_report();
>                                       print_address_description();
>                                        kasan_find_vm_area();
>                                         find_vm_area();
>                                          spin_lock(&vn->busy.lock) // deadlock!
> 
> To prevent possible deadlock while kasan reports, remove kasan_find_vm_area().
> 
> Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
> Reported-by: Yunseong Kim <ysk@kzalloc.com>
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>

Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/37b96f5f-d79e-47bd-9616-b6c8905bc984%40gmail.com.
