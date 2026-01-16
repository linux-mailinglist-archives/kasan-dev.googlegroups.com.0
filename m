Return-Path: <kasan-dev+bncBCSL7B6LWYHBBM74VDFQMGQEJBGZWOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C610D31E26
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 14:33:40 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-653f94a664esf1991055a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 05:33:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768570420; cv=pass;
        d=google.com; s=arc-20240605;
        b=IN1GJRD4zs8BloQjmQYps/sLQdQV5L0qJEaoL1jIyAyXY+T81IqPGIPD5ybFO3pmqK
         6YdGvvSIr3worwmnRCD+j0J5ahK53bpsbQ0hUw6H5tavSQaeRZHxRpCbunmEFiIiQqMY
         mVR5SQCGQbPQTD8zbz/7imyTZcXLr/VxlUUyxsZjhr0kcTR61ZR2k9/Q85FcHykf4845
         QCA9iPXds3XAVqw6+NiYm0+x+vzvbtj0NTAuRYzng6ha6ngBI9HvuZ/1CO7HjjjLdNk2
         RYIgQ7Bq/hYJKVnT9KBwQERRrPyOz+l+TV/pFeK22z/HgFyX2l+5GbahLZyTRNhvSFGS
         GpgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=IOpva2fLNGDPjS7obTF4ofRtptchCH/Htrjo7ONPm7U=;
        fh=Gc/KOJiEo4xR/L08RQuAgi9uCyeMcOv7BijE+w7Jlgo=;
        b=bo/t4mTv6sLjmZhgNdK02oE3RhXw3+GbZDMWTfQnUM+fbTWSHQkj8dlSNlfHO4TDrv
         IzoM4xpB5vl3cmL5KS4YkwsBygCe4Uokv9UveMj/fruxfV/44IYfZIyt53PCfgWGAJbp
         qv+6KSRBYzn/hklkcm0DymKQ3emm/LZtvjwW68AnHv6/yRNGnV7sQfrclnlL4P2nGMTb
         VQzaAQRjyB8G5FxPr0fs2QGUk5D4+OPKMuHXmP/+czJXL2SWUF9LiQ2Z2dE6lKO+sfbj
         UAUkTFTwZ56YSTlG0dO8Fz5FHPx1GuLNjxyn0nAAM+cWkFIemec6gTZe0WfPBv/aTZp+
         +jSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Wx/vDNQV";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768570420; x=1769175220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=IOpva2fLNGDPjS7obTF4ofRtptchCH/Htrjo7ONPm7U=;
        b=f+ogAZxVw740VhU9PHyDrTveOXKEgRZNFzcpzB3PpwP/EirUWJKg0pGuzECn4NXZ2I
         9uKsRzg+KN1Bf2AVh/iI6RgeQ5uHt7sw1wsGcpcvVKSQb3COumX0IPhTGsxz9i1msE74
         i4O+JkuiWhnialZE7MHlMFIB1EYWU7fAliCv6JRZGPUNgIc7OJ3tTF434xXl+hiJmHbs
         iwNm8KXtuqoxDiiZ9Q5zuwVoRSwHlCMytn9BSniDSlMgIPDF0aMJWurwmWYTBXxJgWQV
         G7spyt6l7+3xxpmtHysPJRi56LcDcOOg8uX4pBUrvOxu7egzx2VKOTJ/X1FNjKmT3egD
         tPfw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768570420; x=1769175220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IOpva2fLNGDPjS7obTF4ofRtptchCH/Htrjo7ONPm7U=;
        b=AJtQScyLTLb65hlHFOsguWGeHUHajHTTOGBotus4On843rjUlmOY198f60jG2mnS5M
         coIVO86rFqfCKkwsxNNlPO6BmMUlwEoicyzv2BtLYoKXAxBSf8lq3pnyyaUCxAz0WC/r
         umNmzUNp+x4fInablk3Z/beTT6k8DEo7GBBZKB5H7NtWA0y6LWdFmsWTeULQzlDJOnGE
         MKjP+E2eYpEmR7nEp3Pzv9Dj7n8ahKFIvFjK6dfqLeMurCNd5kzYsIg32S9Jb3tmHDeH
         40ZyeItR8FJgLjblnokeMBoSyy44IkkNd6WHq8vf5c41OYD6RMC35jf1OVrhCa/k8E3u
         4KcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768570420; x=1769175220;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IOpva2fLNGDPjS7obTF4ofRtptchCH/Htrjo7ONPm7U=;
        b=qClEKKi2Al4g58VBnmy48N77F7mKR3MhESbFzFAkzoHDd527P8s327waWBh8XTgbkO
         6zzKKONJNLfoZeyT9qXuawnh7lnIqTurGXwqPnCP+biMl3teF0wTGKR3MuFd+SuU5qL3
         mhd/h6qQLMHXLm9VVtoBbW+kfREGN0vPK09F650IULepCf+loZIOdjz//swKhGwaA2Yf
         K7iz8gvFwRwXl4Du+t/IvFgK3GjKYGp2dzURAkOSBgYXuh87vREVYfqIttY2LzqMT+vv
         zjAtdue+4SmrcnBsddDkOFsYO4r87Mzx37RQyBgljdwsSGTMXe7TlkT/S4CuEZFJ9iCQ
         P0Sg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWp1snv98EdRl4spEF+VthoXNKB0qy16xlicjwMzw3zwGstnMGblgHY1d5xFo1uoa7t9fsNJg==@lfdr.de
X-Gm-Message-State: AOJu0Yy5vk+I2P+2Tis/RPTNumicRsSoo90NiUioL+f7KDtv0k5JqUSh
	klpy+3MEjrUnDxl+DmOkAIm1unZ4FMX/PNPku3CBUWDwn0mlfuSQOOEi
X-Received: by 2002:a05:6402:430c:b0:64d:317e:8ae3 with SMTP id 4fb4d7f45d1cf-65452ce1b00mr2119318a12.33.1768570419746;
        Fri, 16 Jan 2026 05:33:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ErGHrdLMgA9QF4q4EX14KSXv1AiIngf72jYHShF/OMgA=="
Received: by 2002:a05:6402:394:b0:650:855d:592a with SMTP id
 4fb4d7f45d1cf-6541c5e016fls1557516a12.2.-pod-prod-07-eu; Fri, 16 Jan 2026
 05:33:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWhTTvLzq/8sq0T11N4jy1XSSUKosGvIguZwpLSL70KxlWLrcOhr0Ux3JeGs8MQNiO/NOAKILQWKtA=@googlegroups.com
X-Received: by 2002:a05:6402:354e:b0:64d:1762:9be2 with SMTP id 4fb4d7f45d1cf-654525d14b1mr2108960a12.8.1768570417185;
        Fri, 16 Jan 2026 05:33:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768570417; cv=none;
        d=google.com; s=arc-20240605;
        b=Y8KFw7pl1hhtHAyrV3fuh/6zQTbG8gcfDY4aBNsZYeyzmmo+lhQAFCremMKow4EEtF
         cI1Wy6s3k5LbDqKKTV78z0Sc/hhvWYh46IQkAdvdeICXM2T5NDo336h9/ALi4dKfBbOE
         7B8ipf8wnFC5S5nnlYREfjWhE5ZcLwvNEbkYqRGYvZ4OPa/6OqxdMOuuscZt54lFf/Ea
         dc2dZSQXiDnqXXvw9QCaUdL9UA9xg5ej0/AdLDYcf02YD3PurSEaS4MlHgE9Qf6lIsah
         ncJtL+1QBVo5MPnjxrAsP7ToMWyq0xaubomXSEUBZDPL1MmetTX7yGL0616I++RmKJRl
         F3Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=uJ0Kd+SlEJxKbaePbsW3EtzVjRrjQZdOLYvse/lYkyc=;
        fh=tJKMHvAiPObD9RD+ewxkn18e5rZmwOtXwBdZG47Jt+g=;
        b=ekJWMBPboMleGrVR8i9ZR2Kz97OWUrj/x6Txjv9/qh7w513DEqAv17XX2mAhwijdH4
         /Y0pML1BgKV2SfLDZFNEeM+Hes/JhGiPEA214hM7NxBZlDTeFQ34TEFLwmTi9b1SJcCf
         jR+ubFDTmimKBkPaOmvVlzWm8afTXRqwR4lmvD9mIPwpOGiLY1ncL9XM84MuBdDyROLZ
         Meb32fODF8gIlBFpGdECRVCmXcjobuoQAsJ7qUiSqp3sNZYXlDBeTASxKJE7AKc3Fu0J
         d2FPWcjJbleEg3gf/+cP3kpbN0dfqry6ss/hijzDdPBlydP4leoGs2RdBeGi2bpNmX+o
         MrKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Wx/vDNQV";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654530dca1fsi33459a12.4.2026.01.16.05.33.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 05:33:37 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-59b78841dd9so121801e87.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 05:33:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXG8TbLn1GzTCX0qn1pKl4/tKBlbmgjp0sbSuY3vnoWbpUjvtR9CZuNtmewTiHg01uLgoojk7r0RYY=@googlegroups.com
X-Gm-Gg: AY/fxX61csr8oEquRKTc5nZ7mGdzaVg5U7jEVzHsxalOMnGeJxYHC44KshGhare9BZd
	kcPPO4A2KDDI0rQFuPn8kct0Slg5r284xcZELcgdHwCHXjZxOsB2x8J6W3X8XKkgr3XDIIwtUgS
	BxrDCXWhgeiNLYKSTUkSBZQW0b/71b9zKbCRWcwxJm72SiBHkbCt0ZtJAUoqBpCO7YNMSeYY4cL
	tr0EAomEOBgPmKlIXoyPVLMPmcm8dkTJ+kfJxpUU5untmO8OnhVx/+fdz36bEan5X6LbqKFmU5O
	+okUY/37ptW+nxtjRizhQa0eyCJOu8UU2IeZaUO+zDt4bOQq6cvdPSQpdYYx/IxvwB7S53kGXMP
	E+SeTJahDqlyCQYctjkSUwB/11pQvGDM9Db2CUyRTGtT1dP+6d0zerd3vFhXv/Pc1icJTUIRxwL
	pXPoSJIWwmp0zMfTUdGw==
X-Received: by 2002:a05:6512:6184:b0:59b:9fc6:f66 with SMTP id 2adb3069b0e04-59baeeffec8mr547766e87.4.1768570416127;
        Fri, 16 Jan 2026 05:33:36 -0800 (PST)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-59baf34d572sm763752e87.24.2026.01.16.05.33.33
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 05:33:35 -0800 (PST)
Message-ID: <c9841bb2-b82a-4daf-99fa-17aec157e2c2@gmail.com>
Date: Fri, 16 Jan 2026 14:32:49 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v8 02/14] kasan: arm64: x86: Make special tags arch
 specific
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@kernel.org>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka
 <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>
Cc: Samuel Holland <samuel.holland@sifive.com>,
 Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
References: <cover.1768233085.git.m.wieczorretman@pm.me>
 <be136bf8d1a6ae9ef98686c3ba0b6a4e2ea2e780.1768233085.git.m.wieczorretman@pm.me>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <be136bf8d1a6ae9ef98686c3ba0b6a4e2ea2e780.1768233085.git.m.wieczorretman@pm.me>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Wx/vDNQV";       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d
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

On 1/12/26 6:27 PM, Maciej Wieczor-Retman wrote:
> From: Samuel Holland <samuel.holland@sifive.com>
> 
> KASAN's tag-based mode defines multiple special tag values. They're
> reserved for:
> - Native kernel value. On arm64 it's 0xFF and it causes an early return
>   in the tag checking function.
> - Invalid value. 0xFE marks an area as freed / unallocated. It's also
>   the value that is used to initialize regions of shadow memory.
> - Min and max values. 0xFD is the highest value that can be randomly
>   generated for a new tag. 0 is the minimal value with the exception of
>   arm64's hardware mode where it is equal to 0xF0.
> 
> Metadata macro is also defined:
> - Tag width equal to 8.
> 
> Tag-based mode on x86 is going to use 4 bit wide tags so all the above
> values need to be changed accordingly.
> 
> Make tag width and native kernel tag arch specific for x86 and arm64.
> 
> Base the invalid tag value and the max value on the native kernel tag
> since they follow the same pattern on both mentioned architectures.
> 
> Also generalize KASAN_SHADOW_INIT and 0xff used in various
> page_kasan_tag* helpers.
> 
> Give KASAN_TAG_MIN the default value of zero, and move the special value
> for hw_tags arm64 to its arch specific kasan-tags.h.
> 
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> Co-developed-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> Acked-by: Will Deacon <will@kernel.org> (for the arm part)
> ---

Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c9841bb2-b82a-4daf-99fa-17aec157e2c2%40gmail.com.
