Return-Path: <kasan-dev+bncBCSL7B6LWYHBB4P542KQMGQE4LGEXLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EE7A55BA7E
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 16:30:10 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id n18-20020a2e9052000000b0025a891ce677sf1062140ljg.15
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 07:30:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656340209; cv=pass;
        d=google.com; s=arc-20160816;
        b=HpNrh+LN2YT1x9Ci1f1spwoLFptD7Z2FbReidPgYt6LbcCXTuh1/3e3A/XQO+TvpJr
         yB/OOhI2hGqvGsVAItsL6jCjE+ujtrGvwZM/4vh+dq1M/6XHfSrFx9m1sig+gwwhD5dX
         Kx2wo33xm2K6BrGZuTcLHGf3fj+HlSTyWQX6EnRLrUWrGr5eV9XfhBfZo8Dec/OfHt2F
         SoubsBmnr8UqNFSkZlJ6lykWVi1Gj0DrRa2KEiW0cUetOtiEdmqfij5tTQF497QpgQ8g
         ab5A5PDsl+6RtR8jy/EDXRA7Qrmn+6XPOZrSkEg7CGSWWH2dyw8InqqS9w8jkBNNM1O8
         kEdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=GMUL0Yr7GOmgqqej26NF0CQVh3HqEZnj/r1jjJdf4Xw=;
        b=iyLWV+GGPWUMsO/N10Dy8qY2OHp+geHlH0OOSEVu3qINro3DLUbivTvkDcCD37JjhY
         BtNaxjwwfqvKvKm0MlWQrOro/DWrRpBieSf+/oGYpKXR+x3yYTpcN9lhC6Qjxph/fPPC
         7lMAOYyOnHWY2oPIwRZp1UCfg5wcOdyCvH/V7wveolljryQ27No47dLOStoDEn9Vbeai
         gwwot67HNHGlY0pZIBZgqPrXlgMX8XorrTsGFpz+tkGtSAH5g9vh6yiut3mnawL8r2de
         e5lFKQaX6Z6yG6ry0LDhy8rWVQlguhrQ42w5nmnFHxETbjpKSFRHxPdJnL7rymtPp6/x
         pwxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=JlDAoSXg;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GMUL0Yr7GOmgqqej26NF0CQVh3HqEZnj/r1jjJdf4Xw=;
        b=ol9kbZ+4b4SDs9d+HMFAoJNro33aDiwt7iKfmMFWg1i4OY2ftfZKWEy30y73ToPvVR
         OmUUmQxjKMsqWbfVbaFrrdAD/eHjxHT64UvvbvHw0LS4S/hjlYFE5mYJ/RKE2l3O0Qtx
         zdbAym0dg8SeibOaXLQPuA/jfbtUkfl/EE8D3GMRMF/axrHtsaxJdNaG/xGfUiq0H6ZD
         ckra1rqI1n+EUSBcmhkIv4ezUVEtS+dHFXkA1JR/TALBNDeIgoRvn2IVF4Ue+vHo2Z7M
         Q/hI5NgYTe0vqpCjXDQjuGElH2bHxq6odM2pC1BBVdey37oD4XoVZ1agEJUU8dc+JK8h
         zfgw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GMUL0Yr7GOmgqqej26NF0CQVh3HqEZnj/r1jjJdf4Xw=;
        b=na1Yrm5SzZGBYpIzb8J/jlnOSh4Pz8RGqXkzl5c0wSHHaxGME2afsA6aG58eHSmMR5
         KqArL+G6F4uFexqJx3Lu/usMJJFswEu0bDDJqprbE5t4hhYoLbcCyh7l+z/DCiH31rF6
         eBPxJZ7eW3r1HhAmCKk6F1aVnH0WXDt4/DftzTR3pK1+znYuXJP4gP6mzKPnvnJRbv94
         Wlj5nT6Z3uF7Sik1bE9G2K0LBNyK/83jLvz8StaJRB7mpHpxnEvOs48krgKbbD+iFOmB
         9buWWMFDZh+sY7vjRE/mPy5OK5ynNQpwav4EbnzFD7kBQnjkM5jwZa1KZQy5gR1Rwukg
         3V6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GMUL0Yr7GOmgqqej26NF0CQVh3HqEZnj/r1jjJdf4Xw=;
        b=INNwoc58Wa3XGewR0kG8i0U9AZ7SUXBtwJNk71xjesFH7y+xlHY6+LxHV8Wf7FlKCh
         LFkiMnREGONG47t0rQj61AXOGbH3dGi0+9/O6LAVXrJvXEqPPerjd3VLIU8NeTXn2zQy
         giUVy3LwHn2C020jxZOzrrAkEGRqBy6IdRXDZ8M3hMtEIIjvHvGSB87UsC/IhqWijc7T
         aNoj2I7Mwr8CbQBl2CFd2vdbjaBoYQDAI7dqGZwR07OQfEPEl/rkNWEyUKMytBMiCHTO
         k2iznkwBtXz6rRDf3zr26sf4ynQK4sdp4Es1klrQXbHpxLmsUpKC3mbglJBSjqxpi7fF
         fKFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/MD91Rkw/ssVjX2OmEPBMoFcI5GonBzrC/m8e10EdnB6XJRGwe
	SGaeQcw/+5LVEOYlD6LLq40=
X-Google-Smtp-Source: AGRyM1u1RjAWZcXXs6LQF3ezb3GHJToa0KybC6egUq1HV+oggL0qcjuaCdb2xWFPS9v9gltc5Lf3pw==
X-Received: by 2002:a05:6512:33cd:b0:47f:ad57:70d7 with SMTP id d13-20020a05651233cd00b0047fad5770d7mr9303271lfg.558.1656340209296;
        Mon, 27 Jun 2022 07:30:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als82390lfa.2.gmail; Mon, 27 Jun 2022
 07:30:07 -0700 (PDT)
X-Received: by 2002:a05:6512:6c9:b0:47f:b8ec:12c1 with SMTP id u9-20020a05651206c900b0047fb8ec12c1mr9289539lff.531.1656340207845;
        Mon, 27 Jun 2022 07:30:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656340207; cv=none;
        d=google.com; s=arc-20160816;
        b=oB5ofc71pOr4Q2bh3jBImo8E1e5UN63fDvr18tfZ2MR+Y+0tDSqUEmv78O9pKPfMHb
         6pDPyaxN+UBjr6NhjUu1hNcnFeLEJDLRKehx+Q+eqhCkFp3hx7ioFFi9Y78NQ6y2hC+H
         EnKqsbyxwhDJYDExbVShH+XUhFGAgU2nhtsBe5yCw8CL74W9g6IdAOpsBUTIx+fWTjxb
         2G6d4LDLKDwoL2lF9zu6SBjFmor4brZTOfQ4MIkewmac+lgdZ9mBV52zm+gPda5ybsk6
         6mWpzu6VLmGeud+D0f69JfvIj1njQMbUeBNFjpppWWm/t7xpyakbZ/Us43hIa26vtkAA
         9uBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=eFEE88CccHR5CkwS+vurL0zrLbEnGdsXJjb2ZKJiUh0=;
        b=EU6XTgnNpk0eqYc8qavpBJDQKerTRWOMiMhXpl3b0+l8cSzTXdmwxhCVlqU0jHLUCv
         FVckGvZew4gSQ40BRejrg+ROBfIOKbUvcOp/S/hf0PaG04CzPDc1Phg29kv+VFkM1WRM
         Tn05lABejzF4ESDxCp8RcLZAql/Hn1wT6nZp0OEKlamYSS1hLj1B967EwzsrJFXMJaYK
         I8/VDc7B+uYuU7KOCoWdBx7BjNsWsi280jnhxhYHUIQKbfk24u9/BxAF/PnkV03IDZ19
         aI84OAriOfsLWrJQMLU8ey8AWUc5rwiaftvmHI3vJkFTSeUUn2sO8gawdNxKM7yfHBqE
         IZbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=JlDAoSXg;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id b23-20020a0565120b9700b0047fa023c4f6si451606lfv.7.2022.06.27.07.30.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Jun 2022 07:30:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id f39so16985570lfv.3
        for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 07:30:07 -0700 (PDT)
X-Received: by 2002:a05:6512:32c5:b0:481:1822:c41f with SMTP id f5-20020a05651232c500b004811822c41fmr4601636lfg.373.1656340207490;
        Mon, 27 Jun 2022 07:30:07 -0700 (PDT)
Received: from ?IPV6:2a02:6b8:0:107:3e85:844d:5b1d:60a? ([2a02:6b8:0:107:3e85:844d:5b1d:60a])
        by smtp.gmail.com with ESMTPSA id q10-20020a056512210a00b00477a287438csm1837713lfr.2.2022.06.27.07.30.06
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Jun 2022 07:30:06 -0700 (PDT)
Message-ID: <dddd7c7e-3c60-f916-2947-4ee00a765574@gmail.com>
Date: Mon, 27 Jun 2022 17:30:58 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.10.0
Subject: Re: [PATCH] mm/kasan: Fix null pointer dereference warning in
 qlink_to_cache()
Content-Language: en-US
To: Gautam Menghani <gautammenghani201@gmail.com>, glider@google.com,
 andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
 akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, skhan@linuxfoundation.org
References: <20220626170355.198913-1-gautammenghani201@gmail.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20220626170355.198913-1-gautammenghani201@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=JlDAoSXg;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133
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



On 6/26/22 20:03, Gautam Menghani wrote:
> The function virt_to_slab() declared in slab.h can return NULL if the
> address does not belong to a slab. This case is not handled in the
> function qlink_to_cache() in the file quarantine.c, which can cause a
> NULL pointer dereference in "virt_to_slab(qlink)->slab_cache". 

qlink is always slab address, so I don't think this patch makes sense.
NAK. 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dddd7c7e-3c60-f916-2947-4ee00a765574%40gmail.com.
