Return-Path: <kasan-dev+bncBCSL7B6LWYHBBYEYZGNQMGQEN24LEJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id CB795628218
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 15:10:40 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id x10-20020a05600c420a00b003cfa33f2e7csf6825091wmh.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 06:10:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668435040; cv=pass;
        d=google.com; s=arc-20160816;
        b=zbG1tRc0mkEkpDaZ14fF3pdYp6K/AwoeB9Yjug9pnWaogbX+zVDw3xyBMb0x1NTAwo
         1cfiG08XjsXSmeUdj23P6PytJKxOm8GVvITCF6qAxfQgu4LQgNLd/NyXSgVGf4XJQBRR
         krd98R0cZO8+VoT4j6/YtpyuPko23DKquhhLah6DpxLMB+llkqSd1hHomStfZp7Tc768
         k9nrKDWGB6ZZ2qONjOAmR6JcYeCB/8OKdqizZ/xTLfCgQBzS/WvF9spgnqKFdxiXIBVZ
         MbwyKRW59AmYPb1ElCS9fprywc5kMUe8vwWHG0aROXpbDTIzy9OJkyFmjEi74cjQE24Q
         TAxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=6YX8toyguFJmu0vO2FR2wYkS7fxihjh9/DXOEWYVeY4=;
        b=eGUQaEr2DrOommImBCYxQit/Ryyz9QlN6ZDaslsGWgEQzHhg554KRsH5L5G7kZ0LEA
         mmhvN9hXFY6xxTo4jpgQMjlX4faUNykQwfGamJG2/1AvMXVf3d+MGK5ReUHp7aMOX7IF
         vmMsvNDMgoKUhbPvf4SUie92i0wV6zi034i1m+Wfs/LaSOLOHZ68zFsXFtJ/vQIM9LIs
         I+LenlXMgcEJ3DrH/6wFftky+GLGlhLqqmrS8SPNKC8XEAGL/PpfLhkld9aMIwRrc1rL
         lXaXRJdaEfMC+O3MwUukG9CLw0hQqLh1tCjwC+4EZ9LDf8k17BEYtcDBqdSbvSGoZYjV
         Molg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=bSeOmRV8;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6YX8toyguFJmu0vO2FR2wYkS7fxihjh9/DXOEWYVeY4=;
        b=Qq3fPujn2djQfToZl0vXZ7ioDkqznM+dmdgPNQeuTT6RULuOUh7fiT8zMpIUgYWdQu
         xR8kZSnzgh0x45G7cigm3RgX/g9cYd4G9D0eyO/isrjvj+xSzg83ZTCQHbbmZzS4H+nx
         mqxqd669BjD+xJkwwlF/U/lb/Z7+bm0VljKPz8vFrTDBqXGhFhj+CHU+uagiAEJ2udC8
         HTB5PJXjkV16pRFuGFYr3YSuiD6/jYkKs/n4Mx2Vw+nHAponD/dQSFraeA/YxIStPj0D
         mXbBiypT0knkDztOqFaGeRnIU2zyhh2Y6rEMrLNxjFlhLPX6ElmKuj9Um5g4IJgwfIr7
         bYzQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6YX8toyguFJmu0vO2FR2wYkS7fxihjh9/DXOEWYVeY4=;
        b=odefvEffB1gHe2J2kmobY5Oc86P0NFwGqL+6ruzCkl2qFTO38e58dMjx7c+GWEzIqQ
         jPCostVK014SkMaCv5tS9043Ye9ddjsGPr22//Nc9KfBQJUIC3aQjovFVbzHmqyrOsQh
         7JWezkgbsX37uJpwsBR3dmn3q7VT8TRCVXSURCPzKkMqpZ8GdMe9QwnKpMpfbo3/HxtZ
         QIRX4L6jcFsPgHybDx0wHEgfV1U0P2TKUBbkuuG1I5YpL4Ms+GC6fbnZ32A1tezAPc2R
         GOfvQnUGXFyzjSpBmJE86yk0w3RNlcTUdMERHHip3rb2/4Wvoe4qOJfga7U9L8ObnLpQ
         X8Qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6YX8toyguFJmu0vO2FR2wYkS7fxihjh9/DXOEWYVeY4=;
        b=ZjfWlzvJbRuJTtsmMsZtpxFmOE7CNUlMaR9pU8E/PnUgCE3QtHKh+UJCzrDdQuRZhJ
         9E4ym4vqkE5+dyC2Ftt58hlT8PMEOsRMRm7aMWqX/pbRhc9ZwhilQdmVmqpdG7a/Ymnb
         i13XPsFVZ6CEdK73FaKlRyXH3IfyEl1XZ35mwpu6ikcgrPBcLF8yDA7V12da3/+JdOlO
         ggwDy4/HMXyizMvOrE+lLFlCQtBiab79XExXCB7D+g7Digv5iEHhmTwLjR/8Mu81Oqkh
         L0vS6d3WdDDEA5KLUZW6PZQB/SDgua00rtwx4dLbZ9FDSxmQCPOqYiJGi74f7Ming+ec
         5/lA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pn3EIrcIQt59A7yxM6FAg71CJsPUJLjtKi8tGUe3zaxJH1Mytaj
	bzqMOGki4OrQxDnly1Pk/Bw=
X-Google-Smtp-Source: AA0mqf5+6h9UrKXAUnp4YkwWVJmiqasEFvhV+/M31I6cAFpr4PVBBklF49E5AvX9SJEFJWsEJ/ffPw==
X-Received: by 2002:a5d:6743:0:b0:22e:28fe:39d6 with SMTP id l3-20020a5d6743000000b0022e28fe39d6mr7718488wrw.701.1668435040227;
        Mon, 14 Nov 2022 06:10:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1c19:b0:225:6559:3374 with SMTP id
 ba25-20020a0560001c1900b0022565593374ls16227661wrb.2.-pod-prod-gmail; Mon, 14
 Nov 2022 06:10:39 -0800 (PST)
X-Received: by 2002:adf:f284:0:b0:236:6660:62fd with SMTP id k4-20020adff284000000b00236666062fdmr7726179wro.324.1668435038966;
        Mon, 14 Nov 2022 06:10:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668435038; cv=none;
        d=google.com; s=arc-20160816;
        b=obi2fivc7CN5cUBNmkMoB0lLkGv2d/pxkorzha5pt8AxaIEYg6pF3zdQ69jryVlvVm
         8JTyHKa/i6EZxj3UM5SfJyA2XvW8iraKdCD57CLxk8oLO7mv7+mKCczuCds3WeG3yT57
         7nA/2Dc7HcweBb2Dm4SzPtU1tKFBm1VHi4pW/F2xMUqraN/ss24YEmYR2w27JbHZC2Jo
         ZMd9fsqGbw38f8GptGduv/SHzhI/lZ3HJVcotMnAroxIuh8lzMvhpN3+DxaUW/FdIUOk
         3UOnLhAVzBqkCn8UR4GlaXDvzdvuYQf71VImh8lSlDfVVAi0hYFByXgsGnX+VNGKZn83
         QgQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ADSq2f7jGhQ/42j/nm6BykZfXnm5jbp6+XiZg6V4aNs=;
        b=lE3c5+jxqkhIAWJH/hKOlinymibCkqehw4MjF4+SQHp7yDu+QMJ4MNOFs82cLolzjt
         RNnCPMrOa+Ic9iXVdKjuN3QlhjKSyCp5tgOuXRYRhqIlpGlGOZ0lnKRESOntd5r192NS
         XNSjsJMA61QrEdhSqg0L6RvlH0WLxMnYaekunw2A2TmnRGQcW9XtTNefEHyV9ztytsNg
         sDePlCkI7B+F4jGSpxmQWurYt3GrG/SE6V0t1Gc9GNbfz9VIVcvG7RdrLKP5XKl2cDVo
         FFsiC/afHPagOVaz4ClITatbv6+pdtyeOR/WNiBbegodhIO9UjQ7CxkTpcWYFAOoG06Y
         zj8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=bSeOmRV8;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id p190-20020a1c29c7000000b003cfbf566cb8si635496wmp.2.2022.11.14.06.10.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 06:10:38 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id b9so13342792ljr.5
        for <kasan-dev@googlegroups.com>; Mon, 14 Nov 2022 06:10:38 -0800 (PST)
X-Received: by 2002:a05:651c:491:b0:277:38d8:1e28 with SMTP id s17-20020a05651c049100b0027738d81e28mr4570723ljc.46.1668435038555;
        Mon, 14 Nov 2022 06:10:38 -0800 (PST)
Received: from ?IPV6:2a02:6b8:0:107:3e85:844d:5b1d:60a? ([2a02:6b8:0:107:3e85:844d:5b1d:60a])
        by smtp.gmail.com with ESMTPSA id c2-20020a056512074200b004979e1ff641sm1824669lfs.115.2022.11.14.06.10.37
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 06:10:38 -0800 (PST)
Message-ID: <288b8f73-ee5d-76f2-18e4-f8e41ca98df5@gmail.com>
Date: Mon, 14 Nov 2022 17:10:38 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.2
Subject: Re: [PATCH v2 3/5] x86/kasan: Rename local CPU_ENTRY_AREA variables
 to shorten names
Content-Language: en-US
To: Sean Christopherson <seanjc@google.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski
 <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, x86@kernel.org
Cc: "H. Peter Anvin" <hpa@zytor.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com,
 syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
References: <20221110203504.1985010-1-seanjc@google.com>
 <20221110203504.1985010-4-seanjc@google.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20221110203504.1985010-4-seanjc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=bSeOmRV8;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22f
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



On 11/10/22 23:35, Sean Christopherson wrote:
> Rename the CPU entry area variables in kasan_init() to shorten their
> names, a future fix will reference the beginning of the per-CPU portion
> of the CPU entry area, and shadow_cpu_entry_per_cpu_begin is a bit much.
> 
> No functional change intended.
> 
> Signed-off-by: Sean Christopherson <seanjc@google.com>
> ---
>  arch/x86/mm/kasan_init_64.c | 22 +++++++++++-----------
>  1 file changed, 11 insertions(+), 11 deletions(-)
> 

Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/288b8f73-ee5d-76f2-18e4-f8e41ca98df5%40gmail.com.
