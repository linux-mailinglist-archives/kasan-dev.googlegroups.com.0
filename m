Return-Path: <kasan-dev+bncBCSL7B6LWYHBB54ZZGNQMGQE6KCTLXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id AAAAE62821E
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 15:13:12 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id l7-20020a19c207000000b004a471b5cbabsf3267729lfc.18
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 06:13:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668435192; cv=pass;
        d=google.com; s=arc-20160816;
        b=PW2zvYuemfD14g3ayd0r3NIl1BEkorlG4q+iI9d6tl2rWYS0sijEXjFO3pUFNNiv+N
         yCVD7QNBjWbVmnobedp2A/Lps8aDeZ0TkD5HHgFFupFbRA7THTKpUvO4+R+MK6VZmfhW
         dSN3EZNaFh6TfMo0OW8AdaVH0PfjVbptPa0X2NmBmVh9qf7ABeV5m0/qM9UEB9u46Rjn
         TATv92SaG3ITEjYo9qZVGqCSfbSriqf3dnKrmRfvoGnFZv3yQP4JhT9G+4KIrIU1CQmk
         d4Z83RDs+TCYKWE3s00mbkyOMC483b4rselKsQP+1qi1GrL/ym6PmhpnffkVwsKd2yOh
         kStw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=Nc2yBLbDuMCgQ+e8UQvjVLf9dFkqc8GMBLUs4Z5H/ko=;
        b=I3G42hmfBZ86Z6LLpwucxxgPzXXNWmk1TNqKIAA5XTodcvNP/vFwOSRwtpcVg7fQPA
         imsFKbdB6j8rR2UxhipgQ/OKqxNBuHbTdr942+m1IoyhFex271CDIAFAz1eUb+lvGI3v
         BvEOFSVgCDkZ5HtyHhniL4lsJt7XBdVXDpL9OT4i1QyH40nLYPpFHf9SfkL1OBlbP+GS
         QBy4WD5MwJjgFtrkLdhtDdTeJV8dePUndGQm2DX+PLlycdJ3IayChdEXLl8TWa8UjW1d
         +JKkj9RZnOyZGq47iVjAAsi398RLYhU2l56Axc1gacYkQ1mhK78CmWR+B6PkU1YETjNB
         4hPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=PnNB2vRQ;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Nc2yBLbDuMCgQ+e8UQvjVLf9dFkqc8GMBLUs4Z5H/ko=;
        b=nF0KX07MMZ9KF0qyoZs5Abt2KoU7zHlxk8uVEN7++WQPKUig1oYUsC2+7cUQAovBEr
         j/Sj2pVCLXkdBq3BkAaaIbedS/lzGI/76JiyRe1yYJRq1TA3XGhR9gVjQmzuFdbQ+53Z
         Dy5tFU/wyb5sjnvEIysddQjL+WmnILlpjuQjru8ut3gA4nbVv99NswzVla/4Q/Ue1F9F
         ODko6WkDojYd+HuuAzUrvlNPpVsy+x+Jo/YZNqF3lgHuxR84cENCmrcIoFsXjX4fxMN2
         PW6khiaz6phU9JDW1KTF2CwgoREiZNpmkqtu0XG+QnZvOV+oozW1MTCmsJGAiYh2uPri
         Rctg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Nc2yBLbDuMCgQ+e8UQvjVLf9dFkqc8GMBLUs4Z5H/ko=;
        b=XuLkiuzAJQ/sR4/tXb1a+rwAQN8NfcjDBeVHjr5gell6pREMHqcU3wy8Mmm/gT8JwK
         jrrb1bL5r7xLe8mLjbZ8Ks21lno/5jMPsDnY/cLfIvqQ00OIKoyiB+q404Cp0QGDkVdU
         rppJUFLrr0LT4vRycqqI/O2R4eQAzs3+wJk2P+5lOoA+yu34zQ+MgzadFzxKkp9XIzMT
         uAbCIIJg827wmK/He6kixCLyiWb5FA0cfG3EU/ozAxtkWCAQvey8DiOQCwashP+IDcYe
         DGnqarrcq61BU9CEG+5qNSyxkrL/eIpyVa+XGx6q8ROxWRpXagSuXZeFGe+/blRB4k2H
         C8LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Nc2yBLbDuMCgQ+e8UQvjVLf9dFkqc8GMBLUs4Z5H/ko=;
        b=6P7xluEhJws+EBQO/YCRzIdc/WYmc1Ka3n3o7h00lgUImkJJQFbn846tV9OI43ksXJ
         YJCnWAsMINssGRIcF2/ozP5CrbK9pQCKuhIw7XtJMsrJhvlU6c6Qr+Tx9tuKzbCygHdY
         C4JwdqIQ+y0Fnml0KqDRiz61aMj3sfZKfdZ64Ca+TlcNmmepSXKezpkG61W3HdCgvybZ
         XeBqnjgLFzo6/92A/cqIukm8jXrRY611YgypjMGVQi4mzOAx6rY3iplCEZhJPZugnh9O
         MZ+GKikeySKiZ7I7VBLGNPP08YH3uEbfQZ+dcBNZdwPfgROPHxFnvtEhbBkj307Smd9u
         kvXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmpNGrWCGvPjxwVsnja4uXdJKtsjqaKoDxAmgF9G0ykOP0SSTGU
	dXzuHsUYUkztIFeiW9w5bvA=
X-Google-Smtp-Source: AA0mqf7vVRmfI/hqwJO9YDemT+b9elU6P2Oa6C5vxPAfTiZu59wwPZv7On4+MZyONjwSAmXEAXNLmw==
X-Received: by 2002:a2e:9cd0:0:b0:278:f53c:380d with SMTP id g16-20020a2e9cd0000000b00278f53c380dmr3081170ljj.1.1668435191940;
        Mon, 14 Nov 2022 06:13:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a4ca:0:b0:26f:b780:6802 with SMTP id p10-20020a2ea4ca000000b0026fb7806802ls1752373ljm.0.-pod-prod-gmail;
 Mon, 14 Nov 2022 06:13:10 -0800 (PST)
X-Received: by 2002:a05:651c:905:b0:277:71e4:20a3 with SMTP id e5-20020a05651c090500b0027771e420a3mr4065598ljq.332.1668435190587;
        Mon, 14 Nov 2022 06:13:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668435190; cv=none;
        d=google.com; s=arc-20160816;
        b=Oo4KAbUiAopjVsja6Lvta86vUbiNGzAa5YB5vFa/JyM/C8MbOWrp5WRdgOycge3AB4
         UtPPglExjo9OBBbNA31XfYAOyvFjuqppLLLL4M0XtJ7sWxzLbZmLOFmiCcX+A0Dwvife
         +/tqVr0pPrfZEdYzVIBN2sWoBC1EzMI6WgbbJ+rhTnyy+nXY/K82BHWApup1XiNSp8wU
         yYngN3P/kKbGq568gUg/0FcxoflzHCk61GEWsl0l/U6aptIi9ECahmuRtW8YGYHC6y1z
         PPl5yHPcyUcHzkWG6tBoAB9rGS1+ln7q1j6eNS2QxD+cv0TBP1k8pOIiNtD/hBIUiZ0m
         4ySw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=jUVeOBnyNFqKWpHwwbHrMkJUKp2z+BJ7NRt5LPL2W8s=;
        b=Sb0XcX3vmUdaq7c6iUZ+yTie2tdKv/cW1wm1bHZoYjKwQh7xrNVysCCKBjUn6WAPkA
         rdrnK77lwaHtxfnP5EHQwgHzOcn3f8OXAW5znRnPwioZbrfNHJxv8RS/IIeNWzzdUkeD
         NSwC+umHMAtbOC2WQ1X6C92SoaxRUa3bQZB/5gSGFmeJuMzWhr8mdVYU76P2c7HRTSHP
         vY8vykBUAkhW+UtzQ70HOY4ryBfN4yvNiPgq7oGaRIcLwxtCvRUsnAJ/Ruu9dNPcOVO+
         FbIsqDRjaCaRp5CE5UX9gG1wDdqmkqq4KtL72wpN/9BNPl1uxhDSvXZ/WGHRzjfVfRQU
         VFtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=PnNB2vRQ;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id z10-20020a056512370a00b0048b224551b6si273848lfr.12.2022.11.14.06.13.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 06:13:10 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id d6so19443656lfs.10
        for <kasan-dev@googlegroups.com>; Mon, 14 Nov 2022 06:13:10 -0800 (PST)
X-Received: by 2002:ac2:4d2c:0:b0:4b1:2447:6971 with SMTP id h12-20020ac24d2c000000b004b124476971mr4039755lfk.83.1668435190240;
        Mon, 14 Nov 2022 06:13:10 -0800 (PST)
Received: from ?IPV6:2a02:6b8:0:107:3e85:844d:5b1d:60a? ([2a02:6b8:0:107:3e85:844d:5b1d:60a])
        by smtp.gmail.com with ESMTPSA id k2-20020ac257c2000000b004b4930d53b5sm1271041lfo.134.2022.11.14.06.13.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 06:13:09 -0800 (PST)
Message-ID: <a501e1e7-f6ec-6b8b-e7de-cf79d7646de6@gmail.com>
Date: Mon, 14 Nov 2022 17:13:10 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.2
Subject: Re: [PATCH v2 4/5] x86/kasan: Add helpers to align shadow addresses
 up and down
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
 <20221110203504.1985010-5-seanjc@google.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20221110203504.1985010-5-seanjc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=PnNB2vRQ;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::130
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
> Add helpers to dedup code for aligning shadow address up/down to page
> boundaries when translating an address to its shadow.
> 
> No functional change intended.
> 
> Signed-off-by: Sean Christopherson <seanjc@google.com>
> ---
>  arch/x86/mm/kasan_init_64.c | 40 ++++++++++++++++++++-----------------
>  1 file changed, 22 insertions(+), 18 deletions(-)
> 


Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a501e1e7-f6ec-6b8b-e7de-cf79d7646de6%40gmail.com.
