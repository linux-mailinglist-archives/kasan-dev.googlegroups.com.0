Return-Path: <kasan-dev+bncBDIK727MYIIBBH4OTSPAMGQESMI2VZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C8BCD66E7BD
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 21:37:52 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id y8-20020a2e9d48000000b0027f1feabc75sf8562202ljj.16
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 12:37:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673987872; cv=pass;
        d=google.com; s=arc-20160816;
        b=zexCdFpcHL1vTtDCHfoQOcjCogU1ZIT9FMjCIz0a8HIUQGA7reSwKF6c73HxRjOyA1
         YN6BlSg+UwM1vHjiUxriCAX93MVHPf4YGwNccCFJ/acvtIlwWoW9YcFfzfEdur31estN
         sZ3Po34yoRSYwx3G5uxi2hK0wF1O8A9Pvj/UzZLZhOv+DgmCTHnpmg2/An348/Qt8NdA
         PNhmVW7rSYjoRzFDgnJp/6UKiqrANV0vs+Sl+qQFtL2JWUFYLWqYYQDBpHdhgK8jjfLV
         XhijdUYDDxBlFBt6/O1GFZ4ezKV1n09xCtvEHQxy3wMtUn0p8ZhUCyBewmwN5hn72jwt
         +e3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=9lL/eve6B8uVmGEbT8ZDKFFqTFl+ky94qTWdyiilnCA=;
        b=cR/CdOhLNM0aM4F2vuvgKmLedsk63u4wCZpxU4teoOAWjHYW8z3ibNe1m+LmBlvh06
         amqCp4BQ2Xfx87Kf7ADa3twaz/kRFT3QstM3Ww565f0oYaK/V22yPzWBDy+qUy/1rqo8
         XcfD6kVEwqEffS6B72iUvVYKHf0seomnMcfU1n64U8m3lbSKSpYM6CtXFGDUK+QuorKu
         CbzBSft8t8qcbI1E40kUWlVPbM7u0YcuLjp4JkAERV/yyXvquCCfGMGnZIzfNHrGdFDT
         DCUEp+OqoK+xES4/bkSQK6GOfe2W4EfSgrzJoy+L0qppX63Nig/YwiXXnt9cu+12Rxi5
         GuMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9lL/eve6B8uVmGEbT8ZDKFFqTFl+ky94qTWdyiilnCA=;
        b=LElVcqoZqXCCdV5mOcFd/1jXtWE9VkjkRB68zNdifRq+CuRdYh+xjjFI1iqOHkH28E
         KLQTWA+30QYJ8yHPdYf8/JRKM2VFy2wNCNeHNIY2HotKxbKbq9gdRiMrbaA/Yj/F/DBX
         oJ01nbivY75+YH0E9KGh8vnLKgdFqebOmxAx/TFf5Rtv8rrjszxl2jDSNLka3qkZLTOV
         xWF6AFYPe/PHMmbHR0QfxcbtaMcygos6pCYWJHwKFCd7GRMKRXzc36Bewm6G3k0L/GQl
         jlmsKmIfTV87GByPvJHKNpH93m7vh7ywg80nzBuuoe91nrOvN4OgNbRi6GDUiBfvVHJP
         yARQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9lL/eve6B8uVmGEbT8ZDKFFqTFl+ky94qTWdyiilnCA=;
        b=eBEwnsIStO+JrZqeApOeNsGGnpx72CqRN4Reh18jdCZm9KLDm0+SZ4/WVaKNuiGg+v
         sKe1uJPoUV7UZX5a4Ev3/kM5xYCQntMGztPOkjW89+oOeTBjsaEmYrwT4ec6o0vCFIWV
         rFB+XLFAfBjluXmFzld6tBMsM7tlbkb+FM3ha1gEIqB/6CbQ/CajBGUlqPhs4eifcTPm
         3tN+La3oTgKCfd5XkEjIFWHaUXZGvouWstRilnoZXwlgEmNzlY2c/c/fLs2VjNe6i/sp
         wogwnhrlTjxMO2xFF61Es0Wqqi7jj2FRAKfSpFQ1PaAe7+s0ATbSfMGCkI58NE/rhmd3
         6wOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kr85M3W+FAw8j5NrfwyJ7OGF4OQujdRGsYF95E3fyQC+g3d4Arv
	FC+jqH77Eb5RmX0eFnLlJxY=
X-Google-Smtp-Source: AMrXdXu261VQEXOohuboyyza/kSGVNMTwL9pgr0nIWTHazXmV3CSRaHZMcIyu7rO0h0OtVjGEE5mNg==
X-Received: by 2002:a2e:91d1:0:b0:27f:df4a:391d with SMTP id u17-20020a2e91d1000000b0027fdf4a391dmr298353ljg.387.1673987872031;
        Tue, 17 Jan 2023 12:37:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls3947570lfr.3.-pod-prod-gmail; Tue, 17
 Jan 2023 12:37:50 -0800 (PST)
X-Received: by 2002:ac2:59d0:0:b0:4c0:2ddc:4559 with SMTP id x16-20020ac259d0000000b004c02ddc4559mr1232165lfn.69.1673987870780;
        Tue, 17 Jan 2023 12:37:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673987870; cv=none;
        d=google.com; s=arc-20160816;
        b=g0VPrgH0HmT8MR9kz/xz8CvisMjAU4XMQkZ+V6d8yRmgNTnhKpASEv9Zhfku9NL1Vk
         p9aFLLNR6glUXTlZAWJwe/jdUORLzSHZSCLHTSwinPY44C3BJkcNCZwpz5TZJURt03gv
         nBKbmNpH6JNSC4nrwvRBLNXbhcUCFkmz+Ea+7KbRxB+ui0L3fxVFy3ew3gG2itLlaDDC
         HKzglrHxbA/Cn9ZCs457nNZkGN5M+7Pa7a0Csv54I0YDcnyAtKIPQc18eb23j+7fCQgG
         wPDajL+YAl96iKrli5GrE1IRMNflW+OLGkJNKQDBEYg9RzD5yGfoaejh4youg51CfeVU
         Mptg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=S/2oDG1JZ9lppEoafzSChv0UkFMoB6YNk6dLEMlRUgM=;
        b=pscEBmnPdMNL72pR7KJgBqfFuVMDEb10dMtcrOKkFqkUMm6PKdEw/On5CntzXxYssP
         8vcZK17mZujGt7a1M4IWEzHHVPH1686kmVakS7rLaVAVK6O3T+XpoUL556fHKWAzKNAL
         AXZOpdl8oT2jV+sZBx4ZRoFQ2fM23EbZ3lleXa7w0eJERY8jmPJLioK3dcip1noC+DbY
         B0wrR/MfrlhyFOQXyPXQty0eRxXXeU5/ZKbex0s8i9PEkW7RJR5RA6EV585s3HU4Ieq2
         5bNhxriDWtUT7/wgCtJae2XnuOPnxQnTAFbvMhMgy6SMImTc0qRHFAaUqVSUK9HnO0Eq
         C6bA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
Received: from outpost1.zedat.fu-berlin.de (outpost1.zedat.fu-berlin.de. [130.133.4.66])
        by gmr-mx.google.com with ESMTPS id u5-20020a05651220c500b00492ce810d43si1482261lfr.10.2023.01.17.12.37.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Jan 2023 12:37:50 -0800 (PST)
Received-SPF: pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) client-ip=130.133.4.66;
Received: from inpost2.zedat.fu-berlin.de ([130.133.4.69])
          by outpost.zedat.fu-berlin.de (Exim 4.95)
          with esmtps (TLS1.3)
          tls TLS_AES_256_GCM_SHA384
          (envelope-from <glaubitz@zedat.fu-berlin.de>)
          id 1pHsi7-002brB-VR; Tue, 17 Jan 2023 21:37:35 +0100
Received: from p57bd9464.dip0.t-ipconnect.de ([87.189.148.100] helo=[192.168.178.81])
          by inpost2.zedat.fu-berlin.de (Exim 4.95)
          with esmtpsa (TLS1.3)
          tls TLS_AES_128_GCM_SHA256
          (envelope-from <glaubitz@physik.fu-berlin.de>)
          id 1pHsi7-003MvY-Or; Tue, 17 Jan 2023 21:37:35 +0100
Message-ID: <0d238f02-4d78-6f14-1b1b-f53f0317a910@physik.fu-berlin.de>
Date: Tue, 17 Jan 2023 21:37:35 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: Calculating array sizes in C - was: Re: Build
 regressions/improvements in v6.2-rc1
Content-Language: en-US
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: linux-kernel@vger.kernel.org, amd-gfx@lists.freedesktop.org,
 linux-arm-kernel@lists.infradead.org, linux-media@vger.kernel.org,
 linux-wireless@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-sh@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net,
 linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 linux-xtensa@linux-xtensa.org,
 Michael Karcher <kernel@mkarcher.dialup.fu-berlin.de>,
 Arnd Bergmann <arnd@arndb.de>
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org>
 <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de>
 <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
 <3800eaa8-a4da-b2f0-da31-6627176cb92e@physik.fu-berlin.de>
 <CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j=iw@mail.gmail.com>
 <429140e0-72fe-c91c-53bc-124d33ab5ffa@physik.fu-berlin.de>
 <CAMuHMdWpHSsAB3WosyCVgS6+t4pU35Xfj3tjmdCDoyS2QkS7iw@mail.gmail.com>
From: John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
In-Reply-To: <CAMuHMdWpHSsAB3WosyCVgS6+t4pU35Xfj3tjmdCDoyS2QkS7iw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: 87.189.148.100
X-Original-Sender: glaubitz@physik.fu-berlin.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as
 permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
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

Hi!

On 1/17/23 21:05, Geert Uytterhoeven wrote:
>> Isn't this supposed to be caught by this check:
>>
>>          a, __same_type(a, NULL)
>>
>> ?
> 
> Yeah, but gcc thinks it is smarter than us...
> Probably it drops the test, assuming UB cannot happen.

Hmm, sounds like a GGC bug to me then. Not sure how to fix this then.

Adrian

-- 
  .''`.  John Paul Adrian Glaubitz
: :' :  Debian Developer
`. `'   Physicist
   `-    GPG: 62FF 8A75 84E0 2956 9546  0006 7426 3B37 F5B5 F913

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0d238f02-4d78-6f14-1b1b-f53f0317a910%40physik.fu-berlin.de.
