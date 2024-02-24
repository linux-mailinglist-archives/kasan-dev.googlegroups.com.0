Return-Path: <kasan-dev+bncBCKLZ4GJSELRBTHP42XAMGQEPSG2N3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CB008623F2
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 10:33:02 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-33d36736772sf850081f8f.0
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 01:33:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708767182; cv=pass;
        d=google.com; s=arc-20160816;
        b=sG2Brr8SHJrbMw8C/2A+SlTwClfuwYLtAuZMVAeWq9CKQWCe/mJp87VhPsFf7QSb8x
         8x6k9lhZxMhtLZdr31xOr56G7rg4CLs4ofTqq1yfzjDwMLjRBtHHKTe4f8R2s1rFOV8o
         Lz4wuqQJHU6tW8zrygjKgkFCYvNngB7sThaB3a0mFWGUXVShyWPLqXqGf/XHdsYLpdh5
         n5r16n08P9uOJO4oM8vx1ejpO/tSeRs+gfxK+dzIjgoWEWzQGbbWLJK55QcIpyjSf4GM
         gZ4qnOEd8742hUDgpU2hUFSZSKzt5uIvrlKI4J4QBYB0pD59Yr+bMg/gC75lAztnox6A
         G2hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender
         :dkim-signature;
        bh=s4cec7+KIHHMBozbnyTcadxWHORZw5c1ujpL75Cn8kw=;
        fh=oJc16uisZ3MViv+VocP9JaHiNaKZo6XSdjNlvMcj/Lo=;
        b=D0/GW3WgSmq/ycHz+67BByu3xcMnnyfytO4yZxhMOURRYTVeJ6DJRKaAnz0K2R5mem
         TckG7HFXYRK9xmvxG7adYMKRPl//vnwNLOyvr2S64AiW4c5OEfyxjffqwXPIXRCDSCQS
         mO/+tj0qGw6xWOdD/mIM3DrV4mZfb7gfAV5MZlGJnJGfRw+/g19MIGdnBg6zI35/Ig3x
         ffiqD6XQLF717+UFXpR/Pqio6m6BDhCscJOuMdOTL07nOP6bmeaIF7m7eCBG7HQ291wG
         G15LfCwPaOWihUwmS8cXAuHaY6NXVKHLFscdmncSLpi1Csh8xIVjr8dnGiPSYfEvPoe7
         8tcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="U/5SIqsF";
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708767182; x=1709371982; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=s4cec7+KIHHMBozbnyTcadxWHORZw5c1ujpL75Cn8kw=;
        b=LWPEIlmpXtWP/mfhSF+83211KQQH/Wk8s7fE9TnyqiQ1mNP7tlMblbCpvXYpn/Ph57
         Nmc6UkHWEFNXwooYo0wLxALHcpu6JIBve7Z1SeO3Hp8wCR/GeWxSJGRkp8cd9SA+OeUA
         PJ+ecmKwsnsWkLDUZm4LlnnI8eQ8OMppBPx+ShDTYQhTfYbkTS2vBDAxhx67js3Bemkn
         I+CF+J4yRqSVzY0UkrCkTcrxhFfV59S+2QDfxTv3DaUnToozal2fIlhJUSpX1m4cG45z
         tPSmyhi8osdguOeJ4xcl+CugDiVz/Yzih70EChAcmn4vxCFWFQv6O6fhyIDx4zfCnc9L
         MOTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708767182; x=1709371982;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=s4cec7+KIHHMBozbnyTcadxWHORZw5c1ujpL75Cn8kw=;
        b=MqTuLo6dgCACCHpKKyfSb6BJqZQE72LqPVoO1BB16ohtDmYo5rWH/vUJB9dggURAuz
         6sCZnWhvh/2QjOvY3O1YIfAnUieCEugMLiEcFczvIvfEfWaxXHdu9zztM4YNy3W5SKzN
         hA7rVwLowJleBXMoc18u9y8jF7o8L2USxRdspIUfCzYBEDVMVr++vzXYmYnKOI07ZPBP
         FDOOeyq3TlrawDq+oQcdQi5KaS+vf54b9nXPdFvmHC7CVVfWPEWDRMdmS9R5X3CvRDgP
         FSxXt1H8d/Ka3sE0cmEvBOkBVHkqCCwBsp70Amzbf62cAphJ1MdNFE6hnIpWs76z8oLP
         IOEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsp3y9U5xJ2dHUx96NL+hTpV0eM5JCpwgKOkrikmqg/AKWeb/OgmP8LlhWZzdF8+Z7Z8hOaLCyonWZxEdL50zNrjQE5D0P7A==
X-Gm-Message-State: AOJu0Yx0AfHMbh4E3os/NtZicVLuUNZhjwxh1m4q0C4Ia3uKGrd1vlqD
	QetxybDB46jPV2lOUBiOj3xfs3MSVlNyZcCxYLh85CjyluHGzJl4
X-Google-Smtp-Source: AGHT+IH2iBwI9QhGvyu0J7Igl/rUe3GJW45v00bbrambrbz5BQbQb2QbY5PX3W2uCXjPauiaFtS2dA==
X-Received: by 2002:a05:600c:4591:b0:412:9523:87a6 with SMTP id r17-20020a05600c459100b00412952387a6mr1280963wmo.36.1708767180896;
        Sat, 24 Feb 2024 01:33:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e11:b0:412:97d7:5822 with SMTP id
 ay17-20020a05600c1e1100b0041297d75822ls394160wmb.1.-pod-prod-03-eu; Sat, 24
 Feb 2024 01:32:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWFHo7dJg/B4WsrXLHHDOlKlODRE5QkK2Dz3h7ATWONwcLCOzZkt5zUDjZdRCHNFns+VPD6SN88O9ncs+myszRo8NDPdR91o5aCyg==
X-Received: by 2002:adf:fc50:0:b0:33d:c33e:fbce with SMTP id e16-20020adffc50000000b0033dc33efbcemr374827wrs.29.1708767179091;
        Sat, 24 Feb 2024 01:32:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708767179; cv=none;
        d=google.com; s=arc-20160816;
        b=d/q7rm1VrQtLWACe0EFxkui9gsJFD59DWthYaHHl0/nQwxkzxWkcGJmDCNPzPtigG6
         dh0qr6+/VV+0vbIK+hf2+q6FUROIahFyNtjQLXj9RSbqdFz5DFDLlGq2JH7JtleeZjlZ
         OmIOXCAuRtvDqiUKUqroNno76nQIxz6VcU0tKGoZSkGrcNQlS2Ygr5CuTBpZVteQ51Cz
         8iduEd8vsYDSWYkj8x0DywHGSaEUdaU30m41eWTFISQ31Xy8uEQwCMz19oglrw5DsB2Z
         t18+zJvnY6z1nkpm5fxoZs1AzFMTiwMdsj9R8hXBJpXJh0Qf/lo8I3qCHd9nDpS7C2u4
         GxXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:dkim-signature
         :message-id;
        bh=w5CbQ+eZHnRkInbsJ83G0MenQ1/0DqwIekM9Cx5ZW3Q=;
        fh=5+7/iP/2zpuwgTD/2mJdFxlM7TX8/1LSr7e8kRbg4Ik=;
        b=0uiBEfrDzeEyQfVfjMSOQ9Kzwz2HZ/9TFmTx5+Y5w15iLaVH1XSxsfug94keufWsiv
         T6IQDXR9dFLWvZVGYVPGv9H/4yb/eH7WvuaLGPptRS4PlJzmzM3ax2BtYhoxV0YLqTXP
         VmihsviBlfae5ehaLUM2fSKaJxZrF9MDmW+KUU0PgNXW872eZzt+dV7+y1YCISZ+POXh
         Ns1eM+BBGEr6hfJbX7gL65BrDpQvBeO7iY0fY7WW4tZvXxSCiVfBkTI5flpekO8HzDhU
         pPz3n6TBKmJsz+DAv1lsJ72HqHiC6UwfwNKKjn21ZGGAGp/FyI5OtuzY04JF4DV1kQI9
         X8Lg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="U/5SIqsF";
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta0.migadu.com (out-171.mta0.migadu.com. [2001:41d0:1004:224b::ab])
        by gmr-mx.google.com with ESMTPS id e9-20020a5d6d09000000b0033d67b701c9si46355wrq.8.2024.02.24.01.32.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 Feb 2024 01:32:59 -0800 (PST)
Received-SPF: pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) client-ip=2001:41d0:1004:224b::ab;
Message-ID: <e63166ef-4aff-485d-8c32-4e4ad3384563@linux.dev>
Date: Sat, 24 Feb 2024 17:32:20 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
Content-Language: en-US
To: Vlastimil Babka <vbabka@suse.cz>,
 "Song, Xiongwei" <Xiongwei.Song@windriver.com>,
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Zheng Yejian <zhengyejian1@huawei.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 Steven Rostedt <rostedt@goodmis.org>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-1-e657e373944a@suse.cz>
 <ZdZBN_K8yJTVIbtC@P9FQF9L96D.corp.robot.car>
 <CO1PR11MB51854DA6F03753F12A540293EC562@CO1PR11MB5185.namprd11.prod.outlook.com>
 <7e27b853-e10f-4034-bc81-2d5e5a03361a@linux.dev>
 <beb2b051-af97-4a6a-864c-e2c03cd8f624@suse.cz>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Chengming Zhou <chengming.zhou@linux.dev>
In-Reply-To: <beb2b051-af97-4a6a-864c-e2c03cd8f624@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: chengming.zhou@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="U/5SIqsF";       spf=pass
 (google.com: domain of chengming.zhou@linux.dev designates
 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On 2024/2/24 00:41, Vlastimil Babka wrote:
> On 2/22/24 03:32, Chengming Zhou wrote:
>> On 2024/2/22 09:10, Song, Xiongwei wrote:
>>> Hi Vlastimil,
>>>
>>>> On Tue, Feb 20, 2024 at 05:58:25PM +0100, Vlastimil Babka wrote:
>>>> 0;95;0c> The SLAB_MEM_SPREAD flag used to be implemented in SLAB, which was
>>>>> removed.  SLUB instead relies on the page allocator's NUMA policies.
>>>>> Change the flag's value to 0 to free up the value it had, and mark it
>>>>> for full removal once all users are gone.
>>>>>
>>>>> Reported-by: Steven Rostedt <rostedt@goodmis.org>
>>>>> Closes: https://lore.kernel.org/all/20240131172027.10f64405@gandalf.local.home/
>>>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>>>>
>>>> Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>
>>>>
>>>> Do you plan to follow up with a patch series removing all usages?
>>>
>>> If you are not available with it, I can do.
>>
>> Actually, I have done it yesterday. Sorry, I just forgot this task. :)
>>
>> I plan to send out it after this series merged in the slab branch. And
>> I'm wondering is it better to put all diffs in one huge patch or split
>> every diff to each patch?
> 
> I'd suggest you do a patch per subsystem (mostly different filesystems) and
> send them out to respective maintainers to pick in their trees. I've talked
> to David from btrfs and he suggested this way.

Ok, will send out individually.

> 
> You don't need to wait for this series to be merged. The flag is already a
> no-op as of 6.8-rc1. Also I'd suggest sending the patches individually. In a
> series they wouldn't depend on each other anyway, and you would either have
> to Cc maintainers separately per patch of the series, or everyone on
> everything, and there would always be somebody who would prefer the other
> way that you pick.

Right, thanks for your instructions!

> 
>> Thanks!
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e63166ef-4aff-485d-8c32-4e4ad3384563%40linux.dev.
