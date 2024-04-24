Return-Path: <kasan-dev+bncBDNYNPOAQ4GBBR7MUWYQMGQEEXOXNXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E2A1A8B1519
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 23:14:48 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-36c0f8200ffsf3491405ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 14:14:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713993287; cv=pass;
        d=google.com; s=arc-20160816;
        b=EL5ttNI7wxY1WVB4u24GfzDDezwafesfegBFClaYlCkINt8DnU7STKLIIK//+uvVqn
         elmVuvNQt41l57oWci2L/diGaehPq5tC8ImR9MIycbbJ+fbkI8A2ubu0+Ad5U8ldr1Ie
         9WsaSxolznWiphxhZlktoI2FHI7qcJxrHhAAkAzdnWKq0qWLUUnKq8lCig/d5N+k4q9g
         j7jHNupv0GHjcGfIcdjUQN/4bOFfozOkJN7uF0V7aV30eTmL89+JL+Q7efUVbaAJLRfE
         8fp4+CgPThUxu1zxkg5fN6xfRBoKXqIXB6DPHfcl7/oEsYOSn6ik6Ag5HESBxTYZTQe4
         +9uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Yxv1CT/tIsVJdl18nZ+/2A+2UoCQPoCkIg2SwK2hz0U=;
        fh=T9MTMIOXxuz1SrKh2wG874Cn5uXHiUskKisVzfzQOqw=;
        b=Eik8gOY73yVMhe2WpJGLUnxFC3GiYfKfAGtQLRvOIDd9dVDWowpb1UtagqMAHdVBTV
         hsUCFTFO27pv8YhNC4x/XJKNT2TNy+VOMac1UcccoE4Um/pEAZQTBbpfT0YgW6d/U7m1
         pwezEPP2oPUgVKCvS35WIk7cKSramnWAmQCZRNFWBp2uGKk61pu/42kqSN5suIDgtq6m
         5YxREXXJMzRb+ZRMddz2KBZ98kHbdrYg1O+PoZMeCMhANN/jfiRYmZiCWos0ZlLveQyQ
         8sTGQRrm+ECfn1uevObmCDNPUZnMxJZ3ypNGehbB/p8rYSWrGOTTQTe+dxg4G35zdpyF
         GUoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@embeddedor.com header.s=default header.b=GB1Wtd+S;
       spf=pass (google.com: domain of gustavo@embeddedor.com designates 44.202.169.37 as permitted sender) smtp.mailfrom=gustavo@embeddedor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713993287; x=1714598087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Yxv1CT/tIsVJdl18nZ+/2A+2UoCQPoCkIg2SwK2hz0U=;
        b=TX8rXkT84Tg+mbEkVwJyOURyiqwZzp4T4d+bu7JOj7jOpuVdqkdZIOLivz8vnd8m48
         c3Vs8lR3YPFNBaPEAcA9LD5BtvHb+WItJv74vClvD7mb0LrMi0ra2ys23XGSgdgUaI6+
         +NQ+bLc0RVsXaYMNk0M/IJpId39mxQwAd+qeiqjkNBi+Tq1yjesSElrgRzWzN9L0f1zo
         ZdyEN1OBRM2FFBPQMDPfhGx0KnI3nUy+KVHKenlUyn8uZZsc8EpuyTGarqnQSlMJhpc/
         BHpC/7MicohxOwdiFiw7cO4Jdx6h/C8zJxm/8FmUemTl4Zl3izjyre5T5TbM2c447Nao
         GdCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713993287; x=1714598087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Yxv1CT/tIsVJdl18nZ+/2A+2UoCQPoCkIg2SwK2hz0U=;
        b=H9L7PWJ+2eOgwsV3eBBAvNfTFhKQVCNi68QMa7fKoIfR1TeJunqu0XWDZPHpKqSTy/
         FwM1JXMTAmbxo/BPo+dwoQl4ei2BZbSiH3asGc/u8pIj3ZU2ftEcZJ5XxfK9rFDf4+9q
         mj1KLd9+K3gZYSCbB5aFpUGfSvi47U5vfm0zFzD5s36HLwwXLIM4KkxSkXb2SXPMANk8
         kR/L/aVmnVvQpMgVjbx4OZZc8uWl3CBxkf3CqQKqYGlAiKm9APCVzrDLWb/Y7N7wNp2v
         wCxf0Cpq6yiwc5dgU06YbKx9YNTOgi7InYkdxSUKbufA7l3+1PQkUf1KNRDk5QecoKa1
         HSYQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXXWwlU6nH4bVCt8nYObQFsQbmXYbvLWS3CaPNRJsA16B/ltShfX75QDVyAaN7gIdtCrpCiblb5Qe30l7Op0vN2S2XEO2P2Iw==
X-Gm-Message-State: AOJu0YxepSFMvB76fBPyZWLt5a+Lq0llwsFSJI9N3tL1x68onZBw/T4O
	0W+Qg7/uJ5uLAWPzlmyNju7jnVx+vRZutD9/Zz9mwjplxDCNuc+s
X-Google-Smtp-Source: AGHT+IGqY4ZPA0IZakOkqiT48nBMOfuA+/gNxtSykvXRjL+5uu5c/YGA6HD5P4XZgddZQeXdi9OhpQ==
X-Received: by 2002:a05:6e02:1cac:b0:36c:85c:9800 with SMTP id x12-20020a056e021cac00b0036c085c9800mr4647010ill.29.1713993287305;
        Wed, 24 Apr 2024 14:14:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12e2:b0:36a:2a29:6638 with SMTP id
 e9e14a558f8ab-36c29d91a0fls1894135ab.0.-pod-prod-06-us; Wed, 24 Apr 2024
 14:14:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW8QmqiTgzyFbS8+Z8cT07urNp43x+ZSv7Kk+MY2DzohWi3L9wmoQ678VhDMfDdcPDrkiEBBqalvZ1vx4wpM1yD2OnkFxmAt8FsAQ==
X-Received: by 2002:a05:6e02:1523:b0:36c:f20:91b0 with SMTP id i3-20020a056e02152300b0036c0f2091b0mr4476606ilu.11.1713993286001;
        Wed, 24 Apr 2024 14:14:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713993285; cv=none;
        d=google.com; s=arc-20160816;
        b=CJlISpAiqZFkH6JFwm2iilsSA9R9OeLCZ7/SCvSkuIOmqAUu32uAdYcXlhfMtsjKl0
         VEdRhWHHxcS3ZeSoV9NZSgoBHUnKMscGvFmD2lZJTPhj/RQD7294oAATC8+fAG4wrJ6I
         hWSfDz8MD1AK9KxClnHTc7cCHIf5NE0qP9YH2b90EMYvdDIs+u7WbjV1z5EmemQxyElc
         7sRjK1KnvDWFtJV/9gfIfr0k9meiOSxkaqpISwtAd67TcmdzT0P9YySZ504wVc7nXhkE
         rOvLHrrTqYDGV8lcXxiRYqjOr2pDtEhOv+XknJ81dvTtw7X8gp10p1ch4tgmydMcRcS/
         +YjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=v6t9WtKr0oqpAwD8IZNlyuQgZFWtk9VNjNeyiMuDK0k=;
        fh=ksAxWQ4hOYV02kVDYjspiRxCyCqNGM1MbpoVpFGA+e8=;
        b=tXBrYhfeWgT1hPycOwIvwPskzYHIKdWoBbbew7w2ENAGrPoC/1K+44PDo4Q80UjHLX
         GYypon+9Bz4IxUfUKzpNaqpvy3w9+kROLxcEUceKypxbQ0Oov1MofolAXP22oQIfftiR
         mFJzNRhdzg+8/P5OplVvCU1X3vFqR8PAtQEnWVske9GwBV8nVa1RCdj8e1miRS2hzKeu
         C+Wsy85uYoxzF/Yx3xnJIZ2UgNkczTw7wPhRiBlAOhgZN3dgc1CeKNW0GibQTk9pBr5Y
         gra5RvKvMf+O7/fykgNy5nih/s4LCqaeHpNi5Avl3iw96wKVDjQkbXYlhKfPi7YPDyPN
         r0Ug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@embeddedor.com header.s=default header.b=GB1Wtd+S;
       spf=pass (google.com: domain of gustavo@embeddedor.com designates 44.202.169.37 as permitted sender) smtp.mailfrom=gustavo@embeddedor.com
Received: from omta038.useast.a.cloudfilter.net (omta038.useast.a.cloudfilter.net. [44.202.169.37])
        by gmr-mx.google.com with ESMTPS id kk2-20020a056638a90200b0047f1e1a075esi1156781jab.2.2024.04.24.14.14.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Apr 2024 14:14:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of gustavo@embeddedor.com designates 44.202.169.37 as permitted sender) client-ip=44.202.169.37;
Received: from eig-obgw-6002a.ext.cloudfilter.net ([10.0.30.222])
	by cmsmtp with ESMTPS
	id zWAZrR8aYQr4SzjwzrOO1V; Wed, 24 Apr 2024 21:14:45 +0000
Received: from gator4166.hostgator.com ([108.167.133.22])
	by cmsmtp with ESMTPS
	id zjwyrj2dqiKqRzjwyrAKXz; Wed, 24 Apr 2024 21:14:44 +0000
X-Authority-Analysis: v=2.4 cv=I9quR8gg c=1 sm=1 tr=0 ts=66297644
 a=1YbLdUo/zbTtOZ3uB5T3HA==:117 a=zXgy4KOrraTBHT4+ULisNA==:17
 a=IkcTkHD0fZMA:10 a=raytVjVEu-sA:10 a=wYkD_t78qR0A:10 a=cm27Pg_UAAAA:8
 a=VwQbUJbxAAAA:8 a=1XWaLZrsAAAA:8 a=pGLkceISAAAA:8 a=4RBUngkUAAAA:8
 a=PoZ_YbeHmJNqDTfelxsA:9 a=QEXdDO2ut3YA:10 a=xmb-EsYY8bH0VWELuYED:22
 a=AjGcO6oz07-iQ99wixmX:22 a=_sbA2Q-Kp09kWB8D3iXc:22
Received: from [201.172.173.147] (port=34770 helo=[192.168.15.14])
	by gator4166.hostgator.com with esmtpsa  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.96.2)
	(envelope-from <gustavo@embeddedor.com>)
	id 1rzjwx-0031vA-23;
	Wed, 24 Apr 2024 16:14:43 -0500
Message-ID: <cfd32c82-8909-48f7-ba5c-22c08b5eb53a@embeddedor.com>
Date: Wed, 24 Apr 2024 15:14:42 -0600
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] ubsan: Remove 1-element array usage in debug reporting
To: Kees Cook <keescook@chromium.org>,
 "Gustavo A . R . Silva" <gustavoars@kernel.org>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com,
 linux-hardening@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>,
 linux-kernel@vger.kernel.org
References: <20240424162739.work.492-kees@kernel.org>
Content-Language: en-US
From: "Gustavo A. R. Silva" <gustavo@embeddedor.com>
In-Reply-To: <20240424162739.work.492-kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-AntiAbuse: This header was added to track abuse, please include it with any abuse report
X-AntiAbuse: Primary Hostname - gator4166.hostgator.com
X-AntiAbuse: Original Domain - googlegroups.com
X-AntiAbuse: Originator/Caller UID/GID - [47 12] / [47 12]
X-AntiAbuse: Sender Address Domain - embeddedor.com
X-BWhitelist: no
X-Source-IP: 201.172.173.147
X-Source-L: No
X-Exim-ID: 1rzjwx-0031vA-23
X-Source: 
X-Source-Args: 
X-Source-Dir: 
X-Source-Sender: ([192.168.15.14]) [201.172.173.147]:34770
X-Source-Auth: gustavo@embeddedor.com
X-Email-Count: 4
X-Org: HG=hgshared;ORG=hostgator;
X-Source-Cap: Z3V6aWRpbmU7Z3V6aWRpbmU7Z2F0b3I0MTY2Lmhvc3RnYXRvci5jb20=
X-Local-Domain: yes
X-CMAE-Envelope: MS4xfNBeO6/rbbhxRVoYfVSsztox7yXTvqm0VUYXCJgtVVpkRmFnziPK6N6EBR5KOwrlPGMLDcUtVuQ3QfEe2a9BFIE5CZ/sHPneyEep5k5xJpJJjJAUHphT
 MonIRyPXSQU2Y8H2ZT3H+INQGxaCfYOClrEhoGsk5hb9fVMbk7zOFyX+1hbvaE29o9Uy29hmJmKpBLEnYgh9radQ1iMko45EkZOHkmZKICM3Y9RS6Z96YxiZ
X-Original-Sender: gustavo@embeddedor.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@embeddedor.com header.s=default header.b=GB1Wtd+S;       spf=pass
 (google.com: domain of gustavo@embeddedor.com designates 44.202.169.37 as
 permitted sender) smtp.mailfrom=gustavo@embeddedor.com
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



On 24/04/24 10:27, Kees Cook wrote:
> The "type_name" character array was still marked as a 1-element array.
> While we don't validate strings used in format arguments yet, let's fix
> this before it causes trouble some future day.
> 
> Signed-off-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Gustavo A. R. Silva <gustavoars@kernel.org>

Thanks!
--
Gustavo

> ---
> Cc: Gustavo A. R. Silva <gustavoars@kernel.org>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-hardening@vger.kernel.org
> ---
>   lib/ubsan.h | 2 +-
>   1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/lib/ubsan.h b/lib/ubsan.h
> index 0abbbac8700d..50ef50811b7c 100644
> --- a/lib/ubsan.h
> +++ b/lib/ubsan.h
> @@ -43,7 +43,7 @@ enum {
>   struct type_descriptor {
>   	u16 type_kind;
>   	u16 type_info;
> -	char type_name[1];
> +	char type_name[];
>   };
>   
>   struct source_location {

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cfd32c82-8909-48f7-ba5c-22c08b5eb53a%40embeddedor.com.
