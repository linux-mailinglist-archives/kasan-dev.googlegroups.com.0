Return-Path: <kasan-dev+bncBDNYNPOAQ4GBB37WU7FAMGQEKFP2USQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id A4059CD7D82
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Dec 2025 03:16:17 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-3ec7ae7492asf6461749fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 18:16:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766456176; cv=pass;
        d=google.com; s=arc-20240605;
        b=KySeMUVVnlfmV5xTB4FKCktHrRTC5/dMaz37yqYi64TYsSuijStTowJ4jp8TO7/upL
         s3/EyIIay8cRE6Y/uiYE+D7/nBh3KroB1kTZC1z+xrkIjcXwggNGZ6s4DhV+LVIrFACy
         bxipLJsS81a+RogDJfxTj8Z3t8oMJZA/EfSybClEKhb996hth1bqyCyD09MSYUGnX7Do
         BWPvkBoAXaUYHWBYr1Rr8/uVBFehf0eTcTLoafq63dvPugQdGdLz287zNrSct5OtvRu+
         u06Yi6IeJZ4Q6/PcIg9MLXtG5VkGF4WTFXJg9axW9sFOqSH72gLr8rcKqhw6BCW0y5JS
         B04g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=9zUmQMwTa4VZBP6uqJk36eDT6p10yQzUk7un4G74AZA=;
        fh=3j7Y8b/bPUcDpJtCtuZZplRgfqG7ADoveoJOK3EiESk=;
        b=M0HOh5Zww8zcjOYtvo23Km2xxTFnFgWvIbGHvys8z2hyOJCWb1d18EExRqiJlUK5uW
         13PdOtjGgTd0EAxeqgj8R5Bh17qNB3D4ZCja7KgSiycwUeoetDLWA717d8cEAt0t5xiB
         WQ5K4hoqdxx92+L3817wFRWlHWGdeqV9JfwEkBsTmu0uKzuF0CrSLWp/6S1lKrpZ2tT0
         WOkiLcZ6ug7A5aX+VNiw++uRzzYe2JEFpF45Nb36IqPjN95BDwF7MqfBKgO0D0xlq/n1
         epWONjut9IIFzWUEx+UtODCo2Xn/pGRoIxEbN4sW27IvkCXt7QkZlMYFaYRQQA4xdDiu
         Ampg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@embeddedor.com header.s=default header.b=iDMjRWa4;
       spf=pass (google.com: domain of gustavo@embeddedor.com designates 44.202.169.39 as permitted sender) smtp.mailfrom=gustavo@embeddedor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766456176; x=1767060976; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9zUmQMwTa4VZBP6uqJk36eDT6p10yQzUk7un4G74AZA=;
        b=djldtz9CXurkhZ8Pv6FGf481wuDo62e3VtJ+W0jRjiHoXiT0KCRYJ1tTKOG4w0LcIG
         yxYzWwJ0N9LbJpZRg0z7vFsdOJmADWyPNA7Bm0yU05BKdxc3ZXpNlWyyl+DgzmFA8DNI
         h74SvoFdEFSCqrp7/wfCkgnZX6HTp/0+rz3knqTSVwbdeh2hkfqLcfWkPRWqvjUvTp7O
         YYTGIV/xd5Ld00LIPONgQTeB4NqTRG3sZBDregs5noUU4+uCc72CUOPsTVEhPBezZKec
         8YYc33D16krkPMSQ/J0SjxDq5LBZV7JARe6lt81UWs8oopVb8ozWPu1cWDNrhBTci3R+
         t3ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766456176; x=1767060976;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9zUmQMwTa4VZBP6uqJk36eDT6p10yQzUk7un4G74AZA=;
        b=Mj1nN2QeQcKtRGjZzKxWvMa/L08/y0GZch127ILIRI1UccxtK0gVJcLhGjJCmJEzLg
         fcdWVRJieXeVCyNlG3V3sfbrZvTF2n+8kMNFy5dY1HLxXvRFSS9WYUx+8sBU8/lV8FIW
         LPLGjXwQEJ+P71nD/H+H6CTnLpvDrYnmk5B7t+VhSXCfyqrbyAcp8u9kPFjN2cLrfE7d
         I5xI117yrM5X7hottB4EzF6q5PVDpl4eZ6WWII4yblFRI7xPADZ+hPf03oDWz71aMTP7
         DVl6c2H0MNQ0mSYMWraCPSw3kgit4JTHfJaeIyd+i+n0F+2PzIBIQlTSy9mp4xuwdTXv
         MSIg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWT4IvnliBUt79CFVM3pAy7NN3LsUeIS8wIldfifldIw0je+/F21lVuLM27QSpqF855b1UjZw==@lfdr.de
X-Gm-Message-State: AOJu0YxkiPYSNCUsVLNtnEIgndlOoFAMHvN1V0KntzQB7Sy0Q/+ckXk9
	ZMNCYCecGEUgIkqWm4B6f+PZorgQ6qom5g3CRkEXBkZycyXqXtj9kAIB
X-Google-Smtp-Source: AGHT+IGtMvEOEETrubdM1PgHfF67SlZsVVrK2Tj+b9ZkUNpooqdNx/Ui3VOsySgEZ+c98CjOq9fDmw==
X-Received: by 2002:a05:6870:459c:b0:3d3:e9a1:97d3 with SMTP id 586e51a60fabf-3fda580d44fmr6443345fac.34.1766456175888;
        Mon, 22 Dec 2025 18:16:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaQiOZrr/uL1MQ3hUaq0g137Uwe5FjRGjzgZTnBZ27MkQ=="
Received: by 2002:a05:6871:d689:10b0:3ec:7947:3f27 with SMTP id
 586e51a60fabf-3f5f83b937fls5618943fac.0.-pod-prod-01-us; Mon, 22 Dec 2025
 18:16:15 -0800 (PST)
X-Received: by 2002:a05:6830:230e:b0:7ca:e8bf:8c4d with SMTP id 46e09a7af769-7cc668c4b0cmr8141804a34.14.1766456174820;
        Mon, 22 Dec 2025 18:16:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766456174; cv=none;
        d=google.com; s=arc-20240605;
        b=KWX0n/oyumAPxp9yb3P2WAi/Q+RRo00gfil21X/HzvS3X0saSMWnjrcyitVM1tr8fY
         tj2qYntk0msj2oInQtDybGGHNkx3T0t2cg6CSywtm2J6OaVOLlmwbeezEr5Nusz7C1y9
         A+8UrtQfOFYxhVFWaRwatQaYoSpks3czbQwoYTg8/lqZC6y5jFQpTDjsZPouUKvhyVBF
         p0yiNghKYMWc1JSgieeWjjSxKeIdvTeT+STsPpzXVwleUNPapUBDYvA1O/WYr93Zsx/p
         impEEEoCsBBXp7aR12LqFyVAXrjA5D5oXRo8O70IMgPyIyuhGbciqYtgbfF49KYqZ4a1
         /CGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=BDzzqhMgRlf/SepYLBY7ybmCUGIfzjWfLnATsuDUCz4=;
        fh=Jkpijuw/DfEqBLZExbTj1fCQ6GWeDGeIlT/MaCfBeNM=;
        b=OHOmZEia/fnfrzD1ambZaKhU4EOLeZ8O1TaTwrOYWmJ6G0BNUiwofiaL4o0HLLyuux
         y+AdeWb2vzAxPJ5338slfhP8Bu3mHWFR278BveDNgWbl1uiJUEVrPchdeZuJeYHo5nd/
         e+cQnh8dzUn0wSKCFtOU+IDod0knD/LSD7sD+CxTuVZvj3XgmzEhhqRLKMk20H9Ag7GF
         wFFErznYb6piSmferz6eaEQap4T7e/Yoc9XNtitmLKW4/2/CRrbe+U7gYyhxCNHS1akr
         UGvBl+SW+63R8oUrs4j3IxoXPaT7WsWs9wZqzkjIZosQOEl1xyfY76AxbcXfFOWUufwz
         aLIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@embeddedor.com header.s=default header.b=iDMjRWa4;
       spf=pass (google.com: domain of gustavo@embeddedor.com designates 44.202.169.39 as permitted sender) smtp.mailfrom=gustavo@embeddedor.com
Received: from omta040.useast.a.cloudfilter.net (omta040.useast.a.cloudfilter.net. [44.202.169.39])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cc667ca0a2si973057a34.6.2025.12.22.18.16.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 22 Dec 2025 18:16:14 -0800 (PST)
Received-SPF: pass (google.com: domain of gustavo@embeddedor.com designates 44.202.169.39 as permitted sender) client-ip=44.202.169.39;
Received: from eig-obgw-5004b.ext.cloudfilter.net ([10.0.29.208])
	by cmsmtp with ESMTPS
	id XoVWvvU1lv724XrwbvistN; Tue, 23 Dec 2025 02:16:13 +0000
Received: from gator4166.hostgator.com ([108.167.133.22])
	by cmsmtp with ESMTPS
	id XrwbvnN0jqfpWXrwbv65cu; Tue, 23 Dec 2025 02:16:13 +0000
X-Authority-Analysis: v=2.4 cv=A55sP7WG c=1 sm=1 tr=0 ts=6949fb6d
 a=1YbLdUo/zbTtOZ3uB5T3HA==:117 a=ujWNxKVE5dX343uAl30YYw==:17
 a=IkcTkHD0fZMA:10 a=wP3pNCr1ah4A:10 a=7T7KSl7uo7wA:10 a=VwQbUJbxAAAA:8
 a=-cfKi4IEpZHxV7FLFHoA:9 a=QEXdDO2ut3YA:10 a=2aFnImwKRvkU0tJ3nQRT:22
Received: from i118-18-233-1.s41.a027.ap.plala.or.jp ([118.18.233.1]:63188 helo=[10.83.24.44])
	by gator4166.hostgator.com with esmtpsa  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.98.1)
	(envelope-from <gustavo@embeddedor.com>)
	id 1vXrwa-00000000SNN-0yTj;
	Mon, 22 Dec 2025 20:16:13 -0600
Message-ID: <5d144d3a-d02d-4c7b-9360-29aea0705137@embeddedor.com>
Date: Tue, 23 Dec 2025 11:15:52 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: UBSAN: array-index-out-of-bounds
To: Kees Cook <kees@kernel.org>, Randy Dunlap <rdunlap@infradead.org>
Cc: kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org
References: <90e419ad-4036-4669-a4cc-8ce5d29e464b@infradead.org>
 <202512221526.451D1BE1B@keescook>
Content-Language: en-US
From: "Gustavo A. R. Silva" <gustavo@embeddedor.com>
In-Reply-To: <202512221526.451D1BE1B@keescook>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-AntiAbuse: This header was added to track abuse, please include it with any abuse report
X-AntiAbuse: Primary Hostname - gator4166.hostgator.com
X-AntiAbuse: Original Domain - googlegroups.com
X-AntiAbuse: Originator/Caller UID/GID - [47 12] / [47 12]
X-AntiAbuse: Sender Address Domain - embeddedor.com
X-BWhitelist: no
X-Source-IP: 118.18.233.1
X-Source-L: No
X-Exim-ID: 1vXrwa-00000000SNN-0yTj
X-Source: 
X-Source-Args: 
X-Source-Dir: 
X-Source-Sender: i118-18-233-1.s41.a027.ap.plala.or.jp ([10.83.24.44]) [118.18.233.1]:63188
X-Source-Auth: gustavo@embeddedor.com
X-Email-Count: 2
X-Org: HG=hgshared;ORG=hostgator;
X-Source-Cap: Z3V6aWRpbmU7Z3V6aWRpbmU7Z2F0b3I0MTY2Lmhvc3RnYXRvci5jb20=
X-Local-Domain: yes
X-CMAE-Envelope: MS4xfFEpjkS+LA7WMy7BU96IY14aBaF62fM4ueEicyBd8OdSyQOzYeq2+xMx39T5WaSp7vscLlzv4GxAUC+4RIEY5fvAt3r7TCNzmq7WOg3blMydjQb6emLQ
 IvD2BYZr1CGe7Z9mKMCrvfPzMAt9oNZj+mRk8tRSNH1JEOFgWinU/vMVFHLO+9LTmx9KNHbUD67klRxnUAFHHXCSWmJbRqIcvBwz9qEi2IMfy0VV76KcG94h
X-Original-Sender: gustavo@embeddedor.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@embeddedor.com header.s=default header.b=iDMjRWa4;       spf=pass
 (google.com: domain of gustavo@embeddedor.com designates 44.202.169.39 as
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



On 12/23/25 08:28, Kees Cook wrote:
> On Fri, Dec 19, 2025 at 08:20:13PM -0800, Randy Dunlap wrote:
>>
>> from kernel bugzilla:
>> https://bugzilla.kernel.org/show_bug.cgi?id=220823
>>
>>
>> Dec 15 22:01:52 orpheus kernel: UBSAN: array-index-out-of-bounds in /var/tmp/portage/sys-kernel/gentoo-kernel-6.18.1/work/linux-6.18/drivers/mtd/devices/mtd_intel_dg.c:750:15
>>
>>
>> (from drivers/mtd/devices/mtd_intel_dg.c:)
>>
>> 	nvm = kzalloc(struct_size(nvm, regions, nregions), GFP_KERNEL);
> 
> Yes, this needs to be immediately followed with:
> 
> 	nvm->nregions = nregions;
> 

I submitted a fix for this that day:

https://lore.kernel.org/linux-hardening/aUZFLezigzZQVt55@kspp/

It seems someone had submitted a patch in Nov, but it was
never applied upstream.

-Gustavo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5d144d3a-d02d-4c7b-9360-29aea0705137%40embeddedor.com.
