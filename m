Return-Path: <kasan-dev+bncBCM3NNW3WAKBBVEGTHGQMGQENNFNNMI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 40MQFFhDpmlyNQAAu9opvQ
	(envelope-from <kasan-dev+bncBCM3NNW3WAKBBVEGTHGQMGQENNFNNMI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 03:11:36 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 49CD31E7E43
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 03:11:35 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-8274bb61b6dsf1702527b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 18:11:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772503893; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kd1hZ8mRLD/VupSYq7i/SHmIAor+QUOLiX0N0AiyUmcFSWSHlpTLD7gRDgDXg51BW6
         HCdb7AY2GE38l+ZhdYJDrU0i5Jmr1Kd3G8Z9LAh+kLe2i7CfugGCSOg9N3DX7TYdDhUs
         Hqt35LlXuZhFZ8xm6DUwjMFwj4MHul6d0G3cX86x6P2xW6w1YW+PfviBaR4YhqrU4bn1
         ft/bvvadstXr7O5ojQk3GfEFot1OGwhi+RCuVHkCGd91ESjVzQCKXhxeNqAY1IkPldw8
         K4XXvm0Ia/Au1J21Wm8uLTedfwNGkOz+y1SXy7z5w8lySIgQ2HagdxxfEZ4uNFppIB53
         dvkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=3O7q6Pl93chTIwUQn48NbZjC7XrlbykIcfrHtE6L+cA=;
        fh=EU7iAFIyPLRfdJ4x/HZ4paU/rmVlphxVkScC0gu5KnI=;
        b=PVsdlismcMVeKNC+Lt7RSJiRoUK7Q1UKloxJnHVztQMfiS3DB4JhCtnkHL55FZKe2L
         2MswPLpidfPXF2Vg9mod+NorLBygo1Z/uJQjxcyu6ZjF2uNnJIWreTbA2ul7v7//uuHK
         4sC+t/+uiyYI4ledBukygE++H3r3eWW32OTZ+yMfsQbdc34xfM7UT3PVPOxCu2S94KQt
         aKD58/NHh12o8dWPB5NlZvUy/aorBAE9qONWgF1JkzdqpsXD/X3lQ+O4TiZyo+gyzq1I
         p4GIsZZGPG7bsTX5G5jEAlzJbzWElRtvVaHkO/FQP/yNMS8as+lnGE37+eVVVKwKv/Xs
         7NGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.25 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772503893; x=1773108693; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3O7q6Pl93chTIwUQn48NbZjC7XrlbykIcfrHtE6L+cA=;
        b=J30cr2dByCi2QbxypR8hWjKFVh3yBFOO2odpwm7yU4OS/YSLTdYaKdzvU3fQxrB3MN
         oksDN5j5KAuCxX2ICdu3wRsPcWvGQpkcfP72ldwo3daHjFhQs9QPkxxCYusxfUyq5HMk
         4QHEmW1tFadq5+GVLw3T2+1sr1CxNsgDaTQkRLBzJ6ooLusP47VWt9auIHR+LZ9Br1PF
         6XTMqvNEIP/ohZULhms8VNWMV43NxQXi46CJal80pDGz+qN7Qzz4477dGfODH7AcxIMB
         gc5FGdfLnGtohtbaByxY2x/JpvFmkYKSe3H+fYxZzyx1X7TmSsmjsdVYGmkk88vK3X0v
         1Ylg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772503893; x=1773108693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3O7q6Pl93chTIwUQn48NbZjC7XrlbykIcfrHtE6L+cA=;
        b=OZ5WQrsRASM/b7kXyyPHa4oy6b1AcQnOVNLXZIaBEUxAQM/6HWvxnNOVws1EvRcCRv
         0+HVIhArudkmwEc01PDKFDazOes90zOxThAYzz+ZzXuP8CCH/29h1KorpniJ/6eZl8pl
         UyqFH3ouD75qL0RThNyWqghu7/iSomVleB/sKjfqmEMBOVjH7PSZFxL59OZDv6FJ3Tbg
         OQqBlZ26URrGdTg3oYCfkjyD9SsdVwBHNqBO/oWqFe71fWmb74de0qg252M3Bw9WbMap
         PkGsRtdkVAqTL9Y18BtvEl4qKOVD3el26iJ/+OOIenjaZ5wCMchs2DdNBVRuEAtYjvbZ
         8yHA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXN0nEcCzSNst84Iu9vExvUOPtEzAqXnUHviZIm5CF7SymqiA3TKzj8m/K9gE4d1AHbw6F/w==@lfdr.de
X-Gm-Message-State: AOJu0YxAAWeDV1vxb6+YKcUF6ZQ40ZTNia7r46I3m0GGZZr57+67Au+I
	u9lzh238ZmF1RVKZI9+wmebNtl4WHsWQncM/Uh+ppnYFDSPZuYqUyP1K
X-Received: by 2002:a05:6a00:1a0b:b0:81f:3cd5:2069 with SMTP id d2e1a72fcca58-8274d91d197mr11469489b3a.4.1772503893102;
        Mon, 02 Mar 2026 18:11:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Grv4BqDoMC3VX4P7JPu1GLVu9xJ5YP6rmiJrjnoFj6lg=="
Received: by 2002:a05:6a00:4c17:b0:7ab:f0f5:3013 with SMTP id
 d2e1a72fcca58-827270c73adls5489726b3a.1.-pod-prod-09-us; Mon, 02 Mar 2026
 18:11:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUJ6PypKiHkmp8m+eo+O2MR1rpmOHFU9n2O/zaJExK+DOzgsZCU2NFCFwbvAqRYrkwNE90N5P76xnw=@googlegroups.com
X-Received: by 2002:a05:6a00:b53:b0:81f:be3c:9c9e with SMTP id d2e1a72fcca58-8274d9e674emr12533358b3a.33.1772503891646;
        Mon, 02 Mar 2026 18:11:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772503891; cv=none;
        d=google.com; s=arc-20240605;
        b=aakH+tauaOADBOtrsTL9K1dWuqrp13Xa0Q9xoRxdaA/su+viymCYpCDJJSOJF1dnqs
         cFPGyPoqsXcTNBvNYQHM8XLFvkoXTYDuNDzlL5qYo2ZoDIgb+QdgpCdVy4m0AoXRnFfp
         Hk16O6cUIFGLwG46uazuINgFOpxfnvM5sUzfcz55aYERaIl/TnOiyQ5jgUAih6lEZPKS
         tU7iNEYvZhu7Xb4RYZs15ihi6+mGwcKN4XI3cYiGwMsdFSZDE/y71waHh/ORt+41a9de
         zdx+lkeDYCEx6yBz4mvQe4uSSVakQVAZkWmD4PA6pswVN/QUI01YulbvYEP6OQvMM0/q
         xGuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=10RHyunxNafmuRZalfg6QVef/DFa736VdCEf+9PmdsQ=;
        fh=cgx6frOgFD0HOVbyrg3z8JqkYYHI3n5rt84Cbo07OVI=;
        b=b7bkku4penzu3ynlt/q/FK4fCVrASAepCqDeDiz0N2dpdXNR5ecvF8CWeWSi/MIoKP
         VTcSKyt+7rf5IN6xTKxSsqkdsUkL9gt+GeTxHolitgM5vY9AEZ/RKfoY22Fdfemep1F4
         OSYO8Ij4/VoW94ZV2m9AHFoq/hWHWe3EPHEWz0UhsSIeZZ8gDpBqVplBCZnGABJAokTX
         0TqP1iKHELLm2qqZj/hCxthm7Ve8ZVypGGBL1La0kQFT9Tpp2RivnBtCOZGPQfF/GFO7
         Pt2cdpRWDSTVBwWThHYbpIGWU2zffQGlr51wyKnHw13qmxq+zg2rdtHzpyJMESp4KtK3
         8flw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.25 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
Received: from cstnet.cn (smtp25.cstnet.cn. [159.226.251.25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-8273a11d04asi528138b3a.4.2026.03.02.18.11.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Mar 2026 18:11:31 -0800 (PST)
Received-SPF: pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.25 as permitted sender) client-ip=159.226.251.25;
Received: from [10.213.20.192] (unknown [210.73.43.101])
	by APP-05 (Coremail) with SMTP id zQCowADXbBBMQ6ZpW2KNCQ--.3697S2;
	Tue, 03 Mar 2026 10:11:24 +0800 (CST)
Message-ID: <a4799df1-73d9-4653-b64c-7dd833ca0397@iscas.ac.cn>
Date: Tue, 3 Mar 2026 10:11:24 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 1/3] riscv: mm: Rename new_vmalloc into new_valid_map_cpus
To: Alexander Potapenko <glider@google.com>
Cc: Paul Walmsley <pjw@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>,
 Albert Ou <aou@eecs.berkeley.edu>, Alexandre Ghiti <alex@ghiti.fr>,
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Palmer Dabbelt <palmer@rivosinc.com>
References: <20260302-handle-kfence-protect-spurious-fault-v1-0-25c82c879d9c@iscas.ac.cn>
 <20260302-handle-kfence-protect-spurious-fault-v1-1-25c82c879d9c@iscas.ac.cn>
 <CAG_fn=UQj+bdY2YojmfVf=qRQgCttD=PqE0h=vm4pAbtNRP-uw@mail.gmail.com>
Content-Language: en-US
From: Vivian Wang <wangruikang@iscas.ac.cn>
In-Reply-To: <CAG_fn=UQj+bdY2YojmfVf=qRQgCttD=PqE0h=vm4pAbtNRP-uw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: zQCowADXbBBMQ6ZpW2KNCQ--.3697S2
X-Coremail-Antispam: 1UD129KBjvJXoW7Cw47XF1fZryruFW3WF1xZrb_yoW8Xw1fpF
	Z3CFn5KFy5Cryfuw1avrsFgr1rtwnYg3Way398K34vvw4qyFy7tr1DKr1xuryUXFW8Jr40
	kFW3ua4rCw1jyrJanT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUU9qb7Iv0xC_Zr1lb4IE77IF4wAFF20E14v26r4j6ryUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Xr0_Ar1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26F4UJVW0owA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_GcCE3s1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqx4xG64xv
	F2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_Jrv_JF1lYx0Ex4A2jsIE14v26r1j6r
	4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvEwIxGrwACI402YVCY1x02628vn2kIc2xK
	xwCY1x0262kKe7AKxVWUtVW8ZwCY02Avz4vE14v_Gr1l42xK82IYc2Ij64vIr41l4I8I3I
	0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWU
	GVWUWwC2zVAF1VAY17CE14v26r1q6r43MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI
	0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26r4j6F4UMIIF0xvE42xK8VAvwI8IcIk0
	rVWUJVWUCwCI42IY6I8E87Iv67AKxVWUJVW8JwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r
	4UJbIYCTnIWIevJa73UjIFyTuYvjxU2yxRUUUUU
X-Originating-IP: [210.73.43.101]
X-CM-SenderInfo: pzdqw2pxlnt03j6l2u1dvotugofq/
X-Original-Sender: wangruikang@iscas.ac.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.25 as
 permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
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
X-Rspamd-Queue-Id: 49CD31E7E43
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	DMARC_NA(0.00)[iscas.ac.cn];
	SUSPICIOUS_AUTH_ORIGIN(0.00)[];
	TAGGED_FROM(0.00)[bncBCM3NNW3WAKBBVEGTHGQMGQENNFNNMI];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TO_DN_SOME(0.00)[];
	HAS_XOIP(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[wangruikang@iscas.ac.cn,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	RCPT_COUNT_SEVEN(0.00)[11];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email]
X-Rspamd-Action: no action

On 3/2/26 23:41, Alexander Potapenko wrote:
> On Mon, Mar 2, 2026 at 3:21=E2=80=AFAM Vivian Wang <wangruikang@iscas.ac.=
cn> wrote:
>> In preparation of a future patch using this mechanism for non-vmalloc
>> mappings, rename new_vmalloc into new_valid_map_cpus to avoid misleading
>> readers.
>>
>> No functional change intended.
>>
>> Signed-off-by: Vivian Wang <wangruikang@iscas.ac.cn>
>> ---
>>  arch/riscv/include/asm/cacheflush.h |  6 +++---
>>  arch/riscv/kernel/entry.S           | 38 ++++++++++++++++++------------=
-------
>>  arch/riscv/mm/init.c                |  2 +-
>>  3 files changed, 23 insertions(+), 23 deletions(-)
>>
>> diff --git a/arch/riscv/include/asm/cacheflush.h b/arch/riscv/include/as=
m/cacheflush.h
>> index 0092513c3376..b6d1a5eb7564 100644
>> --- a/arch/riscv/include/asm/cacheflush.h
>> +++ b/arch/riscv/include/asm/cacheflush.h
>> @@ -41,7 +41,7 @@ do {                                                  =
\
>>  } while (0)
>>
>>  #ifdef CONFIG_64BIT
>> -extern u64 new_vmalloc[NR_CPUS / sizeof(u64) + 1];
>> +extern u64 new_valid_map_cpus[NR_CPUS / sizeof(u64) + 1];
> new_valid_map_cpus is a bitmap, right? If so, you are allocating 8x
> more memory than needed.
> Can we use DECLARE_BITMAP instead?

I hadn't considered changing since this series is supposed to be just a
fix, but that is a good point.

I'll reorganize this in v2 to include a fix to use DECLARE_BITMAP, and
also use bitmap operations for the marking operation. But I'll leave
that out of consideration for stable backport, maybe along with the
renaming.

Thanks,
Vivian "dramforever" Wang

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
4799df1-73d9-4653-b64c-7dd833ca0397%40iscas.ac.cn.
