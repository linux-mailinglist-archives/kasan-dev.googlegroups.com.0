Return-Path: <kasan-dev+bncBCLI747UVAFRBNNX72MQMGQEICVHUIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 986CA5F7350
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 05:23:34 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id s10-20020a5edc4a000000b006bba58340b1sf143282iop.15
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 20:23:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665113013; cv=pass;
        d=google.com; s=arc-20160816;
        b=hYP38KyG/nPt9UAZpa3fscVYBWYee8QX92gz6j/niNHTJQ8lKW59dif6YqNvYj/uQq
         dW1M6OCImRUoPrKAWZzHHEFAb/GxHR5dhoEmA8XgdsujEq84ZP2d+te5p59FsRdeVmUy
         5W3ugGP8ZMy66E2s7Wm8AeEO421mZfsbaQRN1lYgDogNn8oV0S2mguILUHCOdJ9FY+Ud
         e3SclamkiimbHDhpee7Zdu+0J7W4PXglos62j2G25VGx6IJOebgX1lbi+FGhAD6G3HZu
         6q1Lt/7Rz6V/ZMDBkmpsLEZuc5599kAOycV1IhkyLDj4itwR4gQyqrsukyxlFlmuUtba
         zbtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:references:in-reply-to:mime-version:dkim-signature;
        bh=cCwM2x9wmnEKfxNrRM7OHYUsacG0qCMghSUw1esRgi4=;
        b=qBN3y7Wpb9mhaM0hHV9d4y1w9sSioBca/zH01N2V7XqBZ/HZjPshQxfYSIG04yA6ZQ
         0rOfD3PAhe3t7odT74x7suP3zgb1rOUjYOqcneYQWRh41mpUXN2uDboSl0nZd0vYB3rc
         2iGGwjCkarlPpZQ3++IUAXpqy/2w7fa9hT+a0us1+e0PM9VcIC7NeyHZPT/4BbrIHl3p
         bH4ZLtbS6OjKU7kpYa0fX4rBGMmqe/HudGl/LYDM6PT+71VPR4Jl/dTmJMMEVUy4AEmu
         WWGwQQTVRx94NemvMaruGVouMeJOJOBVwrRnspuSKBL1vOp8S1rm0CBsIODy0qsHis33
         tidA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=MKWvEoG5;
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:references:in-reply-to:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cCwM2x9wmnEKfxNrRM7OHYUsacG0qCMghSUw1esRgi4=;
        b=Kq5jkArlkyEILy/emAI8VSryVYJFV6iSZdoiPttbjAPwit9m/8aePJuKFGxyWUU/vr
         WtI5xwadbWUWSvSlMkfokfUEiJwXLLXuju6kWk/6wEZTuTH5zBlWLNaESaD4xxyW0Zd5
         HBswa1cc3k8Hr6JlfUauHUrGzOjeptsAUlwX/7RIMX7UA5o9nYUCj/7fOEbKefGerEYg
         T8sA4zoqhXfk8kNRRKctq0rwveZs4o5/Y1XTxuDcQ3swnszeNTdCJcAMkZhj3vzwKh01
         aZAt3hq8jwHnALr/ExgK5UgEWY8M55BcGgo39rywAOvKDILeZ83IxD8HiX2Zgbzqmw1i
         17Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:references:in-reply-to:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=cCwM2x9wmnEKfxNrRM7OHYUsacG0qCMghSUw1esRgi4=;
        b=c7hCClpUNxH2h0VEkiKs8c2y5XFLID/g+fRaDTwDKjhdNfLlYSbseiGZcDH+Q8cn2O
         eKAVJD4zjsRmpufVw8SWVA6YhdH00YM4tJq/xlwnFwGh7exHlSi0s1qdBieo7i8fwaA9
         Cry04LSHbCDGQAf4t9oeF4wWyCdZwfxx0o2x6k/7SXjrkW4/Z7NALglalBfL08jB+MBn
         xDTeed9tkx+aDVRMU7wlNSP0NEfTUDHA+iDmKSWTgV5jePhd9Yj3ZZmmpnGVEDyzhgMy
         nemxeBsyyuQInCV4pGliEFFNd3GW9ERXZJcsIwHIT/2of9yVHSvb7USn0fA21g1Kmkpm
         ILzw==
X-Gm-Message-State: ACrzQf0T62YcjfylKX5rSM345h/IJBQwS7fXQruAQ0GULY24sL2+0Ljw
	IgV9G8j6UxjgaqfjMBdFa4k=
X-Google-Smtp-Source: AMsMyM7npltWQDVgMeLG4UCi7XkrfVu/E09ibYDTVOCRTP8EOiVxJKbPRfjEdDQEdgaP/lXbA0XAHg==
X-Received: by 2002:a92:ca4c:0:b0:2f9:5143:faad with SMTP id q12-20020a92ca4c000000b002f95143faadmr1344604ilo.3.1665113013164;
        Thu, 06 Oct 2022 20:23:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c5a1:0:b0:2f8:eaa4:675a with SMTP id r1-20020a92c5a1000000b002f8eaa4675als800096ilt.8.-pod-prod-gmail;
 Thu, 06 Oct 2022 20:23:32 -0700 (PDT)
X-Received: by 2002:a92:6a0d:0:b0:2e5:afe7:8d95 with SMTP id f13-20020a926a0d000000b002e5afe78d95mr1380326ilc.262.1665113012641;
        Thu, 06 Oct 2022 20:23:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665113012; cv=none;
        d=google.com; s=arc-20160816;
        b=A5Df5NERn322Wf5E1wVS3IskqCy6cYsc+HVp2IQItD7qoW+P79yKlz7DHLcToPkYoT
         GKmMq29YHVFXRMlIt5CVeQrGBjO2PXuFybxU4jhPMhg2sY9DezS7vMYL3A1vir3jB7bi
         EBCmGpQOE+tqxKz/rLTbggb0WLLYaBx/6y6K174epXIoEorbYfjgpIKKYBiAcmJa55PG
         m58tkm6g397vwVH2hZNdSLwhNQJza/IFA3Wo7n0V2VuZSgZ3PqyRCThpGldSydEKTzTp
         RTAifAGwlAJMbkg4aqbv1826Uqj1sO0BvZnyoeQrUFWLEHHcXzNsD1qywSrMJCd2aghr
         nI4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:references:in-reply-to
         :mime-version:dkim-signature;
        bh=uPNB36BzWAD0XiB0qY+sJgcivuXHHQm1+0Nq15qRnv8=;
        b=WvQPSxobc3VW1042afTKWK+C5/7zwAgXKrmCNutA1G14806f07xPf/q/hWCK7XliDD
         9EnjCIpsVvVj63E8dxDmD0G7KLhZSEH18Tae3MXmjQmSFegIJfHpWrhuQ7Z/9ch1bRsL
         675Ljk+O4XbJD1YfVUr5mvrRG50amL1DiAXwdy22qcpsoRh9PbtXOIX0ZKvNHLZymv+5
         jxbm4/wYY7Rj5pCVFhN47bBreKA+lRnQ36f6+uMtkc1Y6aThEa7b9zqCqU2018Jlz4FL
         Rj37oPBB6i39wTWSphmONrlRlIeX4PGJbeq9FrlWBotMs8e3Wwujs23whvGqgGfe/XDG
         QETw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=MKWvEoG5;
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id l37-20020a026a25000000b003637596669csi31100jac.5.2022.10.06.20.23.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 20:23:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1C64D61BBE
	for <kasan-dev@googlegroups.com>; Fri,  7 Oct 2022 03:23:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B1B23C433D7
	for <kasan-dev@googlegroups.com>; Fri,  7 Oct 2022 03:23:31 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 15f07e44 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Fri, 7 Oct 2022 03:23:29 +0000 (UTC)
Received: by mail-pj1-f46.google.com with SMTP id v10-20020a17090a634a00b00205e48cf845so6074171pjs.4
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 20:23:27 -0700 (PDT)
X-Received: by 2002:a67:e401:0:b0:398:89f1:492f with SMTP id
 d1-20020a67e401000000b0039889f1492fmr1924805vsf.21.1665112993319; Thu, 06 Oct
 2022 20:23:13 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:ab0:6ed0:0:b0:3d9:6dfd:499 with HTTP; Thu, 6 Oct 2022
 20:23:12 -0700 (PDT)
In-Reply-To: <6c0f1d6a-27e6-5a82-956e-a4f12e0a51bf@gmail.com>
References: <20221006165346.73159-1-Jason@zx2c4.com> <20221006165346.73159-5-Jason@zx2c4.com>
 <6c0f1d6a-27e6-5a82-956e-a4f12e0a51bf@gmail.com>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Oct 2022 21:23:12 -0600
X-Gmail-Original-Message-ID: <CAHmME9rG6GAK6k-GZCBwUR-r2PLDipm--utApBtBHHRveCFEqA@mail.gmail.com>
Message-ID: <CAHmME9rG6GAK6k-GZCBwUR-r2PLDipm--utApBtBHHRveCFEqA@mail.gmail.com>
Subject: Re: [PATCH v3 4/5] treewide: use get_random_bytes when possible
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Andreas Noever <andreas.noever@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, 
	=?UTF-8?Q?Christoph_B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>, 
	Christoph Hellwig <hch@lst.de>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	Daniel Borkmann <daniel@iogearbox.net>, Dave Airlie <airlied@redhat.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, "David S . Miller" <davem@davemloft.net>, 
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "H . Peter Anvin" <hpa@zytor.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Helge Deller <deller@gmx.de>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Huacai Chen <chenhuacai@kernel.org>, 
	Hugh Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>, 
	"James E . J . Bottomley" <jejb@linux.ibm.com>, Jan Kara <jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
	Jens Axboe <axboe@kernel.dk>, Johannes Berg <johannes@sipsolutions.net>, 
	Jonathan Corbet <corbet@lwn.net>, Jozsef Kadlecsik <kadlec@netfilter.org>, KP Singh <kpsingh@kernel.org>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mauro Carvalho Chehab <mchehab@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Pablo Neira Ayuso <pablo@netfilter.org>, Paolo Abeni <pabeni@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Richard Weinberger <richard@nod.at>, 
	Russell King <linux@armlinux.org.uk>, "Theodore Ts'o" <tytso@mit.edu>, 
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Ulf Hansson <ulf.hansson@linaro.org>, 
	Vignesh Raghavendra <vigneshr@ti.com>, WANG Xuerui <kernel@xen0n.name>, Will Deacon <will@kernel.org>, 
	Yury Norov <yury.norov@gmail.com>, dri-devel@lists.freedesktop.org, 
	kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org, 
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-media@vger.kernel.org, 
	linux-mips@vger.kernel.org, linux-mm@kvack.org, linux-mmc@vger.kernel.org, 
	linux-mtd@lists.infradead.org, linux-nvme@lists.infradead.org, 
	linux-parisc@vger.kernel.org, linux-rdma@vger.kernel.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, 
	linux-usb@vger.kernel.org, linux-wireless@vger.kernel.org, 
	linuxppc-dev@lists.ozlabs.org, loongarch@lists.linux.dev, 
	netdev@vger.kernel.org, sparclinux@vger.kernel.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=MKWvEoG5;       spf=pass
 (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On 10/6/22, Bagas Sanjaya <bagasdotme@gmail.com> wrote:
> On 10/6/22 23:53, Jason A. Donenfeld wrote:
>> The prandom_bytes() function has been a deprecated inline wrapper around
>> get_random_bytes() for several releases now, and compiles down to the
>> exact same code. Replace the deprecated wrapper with a direct call to
>> the real function.
>>
>> Reviewed-by: Kees Cook <keescook@chromium.org>
>> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
>> ---
>>  arch/powerpc/crypto/crc-vpmsum_test.c       |  2 +-
>>  block/blk-crypto-fallback.c                 |  2 +-
>>  crypto/async_tx/raid6test.c                 |  2 +-
>>  drivers/dma/dmatest.c                       |  2 +-
>>  drivers/mtd/nand/raw/nandsim.c              |  2 +-
>>  drivers/mtd/tests/mtd_nandecctest.c         |  2 +-
>>  drivers/mtd/tests/speedtest.c               |  2 +-
>>  drivers/mtd/tests/stresstest.c              |  2 +-
>>  drivers/net/ethernet/broadcom/bnxt/bnxt.c   |  2 +-
>>  drivers/net/ethernet/rocker/rocker_main.c   |  2 +-
>>  drivers/net/wireguard/selftest/allowedips.c | 12 ++++++------
>>  fs/ubifs/debug.c                            |  2 +-
>>  kernel/kcsan/selftest.c                     |  2 +-
>>  lib/random32.c                              |  2 +-
>>  lib/test_objagg.c                           |  2 +-
>>  lib/uuid.c                                  |  2 +-
>>  net/ipv4/route.c                            |  2 +-
>>  net/mac80211/rc80211_minstrel_ht.c          |  2 +-
>>  net/sched/sch_pie.c                         |  2 +-
>>  19 files changed, 24 insertions(+), 24 deletions(-)
>>
>> diff --git a/arch/powerpc/crypto/crc-vpmsum_test.c
>> b/arch/powerpc/crypto/crc-vpmsum_test.c
>> index c1c1ef9457fb..273c527868db 100644
>> --- a/arch/powerpc/crypto/crc-vpmsum_test.c
>> +++ b/arch/powerpc/crypto/crc-vpmsum_test.c
>> @@ -82,7 +82,7 @@ static int __init crc_test_init(void)
>>
>>  			if (len <= offset)
>>  				continue;
>> -			prandom_bytes(data, len);
>> +			get_random_bytes(data, len);
>>  			len -= offset;
>>
>>  			crypto_shash_update(crct10dif_shash, data+offset, len);
>> diff --git a/block/blk-crypto-fallback.c b/block/blk-crypto-fallback.c
>> index 621abd1b0e4d..ad9844c5b40c 100644
>> --- a/block/blk-crypto-fallback.c
>> +++ b/block/blk-crypto-fallback.c
>> @@ -539,7 +539,7 @@ static int blk_crypto_fallback_init(void)
>>  	if (blk_crypto_fallback_inited)
>>  		return 0;
>>
>> -	prandom_bytes(blank_key, BLK_CRYPTO_MAX_KEY_SIZE);
>> +	get_random_bytes(blank_key, BLK_CRYPTO_MAX_KEY_SIZE);
>>
>>  	err = bioset_init(&crypto_bio_split, 64, 0, 0);
>>  	if (err)
>> diff --git a/crypto/async_tx/raid6test.c b/crypto/async_tx/raid6test.c
>> index c9d218e53bcb..f74505f2baf0 100644
>> --- a/crypto/async_tx/raid6test.c
>> +++ b/crypto/async_tx/raid6test.c
>> @@ -37,7 +37,7 @@ static void makedata(int disks)
>>  	int i;
>>
>>  	for (i = 0; i < disks; i++) {
>> -		prandom_bytes(page_address(data[i]), PAGE_SIZE);
>> +		get_random_bytes(page_address(data[i]), PAGE_SIZE);
>>  		dataptrs[i] = data[i];
>>  		dataoffs[i] = 0;
>>  	}
>> diff --git a/drivers/dma/dmatest.c b/drivers/dma/dmatest.c
>> index 9fe2ae794316..ffe621695e47 100644
>> --- a/drivers/dma/dmatest.c
>> +++ b/drivers/dma/dmatest.c
>> @@ -312,7 +312,7 @@ static unsigned long dmatest_random(void)
>>  {
>>  	unsigned long buf;
>>
>> -	prandom_bytes(&buf, sizeof(buf));
>> +	get_random_bytes(&buf, sizeof(buf));
>>  	return buf;
>>  }
>>
>> diff --git a/drivers/mtd/nand/raw/nandsim.c
>> b/drivers/mtd/nand/raw/nandsim.c
>> index 4bdaf4aa7007..c941a5a41ea6 100644
>> --- a/drivers/mtd/nand/raw/nandsim.c
>> +++ b/drivers/mtd/nand/raw/nandsim.c
>> @@ -1393,7 +1393,7 @@ static int ns_do_read_error(struct nandsim *ns, int
>> num)
>>  	unsigned int page_no = ns->regs.row;
>>
>>  	if (ns_read_error(page_no)) {
>> -		prandom_bytes(ns->buf.byte, num);
>> +		get_random_bytes(ns->buf.byte, num);
>>  		NS_WARN("simulating read error in page %u\n", page_no);
>>  		return 1;
>>  	}
>> diff --git a/drivers/mtd/tests/mtd_nandecctest.c
>> b/drivers/mtd/tests/mtd_nandecctest.c
>> index 1c7201b0f372..440988562cfd 100644
>> --- a/drivers/mtd/tests/mtd_nandecctest.c
>> +++ b/drivers/mtd/tests/mtd_nandecctest.c
>> @@ -266,7 +266,7 @@ static int nand_ecc_test_run(const size_t size)
>>  		goto error;
>>  	}
>>
>> -	prandom_bytes(correct_data, size);
>> +	get_random_bytes(correct_data, size);
>>  	ecc_sw_hamming_calculate(correct_data, size, correct_ecc, sm_order);
>>  	for (i = 0; i < ARRAY_SIZE(nand_ecc_test); i++) {
>>  		nand_ecc_test[i].prepare(error_data, error_ecc,
>> diff --git a/drivers/mtd/tests/speedtest.c
>> b/drivers/mtd/tests/speedtest.c
>> index c9ec7086bfa1..075bce32caa5 100644
>> --- a/drivers/mtd/tests/speedtest.c
>> +++ b/drivers/mtd/tests/speedtest.c
>> @@ -223,7 +223,7 @@ static int __init mtd_speedtest_init(void)
>>  	if (!iobuf)
>>  		goto out;
>>
>> -	prandom_bytes(iobuf, mtd->erasesize);
>> +	get_random_bytes(iobuf, mtd->erasesize);
>>
>>  	bbt = kzalloc(ebcnt, GFP_KERNEL);
>>  	if (!bbt)
>> diff --git a/drivers/mtd/tests/stresstest.c
>> b/drivers/mtd/tests/stresstest.c
>> index d2faaca7f19d..75b6ddc5dc4d 100644
>> --- a/drivers/mtd/tests/stresstest.c
>> +++ b/drivers/mtd/tests/stresstest.c
>> @@ -183,7 +183,7 @@ static int __init mtd_stresstest_init(void)
>>  		goto out;
>>  	for (i = 0; i < ebcnt; i++)
>>  		offsets[i] = mtd->erasesize;
>> -	prandom_bytes(writebuf, bufsize);
>> +	get_random_bytes(writebuf, bufsize);
>>
>>  	bbt = kzalloc(ebcnt, GFP_KERNEL);
>>  	if (!bbt)
>> diff --git a/drivers/net/ethernet/broadcom/bnxt/bnxt.c
>> b/drivers/net/ethernet/broadcom/bnxt/bnxt.c
>> index 96da0ba3d507..354953df46a1 100644
>> --- a/drivers/net/ethernet/broadcom/bnxt/bnxt.c
>> +++ b/drivers/net/ethernet/broadcom/bnxt/bnxt.c
>> @@ -3874,7 +3874,7 @@ static void bnxt_init_vnics(struct bnxt *bp)
>>
>>  		if (bp->vnic_info[i].rss_hash_key) {
>>  			if (i == 0)
>> -				prandom_bytes(vnic->rss_hash_key,
>> +				get_random_bytes(vnic->rss_hash_key,
>>  					      HW_HASH_KEY_SIZE);
>>  			else
>>  				memcpy(vnic->rss_hash_key,
>> diff --git a/drivers/net/ethernet/rocker/rocker_main.c
>> b/drivers/net/ethernet/rocker/rocker_main.c
>> index 8c3bbafabb07..cd4488efe0a4 100644
>> --- a/drivers/net/ethernet/rocker/rocker_main.c
>> +++ b/drivers/net/ethernet/rocker/rocker_main.c
>> @@ -224,7 +224,7 @@ static int rocker_dma_test_offset(const struct rocker
>> *rocker,
>>  	if (err)
>>  		goto unmap;
>>
>> -	prandom_bytes(buf, ROCKER_TEST_DMA_BUF_SIZE);
>> +	get_random_bytes(buf, ROCKER_TEST_DMA_BUF_SIZE);
>>  	for (i = 0; i < ROCKER_TEST_DMA_BUF_SIZE; i++)
>>  		expect[i] = ~buf[i];
>>  	err = rocker_dma_test_one(rocker, wait, ROCKER_TEST_DMA_CTRL_INVERT,
>> diff --git a/drivers/net/wireguard/selftest/allowedips.c
>> b/drivers/net/wireguard/selftest/allowedips.c
>> index dd897c0740a2..19eac00b2381 100644
>> --- a/drivers/net/wireguard/selftest/allowedips.c
>> +++ b/drivers/net/wireguard/selftest/allowedips.c
>> @@ -284,7 +284,7 @@ static __init bool randomized_test(void)
>>  	mutex_lock(&mutex);
>>
>>  	for (i = 0; i < NUM_RAND_ROUTES; ++i) {
>> -		prandom_bytes(ip, 4);
>> +		get_random_bytes(ip, 4);
>>  		cidr = prandom_u32_max(32) + 1;
>>  		peer = peers[prandom_u32_max(NUM_PEERS)];
>>  		if (wg_allowedips_insert_v4(&t, (struct in_addr *)ip, cidr,
>> @@ -299,7 +299,7 @@ static __init bool randomized_test(void)
>>  		}
>>  		for (j = 0; j < NUM_MUTATED_ROUTES; ++j) {
>>  			memcpy(mutated, ip, 4);
>> -			prandom_bytes(mutate_mask, 4);
>> +			get_random_bytes(mutate_mask, 4);
>>  			mutate_amount = prandom_u32_max(32);
>>  			for (k = 0; k < mutate_amount / 8; ++k)
>>  				mutate_mask[k] = 0xff;
>> @@ -328,7 +328,7 @@ static __init bool randomized_test(void)
>>  	}
>>
>>  	for (i = 0; i < NUM_RAND_ROUTES; ++i) {
>> -		prandom_bytes(ip, 16);
>> +		get_random_bytes(ip, 16);
>>  		cidr = prandom_u32_max(128) + 1;
>>  		peer = peers[prandom_u32_max(NUM_PEERS)];
>>  		if (wg_allowedips_insert_v6(&t, (struct in6_addr *)ip, cidr,
>> @@ -343,7 +343,7 @@ static __init bool randomized_test(void)
>>  		}
>>  		for (j = 0; j < NUM_MUTATED_ROUTES; ++j) {
>>  			memcpy(mutated, ip, 16);
>> -			prandom_bytes(mutate_mask, 16);
>> +			get_random_bytes(mutate_mask, 16);
>>  			mutate_amount = prandom_u32_max(128);
>>  			for (k = 0; k < mutate_amount / 8; ++k)
>>  				mutate_mask[k] = 0xff;
>> @@ -381,13 +381,13 @@ static __init bool randomized_test(void)
>>
>>  	for (j = 0;; ++j) {
>>  		for (i = 0; i < NUM_QUERIES; ++i) {
>> -			prandom_bytes(ip, 4);
>> +			get_random_bytes(ip, 4);
>>  			if (lookup(t.root4, 32, ip) != horrible_allowedips_lookup_v4(&h,
>> (struct in_addr *)ip)) {
>>  				horrible_allowedips_lookup_v4(&h, (struct in_addr *)ip);
>>  				pr_err("allowedips random v4 self-test: FAIL\n");
>>  				goto free;
>>  			}
>> -			prandom_bytes(ip, 16);
>> +			get_random_bytes(ip, 16);
>>  			if (lookup(t.root6, 128, ip) != horrible_allowedips_lookup_v6(&h,
>> (struct in6_addr *)ip)) {
>>  				pr_err("allowedips random v6 self-test: FAIL\n");
>>  				goto free;
>> diff --git a/fs/ubifs/debug.c b/fs/ubifs/debug.c
>> index f4d3b568aa64..3f128b9fdfbb 100644
>> --- a/fs/ubifs/debug.c
>> +++ b/fs/ubifs/debug.c
>> @@ -2581,7 +2581,7 @@ static int corrupt_data(const struct ubifs_info *c,
>> const void *buf,
>>  	if (ffs)
>>  		memset(p + from, 0xFF, to - from);
>>  	else
>> -		prandom_bytes(p + from, to - from);
>> +		get_random_bytes(p + from, to - from);
>>
>>  	return to;
>>  }
>> diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
>> index 58b94deae5c0..00cdf8fa5693 100644
>> --- a/kernel/kcsan/selftest.c
>> +++ b/kernel/kcsan/selftest.c
>> @@ -46,7 +46,7 @@ static bool __init test_encode_decode(void)
>>  		unsigned long addr;
>>  		size_t verif_size;
>>
>> -		prandom_bytes(&addr, sizeof(addr));
>> +		get_random_bytes(&addr, sizeof(addr));
>>  		if (addr < PAGE_SIZE)
>>  			addr = PAGE_SIZE;
>>
>> diff --git a/lib/random32.c b/lib/random32.c
>> index d4f19e1a69d4..32060b852668 100644
>> --- a/lib/random32.c
>> +++ b/lib/random32.c
>> @@ -69,7 +69,7 @@ EXPORT_SYMBOL(prandom_u32_state);
>>   *	@bytes: the requested number of bytes
>>   *
>>   *	This is used for pseudo-randomness with no outside seeding.
>> - *	For more random results, use prandom_bytes().
>> + *	For more random results, use get_random_bytes().
>>   */
>>  void prandom_bytes_state(struct rnd_state *state, void *buf, size_t
>> bytes)
>>  {
>> diff --git a/lib/test_objagg.c b/lib/test_objagg.c
>> index da137939a410..c0c957c50635 100644
>> --- a/lib/test_objagg.c
>> +++ b/lib/test_objagg.c
>> @@ -157,7 +157,7 @@ static int test_nodelta_obj_get(struct world *world,
>> struct objagg *objagg,
>>  	int err;
>>
>>  	if (should_create_root)
>> -		prandom_bytes(world->next_root_buf,
>> +		get_random_bytes(world->next_root_buf,
>>  			      sizeof(world->next_root_buf));
>>
>>  	objagg_obj = world_obj_get(world, objagg, key_id);
>> diff --git a/lib/uuid.c b/lib/uuid.c
>> index 562d53977cab..e309b4c5be3d 100644
>> --- a/lib/uuid.c
>> +++ b/lib/uuid.c
>> @@ -52,7 +52,7 @@ EXPORT_SYMBOL(generate_random_guid);
>>
>>  static void __uuid_gen_common(__u8 b[16])
>>  {
>> -	prandom_bytes(b, 16);
>> +	get_random_bytes(b, 16);
>>  	/* reversion 0b10 */
>>  	b[8] = (b[8] & 0x3F) | 0x80;
>>  }
>> diff --git a/net/ipv4/route.c b/net/ipv4/route.c
>> index 1a37a07c7163..cd1fa9f70f1a 100644
>> --- a/net/ipv4/route.c
>> +++ b/net/ipv4/route.c
>> @@ -3719,7 +3719,7 @@ int __init ip_rt_init(void)
>>
>>  	ip_idents = idents_hash;
>>
>> -	prandom_bytes(ip_idents, (ip_idents_mask + 1) * sizeof(*ip_idents));
>> +	get_random_bytes(ip_idents, (ip_idents_mask + 1) * sizeof(*ip_idents));
>>
>>  	ip_tstamps = idents_hash + (ip_idents_mask + 1) * sizeof(*ip_idents);
>>
>> diff --git a/net/mac80211/rc80211_minstrel_ht.c
>> b/net/mac80211/rc80211_minstrel_ht.c
>> index 5f27e6746762..39fb4e2d141a 100644
>> --- a/net/mac80211/rc80211_minstrel_ht.c
>> +++ b/net/mac80211/rc80211_minstrel_ht.c
>> @@ -2033,7 +2033,7 @@ static void __init init_sample_table(void)
>>
>>  	memset(sample_table, 0xff, sizeof(sample_table));
>>  	for (col = 0; col < SAMPLE_COLUMNS; col++) {
>> -		prandom_bytes(rnd, sizeof(rnd));
>> +		get_random_bytes(rnd, sizeof(rnd));
>>  		for (i = 0; i < MCS_GROUP_RATES; i++) {
>>  			new_idx = (i + rnd[i]) % MCS_GROUP_RATES;
>>  			while (sample_table[col][new_idx] != 0xff)
>> diff --git a/net/sched/sch_pie.c b/net/sched/sch_pie.c
>> index 5a457ff61acd..66b2b23e8cd1 100644
>> --- a/net/sched/sch_pie.c
>> +++ b/net/sched/sch_pie.c
>> @@ -72,7 +72,7 @@ bool pie_drop_early(struct Qdisc *sch, struct pie_params
>> *params,
>>  	if (vars->accu_prob >= (MAX_PROB / 2) * 17)
>>  		return true;
>>
>> -	prandom_bytes(&rnd, 8);
>> +	get_random_bytes(&rnd, 8);
>>  	if ((rnd >> BITS_PER_BYTE) < local_prob) {
>>  		vars->accu_prob = 0;
>>  		return true;
>
> Are there cases where calling get_random_bytes() is not possible?

Yes, but that has absolutely zero bearing whatsoever on this patch
4/5, considering the code this generates is identical. If you have
serious questions about contexts the rng can operate in, please start
another thread, where you can flesh out that inquiry a but more.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9rG6GAK6k-GZCBwUR-r2PLDipm--utApBtBHHRveCFEqA%40mail.gmail.com.
