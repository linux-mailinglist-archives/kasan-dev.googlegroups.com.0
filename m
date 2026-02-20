Return-Path: <kasan-dev+bncBAABBYNY4HGAMGQECFOXR3A@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 3Z8tLWNcmGlRGwMAu9opvQ
	(envelope-from <kasan-dev+bncBAABBYNY4HGAMGQECFOXR3A@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Feb 2026 14:06:43 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 45230167ABC
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Feb 2026 14:06:43 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-385bb7f429csf12308021fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Feb 2026 05:06:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771592802; cv=pass;
        d=google.com; s=arc-20240605;
        b=lWRV/mXXAhzaWSjGZRVHrLRiWm/5kdU+Y4GmGms/nsxYRiNcS6FNwWbpUDsV77v8TM
         yOstSJlIZQ9CV4JDw5famWjideJuBcLPX6eLAOngy5E1YALH0zjQSK+AK/thTRcwxYj6
         i/1rA6ylVhfOkoLVECM5IsWu7VF5TrpDgm8RJ4Pdrrjt/J+QCsrt7WJSUhh5kjAVYkz7
         SOuYoHBKoiuz+XE4Nl7DX5/AjJYNEXbzSudnWcC91qO5CFnU28diXTgPMmxygOR4yrFk
         S4DAp2LxhD1AViByIUMS0Uvzb2g02++MSeW3bP5Bedqg5rTe8kAoYFfCdC8cp/K2D5hI
         Q2Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:references
         :subject:cc:to:from:message-id:date:mime-version:dkim-signature;
        bh=lceUIXiBmofJnPrSTrkdVlHs8ryNmJCJn5YT/CY+IzU=;
        fh=xg/2mcLzNGVyRt2GzxmcTgtK+7/nx2LLFbVUwFwSKOc=;
        b=F/0RH/TsRpfu6CCsKTWwnaG1LGRb4Zcqh5h1/7O11YDyYLc/PVhI87J0ziRVu2AuA6
         9AcA4xyg/KnV74FoF3ZRpQIi3Y62f33kAJ8nW4x3LUbMkZLoKBTCA+/e4z+uTyzD+j2O
         U4dDYp/14eAuKUUSDlqR9QD3of7VAtC9EAgDnyCDi7RKTiiif2F9rMSTVsCa2hO7w/lH
         ZP5YAZxlS6bwkL/+Nw1yL81UuHSlrQ+5Rxz3cOKKbyVRylXpzBk4CjQmdW28xtYelEHG
         rWsO8NIJQJiA6HJrz3Hl0VQ2lI5Wezdfk9UsLLpCDamui6/Qm6azxspI5FWR2STSPvzn
         CmpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tugraz.at header.s=mailrelay header.b=eaazT5cT;
       spf=pass (google.com: domain of ernesto.martinezgarcia@tugraz.at designates 129.27.2.202 as permitted sender) smtp.mailfrom=ernesto.martinezgarcia@tugraz.at;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=tugraz.at
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771592802; x=1772197602; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:subject:cc:to:from:message-id:date:mime-version:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lceUIXiBmofJnPrSTrkdVlHs8ryNmJCJn5YT/CY+IzU=;
        b=xF7cCyERyZc2qqt90ZDM8b9YcsAtWrnJywc1cYLgtz+rhuazElZL19cQ1q6ioD48+3
         6rxrTHQTprr8/AXruIG0GwVzmtaY6Z5FdjUm5Udm5x3aYpY/fDHfiYqyKWhUbqHx5Qu8
         avkdD88CLqVjNvIyvHgsJgeGS2ksgj23EtIMrLo0+F2rTbJyXLssiBCK3dchX4sHm8TV
         fufY3n6LGpUvEGuiOPyY4cRi/kkyn3nSMOIr+0XBi8FmOyD8ok0pIYvqbkapK7PDel67
         SWgjWUwQRgP2OT9TfqdEM04akaivTgaUbkw5ua8hp1upooi86xP0jnh8sMGkPANeQrcM
         7tAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771592802; x=1772197602;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:subject:cc:to:from:message-id:date:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lceUIXiBmofJnPrSTrkdVlHs8ryNmJCJn5YT/CY+IzU=;
        b=finFhcyLIJuRJUtQEHo2fDCEfafKM4wpXi0nvPPvOE9RoYKYAIVdT1AuKeVdhu5Uy1
         3Xqu9n7HgSRQ3cYyi8fJSTe4ncQrYtY5R0Tl3YgHgVTjUMLxQ77tIw6H3MfIMSxB0DDs
         n96oPBVQLSaP6dlJl30OEG7I5r5+SFJoeHSPEFeWLi41UxRMLOeLfBf7R/7oFX8HigLk
         D+7VA1Sj7jDdGASI8VclK6l4BH4vEZfdwRNcwXUvzM0MIACymWZ1+jDgSnXwqdTcBdZa
         lPddkLk/3SyCrXCRAm/tVLWqgJY8sHVmNdUR6bQ2odd02zDx3Rqb0D77AepiuKsTcd8D
         /NaA==
X-Forwarded-Encrypted: i=2; AJvYcCXFootQb7Or8PgSHBpLK52S0867eQgpF/FJ/7PA9bup9VITXtFuDLhadmxxqMiK+Cxh/CgJ6w==@lfdr.de
X-Gm-Message-State: AOJu0YzjfnDJh1CF0XmBa9T5U/vyjn1EwidfAbdDxBpYNjYNkPFVeK28
	FslSRCGFYFsdtWlQgs8wZ6ih6byL1/xTM447v95YO566Q5sjQ+Qc+O2e
X-Received: by 2002:a2e:bc05:0:b0:385:bdfe:2878 with SMTP id 38308e7fff4ca-388c880b931mr5419321fa.24.1771592801745;
        Fri, 20 Feb 2026 05:06:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GOr9TDAtAoczjsOw2NIv3fueMqLDR3kS6oCh6c3KQFog=="
Received: by 2002:a2e:80d8:0:b0:387:1c8c:3ca3 with SMTP id 38308e7fff4ca-3871c8c3d02ls9319551fa.0.-pod-prod-02-eu;
 Fri, 20 Feb 2026 05:06:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUMT3G8v0H4og5BWKeCCxOA9jKa5Kd9iq+ztLUPhgphRnmzYCY6MfhsQgPl+r5dtTV/de2G4M0SbNQ=@googlegroups.com
X-Received: by 2002:a2e:a543:0:b0:385:fbff:ab2e with SMTP id 38308e7fff4ca-388c8792747mr5427701fa.14.1771592799626;
        Fri, 20 Feb 2026 05:06:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771592799; cv=none;
        d=google.com; s=arc-20240605;
        b=JEeIvkV+t//binFCz/IJbD8iaRvjnR0UIK9zPWMm/BZRS2jGtMMh+Ck94oyNGhrVCw
         FrzG2HwaeFiO9BHICFGHF5l3+w/snMySxy9iSeSqbMdk9CZA/cOP14jK+9W7vmDAYH5p
         GeP5Fui1CAPS3wUcUbDE5TmIiPAHB8xSQFLnSSvwTak/nEOJ4/WF428SlfygXoxXvmAq
         oXmNvPV+NAKdGzyun4N1HfIhRdIkoeAPpYF2N1NeNL0bjH1O1nlc0Jin9VhgQ95Jo7sv
         Zqj8qu96xkoROy7PavA/FQDzKa1oorYJ1ZcWLcvPIS/gM9zNa49ASqjyJOzsSMTRUf4R
         acBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:references:subject:cc:to:from:message-id:date
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=TI6pL5l6NcVbZgYUegCvNR9UgHAy5UP25eLtZeSKxCI=;
        fh=EpwIA9MqnHdavKMmXPMqEaklf6G0ieC7sfsZRjldZX0=;
        b=WCQKUMOrGevfDlbPCxzqs/JsNK7Wg6wiawU3HdNdsKGHEO/ffq93r+ByImTSs9lopx
         elb7XIJTALlS5Oro4xiBz6yQRjievhHRRBub47csnKFeIwwy+bMeycXpIG7Jcu0nrI64
         n0CMuYw8QuPpeHDZJpcn7gLmUHTzweLgzLrlPvizHr7sIvNEcm0c1iTpy9KX87tw9jFV
         6LX6yzkRDMLdouvHRHMWWK6lEyheP5VJqcfpwwtCnUiLDm9c0Is2SmZKJ5xYx3pCDIu5
         7fKW7+eZ45vdclROtSH4CXrVRZQ8WMnA61nRrlZZQw7yvVlJGVvacrjDMx3GGy/JgZ6L
         hy3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tugraz.at header.s=mailrelay header.b=eaazT5cT;
       spf=pass (google.com: domain of ernesto.martinezgarcia@tugraz.at designates 129.27.2.202 as permitted sender) smtp.mailfrom=ernesto.martinezgarcia@tugraz.at;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=tugraz.at
Received: from mailrelay.tugraz.at (mailrelay.tugraz.at. [129.27.2.202])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-387068d6304si7697591fa.4.2026.02.20.05.06.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Feb 2026 05:06:39 -0800 (PST)
Received-SPF: pass (google.com: domain of ernesto.martinezgarcia@tugraz.at designates 129.27.2.202 as permitted sender) client-ip=129.27.2.202;
Received: from localhost (unknown [129.27.152.14])
	by mailrelay.tugraz.at (Postfix) with ESMTPSA id 4fHVr968vzz2xP0;
	Fri, 20 Feb 2026 14:06:33 +0100 (CET)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; format=Flowed
Date: Fri, 20 Feb 2026 14:06:33 +0100
Message-Id: <DGJT8E07A37R.2GC7KEDWEI7R@tugraz.at>
From: "'Ernesto Martinez Garcia' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Marco Elver" <elver@google.com>, "Alexander Potapenko"
 <glider@google.com>
Cc: <akpm@linux-foundation.org>, <mark.rutland@arm.com>,
 <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
 <kasan-dev@googlegroups.com>, <pimyn@google.com>, "Andrey Konovalov"
 <andreyknvl@gmail.com>, "Andrey Ryabinin" <ryabinin.a.a@gmail.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, "Ernesto Martinez Garcia"
 <ernesto.martinezgarcia@tugraz.at>, "Greg KH" <gregkh@linuxfoundation.org>,
 "Kees Cook" <kees@kernel.org>, <stable@vger.kernel.org>
Subject: Re: [PATCH v1] mm/kfence: disable KFENCE upon KASAN HW tags
 enablement
X-Mailer: aerc 0.21.0
References: <20260213095410.1862978-1-glider@google.com>
 <CANpmjNPJV-aQKnQ7Mtr6e8_12UR3C2S3abJx_ePFWmS1WV_UVg@mail.gmail.com>
In-Reply-To: <CANpmjNPJV-aQKnQ7Mtr6e8_12UR3C2S3abJx_ePFWmS1WV_UVg@mail.gmail.com>
X-TUG-Backscatter-control: odR5CN6y6BwYAgRjfEtHZQ
X-Spam-Scanner: SpamAssassin 3.003001
X-Spam-Score-relay: 3.6
X-Scanned-By: MIMEDefang 2.74 on 129.27.10.117
X-Original-Sender: ernesto.martinezgarcia@tugraz.at
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tugraz.at header.s=mailrelay header.b=eaazT5cT;       spf=pass
 (google.com: domain of ernesto.martinezgarcia@tugraz.at designates
 129.27.2.202 as permitted sender) smtp.mailfrom=ernesto.martinezgarcia@tugraz.at;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=tugraz.at
X-Original-From: "Ernesto Martinez Garcia" <ernesto.martinezgarcia@tugraz.at>
Reply-To: "Ernesto Martinez Garcia" <ernesto.martinezgarcia@tugraz.at>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.21 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MV_CASE(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[15];
	TAGGED_FROM(0.00)[bncBAABBYNY4HGAMGQECFOXR3A];
	RECEIVED_HELO_LOCALHOST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,arm.com,kvack.org,vger.kernel.org,googlegroups.com,google.com,gmail.com,tugraz.at,linuxfoundation.org,kernel.org];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	HAS_REPLYTO(0.00)[ernesto.martinezgarcia@tugraz.at];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-lj1-x239.google.com:helo,mail-lj1-x239.google.com:rdns,tugraz.at:mid,tugraz.at:replyto]
X-Rspamd-Queue-Id: 45230167ABC
X-Rspamd-Action: no action

On Fri Feb 13, 2026 at 11:50 AM CET, Marco Elver wrote:
> On Fri, 13 Feb 2026 at 10:54, Alexander Potapenko <glider@google.com> wrote:
>>
>> KFENCE does not currently support KASAN hardware tags. As a result, the
>> two features are incompatible when enabled simultaneously.
>>
>> Given that MTE provides deterministic protection and KFENCE is a
>> sampling-based debugging tool, prioritize the stronger hardware
>> protections. Disable KFENCE initialization and free the pre-allocated
>> pool if KASAN hardware tags are detected to ensure the system maintains
>> the security guarantees provided by MTE.
>
> Just double-checking this is explicitly ok: If this is being skipped
> enablement at boot, a user is still free to do 'echo 123 >
> /sys/module/kfence/parameters/sample_interval' to re-enable KFENCE? In
> my opinion, this should be allowed.

Should work, as the late enable codepath is:

- param_set_sample_interval()
	- kfence_enable_late()
		- kfence_init_late()

While the check is only present at:

- mm_core_init()
	- kfence_alloc_pool_and_metadata()
		- kasan_hw_tags_enabled()

However the late activation triggers BUG_ON or KASAN invalid access
issues at the moment:

	~ # dmesg | grep 'disabled as'
	[    0.000000] kfence: disabled as KASAN HW tags are enabled
	~ # echo 100 > /sys/module/kfence/parameters/sample_interval
	[   30.440993] ==================================================================
	[   30.442418] BUG: KASAN: invalid-access in __memset+0x10/0x20
	[   30.443275] Write at addr f4f00000c2e34000 by task sh/1
	[   30.443420] Pointer tag: [f4], memory tag: [f1]
	[   30.443448] 
	...
	[   30.445742] ==================================================================
	[   30.445946] Disabling lock debugging due to kernel taint
	[   30.459644] kfence: initialized - using 2097152 bytes for 255 objects at 0xf5f00000c1c00000-0xf5f00000c1e00000

Likely because the KFENCE pool/metadata memory is allocated and tagged by MTE:

	[    7.590336] kfence: initialized - using 2097152 bytes for 255 objects at 0xf2f00000c1600000-0xf2f00000c1800000
	...
	[    7.710112] kfence: initialized - using 2097152 bytes for 255 objects at 0xf1f00000c1600000-0xf1f00000c1800000
	...
	[    6.627959] kfence: initialized - using 2097152 bytes for 255 objects at 0xf8f00000c1e00000-0xf8f00000c2000000
	...
	[   19.137156] kfence: initialized - using 2097152 bytes for 255 objects at 0xf3f00000c1e00000-0xf3f00000c2000000

Which seems to be an upstream bug of KFENCE+MTE, as I can reproduce the
same issue on mainline 6.19 without the patch applied:

	# uname -r
	6.19.0
	# cat /proc/cmdline 
	root=/dev/vda console=ttyAMA0 rw rootwait earlycon debug hash_pointers=never kfence.sample_interval=0
	# echo 100 > /sys/module/kfence/parameters/sample_interval 
	[   45.555499] ==================================================================
	[   45.556989] BUG: KASAN: invalid-access in __memset+0x10/0x20
	[   45.557844] Write at addr f8f00000c3032000 by task sh/148
	[   45.558063] Pointer tag: [f8], memory tag: [f4]
	...
	[   45.560695] Disabling lock debugging dHey thank you will take a looksie and tell youe to kernel taint
	[   45.574599] kfence: initialized - using 2097152 bytes for 255 objects at 0xf4f00000c1600000-0xf4f00000c1800000

Disabling and enabling won't trigger as the KFENCE pool is not freed on
disable. To trigger the bug it is required to go through the
kfence_init_late() path: KFENCE disabled at boot time.

	Note: Tested with qemu-system-aarch64 -cpu max -machine virt,mte=on (10.1.3)

Changing kfence_init_late() pool and metadata allocations to
use the __GFP_SKIP_KASAN flag fixes it:

	~ # echo 100 > /sys/module/kfence/parameters/sample_interval
	[   19.488734] kfence: initialized - using 2097152 bytes for 255 objects at 0xfff00000c1600000-0xfff00000c1800000
	~ # cat /sys/kernel/debug/kfence/stats 
	enabled: 1
	currently allocated: 1
	total allocations: 12
	total frees: 11
	...
	~ # echo 0 > /sys/module/kfence/parameters/sample_interval
	[  778.414494] kfence: disabled
	~ # echo 100 > /sys/module/kfence/parameters/sample_interval
	[  784.215866] kfence: re-enabled
	~ # cat /sys/kernel/debug/kfence/stats 
	enabled: 1
	currently allocated: 2
	total allocations: 32
	total frees: 30
	...

But this requires adding __GFP_SKIP_KASAN as allowed in
__alloc_contig_verify_gfp_mask I think. Unsure if there is a cleaner way
of doing it, or if changing __alloc_contig_verify_gfp_mask could break
something else unexpectedly.

I would be happy to try to submit a patch for it :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/DGJT8E07A37R.2GC7KEDWEI7R%40tugraz.at.
