Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBQOT57BAMGQEKAICKUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A47DDAE828A
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 14:21:25 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-453804ee4dfsf7479085e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 05:21:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750854082; cv=pass;
        d=google.com; s=arc-20240605;
        b=UNv19XjUl7SpfL1LJ3XUVg/Me7wkx7vShwGpeJCfgErt9PQOWQ3flkIvOhkFt3PGLs
         WgDeHUDDWFdDMjtHPgMaedaH84+62YoFfjGQ7VH8HllZKYQWibJece8RMcYZVrou/5Xv
         uwGJzAg3MN5g6QrHiUutFakP5jFZRa90YsZPPQ46LKdEFHDVxIk5ymC5bBJK4aOVa2se
         7CH/Myriw3zagYIluM+vEH8ODE7Z35WliLdaYOAxiiAiPY8XweEhw5zZ0zCiVonNCQui
         psPgJHodODU+Jhb+3TomniaR7E7NudnAFslSO88dQyMl477/tdOFf4hcLlnYtzPUey/6
         q7Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=3sB3cGJf2ApDPAGSqUEp4/FgQRQqLQnS7hLhLCo2Zrk=;
        fh=e+/0uouXOsfTO2NxsGq2J1zaIL/k90yVkW3T5XYlouQ=;
        b=E65Bmt6XRKmkS23S8/+5SrfyQ2SwAfq3YKBgDRgdsyfysRvz+bDw1oDSevJNsqX5zr
         7c8GoN8qlnYqJOlvqH0z289BDdvsNnNdiyZ+sJ3VHG4KVSsyD0Bagp8QnIRz+5T44UN7
         k1Dm+cN2M8gPtTEFIUKbxFEKWn6xvQyP3leie9GcUcMae3HATvNXXffcZxf4DOUs86+F
         3pkmRCdjRe5YqZ/X+daLPtaXwQPVChCAkcpob40aq5X7ZJnR9hZ3qpqlLQ5sjRve7TzI
         thirET+mdaIPOOJadPfKGW/ToYouFJtQvNrap6jlH4mIEeSzJ/Kso2wOHk0KkyxB+wHg
         3XSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=QszXxUHP;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750854082; x=1751458882; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3sB3cGJf2ApDPAGSqUEp4/FgQRQqLQnS7hLhLCo2Zrk=;
        b=jy3xgpUGRy0+WAJ5r+BPZ9ZscXeyMzr8Tc4ByH06XubVl0/yogVnlE5LAGtoIrTGby
         NwohpeB/bUwoZoJw4G662hOYdMhFKK4KmGsHAe6LEPiMBINWogkw8gldAgXiHEDFVQTV
         RdYV4E3y9NDBSaZxCi9DXwao+MNQQso9V1hH2Cb6fay+tX8nWOMECZSm2rLOgb1yeH9k
         otBiYzlTJp52Sedu8REUlQ+mZ6LAYnKqbtg56ItfDY+o5+6s3Dh20KLRwyDsqtLVJ4Si
         1cPPnIAjzqj3Dt+1LsjCNU0P/XpBI4kB8sBTonaUjzNeulQa0mHlrCWG3qQOLa9Uw0fQ
         GELA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750854082; x=1751458882;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=3sB3cGJf2ApDPAGSqUEp4/FgQRQqLQnS7hLhLCo2Zrk=;
        b=UFMjNwtdKGOyaIp15+oYjMxjOZ4LzZD4SBD9V8i0VrDpvsQlt7ClsBpmokz8nKDNgU
         xD9265mVFu+tn52VFCY6mnBFrcb/RVaKcuxFwMuJDKGMQhGwHu44DGtumCOFFdSw8jOL
         L2HzEdrwh+X63Uvxwmmg0qJLX0ytHmYHPL4JK62NeRx7XlNvzeMExHW4iQsGFY4+exMF
         gIv4J8kasGkN5aqv6r4GmvKESIAKPmuwooRdwehHYq6aE05mHeTvSaba1fzPxiXhoPVH
         q0zN3sbJNNfvbPVKkYCoYwEaxCDacmqt8rnarifu1bFUWRXEGAUjAoSsOLzowvkhxiiT
         decQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdq7gHkRNqvnP1h40e8RzjADo5shBidA6eONCiEvOQUigv9NZgXpNI7gkLxhQ5WTGLdd+gPg==@lfdr.de
X-Gm-Message-State: AOJu0YybeC6iJBYbuGD83MUg5lIMtHWAjp664i7lC/9jfzaSz82//hGN
	Vvo1kkiQVeQleeOj/BN3kC0nuh6Ubw1oXNqZc4Pn19PPiNgE/ZrnMMna
X-Google-Smtp-Source: AGHT+IFFoUZ1H3O5hKog2t/XTgit4V0Cx30h/D1FzHyBs9YFA0MXiL21Wt1Z8DoCoU6Szo48FAcmbw==
X-Received: by 2002:a05:6000:4b04:b0:3a6:e1bd:6102 with SMTP id ffacd0b85a97d-3a6ed6751fbmr2074907f8f.49.1750854082318;
        Wed, 25 Jun 2025 05:21:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf3R/QUOMe+pCNcFEfueP63hvuSw/zY8wUgl0DsAP7WcQ==
Received: by 2002:a05:6000:400f:b0:3a5:2bd4:9d8a with SMTP id
 ffacd0b85a97d-3a6ca0b7e02ls2908297f8f.2.-pod-prod-08-eu; Wed, 25 Jun 2025
 05:21:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVb6m3fvZA8/iiZ2dFw2H6vv2kI565uRZB0Y+rSaJXjKc4bw4VUcIUtLPfR0yka+bmz+hlKoGLIy74=@googlegroups.com
X-Received: by 2002:a05:6000:40c7:b0:3a6:d6e4:dffd with SMTP id ffacd0b85a97d-3a6ed628014mr2654867f8f.14.1750854080104;
        Wed, 25 Jun 2025 05:21:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750854080; cv=none;
        d=google.com; s=arc-20240605;
        b=YVwLr1qFnnFs1WhIxnL+mtLlD+dU/89RgoqJae7SuaugvYK2lSTDUxysSsbbFQwBOa
         VW/e2pwMmhE+OOJVlpNlidPijd+y6H5qRmmlyHlQcLEKj3JMoipcYoYr290UXNIPOcsh
         ouCO8EhMIYjWZFO0+3swAPCthr7eUiUV7+18yPguSBvR8ZCjRIccpDYUEy4cLba/hhW/
         2s3ic6H/1p94WgY6ySlZmF6MiCctZ4BSReLdLX/ya+tTapYK7syHBx38xykfBIXTA9gG
         Nl5LNfbBvnpzvKA8dO3xKtvWnYclC14MrtH0Qe2wS0uwj5+DRjn1qrpCCUTHQTfL1b4S
         zPEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=j9lxAywOv5yt4LeQ6A3AxT624fpEB3GL4l9rgh6gKj8=;
        fh=RB1f9VG+8mtrjOXUHwBPuZog0thMw/jC9NhG8ED26vY=;
        b=ilNgltKwhrfx5sk2ChYvBBwD+PY1zjfWJ0ud60RWcY5EXODVqyw2X28nQ1YDUZs+GR
         kJMDRFxnqlSyKKtas/FtGi2jzmYWOW2gNiZCFRpWuVk06ES4SlsNftfbakkLYYsIpkH6
         +CE5YOSQpgxA3NmstDuRjYxE+NT8k9aURTUJysw+IDD1yiDW+qNMu3rzJFBEG5VAaGYt
         6Ykd1ryu6ckDL+MBJeGGI1lwhseT/CC5Xj8BDc3uQHd5Ju4SJVJ5U+9wNhiMF+AZ/ccB
         cTrVjZh1ggZZaTUH0s4xHbreZtTsMEbdyupfvLdDMYW4U2koyjAWihtgSwucDx993M1m
         c8Xg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=QszXxUHP;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a6e80a9615si66348f8f.3.2025.06.25.05.21.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 05:21:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98.2)
	(envelope-from <johannes@sipsolutions.net>)
	id 1uUP7I-00000009xkX-2M7X;
	Wed, 25 Jun 2025 14:20:40 +0200
Message-ID: <dd87fa28e596126536d79281e87e2e0f52d9dfd4.camel@sipsolutions.net>
Subject: Re: [PATCH 6/9] kasan/um: call kasan_init_generic in kasan_init
From: Johannes Berg <johannes@sipsolutions.net>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com, 
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, catalin.marinas@arm.com, will@kernel.org, 
	chenhuacai@kernel.org, kernel@xen0n.name, maddy@linux.ibm.com,
 mpe@ellerman.id.au, 	npiggin@gmail.com, christophe.leroy@csgroup.eu,
 hca@linux.ibm.com, 	gor@linux.ibm.com, agordeev@linux.ibm.com,
 borntraeger@linux.ibm.com, 	svens@linux.ibm.com, richard@nod.at,
 anton.ivanov@cambridgegreys.com, 	dave.hansen@linux.intel.com,
 luto@kernel.org, peterz@infradead.org, 	tglx@linutronix.de,
 mingo@redhat.com, bp@alien8.de, x86@kernel.org, hpa@zytor.com, 
	chris@zankel.net, jcmvbkbc@gmail.com, akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com, geert@linux-m68k.org, rppt@kernel.org, 
	tiwei.btw@antgroup.com, richard.weiyang@gmail.com, benjamin.berg@intel.com,
 	kevin.brodsky@arm.com, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Date: Wed, 25 Jun 2025 14:20:38 +0200
In-Reply-To: <20250625095224.118679-7-snovitoll@gmail.com> (sfid-20250625_115328_891177_CC2D325A)
References: <20250625095224.118679-1-snovitoll@gmail.com>
	 <20250625095224.118679-7-snovitoll@gmail.com>
	 (sfid-20250625_115328_891177_CC2D325A)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.2 (3.56.2-1.fc42)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=QszXxUHP;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Wed, 2025-06-25 at 14:52 +0500, Sabyrzhan Tasbolatov wrote:
> Call kasan_init_generic() which enables the static flag
> to mark generic KASAN initialized, otherwise it's an inline stub.
> 
> Delete the key `kasan_um_is_ready` in favor of the global static flag in
> linux/kasan-enabled.h which is enabled with kasan_init_generic().
> 
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>

Looks fine, I guess. You can test/build it without qemu - on x86 - by
using 'make ARCH=um' or so.

I'm assuming it'll go through some kasan tree since there are
dependencies:

Acked-by: Johannes Berg <johannes@sipsolutions.net>

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dd87fa28e596126536d79281e87e2e0f52d9dfd4.camel%40sipsolutions.net.
