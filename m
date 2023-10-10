Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBINLSSUQMGQEFSHD3BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C26977BF6EB
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 11:13:07 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5056eada207sf5059689e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 02:13:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696929187; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ucf/3M6h+0euXtP9Od6HvhSY5bmCNQkv6EljVsUxcu3oj7tyQEbW0MltqZdC/gaL0D
         w5zk7slc8yZJqJ1mIQCqPPMucQjE4rEo0NT2Fc5CzSBfIgQjeTT5DKYBq4iqzaPPu9uE
         1F7wK5vUklOr++letffySaOxBiO9cA8UjnmXdNOIY4Y8YuWSYLOXaEvEzcGRABGjrbok
         5G780VMTPwm0+YD13Je7C+WTaUbhStWADsaEwLMXRAVwvlV6NDSt6lo9wwKbLb4d0Fwd
         tl/8glEcnhNEgx5z17BJ54gVnzzFsoYJILioRAcU0kpy3zNqN+9+BdxXDR51l2p63Mjq
         KYdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2ywB3d1pI+US9W5S4tXNOUx8HYNtKaAlR6X1CVf0opM=;
        fh=tMvHKGT1+QcASgZQMJhW3iAjRPPaJkqDzc/tI8OKJZo=;
        b=cpq+cqzlaop8PKnwOlAZDWa9FRdzEwAN6f2yCLxn/GzI0w6uZMaltzcrt4am4DZx3V
         x7ZunwWsFLBsdv1So4SdEIJjaJxw+fSJzeDqdg6gq1xKabQ0sh0ELpOqgPe2E/6RpN+k
         ioaG1MWS3RcQDktTKbpx5t2eUUn3Qf7Zc5eI/z2tNYCooubz5nDvOfp0LTPqzlQcBUng
         HnbSoDY0+xrxgEoU00VNgA4E3yMtFtI5OrKbQfeUA4t1TEYREjtuzjPaQj5uu4p60O8F
         J1h/CobISRWNdA5o49vxp4pixAQITOhnaH2sE2T+Z0QHJcwp7s9AhoVlwin/SueSjuub
         4kww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=Dm3EQFpf;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696929187; x=1697533987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2ywB3d1pI+US9W5S4tXNOUx8HYNtKaAlR6X1CVf0opM=;
        b=jipdDrcI2KfklTHapydW3uTeS4z9z8Dt1JXW5EQ8GqZ0DHoiTX3A8IqLl1+eSLhlTF
         qmFc+XUq3IqebTsorQLQjPnh8uOlpurqpG59ZxHOz+WkHlNA1Vy+wA2JGLytPVxEF9du
         7LO285cbzwLivRLAxBH+42iPGTE9L8pg1YTwNqdKyqt9cWnZeecvGKH3Ef61MQIYswMl
         gdGOa0vavVqWgvz4yy11VWsd3mItowRdDGCtycPbraZg/t3wdsJE42X1WcZ7Rq9Mr7+X
         9RsxghzCmuT9lc+r/SmHaHc6m0Zlizj+WXSaXdRRj98BX8MZq2+j09UpZv1Dsqzfz/qN
         uQhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696929187; x=1697533987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2ywB3d1pI+US9W5S4tXNOUx8HYNtKaAlR6X1CVf0opM=;
        b=pFRavLVbxYBJDdAkDlz6tA8IcOu+7PP/yuTOFMaq5eW23oU+2XmBU209zMQv5IfMp+
         3HIATN1AbxvWVA/dR1KEw3jW7t53Khdq/rnbCli9JlpDwxWU0WV2bSJj0F7RGdxlqbsl
         7y/MgyIksr5PhIxpZ7fTibZz9WJg06ZMrqQi7Z64g7aoc3Voe2iDbs335Ldwgma0gn4o
         PzEfexU3UteCZI/3iedJbwzy55kcifjGnSNkxsnkPxitgwTMOQVwHNi1mKRdwXaSvA07
         h9paZdxNiKMS5votwOZzw8v2J6N1vKUW/EcpePAEmKvgfbUNuD2NNKYEmPfPHkbOYOEa
         Yaeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyn71Mh4hEadHe4A7bRODBKN2uDD60jtw1kWQpcCmB46NySCU7l
	YFAeO60eGWNE1g7qeg+9oj3teg==
X-Google-Smtp-Source: AGHT+IHUEkkpqVl0mqNMYAxI2sw9Kg+soimFQJ3rMSt65+6kt8bQpuocEYJ1G9DUjuX8RVobIW+e8A==
X-Received: by 2002:a19:8c14:0:b0:500:78ee:4cd7 with SMTP id o20-20020a198c14000000b0050078ee4cd7mr12909777lfd.23.1696929185937;
        Tue, 10 Oct 2023 02:13:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:32b2:b0:503:7b0:dff0 with SMTP id
 q18-20020a05651232b200b0050307b0dff0ls2313416lfe.0.-pod-prod-04-eu; Tue, 10
 Oct 2023 02:13:03 -0700 (PDT)
X-Received: by 2002:a05:6512:ac5:b0:500:8f66:5941 with SMTP id n5-20020a0565120ac500b005008f665941mr17962386lfu.50.1696929183798;
        Tue, 10 Oct 2023 02:13:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696929183; cv=none;
        d=google.com; s=arc-20160816;
        b=h26CJ9JE2Cl8L9zF7MizB8qfdnSXCzyZg6z5m6Ig12G7S9k/WJrzeyGF792JMULxe/
         W5/0ZN3y2bRwSbrYds1klH7EmWHE/joCyfarC3mP3Td+xfJ9EgbN5B2qIR5aXVS7F9e7
         7JdGoLbI1nRF+835wkVEVycnLlG9Vj+SHtap63/Ce3t21bSf3oHIgm87JW9iw1hoUMtM
         tGNOA1mAvSRYwSkXkwnsfIwJ7SI4oUODCIWkvW2MWLU51edlZW8ckvECP1L5vMgOneep
         eYUIYUB8qtSYajCw8AKdqvDOUbzKjCzvkSijKe33vfTGmKeqAsutRyXi8Q/SJsuOtPiK
         jLdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=r19Pofs5YPEJUqm6xMsNDsii8MPrvf//VmD3Yjpm95U=;
        fh=tMvHKGT1+QcASgZQMJhW3iAjRPPaJkqDzc/tI8OKJZo=;
        b=Wnnpl7Lq0geMVPVYNABoMhd+SKBYnQQnb53GBAmZB0r01wGCvh3HGOrslu8ej8sPnE
         el+IpTeYsFDCyjVVir6g4o7J6SgCrqWBNst0xMb05YdTuYC4qt8wFaDn5ipMukoK1UQX
         Slep3RaQFBXPpl5OV9EYKsz24rpB+WlreJNkBrbLLUZZb48stHzvYSj/Tm6nsGrNAsRW
         o2ppdNNfwP0p//MQFxxJUogtvzVmh0WOM/h+xU4X9ev2PThhFoP9jQCGceyzTbi25TY+
         nYwKCJNcyvrTuNeuzK5L7ej6p2V/CQEotxwMamRYVBgvJ2Jin//LxFiDjGMh/gmW5ZtT
         Xt6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=Dm3EQFpf;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [2a01:4f9:3051:3f93::2])
        by gmr-mx.google.com with ESMTPS id c19-20020a056512325300b00503ce43f46asi480546lfr.11.2023.10.10.02.13.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Oct 2023 02:13:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) client-ip=2a01:4f9:3051:3f93::2;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 0420540E01A5;
	Tue, 10 Oct 2023 09:13:03 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id zIxRtCHyP9KY; Tue, 10 Oct 2023 09:13:01 +0000 (UTC)
Received: from zn.tnic (pd953036a.dip0.t-ipconnect.de [217.83.3.106])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 2137E40E01AA;
	Tue, 10 Oct 2023 09:12:41 +0000 (UTC)
Date: Tue, 10 Oct 2023 11:12:35 +0200
From: Borislav Petkov <bp@alien8.de>
To: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Peter Zijlstra <peterz@infradead.org>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Fei Yang <fei.yang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCH] x86/alternatives: Disable KASAN on text_poke_early() in
 apply_alternatives()
Message-ID: <20231010091235.GFZSUVgzTetLj2K+s8@fat_crate.local>
References: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
 <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
 <20231010084041.ut5sshyrofh27yyx@box.shutemov.name>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231010084041.ut5sshyrofh27yyx@box.shutemov.name>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=Dm3EQFpf;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Tue, Oct 10, 2023 at 11:40:41AM +0300, Kirill A. Shutemov wrote:
> __VIRTUAL_MASK_SHIFT used in many places. I don't think it is good idea to
> give up on patching completely.

Have you even looked at boot_cpu_has()'s asm?

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010091235.GFZSUVgzTetLj2K%2Bs8%40fat_crate.local.
