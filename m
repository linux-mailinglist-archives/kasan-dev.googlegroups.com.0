Return-Path: <kasan-dev+bncBD7LZ45K3ECBBQNL7S6QMGQEFUQWBYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 78FC2A460A3
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 14:23:15 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2fe98fad333sf296526a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 05:23:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740576193; cv=pass;
        d=google.com; s=arc-20240605;
        b=JFHrFsUqIGtIVxd5LRvF8Pd4NgeOq75hrgDHlQhL7VSaDiUoPGSTjH4otQnEVv7zkv
         on1AVa07XPgMVRaqbRpYPUAGNDiVYKzl2Tmu5YN96RrH7sj+IR9+Itz4qk6XRuC1UzL+
         qK6okay1pOZ4QV1AZ8VGN2pp+kZQzMgAD8vawJz/wWjGsymRSfCU5AiFyaWy1PjlAc9E
         OFLvfslJPVjsB42n7p8fBd6M7caFX3SsreX3balEDqA2djZLAwGtxRb+/Hs0E0Ur4x7I
         USmHlFA1mdM1fkrdjN4lHDgDFSbZKeyqkiAWhtJ5yKRxmKqXo7aWE0b24VdVWgswdLe6
         F4Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=WRdHNz304rdxalWSae75V0SHQAqw+eDSgXtFZfJEs50=;
        fh=lMfE1z1Lt5CqgeN6UUIYJxuRrnSKAIjQ+fGnK0vBtWg=;
        b=I0mkxHqi16xEWLfzM7CyiZg7691DeQBvN+pqdFsj6dJK2VDR24icsBwnpLeZ/6pIhN
         S9Lbt5fc6E+5MwZplo1jR/ZSzscmB82x80/JpA6wIdUmz5kPhvQRRBk6Aku719BEm58Y
         9uH98HrYwIl1c/GcqyHwWz48aszAYxxso0lDC2VWEn2zped4TbiT7v0H+e2BiYwFVwme
         tdhfSmRxLQldJcSD7LGzlTpxgg8ErR4R4F+xh1WQ+RU+Jb9KJB8daxH4HGHCYqhxKwfc
         TWQCxpcqDt5Lcj09lZ3A9ogh9DvswaiG0NGRNwpwhvSovunkkU9m8thewv08gkxDmutv
         t3Ig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bkECZJmp;
       spf=pass (google.com: domain of mingo@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=mingo@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740576193; x=1741180993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=WRdHNz304rdxalWSae75V0SHQAqw+eDSgXtFZfJEs50=;
        b=cuGPVocpOQ6PKfoOC5sywIrcorfXLNdUvNItugS9huUnDd5bfPAzaT4Yz18ljKC8vV
         mNRKzlduV8tjb1nYB93hQYyVKCd3+beBK52ZRpmtY2g9EDD9eHwTXSQ02WDzhj37TzmV
         WivMrA/kJ3zqrZLD6m4lWD43lzZAdRjDDTfNo4xG6Yqpuna2C/Oesk9yssR8r2MC1LJa
         7zo6EfjurgV+qiJZJ0FB4SAY2c4a+FWTOKNBm9UefY/g3C2LRTrTwcB+g6U1K+2E1U1S
         VrbAkZMgyuVnn+aHplcef+klJgYfPVxULfsSGtgOpYli2csjBwAx9QbiMQz0TuxupFWJ
         rDNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740576193; x=1741180993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WRdHNz304rdxalWSae75V0SHQAqw+eDSgXtFZfJEs50=;
        b=GqY5BAwtO8vgWC7eYuGA7e36HZggZE8qejCDrYdmgb7OkSA8rBiSEpQ5Z/uOTw/VXG
         /eYxqfDiPR0BGRTYkXxq3leu1x0XT9SQfoI4mj37Nf/vAdMkDLjjtd+uleYkWdfcsg44
         O8iithMj99oRR6wYwemzYXL5UfSN115fxxCBpyKi/IqzdE2Dtmzv5DYe07kJ7H+r2NA/
         VrJMnmXUjlQxcrvvPldPlCQjbW+ItZsAnfc8OTrexiT6csPC+viFkoEH3r3oseMjHaRI
         oHomp6TFztT3EQzOgWEC80NYMpPRaX9HdcxYmrw9T5o+IiJjOFr6dTrUkD1E7s2Bj0at
         ai8A==
X-Forwarded-Encrypted: i=2; AJvYcCVy7jBca+BUTEPEfTabX/dDbA1poG7GGNP2fIxmj8SUoSjrl0ao5le+K9tL01QKGx9Zx7ZW7g==@lfdr.de
X-Gm-Message-State: AOJu0Yyn66XFKS3IgPnD0FD143PoeksT/a9HxeGifrX46UDg/koxuZzl
	4qOS3MyrBSV2P4prJDMYSqXgW4i2FrQXrdeWmRUzB+VmacfVzsym
X-Google-Smtp-Source: AGHT+IGEA/Hg3qVfSQYtXh9KunnI8c7QKBqO8JXNpRvkEVxo0zD6w3WTjAjKdv5QXAz/BpImiIDoaQ==
X-Received: by 2002:a17:90b:2250:b0:2f6:d266:f462 with SMTP id 98e67ed59e1d1-2fce7b242f5mr34180782a91.35.1740576193512;
        Wed, 26 Feb 2025 05:23:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEU4tvYul/o7LcGLuSzUa6L/F2EIOe4HxlfeThv4gBuJQ==
Received: by 2002:a17:90a:110:b0:2fa:5303:b1e3 with SMTP id
 98e67ed59e1d1-2fcd046d14els1510973a91.1.-pod-prod-01-us; Wed, 26 Feb 2025
 05:23:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW/s6Yth+2w58Co2M0o9Wy0/dR+39FyYvQ36HucmKMbjLzYm1WNVXiISCH28+tLq22JZjsOInleH0g=@googlegroups.com
X-Received: by 2002:a17:902:d2cd:b0:220:c911:3f60 with SMTP id d9443c01a7336-221a00260e0mr343560155ad.47.1740576192303;
        Wed, 26 Feb 2025 05:23:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740576192; cv=none;
        d=google.com; s=arc-20240605;
        b=kQMBBF/idC5b8DmitRY2T5hEENmAx5lGApqHLq5qYbfOizHUBXuODa0l3ZDb6KAygw
         by5LTnEj1xpPZxhGUBYFn6Jk2qtULH+JvvWgPBBRfLLvFu8RWjUzEAGVxPjOOyDjrupF
         gbJ2pYzzt53Mow0PcqT2z4MKFOQsSca5g9Q8m7eFPHPJYXFrTtMINs7AoGcRp8t0ileZ
         id+hkdVi/XpssW5j2ANmet7jVCjva32vwK/HAkccw/fYr2jZcvMYA5NfcZAWF/3yRVL0
         elDLdL50mVCCuhVWGqUU9o65sbDKa65eThUWyLoz/9YtiF7kZR7XmcUumjlajY74nUJo
         HPcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HCKfrFYRRQmKsYa/z4pOerVlFi/2lb9UNKaw5O+iG2I=;
        fh=2d0nZevdMtIC4m/RWoRSoCnOm7AX1TuZZsuoyOcEFFA=;
        b=C49HaCWvYOJipGqwWqMTuw+B1W2wHgxlnMVcOYnLaI0uWFudZBL2qt9BwdbRWAetyv
         CboMyFs3bucLqkKAqNeG8yXhGSKrMEFRGmWRCuxAH2WWBzL18UW19K2V5z4DTnbwZfoi
         2vXQtTSMJxUD1cHOpQ2OnHyFCKRtw66tGGSZNdV7fh3ZM9M1Nz5qQfmgUkXaAiYuGAao
         6FjamtQSTN4kHpsLDLEE9jdscEf6nzQ7pVLafCrTpyqIHQ614FT+ropIm/97VMH2ci9U
         eut2wD6l048IC1pVciS43yNBnaBxlt+dV4zdWeGDNMbe2Jt+cJ7eDSIXBZNVc8O+Lk3C
         N/cg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bkECZJmp;
       spf=pass (google.com: domain of mingo@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=mingo@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2fe6cf92968si210840a91.0.2025.02.26.05.23.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2025 05:23:12 -0800 (PST)
Received-SPF: pass (google.com: domain of mingo@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 97EF66123E;
	Wed, 26 Feb 2025 13:23:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5B1F9C4CEE9;
	Wed, 26 Feb 2025 13:23:09 +0000 (UTC)
Date: Wed, 26 Feb 2025 14:23:03 +0100
From: "'Ingo Molnar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Benjamin Berg <benjamin@sipsolutions.net>
Cc: linux-arch@vger.kernel.org, linux-um@lists.infradead.org,
	x86@kernel.org, briannorris@chromium.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 3/3] x86: avoid copying dynamic FP state from init_task
Message-ID: <Z78Vt8yCcPrFQeqo@gmail.com>
References: <20241217202745.1402932-1-benjamin@sipsolutions.net>
 <20241217202745.1402932-4-benjamin@sipsolutions.net>
 <Z78SVdv5YKie-Mcp@gmail.com>
 <159a83bf5457edbabcc1e88ee5ab98cf58ca6cb0.camel@sipsolutions.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <159a83bf5457edbabcc1e88ee5ab98cf58ca6cb0.camel@sipsolutions.net>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bkECZJmp;       spf=pass
 (google.com: domain of mingo@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=mingo@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Ingo Molnar <mingo@kernel.org>
Reply-To: Ingo Molnar <mingo@kernel.org>
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


* Benjamin Berg <benjamin@sipsolutions.net> wrote:

> > Note that this patch, while it still applies cleanly, crashes/hangs 
> > the x86-64 defconfig kernel bootup in the early boot phase in a KVM 
> > guest bootup.
> 
> Oh, outch. It seems that arch_task_struct_size can actually become 
> smaller than sizeof(init_task) if the CPU does not have certain 
> features.
> 
> See fpu__init_task_struct_size, which does:
> 
>   int task_size = sizeof(struct task_struct);
>   task_size -= sizeof(current->thread.fpu.__fpstate.regs);
>   task_size += fpu_kernel_cfg.default_size;
> 
> I'll submit a new version of the patch and then also switch to use
> memcpy_and_pad.

Thank you!

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z78Vt8yCcPrFQeqo%40gmail.com.
