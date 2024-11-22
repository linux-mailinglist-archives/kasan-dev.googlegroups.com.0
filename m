Return-Path: <kasan-dev+bncBCKLNNXAXYFBBEEDQO5AMGQEJPYJRHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 599C89D6346
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 18:38:26 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2ffa97d9a30sf5732321fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 09:38:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732297106; cv=pass;
        d=google.com; s=arc-20240605;
        b=bf4Afk9XFoPDjDAess7FR/S4AaT5WsXVICYdUgwuNqp6ewHQaB9IKKO8n0HTRurSVe
         3DVHHtXrWDKFS5dZ7Rjg8xCW52/3BtbIWwabjt4jkD8koaOGF6tao/s3S+/YajBTBGU1
         k4VIxOv6AFx+vuvHX54SsDvpi8JpBSvApdQKKiRfH0ivrgDRNdlIoRPBXzstqUmDRW7f
         KV9CbpbiNgDWl4hrU7tH/ZcM70hoHwgoLHYcuKGVGwTYkXC/TLyflCAEbV0Z9yq/5DKQ
         ehKBFLA4FPQSPhX6VT82Yhb0aSFHoHZiVicmZmCLZUYEYXhlRYuA8AV9YglQLYUccM9z
         mrqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=oo8AagCuA+6JjzzIGf9Z9NXzkKknj9w7SNNI81bj2OQ=;
        fh=FvzW36L/E+Bi8q9xQPXV0R+qhCMRCL4eLKH1EFmmxDA=;
        b=Iem0lXMBcrIXAPjHYMuIgxS6xPkaL2czKm/H8vNl7Y8lzvei56dqNtWBh42vMwx1TI
         jwCfA8XThcSMqtMek56AfVsUVI21R9+eSPhRo3/AiaoxzLELem16vyKXHd7Z6n1cHCA6
         Hxfe2KGwz6zLFToSbx5jXDpJTRFBgdk1YwxVfIxOokjep5BvbnFp+nh53MRle1etWtpn
         GViAzVeM8kv1aWG/IMCEo4GPUyJoeYVoiQtUOOnTAN3FDCRwRNv7zDWgs4i3TjUElAml
         1IDRvSjNvjTu681no0jk1QEkOxpncEoShKmcpS9dxuM8qblUXPm+j6c/tYmA8TYQdqmO
         jHSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=AjLurxzS;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732297106; x=1732901906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oo8AagCuA+6JjzzIGf9Z9NXzkKknj9w7SNNI81bj2OQ=;
        b=IzufoPMvDXap50VDABtN+1S1/svZEABBjjNqFUVgCB7vt+YgG17srlI2dr1+PfOZNP
         SXhmjyRWqotenwsJChpoDMLROx5QO/jSdCghVYUnUflAOCQ8F+/Ekev4lhqkfQsAsnQF
         eEu7s4AGIw9MLw4tt4EMzw70GrLB0S6M0LPJuyKoW8A9SUR9YzdH/1ZMgjYibWXX6J3h
         i+R8HzxGz92HyEkaabYys7UI+Ureq2xQS3rRgunYgE4hgK65kPxa9Qioj97i+FIco3oZ
         9XRpYQYmKMUV4dC4S1X9Rkm/gM6t/VvXeidUByYO1Jy5N+GGP+AixcFGt9f03uxzI1zK
         x/EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732297106; x=1732901906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oo8AagCuA+6JjzzIGf9Z9NXzkKknj9w7SNNI81bj2OQ=;
        b=SNOO4fDLHixYXviyYXCMFdeV4A8VWTXJKF+/VFYgh2qckxLmE8i78nYYbzObk7Rox+
         9MsxUvdiiI/CUiboG77XLqwPAVsc/A/mrG1dXKA/1HTKeJBF8jlhFGrb22HErfJg0CTx
         xY9A/aK8yx/sCHe+JAhByoRiEGT0nF/5fHs+M4LmxHYFI9POvIOJj0cEeLd4Flkl/JTa
         jTNId96HLeHgcJbnn+iCuxDl86wdpCbfXiTubdJyKH4FBUXEvSw6LopqU35oaZpKvbVV
         H7pgYso7lAT+s4k7KHohyGiNETMCbTsIIFQwMzDuoIebGYnZblWurpHjTQg5XPiStKaT
         g3Tg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX+E7iqhitngg6kgHhm2AnlTCCjLzU4UM8+DbcMvS8K8bcI513eitUPKzve+x3CSpLcQBnfqw==@lfdr.de
X-Gm-Message-State: AOJu0YxitaKC9LLkyETqqkq2+WD6cSyK6PbotKrhW3kRB/S1ghUNSx4+
	GSmWjBxCyFPlopaHpzxiw9HfUr8qicMXyRSItcjY0ka1oJCtrBj8
X-Google-Smtp-Source: AGHT+IEfLSaortxk9jXHBMLClxGcx94RtVOX25+im2fx29rdFIekeHojZMceMIDvsXJxx7DmzFjFJA==
X-Received: by 2002:a2e:b88f:0:b0:2fa:de52:f03c with SMTP id 38308e7fff4ca-2ffa7148a9fmr24668111fa.5.1732297104966;
        Fri, 22 Nov 2024 09:38:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8a8a:0:b0:2ff:a14b:c292 with SMTP id 38308e7fff4ca-2ffa14bc37bls5181761fa.1.-pod-prod-07-eu;
 Fri, 22 Nov 2024 09:38:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUzE1YKz7Grhd8oLoKoCbSFrr+jLKaJpHLuKbfEQIa61WKUzsffT01nex6FIovgehxKi1ZeH7L9tPE=@googlegroups.com
X-Received: by 2002:a05:651c:1549:b0:2ff:5185:48f3 with SMTP id 38308e7fff4ca-2ffa71f3476mr26589731fa.33.1732297102308;
        Fri, 22 Nov 2024 09:38:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732297102; cv=none;
        d=google.com; s=arc-20240605;
        b=HzM/qbxp64emtrpDvXr/94Dpo2yMkwfzpFli3Xh7OY/MlKgzVx400eBf4akhLhpoke
         3kltL7PNUJdz2qYcGtlaB4VRRhedv6601kj9+muT08Rqd8CEuxDgIQ+60Fb2wmvqy+vz
         B8gJw10v5SnRW22Y47WIBixvBktAWdjHO6ZZ7hYhHnVFpmboS3m4NhKpHD8fB//EDW3d
         QLuFR4jA7mBO6vkLhkdBlqGwByS7dO2CHlTEKrPlQIqJEmskcYuiGojwawGIjeAzfg5y
         N62oYqvstCzC01sJ1H+GW1zfVcG8bsFAaQugNxD3lkoO2/x6qM4gb7Ez899RwdjiNw9y
         jM/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=tLt5o6MBRb5p5Zx9PRWdPnBX09AvSg/52XC6io9nfeg=;
        fh=bldVVDvXjdViX3yd8vNhEIpY4h6SaCAJvjvF0+sMmiQ=;
        b=QA8kHol4jcpM0+N920e4Zj2E/LtR4vNPrAf47ulVzWCxsdungHRe9NCwnOhbleX0uY
         TrLnzkXrvL2nVyEXoGyYPSgEFNrzLforBdUWoO4iUoR9TZvNbn2w4ChWUEPqDH6vVJlP
         DJCwWrd6cKoSGQ3bsquDCSmA3GEIeKIXyIa720aYLRgmMvOnIaW9NoC7YXvZ9uA9eOg+
         1Wup5csPCO4XyQpaBHn0Qs5mNCm78cMJo8ujeKXR0foAn18KdXwrBA0CDnB3KqRJiCnX
         1LsntG0VtZMD9DMGoMSRnj3iWmCL8QkMZrrF9qkLaXuvxLHjqYRWtqG1v8gDdRrMXSLD
         C7NQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=AjLurxzS;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5d01d520015si77876a12.3.2024.11.22.09.38.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Nov 2024 09:38:22 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Fri, 22 Nov 2024 18:38:20 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Oscar Salvador <osalvador@suse.de>, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH] stackdepot: fix stack_depot_save_flags() in NMI context
Message-ID: <20241122173820.-gmDeqUQ@linutronix.de>
References: <20241122154051.3914732-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241122154051.3914732-1-elver@google.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=AjLurxzS;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as
 permitted sender) smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2024-11-22 16:39:47 [+0100], Marco Elver wrote:
> Per documentation, stack_depot_save_flags() was meant to be usable from
> NMI context if STACK_DEPOT_FLAG_CAN_ALLOC is unset. However, it still
> would try to take the pool_lock in an attempt to save a stack trace in
> the current pool (if space is available).
> 
> This could result in deadlock if an NMI is handled while pool_lock is
> already held. To avoid deadlock, only try to take the lock in NMI
> context and give up if unsuccessful.
> 
> The documentation is fixed to clearly convey this.
> 
> Link: https://lkml.kernel.org/r/Z0CcyfbPqmxJ9uJH@elver.google.com
> Fixes: 4434a56ec209 ("stackdepot: make fast paths lock-less again")
> Reported-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241122173820.-gmDeqUQ%40linutronix.de.
