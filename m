Return-Path: <kasan-dev+bncBD2NJ5WGSUOBB5GHRHZAKGQEELVTFGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id BF139158B33
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 09:21:08 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id o9sf5881918wrw.14
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 00:21:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581409268; cv=pass;
        d=google.com; s=arc-20160816;
        b=uHu7I//YNTF7jPxFBIRKb/TIF1z77QHsUZWUnnqzrBDefkZ2GAzNDcMj6KZJmnF0pS
         Ar6MGMQdxByVOnKWqAy3b+5nSu/eITAoz5E2V6BsKuJIza/G2mRqeLdNvWHzLu3LRHs2
         ygIjIijAo/dL2iP2zSKkI9eGCqL30l8SEwUK7U5C3VMN8R/P62v6iyC3+AFdPX3NzXDE
         QMWgA965lFXTfnhXtugt59vaeHIbwmMwJpyRuR87W4xMV2IDapqPZCGtFhZnugXGTUdw
         Vlb1yKGLC3ETSurZiyNGbP9gueeVIrz0rY8WiNiptbvCXTSWVBlNBOhwKa04r+efuIaT
         0IRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=HW6w36gh/R2TyZNIxJ5BMXaJcXdileSPJkSd1K/WSPI=;
        b=C69kVYKb4Ix83zCRfeEWVQtavCTpdOoQuFViq4pE8fYh9WLUvElRuep7E5OfuSQyhH
         nfEoRUSmtXvyxu1EKk2+giOUw03IF3f9/waWLOVU7RrHvhpDNdbZwoj8bgFg8Uru7x2Y
         xKLu7Lor4rN16HjBdVK5EHF1fEglLxgdKKfIqI3EgwX9p+xIEnsoNTNnFkX5LQm5aUSN
         RGJAmZG/OTpqUNsVLI1+O7shCnGeGSTX3EYja1DntHDtmNMe4c27xuFmWScbQy/bFrKc
         hARITvEi7bbKCALw+RB9HbaVl0ppZHCxyZZhYEOXQRBtU9NvRjO8e/6hgWboLzXjwYyF
         2Fiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HW6w36gh/R2TyZNIxJ5BMXaJcXdileSPJkSd1K/WSPI=;
        b=DxRJZGN2MvfH9WZqaRyYYmoxMLBeZmwMCkjgAPpZyKoqnR8LX4aJY1O/ZNM9zPmMlp
         JWFLsbU8DTlH8yi7JB1kbnnoMbZy5MF7dOI4MfMJ8TirCJvisFiWN4fddps1Ea9PI3Ui
         PUMBGSDNiv3Hhnj0FtvqjPm92O+O32NRTXscZCIW4z1cxGlDnNpVdHf83hOvOKHW9ehB
         iaVn23w6DxhEmTg7V6SYcUZrGlR4lIHfVl49iq8ggmzy7TYbuYUf3FxPMn6QeSZbqDPK
         jhjArnFAtv26twxC8+Xlo/l33seQAqRqc7pOgn5+XBurSVua6YTVSIFTENbT+hGlKdm5
         2J2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HW6w36gh/R2TyZNIxJ5BMXaJcXdileSPJkSd1K/WSPI=;
        b=C81ukk3WHieUccxtrszv6VhGa7srSII1J7xL/VavsdSjIWpO+YclE8fQX5kJz77Nq7
         HQ5lk6ZLYjtkm6MzP3S7zUFW37j1NzXrs/MTgPFkfwq5J4ca3dpYSfuKfDL1sye7nIPf
         e8GxiPvWxx9vZ5myQ2sJpEw96He2Z/S6DgVmRvE10BJTyCpxJG6V1GUrV2/RQ1vSU9tA
         6PxV5+zbc0eo2hD4WluVFb4uN0hnw0D6Y1biXDOLgwkM/7wq3uOvfgOiMCTvVShUefUz
         5Ko5dWvPr1tVKFIBBf+1bKht/awADTGnO7rAAUXVjsfscybUGRhi7vyf42G40hu6JNYQ
         +u+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUsR4nfTC/HYMfwFv40u163O7muvOSJNx0eZMpXOturDnYuol/g
	s/VX0Xbrcewqakp/sx9Qdz8=
X-Google-Smtp-Source: APXvYqxrft2wRnlMs1kcgWBMM7LEOljsAZkRzEuFx7mz2XdsysgnYiRl26jx1DUlnUq7gJUHeBEG1g==
X-Received: by 2002:a5d:6a88:: with SMTP id s8mr7108428wru.173.1581409268436;
        Tue, 11 Feb 2020 00:21:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fdc5:: with SMTP id i5ls7425917wrs.9.gmail; Tue, 11 Feb
 2020 00:21:07 -0800 (PST)
X-Received: by 2002:a5d:6b88:: with SMTP id n8mr7381024wrx.288.1581409267910;
        Tue, 11 Feb 2020 00:21:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581409267; cv=none;
        d=google.com; s=arc-20160816;
        b=p8v72r7LVpjypEhvv/2lz+2sidwrBC/QSiZj3+3md/6V7GxDw6cYGZSA7lxRBlWZZ9
         0Fk8XlY5uB/BprWrOgT5nw3eohn/ye6y8ea6znPEKqq5Kq+5N36q0d/GyX4rUo3jpE4K
         XKuIzvsvXZWpE5PVTuyhXUg1IpuJsxWEJjgaWH0Mne0Rzc4ylzw3cGTYxC4MiQDlTK4O
         3fay8Da0OcMGTONTD/Y5kApTCCSEzr95kd1BSDLwBX1fgtuIWhXjvpKpr2nFRd/VLddE
         im9Ey0UybvA3a4htQXkfHqFxxLxp+LOWT1VqNpJj5WVXZwSoOtQnyU3F4+eSodCYvaJ8
         rWSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=5qPNJrBA9gkPtJ0sQBfxv6Ytj6wN3Q/QOiNV9giqInU=;
        b=CzxQcJvLY082bagN7djQ43icoFzySAoa68KIQH7zeKJfx6o6DEBz8xPROLgDPwXHqY
         9KJS1rxvjrBA0qCAcpgfoaMbpoDjnNxfH04dpxqpJVDrAB7mfXw3AvIfDChGzQVPfDfZ
         yn9RrseMmVxBROY1mzEwgr7nS6zicIUZPC/0rhka7OzS8zwPXiq07+UjPtSxmzM3TEE5
         Ne0PsDkOymqBObSfgkETy6voKERaNENSDWUf+weC3xi/4TClv44jZsZIkaZBudlLd2KI
         ygEQT2CavqEk/HZxiQh4jFTKS43P9feC240mXdoolv1zLUgbWUNYcVwZwJje8cZlKDeE
         yC/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id y185si81844wmg.0.2020.02.11.00.21.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Feb 2020 00:21:07 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1j1Qmu-0029iO-8e; Tue, 11 Feb 2020 09:20:56 +0100
Message-ID: <13b0ea0caff576e7944e4f9b91560bf46ac9caf0.camel@sipsolutions.net>
Subject: Re: [RFC PATCH v2] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Patricia Alfonso <trishalfonso@google.com>, jdike@addtoit.com, 
	richard@nod.at, anton.ivanov@cambridgegreys.com, aryabinin@virtuozzo.com, 
	dvyukov@google.com, davidgow@google.com, brendanhiggins@google.com
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-um@lists.infradead.org
Date: Tue, 11 Feb 2020 09:20:54 +0100
In-Reply-To: <20200210225806.249297-1-trishalfonso@google.com> (sfid-20200210_235813_002927_509D549C)
References: <20200210225806.249297-1-trishalfonso@google.com>
	 (sfid-20200210_235813_002927_509D549C)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.2 (3.34.2-1.fc31)
MIME-Version: 1.0
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

Hi,

Looks very nice! Some questions/comments below:

> Depends on Constructor support in UML and is based off of
> "[RFC PATCH] um: implement CONFIG_CONSTRUCTORS for modules"
> (https://patchwork.ozlabs.org/patch/1234551/) 

I guess I should resend this as a proper patch then. Did you test
modules? I can try (later) too.

> The location of the KASAN shadow memory, starting at
> KASAN_SHADOW_OFFSET, can be configured using the
> KASAN_SHADOW_OFFSET option. UML uses roughly 18TB of address
> space, and KASAN requires 1/8th of this.

That also means if I have say 512MB memory allocated for UML, KASAN will
use an *additional* 64, unlike on a "real" system, where KASAN will take
about 1/8th of the available physical memory, right?

> +	help
> +	  This is the offset at which the ~2.25TB of shadow memory is
> +	  initialized 

Maybe that should say "mapped" instead of "initialized", since there are
relatively few machines on which it could actually all all be used?

> +// used in kasan_mem_to_shadow to divide by 8
> +#define KASAN_SHADOW_SCALE_SHIFT 3

nit: use /* */ style comments

> +#define KASAN_SHADOW_START (KASAN_SHADOW_OFFSET)
> +#define KASAN_SHADOW_END (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> +
> +#ifdef CONFIG_KASAN
> +void kasan_init(void);
> +#else
> +static inline void kasan_init(void) { }
> +#endif /* CONFIG_KASAN */
> +
> +void kasan_map_memory(void *start, unsigned long len);
> +void kasan_unpoison_shadow(const void *address, size_t size);
> +
> +#endif /* __ASM_UM_KASAN_H */
> diff --git a/arch/um/kernel/Makefile b/arch/um/kernel/Makefile
> index 5aa882011e04..875e1827588b 100644
> --- a/arch/um/kernel/Makefile
> +++ b/arch/um/kernel/Makefile
> @@ -8,6 +8,28 @@
>  # kernel.
>  KCOV_INSTRUMENT                := n
>  
> +# The way UMl deals with the stack causes seemingly false positive KASAN
> +# reports such as:
> +# BUG: KASAN: stack-out-of-bounds in show_stack+0x15e/0x1fb
> +# Read of size 8 at addr 000000006184bbb0 by task swapper/1
> +# ==================================================================
> +# BUG: KASAN: stack-out-of-bounds in dump_trace+0x141/0x1c5
> +# Read of size 8 at addr 0000000071057eb8 by task swapper/1
> +# ==================================================================
> +# BUG: KASAN: stack-out-of-bounds in get_wchan+0xd7/0x138
> +# Read of size 8 at addr 0000000070e8fc80 by task systemd/1
> +#
> +# With these files removed from instrumentation, those reports are
> +# eliminated, but KASAN still repeatedly reports a bug on syscall_stub_data:
> +# ==================================================================
> +# BUG: KASAN: stack-out-of-bounds in syscall_stub_data+0x299/0x2bf
> +# Read of size 128 at addr 0000000071457c50 by task swapper/1

So that's actually something to fix still? Just trying to understand,
I'll test it later.

> -extern int printf(const char *msg, ...);
> -static void early_print(void)
> +#ifdef CONFIG_KASAN
> +void kasan_init(void)
>  {
> -	printf("I'm super early, before constructors\n");
> +	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);

Heh, you *actually* based it on my patch, in git terms, not just in code
terms. I think you should just pick up the few lines that you need from
that patch and squash them into this one, I just posted that to
demonstrate more clearly what I meant :-)

> +/**
> + * kasan_map_memory() - maps memory from @start with a size of @len.

I think the () shouldn't be there?

> +void kasan_map_memory(void *start, size_t len)
> +{
> +	if (mmap(start,
> +		 len,
> +		 PROT_READ|PROT_WRITE,
> +		 MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE,
> +		 -1,
> +		 0) == MAP_FAILED)
> +		os_info("Couldn't allocate shadow memory %s", strerror(errno));

If that fails, can we even continue?

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/13b0ea0caff576e7944e4f9b91560bf46ac9caf0.camel%40sipsolutions.net.
