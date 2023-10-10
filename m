Return-Path: <kasan-dev+bncBCP4ZTXNRIFBB6E2SWUQMGQEGOO7URQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id ABB567BFCFE
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 15:11:22 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-3fef5403093sf27531765e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 06:11:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696943482; cv=pass;
        d=google.com; s=arc-20160816;
        b=BkmfaF1sAZ21bSz6HfclZCZ55VDrh/IlmeotEph5+Cc694BRxHjiHFT8Ng9zdVzhRp
         ije1bcMWbXJ5ZGe4AVMvXYTUncIg67Y0BHH82LK5a8wYwyzqSfl4IKR8lLsweLcOpYzS
         VDyByyj/OSR75LDx2os437ifZlnGU7f5cajXUEQ1axDgbozP8bWZ3tts2cZoV2IyfJgs
         6DtlTnDxldK6uPhkw8hC01pDeXIrNlfvEe3zenxn5ObtSvEj/Nm0hjhmUc2t4XKIvREk
         iYeGe1UYkMOjKCPmTdJtFxqfEKE45JsTVH2ilRz92sd47GFhIGfb2uM9iTfb6bhAlue4
         d9lQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FvttIyi4NAaE7hy3cBaPUKs79d3ejcSj7ORl6uWYmUg=;
        fh=uLtpt4hgt+ZRjN9FuFmSixD7HUfoX26DL4bVEdLCqYI=;
        b=uIAl/aanvqXDqzzmY3mRE1Ik63kQuTaa+mfDAkR4BDopOlMdmRwb+8GWbzb8LCCwTS
         +J4r0aPMuVJCt6Ft8Az0SsiKDPTVA6RuVyxLAY69eEyjN0PqG/gJj14HUkOr33IZ8Q8w
         QHiKbYN7j7MlsQVXxPFDGjNCLyxqWavCGGKH3Pfv4TG0qrvvp5rwSQK8SImGRMOG4fab
         FvUNR7FBKP2yAWuZAv+ynX9R4s2cV68c9xdKGouVgJqfxe6Z2AtmVsmMNSpZNtM6p6/3
         E/o0YhmG2sdeVlK26JJCixPFeM5ZC2pyWNtzIM/ZG8QbTVopa0MjoGDB05osaUvayOUH
         O1dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=D7Hjwvga;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696943482; x=1697548282; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FvttIyi4NAaE7hy3cBaPUKs79d3ejcSj7ORl6uWYmUg=;
        b=k2hJTW0OtVedyKyfdho6w5WEsBv/4P8Np8oGGclIgIFlu6BV6UGSnsy1uU3xpfz8Xf
         xP1N0L7DwNtr0GcFSqrz/pZTeN7/XT50qYm+eLY8KKF2PqSENeOVyscm2U0GMyietPX0
         AaW0DVEABiil89X9UP3NnKyv8mZtUNx7zKnS4lxa56SqQvj2zg642tkgejTzG0Lgw9ik
         ilp0qIpefDCuGEISpecECYyGUXiRiQq256dcarOwvdR8Ic4ngexZpjDF5uLjv4SSJi5C
         YajDNncxqDHUGxNnwvzW1v3cAzXu9Gi9FG0j2uXfYXk8HuX7xVPUxvVv427kaOdAcIvT
         XyCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696943482; x=1697548282;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FvttIyi4NAaE7hy3cBaPUKs79d3ejcSj7ORl6uWYmUg=;
        b=iLEw42cvW2UA2UEkNsTve3hDexo7amnfow6ROSAfGj3RFMosEdntv0KxG2NVMdoFNA
         v3Pe2G+hyhkkp957f3SaOVVQjImDOKDtM0ku7lERqqXRbWtV9oW/3/2HvWTwKiw62UXV
         bRsrLv7BRJ6FlpSTrAhmEmLaxtaqW4WJZ5h/aXfw83g0IbM9CuVPEDo/4mqitt5udfUW
         2Ha7zkkmpbn3lB6E664fKDycs5hZesUTBkovt/Yllq9Zfuy39XNxBkLx+gOtl2kGSOad
         2prWOcKscXWefgGPgYuyufnqxLY9vb0olhc901SeXnP+FBYS0NfOXyF8S8nI24e9kK49
         c2aA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzdBodt6RRKYsZMilVlroRKzq/Yfb9SRGkObKyJp8AMaNZj8XC5
	Celgd1P/lJc5RjmB32mBSYk=
X-Google-Smtp-Source: AGHT+IEwOWxbyKspAN1EcimFmN+lGBn7G81Tebtx9qY0cnD3rc9XUBZfTEKJJ/wKwkOLMVdPpGnl9g==
X-Received: by 2002:a05:600c:4f02:b0:401:609f:7f9a with SMTP id l2-20020a05600c4f0200b00401609f7f9amr13197568wmq.8.1696943480836;
        Tue, 10 Oct 2023 06:11:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ba6:b0:406:3ddd:4bc9 with SMTP id
 n38-20020a05600c3ba600b004063ddd4bc9ls1191727wms.2.-pod-prod-00-eu; Tue, 10
 Oct 2023 06:11:19 -0700 (PDT)
X-Received: by 2002:adf:e80d:0:b0:31d:db2d:27c6 with SMTP id o13-20020adfe80d000000b0031ddb2d27c6mr12500907wrm.30.1696943479296;
        Tue, 10 Oct 2023 06:11:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696943479; cv=none;
        d=google.com; s=arc-20160816;
        b=zV6luO7G6fcbreyNOoAv8SMbIftaSMiIC1rkMCejoJQtF3Fr6MQhqgbFWqyCJ4/EQO
         LVjB8gx7wQwyeNyM4xEwNMhnDkJsJFmb+ATaT5kOtbEde+0ScID90WAOCjEY63zr7uG6
         cRgWh3eqDdqtojZwe3v6oZkOnTQeyFbu7FhIdgEDjbqSXYh2nSesEUxISg+VnN14ITum
         AVrnvKfNS4W5WLvbOiCOlYONkhGmeIjO8u4h2mM2bqvVIAejDmF6Tt0qGVZu/sHe2U1O
         bFq5ThI3Di169O9pJM1zqxHijrlbiR0BocGi4bG41QtYUNq5Udd+f1sU/5fJDf0sARxS
         S3oQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=s6hwso6prMDxVtqqxwRgLVjr6kJJ/eMt+5h8SrEfaZI=;
        fh=uLtpt4hgt+ZRjN9FuFmSixD7HUfoX26DL4bVEdLCqYI=;
        b=fu3f1w/+TA4OtgFXb5cqJYk/eHVwfhPJbClZ+nON5h5yxHTcnM+QFUzSUXl7f9OtdH
         4RAOZAFgGQxHs36KwBuXsNOAg3z76Jz6+Y6KnQ5+eyXzE1gnyE04pQ9Sq+3l7Rm6FYPf
         yCPP7/36wRFcJElU2QO4ZX+Z/wFJIVUaGKbD5V7OyXc43M/I/h0UYlHOTafJfgDYQ2ly
         JC5n+kowATpkZnhl5H09niejzsngvRZafXduHrptwIw3/dpuhi4S2QKLioP8F0uac0XI
         8Wjv/rRXMpkjFDb2JhcPYyakkO31afH5AvOOGodPuavnVt5IvjlCpPCyKpXa+pA40rck
         H+KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=D7Hjwvga;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [2a01:4f9:3051:3f93::2])
        by gmr-mx.google.com with ESMTPS id v6-20020a5d59c6000000b0032c8861a1d1si101327wry.4.2023.10.10.06.11.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Oct 2023 06:11:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) client-ip=2a01:4f9:3051:3f93::2;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id EE53540E014B;
	Tue, 10 Oct 2023 13:11:17 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id WjwUpLhPDHOh; Tue, 10 Oct 2023 13:11:16 +0000 (UTC)
Received: from zn.tnic (pd953036a.dip0.t-ipconnect.de [217.83.3.106])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 1931340E01AE;
	Tue, 10 Oct 2023 13:11:00 +0000 (UTC)
Date: Tue, 10 Oct 2023 15:10:54 +0200
From: Borislav Petkov <bp@alien8.de>
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
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
Message-ID: <20231010131054.GHZSVNXhruJIx0iCzq@fat_crate.local>
References: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
 <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
 <20231010101056.GF377@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231010101056.GF377@noisy.programming.kicks-ass.net>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=D7Hjwvga;       spf=pass
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

On Tue, Oct 10, 2023 at 12:10:56PM +0200, Peter Zijlstra wrote:
> Now, obviously you really don't want boot_cpu_has() in
> __VIRTUAL_MASK_SHIFT, that would be really bad (Linus recently
> complained about how horrible the code-gen is around this already, must
> not make it far worse).

You mean a MOV (%rip) and a TEST are so horrible there because it is
a mask?

I'd experiment with it when I get a chance...

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010131054.GHZSVNXhruJIx0iCzq%40fat_crate.local.
