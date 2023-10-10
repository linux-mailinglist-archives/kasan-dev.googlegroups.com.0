Return-Path: <kasan-dev+bncBDBK55H2UQKRB4PISSUQMGQE27O5DWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E3C5A7BF99B
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 13:24:34 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-326f05ed8f9sf4050529f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 04:24:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696937074; cv=pass;
        d=google.com; s=arc-20160816;
        b=cbSUbWIVIYTRcMkOAM9XKV7J4kikmwttHoDdDFv3Rh/K/FcsizkPH/5dEAORdeSvBf
         Aze0wbmvNQazeGVu/DCVdXKKfZYm3ZaaEUTwc0agLZVvb+50JVwidmUv7GE7uxiuVv6d
         Rx3r/Lb4WTyN5WP92RYjjYrClg1Vz1xH0w3x2S8klWJYpRXRPFzTnFoQnyGEtDZ+uT2+
         YWSTbg55t3oDQDIbab/U7NaihVaCq0rECIvJJeLswH2sMVMGv4OEcKC2imalJazW+Vvj
         x+dmJG6TszPN15qb7h15xNZwRNX7CIugptfg+f+1A7xoRlGGzmTMzksm9qk6wiwt7yne
         A++A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HaGTg5OtFze6L1owE89gxj3BY9iWSYOwn0vJsLC3Vec=;
        fh=4tWpMuXgM6Grt6tK+V46P+l9WjE2Wblwd5EdpNnwGtU=;
        b=fWW8mr5YVHF5hkv/lyj1zNg4/kQOjxTlEoWaP5PPuRhx1bAner19e506A+6y9FQWDk
         YOCvJAOH2z5ejIpdlrdzCOR3rNPDTcqpvP3llKlznMcWK9gYqfPHYxjV/fMQkg1+c2O6
         z/4XHnFstQIlVh4MEJt2Kb6nV24PEZ2k6annsOVI40Mq3xsf71Pf+U4cZpMYnQI53uPX
         Y4Yg9EaNAHwrKHBb/IIVcZUx87Fxm1XgsoZtwTLO69D78NhJYhNb8ghxnKnkF5jq3MKo
         1HzbcAoVQj+isHe1TV6wKYIDr376LPcbMEcfsgWQLx+8bLZcew++iyrOUIJ+yCq6JRhs
         QxQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="AK/yhtwq";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696937074; x=1697541874; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HaGTg5OtFze6L1owE89gxj3BY9iWSYOwn0vJsLC3Vec=;
        b=BuBmZtMfpfulHs5q7m1/WygWnDrJtX66cVcLpfQ4WGWSozBUfgC5lUtjMABuTk8ZAB
         utw7d3Ng6obq/AIleUviYXNoGGYHD2Gw+3DhI7IHCMFsNhNSr6hgGOTH1JVSYJZ8eqS3
         rkXBpmdWBsahpKLA/0BwQFE1Fwz2S0UJe2uCEjlbEKRz2rP8XtEwmBXfUdIHmI6YfbzY
         dfMoQWDJuv4ezu/aoqPrW7VytoBBWWm5I4AYWCjcpzhPzApdPrtee3AS1zfzdfGo0v8N
         Af51x+Dn8q9eu2UkLHOhj2BoDlmtz3/Zot/badhWbIUcIWkWwa48a4doplE4aMYWw2QK
         robw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696937074; x=1697541874;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HaGTg5OtFze6L1owE89gxj3BY9iWSYOwn0vJsLC3Vec=;
        b=JFYS3XOtmFCg5XtQG0QTofHLMG2vgqI6rzRk5WPl+pPu3YUo6XvsjbkXZJJ16yBq/n
         eWvJnmu5qe4OKmgbICzIrLX4UV0q6AKFgY43D72toP4Hxr1oXToLfW6rtg9LPUxUexgR
         GmjUepWkV6KfGbEvcW2zxpku9pw3w+KkgUT7n6f3pIsqGIACyurn5cA7nlh6Uf8j+iWQ
         +E6CGW9XzUZaVgMGMrYL1eDvh6qBHmnqEmjSZ619EPWUY9KzF7+EMgwKWe2oe+OSCLlg
         xTyQ1ohaG0AnERbUAC1M4nOGXQICdYlqLO6NXhpY1plXaMc/0o435BR4VERngANaudvD
         HAig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyY5glURCYeFc+nAG4B5wmb8V6mkhjA1JxM8ZiKhFbN/f0R1b02
	N92QrL031LUIzJeLcfHV+q4=
X-Google-Smtp-Source: AGHT+IGaZQDljgq/nPEiptjiGMhFfikmcAsmJ8TierdHan5UhyG55Wf+/by2JbtM9PsM6meGXm32QQ==
X-Received: by 2002:a5d:574f:0:b0:324:884a:5cd0 with SMTP id q15-20020a5d574f000000b00324884a5cd0mr14587470wrw.47.1696937073766;
        Tue, 10 Oct 2023 04:24:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c8c:b0:405:ca8d:5cc3 with SMTP id
 bg12-20020a05600c3c8c00b00405ca8d5cc3ls1845528wmb.2.-pod-prod-04-eu; Tue, 10
 Oct 2023 04:24:31 -0700 (PDT)
X-Received: by 2002:a05:600c:332a:b0:407:59d2:7925 with SMTP id q42-20020a05600c332a00b0040759d27925mr673375wmp.21.1696937071805;
        Tue, 10 Oct 2023 04:24:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696937071; cv=none;
        d=google.com; s=arc-20160816;
        b=Pxatl0Ly97C45wex0VyT6pQEhLqXFHqn5f67xWxfhAxlx6IKBFX7sm31dqmO+bSioe
         0ZlmbiaICLYQ/83MNqrrzmGox3YCD5o7Y8buMYkEBht6/OlnxZHdf1iyk5xxw2j55xis
         9DVQ0lSttF4j+Vdarle1ej1cW93KTVm6F3IYeCxtsFeEYhs2n2cf5KAvKLEWuhMiBTkX
         8vlmfELTt/eJr9kbmbJ7B3Xy0P8kAN+YtYrUn+DfIVom/v6EH9Yza+kgpA7HpyJrycJf
         EoeU4JO2l2RuLkM1owpKT8nr8yqmyIWiMdMExTyediRuFyQl/ZwtCVPixZ6qoox/XvuC
         CNQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RHIty1r8jlpg4mbxrTX99MguDdmyNDYNfk7Z509OtEw=;
        fh=4tWpMuXgM6Grt6tK+V46P+l9WjE2Wblwd5EdpNnwGtU=;
        b=kRQ+cH51exPZdbtpzCBM9YcOVSLUhc7tzCRd8Ag0LgI2rCdz3kdIAosLotI/E2II6s
         Y+GR/cQo1OUmUDGwGzHUsNinP8eUT8h2l4A1ZdSJKFTCpPKKsTqyEgVNY7fDF+/X8tUv
         gyRHkmV0D2l90YN82GbnXFBW1ChRXODdFtCv85XMMrya/+M05JrdNk71f4C1xh5Akvoh
         lcSK2mOT68YoJkMTjalnIpFYmac4p8eR5vV7j31N/ZcTjkfPGCzjUapEgTCXU18ryH92
         UsjqAtopyHbQf42GoBIuFgrYgBzK3AyOyQQn6L7iM3JI49VotG/ohzC98nV/4LuC3W/6
         QulQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="AK/yhtwq";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id i6-20020a05600c354600b00401df7502b6si697684wmq.1.2023.10.10.04.24.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Oct 2023 04:24:31 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1qqAqf-004JVi-Mh; Tue, 10 Oct 2023 11:24:25 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 5F185300392; Tue, 10 Oct 2023 13:24:25 +0200 (CEST)
Date: Tue, 10 Oct 2023 13:24:25 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
Cc: Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>,
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
Message-ID: <20231010112425.GJ377@noisy.programming.kicks-ass.net>
References: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
 <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
 <20231010101056.GF377@noisy.programming.kicks-ass.net>
 <20231010102537.qkrfcna2fwfkzgir@box.shutemov.name>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231010102537.qkrfcna2fwfkzgir@box.shutemov.name>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="AK/yhtwq";
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Oct 10, 2023 at 01:25:37PM +0300, Kirill A. Shutemov wrote:

> > That said, I don't particularly like the patch, I think it should, at
> > the veyr least, cover all of apply_alternatives, not just
> > text_poke_early().
> 
> I can do this, if it is the only stopper.
> 
> Do you want it disabled on caller side or inside apply_alternatives()?

Inside probably, covering the whole for()-loop thingy. Ideally with a
comment explaining how KASAN doesn't like partial LA57 patching.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010112425.GJ377%40noisy.programming.kicks-ass.net.
