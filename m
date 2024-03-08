Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBFWMVKXQMGQE7II5J3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A699D875DD2
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Mar 2024 06:46:00 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-51314c5a05asf1186866e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 21:46:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709876760; cv=pass;
        d=google.com; s=arc-20160816;
        b=k3E6liETejIGIJ5QojPiAdB8Am8y54MbQzQHnicCkSaLfvw9XFGioEBfuibYtcsqv/
         VsA6OC8AJznAwRjOg3sWfDcAOB0HFJF3ZZbtfa+2rVuAPDeo217f/1hmyJRGosliAnvE
         bRts8FZJM2R5aM5MdoNfmrj1TJ6ijKEb4wkrUjfDMrECZN+/EAX0XLOedqhHVPtIW+JE
         nH2xOZQL6pXr9qDYE1n0fjEXIQnUbNsID+nRqi5xeyXKmXBiVTp17J/qW/dgw/qxkf3M
         1TwJxgVsUhm3x1sMat1yNOwO+dji7fY9YdeyRQHz6qdfLKf9xTlHjlo91aijMk3h6WPT
         HcXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2Rwbstsb1eJSBPQHHrrmSlOFyUGWAeDuJITqN9HEu0w=;
        fh=ywnzqSNJVFem9iw+iFm6x4fzuwkCw5csu+9VOBfjd6g=;
        b=Ektcz0KIOx7+BPdkcOVoDlaOwUtXag1RizyH8tBDPV4ua9e0hCFPE3qMqIfI8JGW1b
         dZ7gl4hocuJTz3CRJ3Ih8hKvuYZl6SeUXnja4wtA9P8y3aCew1ztYhKC3ffF2GW3i/DI
         GLSw4+mYx9Gx+EUuNzhN38rqV8rJUj/TPvOVmQWr12RVrp/y7VIbpMpmX7mGu6KsjEWH
         OolGaw8Cnjs51O6NBqIaUCcIhYGFNGvq6lNDcK3B3BFnzZ7TmhpVq0FQ0A1hIb4SF3q0
         NcabQlFRieNtoKIfH6eNOVCvyKXCaxNpx3fKP1S3xtGWDI68ZjRknBwnx7frqgtTM034
         RpvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=BBOXMGXy;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709876760; x=1710481560; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2Rwbstsb1eJSBPQHHrrmSlOFyUGWAeDuJITqN9HEu0w=;
        b=wj1VemA7ztA68RXTmD135GJOuhYEetGtz5ByjINPDqOBVT+GgGD0qaYL6TeW/84jLw
         TUT58sgwRodQe7q4tmvT9mkawwXLg5/1/YJv8nghQ65h8MiE+BT/Pq+nOApP/dZuqsfl
         ioinyqsdFNpnOTw1N753UnP8PuPHWj8pHicUThFdHhgx6cTy16aYv6I33TrMiSwhp3GH
         ln2ga4k82J9hGIXoeZ7hrvl0/CsVpC7YWBT3EBXBky/k8mNCa1w5r6n01n1LRinjVFwV
         FNJBAepzwED6WoxbHhFIGkCV6ViyBk2TbXncUX6gNdlI9peE1XUPCUjeY6ZhID2MjAAD
         mihg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709876760; x=1710481560;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2Rwbstsb1eJSBPQHHrrmSlOFyUGWAeDuJITqN9HEu0w=;
        b=kzJrYqkQSptaaHnQVzcssnfTq2oX0EKqXpNwTx8YUbjlcOIgm/1Sm5gCY7sPtY2//5
         I5UuBS1aBcPrIJd5vQxoWz9mrQi2H9AvwoY0ruZ+cgB+4a+dkLFOodvpsrbsp3gomIL2
         MLqvDXuIvFFEQJeA1VChjyw4c42+E7+4UOKXh0h/ti3f2QDmiOncmBtG0zzGKqJU69lm
         JBnC6nQjh6lxA9rTFHlyGiN9Lao7xcKhhkZQ/NuNqnUuZz8CEEDPh3WQLzw4QCe8hHoD
         M1yCvPXJRg77lOQz0GK7LZ4uPVDfTBj+/cQRnHuVnbpo0Ye01ecKCM4rr143ujq5svYg
         wzIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCnwWjNbWSIsXZqMrIgjVx8fLnmafMhvrN7HMGwbAGLxO6uMJjYB06KQbnG/aYLago9CNWJoWvKwoqd3BJhD1nlF949jXiVA==
X-Gm-Message-State: AOJu0YzfWJa7z0CO10qegqLqacdT/qzdjjD7q05rofeBHbCJ36OEISPa
	h+zbATeCoa7JYGJ5ZOnLZBZcEwdO1owGAyiPbJH0uS353X+uztHv
X-Google-Smtp-Source: AGHT+IHKu6x/xD3sFxlM7NS3/G0Ek1p1SOjamKEOIBy1vKT5o/0OlU8bmCHsKaNkHRUdZA9WkUEovQ==
X-Received: by 2002:a19:ca03:0:b0:513:2114:b70c with SMTP id a3-20020a19ca03000000b005132114b70cmr2325052lfg.69.1709876759147;
        Thu, 07 Mar 2024 21:45:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b98:b0:513:4766:2724 with SMTP id
 g24-20020a0565123b9800b0051347662724ls352954lfv.1.-pod-prod-07-eu; Thu, 07
 Mar 2024 21:45:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXE3YI7o39PN6GaPIQgQfMKLaUA9xMWf3crg6olDURJ39ZAvP6LZuYafW8130I0uGgEBOehrKc79EmbH4oMA/PK6HwkNJ+ziTL9tw==
X-Received: by 2002:ac2:55a6:0:b0:513:3f81:224f with SMTP id y6-20020ac255a6000000b005133f81224fmr2816949lfg.37.1709876757134;
        Thu, 07 Mar 2024 21:45:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709876757; cv=none;
        d=google.com; s=arc-20160816;
        b=xCvQsHYHsD0aJhqODAmHfqpHv4tNBGc/kNz3/GP3lCc7eFvk4T7V+MEL3dNZeBmI1C
         pVNdl4ofWfwJ6DEgpj5jfcAVq6hhaExAxCGELFDhls8dBixcVvT78MJaH0wOFJr4GwlH
         xnCPq8/k+CLvgeVVbTPHezAnH+9ocNJxIDGwltQjJj8FEHP+95n9rNlwtWf2l6ZyZIMe
         9mI5mXf8Cno1sYnU2FtOdzwlS0CzgEmzA5ZYxE0qyNu98ClHVQuvzqtpLJnnLwjSympr
         LA1BSlr7HNzX8yESuo9lyhV7pdMh9xd82LrbQRNmd+aPIzWwoicGs6tSf4iIwz01i/NQ
         s1TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FKsdy0bUX5Q/9NG8GdgiRx0riUw7WOmPGga/MBUabv4=;
        fh=5cWROVSDVwlBaAlq/8EZKga8LJsbHzvdbp7itep/MGI=;
        b=tks5LYO5pzFuvViEc34yEB3HPkLq4ncqdxaRXJeEybXxUuil8wTaF1hQ5d8YodG6cB
         AvbVX0HxcHXkEhqBxWogTqU0GDDnKsK2vtaIFDsc+3bzNYJpSojwrDHCeXKdBB30P4bN
         GMcoqRHcUGv/AhHau7lnlZdbOKhlW7/Epx9Fu9QQrMU8mYKDO9e2DSJUIYEmnPJ1bLDu
         /h/rZ/2DCkUxY+YwjinVULChetAwLmh5t1cYJshHxNoWeOg6kXTakjR/xGxbez3tBuoz
         5k0YPr5khZazRf9ngkCv+IX3ADQJh35+mKNzQScNqfS3dYDzq/hXYdAEk33KoLUAWsUA
         m0ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=BBOXMGXy;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [65.109.113.108])
        by gmr-mx.google.com with ESMTPS id o19-20020a05600c4fd300b00412e5895f17si149934wmq.0.2024.03.07.21.45.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Mar 2024 21:45:56 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) client-ip=65.109.113.108;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 8B95340E0185;
	Fri,  8 Mar 2024 05:45:54 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id 2ctcx-lkY7Jc; Fri,  8 Mar 2024 05:45:52 +0000 (UTC)
Received: from zn.tnic (pd953021b.dip0.t-ipconnect.de [217.83.2.27])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 0155740E016C;
	Fri,  8 Mar 2024 05:45:38 +0000 (UTC)
Date: Fri, 8 Mar 2024 06:45:32 +0100
From: Borislav Petkov <bp@alien8.de>
To: Changbin Du <changbin.du@huawei.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	Andy Lutomirski <luto@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH] x86: kmsan: fix boot failure due to instrumentation
Message-ID: <20240308054532.GAZeql_HPGb5lAU-jx@fat_crate.local>
References: <20240308044401.1120395-1-changbin.du@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240308044401.1120395-1-changbin.du@huawei.com>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=BBOXMGXy;       spf=pass
 (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Fri, Mar 08, 2024 at 12:44:01PM +0800, Changbin Du wrote:
> Instrumenting sev.c and mem_encrypt_identity.c with KMSAN will result in
> kernel being unable to boot. Some of the code are invoked too early in
> boot stage that before kmsan is ready.

How do you trigger this?

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240308054532.GAZeql_HPGb5lAU-jx%40fat_crate.local.
