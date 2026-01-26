Return-Path: <kasan-dev+bncBCT4XGV33UIBBDM337FQMGQEVEDLGPQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id cA1CGJDNd2mxlQEAu9opvQ
	(envelope-from <kasan-dev+bncBCT4XGV33UIBBDM337FQMGQEVEDLGPQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 21:24:48 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dy1-x133a.google.com (mail-dy1-x133a.google.com [IPv6:2607:f8b0:4864:20::133a])
	by mail.lfdr.de (Postfix) with ESMTPS id F40B28D080
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 21:24:47 +0100 (CET)
Received: by mail-dy1-x133a.google.com with SMTP id 5a478bee46e88-2b704019c98sf5220086eec.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 12:24:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769459086; cv=pass;
        d=google.com; s=arc-20240605;
        b=MG3uJDcGMNXct2sSKtzHCFPZpR2ErR+FMA9DLss+nldamlJhTvvUQ4qHL5GMB5zthQ
         3O+oPYXNa7+oIkasub5CX0EVpqg23nr4Pe0hEVwV8KtglZsoJDszI5pOLETKijvhJZWc
         tVfPjha5WumNj+3bEJjthtYJSVwepnx6BJi9gge5kJMuc/+w3N4jcnoD3F4+3z+X+j6O
         PJY12CPJhyxJEtq5k/imWTjPZn75/3+NPbVqg1qD5u8FOa07sUP51QkqtHZlOkx8/GSY
         Pnu4kAmhZfQVOB/2Ga6yHC6Np7paXOFRuH74G0CLjJ/QaL0xydoleKfCUVYya9asls0b
         xEqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=boiHogsLA3iRi1nmvd70/wYOXLPL77n+U7t5oN/aUsw=;
        fh=v7l4yll4oknozHG9p+dKEdCibKs1eX3XbpQ6PbIgQX4=;
        b=RNvNA37P7vzuOLaWqDJp1Krp1QA3+wCDT3hSxkbeN5TpIW0r5B87cUqYx4xVM+ZwHT
         3xkkKO6nQW9YrbzOC74iN+IXMf9+/PcrdEkAneZrYnwULlZ1lJDlBgU0C4kmwz/R2KUb
         WX86MgZ5wmuKTGm2WensPnJYYsmvu9Hix6dyUuDwvM/kSnnaeLWVARFmU5Dc1hWOVmY6
         BWB0XPYGu9iBhsKIcsu/Ia5ZJNYs3gyjguZKTbhmfkPTOq/2X7BfLw02eYuXLLkKgYre
         MVgYUAwnlX3+qGYC3ourNzAb8kHk5x7jtr+6cX6tVL5zwpHpeqAYrgdaBXw6TUoL0YKd
         z3Eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=UF0k3RRl;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769459086; x=1770063886; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=boiHogsLA3iRi1nmvd70/wYOXLPL77n+U7t5oN/aUsw=;
        b=BeXD1tBuHFNT1HvsMJUAezpXgg+fWMxLTTU/+SfXq371nzZ24obgPxFgsAu+to9ThM
         MkZcjwjdSNyiBZGdVHILtL5G5k9odC8l1gpTbpnWXzY2zadbGf2mOP7bbV9ZgZE1nz+m
         0YkDN9kJ2Yr2GX70puk0HXRKpEgAdwY5wOl6zaFQE5BvD0X2lMel3bw6TChzHyDWLYNR
         vyAMhcYSPBHZGDaHhS0nudQKgaIP8iHLqZh1dedwEjd7UqtEKuvW59Z2TgFVsdhs3GO/
         BTG/nZKHil8VhAJ86xCee7qBQ5sxOQNV17Q5W2GsoNq5YT1DeztAHTruXa39p/ze8QHN
         aG/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769459086; x=1770063886;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=boiHogsLA3iRi1nmvd70/wYOXLPL77n+U7t5oN/aUsw=;
        b=oBAEj0lZ99AKZ++l4ReuoxAr4m6AzR7iMijQwr53rpdefTpiTtOXy2n4uENSUkJtlJ
         +sX/gbuRC5/DTwBAtpDI7GnXpzKEnkkZKcFJpEfsmc6GBqVGIcnuaW0QeDIfwabFyxvu
         olV6BBMVJLZTPEFMB3cA04aRlXT8d3/37y7IMCLwwGSvpMMZu+23EmNo4DOtgXUtVTLN
         zHlv6a4p09wbkBumLCKbULIC16+Hj89GE7qHyPMUIACQi+DVzeWnAm+yixDJAZySnh9D
         lSdao2BOLcbKekH9b0u7gbEIIlfRN7iGSdEkobQQR1RzlocTBRBRFI2VdF0F1dmAfAqL
         tUzQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFSlVivnVOa+X+nBS4ciW3Oayl0P9KfVGepu+0dr5qofiT8JQQTNgRLrZlcXifR0mwGra8yg==@lfdr.de
X-Gm-Message-State: AOJu0YxssaSPrt0sdHeBztL8ZuvgqmU+fWq8Fm9kPTbpzN3Rrnyfqklu
	6jADwnjVBkpAnLD+x+luA4Ruq0cfM0DC/NRDGXVVXQEP+my2KaOj3pBL
X-Received: by 2002:a05:7022:418a:b0:119:e569:f61b with SMTP id a92af1059eb24-1248ebfd834mr2452294c88.20.1769459085733;
        Mon, 26 Jan 2026 12:24:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EIGFzU9/yv2wX/pFAd3d+ikaYPhsXvfGdytJbchoyu2w=="
Received: by 2002:a05:7022:b057:20b0:11b:50a:6265 with SMTP id
 a92af1059eb24-12476ca9864ls2615295c88.1.-pod-prod-06-us; Mon, 26 Jan 2026
 12:24:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWL4Oe44cV4SD6ZLDQ3FW5Y8Mw601L3Gse6MUCle/cCBhshOSh/4aDJjvoIDBNHG8yg6s8rkZqNbQM=@googlegroups.com
X-Received: by 2002:a05:7022:458c:b0:11f:391c:d01f with SMTP id a92af1059eb24-1248ec72ae8mr3142453c88.38.1769459084049;
        Mon, 26 Jan 2026 12:24:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769459084; cv=none;
        d=google.com; s=arc-20240605;
        b=BAf3wpghuEsk6b3h0ag+NUNltT3WTMC46jFPtVAd0P5vI6bjxZ/VQ8X6y5WNk4Eq+t
         W5XULti+stBTye6hPjE4DWrpRVgRugiqh9xxCwOXF6GAdWVi9vhHReIghXiHJB0K/i5l
         MpxsNCsA162vBwGM/CVJuBreBcjHmgA4JOIZZZoLEYpoAfeZV0Tv5Fgqx/04oLVsx55t
         TlU0mrgCb7/lxUPF9/oq20NQY9E9/ocWAVg18jWoukCkf+MnSxzzxydMEx85hF8KTYnT
         aMizn1j7IogPOZfqQVPBEcqE2lAeNBx7Y9TWuvnnnbU6nqQa/nHfnOzvX+F1ho6ekY9w
         rmzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=s9/FLp6zQORTv0AYjCuv1LGIr87hr2dSo9S6dnUVO9E=;
        fh=fhitneNq2Ky37/1RE/YnDZbHaCNxZGcQYezS0gy3dmc=;
        b=UqItis6ovd7bop59gpUfx6ejsQ9a2jm9B39BpTp22Q8wlBkhj6nH9HvylFx6kuTcZa
         tssyspOmYBhgM99NFSPIOPAiRJQQteSj+zUJ5dCprnZdKijhjNWTtPUstGe8px0R60ge
         mFzafOm5++ba895dUFZGiy974PAaVcoTAQL/v3VFApcbg0W/70Sqv77WnEXt+4YIwb8G
         8ea6t5Hhkiysipl0W+0cJFf94XL1/WV4LbwQrC5hFEaW0fE7m9w6LzH0Byd+xuNYo5za
         TikR/R/f/QOfq/kAsE18XqERCuKKeg1Oik5LCb6qTuN2APTE3PIgr8hVrj2XKFJl2HTj
         DHmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=UF0k3RRl;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-1247d995c7asi354322c88.3.2026.01.26.12.24.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 12:24:43 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 35FC740804;
	Mon, 26 Jan 2026 20:24:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8E8D5C116C6;
	Mon, 26 Jan 2026 20:24:42 +0000 (UTC)
Date: Mon, 26 Jan 2026 12:24:40 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Ryusuke Konishi <konishi.ryusuke@gmail.com>
Cc: Andrew Cooper <andrew.cooper3@citrix.com>, Marco Elver
 <elver@google.com>, LKML <linux-kernel@vger.kernel.org>, Alexander
 Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Thomas
 Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav
 Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, X86 ML
 <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Jann Horn
 <jannh@google.com>, kasan-dev@googlegroups.com, stable
 <stable@vger.kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [REGRESSION] x86_32 boot hang in 6.19-rc7 caused by
 b505f1944535 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
Message-Id: <20260126122440.78e7ffebd5257e5ce00fa35a@linux-foundation.org>
In-Reply-To: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
References: <20260106180426.710013-1-andrew.cooper3@citrix.com>
	<20260107151700.c7b9051929548391e92cfb3e@linux-foundation.org>
	<CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=UF0k3RRl;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
X-Spamd-Result: default: False [0.29 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MV_CASE(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	DMARC_NA(0.00)[linux-foundation.org];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBCT4XGV33UIBBDM337FQMGQEVEDLGPQ];
	FREEMAIL_TO(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[16];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[akpm@linux-foundation.org,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux-foundation.org:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: F40B28D080
X-Rspamd-Action: no action

On Tue, 27 Jan 2026 04:07:04 +0900 Ryusuke Konishi <konishi.ryusuke@gmail.com> wrote:

> Hi All,
> 
> I am reporting a boot regression in v6.19-rc7 on an x86_32
> environment. The kernel hangs immediately after "Booting the kernel"
> and does not produce any early console output.
> 
> A git bisect identified the following commit as the first bad commit:
> b505f1944535 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")

Thanks.  b505f1944535 had cc:stable so let's add some cc's to alert
-stable maintainers.

I see that b505f1944535 prevented a Xen warning, but did it have any
other runtime effects?  If not, a prompt revert may be the way to
proceed for now.

> Environment and Config:
> - Guest Arch: x86_32  (one of my test VMs)
> - Memory Config: # CONFIG_X86_PAE is not set
> - KFENCE Config: CONFIG_KFENCE=y
> - Host/Hypervisor: x86_64 host running KVM
> 
> The system fails to boot at a very early stage. I have confirmed that
> reverting commit b505f1944535 on top of v6.19-rc7 completely resolves
> the issue, and the kernel boots normally.
> 
> Could you please verify if this change is compatible with x86_32
> (non-PAE) configurations?
> I am happy to provide my full .config or test any potential fixes.
> 
> Best regards,
> Ryusuke Konishi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260126122440.78e7ffebd5257e5ce00fa35a%40linux-foundation.org.
