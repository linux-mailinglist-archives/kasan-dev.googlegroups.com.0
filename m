Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBFWG37FQMGQEALZ35WA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id MAp+KRjjd2k9mQEAu9opvQ
	(envelope-from <kasan-dev+bncBCP4ZTXNRIFBBFWG37FQMGQEALZ35WA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 22:56:40 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 49A928DBCC
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 22:56:40 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-4802bb29400sf88512735e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 13:56:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769464599; cv=pass;
        d=google.com; s=arc-20240605;
        b=LTRbJhsOYXooDg8hqhnKpiARimznpk8OHhTDD1EN0q52IQV78RuygGS95xUbJW5vtY
         kSvJ0WQga+GwCGHHXqPq6VHGadirPorJPyQLotKngABcYQJqW2N9BPJQN08VIZ41/5l0
         OrBGw22sw+EKXCVqLjO5iGlhMEdpdoKF8T/I2vdHvpKRXeeA6QD6l2Oqlh3idKnpMWcl
         BzpfCpUZilAvmg3QDqRWfE78Pb1WnixsxDLJpyhLT7Ws+CTWbwtEWU6TAbxpUdsGi5E+
         NlYiNv5A1Re7gfID1oIzn9x9cCfNMjorsZCnSRF1xwLtniF8mQkaYyQM1bWgmLnJUlmf
         zLzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=v0jVnaHAxxIfQmMaoWA44o7T1gK78b8OF0XWIGaS8uc=;
        fh=Znhz07I9l6i4zpXdiqAO0RStK97D40RMnCfBxToy1cM=;
        b=Fwm+oDd1e8bhyz9D73gt2hXWzbdiyMqoKrvxQlWk3jfTsPG+IAWDeo3Sx1VuwUAeh8
         I5Hg+3qoIdUwNqJ2xEIMBPG5eVOv0qJzL0ahfTWmEKqo0V1UKjhfY+QzyeIOTNi7qQsL
         ZabFOzmW25tTE77uI9c1xas/voiBCgpPHCxqfC2Yl/0iC7NzCfKst/QLSPj4XL4h3YEJ
         6GMa+GA4nTSif2Ja7rhImW35Wnk0bhSSRMvTri6sYG/Gb/Wb/svuR9W8bYTM7RjIOIq2
         Z/dh8CJn4jvAAB9XewFM0fMOw+ZZayckAxXLHdghJxmrWgfPwoQFhjNobi2rQbhfYfiP
         xe2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=BsMxEQIf;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769464599; x=1770069399; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=v0jVnaHAxxIfQmMaoWA44o7T1gK78b8OF0XWIGaS8uc=;
        b=BCq0hNJkH4AZmJ3sCw+PZ0bZShN5CtAcb0L7VmMrjDRy2EPAJTOb9DLpX4SC0QxdNN
         3wfBgxKLnjOdY57mLugGUfV0EmeasRHsdXoIFTpfj56XbZzAGly50+6ByyMjJVl4aVZm
         EAIVd5xGQyjle6tsbz3nvlhXbod9fjgzglLPEgvsDHq0s6zAzZsLUiPXKWsqVRGGdSxp
         db/ijQeFF3Yf1TfmnUQ64zVzVlLfXzTUAZWt16Giw4fI9yS0n6M8zdLmILiVSyaY8NZE
         /dq00U5X1DdXt8N7N3I1Y1M6+wiNVTwO4/71cWiafcFUbmMz//c+r46EV8VyAHbFpiuD
         WdIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769464599; x=1770069399;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=v0jVnaHAxxIfQmMaoWA44o7T1gK78b8OF0XWIGaS8uc=;
        b=OSojeI0aLnHUiGv/6JJ69IAAvvIb6Veh31CPyqM7vn+SF/J2o3s5DjkDmfoZ5w8Ts8
         UpDewhW97P56xNk4AKyGz0AvIG38ackWLjTLR+x/351Tdzwqs+UE68cYNwgv3dIL0buX
         GSJm8YKy4JELh4GLKFFdsfr+OoPcQfSIxhX39tn4XuOBS1/JTs9IOeURCAV/morSYy6G
         7gxASmNGMCthZQfW8inwPPEMKK4VYYjAy5iM8ZXaZv6o3ooaf4H3hhRub8iQVFVOtFE+
         +Uz8rLMZIHGclRIXUHOB9lVRNoXGvh52U/YvOg68ygcNcyAOUIAH9bFpVOUnrycQEpN0
         t2Ag==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVPx4Pa33MtirlROmR8XlARrz/fROpiPeDBGrKNdym1njdOI+I8fbCrqvERDxGxr+nuHxwNLA==@lfdr.de
X-Gm-Message-State: AOJu0Ywz6I8LI2WC6NZWiz/mlzikshZMELZvnS/5IMQ8ztNmATiutlj7
	S+wT4AkamD8YNEn1OB82FC0XYS86hX04UHwYWSBFZNETNgmyk5yenm10
X-Received: by 2002:a05:600c:3112:b0:480:6873:b2f6 with SMTP id 5b1f17b1804b1-4806873b558mr627715e9.20.1769464599369;
        Mon, 26 Jan 2026 13:56:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GZ8b/ShoBmuHiZDbp3RjYf11HsbCKmXE8zU23yvBmfYw=="
Received: by 2002:a05:6000:1862:b0:429:ba6a:3a77 with SMTP id
 ffacd0b85a97d-435a667c87fls2662387f8f.2.-pod-prod-02-eu; Mon, 26 Jan 2026
 13:56:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVK7XqtcA3G8aqAlW4ZeX+TMm6xt2YKF3cAiXsmzQczWL2CIgbvCHAn1u0QL5EYYXLWEsLgPiTGw8s=@googlegroups.com
X-Received: by 2002:a05:6000:144c:b0:435:ad52:31d4 with SMTP id ffacd0b85a97d-435ca13028emr11181749f8f.26.1769464597004;
        Mon, 26 Jan 2026 13:56:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769464596; cv=none;
        d=google.com; s=arc-20240605;
        b=GlVnJt8wPPINsEcDjOQOyNGad3o0BYbjiVj4YrBZjbIHY/fnonbNs2Y3ZXPtQx+/wR
         RTCz+1LiuOERdyQHSViY6Ae+WfIkkVqTNsP9VNvddMlTioK6bBeH1qDCrptcQvp8ToBN
         zrYzYCPzH5oFHkgtQ9SQsWxVBo7S7O5Ycfc0XgD0Bo42FfVArJKbxVKI8a/rGAPkVcUY
         OCKku3/CmAIlg/7vy0Bf/DPb80WRyMxcD0AbTrLLeuredjOUCGpBMNvXoFXFPS6AfAC6
         /PKRIXEGQTUpOVDpiu/ydggUQX+r4+MJwrO+puLFV5MZ8Ivv4V4vpAziWiAqTEWtkYSO
         FFaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iSJwfulFitWdgm/6avIgIxYHwyeoxM3FVMdVMMx4hQE=;
        fh=xLK914fCnPEggIlidTdfGkGOMGCs9lgBcDslwoWmnbg=;
        b=f5RxmElA84FrjyIB9DOLEHKsImB9qo/pkvwRtFRTgT1wvS7Vo3ZWjleEDEwm9eK0rM
         0xgNrJB46r1ilmkpn5BfND0YsXLI2P3Enns5paiQM5BhNt3YjCXvtfAxckN0Tr0EIAW7
         EDHzqo8dwIZqDtyiUJfjl5DVOQWw62DRJFSi7kxEGWxc/J9mwqwX+qEQfIsZphUdt0JB
         2cdG1UbPZDRY5Twr2YqKRDeSaU7m13sCpRVbtRKRtRwYED2KnIYWbQSsk03QEiqbts33
         /iMlKIFAYmHrKO9tzTR5ITw7iBEt5qZwahn7zPxLnk3qBuvTIRsqSJjgXAz7yoOTxXpu
         78Qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=BsMxEQIf;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [65.109.113.108])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435b1c78615si293201f8f.8.2026.01.26.13.56.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 13:56:36 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) client-ip=65.109.113.108;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id EB15140E02F8;
	Mon, 26 Jan 2026 21:56:35 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id DSgKfzwrrwyS; Mon, 26 Jan 2026 21:56:32 +0000 (UTC)
Received: from zn.tnic (pd953023b.dip0.t-ipconnect.de [217.83.2.59])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with UTF8SMTPSA id BEB6640E02F6;
	Mon, 26 Jan 2026 21:56:15 +0000 (UTC)
Date: Mon, 26 Jan 2026 22:56:10 +0100
From: Borislav Petkov <bp@alien8.de>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrew Cooper <andrew.cooper3@citrix.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Ryusuke Konishi <konishi.ryusuke@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, Jann Horn <jannh@google.com>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v2] x86/kfence: Fix booting on 32bit non-PAE systems
Message-ID: <20260126215610.GEaXfi-r-5g-9SAVMI@fat_crate.local>
References: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
 <20260126211046.2096622-1-andrew.cooper3@citrix.com>
 <20260126132450.fe903384a227a558fab50536@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260126132450.fe903384a227a558fab50536@linux-foundation.org>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=BsMxEQIf;       spf=pass
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	DMARC_POLICY_SOFTFAIL(0.10)[alien8.de : SPF not aligned (strict), DKIM not aligned (strict),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RECEIVED_HELO_LOCALHOST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[14];
	TAGGED_FROM(0.00)[bncBCP4ZTXNRIFBBFWG37FQMGQEALZ35WA];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[bp@alien8.de,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[citrix.com,vger.kernel.org,gmail.com,google.com,linutronix.de,redhat.com,linux.intel.com,kernel.org,zytor.com,googlegroups.com];
	NEURAL_HAM(-0.00)[-1.000];
	MISSING_XM_UA(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[fat_crate.local:mid]
X-Rspamd-Queue-Id: 49A928DBCC
X-Rspamd-Action: no action

On Mon, Jan 26, 2026 at 01:24:50PM -0800, Andrew Morton wrote:
> Great thanks.  I'll add
> 
> 	Tested-by: Ryusuke Konishi <konishi.ryusuke@gmail.com>
> 
> and, importantly,
> 
> 	Cc: <stable@vger.kernel.org>
> 
> to help everything get threaded together correctly.
> 
> 
> I'll queue this as a 6.19-rcX hotfix.

You can add also

Tested-by: Borislav Petkov (AMD) <bp@alien8.de>

Works on a real hw too.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260126215610.GEaXfi-r-5g-9SAVMI%40fat_crate.local.
