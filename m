Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBJOM37FQMGQECOHVOII@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6AOBKSfmd2k9mQEAu9opvQ
	(envelope-from <kasan-dev+bncBCP4ZTXNRIFBBJOM37FQMGQECOHVOII@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 23:09:43 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F0348DDAA
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 23:09:43 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-385ba7acdd9sf27093801fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 14:09:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769465382; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xe4DYpirnEhdcKaVDxKFqM95q6Dtft7JatyIdoYbd7QH+n7shkKHEEENtcg41MhRQ5
         yi0bXWO2pADpowaX8bfRyjpGL2zqAD/1uOQc6aG06eme8T3sOAC5U9J4E3PYfu79jiXW
         57owtrHw+8JQ+9VTSNetl+jkR+ImCKFoAKAY6V6g9oO/kWrQjgPKoQEex+kFfy8eYs+m
         HvYsCAdB4wN1qhUuejnE6cGiQh0/RxYV522U9lrz2PX2Hlf5XIz7FBCHkf23ydi4xA7x
         e2Cd/0/ggqWwZdP7aN9VTGKFyoEv08GNK7VyETlK9BW1vm9zfsTsmBtTUs0FI1WJCD7U
         Za6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nN3NMn8EXPd+T+Ji5d3HqoQCi4nOgnJsWxKhBVyzKGQ=;
        fh=hscjahQcSVHwTFzl02qLiB+xm0+ERsZn+kkMk2Sv4Do=;
        b=Ey11YJS/JxZ96U8yhyTXE0XjdXe90c3l4hx/Q53ieBQ2cEjd3WgLs/L2RvKtkrqy8+
         JrQSuNa7HYKVIHLLg4cxlaI3Sf7cCnFy5vfbMlrX/KGryAPWJ0rbk0VENSSffWOAqGAo
         lpA4maXSsLxkMveztQ8NIBxmWWXKIh0XiN6U9ShefJwTF3TvoH7pdJ9djGYfwRrlX1LT
         VvDvh0Cs7LgT/ISOSPkB6Fm1wY17Uz3V0SSXRPmEqNuKrWaZTDv6mnjmVUqzDVvLjAMv
         nfmFnVD5f6VjW+BY7y27DQ2r60TFu8NvUZHpbSeqlNHzd156RRUKCEmFAEEUJh7xZmnp
         52Kg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=PHOfMxqG;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769465382; x=1770070182; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nN3NMn8EXPd+T+Ji5d3HqoQCi4nOgnJsWxKhBVyzKGQ=;
        b=fp+FciVbJ37Mn+Mxm6AAqjINXX6xShpm7zFvWhmrO4aiTO7ue6HNGVWRHA8Vfi/pk1
         VAC7kduvCapuomykabXbM+gDBX8iS2hv+DwjDnj2NhJNdEabl4ONvwVtNqgU+/QNDyRq
         lbV/HIjIOBhvuaAo3li57ZCAwNaplnIUbcAhE9rg3MCFbxqniX1vggZdQLMgV59KMxVn
         WWz9uoo2qYKqBoJIxwVuDjEEaCOh4ZytbuKORH7bSH9ur+XUGbRhAmiElJHXsxgE+nrl
         vibSpZ4WcmAcySmOc0hee09ymW3v3zoMrjLGo/p232glkZV0CM6gkpWf8l189DVyVBMa
         nPCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769465382; x=1770070182;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nN3NMn8EXPd+T+Ji5d3HqoQCi4nOgnJsWxKhBVyzKGQ=;
        b=rPEHVQyBNOhlD9THLmyXSzSb+ir1eGvyX3CXmSvG9/hOTaQ41NXFdDhgVcN4NvNHfd
         ogvsi2a28/ZjuGz4O480l0sEa6hgLipud+sZi9CYp0GUXZ4ZMG3qUtR17JLNo/Fb7TCQ
         8+a08vWIx1cIRsRWkQOzQQWWKPyYRDjNetnVT9YwJJiMI0rq5aQbR4deYImDmAPl6/6l
         mIppXOoC14HEpOq0a9yJUU3wZqTt/ucaBJh3urCcX4F+GDTcKq28ekD/KcFQg+MaULQP
         s8XeFy6ukAwGANkqpFxquXuWVrdB7gCN9d0zZr7uv8khacdAfxyvTQGVccVm58OFeL1n
         fhQA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVSPWFQ1+WEFVWzpK20PWsDfzwopsO86vnrgXbZ3IbSIKvZU1sAD/J3LJ3Rpxw5viX/Va/U/Q==@lfdr.de
X-Gm-Message-State: AOJu0YxH3TnzWGcfEh9PkscR4oAK/T120JxW0xw+Sh2/tpCe7joVZCVV
	BNqQ70qZ8859NWtocq7U+zMjS2V7MEO6f8smp/fP5OCwlWjoUSYT7gHy
X-Received: by 2002:a2e:b892:0:b0:383:1b4b:c2b7 with SMTP id 38308e7fff4ca-385fa10863cmr16712691fa.19.1769465381965;
        Mon, 26 Jan 2026 14:09:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EPyECaS04Ajq0lInME/nXZaADxOUDJiov+WGgnY65Q1w=="
Received: by 2002:a2e:871a:0:b0:385:ba7e:10fb with SMTP id 38308e7fff4ca-385c269049fls7826091fa.2.-pod-prod-02-eu;
 Mon, 26 Jan 2026 14:09:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW9hB0RbhzrLXBd2VSeoRI8QZg4ANO7m7fCcCGYN9QrAsK3BcOZ0Nyg3ysFfRop2Z8xpYwpHkT2rnM=@googlegroups.com
X-Received: by 2002:a05:6512:2c8e:b0:598:f283:e12f with SMTP id 2adb3069b0e04-59df360afb0mr2102649e87.11.1769465379258;
        Mon, 26 Jan 2026 14:09:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769465379; cv=none;
        d=google.com; s=arc-20240605;
        b=PEmju9oUPl6a+KIMyKLrO0c/h0MGdl7zcWCFTF+Ilbq8ZAWaNUTuVHyygjhFJVCcKF
         GVMfA8T7F7+FkWF3tYb/9UsGbgCH0pcXtxFE2EmiiJLA0btAohNiq7knIZLut7W16kWH
         vvgqIRmtFz5/k3GwtJEYp+qc7C/wL5V7Sy3E6LhBoaUdTmdt0tQZpZiO08gP/oNLujc0
         q+XN5RwhjXtuLdCMbTEwhh1l9PmsnNvd0wGbo6RUqf7JbwPYyhUblsPlZcg+zizEyH0b
         vYs/WhDDIR+pW7iicbTc7Q720tS3k5xlCNuKbUcZdQTjBJo9NnHmMtJoyWr6hh2SsYy/
         GDnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1blScGLzi5hAP+wiP8i7R54MFzXLgUkQjMIyXxpjKTg=;
        fh=Vm/2LtM8D83+qLm3NgfHK9/EKyNI6L28rJF0OfGohlU=;
        b=KQun3iLA3ZWBE6iwmPVx07YUxOHQhkvCp7WQUxrn8XEwiOc9ab1My7s/rTOCuok3ks
         x77ShwpqshOwD/DVJq23VnW+gAAKXKErIJRXF4BUpkITqXCsSljApgc/cPawlGe0Lrca
         DxyDPUsPiUkPVJJMHAkC8Fj+Q4+uUoJpLymr5HXvMslKVZKN1GdK7zeN8h3oXtpzXN0Q
         GsdshjwQ5Rhuvfm8DQRBzsQ5tLZ+wW6dckDM0AqqNaeLVCJO+NMCxQRXvPY0Ljcf/W5P
         c1eZNUiYr5dhkTOyL53pKxJn6jYU4fnfS4hR03olcPVSRkYzeORv4Wyd/GqcE4VBfR5G
         jZWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=PHOfMxqG;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [65.109.113.108])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59de4913696si295592e87.7.2026.01.26.14.09.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 14:09:39 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) client-ip=65.109.113.108;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 9165640E02F8;
	Mon, 26 Jan 2026 22:09:38 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id MFDnVfE3i6k8; Mon, 26 Jan 2026 22:09:35 +0000 (UTC)
Received: from zn.tnic (pd953023b.dip0.t-ipconnect.de [217.83.2.59])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with UTF8SMTPSA id 29EF740E01AB;
	Mon, 26 Jan 2026 22:09:21 +0000 (UTC)
Date: Mon, 26 Jan 2026 23:09:15 +0100
From: Borislav Petkov <bp@alien8.de>
To: Andrew Cooper <andrew.cooper3@citrix.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
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
Message-ID: <20260126220915.GFaXfmCwu_0xOk8TmX@fat_crate.local>
References: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
 <20260126211046.2096622-1-andrew.cooper3@citrix.com>
 <20260126132450.fe903384a227a558fab50536@linux-foundation.org>
 <20260126215610.GEaXfi-r-5g-9SAVMI@fat_crate.local>
 <fe0e90d2-6237-4a23-baec-dbf8eeb45fc5@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fe0e90d2-6237-4a23-baec-dbf8eeb45fc5@citrix.com>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=PHOfMxqG;       spf=pass
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
	TAGGED_FROM(0.00)[bncBCP4ZTXNRIFBBJOM37FQMGQECOHVOII];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[bp@alien8.de,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[linux-foundation.org,vger.kernel.org,gmail.com,google.com,linutronix.de,redhat.com,linux.intel.com,kernel.org,zytor.com,googlegroups.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,fat_crate.local:mid]
X-Rspamd-Queue-Id: 4F0348DDAA
X-Rspamd-Action: no action

On Mon, Jan 26, 2026 at 10:01:56PM +0000, Andrew Cooper wrote:
> Thanks, and sorry for the breakage.

Bah, no one cares about 32-bit.  :-P

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260126220915.GFaXfmCwu_0xOk8TmX%40fat_crate.local.
