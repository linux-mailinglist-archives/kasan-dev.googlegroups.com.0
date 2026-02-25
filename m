Return-Path: <kasan-dev+bncBDZYJFO6YIBRBFPO7XGAMGQEDJMWKJA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id QMf1ERh3n2nScAQAu9opvQ
	(envelope-from <kasan-dev+bncBDZYJFO6YIBRBFPO7XGAMGQEDJMWKJA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 23:26:32 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B197719E414
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 23:26:31 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-679e5688b33sf3409374eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 14:26:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772058390; cv=pass;
        d=google.com; s=arc-20240605;
        b=SsYEFxpB9EuS8PqsCq3QqCCR8YAXFKSTp+ErzwMgSoBgoI2bss5RuVHPYPzwCcF9h8
         fOEhb+NHEMsdZ8MaDX3yqYw/5KUD+vj71Xv5+G/K7B+ZKJz/NLv/BmMNz7MVejGbN2fA
         cnYJMy52OHSWHNyssWmhGHmrq9T0FqOMY7z3EIxn8ZWeLh7WCNDbr+pkG2DQuY1WBEVO
         XSU4pmBY7AQjayORF4+65chC1JIuGkK89WCG88VxV8r3vo0MXDDFSHt8GgzkrSPd+4R8
         74NwuKx1O/II1AMM3roR0d3QQ6LB1S2Kzee9njA0fWT2CS5bR2Z2KXnlekRw8x5Nb9hw
         dmFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:autocrypt
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=/8DWdURyW5t89f2jxe992jM7MFD3Nxt66KwiCYcKBLw=;
        fh=cEfree2naOzQQDf4KrNlZ28LSvs8pjumRM9k7vW6s6Q=;
        b=BMDYg0k8P03Ku+3xh7r+9MwLRtlFMoW46wHRRDdT3K2Z1jhjD7XCTovpOivyksmz35
         Ij+piP5vlUwXKj5I0U9/0CMamYd6zl646+la3gMMNV0HAQa38uSiEqpwHKjl6bRcZ4sP
         QJcDjNsNC5HjAcr5/QjumrIz7CUu9VqDUdCPwmUEMGgR2AU3t2YJ4JL9maTKGazG8vEu
         wEeS0GjKmZ7jQehho9WYTir7GVJDS0kSOdrbGEUu5uWRLWi839wN+QWfgWNEmJ6ckIKs
         OlTh+jLUE0YapoPExFuyb0J/WCLleDFcNhz8cYxIco2eSluOCiDPKxejUrss0R4/eKDA
         cfow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@surriel.com header.s=mail header.b=mjCBY0xh;
       spf=pass (google.com: domain of riel@surriel.com designates 96.67.55.147 as permitted sender) smtp.mailfrom=riel@surriel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772058390; x=1772663190; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:autocrypt:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/8DWdURyW5t89f2jxe992jM7MFD3Nxt66KwiCYcKBLw=;
        b=C0zYvBoj+p3yBgDA9G8ZOGQwjdIE/HE+WTImxa13qDC/yhmaPspn6Mn24ZmQQNxoyM
         zrlsgJQqeQ9RBxAL0E571x+tSIdY7xsWu7udKEdU+TGFfQ1qjs202bQi6mTEuIxMOlro
         +w2/YjoxCm/8XgUf2qLWFPXHTKj1xMk7MOnKCBcGv7VAs0CFMctqTQP1syOoCNnHBoh3
         bciAOho1PHsu8gyLavlhuvcJ9PqKLrtVICuL99seBrQz1fPsXJWL3i8ZCRfHuplk5Jfe
         XW/hDGfBrFk2u4Ih1oPPZx+7YfqYaqHBb5NtwXrJBrlntZjb9MQGVpi251rbkATJUBUE
         q0/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772058390; x=1772663190;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:autocrypt:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=/8DWdURyW5t89f2jxe992jM7MFD3Nxt66KwiCYcKBLw=;
        b=tkRvgwVkcqhJ83Pze7eBIQRw8F6nT/W9wdMxxSR4FxNgJU6qjkSxB11QSH3+gjuTtG
         eb2TWA4I2lM9BLSwODdh8PzeI/HhoopE4A6NuSNgU8JRO3vKn9r0+m2//SLHfqm4LUU2
         mGAI40ySUNIsdH48D5FI9f/o2ZQ+SOPfoGPwsAYqoxIJcf5LBqTG9NTXTGD7bngmviB9
         cg9my2pphW0c7KVzy+qPI1S84QrKFbED2rLgEkpbGvCtIOcCz5O9KAwp+qw7fs0Dpakp
         NoSnmdrAplIT+qoW2xctkAfPl1b5Ma5S12d0/oXY07jOzhkniSJDQisfcCp+MAWFHSPm
         soTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWVd6MzK1UcQM5VgOXAtMdoDwtFB/kAAEe35Q8Bz4jjtLmAP52obL0TURcyFEDeOhaGsnUEWA==@lfdr.de
X-Gm-Message-State: AOJu0Yykw20y/Gwuw37prsOl1gvwbb09zNHbk/jLUha7QlPAnnNMF9GV
	z8wDIhOsEu+RbTmtVbOQtYzRlhV68zD5Esu0InZtJ67+UffCN/519MT9
X-Received: by 2002:a05:6820:1904:b0:677:bd4a:8f75 with SMTP id 006d021491bc7-679c470f3fbmr8500085eaf.61.1772058389803;
        Wed, 25 Feb 2026 14:26:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GVhhYvFiDt+bapYle8O9Jly0JTZToi3nN3eDFEgM3Wug=="
Received: by 2002:a4a:db6c:0:b0:679:e9bd:73fd with SMTP id 006d021491bc7-679eab455dels294560eaf.2.-pod-prod-02-us;
 Wed, 25 Feb 2026 14:26:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVLmhTew+FmrqREn1LBedqpilouKTNV21L9+GLfuh3mFZQkH6bP5wmP424xlF3whw5vJsBzkv4UO6Q=@googlegroups.com
X-Received: by 2002:a05:6808:c284:b0:450:d143:b77e with SMTP id 5614622812f47-464463e6036mr11026829b6e.58.1772058389039;
        Wed, 25 Feb 2026 14:26:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772058389; cv=none;
        d=google.com; s=arc-20240605;
        b=UO13eHHcY8HvtEyrRZz38EEKhy63Itw3J2hXATUaR+tYEBQeuPSFO0m4KohoqqT2it
         56ONKUQ8CWELLVBimwhg+9llPJf+JFl8J9bZmNL6iEzghWULmYLY9fwdHmUkPEVZI8Fb
         JLbXxW6/Tex0SYFlWwE4Eg/xeNKTNqA5Vn2zuUNWhHgEngyD+kXpS5XZWByfXasi+ITg
         VfkWAey3PV0CK1orih8vpnMN5FWRCDxKgjGhsSa7QWL3yQJPfN8clUnkNVFbcx/J2Rna
         BayzSmY2K50uU5FZgShlT5ElKGgRCOTmlutYgk/OeJJEM1nEWG5MfAEr/lNHz5y9HrKm
         jSmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:autocrypt
         :references:in-reply-to:date:cc:to:from:subject:message-id
         :dkim-signature;
        bh=Fy3cH2rzILpqMLlhVdZJPMYEJrn96kG/FRu7cB1YPhc=;
        fh=rrVrGsY/qvS4annhlm4xJXz19B1wr+hzUcGc0kn81OU=;
        b=UCd5JKbwwdaGyECOOyrm20IqY3v6496tmRWYO7u77+gZbhqH8LR4SN4kKCRAnGlqUw
         4rkFxnzDMzmhYz6IGaj1anhJErtoBF1Q+sD2Y4B7aHEoq+UELYa/oezx9wW8RgSrg7yF
         FF8f31/hyP5pQVRVqneoHslGtRDzSaSI37WeEXnWn3+Ov/39NifVmScDT5WB767BKJNH
         8TBOX3s59rE1iYlu4+pGB1ub0Fb3bfQOYkGSvkW+4E+o0rZ85NAULmNLdeJWF98qAE7u
         SXPl87w7sewVpgPVZorcSAM6YKctkwnurttK1y8HMp6RWM52xSzOmTVai2JmWGyP8L2p
         ihig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@surriel.com header.s=mail header.b=mjCBY0xh;
       spf=pass (google.com: domain of riel@surriel.com designates 96.67.55.147 as permitted sender) smtp.mailfrom=riel@surriel.com
Received: from shelob.surriel.com (shelob.surriel.com. [96.67.55.147])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4644a1934ccsi468435b6e.7.2026.02.25.14.26.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Feb 2026 14:26:27 -0800 (PST)
Received-SPF: pass (google.com: domain of riel@surriel.com designates 96.67.55.147 as permitted sender) client-ip=96.67.55.147;
Received: from fangorn.home.surriel.com ([10.0.13.7])
	by shelob.surriel.com with esmtpsa  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.97.1)
	(envelope-from <riel@surriel.com>)
	id 1vvNKT-000000001pm-3AfW;
	Wed, 25 Feb 2026 17:26:02 -0500
Message-ID: <9476ab2ff783c77ff4f1d323fad3e356bb172fcd.camel@surriel.com>
Subject: Re: [PATCH] kfence: add kfence.fault parameter
From: Rik van Riel <riel@surriel.com>
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>,  Jonathan Corbet	 <corbet@lwn.net>, Shuah Khan
 <skhan@linuxfoundation.org>, 	linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, 	kasan-dev@googlegroups.com,
 workflows@vger.kernel.org, linux-mm@kvack.org,  Ernesto Martinez Garcia
 <ernesto.martinezgarcia@tugraz.at>, Kees Cook <kees@kernel.org>
Date: Wed, 25 Feb 2026 17:26:02 -0500
In-Reply-To: <20260225203639.3159463-1-elver@google.com>
References: <20260225203639.3159463-1-elver@google.com>
Autocrypt: addr=riel@surriel.com; prefer-encrypt=mutual;
 keydata=mQENBFIt3aUBCADCK0LicyCYyMa0E1lodCDUBf6G+6C5UXKG1jEYwQu49cc/gUBTTk33A
 eo2hjn4JinVaPF3zfZprnKMEGGv4dHvEOCPWiNhlz5RtqH3SKJllq2dpeMS9RqbMvDA36rlJIIo47
 Z/nl6IA8MDhSqyqdnTY8z7LnQHqq16jAqwo7Ll9qALXz4yG1ZdSCmo80VPetBZZPw7WMjo+1hByv/
 lvdFnLfiQ52tayuuC1r9x2qZ/SYWd2M4p/f5CLmvG9UcnkbYFsKWz8bwOBWKg1PQcaYHLx06sHGdY
 dIDaeVvkIfMFwAprSo5EFU+aes2VB2ZjugOTbkkW2aPSWTRsBhPHhV6dABEBAAG0HlJpayB2YW4gU
 mllbCA8cmllbEByZWRoYXQuY29tPokBHwQwAQIACQUCW5LcVgIdIAAKCRDOed6ShMTeg05SB/986o
 gEgdq4byrtaBQKFg5LWfd8e+h+QzLOg/T8mSS3dJzFXe5JBOfvYg7Bj47xXi9I5sM+I9Lu9+1XVb/
 r2rGJrU1DwA09TnmyFtK76bgMF0sBEh1ECILYNQTEIemzNFwOWLZZlEhZFRJsZyX+mtEp/WQIygHV
 WjwuP69VJw+fPQvLOGn4j8W9QXuvhha7u1QJ7mYx4dLGHrZlHdwDsqpvWsW+3rsIqs1BBe5/Itz9o
 6y9gLNtQzwmSDioV8KhF85VmYInslhv5tUtMEppfdTLyX4SUKh8ftNIVmH9mXyRCZclSoa6IMd635
 Jq1Pj2/Lp64tOzSvN5Y9zaiCc5FucXtB9SaWsgdmFuIFJpZWwgPHJpZWxAc3VycmllbC5jb20+iQE
 +BBMBAgAoBQJSLd2lAhsjBQkSzAMABgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRDOed6ShMTe
 g4PpB/0ZivKYFt0LaB22ssWUrBoeNWCP1NY/lkq2QbPhR3agLB7ZXI97PF2z/5QD9Fuy/FD/jddPx
 KRTvFCtHcEzTOcFjBmf52uqgt3U40H9GM++0IM0yHusd9EzlaWsbp09vsAV2DwdqS69x9RPbvE/Ne
 fO5subhocH76okcF/aQiQ+oj2j6LJZGBJBVigOHg+4zyzdDgKM+jp0bvDI51KQ4XfxV593OhvkS3z
 3FPx0CE7l62WhWrieHyBblqvkTYgJ6dq4bsYpqxxGJOkQ47WpEUx6onH+rImWmPJbSYGhwBzTo0Mm
 G1Nb1qGPG+mTrSmJjDRxrwf1zjmYqQreWVSFEt26tBpSaWsgdmFuIFJpZWwgPHJpZWxAZmIuY29tP
 okBPgQTAQIAKAUCW5LbiAIbIwUJEswDAAYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQznneko
 TE3oOUEQgAsrGxjTC1bGtZyuvyQPcXclap11Ogib6rQywGYu6/Mnkbd6hbyY3wpdyQii/cas2S44N
 cQj8HkGv91JLVE24/Wt0gITPCH3rLVJJDGQxprHTVDs1t1RAbsbp0XTksZPCNWDGYIBo2aHDwErhI
 omYQ0Xluo1WBtH/UmHgirHvclsou1Ks9jyTxiPyUKRfae7GNOFiX99+ZlB27P3t8CjtSO831Ij0Ip
 QrfooZ21YVlUKw0Wy6Ll8EyefyrEYSh8KTm8dQj4O7xxvdg865TLeLpho5PwDRF+/mR3qi8CdGbkE
 c4pYZQO8UDXUN4S+pe0aTeTqlYw8rRHWF9TnvtpcNzZw==
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.2 (3.56.2-2.fc42)
MIME-Version: 1.0
X-Original-Sender: riel@surriel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@surriel.com header.s=mail header.b=mjCBY0xh;       spf=pass
 (google.com: domain of riel@surriel.com designates 96.67.55.147 as permitted
 sender) smtp.mailfrom=riel@surriel.com
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	DMARC_NA(0.00)[surriel.com];
	RCPT_COUNT_TWELVE(0.00)[13];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBDZYJFO6YIBRBFPO7XGAMGQEDJMWKJA];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_NEQ_ENVFROM(0.00)[riel@surriel.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: B197719E414
X-Rspamd-Action: no action

On Wed, 2026-02-25 at 21:36 +0100, Marco Elver wrote:
> 
> +static int __init early_kfence_fault(char *arg)
> +{
> +	if (!arg)
> +		return -EINVAL;
> +
> +	if (!strcmp(arg, "report"))
> +		kfence_fault = KFENCE_FAULT_REPORT;
> +	else if (!strcmp(arg, "oops"))
> +		kfence_fault = KFENCE_FAULT_OOPS;
> +	else if (!strcmp(arg, "panic"))
> +		kfence_fault = KFENCE_FAULT_PANIC;
> +	else
> +		return -EINVAL;
> +
> +	return 0;
> +}
> +early_param("kfence.fault", early_kfence_fault);

The other parameters in mm/kfence/ seem to be module_param,
which make them tunable at run time through
/sys/module/kfence/parameters/*

Why is this one different?

And, does this one show up as /sys/module/kfence/parameters/fault?

Having the ability to tweak this behavior at run time, without
requiring a system reboot, could be really useful for people
unexpectedly triggering kernel panics across a fleet of servers,
and deciding they would rather not.

-- 
All Rights Reversed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9476ab2ff783c77ff4f1d323fad3e356bb172fcd.camel%40surriel.com.
