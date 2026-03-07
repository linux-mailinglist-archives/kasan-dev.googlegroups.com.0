Return-Path: <kasan-dev+bncBDJPLAN63YNBBVEDV3GQMGQETQOSRWI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6MRrD9eBq2mwdgEAu9opvQ
	(envelope-from <kasan-dev+bncBDJPLAN63YNBBVEDV3GQMGQETQOSRWI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Sat, 07 Mar 2026 02:39:35 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id D7A6B229695
	for <lists+kasan-dev@lfdr.de>; Sat, 07 Mar 2026 02:39:34 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-679c5ed0942sf110356119eaf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 17:39:34 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772847573; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z+4ra+Wv96vgHkEETpIdQ2govglaBLbh7Tb0uPQur9RtwAyeaSV9Pc4quEBZ5T5g3P
         rjRUBGqlYXlVbuIpvkbPvMTzfyC1of82ujEaE7ZK0cTeRaGjNuHE/WM1kUQeMOQdQCBb
         Z8cfduRXEIpj8Pmx6w/Ydiwj7tAprq4VND/eD4hggw6wZA7r6/CF5qpsis0xgx5UIFvh
         bpyuHC9fl769iNdmZgc6jnGq7F9O1HIrd4lYJ/N3XnipK0W4bROUzNw4ydMYT/Wo15no
         q5ZxLJQf8H6is6wMTr/c1xAntRLdCJR3689JGUXk2VA4MffJEft+fjFrdN2XeNAwX7Ia
         +kEA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=A4U0JlpE8xX46STJXsjEa+mUZ6+8XViWZOXp9IfL4IQ=;
        fh=KToZONo4PmbBN+LIhYox95YxQHMhwjqMLdKZ2kTwF70=;
        b=QHoebqmri+33EbGKgmfJwCHz1/r+u2Gk8Dg9CWL3XqQmcaxU9FLSHsxkanl5VAdzAg
         +fU6BL7kjaGO7Fmh/baCGCtbwNl7MldcFzNHPdWJazvzibxDeEAMu6cfKCkm/ObrurjB
         EGUzsswf404WDoMSVp2fUdMgn0OqzI5PPjWzt/Uh792Fl77yCfCeVOqcEoWDaCmcVgOd
         LS2yhmohdkFqNmn/JQWcWkOHgXRil45Pdux8UBrBgCkENKt886Sfa3bF1ZuEP7W+rOhu
         BVvJ9qaD4fhkgq9BUzqbQLQbSy+rSlRekuwC8xNisB/dEYcroZmvnYk3Rnn2GkChmzoE
         V3hw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bbhBwUrE;
       arc=pass (i=1);
       spf=pass (google.com: domain of jiakaipeanut@gmail.com designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=jiakaipeanut@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772847573; x=1773452373; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=A4U0JlpE8xX46STJXsjEa+mUZ6+8XViWZOXp9IfL4IQ=;
        b=O5cUdiLJTTBOmGLD27aADKGdAmFsG/iNkbXR8iiuu+5rsC412nDl0P+SftssoSFNLR
         jepzj7e8VvUaaL7d97Jwy3GlA6yjRkZ2f++/6OXz3lm/dyKQRDsrS/SxmwVkWAJocJgh
         WHsaAdknDwgPG0KvKBjtjjQMpOF1VMTHhQ9gD+y6s2mquivpZfihm4k1UcJX+P7eQnWP
         MgJ4nYxjtlrf+HBfhQy7LtQj6wKNJwlZFKKc3QelTHbNhKX9DSg5wMx/OzpionKDiMip
         Czf99v8fkdM5LGBGBZ74RP/D0bRgNXHuia6tmmpTaiIRp2gYckVq5+UNB0ORTDdwc5Nl
         Z4dQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1772847573; x=1773452373; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=A4U0JlpE8xX46STJXsjEa+mUZ6+8XViWZOXp9IfL4IQ=;
        b=Zv6s9+FTb2JdvX2uhWQTo3mv9Cr1uBNj5EjrPg0v78KAKeOa4DdtF88IVm9bnxmhmU
         2VCWMGqKB8NzJfqCv/NgmdMIoiSHncH0d/R1OcD27p+gkEENq9vDtFun0LKX6NfcbuAZ
         Wc8BWS617ci/5oPQHp1y7JyHP9j6wRF1ITl80xHJklMC5tWiBiYPKKu4+m2C1YbpQTAH
         GudwoONY/H6BHJQ/PS0/+7gNFE37fhaX8QUAz4ZUvkIW2dmriur7aV1q0qdKRYm4F9PE
         hNrD6T4YihCvQM9awvSbuH+t3OJ911vqUyXESWGLcQkZJ6VR5kdPM5T+y75or5mWQHBQ
         Tijw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772847573; x=1773452373;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A4U0JlpE8xX46STJXsjEa+mUZ6+8XViWZOXp9IfL4IQ=;
        b=FxjIEz0BZJTxYGD7ZKrBvHXRfPoUI6zpCLn7p8w6a8Wqz38NHAGGGdgp9KbHIBKEZo
         I3OLWgMbHzJNpS2vhgRDo2NpQDRC5y7NrZSYggV3j1Fw4iDZ21aoiXlKTBG5OX+IQxtn
         56AOh5b6BTQcqM1HNNWnF7UHUlXDSb825nnid/7zPUIgkXBsHT64kTdhfOj7dn4xu665
         SW2r4haZMEg9ZraxAWECG042PDvRGFAAyhjDF3eIH14BoBOZgRAd3YJ9YE5k4ZedOR4P
         y2Fr0YdTrO/JOD6AX0ML26k7cwrhTdxnCHfVecKpolflTfQYhIonF4C625qvb7vk4joE
         qpww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCULvVjc0hMlbCbgRWh5peTjDbKPZKt00CoMiud+64I9g4T69Q9DEN+pUyTxUhfiE91iIia15w==@lfdr.de
X-Gm-Message-State: AOJu0YyEnTfYnWUCSzy5aKPQlNmfwnRz2yU4ioSlX/XsdmIbsK3hio6J
	QvdIUV6R0UlTDLGI+KpOgcOMSd4Kcs3b1bxVlFpJZTZPhlIQ3HMq7PO/
X-Received: by 2002:a05:6820:290b:b0:676:da74:842b with SMTP id 006d021491bc7-67b9bca9783mr2761954eaf.28.1772847572813;
        Fri, 06 Mar 2026 17:39:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GHUEEdKEIXaXf2tg2pM3nCEWm3HmvqNpqbTm80Wlhlcw=="
Received: by 2002:a05:6820:1c97:b0:66a:c0c3:3f26 with SMTP id
 006d021491bc7-67b92eee946ls1559119eaf.0.-pod-prod-08-us; Fri, 06 Mar 2026
 17:39:31 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCU87/0EBeFmuMTmAUKzzV0y9C9TUHEpYdqJCfrup6zuSzElm5BxRkMpnTAmLg7yX1MBMtieMa4WT2g=@googlegroups.com
X-Received: by 2002:a05:6820:4dc4:b0:679:be5f:afcc with SMTP id 006d021491bc7-67b9bca84d9mr2744557eaf.19.1772847571739;
        Fri, 06 Mar 2026 17:39:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772847571; cv=pass;
        d=google.com; s=arc-20240605;
        b=VduCkLVPW1hG1VxJ6M7PFcReT8iNpkmsQpxhNRXv/iTCpHd/J+ffxFW6p1y95nnWlP
         +ed0p/FGOTKGr9i6Pg0cxO1KhLqAw8bOsZXsNYS2NTQ7RdxygtjIYqOujLo1L4dsJOxW
         Avx2tKS9Puh2uCvsI3S8jkSZgrmv7HtcXB72KwzCm9F5iuCGAKt4JDpIWnx67TOUBUg8
         dednzW3pOWEawNlf6FutVmGPcW3OFFi3MfGcjUflcv6xJitud6qsb/rh+bGn8b+1GOCY
         Xw6Ah8SqkbV7FqcjvXYvbVyUHqDOcwb6jCvjVCcTWnsiVN/rUrrLbkrBwjH0ZW5rPnQk
         MKoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WUt9V96pGWBeEnbjx1PAHPx8YoZ8MwGfywkRHa4eCJ8=;
        fh=mvL6A4W8l8Wrjbgf/uX8wXTEcNSUsY7zFFgZm6MVebE=;
        b=MDQW7/mjU56BGpQD+HuSgTHMWLzCXOs/N2Nlvv+PC4WGctg65POk3FTT0LLu3sVXB5
         56Fy83KQaVDaTD+FLkfOOQOolIfbK55zWP3ah/OvNEH3l6QoFd77vXlratZx7NWibK7i
         EeHpSjULBd3f6dhzvg+msvVTfPND1uIgNT5oKp+B4T7IojD5UTYuvpkN2u91Ma4egIWv
         omykafpWuUSSZagPyNU8XjAKg0E+jrvVyFCb8REjOdmtFdYxhhzWFy+fJwiZSQZBKSdQ
         gwRWElNkoJ+ZBhCe4DnUA6UOjhugQVHfF7JFDA3RUk7psgATwg7ke5+vxGedFAE9W5j4
         VrWA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bbhBwUrE;
       arc=pass (i=1);
       spf=pass (google.com: domain of jiakaipeanut@gmail.com designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=jiakaipeanut@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oo1-xc34.google.com (mail-oo1-xc34.google.com. [2607:f8b0:4864:20::c34])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-67b9d4ceb68si101211eaf.2.2026.03.06.17.39.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2026 17:39:31 -0800 (PST)
Received-SPF: pass (google.com: domain of jiakaipeanut@gmail.com designates 2607:f8b0:4864:20::c34 as permitted sender) client-ip=2607:f8b0:4864:20::c34;
Received: by mail-oo1-xc34.google.com with SMTP id 006d021491bc7-679f980a239so4526318eaf.2
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2026 17:39:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772847571; cv=none;
        d=google.com; s=arc-20240605;
        b=fE8VI/7UbLk9NKiUZY8TA4JaXBQbLj0X4oWuNGqb0zKCyyshWDUojmIaGlBJIsmmyY
         e9RUlMHP1NT51toPDccDUbEHqoptZwsV64o+qcLu2lbxGIxJIrCTlH2KSRvIOURxkDYy
         NCNJh16EcZF5iK5uqvH1bTZj3o5d27j4O9G82851ucS7R4SSL6NYyQtamOH/0hX6suyy
         lngvqUea/g670g2avAPC7x2zSOvyqq45KcLPM0XphKuxBZpvU2s5fWw6dttbvz4Z7fRF
         BDOk+x9iQfcW67X+WvmTURq/iq/2Ughis3aBD1oZE6iluDc4JKRfe7ozKL1kesLBDrTN
         9MXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WUt9V96pGWBeEnbjx1PAHPx8YoZ8MwGfywkRHa4eCJ8=;
        fh=mvL6A4W8l8Wrjbgf/uX8wXTEcNSUsY7zFFgZm6MVebE=;
        b=gLHR0dqo7GvEn+bTZavoODUjFCylUFZbwageheIAF9XPF1GscOuxfiCNrKXSBLDt0C
         fpvZbEDyNsj/V6TD+Z9AWu2JISvZCcuB3/yRQt9GNC0X6qNC5JDh7rftavXVo1p2F3FX
         6W/Kqulq6M8QnFAMaFLeD2EbY/2xdzL9/Cnei/DlpMMh5UDQtqpE4vrcGNbzro3Q8umw
         TmPnKqwKAnXrDu+Pda4kovuM75ZgGSuwQGzs6O4QKp+L+ROfNeRx1dJpIAWOHSgJ+gNI
         QdXknLvGGGtpcXvHYvkj6WxlJIL7F9nDm9D2HSgeIY/9AigHFL9w/HTaql9Rwxe66gpu
         w+TQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCVRsLqvezDgLdduQhrdGN648WdfoeL7WXqnbhCL2G0PI+K6gpwLFun7U1SiqTMzvBsbIbpJZeDWtnI=@googlegroups.com
X-Gm-Gg: ATEYQzwteXwjua2Dgl+Aw0A5fBrkEVisF97z+QR28mmZ/BjpC2C89/GehYk+SdT3uC+
	QpTRBiZ0ajeLDX/tr9i51CSxRFUIw8MRaPaHJstWOGO+aO97eQCb1JSoK5kzRPjfBEqSbtLTpdh
	NXFG9I4MMwO72bTtlzTpI2X0YMkbGPKF6JZjNpI2oB29EwweE/eCP93Dx5gthkEzgcJj24ARSMi
	PdrzGwkqbikCX6N0IkLHRWsNtrEGvqYggPRDoYmpZTOQca6PMoqpYUl4dEDGml9S2IWvi5RvUJN
	ixe8Y9PcVIklkfnhoLSTo7vkMD1PxmhC1rAThKbkJMKEL2KceQ==
X-Received: by 2002:a05:6820:98e:b0:67a:381:d0bc with SMTP id
 006d021491bc7-67b9bd7fbd0mr2495746eaf.72.1772847571210; Fri, 06 Mar 2026
 17:39:31 -0800 (PST)
MIME-Version: 1.0
References: <20260112192827.25989-4-ethan.w.s.graham@gmail.com>
 <20260306094459.973-1-jiakaiPeanut@gmail.com> <CANgxf6yMNZ3=xm9xVhPZDuxMc__7pQk=mti-CyD1QjUOgTJLEA@mail.gmail.com>
 <CAFb8wJvmnPv96o9Kr9VAh=cL9zMr8-5eCEmmkjtgX02_Ypa4nw@mail.gmail.com> <CANgxf6wjPOoYemsK9EKrFM-eSpOgSUQvZ6kX5JyDTfC5J62Ufg@mail.gmail.com>
In-Reply-To: <CANgxf6wjPOoYemsK9EKrFM-eSpOgSUQvZ6kX5JyDTfC5J62Ufg@mail.gmail.com>
From: Jiakai Xu <jiakaipeanut@gmail.com>
Date: Sat, 7 Mar 2026 09:39:20 +0800
X-Gm-Features: AaiRm50KpdlvXzopHVFRmT8nMLKcn3vW_ZNiGHxd8-Gph5tiqofDNvJc5-PXCCs
Message-ID: <CAFb8wJsyKF3m=WQDkjFSLPeCL1peUA-G1__aByz8vQ-kw3wZ8A@mail.gmail.com>
Subject: Re: Question about "stateless or low-state functions" in KFuzzTest doc
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, andy.shevchenko@gmail.com, 
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, ebiggers@kernel.org, elver@google.com, glider@google.com, 
	gregkh@linuxfoundation.org, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, mcgrof@kernel.org, rmoar@google.com, 
	shuah@kernel.org, sj@kernel.org, skhan@linuxfoundation.org, 
	tarasmadan@google.com, wentaoz5@illinois.edu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jiakaipeanut@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bbhBwUrE;       arc=pass
 (i=1);       spf=pass (google.com: domain of jiakaipeanut@gmail.com
 designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=jiakaipeanut@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Queue-Id: D7A6B229695
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[34];
	RCVD_COUNT_THREE(0.00)[4];
	TAGGED_FROM(0.00)[bncBDJPLAN63YNBBVEDV3GQMGQETQOSRWI];
	FREEMAIL_TO(0.00)[gmail.com];
	FORGED_SENDER_MAILLIST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	NEURAL_HAM(-0.00)[-0.968];
	FROM_NEQ_ENVFROM(0.00)[jiakaipeanut@gmail.com,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,kernel.org,linux.dev,davemloft.net,google.com,redhat.com,linuxfoundation.org,gondor.apana.org.au,cloudflare.com,suse.cz,sipsolutions.net,googlegroups.com,vger.kernel.org,kvack.org,wunner.de,illinois.edu];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,mail-oo1-xc37.google.com:rdns,mail-oo1-xc37.google.com:helo]
X-Rspamd-Action: no action

Hi Ethan,

Thanks so much for the patient and detailed explanation. Your clarification
has resolved the questions I had, and I now have a much better understandin=
g
of KFuzzTest's design philosophy and approach.

I'm very interested in the design and implementation of KFuzzTest. Thanks
again for the explanation and for proposing KFuzzTest.

Best regards,
Jiakai

On Sat, Mar 7, 2026 at 12:53=E2=80=AFAM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> On Fri, Mar 6, 2026 at 12:04=E2=80=AFPM Jiakai Xu <jiakaipeanut@gmail.com=
> wrote:
> >
> > Hi Ethan,
>
> Hi Jiakai,
>
> > Thanks for the detailed explanation.
> >
> > Would it be fair to say that KFuzzTest is not well suited for testing
> > kernel functions that are heavily influenced by or have a significant
> > impact on kernel state?
>
> With the current fuzzer support (see the PR in the syzkaller repo [1])
> this is a fair assessment, but with a caveat.
>
> It really depends on how you are fuzzing. KFuzzTest itself is just the
> conduit. Whether or not your fuzzer can meaningfully reproduce
> bugs/crashes related to complex state is somewhat out of KFuzzTest's
> hands. However as of v4 the framework only supports blob-based
> fuzzing, I would advise against targeting heavily stateful functions righ=
t
> now. You are welcome to experiment to see if there is a way to meaningful=
ly
> fuzz more stateful functions, but with just binary buffers as inputs, I d=
on't
> reckon that there will be too many candidates.
>
> > I agree with your point that "the goal of the framework is to fuzz real
> > functions with realistic inputs." One thing I've been thinking about,
> > though, is how we determine what counts as "realistic" input for a give=
n
> > function. If the generated inputs that a function would never actually
> > receive in practice, we'd likely end up chasing false-positive crashes
> > that don't represent real bugs.
>
> I would argue that just because an input isn't "realistic" in the current
> kernel context (i.e., the current upstream code only calls into the libra=
ry
> after performing sanity checks and/or validation) doesn't mean that a
> crash isn't problematic.
>
> Code can and does get reused and refactored over time. If an internal
> parser can cause a panic or OOB access when handed certain inputs,
> it is inherently fragile. Even if that code path is shielded today, it co=
uld
> be exposed by a new caller tomorrow. Our baseline assumption here is
> that if a function accepts a blob as input, it should be resilient to all=
 types
> of blobs.
>
> However your concerns about false positives is justified, and something
> that we have thought about. In previous iterations of this work, we relie=
d
> on a constraints system for encoding input semantics and performing
> validation inside the fuzz harness. While we stepped back from that due
> to its inherent complexity, instead favoring a more simple blob-only desi=
gn,
> adding constraints to better define "realistic" inputs is a good idea tha=
t may
> need to be revisited in the future.
>
> Hope this helps clarify the design philosphy!
>
> [1] related syzkaller PR for KFuzzTest:
> https://github.com/google/syzkaller/pull/6280
>
> > Thanks,
> > Jiakai
> >
> >
> > On Fri, Mar 6, 2026 at 6:29=E2=80=AFPM Ethan Graham <ethan.w.s.graham@g=
mail.com> wrote:
> > >
> > > On Fri, Mar 6, 2026 at 10:45=E2=80=AFAM Jiakai Xu <jiakaipeanut@gmail=
.com> wrote:
> > > >
> > > > Hi Ethan and all,
> > >
> > > Hi Jiakai
> > >
> > > > I've been reading the KFuzzTest documentation patch (v4 3/6) with g=
reat
> > > > interest. I have some questions about the scope and applicability o=
f this
> > > > framework that I'd like to discuss with the community.
> > > >
> > > > The documentation states:
> > > > > It is intended for testing stateless or low-state functions that =
are
> > > > > difficult to reach from the system call interface, such as routin=
es
> > > > > involved in file format parsing or complex data transformations.
> > > >
> > > > I'm trying to better understand what qualifies as a "stateless or
> > > > low-state function" in the kernel context. How do we define or iden=
tify
> > > > whether a kernel function is stateless or low-state?
> > > >
> > > > Also, I'm curious - what proportion of kernel functions would we
> > > > estimate falls into this category?
> > >
> > > I would define it based on "practical heuristics". A function is prob=
ably a
> > > good candidate for KFuzzTest if it fits these loose criteria:
> > >
> > > - Minimal setup: KFuzzTest currently supports blob-based fuzzing, so =
the
> > >   function should consume raw data (or a thin wrapper struct) and not
> > >   require a complex web of pre-initialized objects or deep call-chain
> > >   prerequisites.
> > > - Manageable teardown: if the function allocates memory or creates
> > >   objects, the fuzzing harness must be able to cleanly free or revert
> > >   that state before the next iteration. An example of this can be fou=
nd
> > >   in the pkcs7 example in patch 5/6 [1].
> > > - Non-destructive global impact: it's okay if the function touches gl=
obal
> > >   state in minor ways (e.g., writing to the OID registry logs as is d=
one
> > >   by the crypto/ functions that are fuzzed by the harnesses in patch =
5/6),
> > >   but what matters is that the kernel isn't left in a broken state be=
fore the
> > >   next fuzzing iteration, meaning no leaked global locks, no corrupte=
d
> > >   shared data structures, and no deadlocks.
> > >
> > > These loose criteria are just suggestions, as you can technically fuz=
z
> > > anything that you want to - KFuzzTest won't stop you. The danger is
> > > that the kernel isn't designed to have raw userspace inputs shoved
> > > into deep stateful functions out of nowhere. If a harness or function
> > > relies on complex ad-hoc state management or strict preconditions,
> > > fuzzing it out of context will likely just result in false positives,=
 panics,
> > > and ultimately bogus harnesses.
> > >
> > > The goal of the framework is to fuzz real functions with realistic in=
puts
> > > without accidentally breaking other parts of the kernel that the func=
tion
> > > wasn't meant to touch. Therefore ideal targets (like the PKCS7 exampl=
e)
> > > are ones with minimal setup (just passing a blob), have manageable
> > > teardown (like freeing a returned object on success) and don't
> > > destructively impact global state (even if they do minor things like
> > > printing to logs).
> > >
> > > That said, I'm curious to see what you come up with! I'm sure there a=
re
> > > other use cases that I haven't thought of.
> > >
> > > [1] PKCS7 message parser fuzzing harness:
> > > https://lore.kernel.org/all/20260112192827.25989-6-ethan.w.s.graham@g=
mail.com/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AFb8wJsyKF3m%3DWQDkjFSLPeCL1peUA-G1__aByz8vQ-kw3wZ8A%40mail.gmail.com.
