Return-Path: <kasan-dev+bncBCUY5FXDWACRBUPWZ3FQMGQE5K52QOY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id QBDzDFO7c2kmyQAAu9opvQ
	(envelope-from <kasan-dev+bncBCUY5FXDWACRBUPWZ3FQMGQE5K52QOY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 19:17:55 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id BEC0379780
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 19:17:54 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59deb3ffd9dsf258472e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 10:17:54 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769192274; cv=pass;
        d=google.com; s=arc-20240605;
        b=e2gCBz7W/Uh56gp/jplnmhLesDspXd+LLi/fym/IXJ0Siyw7dqhlrL3aJ29l8vTrQ0
         fncsNIFwJvbfXUGuXHWKSv4k9C7SXAYwYSkMNc5sna8wAvPOkGhM5Fc9ErNqLpIMZCUv
         zdSZWFCpZQn3YQRnqN0CXS6ysIRBzW7a0YkSr3rnsE96lMZ15eTztrWhVIkh0ou0MJwR
         dMWyrHci6eYIk/4z0x6Lht13CohIFBnJqTlIXYjq1BtaUuwVpojLbtHfEFZMFiuKjsLH
         kMa9XsZr1ldndwuqju5fzeResFuiU13jF4VgDFu1JgquL9WTG0JRneRQB4I8A5vUqIEx
         /Opw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Zv+Dcrg51c9UHZdp5Bd1Kc5adLWxf72uJFlwDDtXcmY=;
        fh=SNjGUPLEoigw4rKY/juryY9dqvHtcvflP9zEFrKTO3s=;
        b=DexPk9BBzXknyeQIFzb0z+CveaVL3lKClNT1jtcWfj6TO+Dgqs29mneRf+aopxf+4Y
         MR/FUvFT2CksGqWsoOshHMmXaAr7fUZ2d/OfH7HMAiufy3rudMPKVsDCyCdtI5E/VGNG
         1Wm0a/9l5/PWKPy3/w+qHndJ0ntyuRAndQz8xkCu4arg9xvVIhFjBuVhzK/GXlGZEB7m
         e6UrHs3JDaeRmhEv18LhPk8/nKBQRuCUttoOYfnHoEquoMpWyu+/WtnnztOdaIkQeOhc
         9tx9RFmc7hgQIUDUsO7+/XxtIxOPLV/Nv8JtRrjfFoXsI7x1+5X3M0NyznlvgyISqd1v
         bMLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="P+7/zSdL";
       arc=pass (i=1);
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769192274; x=1769797074; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Zv+Dcrg51c9UHZdp5Bd1Kc5adLWxf72uJFlwDDtXcmY=;
        b=CGKVHTV5l18iTjzduM7ZpzimjZQKONpMAlWnmXyVMQN/moXQYRbLDwtIK/Usm6wfpr
         0G/zGUrJ98bdNqspkzZfIqxXtRd8HmdO0yEICragd+fNO7/oHlcmx/Z7k+TvTs7FpypQ
         BbzJgza04F7Nl42XRG+YVwViYmnBWiIceB6nUpi8yl4oOE1kYKKKQSGrESFMyv/e7lav
         Exr1MZvNrwmvszK9jjrH4tk6Gln/TnspykaEXUwOvyP/0RFUR951scrzDS8M75UxoRxo
         jyRNKOT+cZG2pNpPsPvOKNfjC0lDZs48QuitdZUghmRsN2bI371GPquSJjbd5AYN3gdm
         8VgA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769192274; x=1769797074; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zv+Dcrg51c9UHZdp5Bd1Kc5adLWxf72uJFlwDDtXcmY=;
        b=fL2PTQayHcJWzicJS6OQHFC02bOlVHOt/N4m3g9fKbtgLi3NhvLkmjnb5WtomzGGlo
         H/cSVwAaD5rNBurr8kb/D6By3MMSSpkGLbvRYgeoywjcuRHyd/pkXnu/UzoJZciNc6Lv
         wRDpC5XtYuSI7TuB8EWmUDzyZD3/KekpdXHLg7I5M5p1m+zmTuomPWY/o3sNYRxsxlmO
         piqTzXfkl+kmfhpizOcoGoRYEFEoHZOfsFAdJpX9NlgLFgc8F+9iEJauNGRMsNZTAoQe
         oA0epqxfolYNm0r10AQ1RwnNTnWu7w/oCxGo/j2EUaqAvd0F7tOvDEHm5BaFnCI5GEtg
         79sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769192274; x=1769797074;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Zv+Dcrg51c9UHZdp5Bd1Kc5adLWxf72uJFlwDDtXcmY=;
        b=t4B4kaGIxskmhTWrqJQeUSDbJq2tSi4yp80K+PZOX+Cpn/EhaMRGmR+jX786yeg1aw
         loYXtn3pqDlJ6B/uzNJmmim9QfbPKW6AJorPhadQvI+H+e4HLunLEw4WinA3Vd/RBKVA
         AIm3jd56Ho5GsScdkrByuqO34inMA5Nk5ZMJKoVNz4aKtEFnLwpI9chQ/lWotbu6ycmz
         3IIpEDU9oNbXd4bfI95/xnuZfGHMnyqXByP8T89cUnkvwtdCHe/He3X1/c/jqpvur7Dd
         U6kBTbbO8AjVSFQVnpMAqnpS48pbI/yiII21m1mlx/7JqVwx7VelpYV68rGF76Iq/LTK
         3Ugw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCUeorEYKJCHg1RSSVSrQHTrr5j0pRwXsGw2mR3Bt5xOWKAGEFv8QbgP+IySi/KLXsjrcxX38w==@lfdr.de
X-Gm-Message-State: AOJu0Yy83Rx1K7k5GHoms4OkTcGU4A0FbGcDsJ/jTFDkO6dkvcLuh1aH
	HmKLEKwElRfDTx9cn04CrYEaEErJKtNbIkYEN945eLnFIYf9T+mfG1gD
X-Received: by 2002:a05:6512:608a:b0:59d:e5f3:db0b with SMTP id 2adb3069b0e04-59de5f3db0cmr1193759e87.27.1769192273607;
        Fri, 23 Jan 2026 10:17:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H7FsQ/lXS1OzoGrlN35Nk285JAaOLKzu5CKHZitzqFww=="
Received: by 2002:a05:6512:2352:b0:59b:a040:2eb6 with SMTP id
 2adb3069b0e04-59dd7979f26ls735628e87.1.-pod-prod-02-eu; Fri, 23 Jan 2026
 10:17:50 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWPcXRp+oEur7sSHUkycLiJb7gP+jUPm5aVO9j4q6hNm7bYoJiypf8t5MiNJSXtwYXQZYB1W5eQfUo=@googlegroups.com
X-Received: by 2002:a05:6512:1514:10b0:59d:e65e:b365 with SMTP id 2adb3069b0e04-59de65eb4a3mr843624e87.51.1769192270399;
        Fri, 23 Jan 2026 10:17:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769192270; cv=pass;
        d=google.com; s=arc-20240605;
        b=apGnaw0LOBJcs7XRPT3Fw7TtW4sxPljWn92uRF91eSNaCIAWmxjPJRn2f6JR5PM8jc
         J5VofhxWQvy4ehRYfBYWsrktIGYDvQewjXMEUfZKld/nkgy1EkDIFbH4Nd4FIpG9xj8p
         RBnDlt9wG1ed3uqTCVQpW0ICg1uhKyaQwdm6T5Qp2VNqLy0H5FMvjz7Rl+MTQ4FeqGni
         mQLuHV6LNJRfLJCBUK8n9Pi3lR2/1sQA4GmIjMiHWRY0v/sD8ZKKrRiIMhOOsy0L7jvG
         PJgmn0gjX5eKPARAfXhR5IEgjvlYciaUEGYTQzGcxFRjKsKQ8Q4Y1TZPufxqMGgMTEL6
         ZUNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8Njop685CDtDYAHuiepzZeOimPgVGEih4T1bD9GMBYQ=;
        fh=s3mzGfm9TvlKdCgQRSVjsd+OZFBakomA70mGsZV6a+k=;
        b=gDnzZ855f7gK5/k7t6/8pWPdsUUCk4j1v4FuIdVbVipfxrMSJRtFiTfOk/erbcNPXA
         zGVRWwQPhhxdzYmwAtQA2K7v3CpCzMSQlgwcHHWAJoxVn8NEoyjyec/75CAqqLeTbPZd
         4hBOgY28qHm/kfWDt/RCgJnxYQC61bMUU6FgrvKiS3v4oT6pUw/YVk1U7cSZH29W+hBH
         zqF7I+3Q0UdXzFB7A2ydUccIJdEixyfET4jtwpZeRxekmko3Zw/bjrwdviQR5FCQKn1A
         Cnhe6Pc3AvfOwXlK+l2oMucRTIhRLqSpTcCPWB1hxWEqhQ/6kv03xvJZ4744Wa/9VhMJ
         ztNA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="P+7/zSdL";
       arc=pass (i=1);
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59de490f1c6si61500e87.5.2026.01.23.10.17.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Jan 2026 10:17:50 -0800 (PST)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-435a11957f6so2071622f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 23 Jan 2026 10:17:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769192270; cv=none;
        d=google.com; s=arc-20240605;
        b=hCqhnjZJmQLlBU1eVyYfoJqI5Y37Ei3B7TrwVjjqjjjlaC7bEmH3VOhUaG81vh0ByA
         vIrZTFqJWPXeCm1cuziVYTanKmAzdyJRK32T4kEVNzIJlY0bXJfutnRjZWcC9zndpLVk
         HgP28Iy2Bpw/jGXSGm5aRYZiTmvA2N0Aw2bjgkWqdYo+17lazXL8hjQOeJf4hTFZD8ee
         OkInhwxFTDDSxG4++MGh7GicaGZEVcX94Gp9t6w52cxSLP7xvqWa11HH7A9EI6vpD+RP
         RqAObDBTGUyQo2cle7x972xzksfop+EqrdGFH3PpOFJkdd4JWXgYFVwRDURTJLjHHgF0
         Iasw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8Njop685CDtDYAHuiepzZeOimPgVGEih4T1bD9GMBYQ=;
        fh=s3mzGfm9TvlKdCgQRSVjsd+OZFBakomA70mGsZV6a+k=;
        b=PIhCvquH+rFWZJOumsy/N9lLkjYQjNXbFa7E9ubyOjwglsLhDnhM1FvM2jdy4mrmlv
         pAJv3LxxgsIkXKlQ0cI7gg/kXQAnPJSPVZAEaDgP4PitxupoC5KNXzZuCahknaedqpxn
         x+8MnJI+qt1B7K5GYJ4yIP2FLo2DBu7xWOBNSLcd8mvNEn6tGW6n+bZlOagU/CCCcUpa
         i9uJj9UgzmqdGOtaxrndsXgx0v9P1ipZzBxR7oDPILBei6m9bwrGZToipwfjmaWzJeGG
         nQLtyIpmf2MOYadkngo4In5ZA16XxmUWBuMyLLj+tpVl4+ZvJrFOMl2OIa/4YGvCfbRr
         S8iQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXQHEzw6OCjw8o1bHDUXtijLIs4Wv7rsvNqwkeJqmyljOvmwmV/GSqfKOXLBcIWt6JLdLWbIWrfdfs=@googlegroups.com
X-Gm-Gg: AZuq6aLe7gFvItvX5NJdtmcIXbV4SzS0c8+HuJM4Obuft9uDKiMBYoLbZEM+5Kj5j92
	dGSfwvE1Gie8tAM6TfPBo8ofh+R/wpMgP7kKQjz0pK7lysu6K4qmB2GZjjmbUchqHai9mNxLaiu
	+9kt8724sZQ0FU4IHsqvMSj9JFjqFWAvpiaA7M4dkO3guutuX3DSMNAE0eeT0vG+zBJ1fD5PkJr
	Z989c7su3zMwCbeR/3onLa5B4uBj4EHgOyKiOTfLSERGmFlG564jMo1WOUkxvqv8eWmR5e+rplN
	7u6ANzrDtLWKxS6cdU4VMIuGYgBKRnhUX8egF5s5aJSKk/ui+uDOFKjXcKXgsHX0KdhAH8Kn
X-Received: by 2002:a05:6000:2dc8:b0:435:a83e:88e with SMTP id
 ffacd0b85a97d-435b1587c9bmr6392632f8f.2.1769192269543; Fri, 23 Jan 2026
 10:17:49 -0800 (PST)
MIME-Version: 1.0
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz> <20260123-sheaves-for-all-v4-11-041323d506f7@suse.cz>
In-Reply-To: <20260123-sheaves-for-all-v4-11-041323d506f7@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Fri, 23 Jan 2026 10:17:37 -0800
X-Gm-Features: AZwV_QhM-NYlnccFIjcj9RRt6cZ2UOQ2HcV0ateutcQQrobA-XAbfYILlKDwm8s
Message-ID: <CAADnVQKbuLD=gaC1W9gtXrj9VdwQCqt2f_rtYwF1Tc1RcUOjKg@mail.gmail.com>
Subject: Re: [PATCH v4 11/22] slab: remove cpu (partial) slabs usage from
 allocation paths
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	"open list:Real-time Linux (PREEMPT_RT):Keyword:PREEMPT_RT" <linux-rt-devel@lists.linux.dev>, bpf <bpf@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="P+7/zSdL";       arc=pass
 (i=1);       spf=pass (google.com: domain of alexei.starovoitov@gmail.com
 designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TO_DN_ALL(0.00)[];
	TAGGED_FROM(0.00)[bncBCUY5FXDWACRBUPWZ3FQMGQE5K52QOY];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_NEQ_ENVFROM(0.00)[alexeistarovoitov@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,suse.cz:email,oracle.com:email,mail-lf1-x13c.google.com:helo,mail-lf1-x13c.google.com:rdns]
X-Rspamd-Queue-Id: BEC0379780
X-Rspamd-Action: no action

On Thu, Jan 22, 2026 at 10:54=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>
> We now rely on sheaves as the percpu caching layer and can refill them
> directly from partial or newly allocated slabs. Start removing the cpu
> (partial) slabs code, first from allocation paths.
>
> This means that any allocation not satisfied from percpu sheaves will
> end up in ___slab_alloc(), where we remove the usage of cpu (partial)
> slabs, so it will only perform get_partial() or new_slab(). In the
> latter case we reuse alloc_from_new_slab() (when we don't use
> the debug/tiny alloc_single_from_new_slab() variant).
>
> In get_partial_node() we used to return a slab for freezing as the cpu
> slab and to refill the partial slab. Now we only want to return a single
> object and leave the slab on the list (unless it became full). We can't
> simply reuse alloc_single_from_partial() as that assumes freeing uses
> free_to_partial_list(). Instead we need to use __slab_update_freelist()
> to work properly against a racing __slab_free().
>
> To reflect the new purpose of get_partial() functions, rename them to
> get_from_partial(), get_from_partial_node(), and get_from_any_partial().
>
> The rest of the changes is removing functions that no longer have any
> callers.
>
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Reviewed-by: Hao Li <hao.li@linux.dev>
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 628 +++++++++-----------------------------------------------=
------
>  1 file changed, 87 insertions(+), 541 deletions(-)

so much simpler. love the red diff.

Acked-by: Alexei Starovoitov <ast@kernel.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQKbuLD%3DgaC1W9gtXrj9VdwQCqt2f_rtYwF1Tc1RcUOjKg%40mail.gmail.com.
