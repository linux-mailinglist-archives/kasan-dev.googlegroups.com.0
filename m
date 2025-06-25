Return-Path: <kasan-dev+bncBD2NJ5WGSUOBB56U57BAMGQE5MKJAUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 53C8EAE829E
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 14:24:27 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-32a8058e48dsf36209681fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 05:24:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750854264; cv=pass;
        d=google.com; s=arc-20240605;
        b=iLtw9v+pDhmzhJOQZ9mlz/5hMoPdw8pUmXhgBv/q9HWSYdPOC7ifEVErmML8SjRHNw
         WxW1qnv4VKhH/v8OGB1i8ezZEb1HofDuRV7A/pMbWwt4qD7s/DKYQ+yV8J6u/HZPztVt
         k71wHSuONNoXUcNqPMDGvBxVveDxciRal4ga3JAcwgdavJckEzoG4ubkyXMppUIEkYHi
         hRAN8JKV0I5zygkgsDqTiAH6s9XYLzUOQMWTEjoEu57C6nIxIlBirXYJVbcuGmHGh68h
         faiZ4BREXh8UYShnAAW7S926e+cYqELOjRxcFLVhmxs4R5wqoqYDLMhmrPnaOEHZBay6
         dtAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=F5Azooihmpkyn1brQ+KCAupikwoIGuArrAm5vZsaJEc=;
        fh=Sjgz9Y2zaI1kA8T/acP7g5uyS7pPtRYjJ4NWLMQORUQ=;
        b=QFekJrmmuYqCU7A35DVo1FlMNVF5H6yakVzRdRJrc3x0zw+Rh6taAFovJjUaBZhQpr
         y9hgdwr7FzwlK3RaCYVfVI4QmipD8jYz59U79um3cva0oTUU23nsZRoxBGRPHegNvhma
         MKkRDQtyXg9MqtaEZC8fJGwyR4lRgjSg4JQEnfbVPhCf+s+Qw+LUcYySeJns8q7nPjez
         VjNSq+h9hpQAaHssZaFMH5MucL9FYrKatwJOoL9rD11XpkZpq/NB9gdhjJQH+TPvmW5K
         qwMCZpMYlYLmpPOIgzXJy3Jf48SPZSNhQJUaS3aNf0vS9YdNd+0KhScHh8urG9URN5An
         y4Gg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=WC4NYmMz;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750854264; x=1751459064; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=F5Azooihmpkyn1brQ+KCAupikwoIGuArrAm5vZsaJEc=;
        b=k4Kw77flK56QD7zyMc8/5CvnVeRd6eUF0KPYQNTsPhHzkMAUikrPRbapEMit4aVuxM
         58GEACgAh757bjTp1BjPt8lqJMI6kCV5JucWKtJ0W/YZyp6doXPumrNXtXBzvZGcsZFg
         bqRGBqq25mlyOLqrl2pAVJDXgH0wWtEc0GOuBIgsAHtx/eEu4HA5Rzyxwd+ZYrMjVyC2
         Fa6yAP16F3aJWzb/TgXHQBS6RBYi//mcogIn9i7Iz47Bs0vltl+1+mzMjitNsGyZdiI7
         zcGwNJwNIRabryZ0a1AzcSOgQF5H11vahGuhPm4l3oVX7+1CIdW4RzwJNY3sanyvzPBf
         mX5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750854264; x=1751459064;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=F5Azooihmpkyn1brQ+KCAupikwoIGuArrAm5vZsaJEc=;
        b=CrhP/p+UuxD8yUoaxcYvUNMTYQZmWrWwsEnS6jUOO44qBslarUjhCOcdRUeJ7xcgW4
         84xytRyZJG9VZu5ujEB/kM5YQyU4raRpeCm0co9T1ukYPWG1lQ36SE2YkkYlp0tjgwU0
         jCOcnX1DP0fF+H4l3a7goRCjvE1b39932NTdRHRExyMGA6FXDoOoIvBbqP7DLLJJWAsO
         XswqXJ04EHzTneePee9dMBP4R4emPoOR37vqnO8cDB3+79NN1ek/Jn+MPnM9o4QFJsX2
         ihwLEb9hFFC/dmZEmv6OHhlYIZnH28pGMYNR84oc2102IlJYAoLJQt+7mrjAvWHNt+u4
         yIig==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXr3+hboDHhDwZehyajRHHMSFPeMJbJIkSuYEMIq7x8vtLcusqoWLCtDqLBP4aV8fBm0lvCUA==@lfdr.de
X-Gm-Message-State: AOJu0YwESAslsEuLaz1ZmRMn2jMs1MaYc/IBevKFboNYOtzwdALFcwv+
	f0XW60kRYeJA1QtbBrD7uWL5xfiQpe677+V3rcwSGebY6iA1NPoQTB8n
X-Google-Smtp-Source: AGHT+IEJ9qqZaBRLdkfEAq2PCtk/q+kbRxdht2v7KEv6fiBaM0fyZM11YFaPpj5Ev5c5IygEnDod5Q==
X-Received: by 2002:a2e:a58a:0:b0:32b:488a:f519 with SMTP id 38308e7fff4ca-32cc642171fmr9555991fa.6.1750854263776;
        Wed, 25 Jun 2025 05:24:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdLKfrf3vo/Kmhwsl2dNuq7Fls/VQxk1nz5OFnxshD8Tw==
Received: by 2002:a2e:a9a9:0:b0:32a:e3cf:797f with SMTP id 38308e7fff4ca-32b896dcba7ls17910921fa.1.-pod-prod-07-eu;
 Wed, 25 Jun 2025 05:24:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWw2hkdj2VaGyyuezpnfvxfMUSKG1XS80KZySEftdL12ilccfjX67cev8jqzO9nKMsX1YWaFUuqnHo=@googlegroups.com
X-Received: by 2002:a05:6512:3e02:b0:553:2a16:24fd with SMTP id 2adb3069b0e04-554fde59eb1mr839389e87.47.1750854261273;
        Wed, 25 Jun 2025 05:24:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750854261; cv=none;
        d=google.com; s=arc-20240605;
        b=lmAOgRtEOP1gkg93gess0k+oJaRTUEfC5PS5qXx1AOvajHS2r7sQXdzBZHBJO4L4Ol
         65GE2url+4h5Fqvbt/cm/ZYi1Paq4WCFAComnKVZ9ghW3L2KqXs+aY/pvWCkkadO7+AJ
         8JCvaOr1uLc9zROolvDoxfOHLEiPK/jzbHKjX1fCgogoAt1b6SqW4HaSfc7B1ZyylY5g
         fKJ79S9Mq7VulzP3s7lFP7e7nnPjwke0YEf6DfJVCXuEIJeEs9K+PXpwvzB2iQrx5CO7
         XgCUiHmY1SWbAyqaF3LLfCvzP1g74NjQWO/zTlE3sucicc4hqRrvw8Yr6OCAMbs5ZKCo
         NJlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=SJ5NkjC+cOiMPwKXMdsR+3xgXJFhGnL3/wL1U2zUcWg=;
        fh=Ak4cFgz0z3x+5Nid2UmbqAccAt9iyQAwIZwKg8ZMZIY=;
        b=GRtsirEIH271twSb3DM+mQ1IdEkx2o51480s82JY4cPpKNPyrQvQjFWfOQIB5iFlC9
         jTdOJW/w/nWirdnJTGSqw0CTPxFFWHMLBe0GwFfn4dgnGJq7nJitw88ybElqqDObrKPF
         OtT5nTtzIslPCj+gRJ/DfW+XujVWpk2+wB/CR+F4Lp9io0xR6AsZgKOkWRSRVQuV5A7O
         m/FTVPBmy0LH1WmoSdmbUri+KACDipgu0W3QL6yfOWpoq/rOpvpqjmTHT8UVg2gCS6DV
         vwwXmExEiJ2V+dLWxbxg92Ghtw+qQL3RqibPKXo8dACI2oQ4yjqg9KjVNWdtACBwwFYI
         NqNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=WC4NYmMz;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-553e41c1aa9si225948e87.9.2025.06.25.05.24.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 05:24:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98.2)
	(envelope-from <johannes@sipsolutions.net>)
	id 1uUPAV-00000009xvR-1M4X;
	Wed, 25 Jun 2025 14:23:59 +0200
Message-ID: <81a8b60be5b99ecd9b322d188738016376aff4aa.camel@sipsolutions.net>
Subject: Re: [PATCH 2/9] kasan: replace kasan_arch_is_ready with
 kasan_enabled
From: Johannes Berg <johannes@sipsolutions.net>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, Sabyrzhan Tasbolatov	
 <snovitoll@gmail.com>, ryabinin.a.a@gmail.com, glider@google.com, 
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	catalin.marinas@arm.com, will@kernel.org, chenhuacai@kernel.org,
 kernel@xen0n.name, 	maddy@linux.ibm.com, mpe@ellerman.id.au,
 npiggin@gmail.com, hca@linux.ibm.com, 	gor@linux.ibm.com,
 agordeev@linux.ibm.com, borntraeger@linux.ibm.com, 	svens@linux.ibm.com,
 richard@nod.at, anton.ivanov@cambridgegreys.com, 
	dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, x86@kernel.org,
 hpa@zytor.com, 	chris@zankel.net, jcmvbkbc@gmail.com,
 akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com, geert@linux-m68k.org, rppt@kernel.org, 
	tiwei.btw@antgroup.com, richard.weiyang@gmail.com, benjamin.berg@intel.com,
 	kevin.brodsky@arm.com, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Date: Wed, 25 Jun 2025 14:23:57 +0200
In-Reply-To: <750b6617-7abf-4adc-b3e6-6194ff10c547@csgroup.eu>
References: <20250625095224.118679-1-snovitoll@gmail.com>
	 <20250625095224.118679-3-snovitoll@gmail.com>
	 <750b6617-7abf-4adc-b3e6-6194ff10c547@csgroup.eu>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.56.2 (3.56.2-1.fc42)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=WC4NYmMz;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Wed, 2025-06-25 at 12:27 +0200, Christophe Leroy wrote:
>=20
> Le 25/06/2025 =C3=A0 11:52, Sabyrzhan Tasbolatov a =C3=A9crit=C2=A0:
> > Replace the existing kasan_arch_is_ready() calls with kasan_enabled().
> > Drop checks where the caller is already under kasan_enabled() condition=
.
>=20
> If I understand correctly, it means that KASAN won't work anymore=20
> between patch 2 and 9, because until the arch calls kasan_init_generic()=
=20
> kasan_enabled() will return false.
>=20
> The transition should be smooth and your series should remain bisectable.
>=20
> Or am I missing something ?
>=20

Seems right to me, it won't work for architectures that define
kasan_arch_is_ready themselves I think?

But since they have to literally #define it, could #ifdef on that
temporarily?

johannes

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8=
1a8b60be5b99ecd9b322d188738016376aff4aa.camel%40sipsolutions.net.
