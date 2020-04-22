Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBPG4QH2QKGQE6D4JLLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id B2D3D1B4A0F
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 18:18:04 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id f2sf1301537wrm.9
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 09:18:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587572284; cv=pass;
        d=google.com; s=arc-20160816;
        b=jF9nq37O0kfuQ51Sl3G3F/EQLRvZ028ZHOfMA+hLr3n/KaK0n8ay9NocaQs+6riMeK
         05/hJh8qnW2Z/vcqXikUzT9iCGdxWagSTwX4vMkR4wrSpsrysIhoqX2q57pPFsyJ2siO
         PxMATUYn6q2X7ayDcspgyFvoUp32tafDtqBZ+QZLRgPWBVw3tGKDDYhlmaIMX8uDXd2o
         PFcmbwa0Wc1gTz2y82wYpGu2crLT0dE/+7WVLDvcdEkqqtC6q4+nFl3VCyscx0+zOMSA
         tCnEIdRoYIIkYqjE8hQpqx4dUkly4iU5J2UF2a12SrkckfqnHXkPJACv2fDn/aoAVCkK
         1j6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=u3NhC9k7DtAco2M3+v9U8NOYEWyu7CJaXreaKMKMDyg=;
        b=Vc7NhR8kuy/1C4v1i1bNffGWC2wox5Q61GfVdQUKsJyDTYVcWXxG5I/UDN1sWj8KoH
         BpqrlQWuZ8cDlBNcambPwJxXW0fKDLDQnGaBreHVP7RxedZzPiLcn1coFU40EdzI9w1V
         ePV4C4Z52TnllzxllcJJQng6sSF9ffQALC+Kv2cvPUJzOflwcVJ/NzgpgqOGOHjIkky0
         o/K6Cd5jXQ02RmAmlihpxvxREtLQO9CPfCO/nlJPSFYAhuRu4PeK/Kk4EfmgIWiM+fzB
         MS3UrTUBOlmIoOYMZUJlMZ2GTxb0srqGDsk/jRegv3Eu9trK0gVsG8V05DLKmyoUlx7Q
         Jydw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=JrG+2ok8;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u3NhC9k7DtAco2M3+v9U8NOYEWyu7CJaXreaKMKMDyg=;
        b=lOIxXzbkJNNPgr2cFt6+xK8fAdNWFGRohI+s3KLMAQt5QyylOeVtNEU9vzwkJ82ccb
         zp5JvVnVVBqhiAY5AWV2D+yB+/BjMlDgbdZkaoBCHCG1Mpt++Zn8EubpuS7VMRvHFBsG
         dSH5y95q7Gydi5s4jSJ1lmlk9SPkF47PL7lZDLM51dnvANQlsRSW6a/UyLz6k1mRPF+F
         3lehXqNQWaRb2KNMmzORd2dr+t8Mgbc0q9sN83YVZQHUy0etCWT0C49Q5ux+meFHdVUM
         XnzcsF9wuEqXzMKqx6wI6uO5pj6tFw0nKdrTxGR9vxMNacN6IfXHjvTBOepg2moIt7A8
         KhxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u3NhC9k7DtAco2M3+v9U8NOYEWyu7CJaXreaKMKMDyg=;
        b=IVfjBlHxy0yfb571RrgwvFjk3svKYT+frtb+CcMGCSfcKMjJPdL+LiVLo9Rizt5ohq
         Y77FP0oeb0RCe8e/u65m+ULM3hcNSwBn8C/58R8FyLUvd6TiYV54gaSjcV3tXcS5+pfv
         DGzRwlc2+9qg486caOS5tKVFWhd08tkuqSYz3BQq2qzf45QIV5jCGybzFXLkI8kg0nC4
         mVHkmcuPuNfFNjfX2czYVFgntavMyOCTzaSQ8zOd0wzlhmVmOIRLTfazfKGlmXj5dtGF
         hdgqAPaDV+BGG2J7eNbfudahBVOnih8B0L15HtFZD/Zr07D7Y7qUZPMnbZdYRAs1gIfN
         J0/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZ8EOiqwHzsMKsJUXMhGsDAQNK4HMK05AofZEBgizrllPjvMIBM
	MzwVtCDwHEPAaXVPaYWJ8IY=
X-Google-Smtp-Source: APiQypLc1RXPcZKwgokCUcm4pAysbV77Wa9nLjzYD3eH3pDIhlg9LkPjy7mwUXnduxBnWqgeAFGl3g==
X-Received: by 2002:adf:e58d:: with SMTP id l13mr31947997wrm.187.1587572284440;
        Wed, 22 Apr 2020 09:18:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7ec2:: with SMTP id z185ls446844wmc.1.canary-gmail; Wed,
 22 Apr 2020 09:18:04 -0700 (PDT)
X-Received: by 2002:a05:600c:148:: with SMTP id w8mr11771549wmm.144.1587572283997;
        Wed, 22 Apr 2020 09:18:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587572283; cv=none;
        d=google.com; s=arc-20160816;
        b=y4TWHuk9aVlW3UvwI/aJ9d4aU/gK+fsYUiCtxcc8vokHOvTo9hYpEgOj8TTModoh4L
         A0c8E/b5JxdbFmm1Kub8acOFxb4cXONMMMTVfkbJ3EIhN7DpcFRSVdcjaskJwMhi/j5U
         sJx6jaV4ZR7AtkWWTvlDdvX4mUCBZu81EeZblcvDAR1mf+YhiPYk2VcDCHZ7S+eLz0/j
         UKCZ23xz1ee6vjq7c6TB2iA9uF3btgIvhIIj+Vhl8pamSRotPcX9bLdtHI1chSKoWlcJ
         36VFEn1ZtY6NabjCxOemQjJ3Vi7edyf6CGZTmEJmIo7m49Eqt9M/RwfE6gnCIT2NrAea
         qE5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ma3ktAvhs7nRGRilL5NROZKZrJMEP9b4pVVZxv/cT8Q=;
        b=S125kL/GB5LWCqwV9mrR9PgYCIJt/ssWoePFJUWoiAjIlHHaF0B1CQ0I/GOCQxPyEY
         YHnDEDa5KcCBM2JdFOR9CkTnZOBzpJVSt1d+i3VBMULKgonAhbUyZcqb9is70+BqF6++
         44r3EO9Rr3iqVicmd+iQg+mAltyZPtgZ4U4rMcGJWK1mmRT4Y1198sSO9CIgnxAmbiRD
         50gowtkho2vLpqi3tSE/N2jLbg/vEF4Faz0BClUfTfFrkasQ4lo5rO+fJ4EyvZDVshw6
         PfvRF9chrn0McWR4OyC9mIa4B5nXKu9g3iwbhhaWiiGUp2tEKCMqPX9IBu0Dz+B1YoRP
         PXCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=JrG+2ok8;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id u25si453022wmm.3.2020.04.22.09.18.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Apr 2020 09:18:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300EC2F0DC10099981D244BC6B235.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:c100:9998:1d24:4bc6:b235])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 771731EC0D07;
	Wed, 22 Apr 2020 18:18:02 +0200 (CEST)
Date: Wed, 22 Apr 2020 18:17:57 +0200
From: Borislav Petkov <bp@alien8.de>
To: Qian Cai <cai@lca.pw>
Cc: Christoph Hellwig <hch@lst.de>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	x86 <x86@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and
 pgprot_large_2_4k()"
Message-ID: <20200422161757.GC26846@zn.tnic>
References: <1ED37D02-125F-4919-861A-371981581D9E@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <1ED37D02-125F-4919-861A-371981581D9E@lca.pw>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=JrG+2ok8;       spf=pass
 (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted
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

On Wed, Apr 22, 2020 at 11:55:54AM -0400, Qian Cai wrote:
> Reverted the linux-next commit and its dependency,
>=20
> a85573f7e741 ("x86/mm: Unexport __cachemode2pte_tbl=E2=80=9D)
> 9e294786c89a (=E2=80=9Cx86/mm: Cleanup pgprot_4k_2_large() and pgprot_lar=
ge_2_4k()=E2=80=9D)
>=20
> fixed crashes or hard reset on AMD machines during boot that have been fl=
agged by
> KASAN in different forms indicating some sort of memory corruption with t=
his config,
>=20
> https://raw.githubusercontent.com/cailca/linux-mm/master/x86.config

What is the special thing about this config? You have KASAN enabled and?
Anything else?

I need to know what are the relevant switches you've enabled so that I
can enable them on my box too and try to reproduce.

Thx.

--=20
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200422161757.GC26846%40zn.tnic.
