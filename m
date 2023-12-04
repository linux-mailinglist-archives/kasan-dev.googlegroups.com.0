Return-Path: <kasan-dev+bncBC65ZG75XIPRBIF6XCVQMGQEZNSMUTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id A3718803D6D
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Dec 2023 19:49:05 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id 46e09a7af769-6d811dc2a60sf4565307a34.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Dec 2023 10:49:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701715744; cv=pass;
        d=google.com; s=arc-20160816;
        b=YjcM0x8tyVhuFUjPf9ZKNWahpywX8u6oTNfjkyYp3P5fp73aCSGFQwm4igalw0Xul7
         sC/D221lpfIMEkUi0R3LbV2XeayULJU0v5YZX+1BmQYZ8DeZRDpmH/SmekGWgehiWwzf
         bmXKDpaEzLYzUh5i1JjthbnvMXnM3gCUNGent2cFbWQLly4INRsuPBDVIzz1no+n2Ssf
         DJmZ2gdGLNJfO0nlJ/9M3XpbQ1gROtUTcOe5Y6z1FvGan1YX7ebU1H9M9IPoOnO75JAT
         GtKq+9ATPLIpwxgQJu8TTHUtqJhaVtqi2hBMBVE3XlhgMzMelMGiSXACMERw9GBTcbD9
         hvhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=5/NUo9aNPVCBB4BIelQ5oDfF2AClPWPahc6q1D9dq9s=;
        fh=LA5TcmG+J+MIumlHbsq7Y7740AEUuCryJJIwYOuLYy0=;
        b=lVx4CC1m4YlawmPtac4LLp7EwQOrpRo6rVWhbU5MTA5kRpQk8z7o041cDwykxYr/MC
         WvMZJXeWZ/pmPLbHL2Lyfl59I5KpBr0IHgMONfUNu9Ki+KwdbLo2PWjDXLimMecVkzCl
         GyYnF4ut3ZwBcbzeBAliVcYigyHgUeCEQjjTG+Lpko8S35Xvsr7eE9SMk9liMOaMoKWL
         xP1gm9ECuqyimxXtBs4BIKpzVJITUmm0IE54EXhsnQbsL30/oaqhw/18+JrJeHakiTOe
         ypOCpkvQUAuKhSGV41FjcC2TnDPnBGPNRSHvRxvxaUzy7tSkfvpcQw4tXypedxNYRkij
         SM4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=EPw8sxTe;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701715744; x=1702320544; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5/NUo9aNPVCBB4BIelQ5oDfF2AClPWPahc6q1D9dq9s=;
        b=HF/pU4xGA0sHz9Z4rmPtEctRV1MAWzD9F6Jzxe977Lw6NahWKZ9PJj8Fy0HHZDZPCL
         UJDlU8a4CSXMEeLd+uuaIVslrjTN4fuVcrmP3q1Lmh3x4lFAXDRnKcEl7Br3J6YoS1A6
         jDt8TeIQgz8HigD2YAvWn3tmd6HcK8kaxOTiVwYbcjMhyOw/WVaj7YMi9VE/tMWRChye
         jhM684VgOzUvQWwuI/gsd7Y6jJvBofqIByVOftTKFBh0Ohubd9hLOwXZ0TEupRFA1maV
         fFtvI293Z6EtA7D/e07QmnJvZePLJkinfaQNXtCwMvDUB8PQepmqEZbFIm7vLVzBcxc1
         g1pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701715744; x=1702320544;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5/NUo9aNPVCBB4BIelQ5oDfF2AClPWPahc6q1D9dq9s=;
        b=phXppGYLZeZ5ZqxZbxn6pGvRtMul7jJvChzzdZhi3oa4PRX5GwW7vVl4K2rUx2xDsc
         2i5y1NjR6qb7CNEQOmOtcVpuJcwTQd7LFnhwsqitpj98euPBB3f9I/0vqXIkUBpB0Dns
         FLdHigvG0Bg8Oxqa6E4nh4Kcjt+7wn5p5vKp1aLN6RzHMfazu+4yzEfEUZPGPukNG2so
         oRfnZl+MqOoqKrDhtdgjUwmMJLquQIWwO7KPKeHFeSKXIhzZTkAJxh2xZUTY5IocnV47
         BR9n1760Goz0oEldSrXl47ckuKXwhbNO2JM3N/qd1SUZAm5EVJIj0X4lUI7Ue1h8IPVg
         cLDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyebWz3qH298CF4rhNsE/gxat/0f6k5HvTwxmaaLEyDXJyuCNPI
	rupzv6OPIuK4Q7aclmyy4jM=
X-Google-Smtp-Source: AGHT+IG7n3YmvHfu5ETvmrKD0NaVTy8YW16xoEC6fR84Vmn8NxabeAaQYUVDtzj1ALArU+VqxWfeFw==
X-Received: by 2002:a05:6820:46:b0:57b:eee7:4a40 with SMTP id v6-20020a056820004600b0057beee74a40mr2560211oob.7.1701715744258;
        Mon, 04 Dec 2023 10:49:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1c88:b0:58d:be41:d25a with SMTP id
 ct8-20020a0568201c8800b0058dbe41d25als318622oob.2.-pod-prod-00-us; Mon, 04
 Dec 2023 10:49:04 -0800 (PST)
X-Received: by 2002:a05:6808:14cb:b0:3b8:37f9:4383 with SMTP id f11-20020a05680814cb00b003b837f94383mr115847oiw.5.1701715743860;
        Mon, 04 Dec 2023 10:49:03 -0800 (PST)
Received: by 2002:a05:620a:4725:b0:77d:a5e0:dc7c with SMTP id af79cd13be357-77de1779ac1ms85a;
        Sun, 3 Dec 2023 20:12:41 -0800 (PST)
X-Received: by 2002:a05:600c:1c9c:b0:40b:5e21:d374 with SMTP id k28-20020a05600c1c9c00b0040b5e21d374mr2147654wms.125.1701663159813;
        Sun, 03 Dec 2023 20:12:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701663159; cv=none;
        d=google.com; s=arc-20160816;
        b=bK82zncSrAabDwPZF/7SIr6Oce6nv6GxlozhFU7mmN1+wdZ0YXVUAhSqth842QnXuN
         SgPjSHGbLw43cbQzLA7wB4oCEUthB8Zu8ftnhEN2w7DtTiph2kJ2LESpyXntHc5PQmMG
         PwEhHhIJSt8JWT9OZ4UfZvMOBso6PC0y9FDFniVv7RvkYDPK79Ro1O5sXBaDEwWF4tMh
         5q95fbUDZIPcpjbhRvwYHcf8tqW3IbiLaeMjl3Cu4pVazGCAnT1Qgeh9OBBx+y8/y4pH
         n2o2oPmEWDiVd0SkhZQF6RWpxSQq1S/PBexMMMKgsmug3I2o+2XmCpmoGWld2FfDIs5h
         lW0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=uSIjHQyxvuiMYpm126xyxG1Zci+DFvN4cs1bYgkFaNU=;
        fh=LA5TcmG+J+MIumlHbsq7Y7740AEUuCryJJIwYOuLYy0=;
        b=h/BIRkpcmoD5ZZbFZ9yBheOhMs5C+G9is1yDt791qJHrZIsWYRkUKOK/41Auz2XOGs
         1fdj3I2fpS2lbYZV6vpt+WifGY/rIP3VFK4QYMy/sfz7/6ijB5uuxGAnK2pR4Qp93SdD
         RsNO3QU/dX14RpVvANT5s+oI4YpE+XqQpXKwaRL1c+C7afFjIETct1T4Ef/5Owx6gmDh
         rgMmkmJMQcQi4cVHG6LTAmaKYkGy22WclI/i5eMpp8ERMdHTu/UIryUroVgO7hP15ZY7
         O0Mq2rIQCnGdlD6SclFw2qGKjyeEiGmNueld1eAUCPL6ODizWauCu787J0Bfg8AUnqKs
         Lv4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=EPw8sxTe;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id p7-20020a05600c1d8700b0040a25ec1cfesi506210wms.0.2023.12.03.20.12.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Dec 2023 20:12:39 -0800 (PST)
Received-SPF: pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-40bda47c489so19339745e9.3
        for <kasan-dev@googlegroups.com>; Sun, 03 Dec 2023 20:12:39 -0800 (PST)
X-Received: by 2002:a05:600c:3b1d:b0:40b:5e1e:cf9 with SMTP id m29-20020a05600c3b1d00b0040b5e1e0cf9mr1855181wms.52.1701663159222;
        Sun, 03 Dec 2023 20:12:39 -0800 (PST)
Received: from localhost ([102.36.222.112])
        by smtp.gmail.com with ESMTPSA id b19-20020a05600c4e1300b0040648217f4fsm17107376wmq.39.2023.12.03.20.12.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 03 Dec 2023 20:12:38 -0800 (PST)
Date: Mon, 4 Dec 2023 07:12:35 +0300
From: Dan Carpenter <dan.carpenter@linaro.org>
To: Andrey Konovalov <andreyknvl@gmail.com>,
	"Liu, Yujie" <yujie.liu@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	kernel test robot <lkp@intel.com>, Haibo Li <haibo.li@mediatek.com>,
	linux-kernel@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org,
	linux-mediatek@lists.infradead.org, xiaoming.yu@mediatek.com
Subject: Re: [PATCH] fix comparison of unsigned expression < 0
Message-ID: <ecf38b22-ee64-41e5-b9b5-c32fc1cb57bc@moroto.mountain>
References: <20231128075532.110251-1-haibo.li@mediatek.com>
 <20231128172238.f80ed8dd74ab2a13eba33091@linux-foundation.org>
 <CA+fCnZcLwXn6crGF1E1cY3TknMaUN=H8-_hp0-cC+s8-wj95PQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcLwXn6crGF1E1cY3TknMaUN=H8-_hp0-cC+s8-wj95PQ@mail.gmail.com>
X-Original-Sender: dan.carpenter@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=EPw8sxTe;       spf=pass
 (google.com: domain of dan.carpenter@linaro.org designates
 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Wed, Nov 29, 2023 at 04:01:47AM +0100, Andrey Konovalov wrote:
> On Wed, Nov 29, 2023 at 2:22=E2=80=AFAM Andrew Morton <akpm@linux-foundat=
ion.org> wrote:
> >
> > On Tue, 28 Nov 2023 15:55:32 +0800 Haibo Li <haibo.li@mediatek.com> wro=
te:
> >
> > > Kernel test robot reported:
> > >
> > > '''
> > > mm/kasan/report.c:637 kasan_non_canonical_hook() warn:
> > > unsigned 'addr' is never less than zero.
> > > '''
> > > The KASAN_SHADOW_OFFSET is 0 on loongarch64.
> > >
> > > To fix it,check the KASAN_SHADOW_OFFSET before do comparison.
> > >
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -634,10 +634,10 @@ void kasan_non_canonical_hook(unsigned long add=
r)
> > >  {
> > >       unsigned long orig_addr;
> > >       const char *bug_type;
> > > -
> > > +#if KASAN_SHADOW_OFFSET > 0
> > >       if (addr < KASAN_SHADOW_OFFSET)
> > >               return;
> > > -
> > > +#endif
> >
> > We'd rather not add ugly ifdefs for a simple test like this.  If we
> > replace "<" with "<=3D", does it fix?  I suspect that's wrong.
>=20
> Changing the comparison into "<=3D" would be wrong.
>=20

I would say that changing it to <=3D is seldom the correct thing.  I've
wanted to make that trigger a warning as well.

> But I actually don't think we need to fix anything here.
>=20
> This issue looks quite close to a similar comparison with 0 issue
> Linus shared his opinion on here:
>=20
> https://lore.kernel.org/all/Pine.LNX.4.58.0411230958260.20993@ppc970.osdl=
.org/
>=20
> I don't know if the common consensus with the regard to issues like
> that changed since then. But if not, perhaps we can treat this kernel
> test robot report as a false positive.

I would say that the consensus has changed somewhere around 2015 or
so.  Unsigned comparisons to zero used to be one of the most common
types of bugs in new code but now almost all subsystems have turned on
the GCC warning for this.

However, this is a Smatch warning and I agree with Linus on this.  For
example, Smatch doesn't complain about the example code the Linus
mentioned.

	if (a < 0 || a > X)

And in this case, it's a one liner fix for me to add KASAN_SHADOW_OFFSET
as an allowed macro and silence the warning.

regards,
dan carpenter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ecf38b22-ee64-41e5-b9b5-c32fc1cb57bc%40moroto.mountain.
