Return-Path: <kasan-dev+bncBCDZ3R7OWMMRBW5EWKGAMGQEEFNYO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id CDA7144D07E
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 04:47:39 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id d7-20020a5d6447000000b00186a113463dsf741941wrw.10
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 19:47:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636602459; cv=pass;
        d=google.com; s=arc-20160816;
        b=MB3RMUkl/FWwewVKWicBA8TqZVxBCIAcP9GgLdAO0llQN+7HurbPBPeabWKvX/EFSy
         kGbAJBMYJiFIjp1VGN7oP2/6Zj6dTljUXqG/YvGfWYDM6OG424r67NBBdDsX5QkqAjFf
         59oorY+2tV9NLnZVEzBHDXVAIXQDN6tsgnondOaKq2Bn1m0aNB5gTx9qr3gBcX7Ue9G9
         LUCltPZ3EI1uJaQuONa+mE8zSW35XgVjjxgrdqlKs9smH0q+fDXSoK9CfxRky3HS0i27
         08h78QaW7WuUkjrkmGGbWp8a2Sm8ZdRNZUsn/TPhCfXXmNH3tHHt6b5Sv4qlV+woqm+u
         E5TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=7q8Qot6JR3i6zbg06Z2hjmgQH001gR20T3hNmGkmOOU=;
        b=YJiRrMzocINwpS+MgBR0ggDxmzTKkJ8pZEeBNUtUQIpzv02JOzFEhyyhgMoabs4Ipn
         g8wCiaaJ1pszUuwuaUI8BDZnz/xQQGpMurE4Vuz3Oowk5iL1EUBEFeUQaqsbHkZHlu1U
         E75JIs+ihbBT0cEpu0LJUphereY5C4R999P+W1dZ42lv2dR/lryIUICFhaYkh6+kyEHk
         S25eKnP4dvy27P5dZqGnecgfWx/mebJFp/RVhUoU8771z6+V3aNIOMKezH5ULSIBkzuv
         XIaSk3CvnZIwwKtgBbRIchmIwgHkiyuxwuqH4VIgg8cJjV2nwUg4EuEoacgpMg982Cct
         EV0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=a+8s+042;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7q8Qot6JR3i6zbg06Z2hjmgQH001gR20T3hNmGkmOOU=;
        b=NT3pPcHED2cGwZfz/6Wre11tNV5ma8O3gWEX7l5Iv2ZXxbPOHnWlSTf2ANOEHY1bbi
         lNb1YXZ9idiY+eMasOrxJg6zGRGN2GU9KClnO0Tgr9dU3kUopa3fSgbpeJ09JsPcZBVO
         guSMmwd9qgvcF9G/uF+XASVo0cnLmAz2QyBmylhITsr1iAzE8F8OWgV4FPM7cjURg6F1
         Tpmr0b6sw4t9ykAViOGxsSVkkHI43mtFzjG788vdwl49Jmbueqvr03ByQO3pMLiJEFta
         cMlnRiU6smja2kmkNdGePdoPYoD+t9RISXix7sxGG+UF+2j+VMiiQpatcV4DlHFSaDFd
         HvKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7q8Qot6JR3i6zbg06Z2hjmgQH001gR20T3hNmGkmOOU=;
        b=LUlgj/ndv0veBteAbPTV40misbkFDSEWwQYefTlGiyDnCeo1KVOYcvTe1vu3lXNZ/k
         P8KglXGr0HQhi1cKDZxXUCfCbxtKcgmvLDE7nAAy+zQySUFutdOAFLw9pmlvGVay8GuF
         c2s3Xn1g2p9xiNYgdXjDkW9//JCyItbS7gASXEbB26cZaiKk1BVYNFeSsydCzMYuWqDR
         ZGSh2X9ag3+BTdFndOCvDgCX1XnK14Du9zSQr/McJKu1zTr/hBFadmeZlS1jHqf3Z128
         RQk+XuaF9iIO5z6ERYPzqoGsWeIjbeYYLc7OTSr99HnPE5vCY0W00kk+s5tw5Hp1rSZi
         DvBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qKA8Hgqdve9gXGnQgdzvYyoBQ/AG5AlKuLg+He4cx02Jj6CdL
	xlShD0Q2riH61YNEC9ZKWf8=
X-Google-Smtp-Source: ABdhPJwm5UeUl7G0nHfCEjrEdkrPFqF0UkK+cMZ9HxbT21IAoV1h9b5FZ6K3O39xkQWYezXtDZGKFA==
X-Received: by 2002:adf:e991:: with SMTP id h17mr4915391wrm.40.1636602459572;
        Wed, 10 Nov 2021 19:47:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:770f:: with SMTP id t15ls753269wmi.3.gmail; Wed, 10 Nov
 2021 19:47:38 -0800 (PST)
X-Received: by 2002:a7b:cd93:: with SMTP id y19mr4769746wmj.190.1636602458788;
        Wed, 10 Nov 2021 19:47:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636602458; cv=none;
        d=google.com; s=arc-20160816;
        b=PX21q11bePJQ8vhLXi9HZIkfaZ/vSepCGITxkcuTURAZbJz8feeId8gvj/aC9+gM2t
         5rcct9DS3tbUoQYZPjBWnze8qr76GCyRfE724x1kpQytisLEaJETHyDfFmnJ/34OE3e1
         8wbX+xmAo9tK4wiMzZNUOHGNI3ZeilSAGeZ0UCS240CXeFF03kDVK5EWFiWu+B7VwigC
         PCLQya5D4njv91lxApyWco+TehZ7SkXYIVw1/DkJgUxInIWDGHaM9IJqiFsHeLnF668e
         Iufh6rN45DVT0ahmtpEEOvNCL+elhcjTIPnDC+qlj1bgDlVUatodZb4BwDU07UNUXb9v
         hP5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=xxkVIEZYPm3l/5ys+1ZbmYZs5yc9IPo06qsfuC3sE/s=;
        b=zJuQBDMCassVg9DPy18AWkzypJRkz6B+2HEIdb0pzFfJxZ+MI0Vnl/669Kt0EC6c+/
         QVrxHqS7sI7fEZS1ZnIGd29biKoounlpu6m3XdmjQ3H3kgWh0iF1lGLQhdmVQZdLIdXL
         xT1IFWMySZR5ng/yyZgSt8XduqnMKV7fvFX/M7z9acmxr5OlAIBB+8T6+HFAU+/sUwVc
         bZQFXsTegA7pUPBv3RudqOcKHQKxp35CX7TOlGHLoIXW2CluGCZLCoBSZ/IW6NgQFiY3
         f5VE7cSas/qTEBulxe3dKCr//bcgMdw+fqCgZom2yxCZtx+RkYUPk2SFP0BbxZi3V/Ef
         Xfwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=a+8s+042;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.15.15])
        by gmr-mx.google.com with ESMTPS id 125si538576wmc.1.2021.11.10.19.47.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Nov 2021 19:47:38 -0800 (PST)
Received-SPF: pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) client-ip=212.227.15.15;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from homer.fritz.box ([212.114.172.107]) by mail.gmx.net (mrgmx005
 [212.227.17.190]) with ESMTPSA (Nemesis) id 1Mirna-1mEy5h3G1k-00eu48; Thu, 11
 Nov 2021 04:47:33 +0100
Message-ID: <a7febd8825a2ab99bd1999664c6d4aa618b49442.camel@gmx.de>
Subject: Re: [PATCH v2 2/5] preempt/dynamic: Introduce preempt mode accessors
From: Mike Galbraith <efault@gmx.de>
To: Valentin Schneider <valentin.schneider@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
 Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Michael Ellerman <mpe@ellerman.id.au>,
 Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras
 <paulus@samba.org>, Steven Rostedt <rostedt@goodmis.org>, Masahiro Yamada
 <masahiroy@kernel.org>, Michal Marek <michal.lkml@markovi.net>, Nick
 Desaulniers <ndesaulniers@google.com>
Date: Thu, 11 Nov 2021 04:47:28 +0100
In-Reply-To: <803a905890530ea1b86db6ac45bd1fd940cf0ac3.camel@gmx.de>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
	 <20211110202448.4054153-3-valentin.schneider@arm.com>
	 <a7c704c2ae77e430d7f0657c5db664f877263830.camel@gmx.de>
	 <803a905890530ea1b86db6ac45bd1fd940cf0ac3.camel@gmx.de>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.42.0
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Provags-ID: V03:K1:neYARZGAV19oG8yqEbX7zTlDy0reCiY8txJkj+HjJpP++d7PuH1
 EFCHlPw8/g5XIXswE4Utys7VwXDBQESfjgmfjgw9iy8vCIh2z2vCZkV3y9UimkdQuep2EDP
 gWW8TrgLOlO77B5MDA2ngOMVQwWmIBtLQVkrKgVHHhOQGw0ms/Pq2FJuAX1OqafJQRANTQU
 wJ97V0XSChTV4+9OUo0sA==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:H0lKKDMMkPg=:sOFjR+XBi2b2ykrjd07bVe
 KXa7oMTF2HOqn8t+1Tu1/OaLvyEbMCTvN6aDPtwoSsnQAEBXaWVfBRSxINKhLt5KKZJaXfwdQ
 +BwSqVYtqlaLBYOnCeUC+1P2hsyhC3CbQ0MNaIVj6mSGGkdYxFV0jtZftpqjroSsdIf2uCTdx
 AlNCMV5O7if0rX3FqzLp4Bo3xrt95DzDeYexTqe13cdoXcT+HSZY+wendJ1z4q+f5NxSgy93F
 9tdLrxkCCO0yWDAfn0DdBbEeR9jjRcZ0J/UBC1W95CSBkCxpcT2vmrMI8+Vf2ZRVi2miSZmKG
 e6Aw5erTQt79VAQjEmCWQhhl5crSju/2cqCRHwBZ2PurhSLgCW+2HBDxlrvhlJFtqzB3teQ5n
 1Idbijz7pNO2ajWGTzA6EMrVCdZ9gU9zDP4ukCVSMjz2jVlnjIX+jJo4vqAzbBy4zNJMWq9xl
 PfF947O+uWcAiKqJV4oo6pjIVw7vc/BP1o47ZnjLvnewS6UwaLR16OMheim79HkQqCrXxmcKo
 wah4FkYwKlh4DzQmF08nSKgzDDjI1h+mf74xR06jfuGiRJ7EORXBVo9yAnS+JXriG2EoQgDt5
 oucNM5gHuQcGxVO9X6lEjlD6d1OiO91uTItqPY+VQwfotNMRK8UOTDvtWD3tT2He9+XORfnmE
 DnNc0cyn+5X/II1jmuuZEnp7OyguJjKLTXH1TZJPz2OzAJWbRmxAiS19kClMksDHNf2vBZ7bR
 TFxZpifVBFPM18VaBo4FkHfSV15oFpu1MIqMHZkgWyaLr+BUWLRCK1+IKMCbGj6ZUGNivykx8
 Yk58Mf0iGg4iFaEuaLDpgdcPdIh0qJqGcPzE49E8Y8+gXVkUz4ZGE5k3rWqylFEU1Oy22rmbY
 am1fzEn0AC40ErLdgYXqxW5m05hKNLljH/Y7frpVJZ/8BSAG2TbGyLKpsBOCpR9v11wiL9nwY
 ClDuJnFV0NIbHK4AjeEoadUQ8iSp2hx/Et/vZJFZqzH751j3CfsiONK9JE9KpA69amgukSbsx
 ISq/30qO0+YKfpJVwD/ySpjZWIUkSZijiDfWbLDTYj6f3Ep5d9q3thEIsBBFJGxe01AV1IINH
 iXnuUQB9alIHSE=
X-Original-Sender: efault@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b=a+8s+042;       spf=pass
 (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted
 sender) smtp.mailfrom=efault@gmx.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=gmx.de
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

On Thu, 2021-11-11 at 04:35 +0100, Mike Galbraith wrote:
> On Thu, 2021-11-11 at 04:16 +0100, Mike Galbraith wrote:
> > On Wed, 2021-11-10 at 20:24 +0000, Valentin Schneider wrote:
> > >
> > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > index 5f8db54226af..0640d5622496 100644
> > > --- a/include/linux/sched.h
> > > +++ b/include/linux/sched.h
> > > @@ -2073,6 +2073,22 @@ static inline void cond_resched_rcu(void)
> > > =C2=A0#endif
> > > =C2=A0}
> > > =C2=A0
> > > +#ifdef CONFIG_PREEMPT_DYNAMIC
> > > +
> > > +extern bool is_preempt_none(void);
> > > +extern bool is_preempt_voluntary(void);
> > > +extern bool is_preempt_full(void);
> > > +
> > > +#else
> > > +
> > > +#define is_preempt_none() IS_ENABLED(CONFIG_PREEMPT_NONE)
> > > +#define is_preempt_voluntary()
> > > IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY)
> > > +#define is_preempt_full() IS_ENABLED(CONFIG_PREEMPT)
> >
> > I think that should be IS_ENABLED(CONFIG_PREEMPTION), see
> > c1a280b68d4e.
> >
> > Noticed while applying the series to an RT tree, where tglx
> > has done that replacement to the powerpc spot your next patch
> > diddles.
>
> Damn, then comes patch 5 properly differentiating PREEMPT/PREEMPT_RT.

So I suppose the powerpc spot should remain CONFIG_PREEMPT and become
CONFIG_PREEMPTION when the RT change gets merged, because that spot is
about full preemptibility, not a distinct preemption model.

That's rather annoying :-/

	-Mike

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a7febd8825a2ab99bd1999664c6d4aa618b49442.camel%40gmx.de.
