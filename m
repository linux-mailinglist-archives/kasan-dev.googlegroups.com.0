Return-Path: <kasan-dev+bncBCDZ3R7OWMMRBOMWWKGAMGQE4A2GPVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id BAB4D44D03C
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 04:17:13 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 144-20020a1c0496000000b003305ac0e03asf4075641wme.8
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 19:17:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636600633; cv=pass;
        d=google.com; s=arc-20160816;
        b=zb8oNuXX/l7aX+SaJSvO3735BXBR9EhXfdl1iNag7fzZE6IPOfKmfXwrClvTT780s+
         P29uAFxPa0N5ixbAQUYZT0GsXnRx34x8bmlvi8aBmmoo2q6A1mSRlubXz4HO+5EQLQM1
         kRh1zQ0X8PRfKGNw4DrfBO9YJVuKWZGnEuz1QaQjY7dqJCIr8iaTydy0SJhMYSevEVLC
         tvHKuridrANv3Q4jmD4XKHAHLOdBHIl+bQZyMEViLN5iMNKUojluZCzOvlrkVwPOxgEk
         yVP4kbiWuivJNQMiLrHEpb9nycQgYDdJCeNHzMgP48dxJuFWnXCss6Did8un6cxSwpgB
         ednA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=mF+JZ8W0u3oXTgBBruzKEFFk+56ApTO/2I2tqP23DOo=;
        b=axLf13yqXUPu7vcCD7GkUZJc6FEpvO46GMmBK006lQ7OQGeNsTCLHODPjOyijjeHDy
         yvXtoUjnS3NkUM5u8hav3IsKegrJUioiEdFPQAiZoV8hObHaNzKisvNeHKk3tqyn5En7
         WMuwnY+CNuvc5uo8QeIVtV+DcFbdtKkuS3RMqj7E3E58NyDnye6I+gZWQjYSE05utTA/
         KBkWhYTSpn88UqZdnt3M9VwMIb45ztVBTOKcmVLmmhKzzjyspunMfF84LZB00QVNvf/S
         DBoSi+HjfYOf9D+GPRYBHbAxG7myLA9hBmO1o4ZWJ+aoXw9ShQCku/fSJXjsthQYqdBX
         7Kqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=eXapQbE+;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mF+JZ8W0u3oXTgBBruzKEFFk+56ApTO/2I2tqP23DOo=;
        b=hptgLOXIYWlMnX5smt4zrL8SvqBCshGlvKcqonPAcNG5Oys0PqrZ9inzeTm01mJRNf
         qa49JmlnX8GelRiAPKcR4rKdIn7Tjy9YXnV8t4sYTlN6XLjSNaxxPwiG7+Owlscrd2gd
         saTIiVq/nUVKhxGQcCx9GDb2UWyWzMRp/WdDKYkw901gqNgA9kuIuwCW6+okX8PNncGM
         mpqkosfcRObR71kSbcImH3Yu/jzUTOaqys50mmCrsVX1/AHpfIAkHcqw+Owct70RkIUr
         Ep/mRzejyOsRrf8ZC44BMRBhqNSGjyCxh7zM/dtNvIUmA0k9WEJkNX6i0yD6h7rqLFSV
         bS0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mF+JZ8W0u3oXTgBBruzKEFFk+56ApTO/2I2tqP23DOo=;
        b=LL5EBHweqjCDI0AdydrP4PbwXGLGX0tVvkgNG1JtW7NidI7bllxVFChAbNakYXSXu0
         1DPZxcA7NrD6occwIu44tKTjtPA0KtZ048lSZ6ng+O5NlgM/uIIPzKZWP+LFovnFW120
         qAH/uaz1bOjQNe+eaPmEgt22INsYB3hm85Oh1evP5+aAgBQPnkv4oqp7U+CVquhuZw6k
         vWWJtxeHR9zOpIkjNp4xrPSDa6LAphZihl1IVHsy7grh8DmeUNcgpOddJc+oUmnbzdc/
         SaW1gH7j0R3/3LTwQ2XuXjKsFRgmgSyOB5xtOlrjraJqb/vdwBecIXMAN4sqSPEXBUxE
         k7UQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530SeT6MSiSkz3HxG56yQAjOo/hfquoMS/tqidmJWGn0WcBjv85s
	Vs7Gm+gRVWlVvhzflCLB2Xw=
X-Google-Smtp-Source: ABdhPJzCPsvnrAGCJSeQ8ereCv9EKZbsLvgq+8FbzVTA9JJ+bHOXONzJP3rcuzvU1Yx9xA2zo5aLJw==
X-Received: by 2002:a05:6000:1862:: with SMTP id d2mr4792486wri.251.1636600633502;
        Wed, 10 Nov 2021 19:17:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6b08:: with SMTP id v8ls2158258wrw.3.gmail; Wed, 10 Nov
 2021 19:17:12 -0800 (PST)
X-Received: by 2002:a5d:5850:: with SMTP id i16mr4792808wrf.197.1636600632691;
        Wed, 10 Nov 2021 19:17:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636600632; cv=none;
        d=google.com; s=arc-20160816;
        b=aDrRxR8gU4dORNbgEcLqa6H/xD8oQSdKkuH2ZJGuO4X1m6WN64f2RfgrHb7DvkBm+2
         5PCbMpUVcIoPTbWeNHgD3YyPDv3wlQZh4gsAVHfITBAqAHsBV1ShUGsHvKd5YAdf0K02
         HXlb7t1b/WdtqEBW+k5obF1pJDoa7jg/D6J5UcHs4by3SYSfsWP5aKtqQNSiiHHmOT9q
         M6TkDMt8UMVy+Yfz0muHdwKy3bv4Ezt1IiDhB12Hz7hyh6mN+kDAlZVifBvsmzuBqW3F
         dhxhkJhccWrZrEx2HADCqKP/GSDjVK/AkY/bT+PvQrl3AQPHF5USIHyxv+oj+ROJ2vGY
         58XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=UEu3U0vbUNZlXnsVkiWr3cOvTw5UYdgkNIDlq2TyOmk=;
        b=kYtY1KxYRYDI+a/4tbHqGM6VVdWW9qGwioDOJycJNdcb5mOrhH/kGt39qtiGnKU2rg
         4AEtLosU1rvwLEj05PIDwuLkpFCrrgSfdYtEKye5I8FPfaMj79Oham3aLBFNo1wUYt30
         uWvBT1BT8js8N/6Gv9LEdwG32mOWp7dO3vfFp//z/N35OUNOCGSV72gfMe/wRZNfPHa/
         PKQs/KzWzOT0rr50CzmTdcIDT20K/QAKWDLObJXUsvNwDjHBE8U0zsz5+z5R9CCSBOeo
         pbnsMio2CNABtex9fTZFX2vgW8ZRbrXMwT8aapnX/iALgt9AJeAjGfjtVMAbQGM4rjaR
         iETQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=eXapQbE+;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.15.15])
        by gmr-mx.google.com with ESMTPS id s138si686887wme.1.2021.11.10.19.17.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Nov 2021 19:17:12 -0800 (PST)
Received-SPF: pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) client-ip=212.227.15.15;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from homer.fritz.box ([212.114.172.107]) by mail.gmx.net (mrgmx004
 [212.227.17.190]) with ESMTPSA (Nemesis) id 1MNswE-1n4sv12HCy-00OFiG; Thu, 11
 Nov 2021 04:17:03 +0100
Message-ID: <a7c704c2ae77e430d7f0657c5db664f877263830.camel@gmx.de>
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
Date: Thu, 11 Nov 2021 04:16:58 +0100
In-Reply-To: <20211110202448.4054153-3-valentin.schneider@arm.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
	 <20211110202448.4054153-3-valentin.schneider@arm.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.42.0
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Provags-ID: V03:K1:qdKVFo3qUd8POKOz+yc+x/4T44OcjnJV/MAWTG4EkF4hhUSRvqQ
 mUzoLUU1fEtSpidfUhv0y/XvxJ05PaVaIwghabR3cN0QZU3PllhBeGse5gsbZgORgHk0G65
 0YJqU3vKLoBpBV4AOyPaB7kj4As5svKEGAxE1eDJ/pETDTeSYlv4D6x0KqsCLgCRqrsRB1M
 cPmkHNhgrsUG08c9itIpA==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:LZWBhAOA29M=:3Rf6nidJu4DK5U1hJ+TlOb
 fnCw/Zzx1GMgYx0cJovFivxszUF2Vkq4E5zleDi9N1tPsHDKlj5nUJlFJXfG6YMMvqept9Nc+
 T/1uVgUHSCiqBeamu2uv8jf7i2L7oWP96K4TnVfKoegF7s5oG6skJ54tGyWoKdeYygIvzhMM7
 gCpfz4AgLI4AQ5bqCFBxheN9Abwlh9pvogfetMr4ml3WCCzvLRoAB3N9qKt6J6sWnSbUpBejE
 hux2LDf/agCifoHTIVWZKuYSU8KeQr1CdZZo0d79PsmngVPNz6/Hxv33EvcoUqaRY6XorRGqf
 DYURLAYgHILTMDxNttC1Jxx4pzyX66XkmuNziMHwM86HB5S0kljCWzfBQZvZy1zYa2mqBcf72
 MvKJgj7bGXNeIuRwo4HjSOgUIuc+YcNj9aES9dr61Dmpu8Ims2ShrcMDFlVe8GlwraaholgCV
 s7YsIKSDPcbikYu0jxYATZxvYh+fRgU7dwoEtH45EzdunVi19cXo5ZxvHzi1Itdg0Zy3Suw/F
 pcprzm4RtJtiDUy8WCYlH1r/M046lHmrKvh1i+a5k/8GslvhRmHqYUobSUXHbTrlzZQgviQHj
 D5E4kKxWpFIWju9QrXgYSm9TrMeEmldQ9EJXKVakFTj4yM0eFLegY0KdMcaWvSnBdJPsy7VGT
 v/KQPp8J4k272DPRlf5tJ2z/XYVoy+4NGkmPeG4tZM09WKUAg5RiWF9rz/OCiE0cenrfw6GHg
 B1mo5g4wwL/z5i/1D8RNp9JodB4qe61xYOE4QpO+MgzJ7xQxFhr8lBs6EJjqVUZ64DbqGXOxt
 sHrHpIdUNBEN83FowKbVLGhXYO9V+tQ/OZ3tYw4Gom1FRPfO9HdBWTIOrIk8EWS52xlA9rBwG
 HVGp/Q9nmPi3Jd8MHAs5dodJ3qeTIKyInGkd40dkcWPHxp6tQjifJ9sHm1lK5oxT7tTV2hNFC
 TkgMtWDHH0tAw/DY/4FbCzNNF00lrTS47zQxebx7HsN66w7SYhnhh975x/+9pxIeFujzJd+BR
 M9EuuIit0IuefH2mKHZRyXUQTaWKgIdFJ+61q4jkGBAbDmOXEe8/fAxh5+zuuuGDeyCv7jU7K
 T+iEzWbTojYQ7M=
X-Original-Sender: efault@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b=eXapQbE+;       spf=pass
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

On Wed, 2021-11-10 at 20:24 +0000, Valentin Schneider wrote:
>
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 5f8db54226af..0640d5622496 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -2073,6 +2073,22 @@ static inline void cond_resched_rcu(void)
> =C2=A0#endif
> =C2=A0}
> =C2=A0
> +#ifdef CONFIG_PREEMPT_DYNAMIC
> +
> +extern bool is_preempt_none(void);
> +extern bool is_preempt_voluntary(void);
> +extern bool is_preempt_full(void);
> +
> +#else
> +
> +#define is_preempt_none() IS_ENABLED(CONFIG_PREEMPT_NONE)
> +#define is_preempt_voluntary() IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY)
> +#define is_preempt_full() IS_ENABLED(CONFIG_PREEMPT)

I think that should be IS_ENABLED(CONFIG_PREEMPTION), see c1a280b68d4e.

Noticed while applying the series to an RT tree, where tglx
has done that replacement to the powerpc spot your next patch diddles.

	-Mike

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a7c704c2ae77e430d7f0657c5db664f877263830.camel%40gmx.de.
