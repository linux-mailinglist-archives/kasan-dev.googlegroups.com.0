Return-Path: <kasan-dev+bncBCDZ3R7OWMMRBGM7WKGAMGQE72FE7RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A48D44D073
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 04:35:54 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id bq29-20020a056512151d00b003ffce2467adsf2087233lfb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 19:35:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636601753; cv=pass;
        d=google.com; s=arc-20160816;
        b=WJkf+3PcHie04Fj0gcVSpMcHJR7R+2avnv657HGApmzoHpYzun6TQrmlX6OJgkB5kw
         3mTkTvMkQ3mnHh6BXU1EPCPwsq3PR5KGgD9i5JcQgERGt0ROEfe5blGsmRjL9D8X3YJs
         /WTdBTP1IHEvfAysMyQzNHoAFIZRkUe2W4Kg37C/FJcfNHgtCdkjiUpSWBtf6eOX4s2B
         YkRIa4gbWhopCWfi4DhZvp/URI9JGUN9vUBalfIA8DdRb7xdaxFy+LB/8S8OudTCaTzj
         pfWdlEO1WgSPNiEAJyj4RTDiEEojSNhzVzbkoOcSTJHC6EQtGBHSv6W38qxm3xmmnahm
         +DSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=0rYaGmVeKD5a8RcR0u8CYgf3z6zVWI5ib/eCCyvxoUM=;
        b=I118EJUBNv8XzylZSSHEQpWi8eNbXeSVdKDY2tSnqx9ykO+YOTXmlH1KZnBtZQdTVV
         yGGfE8g4yoObzErc6vtPvRPzJG8nrNMkSpBcUU9kteqbVVJJ1ff+NfNq2WAK6fsrE8Vq
         3EO3cFDeadxqLscxyKM3E3KCUrak8jq33q9GY1Y/lg/qgGW9HTQtiOn2aSuJBfr7Vf2O
         HqsRjocgUYQYxWj987N6enwThVoRjP8NoWttp+edvflg0lcT80cMdtsUZQNbeL0sff5i
         wa3t1Q952RuRZr077vKhyFZb/yZSVC1D/m27EWjtG0sA2UuukTNuKcSQ/dhpaxg3tIFY
         cDLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=bCYCzn56;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.17.22 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0rYaGmVeKD5a8RcR0u8CYgf3z6zVWI5ib/eCCyvxoUM=;
        b=hKSTsNXTJdqel7Gib1AIfG3j6LFJr/uyelpTC3VwLbZGyfKuuO9r82v4kzdFHYydhE
         ybWqC1+939ZPbtEXAYTkncwb6FshGFkHQNfwFvnvtT2cKwH6Dj8czEl0cID4DFYa0WVo
         004lgRpVWUX9CcR5P3QKNi9vAAaFh4uVnIBpE7p16LutegVFBbFnuQWAkB6prYO6HQmV
         p3uAFMXdgZ85alWebLKWLxknlHWSMNul74gHu/3dtNOMTjFQ/MhNJ/T/DuHXod/cbuUY
         lAVQR0fijru9o2u7VTG8W7aoF548LoCny8kalZ/cas21lNTyx/iX4rqV0ShUt2gwYtPn
         3WBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0rYaGmVeKD5a8RcR0u8CYgf3z6zVWI5ib/eCCyvxoUM=;
        b=HZif5ZvjmpKqSJAPOdW1S+i2kPrTjpSzNiRGHHDLafEmi+eom2k+gsivec559nifBV
         duhRyn6ziU5rcXF1x53DFg61YucInfXYA4Kgd7FH7MhTNl7hPoihnkpUARo2pKkHAeMN
         4x4+7yna8gR9/x3zPt/DsL9YEO278IA7B/bjLnuXw9tIpn6iaPxnBznyqPc/wp9s51ke
         VKx3z7nXYpGeP28MwQWetxF8YfXgeLD/dSfV7aALfj6Ip0a2nr6QJ1Rdv986nB2CLONV
         5h+Er0MFevFrA7VS2+vriTpO8c5zqt/P9o4KR+gr/9Ydksv4fBfpcfkt+JChAyvDyGQU
         vzEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531MK+NFpzSCIOxzAx68royFpjVDJjs0EBZd//VMpUuEmHjhOCY2
	TgNYx9w83Vw5tbPzDKBHZlU=
X-Google-Smtp-Source: ABdhPJxhKVd0XCYMRmwKYcJEN00kUgJiTexKo4ovnx5VlJsn5BRuEToCh1TpNW2Hs+HikJoYLSa7pA==
X-Received: by 2002:a05:6512:3195:: with SMTP id i21mr3889992lfe.50.1636601753542;
        Wed, 10 Nov 2021 19:35:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2610:: with SMTP id bt16ls877705lfb.2.gmail; Wed,
 10 Nov 2021 19:35:52 -0800 (PST)
X-Received: by 2002:a05:6512:b29:: with SMTP id w41mr3794932lfu.240.1636601752592;
        Wed, 10 Nov 2021 19:35:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636601752; cv=none;
        d=google.com; s=arc-20160816;
        b=MKG902NbgIlYzhCbjCKMxPwh3fAvvxQKBdX4cTXLC20s8kMpPRaTAkYIQxeGcQyLP5
         wb8xYrNMIL+xuGZS49aNj74TkEwLm09p0mQVr3ZGJRVc59Y+z87eL0zWP/NCarvLGfap
         5TmhAwKAlVyEi5TtZd/7a1N1C68FRPN3guM5KcyosSHkEOcM0YslXYxaJBcsqYfji8JG
         SSLMSM6vjA/sdDJ8czI/6Sb0cQ1XzYVcYemWLsxf/BOUXu+JdC/kCaPbFFPci1njJ3dR
         cNaNPO1RPbm7EHUc0Wvxjgw3Q9jm8R5CVB8yxJfRnxdjunvBNxpjq4HleID1VkXLFX8X
         IZpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=JlfhMj8Ms53wRI+F9uMCN/FnA8fBPZpNgeNSQByLCIs=;
        b=bIS2kvVk5010NM9Ql/+BClL0jEwF2cKrWemOb6dJPgBZJF4omxqiCtOVCMhzHKH6wZ
         4UlbreB4nzM2zoncr29XfzX1EgQ5riFdKEa3kiZ+vaMwC/AoM3ajFN4d1ZwvSzLa0Aco
         ocvy2Za4i7F+bmfxz6kJnvZ3fSunymHdjJs1+RIMzPt4tMYiwI8ZvW+cW4qIf9kmgRIs
         gkrRKozrMYE2RQtmmwaJMlBY0PtWBkDbMQ1Z9/Q61jeGg+hsDOLY2+B8AC1Us47jlcO3
         CkB0gOdrz6E/lypNUAPnqPspnxQ8OqrOXSdVeLP+lwNpFzaQ4QRc5gQ4Iiqz9TQSZ2NR
         L0hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=bCYCzn56;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.17.22 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.17.22])
        by gmr-mx.google.com with ESMTPS id i16si142404lfv.2.2021.11.10.19.35.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Nov 2021 19:35:52 -0800 (PST)
Received-SPF: pass (google.com: domain of efault@gmx.de designates 212.227.17.22 as permitted sender) client-ip=212.227.17.22;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from homer.fritz.box ([212.114.172.107]) by mail.gmx.net (mrgmx105
 [212.227.17.168]) with ESMTPSA (Nemesis) id 1MV67y-1nAxUc3DDa-00S6B4; Thu, 11
 Nov 2021 04:35:44 +0100
Message-ID: <803a905890530ea1b86db6ac45bd1fd940cf0ac3.camel@gmx.de>
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
Date: Thu, 11 Nov 2021 04:35:39 +0100
In-Reply-To: <a7c704c2ae77e430d7f0657c5db664f877263830.camel@gmx.de>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
	 <20211110202448.4054153-3-valentin.schneider@arm.com>
	 <a7c704c2ae77e430d7f0657c5db664f877263830.camel@gmx.de>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.42.0
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Provags-ID: V03:K1:m5Cbra52DdXMAE7H+VG8AT7kX3qlvfgdfpx6gGyNLbPdqVV0j9i
 pqzgjniLDEtfh+GNR7V7YSZ1CReg05G3m1fkgnm9KcORv5LF22UU7ZiSxoWjxnlG4T3f68i
 XuDCvFG+2//qny6q6ZpXwZsJrPVLYHdDi/3SO9LVn3FgF7eJmr1NNUTbMSzhK4R5tO9M4Az
 tNyjyk0ii+TyMFksaQtAA==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:EYpd5k5MlBQ=:AkAFq4JduQ34cfsAEeLQGz
 NQzFKr2UtLN2lACkzrMnzk5KbDLPM/2n315ZQ22SkVf9sdJ8eKFWFfhTBJniSyEXb8o2kkGYi
 30GSabsPni/S9Q7uHbLgQm2QN3Bh/nkQVeXLMk5oourWqhdhORVGlJneREUmyAa32WHtIJUDW
 7IyPbNrPb3CN9INF4hfQr6A6gwGwvNXHf1aukUQR+ypLXD2nzOdlsx++iA0lHBMo/uFrSBPtl
 ShTrPStgk5McKTcTbLYAybfAg2XcOldDyf7XdkIlE+1U+H9BHOtkoi9ltfupzDm3cnr/B35Ow
 Huhrsz7/QWgjK3Ul/mhV9GGtUb+CawUMwNdPIoa5tDxkbu7OdPOTsvwJ1LBdcmPKi/e5rB76c
 FxcEhQdwRXAkju6sUORkllHVyaxYKMMqYWNAgyUKpEZv9pCdWKQlqPWiTwHnHmok1vu1I0MjD
 LUqkLRjVIiDhRdCi09LvEXl4wwrbuuGm0BER4VLGbBzJHzNPSTvWghPzqvMLZiCOPt9UeZB6P
 lnYz7r1avfa1yKQB4x/GHPT3emYVqXgt+TMVBHBQL6lhBehPBuu5dNIb0Hhz/wKUTog/qJjO2
 ktp4KvN9ZNL5dzaRzywa/UVcU6v7eVxcDMP1TUJe0dFdCfcp7Cxh59P0VcbZX1UZgDhOhNuTq
 39xT1X2FnoyMMViwjbOT0gQgDwyJistV4LvtQBg69lg0Vn7kaElF8yRjQxmv8eEvQmmlUpM+s
 ZcaWA9ImTq9ogvsCF0AQhfJzMRmlbj32luOz91G8uIfKoCAQhYXbz3Vh9lfwvzqa1At2O6ufP
 Smu1pAxrq4rngh6JOVwmiERIfwXA6TDfwZbcyo+M+MGBdwotmKsYxBcay3LJ1kSxFq7iDrKrH
 rrYtPp1rkpR9NvzJ4vkzeOuIGqr9/sD+2mZWvKUeDoYFKlfEowfTSnHrWiQRgL+NUDx2y1RSx
 /eQkuKECO6xGGJyuV1uUFdNqDFH7V8b9lS+agRqtmxAw0hGSZ0BKSJD/g7104U3YxMvN4HzZx
 kDDrhFf2SUQDBfNgdtYhnx0/0PnAfQF0tifLCW5u380Oafrps70dyG0DbWyp7N+7iAheuzkum
 jvbGqXv/XL7eBY=
X-Original-Sender: efault@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b=bCYCzn56;       spf=pass
 (google.com: domain of efault@gmx.de designates 212.227.17.22 as permitted
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

On Thu, 2021-11-11 at 04:16 +0100, Mike Galbraith wrote:
> On Wed, 2021-11-10 at 20:24 +0000, Valentin Schneider wrote:
> >
> > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > index 5f8db54226af..0640d5622496 100644
> > --- a/include/linux/sched.h
> > +++ b/include/linux/sched.h
> > @@ -2073,6 +2073,22 @@ static inline void cond_resched_rcu(void)
> > =C2=A0#endif
> > =C2=A0}
> > =C2=A0
> > +#ifdef CONFIG_PREEMPT_DYNAMIC
> > +
> > +extern bool is_preempt_none(void);
> > +extern bool is_preempt_voluntary(void);
> > +extern bool is_preempt_full(void);
> > +
> > +#else
> > +
> > +#define is_preempt_none() IS_ENABLED(CONFIG_PREEMPT_NONE)
> > +#define is_preempt_voluntary()
> > IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY)
> > +#define is_preempt_full() IS_ENABLED(CONFIG_PREEMPT)
>
> I think that should be IS_ENABLED(CONFIG_PREEMPTION), see
> c1a280b68d4e.
>
> Noticed while applying the series to an RT tree, where tglx
> has done that replacement to the powerpc spot your next patch
> diddles.

Damn, then comes patch 5 properly differentiating PREEMPT/PREEMPT_RT.

	-Mike

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/803a905890530ea1b86db6ac45bd1fd940cf0ac3.camel%40gmx.de.
