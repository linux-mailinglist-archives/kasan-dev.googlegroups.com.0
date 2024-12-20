Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJ7LSS5QMGQENKDQ27Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 88EB89F8EB9
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Dec 2024 10:15:21 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-29fd1868bc4sf1212099fac.3
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Dec 2024 01:15:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734686120; cv=pass;
        d=google.com; s=arc-20240605;
        b=AJF9XxQDGmhxuUVN3je/PjsTOF+VRJmsTrMTrlMKf/FK9jXjuawPFdkGcvvG/4/qJ8
         wnwMSaOMAZp1jQOPcouqAHHlMLQ8ZlPypR8v/dvB5YaQBN5TZ5iIJ+IVATA+pxV3vo/X
         dBMSvxktK0wqo7TSrjHwsXE3+L9ayUfe9/dMuJ+RApz85duOqeeQ4BGPjUFxcXkxQ397
         hFcPQMm01w5lzSz9l2nFXs1D7dRR6M/TNd5wepa9l7rNYJOU04mbEVI5hZ32jKc4mray
         o02qHef5tf30xWkCj+D0SP3YpbcCnzadUurIgNdZppMCynxipiq8habsE0u4PZnnJtum
         KcHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CJlQPfCP1JUVn25PGynvowUQb23xsMa2Ke3xL11SBjs=;
        fh=Am+Z4sSSgKpFLXKoQzwODbJnRzPo61ARtv5PKWE+Be4=;
        b=ZBXAvNTocLOEKSo8Gb7GjSUfUvH02DpeZbEfJyyxterhpu6s8myXObvtZWsHvF4s5v
         aMxkI9O61CgGLhD+esKS90RcFC2FQaD6rm3qe+CXhzp1HvWn4rLIsWk8HNPesdN9nvVF
         x9b+hGOGXfMTjm7C9680GaVHuLiJj931bLtwM4eSmJ+uboYOndC49E8jvFw4eSIwusz2
         U3qo13sNuo4OAM+R1kGG7AGySCJVKb05cYlN5oW5CZDIryQS2SkGWJ6y7iSXCyZ5TFnI
         mvNlx5BchtPNXwWDT0MYj23IC0DYyLtpm7794yfjcQEKhS1A5aSlRbFeC3dDUlhC98Zl
         iWbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IgegpcF0;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734686120; x=1735290920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CJlQPfCP1JUVn25PGynvowUQb23xsMa2Ke3xL11SBjs=;
        b=lGRmr6EmQCfvd0ggGrGmpU79uQvPgTzuF+uJLAG0JWNsNYmChkKctuzVCof1mLaUp6
         3XFeQuyvwEcMX6sNflu7UpZbuNKKdLxbu9fa0Cmr75thqOgSGy/+ll2hBagYDqDJI7D9
         2jaRIQBaQuPa+nFms2cPRodMXiwPdf0wLLY0UINat4679TjR/ADVmFvDcCNmy7ZPshCr
         KZAXoBw39s8KW+qLEVQssAWxVk+MFF4FjaPEy6a6bmSF89Vx20mvF2Z1EJXGVVyADM2E
         +3U34gEo6rD2pyxfuL1/tCPefVRraJ9ZKAcphfJZ16AZGWIDFbZbFWQDBWv7o3iFO45j
         IC3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734686120; x=1735290920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CJlQPfCP1JUVn25PGynvowUQb23xsMa2Ke3xL11SBjs=;
        b=nOYO7BbKLeurA+CgcVZzDlnn+T0QBn5IH/WLzDmJ3uWNeGtiLOnMEZMqapNSGLANHh
         HoBwZjhvLAwpdnoqDJYhVXPoZpmN+Epddgyvih3ki1WUFvVCaEuqcRhGBKf2wcVyhYfR
         X4iSc3loVj5f6FcbgBMx8MttTbyJk4Totx3Z2x4ZLblWCpP9hPFtKBPUwRleu2tP70tS
         s/IsXobhfnB8xlVbe75wbEmA5MIIg7JpooWtooaChnQlPeNzYlx/yLIaWs66B+s6BHcS
         Bq8/i8dkYhm8CzLUmKJNy3bcsA2fxQb6Nt7N/HSNcJyVv18jclpiOM+jxCZdKbol4wlO
         9Lnw==
X-Forwarded-Encrypted: i=2; AJvYcCWGZrVVT3LdsCNZtxlu4lI1XQiFVFx+8ldDkBrT7RYs27QZDydptOzVBMPJwUSxqkilcN2HcQ==@lfdr.de
X-Gm-Message-State: AOJu0YyLwoR2K5IrDfmcqlJRbF50pdQgM3/PaLKfqahgLG4ZtTY0N9V9
	j7QyZqN84zTIkBHXN4W3oiGYoDVOMI/r1ubVDFgyY8K45gdyS1yg
X-Google-Smtp-Source: AGHT+IFH0DdPgPnik0Jy/g4NcZ5nJw8NeuU0NYijXMkiGByCOpotxkeHuPopizsAqohLFpcN9GVhOg==
X-Received: by 2002:a05:6870:de14:b0:29e:2991:d953 with SMTP id 586e51a60fabf-2a7fb1365eamr1241625fac.20.1734686120041;
        Fri, 20 Dec 2024 01:15:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3906:b0:29e:3d45:93e6 with SMTP id
 586e51a60fabf-2a7d0c1ddd2ls46300fac.1.-pod-prod-03-us; Fri, 20 Dec 2024
 01:15:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXnIJbh+0oz3AVUwKm6N/yNer8yh/D329n3ObRGwdaITepS+uX0asP8uyUjIbGySWIojNoZNZiUqlA=@googlegroups.com
X-Received: by 2002:a05:6871:8085:b0:29e:4a13:603f with SMTP id 586e51a60fabf-2a7fafda817mr1053206fac.4.1734686119103;
        Fri, 20 Dec 2024 01:15:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734686119; cv=none;
        d=google.com; s=arc-20240605;
        b=Tmv5oS3zkRckOW3fS4BrPVfpm3Qr66Vsfg9pumkBP9a79PuX8RyBeS35aeujeVRkZ1
         W+Sjy4mFl5p/mCplraq5T1MYwv2VxIE8+6/xcnCGrOTw/gVvXwO21hbKHLHMsUG+qeV3
         hSNEWLG5c/FTZ0TJ7kEQjrokryNLoP+8UdR/Z0RTBpgf8ZmSerUf4WOT1jWp7yuRBvpO
         CcMcrMhsWdwepTgsBhOl0hFi+rIpELU3RglnHxaFxDLHgdzRtVfcbRmadIZCq4FsuKyp
         TgJ3RB9pdjdr8Aq+PHkWIkkt8an/Eh3q4KiQ61CglowS6MJnizY4t594i+d2krsr/IAi
         1xGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NLetd7nVAxQOP/5NukKrvogts5apKvc1tTqPC3qKmrg=;
        fh=tCuoogBQ88c+Ca68bBLVvwdvizME1I7ePNOm9wX9/OU=;
        b=WfjQQso3TD/TUW9RZTJD1/1pLcRl5dMyPCGENfaaihJo3iC/3Wk9whCR6Qu4zH2DWD
         6+DiSafBNPAkS2TszSBsPgN+zaVdzQGyrC97pPjIn5Oi+UXyrljp7gg1u2a+aQX9S9H9
         d5jIuUUxoZbie/vomNdcf0OGyo1zlHBMJwvCoCydWrYUH83EF2acjBndfi6MuhNR+Yaz
         zGxKZud7LkoG7QupGUMmfgSZb1rjJijjFCzW2XM+lRDWdKncP1mfRUfkTT8wnBdzz5MV
         LEPe4dUD1i51WAGAbvLvQ2hGFiby6y2hHjL9PrK4ZOcVYRDXgTxP1W1gXOPcxKKBD47I
         SqhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IgegpcF0;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2a7d6f5425bsi183738fac.0.2024.12.20.01.15.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Dec 2024 01:15:19 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id d75a77b69052e-46677ef6910so16848971cf.2
        for <kasan-dev@googlegroups.com>; Fri, 20 Dec 2024 01:15:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXGzqkqyE2pHIhEECV4buiNprpJ5Q0dVsIuaYTehBvEzPmzrkio2d/GGOcIHrGzvRDdi1/vapPT1Xg=@googlegroups.com
X-Gm-Gg: ASbGncuizDJL8RQ8TsURLN/SRkQAs/4jTxnNjsHfGrtgzQ+1jFwnCwgt0p+feSrcChY
	wqqBeOt3Ip09VnRifw85DNGuC/hX0yHn4hIYKDNneBpqpO7bjXovb9D2IVxYKEV5XtHuXm2k=
X-Received: by 2002:a05:6214:4188:b0:6d8:9002:bdd4 with SMTP id
 6a1803df08f44-6dd23358724mr35457356d6.28.1734686118302; Fri, 20 Dec 2024
 01:15:18 -0800 (PST)
MIME-Version: 1.0
References: <AFMAUQCEIuMrCuBcOuRJwqrY.1.1734682065298.Hmail.3014218099@tju.edu.cn>
In-Reply-To: <AFMAUQCEIuMrCuBcOuRJwqrY.1.1734682065298.Hmail.3014218099@tju.edu.cn>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 20 Dec 2024 10:14:41 +0100
Message-ID: <CAG_fn=ULq8ZY_PtZO96ADVHTAVEr1LyTp+XHYOtiBFmn6EewbA@mail.gmail.com>
Subject: Re: Kernel Bug: "KASAN: slab-out-of-bounds Read in jfs_readdir"
To: Haichi Wang <wanghaichi@tju.edu.cn>
Cc: paulmck@kernel.org, rientjes@google.com, josh@joshtriplett.org, 
	dvyukov@google.com, akpm@linux-foundation.org, linux-fsdevel@vger.kernel.org, 
	mathieu.desnoyers@efficios.com, andreyknvl@gmail.com, peterz@infradead.org, 
	jfs-discussion@lists.sourceforge.net, bp@alien8.de, linux-mm@kvack.org, 
	cl@linux.com, joel@joelfernandes.org, iamjoonsoo.kim@lge.com, 
	jiangshanlai@gmail.com, viro@zeniv.linux.org.uk, kasan-dev@googlegroups.com, 
	mingo@redhat.com, tglx@linutronix.de, luto@kernel.org, 
	neeraj.upadhyay@kernel.org, urezki@gmail.com, roman.gushchin@linux.dev, 
	vbabka@suse.cz, linux-kernel@vger.kernel.org, jack@suse.cz, 
	rcu@vger.kernel.org, boqun.feng@gmail.com, x86@kernel.org, 
	frederic@kernel.org, vincenzo.frascino@arm.com, rostedt@goodmis.org, 
	42.hyeyoo@gmail.com, shaggy@kernel.org, penberg@kernel.org, 
	dave.hansen@linux.intel.com, hpa@zytor.com, brauner@kernel.org, 
	qiang.zhang1211@gmail.com, ryabinin.a.a@gmail.com, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=IgegpcF0;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Dec 20, 2024 at 9:07=E2=80=AFAM Haichi Wang <wanghaichi@tju.edu.cn>=
 wrote:
>
> Dear Linux maintainers and reviewers:
>
> We are reporting a Linux kernel bug titled **KASAN: slab-out-of-bounds Re=
ad in jfs_readdir**, discovered using a modified version of Syzkaller.
>

Hello Haichi,

Unfortunately right now the bug is not actionable, because one needs
to download 180Mb of archives just to look at it and decide whether
they know anything about it or not.
Could you at least post the symbolized KASAN report?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DULq8ZY_PtZO96ADVHTAVEr1LyTp%2BXHYOtiBFmn6EewbA%40mail.gmail.com.
