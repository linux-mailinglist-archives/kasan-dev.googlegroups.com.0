Return-Path: <kasan-dev+bncBCDZ3R7OWMMRBPNIWKGAMGQEXA2FQJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 15F9B44D089
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 04:55:42 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id bp10-20020a056512158a00b0040376f60e35sf2103965lfb.8
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 19:55:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636602941; cv=pass;
        d=google.com; s=arc-20160816;
        b=votQ+1Lkc1r0pv6L0doNe3VblSV+mDKi5ZOO2y/BD1teh6JUlVV8dyeFSh9HfqUgab
         vycj2MXVqeSKdiqv9MBqNiyMDjVTZfL9ClVs23EZiaZciEHQvGM1kdzduW2YaBFfytop
         /tyVWXKOmlqXhBx8QwCLH/c/++Usy14gwr0xg4dYEeUJ1sHbYddt7yMyUKcZfW0XBQ7w
         D1qj3DQVH6B2RrBcdEttFGPbraoafHnkMh9K9zk0Nb+kPTmJZWRzYNm6g86kwFDdKgan
         FmA+e5p1xIv4nYvWD/n02XRznqmLuF2NMrj7Ez5nnGaIqw3CX/9/5KWKntgYUSF+02dn
         PzUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=a051v8+6tfLKqNCrwgwqroBH7/xzUD4aDgeJy/PoP9M=;
        b=dU/Z6F8lRosnHeYFokgBI9UoR0AVQno+e1fUwnaRUJeds1HhpEIyWeIV/aZrNDWIgc
         xQVI38taTM2yXBNKdSRRigflw0ocpcPuavNgvFYjZBBbpP1Yhf5RfanOAnncDK7mwIMU
         eIdQVKyfTQEdVx5oVuTyFhfwSgPhW6Gmu3LvWKcZ7AeBnDFraiypzI3aYCAR6nnCl4mP
         ByPcGt3dPMLKaSWwVuNREQ0+r4LvTkG1q2go+j9NK9qJdBIQ/q2hYLLZN4Qbw/AfIWZj
         GngKEbMuXsGEDxkSgMCGAk7avI/G1eBOZPrVmzYbZxC4covjqjoDNXdmstChvC1NF5Wj
         O3Og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=Yves5vPe;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.17.20 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=a051v8+6tfLKqNCrwgwqroBH7/xzUD4aDgeJy/PoP9M=;
        b=HPwEHWiqA2lmYQWeYxH6/OnnweSKO907Icj2PeUkOSFZO0QtS5nk6ZDlr8qBP/sFhO
         jB4GamooTLmn4T8Bp206PYfNeV/N76nyyNyKpeHx1cUd7bmR1kee77amW9ait5Y5sIye
         6i9ePJ+sP5W1wlujFshhdtGNFsBH81BChKvKtTfl/neTbbDwMKqo0QGm2WSRVwNsjS4U
         euOL5M8uMUskLxvHcwQpnJjAdluXpk2dOuOf57dPZW2OdGLciPLLk3B3lNn9cOZE//k6
         VdwrjuQ4UxClzNDGK/RP0f1KzMyGAQQflSZWdC3Ij4MyWjC+hmc7R5LOhieKGPadJG60
         PHEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a051v8+6tfLKqNCrwgwqroBH7/xzUD4aDgeJy/PoP9M=;
        b=ktLxiaWn//NaOAphdNP4HYeoUxAFFJsiWJmURYop2kjgw+N7qQUwxUhluwXuybN97L
         reEDF222D/mIPM5EFSRcJCBHfJo8sYOculBPrIRgHusPG9s9CbLSP666XUdNJboGOG8y
         V6+Wz94ERdnUxdwbTtOZ37od18cYjxowNrL7H+RPXoZhlZ/DUsBzeCmmW41tCBYF6X4s
         6qVTMjPy7cltNj9Y37NxTb9wRdDH1Kd2svKnPCHEg0IC8kROzTpvrIPSRaz9lZYjMGVT
         kplk56/o6UetvClbGJ82Z5BOHdHnafvj8xYtMozwur3W5UD2XrZ38pC06CnWMDQAvRMF
         2T3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305cfV1avaqhU+9Du2zqaPSk8auFTOf5mzAD9HVqegs/hVxU5XC
	UuWnndd6ncPhtDeWQ+DNhvA=
X-Google-Smtp-Source: ABdhPJwEBLtfe0yPpMUWna3Z3B9q7XTElfSoD1mCDNQVHexu95UJKBvMtpCkcHl5cP1MMzG824BKdg==
X-Received: by 2002:a05:6512:3216:: with SMTP id d22mr4000695lfe.604.1636602941687;
        Wed, 10 Nov 2021 19:55:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3499:: with SMTP id v25ls1265107lfr.0.gmail; Wed,
 10 Nov 2021 19:55:40 -0800 (PST)
X-Received: by 2002:ac2:57d3:: with SMTP id k19mr4102352lfo.150.1636602940738;
        Wed, 10 Nov 2021 19:55:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636602940; cv=none;
        d=google.com; s=arc-20160816;
        b=y275DmaeeVHP252CGDqUoSFPdmQ0zv4fRWDpJN3wn6r32WANJlDYR/M1mN9KXbiO7b
         RPPUnz5YN1hY1kDAs8AsFQK5O53C+EWjFR+9eMQKTsIDV1+M0m3HoFmltl+lCEeuNrlN
         TMTcjLQZ9182VJ3PE4JCMi2rTPHA5pNCWQXzadqe4BJAKKY2pUZWzzBMlGbPZJ1OVdPV
         IyHSrXb4bfFSgL51J9o1D883NogWg4SPi43ffowyewcI5P4jrcq3UiHBfRFc3MjQomOX
         E1n4pMchHYSoYEwUzXY7dHCmZgxa6JUIn5gX+4HhpdOtn0lY6nvBSW/FIfZAgUmrauvF
         osMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=3dAnNnhvGB20Uum7lpdKdYzzDSC/Xkz9vwcmijnTveM=;
        b=vaRt9y1m11JRNCHjlR+16OiKKt7lgENINtVyNm9tRRe8KC7ukY7CMwPL4xh6XgDH05
         YdPljPe5VQYV98E6+giyO+ZSgnILcljdpnscsRncrMX9PHwNbAshHDC3/1AVwiE/des0
         C9a9mxxKcvJq8SUM1fve4WbM21SESmpCLeaYAP4mT0iRID6fbz4QrfEw4AyThRNNMJmz
         4S5JkhvXCRywIIPuWAUJXjKOIYI+ZOBwVSQDpMzsErrpebN6Ttgfm18aTB0xUZnuuHBY
         UnC8wmvHV8ErxmGdKt9MYPUk8GXb9Tn9KRj+PqlOREf81ZsFDbLhMsfLkYL4S/9MS2kz
         WNRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=Yves5vPe;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.17.20 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.17.20])
        by gmr-mx.google.com with ESMTPS id z12si163514lfd.12.2021.11.10.19.55.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Nov 2021 19:55:40 -0800 (PST)
Received-SPF: pass (google.com: domain of efault@gmx.de designates 212.227.17.20 as permitted sender) client-ip=212.227.17.20;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from homer.fritz.box ([212.114.172.107]) by mail.gmx.net (mrgmx104
 [212.227.17.168]) with ESMTPSA (Nemesis) id 1MuUjC-1mTu4a2aTy-00rXfd; Thu, 11
 Nov 2021 04:55:34 +0100
Message-ID: <952135b1fcfdabe40c2cfaf2ef0a5b90ede418fe.camel@gmx.de>
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
Date: Thu, 11 Nov 2021 04:55:30 +0100
In-Reply-To: <a7febd8825a2ab99bd1999664c6d4aa618b49442.camel@gmx.de>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
	 <20211110202448.4054153-3-valentin.schneider@arm.com>
	 <a7c704c2ae77e430d7f0657c5db664f877263830.camel@gmx.de>
	 <803a905890530ea1b86db6ac45bd1fd940cf0ac3.camel@gmx.de>
	 <a7febd8825a2ab99bd1999664c6d4aa618b49442.camel@gmx.de>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.42.0
MIME-Version: 1.0
X-Provags-ID: V03:K1:qqcgSnijT7Gw/VNX30SqkB8YdoGSCJKiue2bRmosehBHInhIZuM
 6DZWOjxgWyIEvIeL7Gc976oonmjoY3HIceHHbwHi72bdnd2Gy+AWDEjKmA0WKHQ0CELOyD3
 xLnU0oKxZOds2XaKZjWN/+cAkATrBuJlSJHbhDH0nCttt8tD52gDip/JCkLGmF9g5w8sHqC
 GkJN8GHNKWsuhjUFrVHNg==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:eEWI9N1+sSQ=:MUAOZY4Ngrc5ZNOlWGZeyG
 pqP9pc6zPRXcdR6ad8Xlc+jc/mJNRz+Svfzr7MggeZQ4eDj6OQQLgRBCcikSL5USnqjUEW2m6
 CWQTp3BrwaZxxZfBpbB4N5WjczQDNDhDOq4Zhiw/d9yZmjBCFWl15FHE4Yw7tZe3OsD9XPHik
 0R3Bzs1tINPwcjUn/tYIL8ARKxF+4yYyDUwHNpwAzN4I+C4iLftcHSQmAiY3m/PcxCr0SGj/f
 v92/Cj4MYzGzv4wMgSX0gZEQ8tKREivmzKTRixKodssvflrbLcWGC6z9rkeB2lRwvE4sqQ2k6
 RGpLkQ85dvunXUzXAWY2O2cZNW2gd1M0Y+hV9g5PcQYW5XXURp2SahMbiHxRJD3SqnNLL0TP5
 AEwRNCFXr0n2ytyl7yOjHZUx5p7iAXiMycNMCmgLe/yk2sl+z24zHY/7mpJGIzQSmR5SiY7iJ
 c1eTW+cCdCN+QQbxuB2ejtjLjSlSd4/V38A0HyKe2Pihq6/hibzabFGY97qrqLkOa5j+6ytfY
 SI2/UUA63c2utNAC4Pf+6X1sLgLOQXpSGOvsD20ME9W8WHyfZXE3Gt2QxvMMyiPh9byqwCs2o
 XtRlwHqpz4UBv+r6abzjlPfrHN3RJehVLXRF1vwv61Z409xa+8BMLs5GxvQUnFaBjjNj6cMsG
 H2NDDkM6RaioEStzakCkr7XcPhIw/0eOq+KqxVKKWSeFGC5vYTodArZzCe/HgZ2ML/z8KCX4p
 LvoMc/RcpnOThvUU6MFO4bvISSXSGhop94bgbRZ30uxYIGa06Gyu1RDDux6OKMYdQdq+kM6ZR
 9ozvD36JiV5Ynq1VumV8SSjmd7hMyKeCv9GGg4gh9UAQIXTlyBcBkhcnATofgc5dZhl/fFIrG
 apDn2e0weD8Qpta82xhkPEyV3eM+8eHD1XbAKarChCaFU+FtBuLcCI9yXwDtsqR2PqXJkchLX
 nkz07bbCfKZGvPGTOpE8Pr7jrXB1lMYEv+rXjI5E+y632R7B5CHDLfZqz4Jxhnsjzf/9+8UX9
 2tpkU4324OelND7dC7BLMQWSLkGV7RU7pLqYHUvmE0L1uK4cVtn5zg+6Qa/dDVyfhCiVF306W
 rVFnq0DtdWAPmE=
X-Original-Sender: efault@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b=Yves5vPe;       spf=pass
 (google.com: domain of efault@gmx.de designates 212.227.17.20 as permitted
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

On Thu, 2021-11-11 at 04:47 +0100, Mike Galbraith wrote:
>
> So I suppose the powerpc spot should remain CONFIG_PREEMPT and become
> CONFIG_PREEMPTION when the RT change gets merged, because that spot is
> about full preemptibility, not a distinct preemption model.

KCSAN needs a little help to be usable by RT, but ditto that spot.

	-Mike

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/952135b1fcfdabe40c2cfaf2ef0a5b90ede418fe.camel%40gmx.de.
