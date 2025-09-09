Return-Path: <kasan-dev+bncBDBK55H2UQKRBH6N77CQMGQEQTPYSJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 938F2B4A560
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 10:34:41 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3e3f8616125sf2488520f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 01:34:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757406881; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZqjkcabK8fXEqyA1dqAJ7jeBlJVJILRysOiD0AXPsm5MuMYM7hy6ACwlPYSupAbopk
         h1XHu32JT9CcJyCevwzPAoPHr7yBuXyNpgLhPtATu1Xru8jhtCHuSCFxTvjmGxhsa4f0
         IQqS0ec7wD6ZLkO/xwYSWHjesP+mqcVzYc9HX17wmQxvyL8cQcxAiRk05YxGsHlSu7kk
         5KYGCl0Zr32ZxLMatLzfEV7tsjiS/NgxvCgul0Ozi79VLta5+jJZt+C5OQ6HTvVg0W1b
         bM6TmDTOWiVF/vsvsB/3MlnI0TQiE9DsgUdFRY/es6L3vaKYmrRiyK64NYeLyTcwEA/u
         ++hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=55OUyL1RaJwPbLre0ss21gZCreUniPCQS/S8nGdeYP8=;
        fh=SljlPjELQgjXTXUFcoaQlxrqhJyQ7kUQUCFKx5AOBnk=;
        b=LZniucR+c4uUxH37ILeE3sM3bxeNHpaY8Nx1B+YBiUJ+PwtVCKVyuJ0KCORFJyHWcB
         27i0ZKAEdAy3e3uh9XwbXbf/JEMAgX/1dj55aoUVNHseTxqS90WcjRmuO0Z38ercRUOR
         lzR7/02TqxeOyD48A8l9s8Z497BmoezoXkrZFsN0obYBHFtNPUya/FBwYuKO90IX8Fnx
         gS0H1uHAXE5PL4MH4aHZ4Nb63HprvwJXI476vrYZrif+5I2sJlPyn58VjKZOiVT+zhga
         Kr49OgrExLOaK3I6xZTO3HOZVkUAFrIFY60LYTSmF9pqAwr7HOtogjVk4pDZjyUjaTQ1
         Z8Uw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=AkETeRDs;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757406881; x=1758011681; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=55OUyL1RaJwPbLre0ss21gZCreUniPCQS/S8nGdeYP8=;
        b=KnMtgDOlrEjUAQbgtAp685zGlH+YkbiRQUbrtYBcrMr60xsjETq2KD8SM/+De8kjRs
         pQj2TrOHNmLZWJTCtPHkSwYNHu+dfaLO3vbLN5ijbDuezCrUdv2Fi3XXwQoJJPBLwLJt
         /pAggGvwJ4iVuj8KxrqvHRHhiYhgsmCJOEpnvb1X+DcYzhW4dzVcNaLKYZvlsXkL/P9N
         +UvAE2kBOA+rokFbB3nN+0qF6rH9LpPW1z8PGUAJajdRjVdBL+2eSJPqbN28hUWJopPs
         51DPv0dAWC3GngJQuilf+4QAULSX7PQxlGer+Fxov4GN3SnOz1Nm74qobAoWHHrMEfA6
         KwZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757406881; x=1758011681;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=55OUyL1RaJwPbLre0ss21gZCreUniPCQS/S8nGdeYP8=;
        b=EV4jqcPZH2fAT6YsswkV1wJtHuKnm0hUPGeIKw2B9ZqCY5/9b3dtu0FLr0JFaSBZMm
         7rHxcPqwePPIAaiGaXlrzpFkV66FyxFMNVbPq0wQOFyDKr9Vwm89texdq7k/0B4Eropt
         /S3ZwUTMkTkVPkwqEo8hUndXZ2Iu6O4TzjlW5PVXPd4zfMJHYrvQe0BplPtaeOcDbGiZ
         E0VN+ok5mrR6pw8IUtm6d+WZ0KQx+Hr417Vm9SJV9AkbwUpHfxQ4HVATK33FWM3KYJHa
         gKdhG3Zssc5xzPpgN8RYySivogR4USpfj3ZOCr4wvCSS5P7A1e14o268iVlWcs3hAJJM
         l9xg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXwgHdtzTe24Tnapqd4jcXTShs9pjfnPsQ5j3baSqYqC4CMR75jg42mHNVHqcln2hN1rjTsWA==@lfdr.de
X-Gm-Message-State: AOJu0YxCF9P4R7mxhlFP0vGMp5NDzYC6sbY3jIRKANdrK52SC6PflUeZ
	sBMgUdp9u6Kh8cnUSdf9RVe3VmtD8DvQo/vP1uL1REtp/4Uq9o1JYhOD
X-Google-Smtp-Source: AGHT+IGYa1nk9Z/exHIW8pyVC1ykoqEW/06Bk3WVId/CnwP+hcYhOmqL+gl2Xg9/3g/W/1kCyf44Hg==
X-Received: by 2002:a05:6000:40cc:b0:3e0:63dc:914f with SMTP id ffacd0b85a97d-3e2ffd7fc12mr13530768f8f.5.1757406880567;
        Tue, 09 Sep 2025 01:34:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6NGfZbL55ZG+euENV0KUXWhLyZjANZaypoahDz3M/iyw==
Received: by 2002:adf:a407:0:b0:3cd:ba6b:8407 with SMTP id ffacd0b85a97d-3e0b802f614ls564473f8f.0.-pod-prod-00-eu-canary;
 Tue, 09 Sep 2025 01:34:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHI+FYS4IlpET50Z7awt4MgzfmGCI6Xx6NHy+FrYyv4o8agw0mowedl6V0aRusQi+jmqHeeQe7+dM=@googlegroups.com
X-Received: by 2002:a05:6000:26cd:b0:3c6:c737:d39f with SMTP id ffacd0b85a97d-3e627a7c648mr10824572f8f.3.1757406877451;
        Tue, 09 Sep 2025 01:34:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757406877; cv=none;
        d=google.com; s=arc-20240605;
        b=QZmb5abxqwNFb7FJqlMzRyhGhv772+hoEdqaoGEjQFZY/JG9LTEJO4pjwbCAOdhiv2
         e63eoyMxCGhOZvdGXxpe7DxTw4z7r8yiBFsR4s3BwYIvzSJuNiMz/FrmXJhGUSRJXj1Y
         cjMdV1cneWhOTFTZ+EFevt5RnxUhdRn2Vy5xWxHev4lXkzyIiyJvcDf0EQAN+A2bu52G
         lb7g/Mq91u4+DLUs7EuNGyUrwqEFon9EKzMw8FoIMhWtlSzgCdY6x43jA3i7+xZtTnPK
         aeuIbgsqTdWnL3EegODarkHAhWRVeSvFogVrGV0d5LHhhWoJfdDw3L73WD//Lx2Wrvhk
         ZnZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=tUi9+YGmuLz8MduOv6pUfelR4HtcHzXR6NiGUZMk3E0=;
        fh=6o9exbjceqOafs/JqE/dn63d3bNVOIy3yYCOlKb10pY=;
        b=Fp8Z1gfmoJtDwVvDqblzfVBH2ADK/M/oLAGY3k6ISndou0u6t4BPfnmfjKSfZ4f/ZP
         9riAVw/9q4RKsN4dXVp1NSLvqFVRs6MEh7Le/s1MY0aLiwSSzawezYE4NropgdE0HtgN
         9P0pmfS2GfKipm2HC6EyOKteZzrd4pvCTYvtaiIhoijuSfirtG2FQu3vPsYzefXHO+4g
         AemWI2b+9KR3vNQSJeYMbojsgPRtIZzf28rt9qqScvGepZ6I4kK44VkHdo8t+PWG/9Gx
         OOd/yrVd94c0OV783eWhe0DElJG469+3e2KyX3cfL/cJuhBkCdk6kyw9o+SpMiqH1Qeb
         VbEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=AkETeRDs;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3e75233b260si15822f8f.3.2025.09.09.01.34.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 01:34:37 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uvto3-00000005FzH-2299;
	Tue, 09 Sep 2025 08:34:27 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id D2142300579; Tue, 09 Sep 2025 10:34:25 +0200 (CEST)
Date: Tue, 9 Sep 2025 10:34:25 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, sohil.mehta@intel.com,
	baohua@kernel.org, david@redhat.com, kbingham@kernel.org,
	weixugc@google.com, Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com,
	trintaeoitogc@gmail.com, axelrasmussen@google.com,
	yuanchu@google.com, joey.gouly@arm.com, samitolvanen@google.com,
	joel.granados@kernel.org, graf@amazon.com,
	vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org,
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com,
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz,
	kaleshsingh@google.com, justinstitt@google.com,
	catalin.marinas@arm.com, alexander.shishkin@linux.intel.com,
	samuel.holland@sifive.com, dave.hansen@linux.intel.com,
	corbet@lwn.net, xin@zytor.com, dvyukov@google.com,
	tglx@linutronix.de, scott@os.amperecomputing.com,
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org,
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com,
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org,
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com,
	mhocko@suse.com, ada.coupriediaz@arm.com, hpa@zytor.com,
	leitao@debian.org, wangkefeng.wang@huawei.com, surenb@google.com,
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com,
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org,
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com,
	rppt@kernel.org, pcc@google.com, jan.kiszka@siemens.com,
	nicolas.schier@linux.dev, will@kernel.org, jhubbard@nvidia.com,
	bp@alien8.de, x86@kernel.org, linux-doc@vger.kernel.org,
	linux-mm@kvack.org, llvm@lists.linux.dev,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v5 13/19] kasan: x86: Handle int3 for inline KASAN reports
Message-ID: <20250909083425.GH4067720@noisy.programming.kicks-ass.net>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <36c0e5e9d875addc42a73168b8090144c327ec9f.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcMV0BOJyvx2nciCK2jvht-Hx0HnFtRzcc=zu+pQSOdVw@mail.gmail.com>
 <couuy2aawztipvnlmaloadkbceewcekur5qbtzktr7ovneduvf@l47rxycy65aa>
 <hw7xa2ooqeyjo5ypc5jluuyjlgyzimxtylj5sh6igyffsxtyaf@qajqp37h6v2n>
 <epbqhjyfdt3daudp2wx54jsw6d7jf6ifbr3yknlfuqptz7b4uq@73n5k6b2jrrl>
 <CA+fCnZdJckDC4AKYxLS1MLBXir4wWqNddrD0o+mY4MXt0CYhcQ@mail.gmail.com>
 <ra5s3u5ha6mveijzwkoe2437ged5k5kacs5nqvkf4o7c2lcfzd@fishogqlatjb>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <ra5s3u5ha6mveijzwkoe2437ged5k5kacs5nqvkf4o7c2lcfzd@fishogqlatjb>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=AkETeRDs;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Sep 09, 2025 at 10:24:22AM +0200, Maciej Wieczor-Retman wrote:
> On 2025-09-08 at 22:19:05 +0200, Andrey Konovalov wrote:
> >On Mon, Sep 8, 2025 at 3:09=E2=80=AFPM Maciej Wieczor-Retman
> ><maciej.wieczor-retman@intel.com> wrote:
> >>
> >> >>I recall there were some corner cases where this code path got calle=
d in outline
> >> >>mode, didn't have a mismatch but still died due to the die() below. =
But I'll
> >> >>recheck and either apply what you wrote above or get add a better ex=
planation
> >> >>to the patch message.
> >> >
> >> >Okay, so the int3_selftest_ip() is causing a problem in outline mode.
> >> >
> >> >I tried disabling kasan with kasan_disable_current() but thinking of =
it now it
> >> >won't work because int3 handler will still be called and die() will h=
appen.
> >>
> >> Sorry, I meant to write that kasan_disable_current() works together wi=
th
> >> if(!kasan_report()). Because without checking kasan_report()' return
> >> value, if kasan is disabled through kasan_disable_current() it will ha=
ve no
> >> effect in both inline mode, and if int3 is called in outline mode - th=
e
> >> kasan_inline_handler will lead to die().
> >
> >So do I understand correctly, that we have no way to distinguish
> >whether the int3 was inserted by the KASAN instrumentation or natively
> >called (like in int3_selftest_ip())?
> >
> >If so, I think that we need to fix/change the compiler first so that
> >we can distinguish these cases. And only then introduce
> >kasan_inline_handler(). (Without kasan_inline_handler(), the outline
> >instrumentation would then just work, right?)
> >
> >If we can distinguish them, then we should only call
> >kasan_inline_handler() for the KASAN-inserted int3's. This is what we
> >do on arm64 (via brk and KASAN_BRK_IMM). And then int3_selftest_ip()
> >should not be affected.
>=20
> Looking at it again I suppose LLVM does pass a number along metadata to t=
he
> int3. I didn't notice because no other function checks anything in the x8=
6 int3
> handler, compared to how it's done on arm64 with brk.
>=20
> So right, thanks, after fixing it up it shouldn't affect the int3_selftes=
t_ip().

Seriously guys, stop using int3 for this. UBSAN uses UD1, why the heck
would KASAN not do the same?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250909083425.GH4067720%40noisy.programming.kicks-ass.net.
