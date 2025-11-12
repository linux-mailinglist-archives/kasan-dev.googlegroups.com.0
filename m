Return-Path: <kasan-dev+bncBD53XBUFWQDBBC63Z7EAMGQERHRPEEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id E2B76C50507
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Nov 2025 03:14:36 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4e8984d8833sf19249551cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 18:14:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762913675; cv=pass;
        d=google.com; s=arc-20240605;
        b=AjXfb4DORcpF+oYAA2BpkxNROvmPiMNDUYGyvvdm6tcw3wylWjB1hCoZ8VrHojbqvX
         rLZ6Fk3BM6n+HspHs23eTZ4a9oAz/3Fk0/VuiQ7kZgugOm1KDUobMCpoLx8Ph+GDk+hY
         CfPU8VX/wfgU6FMcq1pftY9GuS70EK51ijmieL0K74MEZzpdlSDZZLE9tPwsWwlq4P77
         G/XojRdlBtORvXpz79oMJD9iwo7bBV7bmVSiFOGTyDkrF/REXIA0cOzP6ywRjzAk5e1P
         Jkn3hLtez5RW0KHxM295ZUgmpYwfb/j9dZVW+OI+eyEJoQt1n63wfmGhW3yrTrRXCsB/
         iv6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=HU7fDGLc4YotYEXUitPkvRyvk5+VEVXvOCaE1BxbN28=;
        fh=drnkxLjsAYvuQ0hdFpbMugcau3qXou6XrpWStGlot0U=;
        b=kyTYaomYrLSixD0CpenHsw1STu4VKg5d4fHtu3Pl64KyKMK9EKOeYqjUozCqkLKq3x
         hB1i9RskHryGnAzmkLxyXhJfhso3S9IlXMB0O5W7BEco8uUcucpF4Ml0MCzUVhrBcfId
         1TEcUEMXIcOMt4fk0UPF6878bfJ8gU27qO3nZ41YhhDbVFhArNkmobYArqL/c8UU4V7k
         22GhlAHsKx7MOpMLhzOtG4yTzQUlYGq+4dHvg5ds6ohucEf6B27X6bu/dtJase87g3wv
         LJGxYcZjRy5I273eDpEjkgXHgqAmpVosAAsGziPp09m9zsIQD0H0p6rMXHUotKCaBOyE
         yrmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZuHunIKC;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762913675; x=1763518475; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HU7fDGLc4YotYEXUitPkvRyvk5+VEVXvOCaE1BxbN28=;
        b=MuJhRxsPkYzT3zqqIEakTSHfBBzrfR2D/TRggTJ/QpajVIr2S/WCgQkHHn3M99QaRp
         mM4n8huozOJtDoZZUiXTfx+QGZpghIl/KqqyxuwD941nrbUeBfwOP37Cn80nx/2tOSSZ
         9oJ3oRUk0ThYHAPGqZrePePCkTTS/6rGmJcGcI99rhdwMuFeGKR/xf/vb/pM0B5N+ei6
         ftyWNGrhcnt5uKnkxPQ965v2Hx9vRrmxgbkzStLEhLB5yjNESA11reCiqw018JGClbsO
         OvQZ9C8e6tc8x5TRfo5vyqk1vFqvvP1rmtbUzIJEYXICCaliieVO69rCYtpulVu9OdRB
         a7bQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762913675; x=1763518475; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=HU7fDGLc4YotYEXUitPkvRyvk5+VEVXvOCaE1BxbN28=;
        b=aJ3/AVb2hQAglRQ6caap4I2bz/56pLj3Ao5EVKcD6xlVLV0SgP38pEL1YMsc9wZGJN
         hskiKtBXmO/OyxKjIme7yS6938ww13fWOWsjg4OGPNHatF2pHlwx/hocGchaLJZ6GK3y
         FlGZRq0bSLy2XtuY0vDNB4ZU1CYEoRUTbncGSDcTVZY8sbyGovwuClo0q+p8UvPgdSSR
         dFlSmSBimH8cCCmynXLJbJXaYpQHm9+Vl6cEvzW0R3nhCggXuuvTlJ79WOGe6TYSABgj
         sqEf8DuwVF4rUBFrA6ATRMDtpcNoeXOc/aDsqti6B7ExMgfcKNeV+c+L1xgN5GamlV+X
         In3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762913675; x=1763518475;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HU7fDGLc4YotYEXUitPkvRyvk5+VEVXvOCaE1BxbN28=;
        b=KaKfvDqXOQ3fB1fCEMDoyd2OdMDxfbf04Llx4Qrul2q2F/L1emvY7iw+Jrm7OAlIOU
         3L2f5J1HM/ff+o+Lu9Wj7/hKp7ARb6OWtG+ubrocbTqHecNhTb0fcVJoo59UFeelOICj
         q7N10bZdgkS+Gw91lIDOfL9PX+aecrSa53duP52Qnewn27Rm9iwU2kH0/rEbMA8QNT/J
         425H3uiI5vie87jmsRRrfwHQ/MLbad/N20OAzc/Wxf3GUXwXRF9xKpXlSsKYrylJg6Xb
         Kuaw1zXin2tu5fknSjs8DhAS7dmTJIjVRhYUHnAFw1U933wx8g1l4vJ48a1IHo4DHaMT
         MJlA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmFqbw2p91IwBDF075dQgwaimhjXei2tdht8y2aFTQasstmeUK9AX61eDr0t1l0P8hIz0tkA==@lfdr.de
X-Gm-Message-State: AOJu0YweYy/gmVbhiT++k/ZR0uZlF5j3F/3WTKS7u37TmgclpFXri8E2
	aMxTYIkAxDGGHvDigMo/o7/83LTYoLlRqxIBb0ikOY0t/2ooX9vJOVac
X-Google-Smtp-Source: AGHT+IHaLSEDgHKd+en6KeNJetrumUb3cScDOir5NFn9fHrMh7VYcact2X0exgke4eHkRmMKst5xow==
X-Received: by 2002:a05:622a:1450:b0:4ed:d76f:a350 with SMTP id d75a77b69052e-4eddbdd8d66mr20359651cf.75.1762913675509;
        Tue, 11 Nov 2025 18:14:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ai7IlyyiiN3wyQn7y98dfKkILinV5c1oA64/OcprHtxg=="
Received: by 2002:a05:6214:19cc:b0:882:7510:5ec3 with SMTP id
 6a1803df08f44-88275106359ls1618016d6.2.-pod-prod-04-us; Tue, 11 Nov 2025
 18:14:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV5mEJOGxNwtAMQpDDu63fovyrve3YfWdCPwthq7keq3y6PKhABxPZwEYbZ1TYTuY8cvRO73ld7dhw=@googlegroups.com
X-Received: by 2002:a05:620a:700b:b0:8ab:91ad:b21d with SMTP id af79cd13be357-8b29b765fdbmr238465485a.5.1762913674725;
        Tue, 11 Nov 2025 18:14:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762913674; cv=none;
        d=google.com; s=arc-20240605;
        b=OUpb3wJPiVwLzt7LjRJ5eqBNHq+EShTjSfhSwzTLrZ0CIOBNo4d2Idz/RtmCOLRpoj
         s/i3sHuakCjq2aTUJARs33qkTd/g2wkpOlmvxb+eREjK6gQMOLIs+6tuuZOs4uf8xs2k
         xP+vKI6cOLHZGqmKkjCBWf8iGX7abxO0UPoeIbafro8a6IkHwaBJNR7PwyNOtfGFU2U0
         cfwyCZsNNzpni/vPrj8ERBRRsmil/EBgWJ+2vY2BsEuRnETRo/n1NaSrt08q5lRTqunh
         XjkS+2S+g9/K4sTdeUEwK3U9+oD0L9QDsCvcj5ci8wOkPUDKG6+45bjeCvOo0J+4CXIh
         P4zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=lVQBcx6xFjlJyhg8EGvnzlqkKD9tleq1IsOwgdEnnOg=;
        fh=3oFkuEKspV+8uuzB0k6fge4p8sEWlLkFP+IOcXZ9LM4=;
        b=ZeNGdJtIze+xMLeBroFNTRFR1x/bNkI3e58nIS/t0RNZvnLWWGSOa0Okf3Fc6ds/m5
         Z6WaGicCn7W6ufBKXGiMBKnK0HNTpelzfwMwf11XxJJHOzKuYmv6wwsN+HFTcI/hRDoL
         vWFW/Pr1O4DJ4SniHjuILpCOkoqYa2T0Kaj9x9QdsCHMezu77aOfuQuCUTuqvNBPukBI
         h93PqcKvYFlxprU/dybfuhSMKGiayxZ/TXRXcRAhbHgF83SjgG5LoYXO/N0TTbhGXkrW
         uQ/ItM2F9dxCQQP9kaUSpYABh6MMZa036jbo7dEBLCs3J7DBa+yo5j7Xm0DhIXFYKAdh
         8mEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZuHunIKC;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8b29a84c1b8si1323285a.1.2025.11.11.18.14.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 18:14:34 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-34381ec9197so376822a91.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 18:14:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWdHDcsGQBXShVQcxWiFAFEuzkn2+YbkYxcCiDm+1G0IiXF6oe8PhUTYXAMhPf6bt31RWGVwfJStVo=@googlegroups.com
X-Gm-Gg: ASbGnctDTuE7kJwG9PBy4wsTuW0bX3g/hXMlvsJnKrMao7MKRF48CLb/uLJYxWKTHbE
	RMZVwXgvP7UEHXtdkppXiC0H2xVwXhgJOAeQ6poLKG9KfnNpcKTJvxRruf8W12ueKOCbdBV/TP3
	hSUN7+IivuX3oMLXN1Y2rccC46arlUloU98VksiQViDkkn/5qu2dUfhmUZMG070ELD5PKhtagpF
	U/IJZmIqJASYgt2FapoKwFhYYv2A5TXGoRM27VGJo7Dp6H5ljQOKCocY86WGKkULUm3Es6w+vcf
	iMaQQ4UQbCduL9qhOKk41O/96TglubG3K/HVSM3aRGiNRoLyGc20VCm2H/hU3nNoFTJFdo1uDJa
	44DLGdAMnBKarRf/5rgdIWlzZbQWRHYWxWhdRuoK2bWIGykMSi14MAyb/+yx9xKiST5bnesWaYr
	XsAtbW6SO9mIc=
X-Received: by 2002:a17:90b:1b0c:b0:340:a5b2:c30b with SMTP id 98e67ed59e1d1-343dddf6caemr2117777a91.9.1762913673519;
        Tue, 11 Nov 2025 18:14:33 -0800 (PST)
Received: from localhost ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-343e0714267sm559591a91.6.2025.11.11.18.14.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Nov 2025 18:14:32 -0800 (PST)
Date: Wed, 12 Nov 2025 10:14:29 +0800
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Matthew Wilcox <willy@infradead.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	"Masami Hiramatsu (Google)" <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>, Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Alice Ryhl <aliceryhl@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ben Segall <bsegall@google.com>, Bill Wendling <morbo@google.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	David Kaplan <david.kaplan@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ian Rogers <irogers@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	James Clark <james.clark@linaro.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>, Jiri Olsa <jolsa@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juri Lelli <juri.lelli@redhat.com>,
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com,
	Kees Cook <kees@kernel.org>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Liang Kan <kan.liang@linux.intel.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org, llvm@lists.linux.dev,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Mel Gorman <mgorman@suse.de>, Michal Hocko <mhocko@suse.com>,
	Miguel Ojeda <ojeda@kernel.org>, Nam Cao <namcao@linutronix.de>,
	Namhyung Kim <namhyung@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Naveen N Rao <naveen@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Rong Xu <xur@google.com>, Sami Tolvanen <samitolvanen@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Thomas =?iso-8859-1?Q?Wei=DFschuh?= <thomas.weissschuh@linutronix.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>,
	workflows@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v8 00/27] mm/ksw: Introduce KStackWatch debugging tool
Message-ID: <aRLmGxKVvfl5N792@ndev>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
 <aRIh4pBs7KCDhQOp@casper.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <aRIh4pBs7KCDhQOp@casper.infradead.org>
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZuHunIKC;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

On Mon, Nov 10, 2025 at 05:33:22PM +0000, Matthew Wilcox wrote:
> On Tue, Nov 11, 2025 at 12:35:55AM +0800, Jinchao Wang wrote:
> > Earlier this year, I debugged a stack corruption panic that revealed th=
e
> > limitations of existing debugging tools. The bug persisted for 739 days
> > before being fixed (CVE-2025-22036), and my reproduction scenario
> > differed from the CVE report=E2=80=94highlighting how unpredictably the=
se bugs
> > manifest.
>=20
> Well, this demonstrates the dangers of keeping this problem siloed
> within your own exfat group.  The fix made in 1bb7ff4204b6 is wrong!
> It was fixed properly in 7375f22495e7 which lists its Fixes: as
> Linux-2.6.12-rc2, but that's simply the beginning of git history.
> It's actually been there since v2.4.6.4 where it's documented as simply:
>=20
>       - some subtle fs/buffer.c race conditions (Andrew Morton, me)
>=20
> As far as I can tell the changes made in 1bb7ff4204b6 should be
> reverted.

Thank you for the correction and the detailed history. I wasn't aware this
dated back to v2.4.6.4. I'm not part of the exfat group; I simply
encountered a bug that 1bb7ff4204b6 happened to resolve in my scenario.
The timeline actually illustrates the exact problem KStackWatch addresses:
a bug introduced in 2001, partially addressed in 2025, then properly fixed
months later. The 24-year gap suggests these silent stack corruptions are
extremely difficult to locate.

>=20
> > Initially, I enabled KASAN, but the bug did not reproduce. Reviewing th=
e
> > code in __blk_flush_plug(), I found it difficult to trace all logic
> > paths due to indirect function calls through function pointers.
>=20
> So why is the solution here not simply to fix KASAN instead of this
> giant patch series?

KASAN caught 7375f22495e7 because put_bh() accessed bh->b_count after
wait_on_buffer() of another thread returned=E2=80=94the stack was invalid.
In 1bb7ff4204b6 and my case, corruption occurred before the victim
function of another thread returned. The stack remained valid to KASAN,
so no warning triggered. This is timing-dependent, not a KASAN deficiency.

Making KASAN treat parts of active stack frame as invalid would be
complex and add significant overhead, likely worsening the reproduction
prevention issue. KASAN's overhead already prevented reproduction in my
environment.

KStackWatch takes a different approach: it watches stack frame regardless
of whether KASAN considers them valid or invalid, with much less overhead
thereby preserving reproduction scenarios.

The value proposition:
Finding where corruption occurs is the bottleneck. Once located,
subsystem experts can analyze the root cause. Without that location, even
experts are stuck.

If KStackWatch had existed earlier, this 24-year-old bug might have been
found sooner when someone hit a similar corruption. The same applies to
other stack corruption bugs.

I'd appreciate your thoughts on whether this addresses your concerns.

Best regards,
Jinchao

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
RLmGxKVvfl5N792%40ndev.
