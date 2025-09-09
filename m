Return-Path: <kasan-dev+bncBDBK55H2UQKRBDG377CQMGQE5CIUOLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id BB4C0B4A673
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 11:04:13 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-337ec9ab203sf21553141fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 02:04:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757408653; cv=pass;
        d=google.com; s=arc-20240605;
        b=AVE+sTyfSynmmggSbNmwPbRj9xj3rb+IIa56MEbHblZbJyQaYABV3ec8QTzF6G9uIe
         vt4CeOu5xoNopSfHjBSWT+vFRGsO3qCFQYPzmmBzkZRFLsUj3d7JDcrBceeMb4J1Phdm
         l01d96BEB1XRssKgAsBNfVDPw2wY0jtZNSPOagxXvXYHIqhayAepr+QgkOszJ8kiUZ5i
         GhSrpw7DUZT6o1H7GANTeqe49+y2o7pCO/dVqNQ8/XzU5J/YGyNGiDdPKuuFcTW1LebM
         jEUlW3qDtlsCYq6ZeHtOO2k5QVk+HlkUjdOU15GEYvZ/FdLxPLUK54ESyiqxeM7m5akf
         rlxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=AfJjdUxbatXhoFYcHyQn4FVBVQsyA7h4AATuUnkmqYI=;
        fh=zEIiywUX7LV1oSaVEiOvCdrdJcXsZPD5U3LA1Jmp07c=;
        b=LswNbJoFaLmDxgmEoJZRmseLuQ0honxChkzTzlmrMAkJrYLiCd2EUgKSjcg9QUaxbi
         WRWZLbUkkWcsvXe/9mULPcKp7YdxNqG9IQLzPJa3JWpTkBxXFACDUCvWdP4i39DmlgDP
         MGriQVqCLSbuafLfgLg5Zy/79T0hKT1pQSQUuZ+dON9hJpawWh8SxhGaIkgtyRTOieAA
         aOMx5ANzdpsRh1bDzqFR/U7GFdRA1h1tg9jd8Mi2gFnq1D8cMyFwJPHdZA/5BzZ3h109
         71A0d/Kei+eqlVVt6MBJkUXPaeHkndmZtWWh3Iu7wGUa3sGo3sAXanMrYl9n6sT/Aa7c
         qs0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=FEfgeDR9;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757408653; x=1758013453; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AfJjdUxbatXhoFYcHyQn4FVBVQsyA7h4AATuUnkmqYI=;
        b=vFjkEC9exHU3HLxn3GoV51Bu/fgnnl952RXEnqC8TGQ8CjuyUhJDVVFWEhhsceUlll
         H7hg1cuPRDUK0hFLrsis/KN91oIhB5KFbd60enTULN+YBCn02/DP3MvbzqoGs+a1O7pT
         7og1ynzS64bU5X60LDHRymT5qhYWDvA3Fhq3naW067SAjHwoyLG4EP9WtfOxi/VPdhjR
         IhwFKIOe54Lk1x9oZHQqbvnvdXBRT33T5EuwqTLpm5+Oa4HjNPHaelKJO+zyqgXHKLnA
         Z0hNk5M+CBEO/DnSS9cPDuZ/ueweUh27kWHPjdBlcm9gI1PZJqk6UIIPfFl7+BnfWXbf
         XgCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757408653; x=1758013453;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AfJjdUxbatXhoFYcHyQn4FVBVQsyA7h4AATuUnkmqYI=;
        b=HhpTC0JfeHbR1LKxI0Iy8R7kteebf4fbuQoSsuJ8YNxP+/Wl16YU+9LDZQChCFmBRN
         RGA5oGjHV00PQOwHODuB/5SN4OgpjXT7fSwsX5RRDJFiQYt7abASLnljGQZJkxMZDMDW
         ikBXxKQVGyA4ug4vomxijOPIAvOPhy7r+a3jAR8jZivKI3k1JFSFiHJDC3bD3iBKClzJ
         AysazmLz4xHbeSqkSHWPqCbBNGugT4JJ1cyW4XeUjWhuqSuq1vtuZG2EG4z2L9i9cM4Y
         /y2K06JBup4Zc0V3MO7939X/kHpSWBse/aAeNSHPgbgdinfDKhwAzKtew+Xo7/8xWkNp
         V88w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXyzvlya8oNVzBv0Ne1JZtCWtrMW3cqKZNxsr1tXsAVwhn/jWWPcBPke95q63NprWoL6pND1w==@lfdr.de
X-Gm-Message-State: AOJu0Yz/ZUh8eqVxNiOz/Ej4hpv1N5LNkhIsCi9ZSlLzNp9RsH2qnrc7
	INek3nRr4YQB67M5uLWTPGZEAGlsN9bReHJqHgFj8pygz/SAuxVIZOxm
X-Google-Smtp-Source: AGHT+IE5Ttm39346CesQrBMgSDMsYWrn071UE0JrOsG0hHQoNGvfyhO2+Cf5y2mbAYbIShiXxOqXiQ==
X-Received: by 2002:a05:651c:19a3:b0:336:8228:29f7 with SMTP id 38308e7fff4ca-33b5cfd1cfcmr39312721fa.27.1757408652625;
        Tue, 09 Sep 2025 02:04:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcxHGJbkLcP8rGot8Qdu+xAREOrcBFCTAOWENnxCfj3sg==
Received: by 2002:a05:651c:20c7:b0:332:2a32:2846 with SMTP id
 38308e7fff4ca-338ccf15627ls5191991fa.0.-pod-prod-02-eu; Tue, 09 Sep 2025
 02:04:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWJ0emX6LxU/FgHLCzxLQ7LvUa5pE/9fUXlTw1j21Ty+mXkKkQT9V8iKBbt3kg8T+KWHLbhUpgjV3g=@googlegroups.com
X-Received: by 2002:a2e:a54c:0:b0:336:6c83:f0ff with SMTP id 38308e7fff4ca-33b5e421094mr27876301fa.34.1757408649009;
        Tue, 09 Sep 2025 02:04:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757408649; cv=none;
        d=google.com; s=arc-20240605;
        b=dI19bF5Uegk39S1hBsRnl9P+MYWjpRz57I6wDmya9uTaUYrQmUBdSR+t0QaDFhAA1O
         K5NVTom05KM6uK8F6RcZHsxw5x9QBNSrHii2c+QE/SmOTUd4IwXtXmC5fDb7HktXDLkw
         RsfEQy/N1d7IKNf+JDJipMy7TJE0bNfar7bpCGUQRYrMPRVb06/xGeMAaafBD734llbz
         0OXEWGeTFJouTMZysgnKVxrjO1rTG68kfmUbSGbj4rd3UiekCSVd1lLrCKQMFjtSWKmn
         MfO2U+H0IEeSCp7GXN7XTvjUbsUEgNqUajisEvWI8yvcaRXsZeIZngArk245tiJA+rlg
         OsVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=NpXa+vu5fBKULSWcWQHqLrFFROyEpt4qyTDAIt4nodE=;
        fh=6o9exbjceqOafs/JqE/dn63d3bNVOIy3yYCOlKb10pY=;
        b=lIxT5BDsDaFhS1WD2geU6ssaqimaomgm8XJsI7RurIAYY5R56lFI6e3g2ryq5/YpJc
         9DQjHPfMcKPuP78oUJBlZ7lBV/+gbDBPT6+3DVVihhsC1RlaqgFyk73ZgXt09fuuPISL
         ARe7Ac2KV349h6WXaMh0gFQHT9JNEx3eeqqV8hM8uZEwCNIGRNTXGLIWBdG+/03eR/Zu
         YXZBeA/PhekCCikDC4HYpjmbFetNRGUxo0X/oUEYBZUz5YUB2GxrYgCIv154SHRiOLyZ
         Kv11CBeo4kJKoSf2wB1nDNX7CO4hcCvSXcJU6YlznwSA2Q5EDiRHmhy7jFwDZOKGM4/P
         R1jg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=FEfgeDR9;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-56807035b15si25228e87.1.2025.09.09.02.04.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 02:04:08 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uvuGc-00000005GfE-0h0I;
	Tue, 09 Sep 2025 09:03:58 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id A7C8F300399; Tue, 09 Sep 2025 11:03:57 +0200 (CEST)
Date: Tue, 9 Sep 2025 11:03:57 +0200
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
Message-ID: <20250909090357.GJ4067720@noisy.programming.kicks-ass.net>
References: <36c0e5e9d875addc42a73168b8090144c327ec9f.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcMV0BOJyvx2nciCK2jvht-Hx0HnFtRzcc=zu+pQSOdVw@mail.gmail.com>
 <couuy2aawztipvnlmaloadkbceewcekur5qbtzktr7ovneduvf@l47rxycy65aa>
 <hw7xa2ooqeyjo5ypc5jluuyjlgyzimxtylj5sh6igyffsxtyaf@qajqp37h6v2n>
 <epbqhjyfdt3daudp2wx54jsw6d7jf6ifbr3yknlfuqptz7b4uq@73n5k6b2jrrl>
 <CA+fCnZdJckDC4AKYxLS1MLBXir4wWqNddrD0o+mY4MXt0CYhcQ@mail.gmail.com>
 <ra5s3u5ha6mveijzwkoe2437ged5k5kacs5nqvkf4o7c2lcfzd@fishogqlatjb>
 <20250909083425.GH4067720@noisy.programming.kicks-ass.net>
 <20250909084029.GI4067720@noisy.programming.kicks-ass.net>
 <xeedvhlav5rwra4pirinqcgqynth2zrixv7aknlsh2rz7lkppq@kubknviwhpfp>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <xeedvhlav5rwra4pirinqcgqynth2zrixv7aknlsh2rz7lkppq@kubknviwhpfp>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=FEfgeDR9;
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

On Tue, Sep 09, 2025 at 10:49:53AM +0200, Maciej Wieczor-Retman wrote:

> >Specifically, look at arch/x86/kernel/traps.h:decode_bug(), UBSan uses
> >UD1 /0, I would suggest KASAN to use UD1 /1.
> 
> Okay, that sounds great, I'll change it in this patchset and write the LLVM
> patch later.

Thanks! Also note how UBSAN encodes an immediate in the UD1 instruction.
You can use that same to pass through your meta-data thing.

MOD=1 gives you a single byte immediate, and MOD=2 gives you 4 bytes,
eg:

  0f b9 49 xx -- ud1 xx(%rcx), %rcx

When poking at LLVM, try and convince the thing to not emit that
'operand address size prefix' byte like UBSAN does, that's just a waste
of bytes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250909090357.GJ4067720%40noisy.programming.kicks-ass.net.
