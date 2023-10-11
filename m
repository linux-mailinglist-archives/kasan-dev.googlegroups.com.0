Return-Path: <kasan-dev+bncBD7LZ45K3ECBBSFRTGUQMGQETG5DRFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id C243E7C4CAB
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Oct 2023 10:11:54 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-5042bc93273sf5827803e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Oct 2023 01:11:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697011914; cv=pass;
        d=google.com; s=arc-20160816;
        b=MvZi/XqPN293aVhYU0OkNxgq/yr4KkgEsfhEh461CBVIJ+mfqQy9gUEfiLTYZ6OVSM
         TsrogUh/9e/k6fDOr7clyjXH6HO/7Hsfw426c5HpYMQmUE3H04t5AogH1sgMKy/7tEri
         RaknDCs7hKXBSvQCzyYhbKoTP2rY65W4bWZ63n6P3VCyUa3LB46jaMQxLIog+R+AC7nP
         6NmZxNPOnTy2GbmLcMMj61ewqRyTuM+5KYKjF7QS0ThYv4I48zjTLxxNlOCVEr8xLcij
         vFZ/t25eNynbIooGdtepjiNlifs0my+UU0O7f9Axq2hSCR1qDiHtXnW/Lw3brmOmLmgy
         GreA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vckM8CayknaH8wfSXIqvwcOrQvonczbXKaoWKOh3x94=;
        fh=zfkn1WtPT87mngJgL9p9wu8i1nQQ7xGjillBK0W061I=;
        b=IGNkkA+eSbjMwk5zdVIACJdmo/xjfC1YFZB1jDjrchksv55VeB/hzJpZXkzrlt/CF5
         kLPxtfH7TkxLEQUIWyINtkzn4XVncpBAHoJjOOgpKX1eG6ohoLMroBg2UXZtxezw2djU
         46WLF0LDRqPYVe1IsAs8GmwZJJOtMkM04WYvLpHWwlxdcZlulU0RxZdutgT4w+cy/I8I
         KnaDqSHOFSJHdjeyC3Ne9cNBOKyENP47MAJ2sP6QNbIZ1xaFyXjeR/CRZwdUKP2+gPaR
         Qy5xJyHtv7EMkTQv3VlU5hgtfjR2NEvRCR1Ft5kvabZnx3cEPUwlmn50oEO2HD6H68M4
         RnVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ge3K+Kk8;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1697011914; x=1697616714; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vckM8CayknaH8wfSXIqvwcOrQvonczbXKaoWKOh3x94=;
        b=Izf1IK5Rbd2dKj8xQxlUaZdJpz5Nzr63Q7H4/JajLdFpNH6tU/AFCukDm4pgBoseR0
         N6G0O12IXrkQ+2yz0qhpbaxF+z93cUwec4hPpEadbCKmksVpNOHA1lk/I96RGOsfGhS/
         INvsrDTWmtiR21qBVcOnuXqisSGuWfS6U17dxywDlktUKQuRsHOJWRZyn3LxG3+mA+Li
         XJlq8q2OtUyFoBPVC+4CYwO6tzIQ/lktM4iqmVBKVmNn/Z5GFNBpc3wFkp6diUp+mD/f
         rBi2gKV041SycZgST1aHvW4GHqh/Z4KSFyN2w4MXXkZrEGp1gvCNJ7iRfIOPjUgwVuch
         3W0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697011914; x=1697616714;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vckM8CayknaH8wfSXIqvwcOrQvonczbXKaoWKOh3x94=;
        b=fyhfXSsG3aIChMFpdJEJfMg9Wz7zO1wPaiZxKYQJ5floioOAt91P3mBEOfWK9sIh7O
         U7vZgOdk9NCRLm6gKI+0woN4CupXifxyZnct+f6eUTddKGEbHqbQK/2JLaA5bjhvML0M
         T+sLnLlAGTRtSiQEoJ9JBxn3QHhVUmlNBcetju8LqpDNhvPxptPKxeaheve7o/RFYOy4
         ZW17EXASQXUcoB6RiA7b5x/YBmWk0C7MdJnnjibGsj2YszGPA7Zkvbwe83JYQ3PAFc6d
         DjoRnS6DYn6Oc8CzwKMGXH9KlPRj95UunjPA4bXmUHHuFemstfV4JLIBk1yTPgWJqScy
         3mrw==
X-Gm-Message-State: AOJu0YzDOTIYTnaI3DTXzBPNDH+8PJs6CfSSCx+psKTGSEBz+20273En
	i2KBKLhnrnaBJgD/87osx6/FBg==
X-Google-Smtp-Source: AGHT+IHzLMZHCrAz6b3fJPbXVBltrRZGT1mdJ7+BlotOPhSXOJAUJ2CTNgNql1/Zl1RuKQXI9JnNFg==
X-Received: by 2002:ac2:5f64:0:b0:4fb:7c40:9f97 with SMTP id c4-20020ac25f64000000b004fb7c409f97mr15805265lfc.27.1697011913012;
        Wed, 11 Oct 2023 01:11:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5129:b0:406:6068:9f06 with SMTP id
 o41-20020a05600c512900b0040660689f06ls49609wms.0.-pod-prod-08-eu; Wed, 11 Oct
 2023 01:11:50 -0700 (PDT)
X-Received: by 2002:a05:600c:1907:b0:406:84b2:67f with SMTP id j7-20020a05600c190700b0040684b2067fmr17047026wmq.20.1697011910863;
        Wed, 11 Oct 2023 01:11:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697011910; cv=none;
        d=google.com; s=arc-20160816;
        b=V0JdSCd88gOI4bLYiQJi5xsFbosOuHTxsyksZXYCrcV6vQ6IqVvR12XSo04zfTxHMH
         fB7i58qRDyPr6+IM37KMS2unPSgkSK/rrS83JR4QWHqyIUiE87Zmu4KgVT7ADeLa6wa0
         CeA1SDvi2e7a38q6v1SXFdu9/f+TaA2ono4r/P3qmsaJTlsLrkVE6Ub7wCA46upm/ldq
         UhrIFZRvrqJm7iPbUvA7WJWpwv0mDvwfwXTADv9Sl8fMn257QNjAI5xUZpdnEc82fpsj
         aOTKlQKBHoKcTsAXm4/xP99RPbk2jC0SA03KG9pL5pvchSvaVOcVanUISucHDe8WPPaf
         CCRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=SGMCBTNusP70u42LHRRik7B8Z00QtRCIGDUylj6XYAw=;
        fh=zfkn1WtPT87mngJgL9p9wu8i1nQQ7xGjillBK0W061I=;
        b=GCqX6j1yjnOeWb29Kz4KhXW7fSezpcv2lF2pHskHv6ljegKucyClgsnp0K0LVX7GkX
         QQ0QGNiPbbKyzspu1VAoMbkKPlpJIZL2/dSkO3Bnx5Y6sKkh6O41AocTlyXe/Qb+bwwZ
         oUg7a6LNk6/usXa0KC+SgTJeDLn4Ms5fkxVq1EDELvmuVfOAK2NBzffKJsJhT7RnOM/B
         QFDQE6qfBYjz/moHPfwv8VIIgIquhOUcewQAbYw3FORKspAUdB5o/W4FXMNHZEEbAfO5
         v4aQFBMRYzZ/iB41tqsQNqQgAYItA0oGQqQVWIR1C36dSlRefGSSolCXW0UfzD6j9Sgw
         FhXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ge3K+Kk8;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id j35-20020a05600c1c2300b003fe1f9a8405si38002wms.0.2023.10.11.01.11.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Oct 2023 01:11:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id 4fb4d7f45d1cf-53de0d1dc46so397551a12.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Oct 2023 01:11:50 -0700 (PDT)
X-Received: by 2002:a17:906:3050:b0:9ad:df85:97ae with SMTP id d16-20020a170906305000b009addf8597aemr16960697ejd.66.1697011910095;
        Wed, 11 Oct 2023 01:11:50 -0700 (PDT)
Received: from gmail.com (1F2EF405.nat.pool.telekom.hu. [31.46.244.5])
        by smtp.gmail.com with ESMTPSA id la18-20020a170906ad9200b0099cd008c1a4sm9501500ejb.136.2023.10.11.01.11.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Oct 2023 01:11:48 -0700 (PDT)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Wed, 11 Oct 2023 10:11:46 +0200
From: Ingo Molnar <mingo@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Fei Yang <fei.yang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCHv2] x86/alternatives: Disable KASAN in apply_alternatives()
Message-ID: <ZSZYwvHTSapAaJQv@gmail.com>
References: <20231011065849.19075-1-kirill.shutemov@linux.intel.com>
 <20231011074616.GL14330@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231011074616.GL14330@noisy.programming.kicks-ass.net>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ge3K+Kk8;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Peter Zijlstra <peterz@infradead.org> wrote:

> >  	DPRINTK(ALT, "alt table %px, -> %px", start, end);
> > +
> > +	/*
> > +	 * In the case CONFIG_X86_5LEVEL=y, KASAN_SHADOW_START is defined using
> > +	 * cpu_feature_enabled(X86_FEATURE_LA57) and is therefore patched here.
> > +	 * During the process, KASAN becomes confused and triggers
> 
> 	because of partial LA57 convertion ..

Not all LA57 related sites are patched yet at this point, and KASAN sees
a weird & broken mixture of LA48 and LA57 runtime semantics, right?

Ie. as far as KASAN is concerned, the LA48 -> LA57 behavioral switchover
must be atomic, but during the kernel code patching process it isn't.

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZSZYwvHTSapAaJQv%40gmail.com.
