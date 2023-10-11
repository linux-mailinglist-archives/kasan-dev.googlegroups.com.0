Return-Path: <kasan-dev+bncBDBK55H2UQKRBXWZTGUQMGQEDZIPZBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FB9E7C4F24
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Oct 2023 11:37:36 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-32320b9d671sf4760661f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Oct 2023 02:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697017056; cv=pass;
        d=google.com; s=arc-20160816;
        b=EDFE+3HAzF/YwNO3Rw46lzYmYe5VBpBHO8/BtUpDmA4pl+kUk2Vg6qJ6/RUz148u2b
         qO1D3MGa6QctusTZ2w545aOa2bC2K+C+2/8OGTgJWXgrrGP2LQtP0ygTZf/ygts3uLKM
         qV+Q9Sv9ZOqwPuyeWvbAsiIyAx/hhhPgYBztXMYMOATzgflZMeaHTDholiyWBbFfT1+N
         7rZAR8fqNHlM0PTmcVk2//h334BDKWgvJ3TUAsQ2h24GDF5ovQRbwrv6XOkivhmNxpxw
         8G4ZA5o8DmissJRIcBH/u3/q7RexqArS6cLa03caxrPfy+T9S+OCY51h1dVJdwFKXnDL
         6JkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1TrSi5jg8O/eck9EVEFQ4k0Iepb6UcOmJDcxMa5F0fk=;
        fh=hn2JrZ3LUYBkD0UvayGkvFOb9iSkIxCaaMYn63/AYmk=;
        b=V37qtQB2CD2o7UvlcA8tVX417qqLiPIP54dDoBEmCI+f8WxjCAvyDcjpCyJIM+nT8v
         6LEj61t1vt/CgKxVvQaADfPvBE5WuvEjBz+REjU2ENvCMIN4BnbkfecRyjIZmjvyxXSh
         IJk9rGam+bzsHs7rpMSTAndHpo0lIThZq6KfQJIg/iFshcQXPNfDQL9l5Dp5U0hBYCCK
         pvsJcnU4/6FRTjfCDRMjuXeeN/ANR09uybq+u9mO90U4rYqbDBa/cydBVQsCTHpHOdtx
         PGm1FFNo7WJL+6akpBtQ9+WAySek90Rsf3sKqv7cQJZGEpUcZe8GkbY3EB8wIA0K/a/E
         owtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ovTUowYu;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697017056; x=1697621856; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1TrSi5jg8O/eck9EVEFQ4k0Iepb6UcOmJDcxMa5F0fk=;
        b=axcMoyOBNqjvBCwaItn+7VfDJA8AxOg4Vrsyy2DtNbdlVyZ1pXrpfzbmdb3/FiIK3L
         oKsiI5UECH4vlsf7REzast7TTliF9Bu6//Jo+v6FChwZYELAMJ0Cyf8oo+Oo9dCOZBl+
         g4weW/rvgRWhjJ9h5jGRixOCOHi2kDYNUw4XmJ07kGDDYy5xGKhUR8vy7ZPilY6+UVXk
         U6+NMljbxaJ4y8FKS37DLjsiHD9n56Q03oiBUlOFSY1XQD6TRKv/scpf2iToiQFgfaq0
         nUUtQuL7aJLTfQRq38Rq/I6STeANLOzo++uWH0+9aMq3Pij42PiiZF7k72UIinWa8vFl
         lRRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697017056; x=1697621856;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1TrSi5jg8O/eck9EVEFQ4k0Iepb6UcOmJDcxMa5F0fk=;
        b=jTUAl6JjSOqARzQz5eOEEzGaqlmF3ZyYnfhxGcpLvOyi9G05YfmILxd/3I4nJ2e23a
         FphhqfnvUgk2xoV0HR3nNrn63C18ycBFLWYa/sn0zeUkNENNEgsyGy5vJFEgB098iQXE
         AGhoY11CMRbyfbgg/slMpOBKkFdfcfGOXWhNKsDNAnE7OT/Xv0mPw05X2kCOZmYCRaW8
         eR7Zm179tLp6AgWVcJT0ScaSCKfDivjl90KHFud3qgrnrhpnR48L4VHwMvz17xUU/lzH
         wt8sMO9ehQadsDO7upObxxAL/IfFLI7ndmNL3MgPcE+QYxMIV7eupXgcdKGI655qVcSI
         mpRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx6OK+/kPC8OeJ8Du6d92tsI7JhnwNFMkXHHyR1XkeDpTpmV53Y
	er+n0pmYt6GJybeg1Jtkfo0=
X-Google-Smtp-Source: AGHT+IG1EerEWX2FvPYiCoeQD24d2etJLuA+RuSROH8tQRDhIKz0jVp0qNPLWHPKfOL2Xvi/9/owcA==
X-Received: by 2002:adf:e382:0:b0:319:7472:f0b6 with SMTP id e2-20020adfe382000000b003197472f0b6mr17959905wrm.15.1697017055042;
        Wed, 11 Oct 2023 02:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e18c:0:b0:32d:72f4:a958 with SMTP id az12-20020adfe18c000000b0032d72f4a958ls500056wrb.1.-pod-prod-04-eu;
 Wed, 11 Oct 2023 02:37:33 -0700 (PDT)
X-Received: by 2002:adf:e382:0:b0:319:7472:f0b6 with SMTP id e2-20020adfe382000000b003197472f0b6mr17959826wrm.15.1697017053031;
        Wed, 11 Oct 2023 02:37:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697017053; cv=none;
        d=google.com; s=arc-20160816;
        b=xGKGLpRkHEZgjTE5/I+O7o+XI+oDAhVm5kHPdDv3sg3cNMXA4b5BTtIL49zgbtQmFN
         WQuOXHXY92h8iNmZ5x7OY/3mgX8YS3VlsZQ/oZlt7KBl7Pb9F19slFhYdMnU2o8yep1/
         BjI0v/5KcSEBcLsR+iIPeNoSPRd4TINoZv5dZE0TM3oNCt2HHpsdyYz4XoXQQ+wODF1N
         BoDAqQtlEtikLIM9gZaJObcna/hffp3XKxNOEixncsgCsBilxRX8r/v53NJOKEbtodUu
         ILyLhqLQ2o6YuaUBvlMe/NMIgvvmhgj2hRR80DCew+23BantDYt5VuIkBgqE1IWAJbmv
         lrIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZZWhJTb7VIJxHwosENExWUwMq4pQEqYalf1VKDcUJSY=;
        fh=hn2JrZ3LUYBkD0UvayGkvFOb9iSkIxCaaMYn63/AYmk=;
        b=QqDFLcqKzB3ZYWpcJq5TGf3vqDt2a2W170RvT9hmdXiSjcAYlBMs1v3fqQBxJnPFga
         3RJ6+cUQu8ML5sbUuhWvPDg1isiyFIMED+4RZzqTj28v7Tg0dwFlD7pJBqed4UfDWFMA
         8uTMH4gksrADBcg4JcEIpJLGw35jt1BpuMH2JFVN3VTEj13DD+X+OGaY8Zd2RG8hiuM7
         e2CBlqkwPqSsPgvydztsULy6JORzxJPHffJWdr2QUENBgH462SeCvBaFbL9DWbkKp6K5
         e3qF3v5mcimjxH1uzPCPEkRcO4A9+sDqZIHQqnfc0wMeKPYAYNv+NF6GKEy+g/8rtHjg
         +EaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ovTUowYu;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id az19-20020adfe193000000b0032626963dfbsi566498wrb.5.2023.10.11.02.37.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Oct 2023 02:37:33 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1qqVeg-00A0N0-9Z; Wed, 11 Oct 2023 09:37:26 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id EF83F30026F; Wed, 11 Oct 2023 11:37:25 +0200 (CEST)
Date: Wed, 11 Oct 2023 11:37:25 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Ingo Molnar <mingo@kernel.org>
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
Message-ID: <20231011093725.GD6307@noisy.programming.kicks-ass.net>
References: <20231011065849.19075-1-kirill.shutemov@linux.intel.com>
 <20231011074616.GL14330@noisy.programming.kicks-ass.net>
 <ZSZYwvHTSapAaJQv@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZSZYwvHTSapAaJQv@gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=ovTUowYu;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Wed, Oct 11, 2023 at 10:11:46AM +0200, Ingo Molnar wrote:
> 
> * Peter Zijlstra <peterz@infradead.org> wrote:
> 
> > >  	DPRINTK(ALT, "alt table %px, -> %px", start, end);
> > > +
> > > +	/*
> > > +	 * In the case CONFIG_X86_5LEVEL=y, KASAN_SHADOW_START is defined using
> > > +	 * cpu_feature_enabled(X86_FEATURE_LA57) and is therefore patched here.
> > > +	 * During the process, KASAN becomes confused and triggers
> > 
> > 	because of partial LA57 convertion ..
> 
> Not all LA57 related sites are patched yet at this point, and KASAN sees
> a weird & broken mixture of LA48 and LA57 runtime semantics, right?
> 
> Ie. as far as KASAN is concerned, the LA48 -> LA57 behavioral switchover
> must be atomic, but during the kernel code patching process it isn't.

Yep, half-way through the patching it observes inconsistencies and goes
WTF :-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231011093725.GD6307%40noisy.programming.kicks-ass.net.
