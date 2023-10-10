Return-Path: <kasan-dev+bncBDBK55H2UQKRBONPSWUQMGQEFRUWKBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 59FF37BFE89
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 15:55:08 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2c296e65210sf49580011fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 06:55:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696946107; cv=pass;
        d=google.com; s=arc-20160816;
        b=d+TC6Sa7Nvth/UGO0jwz1Z7WGMBBEwettT3oxKy7duCUIKKWvPsZGBpcn5TzSl8bqF
         c/DMoJwgl3wJyfQVA47wHJOGAzc8s75U2OlPjNVqYqlZM5yoyG0pC8q8JKKuFLmjpSL/
         K020GrghipTWbeqP+9+MlnYkSj05fN/rCJyk8Vdh8xvsGIiPNxZu+tPbf1pVYWkBLgyG
         LO1kA1BWtkDioWT9ZxnnCctun0e5pQ1U4n5nYAVSpHVgUJf2H236jpIw9KIau45G/RRC
         U62yCiIjAis+R3/saRbHNRRjCJWkkaL+O1FapGt2T3Om8UYxloyAiHAHUekaUrrlSKzp
         yCCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KF91Oy+0Ao2Kxfu2/2R2yvrRvhobhOLit72BUlbUyg4=;
        fh=mUf2ndWDL5c84ldV6DszTy3j42/aMLRyYOLwUcEDGhM=;
        b=ycablFm2SQbGLOiBPsTThViIGK7/6ZwceAEgkfIg7BzVaWEi3LuW1lfSD0Bv6SMl+/
         mYrpVrw7iGq0U+6lI+035oLCAtk7+h60V8RGPrzR55DpFQfLQHBgSgD7WuaYgjZqagQE
         SyE741K1pMt97oMyMJe9k+quh2JPcRh74I+Bm0HWWvJcN2oLuLu9432Ks2mQR9kylYo0
         Qh9EAQgWn33RDFT8WWjri+fbQsNFY/ynbOLMc6nf3sqysSTjar5IBGWGMp7gCGD0Zc/v
         xU7yer2unOtIIevN9v96vblFanoNKM2JoAPjx1IKQcZUskKpGs5Q7iuE5J6ZBcj37i/m
         IWMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=X22LW5WC;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696946107; x=1697550907; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KF91Oy+0Ao2Kxfu2/2R2yvrRvhobhOLit72BUlbUyg4=;
        b=YZJxzpIa68use9Nw/JxQlM45/Kbq2OUGKqV7YbmjqAINStLyVgx/XLrDei7cXDhR5T
         WRdKnYWb61BHgTN64bI4HmCfM10xMOk/tDm+CQjVgwtokD8VHvhd96kf1gm6g95xc/EP
         o0fjNMUMdd3RpPZZFCWzJ22r8xp9xsxzg63bhiH1D9gNYOK+dOuGvKu+Ki6VK0rPclHH
         0PwJrJJSp345eJ5qrAkA7Vtgp4Z0iVZir8StAJjbrw96iRVC3zmozIo9Mi2nluzcAsFP
         dFVprkS67B7nHfGdAMjkBGsd3P22/Gk7xQIUf1Inf9EfT/1/ETHsioW7Z/pXauwv1sZi
         t1wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696946107; x=1697550907;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KF91Oy+0Ao2Kxfu2/2R2yvrRvhobhOLit72BUlbUyg4=;
        b=foyCdRCEI52SxgJbfnH3VMpTjuPPwxI/b6XXoKL44re81jenGIq5HqEMIlNMytqeRq
         VBN+7lcjnmCuwdL9+z8YFT+Hl9YQL+FDImDJmvdB/uiQv8aQze+jXsPd8DdjmEmyoScu
         F0mjqDCp+w/qLRdn8DGhEfctjvxGQx8Ex1a6T5ZN05bSy3M2iiAYbzIcqSJroyUrxKvJ
         /LZCj2Tvqyyii0cVkT6MnLfVQPS8Sc3oKMpiGk7yNr6pnEwUytDsSEdMKj8t3zW+G7R0
         +3imnNQACnfFdFfO+40BhduwgY+DnOoKL6OVhq3WFafIckGp8sC5M+X6fadff43YF1pw
         gigQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxOlALYenj3aKgKavI7wua35CBObrdqdSTmAcAD/ZRt/F4OhN4d
	bIGST0RMpZCKwEGnVii9H7g=
X-Google-Smtp-Source: AGHT+IEIl4BNCoaDg+svud/ylyFDHxGP85052rOp39idRPGYB9COxfldB9JqblcYR5ElmnJRFyy5SA==
X-Received: by 2002:a2e:3612:0:b0:2c0:293c:ad12 with SMTP id d18-20020a2e3612000000b002c0293cad12mr14785497lja.17.1696946106229;
        Tue, 10 Oct 2023 06:55:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc1b:0:b0:2bc:b6ef:c3f4 with SMTP id b27-20020a2ebc1b000000b002bcb6efc3f4ls727768ljf.1.-pod-prod-07-eu;
 Tue, 10 Oct 2023 06:55:03 -0700 (PDT)
X-Received: by 2002:a2e:3612:0:b0:2c0:293c:ad12 with SMTP id d18-20020a2e3612000000b002c0293cad12mr14785421lja.17.1696946103290;
        Tue, 10 Oct 2023 06:55:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696946103; cv=none;
        d=google.com; s=arc-20160816;
        b=jtwF7LQ2RtzMsh+QYUqURtoGVshUEs5KdrcKNa5s/vfzw+pq/xjr7R+yfbX5N4ccwP
         f498fHw+oDTM7ZbdL/2FhEXnAWzBlm+BfqRvHqUVDHLCgYmPS0OIuOIPd+Zuno25ayUs
         dITJqrTpVahE+7VX6hqMw54EOz7QPVpL4MIsZ3ifEJsbPnZXFTYv5LnGqzunCn/63CYj
         aMtur/vO5RqM4Nb4iV34rq4BO43eNxb2xCk/Nsxqb5A+txG/KnBIvX+fuXJMxTOPx2Xq
         pvlgrGE9k9FwbExpX9jVwr7tDaWnRb54JbpaF3wYNRL5oQgO1wXc8tV1CLPE4Rn2jTCW
         Z6Qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=S2MeW9xBBP5ir4MyshyKYBTdw1uG9obgtaYQpOlwGak=;
        fh=mUf2ndWDL5c84ldV6DszTy3j42/aMLRyYOLwUcEDGhM=;
        b=NEgrYOl6yyzeqQT1bKEpptuawLcwtck7HyBGj/1wlNY2xUOcu0ptKHH3euN+X6Vmfb
         1NPMv35YUgm2wlBi9Msm6nMmGIUCdhYs3VHK07k3sPo0DELN/s/+6Jgs8p18AUQBhD99
         1c7A/LTGYoWzsaalL2IFj4mkHXIFEm+IyEWsXZnuVkbGh6GjrUmmPKyG4DhS6q04/3Zd
         QvV6wzKG0ODezxZQ6HMOnRzyiwcoQMTAf+iZxrRDrw+FRGRKttzrcm6oQQBv3PV/HSBL
         2vNWUV4bEvzAWO8jSKQUXB6k9E+RkRabUMz+1tpEB2O5AkoU6z45IeueWuA3yAsH8NrV
         i1Zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=X22LW5WC;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id e3-20020a2e9e03000000b002b9d5a29ef7si584230ljk.4.2023.10.10.06.55.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Oct 2023 06:55:03 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1qqDCK-004xqT-W8; Tue, 10 Oct 2023 13:54:57 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id A6E4F300392; Tue, 10 Oct 2023 15:54:56 +0200 (CEST)
Date: Tue, 10 Oct 2023 15:54:56 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Borislav Petkov <bp@alien8.de>
Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Fei Yang <fei.yang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCH] x86/alternatives: Disable KASAN on text_poke_early() in
 apply_alternatives()
Message-ID: <20231010135456.GL377@noisy.programming.kicks-ass.net>
References: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
 <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
 <20231010101056.GF377@noisy.programming.kicks-ass.net>
 <20231010131054.GHZSVNXhruJIx0iCzq@fat_crate.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231010131054.GHZSVNXhruJIx0iCzq@fat_crate.local>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=X22LW5WC;
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

On Tue, Oct 10, 2023 at 03:10:54PM +0200, Borislav Petkov wrote:
> On Tue, Oct 10, 2023 at 12:10:56PM +0200, Peter Zijlstra wrote:
> > Now, obviously you really don't want boot_cpu_has() in
> > __VIRTUAL_MASK_SHIFT, that would be really bad (Linus recently
> > complained about how horrible the code-gen is around this already, must
> > not make it far worse).
> 
> You mean a MOV (%rip) and a TEST are so horrible there because it is
> a mask?
> 
> I'd experiment with it when I get a chance...

That gets you a memory-reference and potential cachemiss what should
have been an immediate :/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010135456.GL377%40noisy.programming.kicks-ass.net.
